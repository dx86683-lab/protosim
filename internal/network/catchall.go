package network

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/telemetry"
)

// CatchAllRunner manages optional TCP/UDP catch-all listeners for capturing unknown/novel probes.
type CatchAllRunner struct {
	mu           sync.Mutex
	bus          *telemetry.Bus
	tracker      *SessionTracker
	listenTCPFn  func(ip string, port uint16) (net.Listener, error)
	listenUDPFn  func(ip string, port uint16) (net.PacketConn, error)
	excludeFn    func(net.Addr) bool
	tcpListeners []net.Listener
	udpConns     []net.PacketConn
	stopCh       chan struct{}
}

func NewCatchAllRunner(bus *telemetry.Bus, tracker *SessionTracker) *CatchAllRunner {
	return &CatchAllRunner{
		bus:     bus,
		tracker: tracker,
		stopCh:  make(chan struct{}),
	}
}

func (c *CatchAllRunner) SetListeners(
	tcpFn func(ip string, port uint16) (net.Listener, error),
	udpFn func(ip string, port uint16) (net.PacketConn, error),
	excludeFn func(net.Addr) bool,
) {
	c.mu.Lock()
	c.listenTCPFn = tcpFn
	c.listenUDPFn = udpFn
	c.excludeFn = excludeFn
	c.mu.Unlock()
}

func (c *CatchAllRunner) Start(bindIP string, tcpPorts, udpPorts []uint16) error {
	c.Stop()

	c.mu.Lock()
	c.stopCh = make(chan struct{})
	stopCh := c.stopCh
	tcpFn := c.listenTCPFn
	udpFn := c.listenUDPFn
	c.mu.Unlock()

	if bindIP == "" {
		bindIP = "0.0.0.0"
	}

	var started int
	var lastErr error

	for _, port := range tcpPorts {
		addr := fmt.Sprintf("%s:%d", bindIP, port)
		var (
			ln  net.Listener
			err error
		)
		if tcpFn != nil {
			ln, err = tcpFn(bindIP, port)
		} else {
			ln, err = net.Listen("tcp", addr)
		}
		if err != nil {
			lastErr = err
			logrus.Warnf("[CatchAll] TCP listen %s failed: %v", addr, err)
			continue
		}
		started++
		c.mu.Lock()
		c.tcpListeners = append(c.tcpListeners, ln)
		c.mu.Unlock()
		logrus.Infof("[CatchAll] TCP listening on %s", addr)
		go c.acceptTCP(ln, bindIP, port, stopCh)
	}

	for _, port := range udpPorts {
		addr := fmt.Sprintf("%s:%d", bindIP, port)
		var (
			pc  net.PacketConn
			err error
		)
		if udpFn != nil {
			pc, err = udpFn(bindIP, port)
		} else {
			pc, err = net.ListenPacket("udp", addr)
		}
		if err != nil {
			lastErr = err
			logrus.Warnf("[CatchAll] UDP listen %s failed: %v", addr, err)
			continue
		}
		started++
		c.mu.Lock()
		c.udpConns = append(c.udpConns, pc)
		c.mu.Unlock()
		logrus.Infof("[CatchAll] UDP listening on %s", addr)
		go c.serveUDP(pc, bindIP, port, stopCh)
	}

	if (len(tcpPorts)+len(udpPorts) > 0) && started == 0 && lastErr != nil {
		return fmt.Errorf("catch-all failed to bind any configured port: %w", lastErr)
	}
	return nil
}

func (c *CatchAllRunner) acceptTCP(ln net.Listener, bindIP string, port uint16, stopCh chan struct{}) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				return
			}
		}
		go func(conn net.Conn) {
			bus := c.bus
			c.mu.Lock()
			excl := c.excludeFn
			c.mu.Unlock()
			if excl != nil && excl(conn.RemoteAddr()) {
				bus = nil
			}
			tc := NewTelemetryConn(conn, bus, c.tracker, "catch_all", bindIP, port)
			defer tc.Close()
			_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 4096)
			n, _ := tc.Read(buf)
			if bus != nil {
				bus.RecordEvent(telemetry.Event{
					SessionID: tc.SessionID(),
					Timestamp: time.Now().UTC(),
					Protocol:  "catch_all",
					RemoteIP:  tc.remoteIP,
					LocalPort: port,
					Kind:      "catch_all",
					Summary:   fmt.Sprintf("Captured %dB TCP probe on port %d", n, port),
				})
			}
		}(raw)
	}
}

func (c *CatchAllRunner) serveUDP(pc net.PacketConn, bindIP string, port uint16, stopCh chan struct{}) {
	buf := make([]byte, 4096)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				return
			}
		}
		if n <= 0 || raddr == nil {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		rIP, rPort := splitHostPort(raddr)
		now := time.Now().UTC()
		sid := uuid.NewString()
		if c.bus != nil {
			hash, tag := c.bus.RecordProbeHit("catch_all", "udp", port, rIP, "", sid, payload)
			c.bus.RecordSession(telemetry.Session{
				ID:         sid,
				Protocol:   "catch_all",
				Transport:  "udp",
				RemoteIP:   rIP,
				RemotePort: rPort,
				LocalIP:    bindIP,
				LocalPort:  port,
				ScannerTag: tag,
				ProbeHash:  hash,
				StartedAt:  now,
				EndedAt:    now,
				BytesIn:    int64(n),
				ParseOK:    true,
				Status:     "closed",
			})
			c.bus.RecordPayload(telemetry.PayloadChunk{
				SessionID: sid,
				Seq:       1,
				Timestamp: now,
				Direction: "in",
				Data:      payload,
			})
			c.bus.RecordEvent(telemetry.Event{
				SessionID: sid,
				Timestamp: now,
				Protocol:  "catch_all",
				RemoteIP:  rIP,
				LocalPort: port,
				Kind:      "catch_all",
				Summary:   fmt.Sprintf("Captured %dB UDP probe on port %d", n, port),
			})
		}
	}
}

func (c *CatchAllRunner) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	for _, ln := range c.tcpListeners {
		_ = ln.Close()
	}
	for _, pc := range c.udpConns {
		_ = pc.Close()
	}
	c.tcpListeners = nil
	c.udpConns = nil
}
