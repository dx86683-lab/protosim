package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/dx86683-lab/protosim/internal/config"
	"github.com/dx86683-lab/protosim/internal/telemetry"
	"github.com/dx86683-lab/protosim/pkg/capture"
	"github.com/dx86683-lab/protosim/pkg/netstack/core"
	"github.com/dx86683-lab/protosim/pkg/tun"
	"github.com/dx86683-lab/protosim/protocols"
)

// ServiceStatus describes one running protocol listener exposed via /api/v2/services.
type ServiceStatus struct {
	ID        string                 `json:"id"`
	IP        string                 `json:"ip"`
	Port      uint16                 `json:"port"`
	Protocol  string                 `json:"protocol"`
	Transport string                 `json:"transport"`
	App       string                 `json:"app,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
	StartedAt time.Time              `json:"started_at"`
	Status    string                 `json:"status"`
}

// ProtocolDescriptor describes one of the 61 registered protocol handlers.
type ProtocolDescriptor struct {
	Name        string                 `json:"name"`
	DefaultPort uint16                 `json:"default_port"`
	Transport   string                 `json:"transport"`
	Params      map[string]interface{} `json:"params,omitempty"`
}

type runningService struct {
	status ServiceStatus
	stopFn func()
}

// Manager orchestrates the network stack (localhost / TUN+gVisor userdef & all),
// all 61 protocol handlers, Catch-All listeners, optional rate limiting, and capture.
type Manager struct {
	cfg      *config.Config
	bus      *telemetry.Bus
	tracker  *SessionTracker
	protoLog *logrus.Logger
	catchAll *CatchAllRunner

	tunIP   net.IP
	ipNet   *net.IPNet
	nic     tcpip.NICID
	stack   *stack.Stack
	vrouter *virtualRouter
	device  core.Device

	mu           sync.RWMutex
	services     map[string]*runningService
	limiters     sync.Map      // ip -> *rate.Limiter
	excludedIPs  map[string]struct{}
	excludedNets []*net.IPNet
	connSem      chan struct{} // global concurrent TCP connection guard
	connSeq      atomic.Uint32
	closed       atomic.Bool
}

// NewManager initializes the network manager and protocol telemetry logger.
func NewManager(cfg *config.Config, bus *telemetry.Bus) (*Manager, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	parsedIP, ipNet, err := net.ParseCIDR(cfg.Network.CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %q: %w", cfg.Network.CIDR, err)
	}
	tunIP := resolveTunHostIP(parsedIP, ipNet)
	if cfg.GeoIP.CityDBPath != "" {
		if err := protocols.SetGeoDB(cfg.GeoIP.CityDBPath); err != nil {
			logrus.Warnf("GeoIP DB load failed (%s): %v", cfg.GeoIP.CityDBPath, err)
		}
	}

	tracker := NewSessionTracker()
	hook := NewTelemetryHook(bus, tracker)
	pLog := logrus.New()
	pLog.SetOutput(io.Discard) // structured events flow through TelemetryHook to SQLite + SSE
	pLog.SetLevel(logrus.InfoLevel)
	pLog.AddHook(hook)

	maxConns := cfg.Network.MaxConns
	if maxConns <= 0 {
		maxConns = 4096
	}
	excludedIPs := make(map[string]struct{})
	var excludedNets []*net.IPNet
	for _, raw := range cfg.Network.Exclusions {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				excludedNets = append(excludedNets, cidr)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			excludedIPs[ip.String()] = struct{}{}
		}
	}

	m := &Manager{
		cfg:          cfg,
		bus:          bus,
		tracker:      tracker,
		protoLog:     pLog,
		catchAll:     NewCatchAllRunner(bus, tracker),
		tunIP:        tunIP,
		ipNet:        ipNet,
		nic:          1,
		services:     make(map[string]*runningService),
		excludedIPs:  excludedIPs,
		excludedNets: excludedNets,
		connSem:      make(chan struct{}, maxConns),
	}
	hook.SetExcludeIPFn(m.isExcludedIP)
	m.catchAll.SetListeners(m.listenTCP, m.listenUDP, m.isExcluded)
	return m, nil
}

// Start initializes the network layer (if TUN/gVisor), starts all configured services,
// Catch-All ports, and optional packet capture.
func (m *Manager) Start() error {
	if m.cfg.Network.Mode != config.ModeLocalhost {
		if err := m.initVirtualStack(); err != nil {
			return err
		}
	}

	for _, host := range m.cfg.Hosts {
		if err := m.ensureVirtualIP(host.IP); err != nil {
			return err
		}
		for _, svc := range host.Services {
			if err := m.StartService(host.IP, svc); err != nil {
				logrus.Warnf("[Manager] start service %s on %s:%d failed: %v", svc.Protocol, host.IP, svc.Port, err)
			}
		}
	}

	if m.cfg.CatchAll.Enabled {
		bindIP := "0.0.0.0"
		if len(m.cfg.Hosts) > 0 && m.cfg.Hosts[0].IP != "" {
			bindIP = m.cfg.Hosts[0].IP
		}
		_ = m.catchAll.Start(bindIP, m.cfg.CatchAll.TCPPorts, m.cfg.CatchAll.UDPPorts)
	}

	if m.cfg.Capture.Enabled && m.cfg.Capture.Device != "" {
		dev := m.cfg.Capture.Device
		go func() {
			defer func() { _ = recover() }()
			capture.LogSYN(dev, m.protoLog)
		}()
		go func() {
			defer func() { _ = recover() }()
			capture.LogUDP(dev, m.protoLog)
		}()
		go func() {
			defer func() { _ = recover() }()
			capture.LogICMP(dev, m.protoLog)
		}()
	}

	return nil
}

// resolveTunHostIP picks a valid host IP for the OS-side TUN interface.
// If the user supplied a network address like 10.99.0.0/24, bump it to .1 so
// the host TUN interface never takes the .0 network address or collides with
// virtual hosts inside gVisor.
func resolveTunHostIP(parsedIP net.IP, ipNet *net.IPNet) net.IP {
	if ip4 := parsedIP.To4(); ip4 != nil {
		res := make(net.IP, len(ip4))
		copy(res, ip4)
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones < 31 && res.Equal(ipNet.IP.To4()) {
			res[3]++
		}
		return res
	}
	return parsedIP
}

func (m *Manager) tunCIDR() string {
	ones, _ := m.ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", m.tunIP.String(), ones)
}

func (m *Manager) initVirtualStack() error {
	dev, err := tun.NewDeviceWithMTU(m.cfg.Network.DevName, m.cfg.Network.MTU)
	if err != nil {
		return fmt.Errorf("create tun %s: %w", m.cfg.Network.DevName, err)
	}
	if err := dev.Activate(); err != nil {
		return fmt.Errorf("activate tun: %w", err)
	}
	if err := dev.SetInterfaceAddress(m.tunCIDR()); err != nil {
		return fmt.Errorf("set tun addr %s: %w", m.tunCIDR(), err)
	}
	if runtime.GOOS != "windows" {
		if err := dev.AddRouteEntry([]string{m.ipNet.String()}); err != nil {
			return fmt.Errorf("add tun route: %w", err)
		}
	}

	ep := core.NewEndpoint(dev, m.cfg.Network.MTU)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	// Attach dynamic TCP/UDP forwarder BEFORE CreateNIC so no inbound packets
	// race with handler registration.
	vrouter := newVirtualRouter(m.ipNet, m.tunIP)
	vrouter.Attach(s)

	if tcperr := s.CreateNIC(m.nic, ep); tcperr != nil {
		return fmt.Errorf("create NIC: %s", tcperr)
	}

	// Follow tun2socks best practices: route all outbound replies (0.0.0.0/0 and ::/0)
	// back through the TUN NIC so cross-subnet / external scanners never hit
	// "network is unreachable" inside gVisor.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: m.nic},
		{Destination: header.IPv6EmptySubnet, NIC: m.nic},
	})
	_ = s.SetPromiscuousMode(m.nic, true)
	_ = s.SetSpoofing(m.nic, true)

	ttlVal := m.cfg.Network.TTL
	if ttlVal <= 0 || ttlVal > 255 {
		ttlVal = 64
	}
	ttl := tcpip.DefaultTTLOption(ttlVal)
	_ = s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl)
	_ = s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttl)
	tcpDelay := tcpip.TCPDelayEnabled(false)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpDelay)
	tcpSACK := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSACK)

	m.device = dev
	m.stack = s
	m.vrouter = vrouter
	return nil
}

func (m *Manager) ensureVirtualIP(ipStr string) error {
	// Promiscuous + Spoofing + dynamic Forwarder handles any virtual IP inside
	// m.ipNet on demand without upfront AddProtocolAddress fan-out.
	return nil
}

// StartService launches one protocol listener on (ip, svc.Port) and registers it.
func (m *Manager) StartService(ip string, svc config.ServiceConfig) error {
	protoName := strings.ToLower(strings.TrimSpace(svc.Protocol))
	if protoName == "" {
		return fmt.Errorf("protocol is required")
	}

	// TLS aliases map to their underlying protocol handler with ssl=true
	tlsAliases := map[string]string{
		"https":  "http",
		"smtps":  "smtp",
		"ldaps":  "ldap",
		"imaps":  "imap",
		"pop3s":  "pop3",
		"ftps":   "ftp",
		"winrms": "winrm",
		"mqtts":  "mqtt",
		"amqps":  "amqp",
	}
	handlerName := protoName
	params := make(map[string]interface{})
	for k, v := range svc.Params {
		params[k] = v
	}
	if base, ok := tlsAliases[protoName]; ok {
		handlerName = base
		params["ssl"] = true
	}

	pi, ok := protocols.LookupProtocol(handlerName)
	if !ok {
		return fmt.Errorf("unknown protocol %q", protoName)
	}
	port := svc.Port
	if port == 0 {
		port = pi.DefaultPort
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	transport := "tcp"
	if _, ok := pi.HandleFunc.(func(*protocols.UDPConnection, []byte) error); ok {
		transport = "udp"
	} else if _, ok := pi.HandleFunc.(protocols.UDPFunction); ok {
		transport = "udp"
	}
	if pi.DatagramHandler != nil && transport == "tcp" {
		transport = "tcp+udp"
	}

	svcID := fmt.Sprintf("%s:%d:%s:%s", ip, port, transport, protoName)

	m.mu.RLock()
	_, exists := m.services[svcID]
	m.mu.RUnlock()
	if exists {
		return fmt.Errorf("service %s already running", svcID)
	}

	if err := m.ensureVirtualIP(ip); err != nil {
		return err
	}

	bi := &protocols.BindInfo{
		Handler: protoName,
		Port:    port,
		App:     svc.App,
		Params:  params,
		IP:      ip,
		Log:     m.protoLog,
	}
	ci := protocols.NewConfigInfo(fmt.Sprintf("%s:%d", ip, port), bi, m.protoLog.WithFields(logrus.Fields{
		"protocol": protoName,
		"local":    fmt.Sprintf("%s:%d", ip, port),
	}))

	var stopFns []func()
	var err error

	switch fn := pi.HandleFunc.(type) {
	case func() func(*protocols.SessionConnection) error:
		var sf func()
		sf, err = m.startTCPService(ip, port, protoName, bi, ci, fn())
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func() protocols.TCPFunction:
		var sf func()
		sf, err = m.startTCPService(ip, port, protoName, bi, ci, fn())
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func() (protocols.TCPFunction, protocols.UDPFunction):
		tcpFn, udpFn := fn()
		if tcpFn != nil {
			var sf func()
			sf, err = m.startTCPService(ip, port, protoName, bi, ci, tcpFn)
			if sf != nil {
				stopFns = append(stopFns, sf)
			}
		}
		if err == nil && udpFn != nil {
			if sf, uerr := m.startUDPService(ip, port, protoName, bi, ci, udpFn); uerr == nil && sf != nil {
				stopFns = append(stopFns, sf)
			}
		}
	case func(*protocols.SessionConnection) error:
		var sf func()
		sf, err = m.startTCPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case protocols.TCPFunction:
		var sf func()
		sf, err = m.startTCPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func(*protocols.ListenConnection) error:
		var sf func()
		sf, err = m.startTCPListenerService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case protocols.TCPListenerFunction:
		var sf func()
		sf, err = m.startTCPListenerService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func(*protocols.ConfigInfo) http.Handler:
		var sf func()
		sf, err = m.startHTTPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case protocols.HTTPFunction:
		var sf func()
		sf, err = m.startHTTPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func(*protocols.UDPConnection, []byte) error:
		var sf func()
		sf, err = m.startUDPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case protocols.UDPFunction:
		var sf func()
		sf, err = m.startUDPService(ip, port, protoName, bi, ci, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case func(net.Conn, net.Conn, []byte, bool) error:
		var sf func()
		sf, err = m.startTCPForwardService(ip, port, protoName, bi, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	case protocols.TCPForwardFunction:
		var sf func()
		sf, err = m.startTCPForwardService(ip, port, protoName, bi, fn)
		if sf != nil {
			stopFns = append(stopFns, sf)
		}
	default:
		return fmt.Errorf("unsupported handler function type %T for %q", pi.HandleFunc, protoName)
	}
	if err != nil {
		return err
	}

	// Start companion UDP handler for dual-transport protocols (e.g. DNS, CoAP, SIP, MelSecQ)
	if pi.DatagramHandler != nil {
		if udpFn := pi.DatagramHandler(bi); udpFn != nil {
			if sf, uerr := m.startUDPService(ip, port, protoName, bi, ci, udpFn); uerr == nil && sf != nil {
				stopFns = append(stopFns, sf)
			} else if uerr != nil {
				logrus.Warnf("[Manager] companion UDP listener for %s on %s:%d failed (running TCP-only): %v", protoName, ip, port, uerr)
				if transport == "tcp+udp" {
					transport = "tcp"
					svcID = fmt.Sprintf("%s:%d:%s:%s", ip, port, transport, protoName)
				}
			}
		}
	}

	stopFn := func() {
		for _, sf := range stopFns {
			sf()
		}
	}

	m.mu.Lock()
	m.services[svcID] = &runningService{
		status: ServiceStatus{
			ID:        svcID,
			IP:        ip,
			Port:      port,
			Protocol:  protoName,
			Transport: transport,
			App:       svc.App,
			Params:    params,
			StartedAt: time.Now().UTC(),
			Status:    "running",
		},
		stopFn: stopFn,
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) listenTCP(ip string, port uint16) (net.Listener, error) {
	if m.cfg.Network.Mode == config.ModeLocalhost {
		return net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	}
	if m.vrouter == nil {
		return nil, errors.New("virtual router not initialized")
	}
	return m.vrouter.ListenTCP(ip, port)
}

func (m *Manager) listenUDP(ip string, port uint16) (net.PacketConn, error) {
	if m.cfg.Network.Mode == config.ModeLocalhost {
		return net.ListenPacket("udp", fmt.Sprintf("%s:%d", ip, port))
	}
	if m.vrouter == nil {
		return nil, errors.New("virtual router not initialized")
	}
	return m.vrouter.ListenUDP(ip, port)
}

func (m *Manager) isExcludedIP(ipStr string) bool {
	if ipStr == "" || (len(m.excludedIPs) == 0 && len(m.excludedNets) == 0) {
		return false
	}
	if _, ok := m.excludedIPs[ipStr]; ok {
		return true
	}
	if len(m.excludedNets) > 0 {
		if parsed := net.ParseIP(ipStr); parsed != nil {
			for _, cidr := range m.excludedNets {
				if cidr.Contains(parsed) {
					return true
				}
			}
		}
	}
	return false
}

func (m *Manager) isExcluded(remoteAddr net.Addr) bool {
	if remoteAddr == nil || (len(m.excludedIPs) == 0 && len(m.excludedNets) == 0) {
		return false
	}
	ipStr, _ := splitHostPort(remoteAddr)
	return m.isExcludedIP(ipStr)
}

func (m *Manager) allowIP(remoteAddr net.Addr) bool {
	if !m.cfg.RateLimit.Enabled || remoteAddr == nil {
		return true
	}
	ip, _ := splitHostPort(remoteAddr)
	if ip == "" {
		return true
	}
	val, _ := m.limiters.LoadOrStore(ip, rate.NewLimiter(rate.Limit(m.cfg.RateLimit.PerIPPerSec), m.cfg.RateLimit.Burst))
	return val.(*rate.Limiter).Allow()
}

func (m *Manager) startTCPService(ip string, port uint16, protoName string, bi *protocols.BindInfo, ci *protocols.ConfigInfo, fn protocols.TCPFunction) (func(), error) {
	ln, err := m.listenTCP(ip, port)
	if err != nil {
		return nil, err
	}
	sslW := NewSSLWrapper(bi.GetCertName())
	if bi.GetBoolParams("ssl") {
		if err := sslW.InitSslConfig(bi.GenCert()); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}

	stopCh := make(chan struct{})
	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			if !m.allowIP(rawConn.RemoteAddr()) {
				_ = rawConn.Close()
				continue
			}
			select {
			case m.connSem <- struct{}{}:
			default:
				_ = rawConn.Close()
				continue
			}
			go func(c net.Conn) {
				defer func() { <-m.connSem }()
				bus := m.bus
				if m.isExcluded(c.RemoteAddr()) {
					bus = nil
				}
				tc := NewTelemetryConn(c, bus, m.tracker, protoName, ip, port)
				defer tc.Close()
				if m.cfg.Network.TimeoutSec > 0 {
					_ = tc.SetDeadline(time.Now().Add(time.Duration(m.cfg.Network.TimeoutSec) * time.Second))
				}
				var conn net.Conn = tc
				if bi.GetBoolParams("ssl") {
					sc := sslW.WrapSslConn(tc)
					if err := sc.Handshake(); err != nil {
						tc.MarkParseError("tls handshake failed: " + err.Error())
						return
					}
					conn = sc
				}
				sc := &protocols.SessionConnection{
					SslConnWraper: sslW,
					Conn:          conn,
					ConnectionID:  m.connSeq.Add(1),
					ConfigInfo:    ci,
				}
				if err := fn(sc); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					if !strings.Contains(strings.ToLower(err.Error()), "closed") {
						tc.MarkParseError(err.Error())
					}
				}
			}(rawConn)
		}
	}()

	return func() {
		close(stopCh)
		_ = ln.Close()
	}, nil
}

func (m *Manager) startTCPListenerService(ip string, port uint16, protoName string, bi *protocols.BindInfo, ci *protocols.ConfigInfo, fn protocols.TCPListenerFunction) (func(), error) {
	rawLn, err := m.listenTCP(ip, port)
	if err != nil {
		return nil, err
	}
	tl := NewTelemetryListener(rawLn, m.bus, m.tracker, protoName, ip, port)
	tl.SetExcludeFn(m.isExcluded)
	sslW := NewSSLWrapper(bi.GetCertName())
	if bi.GetBoolParams("ssl") {
		if err := sslW.InitSslConfig(bi.GenCert()); err != nil {
			_ = tl.Close()
			return nil, err
		}
		sslW.WrapSslListener(tl)
	}

	lc := &protocols.ListenConnection{
		SslConnWraper: sslW,
		Listener:      tl,
		ConfigInfo:    ci,
	}
	go func() {
		if err := fn(lc); err != nil && !errors.Is(err, net.ErrClosed) {
			logrus.Debugf("[%s] listener exited: %v", protoName, err)
		}
	}()
	return func() { _ = tl.Close() }, nil
}

func (m *Manager) startHTTPService(ip string, port uint16, protoName string, bi *protocols.BindInfo, ci *protocols.ConfigInfo, fn protocols.HTTPFunction) (func(), error) {
	rawLn, err := m.listenTCP(ip, port)
	if err != nil {
		return nil, err
	}
	tl := NewTelemetryListener(rawLn, m.bus, m.tracker, protoName, ip, port)
	tl.SetExcludeFn(m.isExcluded)
	if bi.GetBoolParams("ssl") {
		sslW := NewSSLWrapper(bi.GetCertName())
		if err := sslW.InitSslConfig(bi.GenCert()); err != nil {
			_ = tl.Close()
			return nil, err
		}
		sslW.WrapSslListener(tl)
	}
	srv := &http.Server{
		Handler:           fn(ci),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.Serve(tl); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			logrus.Debugf("[%s] http serve exited: %v", protoName, err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = tl.Close()
	}, nil
}

type udpTelemetryPacketConn struct {
	net.PacketConn
	bus        *telemetry.Bus
	sessionID  string
	seq        atomic.Int32
	bytesOut   atomic.Int64
	maxCapture int64
	captured   atomic.Int64
}

func (u *udpTelemetryPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := u.PacketConn.WriteTo(p, addr)
	if n > 0 {
		u.bytesOut.Add(int64(n))
		if u.bus != nil && u.maxCapture > 0 {
			prev := u.captured.Load()
			if prev < u.maxCapture {
				take := int64(n)
				if prev+take > u.maxCapture {
					take = u.maxCapture - prev
				}
				if take > 0 && u.captured.Add(take) <= u.maxCapture+take {
					u.bus.RecordPayload(telemetry.PayloadChunk{
						SessionID: u.sessionID,
						Seq:       int(u.seq.Add(1)),
						Timestamp: time.Now().UTC(),
						Direction: "out",
						Data:      p[:take],
					})
				}
			}
		}
	}
	return n, err
}

func (m *Manager) startUDPService(ip string, port uint16, protoName string, _ *protocols.BindInfo, ci *protocols.ConfigInfo, fn protocols.UDPFunction) (func(), error) {
	pc, err := m.listenUDP(ip, port)
	if err != nil {
		return nil, err
	}
	stopCh := make(chan struct{})
	servePacketConn := func(conn net.PacketConn) {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			if n <= 0 || raddr == nil || !m.allowIP(raddr) {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			go func(payload []byte, remote net.Addr) {
				start := time.Now().UTC()
				rIP, rPort := splitHostPort(remote)
				sid := uuid.NewString()
				rKey := remote.String()
				localIP := ip
				if vp, ok := remote.(*virtualUDPPeerAddr); ok && vp.localIP != "" {
					localIP = vp.localIP
				}
				bus := m.bus
				if m.isExcluded(remote) {
					bus = nil
				}

				hash, tag := "", "unknown"
				maxCap := int64(65536)
				if bus != nil {
					if mc := bus.StorageConfig().MaxPayloadBytes; mc > 0 {
						maxCap = int64(mc)
					}
					hash, tag = bus.RecordProbeHit(protoName, "udp", port, rIP, "", sid, payload)
					inCap := payload
					if int64(len(inCap)) > maxCap {
						inCap = inCap[:maxCap]
					}
					bus.RecordPayload(telemetry.PayloadChunk{
						SessionID: sid,
						Seq:       1,
						Timestamp: start,
						Direction: "in",
						Data:      inCap,
					})
				}
				m.tracker.Register(protoName, rKey, &activeSessionMeta{
					sessionID:  sid,
					scannerTag: tag,
					localPort:  port,
				})
				defer m.tracker.Unregister(protoName, rKey)

				wrappedPC := &udpTelemetryPacketConn{
					PacketConn: conn,
					bus:        bus,
					sessionID:  sid,
					maxCapture: maxCap,
				}
				wrappedPC.seq.Store(1)
				if int64(len(payload)) > maxCap {
					wrappedPC.captured.Store(maxCap)
				} else {
					wrappedPC.captured.Store(int64(len(payload)))
				}
				uc := protocols.NewUDPConnection(wrappedPC, remote, ci)
				err := fn(uc, payload)
				end := time.Now().UTC()
				status := "closed"
				parseOK := true
				if err != nil {
					status = "parse_error"
					parseOK = false
					if bus != nil {
						bus.RecordEvent(telemetry.Event{
							SessionID: sid,
							Timestamp: end,
							Protocol:  protoName,
							RemoteIP:  rIP,
							LocalPort: port,
							Kind:      "parse_error",
							Summary:   err.Error(),
						})
					}
				}
				if bus != nil {
					bus.RecordSession(telemetry.Session{
						ID:         sid,
						Protocol:   protoName,
						Transport:  "udp",
						RemoteIP:   rIP,
						RemotePort: rPort,
						LocalIP:    localIP,
						LocalPort:  port,
						ScannerTag: tag,
						ProbeHash:  hash,
						StartedAt:  start,
						EndedAt:    end,
						DurationMs: end.Sub(start).Milliseconds(),
						BytesIn:    int64(len(payload)),
						BytesOut:   wrappedPC.bytesOut.Load(),
						ParseOK:    parseOK,
						Status:     status,
					})
				}
			}(data, raddr)
		}
	}
	go servePacketConn(pc)

	// In localhost mode, also join SSDP multicast group 239.255.255.250:1900 so LAN
	// UPnP/SSDP M-SEARCH discovery probes are answered seamlessly.
	var mcastPC net.PacketConn
	if protoName == "ssdp" && port == 1900 && m.cfg.Network.Mode == config.ModeLocalhost {
		if mc, merr := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); merr == nil {
			mcastPC = mc
			go servePacketConn(mc)
		} else {
			logrus.Debugf("[ssdp] multicast 239.255.255.250:1900 join skipped: %v", merr)
		}
	}

	return func() {
		close(stopCh)
		_ = pc.Close()
		if mcastPC != nil {
			_ = mcastPC.Close()
		}
	}, nil
}

func (m *Manager) startTCPForwardService(ip string, port uint16, protoName string, bi *protocols.BindInfo, _ protocols.TCPForwardFunction) (func(), error) {
	target := bi.GetStringParams("target", "")
	if target == "" {
		return nil, fmt.Errorf("tcp_forward requires target param")
	}
	ln, err := m.listenTCP(ip, port)
	if err != nil {
		return nil, err
	}
	stopCh := make(chan struct{})
	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				tc := NewTelemetryConn(c, m.bus, m.tracker, protoName, ip, port)
				defer tc.Close()
				up, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					tc.MarkParseError("dial target failed: " + err.Error())
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, tc) }()
				_, _ = io.Copy(tc, up)
			}(rawConn)
		}
	}()
	return func() {
		close(stopCh)
		_ = ln.Close()
	}, nil
}

// StopService stops a running service by ID.
func (m *Manager) StopService(id string) error {
	m.mu.Lock()
	rs, ok := m.services[id]
	if ok {
		delete(m.services, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("service %q not found", id)
	}
	if rs.stopFn != nil {
		rs.stopFn()
	}
	return nil
}

// ListServices returns a sorted snapshot of all active services.
func (m *Manager) ListServices() []ServiceStatus {
	m.mu.RLock()
	out := make([]ServiceStatus, 0, len(m.services))
	for _, rs := range m.services {
		out = append(out, rs.status)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// ApplyScenario stops all current services and starts all services defined in the ScenarioPreset.
// It pre-validates network mode compatibility and rolls back to the previous hosts if all new
// services fail to start.
func (m *Manager) ApplyScenario(preset config.ScenarioPreset) (int, []string) {
	if preset.Mode != "" && preset.Mode != m.cfg.Network.Mode {
		return 0, []string{fmt.Sprintf(
			"scenario %q requires network mode %q, but ProtoSim is running in %q mode (restart with --mode %s)",
			preset.ID, preset.Mode, m.cfg.Network.Mode, preset.Mode,
		)}
	}

	prevScenario := m.cfg.Scenario
	prevHosts := m.cfg.Hosts

	m.mu.Lock()
	old := make([]*runningService, 0, len(m.services))
	for _, rs := range m.services {
		old = append(old, rs)
	}
	m.services = make(map[string]*runningService)
	m.mu.Unlock()

	for _, rs := range old {
		if rs.stopFn != nil {
			rs.stopFn()
		}
	}

	started := 0
	var errs []string
	for _, host := range preset.Hosts {
		for _, svc := range host.Services {
			if err := m.StartService(host.IP, svc); err != nil {
				errs = append(errs, fmt.Sprintf("%s:%d (%s): %v", host.IP, svc.Port, svc.Protocol, err))
			} else {
				started++
			}
		}
	}

	// If every service in the target scenario failed, roll back to the previous scenario.
	if started == 0 && len(errs) > 0 {
		for _, host := range prevHosts {
			for _, svc := range host.Services {
				_ = m.StartService(host.IP, svc)
			}
		}
		m.cfg.Scenario = prevScenario
		m.cfg.Hosts = prevHosts
		return 0, errs
	}

	m.cfg.Scenario = preset.ID
	m.cfg.Hosts = preset.Hosts
	return started, errs
}

// UpdateCatchAll reconfigures Catch-All TCP/UDP ports dynamically.
func (m *Manager) UpdateCatchAll(cfg config.CatchAllConfig) error {
	m.cfg.CatchAll = cfg
	if !cfg.Enabled {
		m.catchAll.Stop()
		return nil
	}
	bindIP := "0.0.0.0"
	if len(m.cfg.Hosts) > 0 && m.cfg.Hosts[0].IP != "" {
		bindIP = m.cfg.Hosts[0].IP
	}
	return m.catchAll.Start(bindIP, cfg.TCPPorts, cfg.UDPPorts)
}

// Close shuts down all services, Catch-All listeners, and the gVisor/TUN stack cleanly.
func (m *Manager) Close() {
	if !m.closed.CompareAndSwap(false, true) {
		return
	}
	m.catchAll.Stop()
	m.mu.Lock()
	svcs := make([]*runningService, 0, len(m.services))
	for _, rs := range m.services {
		svcs = append(svcs, rs)
	}
	m.services = make(map[string]*runningService)
	m.mu.Unlock()

	for _, rs := range svcs {
		if rs.stopFn != nil {
			rs.stopFn()
		}
	}
	if m.vrouter != nil {
		m.vrouter.Close()
	}
	if m.stack != nil {
		m.stack.Close()
	}
	if closer, ok := m.device.(io.Closer); ok {
		_ = closer.Close()
	}
}

// ListRegisteredProtocols returns metadata for all protocols registered in the engine.
func ListRegisteredProtocols() []ProtocolDescriptor {
	all := protocols.ProtocolDetails()
	out := make([]ProtocolDescriptor, 0, len(all)+1)
	hasHTTPS := false
	for _, pi := range all {
		if pi.Name == "https" {
			hasHTTPS = true
		}
		transport := "tcp"
		if _, ok := pi.HandleFunc.(func(*protocols.UDPConnection, []byte) error); ok {
			transport = "udp"
		} else if _, ok := pi.HandleFunc.(protocols.UDPFunction); ok {
			transport = "udp"
		}
		if pi.DatagramHandler != nil && transport == "tcp" {
			transport = "tcp+udp"
		}
		params := map[string]interface{}{}
		for _, v := range pi.Params {
			params[v.Name] = v.DefaultValue
		}
		out = append(out, ProtocolDescriptor{
			Name:        pi.Name,
			DefaultPort: pi.DefaultPort,
			Transport:   transport,
			Params:      params,
		})
	}
	tlsEntries := []ProtocolDescriptor{
		{Name: "https", DefaultPort: 443, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "smtps", DefaultPort: 465, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "ldaps", DefaultPort: 636, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "ftps", DefaultPort: 990, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "imaps", DefaultPort: 993, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "pop3s", DefaultPort: 995, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "amqps", DefaultPort: 5671, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "winrms", DefaultPort: 5986, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
		{Name: "mqtts", DefaultPort: 8883, Transport: "tcp", Params: map[string]interface{}{"ssl": true}},
	}
	existing := map[string]bool{}
	for _, p := range out {
		existing[p.Name] = true
	}
	for _, te := range tlsEntries {
		if !existing[te.Name] {
			out = append(out, te)
		}
	}
	_ = hasHTTPS
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ipToAddress(ip net.IP) tcpip.Address {
	if ip == nil {
		return tcpip.AddrFrom4([4]byte{})
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.AddrFromSlice(v4)
	}
	return tcpip.AddrFromSlice(ip.To16())
}

func ipMaskToAddressMask(mask net.IPMask) tcpip.AddressMask {
	return tcpip.MaskFromBytes(mask)
}
