package core

import (
	"fmt"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Reader receives batched packets after platform-specific header space.
// WinTun uses offset 0; Unix reserves room for virtio/address-family headers.
type Reader interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	BatchSize() int
}

// readPackets handles both Unix TUN headroom and WinTun's zero offset.
func readPackets(r Reader, mtu, offset int, ep *channel.Endpoint) error {
	batchSize := r.BatchSize()
	if batchSize < 1 || mtu < 1 || offset < 0 {
		return fmt.Errorf("invalid TUN read configuration: batch=%d mtu=%d offset=%d", batchSize, mtu, offset)
	}
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+offset)
	}
	for {
		n, err := r.Read(bufs, sizes, offset)
		if n < 0 || n > len(bufs) {
			return fmt.Errorf("TUN returned invalid packet count %d", n)
		}
		for i := 0; i < n; i++ {
			if sizes[i] < 0 || sizes[i] > len(bufs[i])-offset {
				return fmt.Errorf("TUN returned invalid packet size %d", sizes[i])
			}
			if sizes[i] == 0 {
				continue
			}
			packet := bufs[i][offset : offset+sizes[i]]
			protocol := header.IPv4ProtocolNumber
			switch header.IPVersion(packet) {
			case header.IPv4Version:
			case header.IPv6Version:
				protocol = header.IPv6ProtocolNumber
			default:
				continue
			}
			// MakeWithData copies into gVisor-owned storage before read slots are reused.
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
			ep.InjectInbound(protocol, pkt)
			pkt.DecRef()
		}
		// A final read may return packets together with an error; deliver them first.
		if err != nil {
			return err
		}
	}
}

// Logger is for showing logs of netstack
type Logger interface {
	Error(string, ...interface{})
	Info(string, ...interface{})
	Debug(string, ...interface{})
}

// Handler is for handling incoming TCP and UDP connections
type Handler interface {
	Handle(*TCPConn, *net.TCPAddr)
	HandlePacket(*UDPConn, *net.UDPAddr)
}

// timeoutError is how the net package reports timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// deadlineTimer is ...
type deadlineTimer struct {
	// mu protects the fields below.
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *deadlineTimer) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *deadlineTimer) readCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.readCancelCh
	d.mu.Unlock()
	return c
}
func (d *deadlineTimer) writeCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.writeCancelCh
	d.mu.Unlock()
	return c
}

// setDeadline contains the shared logic for setting a deadline.
//
// cancelCh and timer must be pointers to deadlineTimer.readCancelCh and
// deadlineTimer.readTimer or deadlineTimer.writeCancelCh and
// deadlineTimer.writeTimer.
//
// setDeadline must only be called while holding d.mu.
func (d *deadlineTimer) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	// Create a new channel if we already closed it due to setting an already
	// expired time. We won't race with the timer because we already handled
	// that above.
	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	// "A zero value for t means I/O operations will not time out."
	// - net.Conn.SetDeadline
	if t.IsZero() {
		return
	}

	timeout := time.Until(t)
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	// Timer.Stop returns whether or not the AfterFunc has started, but
	// does not indicate whether or not it has completed. Make a copy of
	// the cancel channel to prevent this code from racing with the next
	// call of setDeadline replacing *cancelCh.
	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

// SetReadDeadline implements net.Conn.SetReadDeadline and
// net.PacketConn.SetReadDeadline.
func (d *deadlineTimer) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline and
// net.PacketConn.SetWriteDeadline.
func (d *deadlineTimer) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// SetDeadline implements net.Conn.SetDeadline and net.PacketConn.SetDeadline.
func (d *deadlineTimer) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}
