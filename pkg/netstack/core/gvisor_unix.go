//go:build linux || darwin

package core

import (
	"errors"
	"log"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Linux GSO needs a 10-byte virtio header; Darwin uses the last 4 bytes.
const unixPacketOffset = 16

// Device is a tun-like device for reading packets from system
type Device interface {
	// Reader is ...
	Reader
	// Writer is ...
	Writer
	// DeviceType is ...
	// give device type
	DeviceType() string
}

// Endpoint is ...
type Endpoint struct {
	// Endpoint is ...
	*channel.Endpoint
	// Reader is ...
	// read packets from tun device
	Reader Reader
	// Writer is ...
	// write packets to tun device
	Writer Writer

	mtu  int
	mu   sync.Mutex
	buff []byte
}

// NewEndpoint is ...
func NewEndpoint(dev Device, mtu int) stack.LinkEndpoint {
	wt, ok := dev.(Writer)
	if !ok {
		log.Panic(errors.New("not a valid tun for unix"))
	}
	rt, ok := dev.(Reader)
	if !ok {
		log.Panic(errors.New("not a valid tun for unix"))
	}
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(mtu), ""),
		Reader:   rt,
		Writer:   wt,
		mtu:      mtu,
		buff:     make([]byte, unixPacketOffset+mtu),
	}
	ep.Endpoint.AddNotify(ep)
	return ep
}

// Attach is to attach device to stack
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	if dispatcher != nil {
		go readPackets(e.Reader, e.mtu, unixPacketOffset, e.Endpoint)
	}
}

// WriteNotify is to write packets back to system
func (e *Endpoint) WriteNotify() {
	pkt := e.Endpoint.Read()
	if pkt == nil {
		return
	}
	defer pkt.DecRef()

	e.mu.Lock()
	buf := append(e.buff[:unixPacketOffset], pkt.NetworkHeader().Slice()...)
	buf = append(buf, pkt.TransportHeader().Slice()...)
	buf = append(buf, pkt.Data().AsRange().ToSlice()...)
	// Darwin returns packet count; the current Linux backend returns byte count.
	if n, err := e.Writer.Write([][]byte{buf}, unixPacketOffset); err != nil || n == 0 {
		log.Printf("TUN packet write failed: count=%d error=%v", n, err)
	}
	e.mu.Unlock()
}

// Writer is for Unix batch TUN writes with platform header space.
type Writer interface {
	// Write packets to tun device
	Write([][]byte, int) (int, error)
}
