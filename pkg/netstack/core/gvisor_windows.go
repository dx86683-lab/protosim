//go:build windows

package core

import (
	"errors"
	"io"
	"log"
	"sync"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is a tun-like device for reading packets from system
type Device interface {
	// Writer is ...
	io.Writer
	// DeviceType is ...
	// give device type
	DeviceType() string
}

// Endpoint is ...
type Endpoint struct {
	// Endpoint is ...
	*channel.Endpoint
	// Device is ...
	Device Device
	// Writer is ...
	Writer io.Writer

	mtu  int
	mu   sync.Mutex
	buff []byte
}

// NewEndpoint is ...
func NewEndpoint(dev Device, mtu int) stack.LinkEndpoint {
	wt, ok := dev.(io.Writer)
	if !ok {
		log.Panic(errors.New("not a valid device for windows"))
	}
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(mtu), ""),
		Device:   dev,
		Writer:   wt,
		mtu:      mtu,
		buff:     make([]byte, mtu),
	}
	ep.Endpoint.AddNotify(ep)
	return ep
}

// Attach is to attach device to stack
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)
	if dispatcher == nil {
		return
	}

	// WinDivert has no Reader
	r, ok := e.Device.(Reader)
	if !ok {
		wt, ok := e.Device.(io.WriterTo)
		if !ok {
			log.Panic(errors.New("not a valid device for windows"))
		}
		go func(w io.Writer, wt io.WriterTo) {
			if _, err := wt.WriteTo(w); err != nil {
				return
			}
		}((*endpoint)(unsafe.Pointer(e.Endpoint)), wt)
		return
	}
	// WinTun
	go readPackets(r, e.mtu, 0, e.Endpoint)
}

// WriteNotify is to write packets back to system
func (e *Endpoint) WriteNotify() {
	pkt := e.Endpoint.Read()
	if pkt == nil {
		return
	}
	defer pkt.DecRef()

	e.mu.Lock()
	buf := append(e.buff[:0], pkt.NetworkHeader().Slice()...)
	buf = append(buf, pkt.TransportHeader().Slice()...)
	buf = append(buf, pkt.Data().AsRange().ToSlice()...)
	e.Writer.Write(buf)
	e.mu.Unlock()
}

// endpoint is for WinDivert
// write packets from WinDivert to gvisor netstack
type endpoint struct {
	Endpoint channel.Endpoint
}

func pseudochecksum(bytes []byte) uint32 {
	SrcIP := bytes[12:16]
	DstIP := bytes[16:20]
	var csum uint32 = 0
	csum += (uint32(SrcIP[0]) + uint32(SrcIP[2])) << 8
	csum += uint32(SrcIP[1]) + uint32(SrcIP[3])
	csum += (uint32(DstIP[0]) + uint32(DstIP[2])) << 8
	csum += uint32(DstIP[1]) + uint32(DstIP[3])
	return csum
}

// Calculate the TCP/IP checksum defined in rfc1071.  The passed-in csum is any
// initial checksum data that's already been computed.
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

func tcpChecksum(tcpbuf []byte, ipbuf []byte) uint16 {
	tcpbuf[16] = 0
	tcpbuf[17] = 0

	length := uint32(len(tcpbuf))
	csum := pseudochecksum(ipbuf)
	csum += uint32(layers.IPProtocolTCP)
	csum += length & 0xffff
	csum += length >> 16
	return tcpipChecksum(tcpbuf, csum)
}

func ipv4hdrChecksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}

func dumpPktInfo(buf []byte) {
	p := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	ipv4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		log.Printf("%v:%d -> %v:%d", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)
		log.Printf("tcp checksum: %04x / %04x",
			tcpChecksum(append(tcp.Contents, tcp.Payload...), ipv4.Contents),
			tcp.Checksum)
	} else if udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		log.Printf("%v:%d -> %v:%d", ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort)
	}

	log.Printf("ip4 checksum: %04x / %04x",
		ipv4hdrChecksum(ipv4.LayerContents()),
		ipv4.Checksum)

	log.Println(p.Dump())
}

// Write is to write packet to stack
func (e *endpoint) Write(b []byte) (int, error) {
	buf := append(make([]byte, 0, len(b)), b...)

	switch header.IPVersion(buf) {
	case header.IPv4Version:
		// WinDivert: need to calculate chekcsum
		pkt := header.IPv4(buf)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^pkt.CalculateChecksum())
		switch ProtocolNumber := pkt.TransportProtocol(); ProtocolNumber {
		case header.UDPProtocolNumber:
			hdr := header.UDP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), hdr.Length())
			sum = checksum.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		case header.TCPProtocolNumber:
			hdr := header.TCP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), pkt.PayloadLength())
			sum = checksum.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		}
		pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf),
		})

		//dumpPktInfo(buf)

		e.Endpoint.InjectInbound(header.IPv4ProtocolNumber, pktBuffer)
		pktBuffer.DecRef()
	case header.IPv6Version:
		// WinDivert: need to calculate chekcsum
		pkt := header.IPv6(buf)
		switch ProtocolNumber := pkt.TransportProtocol(); ProtocolNumber {
		case header.UDPProtocolNumber:
			hdr := header.UDP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), hdr.Length())
			//sum = header.Checksum(hdr.Payload(), sum)
			sum = checksum.Combine(hdr.Checksum(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		case header.TCPProtocolNumber:
			hdr := header.TCP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), pkt.PayloadLength())
			//sum = header.Checksum(hdr.Payload(), sum)
			sum = checksum.Combine(hdr.Checksum(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		}
		pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf),
		})
		e.Endpoint.InjectInbound(header.IPv6ProtocolNumber, pktBuffer)
		pktBuffer.DecRef()
	}
	return len(buf), nil
}
