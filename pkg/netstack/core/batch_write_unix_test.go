//go:build linux || darwin

package core

import (
	"bytes"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type capturingBatchDevice struct {
	t       *testing.T
	packets [][]byte
}

func (*capturingBatchDevice) DeviceType() string { return "test" }
func (*capturingBatchDevice) BatchSize() int     { return 3 }
func (*capturingBatchDevice) Read([][]byte, []int, int) (int, error) {
	return 0, io.EOF
}

func (d *capturingBatchDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.t.Helper()
	// NativeTun's Linux GSO path prepends a 10-byte virtio_net_hdr.
	if len(bufs) != 1 || offset < 10 {
		d.t.Fatalf("outbound batch=%d offset=%d, want one packet and at least ten bytes of headroom", len(bufs), offset)
	}
	for _, packet := range bufs {
		d.packets = append(d.packets, bytes.Clone(packet[offset:]))
	}
	return len(bufs), nil
}

func TestEndpointWritesBatchAPIWithUnixHeadroom(t *testing.T) {
	device := &capturingBatchDevice{t: t}
	ep := NewEndpoint(device, 128).(*Endpoint)
	defer ep.Close()
	var packets stack.PacketBufferList
	var want [][]byte
	for _, payload := range [][]byte{{1, 2, 3}, {4}, {5, 6, 7, 8}} {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 16, Payload: buffer.MakeWithData(payload)})
		copy(pkt.TransportHeader().Push(2), []byte{0xaa, 0xbb})
		copy(pkt.NetworkHeader().Push(2), []byte{0x45, 0xcc})
		packets.PushBack(pkt)
		want = append(want, append([]byte{0x45, 0xcc, 0xaa, 0xbb}, payload...))
		defer pkt.DecRef()
	}
	if n, err := ep.WritePackets(packets); n != len(want) || err != nil {
		t.Fatalf("WritePackets = (%d,%v)", n, err)
	}
	if len(device.packets) != len(want) {
		t.Fatalf("wrote %d packets, want %d", len(device.packets), len(want))
	}
	for i := range want {
		if !bytes.Equal(device.packets[i], want[i]) {
			t.Errorf("packet %d = %x, want %x", i, device.packets[i], want[i])
		}
	}
	// Notifications after the queue is drained must not dereference a nil packet.
	ep.WriteNotify()
}
