package core

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type scriptedBatchReader struct {
	t       *testing.T
	offset  int
	packets [][][]byte
	calls   int
}

func (r *scriptedBatchReader) BatchSize() int { return 3 }

func (r *scriptedBatchReader) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	r.t.Helper()
	if len(bufs) != r.BatchSize() || len(sizes) != r.BatchSize() || offset != r.offset {
		r.t.Fatalf("invalid batch buffers=%d sizes=%d offset=%d", len(bufs), len(sizes), offset)
	}
	packets := r.packets[r.calls]
	r.calls++
	for i, packet := range packets {
		// Overwrite the complete reusable input slot, including headroom and tail.
		for j := range bufs[i] {
			bufs[i][j] = 0xee
		}
		copy(bufs[i][offset:], packet)
		sizes[i] = len(packet)
	}
	if r.calls == len(r.packets) {
		return len(packets), io.EOF
	}
	return len(packets), nil
}

type retainingDispatcher struct {
	packets   []*stack.PacketBuffer
	protocols []tcpip.NetworkProtocolNumber
}

func (d *retainingDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.packets = append(d.packets, pkt.IncRef())
	d.protocols = append(d.protocols, protocol)
}

func (*retainingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestBatchReadPreservesPacketsLengthsAndOffsets(t *testing.T) {
	for _, offset := range []int{0, 4, 16} {
		t.Run(map[int]string{0: "wintun", 4: "address-family-header", 16: "unix-gso"}[offset], func(t *testing.T) {
			packets := [][]byte{
				append([]byte{0x45}, bytes.Repeat([]byte{0x11}, 24)...),
				append([]byte{0x60}, bytes.Repeat([]byte{0x22}, 48)...),
				append([]byte{0x45}, bytes.Repeat([]byte{0x33}, 36)...),
				append([]byte{0x60}, bytes.Repeat([]byte{0x44}, 55)...),
			}
			r := &scriptedBatchReader{t: t, offset: offset, packets: [][][]byte{packets[:2], packets[2:]}}
			dispatcher := &retainingDispatcher{}
			ep := channel.New(8, 128, "")
			ep.Attach(dispatcher)
			defer func() {
				for _, pkt := range dispatcher.packets {
					pkt.DecRef()
				}
				ep.Close()
			}()
			if err := readPackets(r, 128, offset, ep); !errors.Is(err, io.EOF) {
				t.Fatalf("read error = %v, want EOF", err)
			}
			if len(dispatcher.packets) != len(packets) {
				t.Fatalf("delivered %d packets, want %d, including packets returned with EOF", len(dispatcher.packets), len(packets))
			}
			for i, pkt := range dispatcher.packets {
				// Read retained gVisor data after input slots were reused in the next batch.
				got := pkt.Data().AsRange().ToSlice()
				if !bytes.Equal(got, packets[i]) {
					t.Errorf("packet %d changed/truncated or includes offset/tail: got %x want %x", i, got, packets[i])
				}
				wantProtocol := header.IPv4ProtocolNumber
				if i%2 == 1 {
					wantProtocol = header.IPv6ProtocolNumber
				}
				if dispatcher.protocols[i] != wantProtocol {
					t.Errorf("packet %d protocol = %d, want %d", i, dispatcher.protocols[i], wantProtocol)
				}
			}
		})
	}
}
