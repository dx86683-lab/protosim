package protocols

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestReferenceModbusConfiguredIdentification(t *testing.T) {
	values := strings.Fields("v0 v1 v2 v3 v4 v5 v6 v7 v8")
	for _, tc := range []struct {
		length        int
		access, first byte
		response      string
	}{
		{3, 1, 0, "2b0e0181000003000276300102763102027632"},
		{7, 2, 3, "2b0e028200000403027633040276340502763506027636"},
		{9, 2, 3, "2b0e028300000403027633040276340502763506027636"},
		{9, 4, 6, "2b0e048300000106027636"},
		{9, 4, 7, "ab03"},
	} {
		got := modbusIdentification(tc.access, tc.first, values[:tc.length])
		if hex.EncodeToString(got) != tc.response {
			t.Errorf("%d objects, access %d, first %d: got %x, want %s", tc.length, tc.access, tc.first, got, tc.response)
		}
	}
}

func TestReferenceModbusIdentificationPagination(t *testing.T) {
	first := strings.Repeat("a", 88)
	second := strings.Repeat("b", 150)
	third := strings.Repeat("c", 82)
	info := []string{first, second, third}
	want := append([]byte{0x2b, 0x0e, 1, 0x81, 0xff, 2, 2, 0, 88}, first...)
	want = append(append(want, 1, 150), second...)
	page := modbusIdentification(1, 0, info)
	if !bytes.Equal(page, want) {
		t.Fatalf("first page = %d bytes, head %.12x; want %d bytes, head %.12x", len(page), page, len(want), want)
	}
	want = append([]byte{0x2b, 0x0e, 1, 0x81, 0, 0, 1, 2, 82}, third...)
	continuation := modbusIdentification(1, page[5], info)
	if !bytes.Equal(continuation, want) {
		t.Fatalf("continuation = %d bytes, head %.12x; want %d bytes, head %.12x", len(continuation), continuation, len(want), want)
	}
	info[2] = "cc"
	page = modbusIdentification(1, 0, info)
	if len(page) != modbusMaxPDU || page[4] != 0 || page[5] != 0 || page[6] != 3 || !bytes.Equal(page[249:], []byte{2, 2, 'c', 'c'}) {
		t.Fatalf("exact-fit page = %d bytes, head %.12x", len(page), page)
	}
	info[0] = strings.Repeat("a", 244)
	page = modbusIdentification(1, 0, info)
	if len(page) != modbusMaxPDU || page[4] != 0xff || page[5] != 1 || page[6] != 1 || string(page[9:]) != info[0] {
		t.Fatalf("full first-object page = %d bytes, head %.12x", len(page), page)
	}
}

func TestReferenceModbusReadEmptyFIFO(t *testing.T) {
	want := []byte{0x18, 0, 2, 0, 0}
	for _, address := range []byte{0, 9, 10, 14} {
		if got := modbusReply([]byte{0x18, 0, address}, nil); !bytes.Equal(got, want) {
			t.Errorf("Read FIFO at %d = %x, want %x", address, got, want)
		}
	}
	for _, address := range [][]byte{{0, 15}, {0xff, 0xff}} {
		if got := modbusReply(append([]byte{0x18}, address...), nil); len(got) != 0 {
			t.Errorf("out-of-range Read FIFO at %x = %x, want no response", address, got)
		}
	}
}

func TestReferenceModbusIdentificationObjectBudget(t *testing.T) {
	// Modbus V1.1b3: total PDU length must not exceed modbusMaxPDU (253 bytes):
	// 7-byte header + 2 bytes (id, len) per object + value bytes.
	for _, tc := range []struct {
		length               int
		access, next, number byte
	}{
		{244, 1, 1, 1}, // 7 + 2 + 244 = 253 (exact fit for first object)
		{245, 1, 0, 0}, // 7 + 2 + 245 = 254 > 253 (cannot fit first object)
		{244, 4, 0, 1}, // individual access fits 244-byte object
		{245, 4, 0, 0}, // individual access rejects 245-byte object
	} {
		info := []string{strings.Repeat("a", tc.length), "b", "c"}
		more := byte(0)
		if tc.next != 0 || tc.number == 0 {
			more = 0xff
		}
		want := []byte{0x2b, 0x0e, tc.access, 0x81, more, tc.next, tc.number}
		for id, value := range info[:tc.number] {
			want = append(want, byte(id), byte(len(value)))
			want = append(want, value...)
		}
		got := modbusIdentification(tc.access, 0, info)
		if !bytes.Equal(got, want) {
			t.Errorf("access %d, object size %d: got length %d, header %x; want length %d, header %x",
				tc.access, tc.length, len(got), got[:min(7, len(got))], len(want), want[:7])
		}
	}
}

func TestReferenceModbusReadFileRecords(t *testing.T) {
	listener := referenceTCPHandler(t, "modbus")
	requireReferenceTCPHandler(t, listener, nil, []referenceExchange{
		{"\x80\x01\x00\x00\x00\x0a\x02\x14\x07\x06\x00\x01\x00\x00\x00\x02", "\x80\x01\x00\x00\x00\x05\x02\x14\x07\x01\x06"},
		{"\x80\x02\x00\x00\x00\x11\x02\x14\x0e\x06\x00\x01\x00\x00\x00\x02\x06\x00\x02\x00\x00\x00\x01", "\x80\x02\x00\x00\x00\x07\x02\x14\x0b\x01\x06\x01\x06"},
		{"\x80\x03\x00\x00\x00\x0a\x02\x14\x07\x06\x00\x05\x00\x00\x00\x01", "\x80\x03\x00\x00\x00\x03\x02\x94\x02"},
		{"\x80\x04\x00\x00\x00\x02\x02\x07", "\x80\x04\x00\x00\x00\x03\x02\x07\x00"},
	})
}

func TestReferenceModbusCommunicationEventsAcrossConnections(t *testing.T) {
	const counterRequest = "\x90\x01\x00\x00\x00\x02\x01\x0b"
	const counterReply = "\x90\x01\x00\x00\x00\x06\x01\x0b\x00\x00\x00\x00"
	const logRequest = "\x90\x02\x00\x00\x00\x02\x01\x0c"
	const logReply = "\x90\x02\x00\x00\x00\x0a\x01\x0c\x07\x00\x00\x00\x01\x00\x02\x80"
	listener := referenceTCPHandler(t, "modbus")
	requireReferenceTCPHandler(t, listener, nil, []referenceExchange{{counterRequest, counterReply}})
	requireReferenceTCPHandler(t, listener, nil, []referenceExchange{{logRequest, logReply}})
	requireReferenceTCP(t, "modbus", nil, []referenceExchange{{counterRequest, counterReply}})
}
