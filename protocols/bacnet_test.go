package protocols

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestReferenceBACnetRequestEvents(t *testing.T) {
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(&output)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	config := &ConfigInfo{BindInfo: &BindInfo{}, Log: logger.WithField("protocol", "bacnet")}
	conn := NewUDPConnection(server, client.LocalAddr(), config)
	for _, tc := range []struct {
		wire, message string
		service       int
	}{
		{"810b000801001008", "unconfirmed_req", 8},
		{"810a001101040005010c0c023fffff194b", "confirmed_req", 12},
		{"810a001501040005200e0c020004d21e094d09781f", "confirmed_req", 14},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		output.Reset()
		if err := serveBACnet(conn, wire); err != nil {
			t.Fatal(err)
		}
		var event struct {
			Msg, Protocol, Transport string
			Type                     int
		}
		if err := json.Unmarshal(output.Bytes(), &event); err != nil {
			t.Fatalf("could not read BACnet event for service %d: %v", tc.service, err)
		}
		if event.Msg != tc.message || event.Protocol != "bacnet" || event.Transport != "udp" || event.Type != tc.service {
			t.Fatalf("unexpected BACnet event: %#v", event)
		}
	}
}

func TestBACnetAPDURequiresCompleteNetworkAddresses(t *testing.T) {
	for _, npdu := range [][]byte{
		{1, 0x20, 0, 32},          // Missing destination length.
		{1, 0x20, 0, 32, 4, 0x25}, // Incomplete destination address.
		{1, 0x08, 0, 7, 2, 0x22},  // Incomplete source address.
		{1, 0x20, 0, 32, 1, 0x25}, // Missing hop count.
	} {
		wire := binary.BigEndian.AppendUint16([]byte{0x81, 0x0a}, uint16(4+len(npdu)))
		if pdu := bacnetAPDU(append(wire, npdu...)); len(pdu) != 0 {
			t.Errorf("incomplete NPDU %x left APDU bytes %x", npdu, pdu)
		}
	}
}

func TestReferenceBACnetCharacterStringLengths(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		wire, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, tc := range []struct {
		length          int
		request, prefix string
	}{
		{3, "810a001101040005040c0c02007d03194d", "810b0017010030040c0c02007d03194d3e7400"},
		{4, "810a001101040005050c0c02007d04194d", "810b0019010030050c0c02007d04194d3e750500"},
		{252, "810a001101040005fd0c0c02007dfc194d", "810b0111010030fd0c0c02007dfc194d3e75fd00"},
		{253, "810a001101040005fe0c0c02007dfd194d", "810b0114010030fe0c0c02007dfd194d3e75fe00fe00"},
		{800, "810a001101040005270c0c02008020194d", "810b0337010030270c0c02008020194d3e75fe032100"},
		{4096, "810a001101040005410c0c02008d00194d", "810b1017010030410c0c02008d00194d3e75fe100100"},
	} {
		value := strings.Repeat("x", tc.length)
		params := map[string]any{"device_id": 32000 + tc.length, "vender_id": 42, "object_name": value}
		want := append(decode(tc.prefix), value...)
		want = append(want, 0x3f)
		requireReferenceDatagram(t, "bacnet", decode(tc.request), want, params)
	}
}

func TestReferenceBACnetConfiguredIdentifiers(t *testing.T) {
	requireReferenceDatagram(t, "bacnet",
		[]byte("\x81\x0b\x00\x08\x01\x00\x10\x08"),
		[]byte("\x81\x0b\x00\x16\x01\x00\x10\x00\xc4\x02\x00\x00\x01\x22\x05\xc4\x91\x03\x23\x01\x00\x00"),
		map[string]any{"device_id": 4194305, "vender_id": 65536})
	requireReferenceDatagram(t, "bacnet",
		[]byte("\x81\x0a\x00\x11\x01\x04\x00\x05\x01\x0c\x0c\x02\x00\x04\xd2\x19\x78"),
		[]byte("\x81\x0b\x00\x17\x01\x00\x30\x01\x0c\x0c\x02\x3f\xff\xff\x19\x78\x3e\x24\xff\xff\xff\xff\x3f"),
		map[string]any{"device_id": float64(-1), "vender_id": float64(-1)})
}
