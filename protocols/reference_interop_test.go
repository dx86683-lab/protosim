package protocols

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func TestReferenceTCPResponses(t *testing.T) {
	for _, tc := range []struct {
		name, request, expected string
	}{
		{"ssh", "", "SSH-2.0-OpenSSH_7.4\r\n"},
		{"redis", "*1\r\n$4\r\nPING\r\n", "+PONG\r\n"},
		{"mysql", "", "\x0a5.7.9\x00"},
		{"modbus", "\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00", "\x00\x01\x00\x00\x00\x2f\x01\x2b\x0e\x01\x82\x00\x00\x03\x00\x12Schneider Electric\x01\x0bATV630D22N4\x02\x040204"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle := referenceTCPHandler(t, tc.name)
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(3 * time.Second)
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)
			go handle(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
			if tc.request != "" {
				if _, err := io.WriteString(client, tc.request); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "mysql" {
				var header [4]byte
				if _, err := io.ReadFull(client, header[:]); err != nil {
					t.Fatal(err)
				}
				if header[3] != 0 || int(header[0])+int(header[1])<<8 < len(tc.expected) {
					t.Fatalf("invalid MySQL greeting header: %x", header)
				}
			}
			actual := make([]byte, len(tc.expected))
			if _, err := io.ReadFull(client, actual); err != nil {
				t.Fatal(err)
			}
			if string(actual) != tc.expected {
				t.Fatalf("received %x, want %x", actual, tc.expected)
			}
		})
	}
}

func TestReferenceDNSResponse(t *testing.T) {
	entry, ok := registor.Load("dns")
	if !ok {
		t.Fatal("dns is not registered")
	}
	bind := &BindInfo{}
	handle := entry.(*ProtocolInfo).DatagramHandler(bind)
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
	client.SetDeadline(time.Now().Add(time.Second))
	query, _ := hex.DecodeString("123401000001000000000000076578616d706c6504746573740000010001")
	if err := handle(NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{BindInfo: bind}), query); err != nil {
		t.Fatal(err)
	}
	var buf [512]byte
	n, _, err := client.ReadFrom(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("123481000001000000000001076578616d706c6504746573740000010001076578616d706c650474657374000010000100000000000100")
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("DNS reply %x; want %x", buf[:n], want)
	}
}

func TestReferenceMelsecqDefaultFrame(t *testing.T) {
	request, _ := hex.DecodeString("57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001")
	want, _ := hex.DecodeString("d700490000111107000000e40300ffff03000036009c000c08000000000304000000000101010000005131335544564350552020202020202020202041050008baba240201143531042002000000")
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	go handleMelsecqConnection(server, MelsecqDiscover_cpuType, discardMelsecqEvent)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	_, err := io.ReadFull(client, got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("response = %x, %v, want %x", got, err, want)
	}
}

func TestReferenceL2TPResponse(t *testing.T) {
	entry, ok := registor.Load("l2tp")
	if !ok {
		t.Fatal("l2tp is not registered")
	}
	handle := entry.(*ProtocolInfo).HandleFunc.(func(*UDPConnection, []byte) error)
	packet := func(encoded string) []byte {
		t.Helper()
		data, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	request := packet("c8020048000000000000000080080000000000018008000000020100800a00000003000000018012000000076578616d706c652e74657374800800000009000280080000000a0008")
	want := packet("c8020046000000000000000180080000000000028008000000020100800d000000074472617954656b0013000000084472617954656b2c206c327470800a0000000300000003")
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
	client.SetDeadline(time.Now().Add(time.Second))
	if err := handle(NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{BindInfo: &BindInfo{}}), request); err != nil {
		t.Fatal(err)
	}
	var buf [512]byte
	n, _, err := client.ReadFrom(buf[:])
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("L2TP reply %x, %v; want %x", buf[:n], err, want)
	}
}
