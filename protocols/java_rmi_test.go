package protocols

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRMILookupSerializesRemoteReference(t *testing.T) {
	for _, test := range []struct {
		name, object, host, wantInterface string
		interfaces                        uint32
		longBlock                         bool
	}{
		{"default JMX interface", "javax.management.remote.rmi.RMIServerImpl_Stub", "172.17.17.1", "javax.management.remote.rmi.RMIServer", 2, false},
		{"remote interface once", "java.rmi.Remote", "127.0.0.1", "java.rmi.Remote", 1, false},
		{"long endpoint", "java.rmi.registry.Registry", strings.Repeat("z", 230) + ".invalid", "java.rmi.registry.Registry", 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := rmiLookupReturn(rmiService{Object: test.object, IP: test.host, Port: 19039})
			descriptor := bytes.Index(wire, []byte{0x73, 0x7d})
			if descriptor < 0 || binary.BigEndian.Uint32(wire[descriptor+2:]) != test.interfaces ||
				!bytes.Contains(wire, javaUTF(test.wantInterface)) {
				t.Errorf("result must declare %d interfaces including %s", test.interfaces, test.wantInterface)
			}
			ref := bytes.Index(wire, javaUTF("UnicastRef"))
			if ref < 5 {
				t.Fatal("missing UnicastRef")
			}
			var length int
			if test.longBlock && wire[ref-5] == 0x7a {
				length = int(binary.BigEndian.Uint32(wire[ref-4:]))
			} else if !test.longBlock && wire[ref-2] == 0x77 {
				length = int(wire[ref-1])
			}
			if want := len(wire) - ref - 1; length != want || wire[len(wire)-1] != 0x78 {
				t.Errorf("block length = %d, want %d before end marker", length, want)
			}
		})
	}
}

func TestRMIUnknownLookupKeepsRegistryConnection(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go serveJavaRMI(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "JRMI\x00\x05L"); err != nil {
		t.Fatal(err)
	}
	var control [1]byte
	if _, err := io.ReadFull(client, control[:]); err != nil || control[0] != 'N' {
		t.Fatalf("handshake %x, %v", control, err)
	}
	call := append([]byte{0x50, 0xac, 0xed, 0, 5, 0x77, 0x22}, make([]byte, 22)...)
	call = binary.BigEndian.AppendUint32(call, 2)
	call = binary.BigEndian.AppendUint64(call, 4905912898345647071)
	call = append(append(call, 0x74), javaUTF("absent-fixture")...)
	if _, err := client.Write(call); err != nil {
		t.Fatal(err)
	}
	var reply [401]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 0x51 || reply[7] != 2 ||
		!bytes.Contains(reply[:], javaUTF("java.rmi.NotBoundException")) {
		t.Fatalf("unexpected missing-name return: prefix %x, error %v", reply[:8], err)
	}
	if _, err := client.Write([]byte{rmiPing}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, control[:]); err != nil || control[0] != 0x53 {
		t.Fatalf("registry connection after missing lookup: %x, %v", control, err)
	}
}

func TestRMIRegistryRetainsFirstSuccessfulConfiguration(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	write := func(path, document string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(document), 0600); err != nil {
			t.Fatal(err)
		}
	}

	var cache rmiRegistryCache
	write(first, "{")
	if _, err := cache.load(first); err == nil {
		t.Fatal("invalid JSON loaded as the registry")
	}
	write(first, `{"services":[]}`)
	initial, err := cache.load(first)
	if err != nil || len(initial) != 0 {
		t.Fatalf("load the empty registry: %v, %v", initial, err)
	}

	write(second, `{"services":[{"name":"second","object":"java.rmi.Remote","ip":"192.0.2.4","port":1099}]}`)
	write(first, `{"services":[{"name":"replacement","object":"java.rmi.Remote","ip":"192.0.2.5","port":1099}]}`)
	for _, path := range []string{second, first, filepath.Join(dir, "missing.json")} {
		got, err := cache.load(path)
		if err != nil || !reflect.DeepEqual(got, initial) {
			t.Fatalf("registry changed when reading %s: %v, %v", filepath.Base(path), got, err)
		}
	}
	write(second, "{")
	if _, err := cache.load(second); err == nil {
		t.Fatal("an invalid listener configuration passed validation after the registry was cached")
	}
}

func TestReferenceRMIHandshakeReadBoundary(t *testing.T) {
	const header = "JRMI\x00\x05L"
	const ping = "\x52"
	for _, tc := range []struct {
		name, first, tail         string
		closeOnFirst, replyToTail bool
	}{
		{"coalesced", header + ping, "", false, false},
		{"before_magic", header[:3], "", true, false},
		{"after_magic", header[:4], header[4:] + ping, false, false},
		{"after_version", header[:6], header[6:] + ping, false, false},
		{"request_after_magic", header[:4], "", false, false},
		{"stream_empty_endpoint", "JRMI\x00\x05K", "\x00\x00\x00\x00\x00\x00" + ping, false, false},
		{"stream_named_endpoint", "JRMI\x00\x05K", "\x00\x09" + "127.0.0.1" + "\x00\x00\x04\x4b" + ping, false, false},
		{"coalesced_pings", header, ping + ping, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			go serveJavaRMI(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(client, tc.first); err != nil {
				t.Fatal(err)
			}
			var response [1]byte
			_, err := io.ReadFull(client, response[:])
			if tc.closeOnFirst {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("short handshake returned %v, want EOF", err)
				}
				return
			}
			if err != nil || response[0] != 'N' {
				t.Fatalf("handshake acknowledgement = %x, %v", response, err)
			}
			if tc.tail != "" {
				if _, err := io.WriteString(client, tc.tail); err != nil {
					t.Fatal(err)
				}
			}
			if tc.replyToTail {
				if _, err := io.ReadFull(client, response[:]); err != nil || response[0] != 0x53 {
					t.Fatalf("first ping response = %x, %v", response, err)
				}
			}
			if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Read(response[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("unexpected response after acknowledgement: %x, %v", response, err)
			}
			if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(client, ping); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(client, response[:]); err != nil || response[0] != 0x53 {
				t.Fatalf("subsequent ping response = %x, %v", response, err)
			}
		})
	}
}
