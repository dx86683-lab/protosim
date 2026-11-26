package protocols

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestReferenceMelsecqModelConfiguration(t *testing.T) {
	request, err := hex.DecodeString("57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		params map[string]interface{}
		model  string
	}{
		{"default", nil, "Q13UDVCPU"},
		{"advertised_key", map[string]interface{}{"cpu_type": "Q03UDVCPU"}, "Q13UDVCPU"},
		{"version", map[string]interface{}{"version": "Q03UDVCPU"}, "Q03UDVCPU"},
		{"conflicting_keys", map[string]interface{}{"version": "Q03UDVCPU", "cpu_type": "Q02UDVCPU"}, "Q03UDVCPU"},
		{"empty_version", map[string]interface{}{"version": "", "cpu_type": "Q03UDVCPU"}, "Q13UDVCPU"},
		{"short_version", map[string]interface{}{"version": "Q"}, "Q"},
		{"long_version", map[string]interface{}{"version": "CPU-01234567890123456789"}, "CPU-01234567890123456789"},
		{"unicode_version", map[string]interface{}{"version": "Q06 模拟 CPU 型号"}, "Q06 模拟 CPU 型号"},
		{"leading_space", map[string]interface{}{"version": " CPU test"}, " CPU test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			go MelsecqDiscover(&ListenConnection{Listener: listener, ConfigInfo: NewConfigInfo(
				"", &BindInfo{Params: tc.params}, logrus.NewEntry(logger),
			)})
			conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			want := "d700490000111107000000e40300ffff03000036009c000c0800000000030400000000010101000000" +
				hex.EncodeToString([]byte(tc.model+"          ")) + "41050008baba240201143531042002000000"
			if got := hex.EncodeToString(reply); got != want {
				t.Fatalf("response = %s, want %s", got, want)
			}
		})
	}
}

func TestMelsecqClosesHandledConnection(t *testing.T) {
	for _, tc := range []struct {
		name, request string
		responds      bool
	}{
		{"valid_query", "57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001", true},
		{"minimum_read", "787878787878787878787878787878787878787878787878787878787878787878787878", true},
		{"short_packet", "5700", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { server.Close(); client.Close() })
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			var messages []string
			var requestFields map[string]interface{}
			go func() {
				err := handleMelsecqConnection(server, MelsecqDiscover_cpuType, func(message string, fields map[string]interface{}) {
					messages = append(messages, message)
					if message == "req command" {
						requestFields = fields
					}
				})
				done <- err
			}()
			request, err := hex.DecodeString(tc.request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			if tc.responds {
				for i := 0; i < 2; i++ {
					response := make([]byte, 78)
					if _, err := io.ReadFull(client, response); err != nil {
						t.Fatal(err)
					}
					if !bytes.HasPrefix(response, []byte{0xd7, 0x00, 0x49, 0x00}) || !bytes.Contains(response, []byte("Q13UDVCPU")) {
						t.Fatalf("unexpected MELSECQ response: %x", response)
					}
					if i == 0 {
						if _, err := client.Write(request); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := client.Write(bytes.Repeat([]byte{'x'}, 35)); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("connection handler did not return")
			}
			wantMessages := []string{"invalid packet"}
			if tc.responds {
				wantMessages = []string{"req command", "req command", "invalid packet"}
			}
			if !reflect.DeepEqual(messages, wantMessages) {
				t.Fatalf("events = %v, want %v", messages, wantMessages)
			}
			if tc.name == "valid_query" {
				want := map[string]interface{}{
					"header": "57", "frame_type": "DatatranslationRequest",
					"access_type":  "E71 Mounting Station (Local Station)",
					"request_type": "Request Target Module I/O Number", "command": "0101",
					"command_type": "[MCCPU Model Reading]", "raw_data": "0000000001",
				}
				if !reflect.DeepEqual(requestFields, want) {
					t.Fatalf("request event = %v, want %v", requestFields, want)
				}
			}
			client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("handled connection remains open: got %v, want EOF", err)
			}
		})
	}
}

func TestMelsecqClosesConnectionAfterIOError(t *testing.T) {
	for _, scenario := range []string{"read_timeout", "write_timeout"} {
		t.Run(scenario, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { server.Close(); client.Close() })
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			if scenario == "read_timeout" {
				server.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			} else {
				server.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			done := make(chan error, 1)
			go func() {
				err := handleMelsecqConnection(server, MelsecqDiscover_cpuType, discardMelsecqEvent)
				done <- err
			}()
			if scenario == "write_timeout" {
				request, err := hex.DecodeString("57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Write(request); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if scenario == "write_timeout" && err == nil {
					t.Fatal("expected fixture write timeout")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("connection handler did not return after I/O error")
			}
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("connection remains open after I/O error: %v", err)
			}
		})
	}
}

func discardMelsecqEvent(string, map[string]interface{}) {}
