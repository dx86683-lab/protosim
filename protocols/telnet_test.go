package protocols

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTelnetLongPassword(t *testing.T) {
	password := strings.Repeat("x", 5100)
	input := password + "extra\n" + password + "\r\x00"
	reader := bufio.NewReader(strings.NewReader(input))
	if match, nul, err := readTelnetPassword(reader, password); err != nil || match || nul {
		t.Fatalf("overlong attempt returned match=%v, nul=%v, err=%v", match, nul, err)
	}
	if match, nul, err := readTelnetPassword(reader, password); err != nil || !match || !nul {
		t.Fatalf("configured long password returned match=%v, nul=%v, err=%v", match, nul, err)
	}
}

func TestReferenceTelnetSessions(t *testing.T) {
	var fixture struct {
		Listeners map[string]map[string]interface{}
		Cases     []struct {
			Name, Listener string
			Steps          []struct {
				Send, Receive string
				Closed        bool
			}
		}
	}
	data, err := os.ReadFile("fixtures/reference-telnet.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go serveTelnet(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
				BindInfo: &BindInfo{Params: fixture.Listeners[test.Listener]},
			}})
			for index, step := range test.Steps {
				request, err := hex.DecodeString(step.Send)
				if err != nil {
					t.Fatal(err)
				}
				if len(request) > 0 {
					if _, err := client.Write(request); err != nil {
						t.Fatal(err)
					}
				}
				want, err := hex.DecodeString(step.Receive)
				if err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(want))
				if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, want) {
					t.Fatalf("step %d: got %q (%v), want %q", index+1, reply, err, want)
				}
				if step.Closed {
					if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatalf("step %d: expected close, got %d bytes (%v)", index+1, n, err)
					}
				} else if len(want) == 0 {
					if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
						t.Fatal(err)
					}
					if n, err := client.Read(make([]byte, 1)); n != 0 || !os.IsTimeout(err) {
						t.Fatalf("step %d: expected an open, silent connection, got %d bytes (%v)", index+1, n, err)
					}
					if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
