package protocols

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestReferenceSOCKS5NegotiationDoesNotSetDeadline(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deadlines := make(chan time.Time, 1)
	go serveSOCKS5(&SessionConnection{
		Conn:       observedDeadlineConn{Conn: server, deadline: deadlines},
		ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: map[string]any{"auth": false}}},
	})
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [2]byte{5, 0} {
		t.Fatalf("method selection = %x (%v)", reply, err)
	}
	select {
	case deadline := <-deadlines:
		if !deadline.IsZero() {
			t.Fatalf("SOCKS5 negotiation set a connection deadline: %v", deadline)
		}
	default:
	}
}

func TestReferenceSOCKS5Sessions(t *testing.T) {
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
	data, err := os.ReadFile("fixtures/reference-socks5.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { server.Close(); client.Close() })
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			go serveSOCKS5(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
				BindInfo: &BindInfo{Params: fixture.Listeners[test.Listener]},
			}})
			for _, step := range test.Steps {
				request, err := hex.DecodeString(step.Send)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Write(request); err != nil {
					t.Fatal(err)
				}
				want, err := hex.DecodeString(step.Receive)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatalf("after %x: %x, %v; want %x", request, got, err, want)
				}
				if len(want) >= 10 && bytes.Equal(want[:4], []byte{5, 0, 0, 1}) {
					clear(got[8:10])
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("after %x: %x; want %x", request, got, want)
				}
				if step.Closed {
					if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatalf("expected close after reply, got %d bytes and %v", n, err)
					}
				}
			}
		})
	}
}
