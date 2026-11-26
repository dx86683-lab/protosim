package protocols

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

//go:embed fixtures/reference-vnc.json
var vncFixture []byte

type observedDeadlineConn struct {
	net.Conn
	deadline chan<- time.Time
}

func (c observedDeadlineConn) SetDeadline(deadline time.Time) error {
	select {
	case c.deadline <- deadline:
	default:
	}
	return c.Conn.SetDeadline(deadline)
}

func TestVNCHandshakeAllowsIdleClients(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deadline := make(chan time.Time, 1)
	go serveVNC(&SessionConnection{
		Conn:       observedDeadlineConn{Conn: server, deadline: deadline},
		ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}},
	})
	version := make([]byte, len(vncVersion))
	if _, err := io.ReadFull(client, version); err != nil || string(version) != vncVersion {
		t.Fatalf("version = %q (%v)", version, err)
	}
	select {
	case v := <-deadline:
		if !v.IsZero() {
			t.Fatalf("VNC handshake sets a deadline: %v", v)
		}
	default:
	}
}

func TestReferenceVNCDesktop(t *testing.T) {
	var fixture struct {
		Init   string   `json:"server_init"`
		Header string   `json:"frame_header"`
		Hashes []string `json:"frame_sha256"`
		Cases  []struct {
			Name, Challenge, Password, Answer, Failure string
			Version                                    int
		}
	}
	if err := json.Unmarshal(vncFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		t.Helper()
		data, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var params map[string]any
			if c.Password != "" {
				params = map[string]any{"password": c.Password, "challenge": c.Challenge}
			}
			conn, stop := startRound6Server(t, round6Case{Handler: "vnc", Params: params})
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			read := func(expected []byte) {
				t.Helper()
				reply := make([]byte, len(expected))
				if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, expected) {
					t.Fatalf("reply %x (%v), want %x", reply, err, expected)
				}
			}
			write := func(packet []byte) {
				t.Helper()
				if _, err := conn.Write(packet); err != nil {
					t.Fatal(err)
				}
			}
			read([]byte("RFB 003.008\n"))
			write([]byte(fmt.Sprintf("RFB 003.%03d\n", c.Version)))
			if c.Version < 7 {
				read([]byte{0, 0, 0, 2})
			} else {
				read([]byte{1, 2})
				write([]byte{2})
			}
			read([]byte(c.Challenge))
			write(decode(c.Answer))
			switch c.Failure {
			case "closed":
				// RFC 6143 §7.1.3: RFB 3.3 and 3.7 send 4-byte SecurityResult=1 on failure.
				read([]byte{0, 0, 0, 1})
				return
			case "":
			default:
				read(decode(c.Failure))
				return
			}
			read([]byte{0, 0, 0, 0})
			write([]byte{1})
			read(decode(fixture.Init))
			write(decode("02000001000000070000000010100001001f003f001f0b0500000000"))
			write([]byte{3, 0, 0, 1, 0, 2, 0, 3, 0, 2})
			pixels := make([]byte, 800*600*4)
			for _, expected := range fixture.Hashes {
				read(decode(fixture.Header))
				if _, err := io.ReadFull(conn, pixels); err != nil {
					t.Fatal(err)
				}
				if digest := sha256.Sum256(pixels); hex.EncodeToString(digest[:]) != expected {
					t.Fatalf("frame hash = %x, want %s", digest, expected)
				}
			}
		})
	}
}
