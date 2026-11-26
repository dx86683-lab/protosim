package protocols

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestReferenceSIPDatagrams(t *testing.T) {
	type sipEvent struct {
		Msg    string
		Header map[string]string
	}
	var fixture struct {
		Listeners map[string]map[string]interface{}
		Cases     []struct {
			Name, Listener, Send string
			Receive              *string
			Events               []sipEvent
		}
	}
	data, err := os.ReadFile("fixtures/reference-sip.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
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
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&logs)
			logger.SetFormatter(&logrus.JSONFormatter{})
			config := &ConfigInfo{
				BindInfo: &BindInfo{Params: fixture.Listeners[test.Listener]},
				Log:      logrus.NewEntry(logger),
			}
			conn := NewUDPConnection(server, client.LocalAddr(), config)
			if err := serveSIP(conn, []byte(test.Send)); err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var buffer [8192]byte
			n, _, err := client.ReadFrom(buffer[:])
			switch {
			case test.Receive == nil:
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					t.Fatalf("expected silence, got %q (%v)", buffer[:n], err)
				}
			case err != nil || string(buffer[:n]) != *test.Receive:
				t.Fatalf("got %q (%v), want %q", buffer[:n], err, *test.Receive)
			}
			var events []sipEvent
			decoder := json.NewDecoder(&logs)
			for decoder.More() {
				var event sipEvent
				if err := decoder.Decode(&event); err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			if !slices.EqualFunc(events, test.Events, func(a, b sipEvent) bool {
				return a.Msg == b.Msg && maps.Equal(a.Header, b.Header)
			}) {
				t.Fatalf("events = %+v, want %+v", events, test.Events)
			}
		})
	}
}

func TestSIPConfiguredResponseHeaderRejectsFramingFields(t *testing.T) {
	for _, line := range []string{
		"Content-Length \t: 42",
		"L : 42",
		" X-Note: value",
		"X-Note: value\r\n",
		"X-Note: value\x00",
	} {
		if header := sipConfiguredResponseHeader(line); header != nil {
			t.Errorf("accepted configured header %q", line)
		}
	}
}

func TestReferenceSIPConfiguredResponseBody(t *testing.T) {
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

	const transaction = "Via: SIP/2.0/UDP ua.fixture.invalid;branch=z9hG4bK-fixture\r\n" +
		"From: <sip:alice@fixture.invalid>;tag=from01\r\n" +
		"To: <sip:bob@fixture.invalid>\r\n" +
		"Call-ID: body@fixture.invalid\r\nCSeq: 1 OPTIONS\r\n"
	request := []byte("OPTIONS sip:bob@fixture.invalid SIP/2.0\r\n" + transaction + "Content-Length: 0\r\n\r\n")
	for _, size := range []int{1201, 8192, 8193, 65000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := strings.Repeat("样", size/3) + strings.Repeat("x", size%3)
			config := &ConfigInfo{BindInfo: &BindInfo{Params: map[string]interface{}{"body": body}}}
			if err := serveSIP(NewUDPConnection(server, client.LocalAddr(), config), request); err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var receive [65535]byte
			n, _, err := client.ReadFrom(receive[:])
			if err != nil {
				t.Fatal(err)
			}
			want := "SIP/2.0 200 OK\r\n" + transaction + fmt.Sprintf("Content-Length: %d\r\n\r\n", size) + body
			if string(receive[:n]) != want {
				t.Fatalf("unexpected SIP response for %d-byte body, received %d bytes", size, n)
			}
		})
	}
}

func TestSIPTCPFramingAndReuse(t *testing.T) {
	protocol := GetProtocol("sip")
	if _, ok := protocol.HandleFunc.(func(*SessionConnection) error); !ok || protocol.DatagramHandler == nil {
		t.Fatal("SIP requires TCP and UDP handlers on one binding")
	}
	conn, stop := startRound6Server(t, round6Case{Handler: "sip"})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	const first = "OPTIONS sip:fixture.invalid SIP/2.0\r\nCall-ID: first@fixture.invalid\r\nCSeq: 1 OPTIONS\r\nl: 9000\r\n\r\n"
	const second = "OPTIONS sip:fixture.invalid SIP/2.0\r\nCall-ID: second@fixture.invalid\r\nCSeq: 2 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	for _, chunk := range []string{"\r\n" + first[:30], first[30:] + strings.Repeat("x", 1000), strings.Repeat("y", 8000) + second} {
		if _, err := io.WriteString(conn, chunk); err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range []string{"first", "second"} {
		want := fmt.Sprintf("SIP/2.0 200 OK\r\nCall-ID: %s@fixture.invalid\r\nCSeq: %d OPTIONS\r\nContent-Length: 0\r\n\r\n", id, i+1)
		data := make([]byte, len(want))
		if _, err := io.ReadFull(reader, data); err != nil || string(data) != want {
			t.Fatalf("reply %q, error %v, want %q", data, err, want)
		}
	}
}

func TestSIPDatagramBodyFraming(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "sip", UDP: true})
	defer stop()
	const headers = "OPTIONS sip:fixture.invalid SIP/2.0\r\nCall-ID: framing@fixture.invalid\r\nCSeq: 1 OPTIONS\r\n"
	for _, test := range []struct{ wire, status string }{
		{"Content-Length: 4\r\n\r\nab", "400 Bad Request"},
		{"l: 2\r\n\r\nabcdef", "200 OK"},
		{"X-Note: " + strings.Repeat("a", 1400) + "\r\nContent-Length: 0\r\n\r\n", "200 OK"},
	} {
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, headers+test.wire); err != nil {
			t.Fatal(err)
		}
		var packet [1024]byte
		n, err := conn.Read(packet[:])
		want := "SIP/2.0 " + test.status + "\r\nCall-ID: framing@fixture.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
		if err != nil || string(packet[:n]) != want {
			t.Fatalf("reply %q, error %v, want %q", packet[:n], err, want)
		}
	}
}
