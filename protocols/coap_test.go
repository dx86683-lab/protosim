package protocols

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestReferenceCoAPConfiguredReplies(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "routes.json")
	const routes = `{"pages":[
		{"path":"/a","method":"GET","status":"Content","options":{"ContentFormat":"application/json","MaxAge":0},"body":"{\"mode\":\"a\"}"},
		{"path":"/f","method":"GET","status":"Content","options":{"ContentFormat":"application/json","MaxAge":31.75},"body":"age"},
		{"path":"/n","method":"GET","status":"Content","options":{"MaxAge":-1},"body":"age"},
		{"path":"/w","method":"GET","status":"Content","options":{"MaxAge":4294967296},"body":"age"},
		{"path":"/unknown-age","method":"GET","status":"Content","options":{"ContentFormat":"example/unknown","MaxAge":99},"body":"age"},
		{"path":"/lower-options","method":"GET","status":"Content","options":{"contentformat":"application/json","maxage":50},"body":"lower"}
	]}`
	if err := os.WriteFile(config, []byte(routes), 0600); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) []byte {
		t.Helper()
		data, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, tc := range []struct{ name, request, response string }{
		{"non-confirmable", "5101234c78b161", "5145234c78c13220ff7b226d6f6465223a2261227d"},
		{"acknowledgement-get", "6101234d78b161", "6145234d78c13220ff7b226d6f6465223a2261227d"},
		{"empty-reset", "7000234e", "6084234e"},
		{"unknown-media-with-max-age", "40012343bb756e6b6e6f776e2d616765", "60452343d10163ff616765"},
		{"case-sensitive-options", "40012344bd006c6f7765722d6f7074696f6e73", "60452344ff6c6f776572"},
		{"fractional-max-age", "40012349b166", "60452349c132211fff616765"},
		{"signed-max-age", "4001234ab16e", "6045234ad401ffffffffff616765"},
		{"wrapped-max-age", "4001234bb177", "6045234bd001ff616765"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireReferenceDatagram(t, "coap", decode(tc.request), decode(tc.response), map[string]any{"config_file": config})
		})
	}
	t.Run("missing-file", func(t *testing.T) {
		request := decode("40012341")
		fixture := roundTripDatagram(t, "coap", nil, request)
		requireReferenceDatagram(t, "coap", request, fixture, map[string]any{"config_file": filepath.Join(dir, "missing.json")})
	})
}

func TestCoAPControlRepliesAreTerminal(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	conn := NewUDPConnection(socket, socket.LocalAddr(), &ConfigInfo{BindInfo: &BindInfo{}})
	for _, packet := range []string{"\x60\x45\x23\x4f", "\x60\x84\x23\x50", "\x70\x45\x23\x51"} {
		if err := serveCoAP(conn, []byte(packet)); err != nil {
			t.Fatal(err)
		}
	}
	if err := socket.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := socket.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("control replies triggered a reply of %d bytes, error %v", n, err)
	}
}

func TestReferenceCoAPIncompleteConfigDiagnostic(t *testing.T) {
	config := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(config, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	conn := NewUDPConnection(nil, nil, &ConfigInfo{
		BindInfo: &BindInfo{Params: map[string]any{"config_file": config}},
	})
	err := serveCoAP(conn, []byte("\x60\x01\x23\x52"))
	if err == nil || err.Error() != "unexpected end of JSON input" {
		t.Fatalf("incomplete configuration returned %v", err)
	}
}

func TestReferenceCoAPInvalidOptionEvent(t *testing.T) {
	config := filepath.Join(t.TempDir(), "routes.json")
	const routes = `{"pages":[{"path":"/sensor","method":"POST","status":"Created","options":{"MaxAge":null},"body":"sample"}]}`
	if err := os.WriteFile(config, []byte(routes), 0600); err != nil {
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

	var output bytes.Buffer
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(&output)
	conn := NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{
		BindInfo: &BindInfo{Params: map[string]any{"config_file": config}},
		Log:      logger.WithField("protocol", "coap"),
	})
	request := []byte("\x51\x02\x23\x4dR\xb6sensor\xfflab\xff\x00v")
	if err := serveCoAP(conn, request); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := client.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("invalid option received %d response bytes, error %v", n, err)
	}
	var event struct {
		ID                                                    int
		Msg, Method, Path, Payload, Protocol, Type, Transport string
	}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.ID != 0x234d || event.Msg != "new message" || event.Method != "POST" || event.Path != "/sensor" ||
		event.Payload != "lab\ufffd\x00v" || event.Protocol != "coap" || event.Type != "NonConfirmable" || event.Transport != "udp" {
		t.Fatalf("unexpected CoAP event %#v", event)
	}
}
