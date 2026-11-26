package protocols

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestSSDPUnicastSearch(t *testing.T) {
	const uuid = "uuid:f276a12b-5187-41d8-82b7-297a6c4c8881"
	const device = "urn:fixture-invalid:device:Demo:2"
	const earlier = "urn:fixture-invalid:device:Demo:1"
	const man = "MAN: \"ssdp:discover\"\r\n"
	for _, test := range []struct {
		name, version, headers, target, usn string
	}{
		{"exact", "1.1", man + "ST: " + device + "\r\n", device, uuid + "::" + device},
		{"all", "1.1", man + "ST: ssdp:all\r\n", device, uuid + "::" + device},
		{"uuid", "1.1", man + "ST: " + uuid + "\r\n", uuid, uuid},
		{"older device version", "1.1", man + "ST: " + earlier + "\r\n", earlier, uuid + "::" + earlier},
		{"newer device version", "1.1", man + "ST: urn:fixture-invalid:device:Demo:3\r\n", "", ""},
		{"unmatched target", "1.1", man + "ST: upnp:rootdevice\r\n", "", ""},
		{"missing target", "1.1", man, "", ""},
		{"duplicate target", "1.1", man + "ST: " + device + "\r\nST: ssdp:all\r\n", "", ""},
		{"missing MAN", "1.1", "ST: " + device + "\r\n", "", ""},
		{"invalid MAN", "1.1", "MAN: ssdp:discover\r\nST: " + device + "\r\n", "", ""},
		{"HTTP 1.0", "1.0", man + "ST: " + device + "\r\n", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			binding := &BindInfo{Params: map[string]any{"dev_type": device, "dev_usn": uuid + "::" + device}}
			info := NewConfigInfo(server.LocalAddr().String(), binding, logrus.NewEntry(logger))
			packet := "M-SEARCH * HTTP/" + test.version + "\r\nHOST: 127.0.0.1:1900\r\n" + test.headers + "\r\n"
			if err := SSDP(NewUDPConnection(server, client.LocalAddr(), info), []byte(packet)); err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var buf [1024]byte
			n, _, err := client.ReadFrom(buf[:])
			if test.target == "" {
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					t.Fatalf("expected silence, got %q, %v", buf[:n], err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || response.Header.Get("ST") != test.target ||
				response.Header.Get("USN") != test.usn {
				t.Fatalf("unexpected response %q", buf[:n])
			}
		})
	}
}

type ssdpResponseCapture struct {
	net.PacketConn
	response []byte
}

func (c *ssdpResponseCapture) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.response = bytes.Clone(payload)
	return len(payload), nil
}

func TestSSDPMulticastSearch(t *testing.T) {
	for _, test := range []struct {
		name, host, mx string
		respond        bool
	}{
		{"valid", SSDPMulticastAddress + ":1900", "MX: 1\r\n", true},
		{"missing MX", SSDPMulticastAddress + ":1900", "", false},
		{"zero MX", SSDPMulticastAddress + ":1900", "MX: 0\r\n", false},
		{"duplicate MX", SSDPMulticastAddress + ":1900", "MX: 1\r\nMX: 2\r\n", false},
		{"unicast Host", "127.0.0.1:1900", "MX: 1\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			capture := new(ssdpResponseCapture)
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12000}
			info := NewConfigInfo("127.0.0.1:1900", &BindInfo{}, logrus.NewEntry(logger))
			request := "M-SEARCH * HTTP/1.1\r\nHOST: " + test.host + "\r\nMAN: \"ssdp:discover\"\r\n" +
				test.mx + "ST: upnp:rootdevice\r\n\r\n"
			if err := SSDPMulticast(NewUDPConnection(capture, peer, info), []byte(request)); err != nil {
				t.Fatal(err)
			}
			if got := bytes.HasPrefix(capture.response, []byte("HTTP/1.1 200 OK\r\n")); got != test.respond ||
				!test.respond && len(capture.response) != 0 {
				t.Fatalf("unexpected response %q", capture.response)
			}
		})
	}
}
