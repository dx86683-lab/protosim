package gossdp

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"
)

func TestSsdpResponseHeader(t *testing.T) {
	packet := createSsdpHeader("200 OK", map[string]string{"ST": "ssdp:all", "EXT": "", "LOCATION": "http://127.0.0.1/device.xml"}, true)
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(packet)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("ST") != "ssdp:all" {
		t.Fatalf("invalid response: %s", packet)
	}
	if _, ok := response.Header["Ext"]; !ok {
		t.Fatal("empty EXT header lost")
	}
	if !bytes.HasSuffix(packet, []byte("\r\n\r\n")) {
		t.Fatal("missing packet terminator")
	}
}

func TestSsdpNotifyHeader(t *testing.T) {
	packet := createSsdpHeader("NOTIFY", map[string]string{"HOST": "239.255.255.250:1900", "NTS": "ssdp:alive"}, false)
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(packet)))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Body.Close()
	if request.Method != "NOTIFY" || request.RequestURI != "*" || request.Host != "239.255.255.250:1900" || request.Header.Get("NTS") != "ssdp:alive" {
		t.Fatalf("invalid request: %s", packet)
	}
}
