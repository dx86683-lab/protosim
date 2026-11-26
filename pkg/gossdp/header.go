package gossdp

import (
	"bytes"
	"fmt"
	"net/http"
)

// createSsdpHeader formats the response and NOTIFY packets documented in ssdp.go.
func createSsdpHeader(method string, fields map[string]string, response bool) []byte {
	var packet bytes.Buffer
	if response {
		fmt.Fprintf(&packet, "HTTP/1.1 %s\r\n", method)
	} else {
		fmt.Fprintf(&packet, "%s * HTTP/1.1\r\n", method)
	}
	headers := make(http.Header)
	for name, value := range fields {
		headers.Set(name, value)
	}
	headers.Write(&packet)
	packet.WriteString("\r\n")
	return packet.Bytes()
}
