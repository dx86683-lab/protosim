package protocols

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("ipp", IPP, 631))
}

// IPP implements RFC 8011 Internet Printing Protocol / CUPS HTTP endpoint (TCP 631).
func IPP(ci *ConfigInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
		_ = r.Body.Close()

		addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		fields := logrus.Fields{
			"method":       r.Method,
			"uri":          r.RequestURI,
			"content_type": r.Header.Get("Content-Type"),
		}

		w.Header().Set("Server", "CUPS/2.4 IPP/2.1")

		if r.Method == http.MethodPost && len(body) >= 8 {
			major, minor := body[0], body[1]
			opID := binary.BigEndian.Uint16(body[2:4])
			reqID := binary.BigEndian.Uint32(body[4:8])
			fields["ipp_version"] = major
			fields["ipp_minor"] = minor
			fields["operation_id"] = opID
			fields["request_id"] = reqID
			ci.LogWithRemote("ipp_request", addr, fields)

			var resp bytes.Buffer
			resp.Write([]byte{major, minor, 0x00, 0x00}) // status-code: successful-ok (0x0000)
			_ = binary.Write(&resp, binary.BigEndian, reqID)
			resp.WriteByte(0x01) // operation-attributes-tag
			writeIPPAttr(&resp, 0x47, "attributes-charset", "utf-8")
			writeIPPAttr(&resp, 0x48, "attributes-natural-language", "en-us")
			resp.WriteByte(0x04) // printer-attributes-tag
			writeIPPAttr(&resp, 0x45, "printer-uri-supported", "ipp://localhost:631/printers/Office_LaserJet")
			writeIPPAttr(&resp, 0x42, "printer-name", "Office_LaserJet")
			writeIPPAttr(&resp, 0x41, "printer-make-and-model", "HP LaserJet Pro M404dn")
			resp.WriteByte(0x03) // end-of-attributes-tag

			w.Header().Set("Content-Type", "application/ipp")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(resp.Bytes())
			return
		}

		ci.LogWithRemote("ipp_http_request", addr, fields)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE HTML><html><head><title>Home - CUPS 2.4.7</title></head><body><h1>CUPS 2.4.7</h1><p>Office_LaserJet (Idle)</p></body></html>"))
	})
}

func writeIPPAttr(buf *bytes.Buffer, tag byte, name, val string) {
	buf.WriteByte(tag)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(name)))
	buf.WriteString(name)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(val)))
	buf.WriteString(val)
}
