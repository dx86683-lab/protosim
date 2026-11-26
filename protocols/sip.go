package protocols

import (
	"bytes"
	"errors"
	"io"
	"net"
	"slices"
	"strings"

	siplog "github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/sirupsen/logrus"
)

// The SIP parser's diagnostics can include raw request headers. Use the
// structured protocol event below for observable fields.
var sipParserLog = func() siplog.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return siplog.NewLogrusLogger(logger, "sip", nil)
}()

var sipDatagramParser = func() *parser.PacketParser {
	base := parser.NewPacketParser(sipParserLog)
	compatible := parser.NewPacketParser(sipParserLog)
	// Apply the reference's address rule to each parsed header line. A
	// separate duplicate header can still be retained by the parser.
	for _, name := range []string{"via", "v", "from", "f", "to", "t", "contact", "m", "route", "record-route"} {
		compatible.SetHeaderParser(name, func(name, value string) ([]sip.Header, error) {
			headers, err := base.ParseHeader(name + ": " + value)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(headers, sipHeaderHasIPv6) {
				return nil, errors.New("unsupported SIP header address")
			}
			return sipLiteralHeaders(base, name, value, headers), nil
		})
	}
	return compatible
}()

func sipURIHasIPv6(uri sip.Uri) bool {
	return uri != nil && strings.Contains(uri.Host(), ":")
}

func sipHeaderHasIPv6(header sip.Header) bool {
	switch h := header.(type) {
	case sip.ViaHeader:
		return slices.ContainsFunc(h, func(hop *sip.ViaHop) bool { return strings.Contains(hop.Host, ":") })
	case *sip.FromHeader:
		return sipURIHasIPv6(h.Address)
	case *sip.ToHeader:
		return sipURIHasIPv6(h.Address)
	case *sip.ContactHeader:
		return sipURIHasIPv6(h.Address)
	case *sip.RouteHeader:
		return slices.ContainsFunc(h.Addresses, sipURIHasIPv6)
	case *sip.RecordRouteHeader:
		return slices.ContainsFunc(h.Addresses, sipURIHasIPv6)
	default:
		return false
	}
}

func replySIP(config *ConfigInfo, peer net.Addr, packet []byte, limit int, incompleteBody bool, write func([]byte) (int, error)) error {
	if line, _, ok := bytes.Cut(packet, []byte("\r\n")); ok && bytes.Contains(line, []byte(" * ")) {
		// The reference accepts the wildcard target. The parser requires a URI
		// there, and the simulated response does not use the target.
		packet = bytes.Replace(packet, []byte(" * "), []byte(" sip:fixture.invalid "), 1)
	}
	message, err := sipDatagramParser.ParseMessage(packet)
	if err != nil {
		return nil
	}
	request, ok := message.(sip.Request)
	if ok && sipURIHasIPv6(request.Recipient()) {
		return nil
	}
	if config.Log != nil {
		fields := make(map[string]string)
		for _, header := range message.Headers() {
			switch strings.ToLower(header.Name()) {
			case "authorization", "proxy-authorization":
				continue
			}
			fields[header.Name()] = header.Value()
		}
		config.LogWithRemote("new message", peer, map[string]interface{}{"header": fields})
	}
	if !ok {
		return nil
	}
	body := config.GetStringParams("body", "")
	status, reason := sip.StatusCode(200), "OK"
	if incompleteBody {
		status, reason, body = 400, "Bad Request", ""
	}
	if len(body) >= limit {
		return errors.New("simulated SIP body exceeds limit")
	}
	response := sip.NewResponse("", request.SipVersion(), status, reason, nil, "", nil)
	for _, key := range []string{"Record-Route", "Via", "From", "To", "Call-ID", "CSeq"} {
		sip.CopyHeaders(key, request, response)
	}
	response.SetBody(body, true)
	sip.CopyHeaders("Max-Forwards", request, response)
	for _, line := range config.GetStringsParams("headers", nil) {
		if header := sipConfiguredResponseHeader(line); header != nil {
			response.AppendHeader(header)
		}
	}
	wire := []byte(response.String())
	if len(wire) > limit {
		return errors.New("simulated SIP response exceeds transport limit")
	}
	n, err := write(wire)
	if err == nil && n != len(wire) {
		return io.ErrShortWrite
	}
	return err
}

func sipConfiguredResponseHeader(line string) *sip.GenericHeader {
	key, value, ok := strings.Cut(line, ": ")
	name := strings.TrimRight(key, " \t")
	if !ok || name == "" || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "l") {
		return nil
	}
	if strings.ContainsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-.!%*_+`'~", r))
	}) || strings.ContainsFunc(value, func(r rune) bool {
		return r < ' ' && r != '\t' || r == 127
	}) {
		return nil
	}
	// Keep the spelling and whitespace used by the listener configuration.
	return &sip.GenericHeader{HeaderName: key, Contents: value}
}
