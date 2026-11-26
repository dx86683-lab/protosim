package protocols

import (
	"bufio"
	"errors"
	"net/textproto"
	"strings"
)

func init() {
	AddProtocol(NewProtocolInfo("icap", serveICAP, 1344),
		ProtocolParams{Name: "headers", DefaultValue: icapHeaders},
		ProtocolParams{Name: "server", DefaultValue: icapService})
	AddProtocol(NewProtocolInfo("rtsp", newRTSPHandler, 554),
		ProtocolParams{Name: "server", DefaultValue: ""},
		ProtocolParams{Name: "headers", DefaultValue: []string{}})
	sip := NewProtocolInfo("sip", serveSIPTCP, 5060)
	sip.DatagramHandler = func(*BindInfo) UDPFunction { return serveSIP }
	AddProtocol(sip,
		ProtocolParams{Name: "body", DefaultValue: ""},
		ProtocolParams{Name: "headers", DefaultValue: []string{}})
}

type textRequest struct {
	method, target, version string
	headers                 textproto.MIMEHeader
}

const (
	rtspMaxTargetBytes      = 2047
	rtspMaxHeaderFields     = 255
	rtspMaxHeaderNameBytes  = 511
	rtspMaxHeaderValueBytes = 2047
)

func readRTSPRequest(reader *bufio.Reader) (textRequest, error) {
	wire, err := reader.ReadSlice('\r')
	if err != nil {
		return textRequest{}, err
	}
	line := string(wire[:len(wire)-1])
	next, err := reader.ReadByte()
	if err != nil {
		return textRequest{}, err
	}
	start := strings.Fields(line)
	if next != '\n' || len(start) != 3 || strings.Join(start, " ") != line || !validRTSPToken(start[0]) {
		return textRequest{}, errors.New("invalid RTSP request line")
	}
	if len(start[1]) > rtspMaxTargetBytes {
		return textRequest{}, errors.New("RTSP request target exceeds limit")
	}
	headers, err := readRTSPHeaders(reader)
	return textRequest{method: start[0], target: start[1], version: start[2], headers: headers}, err
}

func readRTSPHeaders(reader *bufio.Reader) (textproto.MIMEHeader, error) {
	headers := make(textproto.MIMEHeader)
	var key, value string
	for count := 0; ; count++ {
		wire, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		if len(wire) < 2 || wire[len(wire)-2] != '\r' {
			return nil, errors.New("RTSP headers require CRLF")
		}
		line := string(wire[:len(wire)-2])
		if line == "" {
			if key != "" {
				headers.Add(key, strings.Trim(value, " \t"))
			}
			return headers, nil
		}
		if count >= rtspMaxHeaderFields || !validRTSPHeaderValue(line) {
			return nil, errors.New("invalid RTSP header line")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if key == "" {
				return nil, errors.New("RTSP continuation without a field")
			}
			value += " " + strings.TrimLeft(line, " \t")
		} else {
			if key != "" {
				headers.Add(key, strings.Trim(value, " \t"))
			}
			var ok bool
			key, value, ok = strings.Cut(line, ":")
			if !ok || len(key) > rtspMaxHeaderNameBytes || !validRTSPToken(key) {
				return nil, errors.New("invalid RTSP header name")
			}
			value = strings.TrimLeft(value, " \t")
		}
		if len(value) > rtspMaxHeaderValueBytes {
			return nil, errors.New("RTSP header value exceeds limit")
		}
	}
}

func validRTSPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') &&
			!strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func validRTSPHeaderValue(value string) bool {
	for i := range len(value) {
		c := value[i]
		if c < ' ' && c != '\t' || c == 127 {
			return false
		}
	}
	return true
}

type textHeaderLimits struct {
	totalBytes, fields, nameBytes, valueBytes int
}

func readTextHeaders(reader *bufio.Reader, total int, limits textHeaderLimits, normalizeValue func(key, value string) string) (textproto.MIMEHeader, error) {
	headers := make(textproto.MIMEHeader)
	for count := 0; ; count++ {
		wire, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		total += len(wire)
		if limits.totalBytes > 0 && total > limits.totalBytes {
			return nil, errors.New("protocol headers exceed limit")
		}
		line := strings.TrimRight(string(wire), "\r\n")
		if line == "" {
			return headers, nil
		}
		if limits.fields > 0 && count >= limits.fields {
			return nil, errors.New("protocol header count exceeds limit")
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.ContainsAny(key, " \t\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("invalid protocol request header")
		}
		if limits.nameBytes > 0 && len(key) > limits.nameBytes ||
			limits.valueBytes > 0 && len(strings.TrimLeft(value, " ")) > limits.valueBytes {
			return nil, errors.New("protocol header field exceeds limit")
		}
		headers.Add(key, normalizeValue(key, value))
	}
}
