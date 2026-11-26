package protocols

import (
	"strconv"
	"strings"

	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

// Keep the parser's validation and header ordering. A second parse protects
// percent spelling before formatting the header values used by the simulator.
func sipLiteralHeaders(base *parser.PacketParser, name, value string, headers []sip.Header) []sip.Header {
	literal := headers
	if strings.Contains(value, "%") {
		parsed, err := base.ParseHeader(name + ": " + strings.ReplaceAll(value, "%", "%25"))
		if err != nil || len(parsed) != len(headers) {
			return headers
		}
		literal = parsed
	}
	for i, header := range literal {
		original := headers[i].Value()
		rewriteSIPLiteralHeader(header)
		rendered := header.Value()
		if strings.ContainsAny(rendered, "\r\n\x00") {
			rendered = original
		}
		headers[i] = &sip.GenericHeader{HeaderName: header.Name(), Contents: rendered}
	}
	return headers
}

func rewriteSIPLiteralHeader(header sip.Header) {
	switch h := header.(type) {
	case sip.ViaHeader:
		for _, hop := range h {
			hop.Params = sipLiteralParameters(hop.Params)
		}
	case *sip.FromHeader:
		h.DisplayName = sipLiteralDisplay(h.DisplayName)
		h.Address = sipLiteralAddress(h.Address)
		h.Params = sipLiteralParameters(h.Params)
	case *sip.ToHeader:
		h.DisplayName = sipLiteralDisplay(h.DisplayName)
		h.Address = sipLiteralAddress(h.Address)
		h.Params = sipLiteralParameters(h.Params)
	case *sip.ContactHeader:
		h.DisplayName = sipLiteralDisplay(h.DisplayName)
		h.Address = sipLiteralAddress(h.Address)
		h.Params = sipLiteralParameters(h.Params)
	case *sip.RouteHeader:
		for i, address := range h.Addresses {
			h.Addresses[i] = sipLiteralAddress(address)
		}
	case *sip.RecordRouteHeader:
		for i, address := range h.Addresses {
			h.Addresses[i] = sipLiteralAddress(address)
		}
	}
}

func sipLiteralDisplay(display sip.MaybeString) sip.MaybeString {
	if name, ok := display.(sip.String); ok {
		// The parser leaves display names alone, including the protection
		// added to literal percent signs before re-parsing.
		return sip.String{Str: strings.ReplaceAll(name.Str, "%25", "%")}
	}
	return display
}

type sipLiteralURI struct{ sip.Uri }

func sipLiteralAddress(address sip.Uri) sip.Uri {
	if _, ok := address.(*sip.SipUri); ok {
		return sipLiteralURI{address}
	}
	return address
}

func (address sipLiteralURI) String() string {
	var out strings.Builder
	if address.IsEncrypted() {
		out.WriteString("sips:")
	} else {
		out.WriteString("sip:")
	}
	if user, ok := address.User().(sip.String); ok && user.Str != "" {
		out.WriteString(user.Str)
		if password, ok := address.Password().(sip.String); ok && password.Str != "" {
			out.WriteByte(':')
			out.WriteString(password.Str)
		}
		out.WriteByte('@')
	}
	out.WriteString(address.Host())
	if port := address.Port(); port != nil {
		out.WriteByte(':')
		out.WriteString(strconv.Itoa(int(*port)))
	}
	if params := address.UriParams(); params != nil && params.Length() != 0 {
		out.WriteByte(';')
		out.WriteString(sipLiteralParams{params}.ToString(';'))
	}
	if fields := address.Headers(); fields != nil && fields.Length() != 0 {
		out.WriteByte('?')
		out.WriteString(sipLiteralParams{fields}.ToString('&'))
	}
	return out.String()
}

type sipLiteralParams struct{ sip.Params }

func sipLiteralParameters(params sip.Params) sip.Params {
	if params == nil {
		return nil
	}
	return sipLiteralParams{params}
}

func (params sipLiteralParams) ToString(separator uint8) string {
	var out strings.Builder
	for i, key := range params.Keys() {
		if i != 0 {
			out.WriteByte(separator)
		}
		out.WriteString(key)
		value, _ := params.Get(key)
		if text, ok := value.(sip.String); ok {
			out.WriteByte('=')
			literal := text.Str
			if strings.ContainsAny(literal, " \t") && !(strings.HasPrefix(literal, "\"") && strings.HasSuffix(literal, "\"")) {
				literal = "\"" + strings.ReplaceAll(literal, "\"", "\\\"") + "\""
			}
			out.WriteString(literal)
		}
	}
	return out.String()
}
