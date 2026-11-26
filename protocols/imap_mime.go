package protocols

import (
	"fmt"
	"maps"
	"mime"
	"slices"
	"strconv"
	"strings"
)

const (
	imapMIMEDepth = 16
	imapMIMEParts = 256
)

type imapMIMEPart struct {
	headers, body string
	mediaType     string
	subtype       string
	params        map[string]string
	parts         []*imapMIMEPart
	embedded      *imapMIMEPart
}

func (m *imapMessage) mimeRoot() *imapMIMEPart {
	if m.mime == nil {
		remaining := imapMIMEParts
		m.mime = parseIMAPMIME(m.headers, m.text, 0, &remaining)
	}
	return m.mime
}

func parseIMAPMIME(headers, body string, depth int, remaining *int) *imapMIMEPart {
	(*remaining)--
	value, params, _ := mime.ParseMediaType(imapHeaderValue(headers, "Content-Type"))
	kind, subtype, ok := strings.Cut(value, "/")
	if !ok {
		kind, subtype = "text", "plain"
	}
	part := &imapMIMEPart{headers: headers, body: body, mediaType: kind, subtype: subtype, params: params}
	if depth >= imapMIMEDepth || *remaining == 0 {
		return part
	}
	switch {
	case kind == "multipart" && params["boundary"] != "":
		imapVisitMIMEParts(body, params["boundary"], func(raw string) bool {
			h, b := imapSplitMessage(raw)
			part.parts = append(part.parts, parseIMAPMIME(h, b, depth+1, remaining))
			return *remaining > 0
		})
	case kind == "message" && subtype == "rfc822":
		h, b := imapSplitMessage(body)
		part.embedded = parseIMAPMIME(h, b, depth+1, remaining)
	}
	return part
}

// imapVisitMIMEParts retains the source bytes and excludes the CRLF that
// introduces each MIME boundary.
func imapVisitMIMEParts(body, boundary string, visit func(string) bool) {
	delimiter := "--" + boundary
	partStart := -1
	for offset := 0; offset < len(body); {
		line, _, hasNewline := strings.Cut(body[offset:], "\n")
		next := offset + len(line)
		if hasNewline {
			next++
		}
		marker := strings.TrimRight(line, "\r\t ")
		if marker == delimiter || marker == delimiter+"--" {
			if partStart >= 0 {
				raw := strings.TrimSuffix(body[partStart:offset], "\n")
				raw = strings.TrimSuffix(raw, "\r")
				if !visit(raw) {
					return
				}
			}
			if marker != delimiter {
				return
			}
			partStart = next
		}
		offset = next
	}
	if partStart >= 0 && partStart < len(body) {
		visit(body[partStart:])
	}
}

func imapSplitMessage(raw string) (headers, body string) {
	if body, ok := strings.CutPrefix(raw, "\r\n"); ok {
		return "\r\n", body
	}
	headers, body, found := strings.Cut(raw, "\r\n\r\n")
	if !found {
		return "", raw
	}
	return headers + "\r\n\r\n", body
}

func (p *imapMIMEPart) section(name string) (*imapMIMEPart, string) {
	for depth := 0; depth <= imapMIMEDepth; depth++ {
		number, rest, _ := strings.Cut(name, ".")
		if number == "" || number[0] < '0' || number[0] > '9' {
			return p, name
		}
		index, err := strconv.Atoi(number)
		if err != nil || index <= 0 {
			return nil, ""
		}
		if depth != 0 || len(p.parts) != 0 || index != 1 || p.mediaType == "multipart" {
			if index > len(p.parts) {
				return nil, ""
			}
			p = p.parts[index-1]
		}
		name = rest
	}
	return nil, ""
}

func (p *imapMIMEPart) structure(extended bool) string {
	if len(p.parts) != 0 {
		parts := make([]string, 0, len(p.parts)+4)
		for _, child := range p.parts {
			parts = append(parts, "("+child.structure(extended)+")")
		}
		parts = append(parts, strconv.Quote(p.subtype))
		if extended {
			parts = append(parts, imapMIMEParams(p.params), p.disposition(), "NIL", "NIL")
		}
		return strings.Join(parts, " ")
	}
	fields := fmt.Sprintf("%q %q %s %s %s %s %d", p.mediaType, p.subtype, imapMIMEParams(p.params),
		imapNString(imapHeaderValue(p.headers, "Content-ID")), imapNString(imapHeaderValue(p.headers, "Content-Description")),
		imapNString(imapHeaderValue(p.headers, "Content-Transfer-Encoding")), len(p.body))
	switch {
	case p.mediaType == "text":
		fields += fmt.Sprintf(" %d", strings.Count(p.body, "\n")+1)
	case p.embedded != nil:
		msg := imapMessage{headers: p.embedded.headers, text: p.embedded.body}
		lines := strings.Count(p.embedded.headers, "\n") + strings.Count(p.embedded.body, "\n") + 2
		fields += fmt.Sprintf(" %s (%s) %d", msg.envelope(), p.embedded.structure(extended), lines)
	}
	if extended {
		fields += " NIL " + p.disposition() + " NIL NIL"
	}
	return fields
}

func (p *imapMIMEPart) disposition() string {
	value, params, err := mime.ParseMediaType(imapHeaderValue(p.headers, "Content-Disposition"))
	if err != nil || value == "" {
		return "NIL"
	}
	return fmt.Sprintf("(%q %s)", value, imapMIMEParams(params))
}

func imapMIMEParams(params map[string]string) string {
	fields := make([]string, 0, len(params)*2)
	for _, key := range slices.Sorted(maps.Keys(params)) {
		fields = append(fields, strconv.Quote(key), strconv.Quote(params[key]))
	}
	return "(" + strings.Join(fields, " ") + ")"
}

// imapHeaderFields groups continuation lines with their original header.
func imapHeaderFields(headers string) []string {
	wire := strings.TrimSuffix(headers, "\r\n\r\n")
	if wire == "" || wire == "\r\n" {
		return nil
	}
	var fields []string
	start := 0
	for offset := 0; offset < len(wire); {
		n := strings.Index(wire[offset:], "\r\n")
		if n < 0 {
			break
		}
		end := offset + n
		offset = end + 2
		if offset == len(wire) || wire[offset] != ' ' && wire[offset] != '\t' {
			fields = append(fields, wire[start:end])
			start = offset
		}
	}
	if start < len(wire) {
		fields = append(fields, wire[start:])
	}
	return fields
}

func imapHeaderValue(headers, name string) string {
	for _, line := range imapHeaderFields(headers) {
		field, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(field, name) {
			return strings.TrimSpace(strings.ReplaceAll(value, "\r\n", ""))
		}
	}
	return ""
}
