package protocols

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	imapEnvelopeAddress = `((NIL NIL "contact" "example.org"))`
	imapEnvelope        = `("Wed, 11 May 2016 14:31:59 +0000" "A little message, just for you" ` +
		imapEnvelopeAddress + " " + imapEnvelopeAddress + " " + imapEnvelopeAddress + " " + imapEnvelopeAddress +
		` NIL NIL NIL "<0000000@localhost/>")`
	imapStructure  = `"text" "plain" () NIL NIL NIL 11 1`
	imapFetchLimit = 16 << 20
)

func imapFetchReply(tag, done, argument string, uid bool, messages []imapMessage) string {
	sequence, attributes, _ := strings.Cut(strings.TrimSpace(argument), " ")
	attributes = strings.TrimSpace(attributes)
	if sequence == "" || attributes == "" {
		return tag + " BAD No enough arguments\r\n"
	}
	indices, err := imapMatchingMessages(messages, sequence, uid)
	if err != nil {
		return tag + " BAD " + err.Error() + "\r\n"
	}
	var fields []string
	var hasUID bool
	for _, attribute := range imapFetchAttributes(attributes) {
		for _, field := range imapFetchMacro(attribute) {
			fields = append(fields, field)
			hasUID = hasUID || field == "UID"
		}
	}
	if uid && !hasUID {
		fields = append(fields, "UID")
	}
	var reply strings.Builder
	for _, index := range indices {
		fmt.Fprintf(&reply, "* %d FETCH (", index+1)
		for i, field := range fields {
			if i != 0 {
				reply.WriteByte(' ')
			}
			value := imapFetchField(field, &messages[index])
			if reply.Len()+len(value) > imapFetchLimit {
				return tag + " NO FETCH response too large\r\n"
			}
			reply.WriteString(value)
		}
		reply.WriteString(")\r\n")
	}
	return reply.String() + done
}

func imapFetchAttributes(input string) []string {
	if strings.HasPrefix(input, "(") && strings.HasSuffix(input, ")") {
		input = input[1 : len(input)-1]
	}
	var result []string
	words := strings.Fields(input)
	for i := 0; i < len(words); i++ {
		start := i
		if strings.Contains(words[i], "[") {
			for i+1 < len(words) && !strings.Contains(words[i], "]") {
				i++
			}
		}
		result = append(result, strings.ToUpper(strings.Trim(strings.Join(words[start:i+1], " "), `"`)))
	}
	return result
}

func imapFetchMacro(attribute string) []string {
	switch attribute {
	case "FAST":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}
	case "ALL":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}
	case "FULL":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}
	default:
		return []string{attribute}
	}
}

func imapFetchField(field string, message *imapMessage) string {
	switch field {
	case "UID":
		return fmt.Sprintf("UID %d", message.uid)
	case "FLAGS":
		return "FLAGS (" + strings.Join(message.flags, " ") + ")"
	case "RFC822.SIZE":
		return fmt.Sprintf("RFC822.SIZE %d", len(message.headers)+len(message.text))
	case "INTERNALDATE":
		return "INTERNALDATE \"" + message.date.Format("02-Jan-2006 15:04:05 -0700") + "\""
	case "ENVELOPE":
		return "ENVELOPE " + message.envelope()
	case "BODY":
		return "BODY (" + message.structure(false) + ")"
	case "BODYSTRUCTURE":
		return "BODYSTRUCTURE (" + message.structure(true) + ")"
	case "RFC822":
		return imapLiteral(field, message.headers+message.text)
	case "RFC822.HEADER":
		return imapLiteral(field, message.headers)
	case "RFC822.TEXT":
		return imapLiteral(field, message.text)
	}
	bodyField := strings.Replace(field, "BODY.PEEK[", "BODY[", 1)
	if sectionStart, ok := strings.CutPrefix(bodyField, "BODY["); ok {
		return imapFetchBody(bodyField, sectionStart, message)
	}
	return field + " NIL"
}

func imapFetchBody(field, spec string, message *imapMessage) string {
	section, suffix, ok := strings.Cut(spec, "]")
	if !ok {
		return field + " NIL"
	}
	var body string
	if section == "" {
		body = message.headers + message.text
	} else {
		part, spec := message.mimeRoot().section(section)
		if part == nil {
			return field + " NIL"
		}
		switch spec {
		case "", "TEXT":
			body = part.body
		case "HEADER", "MIME":
			body = part.headers
		default:
			kind, names, _ := strings.Cut(spec, " ")
			if kind != "HEADER.FIELDS" && kind != "HEADER.FIELDS.NOT" {
				return field + " NIL"
			}
			headers := strings.Fields(strings.Trim(names, "() "))
			prefix := strings.TrimSuffix(section, spec)
			if len(headers) == 0 {
				section, body = prefix+"HEADER", part.headers
			} else {
				section = prefix + kind + " (" + strings.Join(headers, " ") + ")"
				body = imapFilterHeaders(part.headers, headers, kind == "HEADER.FIELDS.NOT")
			}
		}
	}
	label := "BODY[" + section + "]"
	if suffix == "" {
		return imapLiteral(label, body)
	}
	if !strings.HasPrefix(suffix, "<") || !strings.HasSuffix(suffix, ">") {
		return field + " NIL"
	}
	offset, count, hasCount := strings.Cut(suffix[1:len(suffix)-1], ".")
	at, err := strconv.ParseUint(offset, 10, 32)
	if err != nil {
		return field + " NIL"
	}
	body = body[min(int64(at), int64(len(body))):]
	if hasCount {
		size, err := strconv.ParseUint(count, 10, 32)
		if err != nil {
			return field + " NIL"
		}
		body = body[:min(int64(size), int64(len(body)))]
	}
	return imapLiteral(fmt.Sprintf("%s<%d>", label, at), body)
}

func imapFilterHeaders(headers string, names []string, exclude bool) string {
	var result strings.Builder
	for _, line := range imapHeaderFields(headers) {
		name, _, _ := strings.Cut(line, ":")
		found := false
		for _, want := range names {
			found = found || strings.EqualFold(name, want)
		}
		if found != exclude {
			result.WriteString(line + "\r\n")
		}
	}
	return result.String() + "\r\n"
}

func imapLiteral(attribute, body string) string {
	return fmt.Sprintf("%s {%d}\r\n%s", attribute, len(body), body)
}

func imapSequenceMatch(sequence string, id uint32) (bool, error) {
	index := func(s string) (uint32, error) {
		if s == "*" {
			return 0, nil
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("imap: bad sequence set value %q", s)
		}
		return uint32(n), nil
	}
	var matched bool
	for _, item := range strings.Split(sequence, ",") {
		a, b, span := strings.Cut(item, ":")
		first, err := index(a)
		if err != nil {
			return false, err
		}
		if !span {
			matched = matched || first == id
			continue
		}
		last, err := index(b)
		if err != nil {
			return false, err
		}
		switch {
		case first == 0 || last == 0:
			matched = matched || max(first, last) != 0 && max(first, last) <= id
		default:
			matched = matched || min(first, last) <= id && id <= max(first, last)
		}
	}
	return matched, nil
}
