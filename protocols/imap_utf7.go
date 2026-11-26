package protocols

import (
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"unicode/utf16"
)

const imapInvalidMailboxEncoding = " BAD utf7: invalid UTF-7\r\n"

var imapModifiedBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

func decodeIMAPMailboxName(wire string) (string, bool) {
	for _, char := range wire {
		if char < ' ' || char > '~' {
			return "", false
		}
	}
	if !strings.Contains(wire, "&") {
		return imapMailboxName(wire), true
	}

	var name strings.Builder
	previousShift := false
	for wire != "" {
		plain, shifted, escaped := strings.Cut(wire, "&")
		name.WriteString(plain)
		if !escaped {
			break
		}
		encoded, rest, terminated := strings.Cut(shifted, "-")
		if !terminated {
			return "", false
		}
		wire = rest
		if encoded == "" {
			name.WriteByte('&')
			previousShift = false
			continue
		}
		if previousShift && plain == "" {
			return "", false
		}
		data, err := imapModifiedBase64.DecodeString(encoded)
		if err != nil || len(data) == 0 || len(data)%2 != 0 {
			return "", false
		}
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(data[i*2:])
		}
		decoded := utf16.Decode(units)
		if !slices.Equal(utf16.Encode(decoded), units) {
			return "", false
		}
		for _, char := range decoded {
			if char >= ' ' && char <= '~' {
				return "", false
			}
			name.WriteRune(char)
		}
		previousShift = true
	}
	return imapMailboxName(name.String()), true
}

func encodeIMAPMailboxName(name string) string {
	var wire strings.Builder
	var shifted []byte
	flush := func() {
		if len(shifted) != 0 {
			wire.WriteByte('&')
			wire.WriteString(imapModifiedBase64.EncodeToString(shifted))
			wire.WriteByte('-')
			shifted = shifted[:0]
		}
	}
	for _, char := range name {
		if char < ' ' || char > '~' {
			if char <= 0xffff {
				shifted = binary.BigEndian.AppendUint16(shifted, uint16(char))
			} else {
				high, low := utf16.EncodeRune(char)
				shifted = binary.BigEndian.AppendUint16(shifted, uint16(high))
				shifted = binary.BigEndian.AppendUint16(shifted, uint16(low))
			}
			continue
		}
		flush()
		wire.WriteByte(byte(char))
		if char == '&' {
			wire.WriteByte('-')
		}
	}
	flush()
	return wire.String()
}
