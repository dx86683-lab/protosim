package protocols

import (
	"encoding/binary"
	"errors"
	"io"
)

// Minimal BER support for the LDAP and SPNEGO handlers. Decoding is bounded
// and returns errors for malformed input instead of panicking.

const berMaxMessage = 1 << 20

var errBER = errors.New("malformed BER element")

type berElement struct {
	Tag      byte
	Value    []byte
	Children []berElement
}

func (e berElement) constructed() bool { return e.Tag&0x20 != 0 }

// readBERMessage reads one complete top-level element from r.
func readBERMessage(r io.Reader) ([]byte, error) {
	return readBERMessageLimit(r, berMaxMessage)
}

func readBERMessageLimit(r io.Reader, limit int) ([]byte, error) {
	var header [6]byte
	if n, err := io.ReadFull(r, header[:2]); err != nil {
		if n != 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	headerSize := 2
	length := int(header[1])
	if header[1]&0x80 != 0 {
		n := int(header[1] & 0x7f)
		if n == 0 || n > 4 {
			return nil, errBER
		}
		headerSize += n
		if _, err := io.ReadFull(r, header[2:headerSize]); err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		length = 0
		for _, b := range header[2:headerSize] {
			if length > limit>>8 {
				return nil, errBER
			}
			length = length<<8 | int(b)
		}
	}
	if length > limit {
		return nil, errBER
	}
	message := make([]byte, headerSize+length)
	copy(message, header[:headerSize])
	if _, err := io.ReadFull(r, message[headerSize:]); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return message, nil
}

func parseBER(data []byte, depth int) (berElement, []byte, error) {
	if depth > 32 || len(data) < 2 {
		return berElement{}, nil, errBER
	}
	tag, first := data[0], data[1]
	data = data[2:]
	length := int(first)
	if first&0x80 != 0 {
		n := int(first & 0x7f)
		if n == 0 || n > 4 || len(data) < n {
			return berElement{}, nil, errBER
		}
		length = 0
		for _, b := range data[:n] {
			length = length<<8 | int(b)
		}
		data = data[n:]
	}
	if length < 0 || length > len(data) {
		return berElement{}, nil, errBER
	}
	e := berElement{Tag: tag, Value: data[:length]}
	if e.constructed() {
		rest := e.Value
		for len(rest) > 0 {
			child, tail, err := parseBER(rest, depth+1)
			if err != nil {
				return berElement{}, nil, err
			}
			e.Children = append(e.Children, child)
			rest = tail
		}
	}
	return e, data[length:], nil
}

func decodeBER(data []byte) (berElement, error) {
	e, rest, err := parseBER(data, 0)
	if err == nil && len(rest) != 0 {
		err = errBER
	}
	return e, err
}

func berInt(e berElement) int {
	v := 0
	for i, b := range e.Value {
		if i == 0 && b&0x80 != 0 {
			v = -1
		}
		v = v<<8 | int(b)
	}
	return v
}

// berLength follows the reference encoder: short form up to 127, otherwise
// a long form of at least two length octets.
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		out := []byte{0x84, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[1:], uint32(n))
		return out
	}
}

func berTLV(tag byte, parts ...[]byte) []byte {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := append([]byte{tag}, berLength(size)...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func berIntBytes(tag byte, v int) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return berTLV(tag, b)
}
