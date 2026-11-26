package protocols

import (
	"encoding/binary"
	"unicode/utf16"
)

type tdsVersion struct {
	ack      uint32
	wideRows bool
}

type tdsLogin struct {
	user, password string
	version        tdsVersion
}

func parseTDSLogin(body []byte) (tdsLogin, bool) {
	le := binary.LittleEndian
	if len(body) < 86 || le.Uint32(body) != uint32(len(body)) || body[25]&0x80 != 0 {
		return tdsLogin{}, false
	}
	requested := body[7]
	fixedSize := 86
	version := tdsVersion{wideRows: true}
	if requested >= 0x72 {
		fixedSize = 94
	}
	if len(body) < fixedSize {
		return tdsLogin{}, false
	}
	switch requested {
	case 0x70:
		version = tdsVersion{ack: 0x07000000}
	case 0x71:
		version = tdsVersion{ack: 0x07010000}
	case 0x72:
		version.ack = 0x72090002
	case 0x73:
		version.ack = 0x730b0003
	case 0x74:
		version.ack = 0x74000004
	}
	user, ok := tdsLoginField(body, 40, fixedSize)
	if !ok {
		return tdsLogin{}, false
	}
	password, ok := tdsLoginField(body, 44, fixedSize)
	if !ok {
		return tdsLogin{}, false
	}
	for i, value := range password {
		value ^= 0xa5
		password[i] = value<<4 | value>>4
	}
	return tdsLogin{user: tdsDecodeText(user), password: tdsDecodeText(password), version: version}, true
}

func tdsLoginField(body []byte, field, fixedSize int) ([]byte, bool) {
	le := binary.LittleEndian
	offset, units := int(le.Uint16(body[field:])), int(le.Uint16(body[field+2:]))
	if units == 0 {
		return nil, true
	}
	if units > 128 || offset < fixedSize || offset > len(body) || units*2 > len(body)-offset {
		return nil, false
	}
	return body[offset : offset+units*2], true
}

func tdsText(text string) []byte {
	var out []byte
	for _, unit := range utf16.Encode([]rune(text)) {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return out
}

func tdsDecodeText(data []byte) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(units))
}

func tdsSessionReply(payload []byte) []byte {
	header := []byte{tdsReply, tdsEndMessage, 0, 0, 0, 57, 1, 0}
	binary.BigEndian.PutUint16(header[2:], uint16(len(payload)+len(header)))
	return append(header, payload...)
}

func tdsDone(payload []byte, wideRows bool) []byte {
	payload = append(payload, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0)
	if wideRows {
		payload = append(payload, 0, 0, 0, 0)
	}
	return payload
}

func tdsToken(payload []byte, tag byte, data []byte) []byte {
	payload = binary.LittleEndian.AppendUint16(append(payload, tag), uint16(len(data)))
	return append(payload, data...)
}

func tdsCountedText(payload []byte, text string) []byte {
	data := tdsText(text)
	return append(append(payload, byte(len(data)/2)), data...)
}

func tdsEnvironment(kind byte, current, previous string) []byte {
	return tdsCountedText(tdsCountedText([]byte{kind}, current), previous)
}

func tdsMessage(number uint32, state, severity byte, text, server string, wideRows bool) []byte {
	le := binary.LittleEndian
	message := tdsText(text)
	payload := append(le.AppendUint32(nil, number), state, severity)
	payload = append(le.AppendUint16(payload, uint16(len(message)/2)), message...)
	payload = append(tdsCountedText(payload, server), 0) // Empty procedure name.
	payload = le.AppendUint16(payload, 1)
	if wideRows {
		payload = append(payload, 0, 0)
	}
	return payload
}

func tdsLoginAccepted(server string, version tdsVersion) []byte {
	const infoServer = "ed3fca3d1dce" // The reference's fixed INFO token server label.
	payload := tdsToken(nil, 0xe3, tdsEnvironment(1, "master", "master"))
	payload = tdsToken(payload, 0xab, tdsMessage(5701, 2, 0, "Changed database context to 'master'.", infoServer, version.wideRows))
	payload = tdsToken(payload, 0xe3, []byte{7, 5, 9, 4, 0xd0, 0, 0x34, 0})
	payload = tdsToken(payload, 0xe3, tdsEnvironment(2, "us_english", ""))
	payload = tdsToken(payload, 0xab, tdsMessage(5703, 1, 0, "Changed language context to us_english.", infoServer, version.wideRows))
	ack := tdsCountedText(binary.BigEndian.AppendUint32([]byte{1}, version.ack), server)
	// MS-TDS 2.2.7.14: LOGINACK ends with a 4-byte ProgVersion (Major, Minor, BuildNumHi, BuildNumLow).
	ack = append(ack, 0x0f, 0x00, 0x00, 0x00)
	payload = tdsToken(payload, 0xad, ack)
	payload = tdsToken(payload, 0xe3, tdsEnvironment(4, "4096", "4096"))
	return tdsDone(payload, version.wideRows)
}

func tdsLoginRejected(user, server string, version tdsVersion) []byte {
	text := "Login failed for `" + user + "`"
	body := tdsMessage(18456, 1, 14, text, server, version.wideRows)
	// MS-TDS 2.2.7.10: ERROR token length is a 2-byte Little-Endian byte count.
	payload := tdsToken(nil, 0xaa, body)
	return tdsDone(payload, version.wideRows)
}
