package protocols

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/sirupsen/logrus"
)

const (
	tnsVersionNumber  = "186647040"
	tnsDefaultBanner  = "x86_64/Linux 2.4.xx"
	tnsDefaultVersion = "Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production"
)

var tnsDefaultSIDs = []string{"ORCL", "XE", "oracle"}

//go:embed fixtures/tns-negotiation.json
var tnsNegotiationFixture []byte

var tnsNegotiation = loadTNSNegotiation()

func loadTNSNegotiation() map[string][]byte {
	var encoded map[string]string
	if err := json.Unmarshal(tnsNegotiationFixture, &encoded); err != nil {
		panic(err)
	}
	payloads := make(map[string][]byte, len(encoded))
	for _, name := range []string{"ano", "protocol", "types", "types_tail"} {
		payload, err := hex.DecodeString(encoded[name])
		if err != nil || len(payload) == 0 {
			panic("invalid TNS negotiation fixture: " + name)
		}
		payloads[name] = payload
	}
	return payloads
}

func init() {
	AddProtocol(NewProtocolInfo("tns", serveTNS, 1521),
		ProtocolParams{Name: "sids", DefaultValue: tnsDefaultSIDs},
		ProtocolParams{Name: "accounts", DefaultValue: []string{"system:oracle"}},
		ProtocolParams{Name: "newmode", DefaultValue: false},
		ProtocolParams{Name: "VSNNUM", DefaultValue: tnsVersionNumber},
		ProtocolParams{Name: "banner", DefaultValue: tnsDefaultBanner},
		ProtocolParams{Name: "version", DefaultValue: tnsDefaultVersion})
}

func serveTNS(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	version := session.GetStringParams("vsnnum", session.GetStringParams("VSNNUM", tnsVersionNumber))
	banner := session.GetStringParams("banner", tnsDefaultBanner)
	if len(banner) > 256 || strings.ContainsRune(banner, 0) {
		return errors.New("invalid TNS platform banner")
	}
	modern := session.GetBoolParams("newmode")
	sids := session.GetStringsParams("sids", tnsDefaultSIDs)
	resent := false
	for {
		kind, content, err := readTNSFrame(session.Conn, modern)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch kind {
		case 1:
			descriptor, err := tnsConnectDescriptor(session.Conn, modern, content)
			if err != nil {
				return err
			}
			parts := tnsParameters(descriptor)
			var service string
			var hasService bool
			if len(parts) != 0 && parts[0].key == "DESCRIPTION" {
				service, hasService = tnsDescriptorService(parts[0].value)
				if hasService && service == "" {
					return nil
				}
			}
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "data", logrus.Fields{"ConnectDescriptor": descriptor})
			if len(parts) == 0 {
				continue
			}
			switch root := parts[0]; root.key {
			case "CONNECT_DATA":
				if tnsVersionCommand(root.value) {
					err = writeTNSRefusal(session.Conn, modern, version, 1189)
				}
			case "DESCRIPTION":
				if !hasService {
					continue
				}
				known := false
				for _, sid := range sids {
					known = known || strings.EqualFold(sid, service)
				}
				switch {
				case !known:
					err = writeTNSRefusal(session.Conn, modern, version, 12514)
				case !resent:
					resent = true
					err = writeTNSFrame(session.Conn, modern, 11, nil)
				default:
					accept := make([]byte, 24)
					copy(accept, []byte{0x01, 0x3a})
					copy(accept[2:8], content[4:10])
					copy(accept[8:], []byte{0, 1, 0, 0, 0, 0x20, 0x41, 0x41})
					err = writeTNSFrame(session.Conn, modern, 2, accept)
				}
			}
			if err != nil {
				return err
			}
		case 6:
			if len(content) == 2 && content[0] == 0 && content[1] == 0 {
				continue
			}
			payloads := tnsNegotiationReplies(session, content, banner)
			if payloads == nil {
				return nil
			}
			for _, payload := range payloads {
				if err := writeTNSFrame(session.Conn, modern, 6, payload); err != nil {
					return err
				}
			}
		case 12: // MARKER
			continue
		default:
			return nil
		}
	}
}

const tnsFrameLimit = 4096

func readTNSFrame(r io.Reader, modern bool) (byte, []byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	length := uint32(binary.BigEndian.Uint16(header[:2]))
	if length == 0 {
		if !modern {
			return 0, nil, nil
		}
		length = binary.BigEndian.Uint32(header[:4])
	}
	if length < uint32(len(header)) || length > tnsFrameLimit {
		return 0, nil, errors.New("invalid TNS frame length")
	}
	content := make([]byte, int(length)-len(header))
	_, err := io.ReadFull(r, content)
	return header[4], content, err
}

func tnsConnectDescriptor(r io.Reader, modern bool, content []byte) (string, error) {
	if len(content) < 20 {
		return "", errors.New("short TNS CONNECT frame")
	}
	dataLength := int(binary.BigEndian.Uint16(content[16:18]))
	start := int(binary.BigEndian.Uint16(content[18:20])) - 8
	if start < 20 || start > len(content) || dataLength > tnsFrameLimit {
		return "", errors.New("invalid TNS descriptor length")
	}
	if dataLength <= len(content)-start {
		return string(content[start : start+dataLength]), nil
	}
	descriptor := append(make([]byte, 0, dataLength), content[start:]...)
	for len(descriptor) < dataLength {
		kind, part, err := readTNSFrame(r, modern)
		if err != nil {
			return "", err
		}
		if kind != 6 || len(part) <= 2 || len(part)-2 > dataLength-len(descriptor) {
			return "", errors.New("invalid TNS descriptor continuation")
		}
		descriptor = append(descriptor, part[2:]...)
	}
	return string(descriptor), nil
}

type tnsParameter struct {
	key, value string
}

func tnsParameters(input string) []tnsParameter {
	var groups []tnsParameter
	for {
		input = strings.TrimLeftFunc(input, unicode.IsSpace)
		if len(input) < 3 || input[0] != '(' {
			return groups
		}
		keyEnd := strings.IndexAny(input[1:], "=()") + 1
		if keyEnd <= 1 || input[keyEnd] != '=' {
			return groups
		}
		depth := 1
		end := keyEnd + 1
		for ; end < len(input); end++ {
			switch input[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			return groups
		}
		groups = append(groups, tnsParameter{
			key:   strings.ToUpper(input[1:keyEnd]),
			value: strings.TrimLeftFunc(input[keyEnd+1:end], unicode.IsSpace),
		})
		input = input[end+1:]
	}
}

func tnsVersionCommand(value string) bool {
	for _, child := range tnsParameters(value) {
		if child.key == "COMMAND" && strings.EqualFold(child.value, "VERSION") {
			return true
		}
	}
	return false
}

func tnsDescriptorService(value string) (service string, found bool) {
	for _, group := range tnsParameters(value) {
		if group.key != "CONNECT_DATA" {
			continue
		}
		for _, child := range tnsParameters(group.value) {
			if child.key == "SID" || child.key == "SERVICE_NAME" {
				if child.value == "" {
					return "", true
				}
				service, found = child.value, true
			}
		}
	}
	return service, found
}

func tnsNegotiationReplies(session *SessionConnection, content []byte, banner string) [][]byte {
	if len(content) < 3 || content[0] != 0 || content[1] != 0 {
		return nil
	}
	switch {
	case bytes.HasPrefix(content[2:], []byte{0xde, 0xad, 0xbe, 0xef}):
		return [][]byte{tnsNegotiation["ano"]}
	case content[2] == 1 && len(content) >= 5:
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "data", logrus.Fields{"Client": string(content[5:])})
		return [][]byte{bytes.Replace(tnsNegotiation["protocol"], []byte(tnsDefaultBanner), []byte(banner), 1)}
	case content[2] == 2:
		return [][]byte{tnsNegotiation["types"], tnsNegotiation["types_tail"]}
	}
	return nil
}

func writeTNSRefusal(w net.Conn, modern bool, version string, code int) error {
	descriptor := fmt.Sprintf("(DESCRIPTION=(TMP=)(VSNNUM=%s)(ERR=%d)(ERROR_STACK=(ERROR=(CODE=%d)(EMFI=4))))", version, code, code)
	payload := append([]byte{0x22, 0, 0, 0}, descriptor...)
	return writeTNSFrame(w, modern, 4, payload)
}

func writeTNSFrame(w net.Conn, modern bool, kind byte, payload []byte) error {
	if len(payload) > 65535-8 {
		return errors.New("TNS response exceeds limit")
	}
	packet := make([]byte, 8+len(payload))
	if modern {
		binary.BigEndian.PutUint32(packet[:4], uint32(len(packet)))
	} else {
		binary.BigEndian.PutUint16(packet[:2], uint16(len(packet)))
	}
	packet[4] = kind
	copy(packet[8:], payload)
	if err := w.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	_, err := w.Write(packet)
	return err
}
