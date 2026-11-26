package protocols

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	rdpGlobalChannel     = 1003
	rdpFirstUserID       = 1001
	rdpMaxStaticChannels = 31
)

const rdpGCCClientHeader = "\x00\x08\x00\x10\x00\x01\xc0\x00Duca"
const rdpGCCServerHeader = "\x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0\x00McDn"

var errRDPMCS = errors.New("invalid RDP MCS message")

func serveRDPBasicSettings(conn io.ReadWriter, options rdpStandardOptions, clientProtocols uint32) error {
	request, err := readRDPData(conn)
	if err != nil {
		return err
	}
	count, err := rdpStaticChannelCount(request)
	if err != nil {
		return err
	}
	var identity *rdpIdentity
	var serverRandom, certificate []byte
	if clientProtocols == 0 {
		identity, err = rdpStandardIdentity()
		if err != nil {
			return err
		}
		certificate = identity.certificate
		serverRandom = make([]byte, 32)
		if _, err := rand.Read(serverRandom); err != nil {
			return err
		}
	}
	if err := writeRDPData(conn, rdpMCSConnectResponse(count, serverRandom, certificate, clientProtocols)); err != nil {
		return err
	}

	request, err = readRDPData(conn)
	if err != nil {
		return err
	}
	if len(request) < 3 || request[0]>>2 != 1 {
		return errRDPMCS
	}
	request, err = readRDPData(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(request, []byte{0x28}) {
		return errRDPMCS
	}

	userChannel := rdpGlobalChannel + count + 1
	userOffset := userChannel - rdpFirstUserID
	attach := binary.BigEndian.AppendUint16([]byte{0x2e, 0}, userOffset)
	if err := writeRDPData(conn, attach); err != nil {
		return err
	}

	joined := make(map[uint16]bool, int(count)+2)
	for len(joined) < int(count)+2 {
		request, err = readRDPData(conn)
		if err != nil {
			return err
		}
		if len(request) != 5 || request[0] != 0x38 || binary.BigEndian.Uint16(request[1:]) != userOffset {
			return errRDPMCS
		}
		channel := binary.BigEndian.Uint16(request[3:])
		if channel < rdpGlobalChannel || channel > userChannel || joined[channel] {
			return errRDPMCS
		}
		joined[channel] = true
		join := binary.BigEndian.AppendUint16([]byte{0x3e, 0}, userOffset)
		join = binary.BigEndian.AppendUint16(join, channel)
		join = binary.BigEndian.AppendUint16(join, channel)
		if err := writeRDPData(conn, join); err != nil {
			return err
		}
	}

	if identity == nil {
		return serveRDPEnhancedSecurity(conn, userOffset, options.imageName)
	}
	return serveRDPStandardSecurity(conn, userOffset, identity, serverRandom, options)
}

func readRDPData(conn io.Reader) ([]byte, error) {
	frame, err := readTPKT(conn)
	if err != nil {
		return nil, err
	}
	if len(frame) < 8 || !bytes.Equal(frame[4:7], []byte{2, 0xf0, 0x80}) {
		return nil, errRDPMCS
	}
	return frame[7:], nil
}

func writeRDPData(conn io.Writer, payload []byte) error {
	frame := binary.BigEndian.AppendUint16([]byte{3, 0}, uint16(7+len(payload)))
	frame = append(frame, 2, 0xf0, 0x80)
	_, err := conn.Write(append(frame, payload...))
	return err
}

func rdpStaticChannelCount(request []byte) (uint16, error) {
	if !bytes.HasPrefix(request, []byte{0x7f, 0x65}) {
		return 0, errRDPMCS
	}
	message, err := decodeBER(request[1:])
	if err != nil || len(message.Children) != 7 || message.Children[6].Tag != 4 {
		return 0, errRDPMCS
	}
	gcc := message.Children[6].Value
	if !bytes.HasPrefix(gcc, []byte{0, 5, 0, 0x14, 0x7c, 0, 1}) {
		return 0, errRDPMCS
	}
	conference := readRDPPerPayload(gcc[7:])
	if !bytes.HasPrefix(conference, []byte(rdpGCCClientHeader)) {
		return 0, errRDPMCS
	}
	data := readRDPPerPayload(conference[len(rdpGCCClientHeader):])
	for len(data) >= 4 {
		blockType := binary.LittleEndian.Uint16(data)
		length := int(binary.LittleEndian.Uint16(data[2:]))
		if length < 4 || length > len(data) {
			return 0, errRDPMCS
		}
		if blockType == 0xc003 {
			if length < 8 {
				return 0, errRDPMCS
			}
			count := binary.LittleEndian.Uint32(data[4:])
			if count > rdpMaxStaticChannels || length != 8+12*int(count) {
				return 0, errRDPMCS
			}
			return uint16(count), nil
		}
		data = data[length:]
	}
	return 0, nil
}

func readRDPPerPayload(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	length := int(data[0])
	data = data[1:]
	if length&0x80 != 0 {
		if len(data) == 0 {
			return nil
		}
		length = (length&0x7f)<<8 | int(data[0])
		data = data[1:]
	}
	if length != len(data) {
		return nil
	}
	return data
}

func rdpMCSConnectResponse(count uint16, serverRandom, certificate []byte, clientProtocols uint32) []byte {
	core := []byte{4, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	network := binary.LittleEndian.AppendUint16(nil, rdpGlobalChannel)
	network = binary.LittleEndian.AppendUint16(network, count)
	for index := uint16(1); index <= count; index++ {
		network = binary.LittleEndian.AppendUint16(network, rdpGlobalChannel+index)
	}
	if count%2 != 0 {
		network = append(network, 0, 0)
	}

	security := make([]byte, 8)
	if clientProtocols == 0 {
		binary.LittleEndian.PutUint32(security, 2)
		binary.LittleEndian.PutUint32(security[4:], 3)
		security = binary.LittleEndian.AppendUint32(security, uint32(len(serverRandom)))
		security = binary.LittleEndian.AppendUint32(security, uint32(len(certificate)))
		security = append(security, serverRandom...)
		security = append(security, certificate...)
	} else {
		binary.LittleEndian.PutUint32(core, 0x00080004)
		binary.LittleEndian.PutUint32(core[4:], clientProtocols)
	}

	blocks := appendRDPServerBlock(nil, 0x0c01, core)
	blocks = appendRDPServerBlock(blocks, 0x0c03, network)
	blocks = appendRDPServerBlock(blocks, 0x0c02, security)
	gcc := []byte(rdpGCCServerHeader)
	if len(blocks) < 0x80 {
		gcc = append(gcc, byte(len(blocks)))
	} else {
		gcc = binary.BigEndian.AppendUint16(gcc, uint16(len(blocks))|0x8000)
	}
	gcc = append(gcc, blocks...)
	domain := berTLV(0x30,
		berIntBytes(2, 34), berIntBytes(2, 3), berIntBytes(2, 0), berIntBytes(2, 1),
		berIntBytes(2, 0), berIntBytes(2, 1), berTLV(2, []byte{0xff, 0xf8}), berIntBytes(2, 2))
	mcs := berTLV(0x66, berIntBytes(0x0a, 0), berIntBytes(2, 0), domain, berTLV(4, gcc))
	return append([]byte{0x7f}, mcs...)
}

func appendRDPServerBlock(blocks []byte, kind uint16, payload []byte) []byte {
	blocks = binary.LittleEndian.AppendUint16(blocks, kind)
	blocks = binary.LittleEndian.AppendUint16(blocks, uint16(4+len(payload)))
	return append(blocks, payload...)
}
