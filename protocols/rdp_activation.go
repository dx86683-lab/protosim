package protocols

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	rdpServerChannel   = 1002
	rdpConfirmActive   = 0x13
	rdpShareData       = 0x17
	rdpDataControl     = 20
	rdpDataSynchronize = 31
	rdpDataFontList    = 39
	rdpDataFontMap     = 40
	rdpDataPersistent  = 43
)

var errRDPActivation = errors.New("invalid RDP connection finalization")

func serveRDPActivation(conn io.ReadWriter, user uint16, keys *rdpStandardKeys, imageName string) error {
	confirm, err := readRDPShare(conn, user, keys, rdpConfirmActive)
	if err != nil {
		return err
	}
	if !validRDPConfirmActive(confirm) {
		return errRDPActivation
	}

	expected := []struct {
		kind      byte
		size      int
		firstWord uint16
	}{
		{rdpDataSynchronize, 4, 1},
		{rdpDataControl, 8, 4},
		{rdpDataControl, 8, 1},
	}
	for _, step := range expected {
		kind, body, err := readRDPShareData(conn, user, keys)
		if err != nil {
			return err
		}
		if kind != step.kind || len(body) != step.size || binary.LittleEndian.Uint16(body) != step.firstWord {
			return errRDPActivation
		}
	}

	fontListComplete := false
	for attempt := 0; attempt < 64 && !fontListComplete; attempt++ {
		kind, body, err := readRDPShareData(conn, user, keys)
		if err != nil {
			return err
		}
		switch kind {
		case rdpDataPersistent:
			continue
		case rdpDataFontList:
			if len(body) != 8 {
				return errRDPActivation
			}
			fontListComplete = binary.LittleEndian.Uint16(body[4:])&2 != 0
		default:
			return errRDPActivation
		}
	}
	if !fontListComplete {
		return errRDPActivation
	}

	responses := []struct {
		kind byte
		data []byte
	}{
		{rdpDataSynchronize, binary.LittleEndian.AppendUint16([]byte{1, 0}, rdpServerChannel)},
		{rdpDataControl, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
		{rdpDataControl, []byte{2, 0, 0, 0, 0, 0, 0, 0}},
		{rdpDataFontMap, []byte{0, 0, 0, 0, 3, 0, 4, 0}},
	}
	for _, response := range responses {
		if err := writeRDPShareData(conn, user, keys, response.kind, response.data); err != nil {
			return err
		}
	}
	picture, imageErr := loadRDPDesktop(imageName)
	if imageErr == nil {
		if err := writeRDPDesktop(conn, user, keys, picture); err != nil {
			return err
		}
	}
	_, err = io.Copy(io.Discard, conn)
	return err
}

func validRDPConfirmActive(confirm []byte) bool {
	if len(confirm) < 20 || binary.LittleEndian.Uint32(confirm[6:]) != rdpServerChannel ||
		binary.LittleEndian.Uint16(confirm[10:]) != rdpServerChannel {
		return false
	}
	start := 16 + int(binary.LittleEndian.Uint16(confirm[12:]))
	size := int(binary.LittleEndian.Uint16(confirm[14:]))
	if size < 4 || start+size != len(confirm) {
		return false
	}
	count := int(binary.LittleEndian.Uint16(confirm[start:]))
	capabilities := confirm[start+4:]
	for range count {
		if len(capabilities) < 4 {
			return false
		}
		length := int(binary.LittleEndian.Uint16(capabilities[2:]))
		if length < 4 || length > len(capabilities) {
			return false
		}
		capabilities = capabilities[length:]
	}
	return len(capabilities) == 0
}

func readRDPShare(conn io.Reader, user uint16, keys *rdpStandardKeys, expectedType uint16) ([]byte, error) {
	data, err := readRDPSecurityData(conn, user)
	if err != nil {
		return nil, err
	}
	plain := data
	if keys != nil {
		plain, err = keys.open(data)
		if err != nil {
			return nil, err
		}
	}
	if len(plain) < 6 || int(binary.LittleEndian.Uint16(plain)) != len(plain) ||
		binary.LittleEndian.Uint16(plain[2:]) != expectedType ||
		binary.LittleEndian.Uint16(plain[4:]) != user+rdpFirstUserID {
		return nil, errRDPActivation
	}
	return plain, nil
}

func readRDPShareData(conn io.Reader, user uint16, keys *rdpStandardKeys) (byte, []byte, error) {
	plain, err := readRDPShare(conn, user, keys, rdpShareData)
	if err != nil {
		return 0, nil, err
	}
	if len(plain) < 18 || plain[15] != 0 || binary.LittleEndian.Uint16(plain[16:]) != 0 {
		return 0, nil, errRDPActivation
	}
	share := binary.LittleEndian.Uint32(plain[6:])
	if share != rdpServerChannel && share != 0x10000|rdpServerChannel {
		return 0, nil, errRDPActivation
	}
	return plain[14], plain[18:], nil
}

func writeRDPShareData(conn io.Writer, user uint16, keys *rdpStandardKeys, kind byte, body []byte) error {
	packet := binary.LittleEndian.AppendUint16(nil, uint16(18+len(body)))
	packet = binary.LittleEndian.AppendUint16(packet, rdpShareData)
	packet = binary.LittleEndian.AppendUint16(packet, rdpServerChannel)
	packet = binary.LittleEndian.AppendUint32(packet, 0x10000|rdpServerChannel)
	packet = append(packet, 0, 2)
	packet = binary.LittleEndian.AppendUint16(packet, uint16(len(body)))
	packet = append(packet, kind, 0, 0, 0)
	return writeRDPSecurityData(conn, user, keys, rdpSecSecureChecksum, append(packet, body...))
}
