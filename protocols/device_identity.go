package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	eipDeviceIP    = "192.168.1.11"
	eipProductName = "1766-L32BXBA C/21.02"

	eipNOP               = 0
	eipListServices      = 4
	eipListIdentity      = 0x63
	eipListInterfaces    = 0x64
	eipRegisterSession   = 0x65
	eipUnregisterSession = 0x66
)

var eipCommandName = map[uint16]string{
	eipNOP: "NOP", eipListServices: "ListServices", eipListIdentity: "ListIdentity",
	eipListInterfaces: "ListInterfaces", eipRegisterSession: "RegisterSession",
	eipUnregisterSession: "UnRegisterSession",
}

type dnp3Link struct {
	Code   byte   `json:"code"`
	Dest   uint16 `json:"dest"`
	Source uint16 `json:"source"`
}

var dnp3DefaultLink = dnp3Link{Code: 11, Source: 8}

var dnp3PrimaryFunctions = [16]string{
	0: "RESET_LINK_STATES",
	2: "TEST_LINK_STATES",
	3: "CONFIRMED_USER_DATA",
	4: "UNCONFIRMED_USER_DATA",
	9: "REQUEST_LINK_STATUS",
}

var dnp3SecondaryFunctions = [16]string{
	0:  "ACK",
	1:  "NACK",
	11: "LINK_STATUS",
	15: "NOT_SUPPORTED",
}

func init() {
	AddProtocol(NewProtocolInfo("eip", serveEIP, 44818),
		ProtocolParams{Name: "ip", DefaultValue: eipDeviceIP},
		ProtocolParams{Name: "product_name", DefaultValue: eipProductName})
	AddProtocol(NewProtocolInfo("dnp3", serveDNP3, 20000),
		ProtocolParams{Name: "link", DefaultValue: dnp3DefaultLink})
}

func serveEIP(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	le := binary.LittleEndian
	for {
		var header [24]byte
		if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		length := le.Uint16(header[2:4])
		command := le.Uint16(header[:2])
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "request", logrus.Fields{
			"command": eipCommandName[command],
		})
		var item []byte
		switch command {
		case eipNOP:
			if _, err := io.CopyN(io.Discard, session.Conn, int64(length)); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil {
				return err
			}
			continue
		case eipListServices:
			item = append([]byte{1, 0, 0, 1, 20, 0, 1, 0, 0x20, 0}, "Communications\x00\x00"...)
		case eipListIdentity:
			item = eipIdentity(session)
			if item == nil {
				return nil
			}
		case eipListInterfaces:
			item = []byte{0, 0}
		case eipRegisterSession:
			var registration [4]byte
			if length < uint16(len(registration)) {
				return nil
			}
			if _, err := io.ReadFull(session.Conn, registration[:]); err != nil {
				return err
			}
			if le.Uint16(registration[:2]) > 1 {
				le.PutUint16(registration[:2], 1)
				le.PutUint32(header[8:12], 0x69)
			} else {
				le.PutUint32(header[4:8], rand.Uint32N(0xffffffff)+1)
			}
			item = registration[:]
		case eipUnregisterSession:
			return nil
		default:
			item = make([]byte, length)
			if _, err := io.ReadFull(session.Conn, item); err != nil {
				return err
			}
			le.PutUint32(header[8:12], 1)
		}
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		le.PutUint16(header[2:4], uint16(len(item)))
		if _, err := session.Conn.Write(append(header[:], item...)); err != nil {
			return err
		}
	}
}

func eipIdentity(session *SessionConnection) []byte {
	ip := net.ParseIP(session.GetStringParams("ip", eipDeviceIP)).To4()
	name := session.GetStringParams("product_name", eipProductName)
	if ip == nil || len(name) > 65535-40 {
		return nil
	}
	identity := append([]byte{1, 0, 0, 2, 0, 0}, ip...)
	identity = append(identity, make([]byte, 8)...)
	identity = append(identity, 1, 0, 14, 0, 1, 0, 1, 1, 0, 0, 0x60, 0xda, 0x6f, 0xa2, byte(len(name)))
	identity = append(identity, name...)
	identity = append(identity, 3)
	item := binary.LittleEndian.AppendUint16([]byte{1, 0, 12, 0}, uint16(len(identity)))
	return append(item, identity...)
}

func dnp3CRC(data []byte) uint16 {
	var crc uint16
	for _, octet := range data {
		crc ^= uint16(octet)
		for i := 0; i < 8; i++ {
			if crc&1 == 1 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func serveDNP3(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	link := dnp3DefaultLink
	if configured, ok := session.Params["link"].(dnp3Link); ok {
		link = configured
	}
	reply := binary.LittleEndian.AppendUint16([]byte{0x05, 0x64, 0x05, link.Code}, link.Dest)
	reply = binary.LittleEndian.AppendUint16(reply, link.Source)
	reply = binary.LittleEndian.AppendUint16(reply, dnp3CRC(reply))
	reader := bufio.NewReader(session.Conn)
	for {
		request, err := readDNP3LinkHeader(reader)
		if err != nil {
			return err
		}
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "message", logrus.Fields{
			"ctrl": dnp3FunctionName(request[3]),
			"dst":  binary.LittleEndian.Uint16(request[4:6]),
			"src":  binary.LittleEndian.Uint16(request[6:8]),
		})
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		if _, err := session.Conn.Write(reply); err != nil {
			return err
		}
	}
}

func readDNP3LinkHeader(reader io.Reader) ([10]byte, error) {
	var header [10]byte
	for _, field := range [...]struct {
		name       string
		start, end int
	}{
		{"Start", 0, 2}, {"Length", 2, 3}, {"Control", 3, 4},
		{"Dest", 4, 6}, {"Source", 6, 8}, {"Crc", 8, 10},
	} {
		if _, err := io.ReadFull(reader, header[field.start:field.end]); err != nil {
			return header, fmt.Errorf("read field %s: %w", field.name, err)
		}
		switch field.start {
		case 0:
			if start := binary.LittleEndian.Uint16(header[:2]); start != 0x6405 {
				return header, fmt.Errorf("h.Start mismatch! expect: %d. actual: %d.", 0x6405, start)
			}
		case 2:
			if length := header[2]; length != 5 {
				return header, fmt.Errorf("h.Length mismatch! expect: 5. actual: %d.", length)
			}
		}
	}
	return header, nil
}

func dnp3FunctionName(control byte) string {
	code := control & 0x0f
	if control&0x40 != 0 {
		if name := dnp3PrimaryFunctions[code]; name != "" {
			return name
		}
		return fmt.Sprintf("UNKNOWN_PRM_%d", code)
	}
	if name := dnp3SecondaryFunctions[code]; name != "" {
		return name
	}
	return fmt.Sprintf("UNKNOWN_SND_%d", code)
}
