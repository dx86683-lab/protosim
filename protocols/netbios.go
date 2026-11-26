package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

const netbiosHost, netbiosGroup, netbiosMAC = "Admin", "WORKGROUP", "00:01:02:03:04:05"

func init() {
	AddProtocol(NewProtocolInfo("netbios", serveNetBIOS, 137),
		ProtocolParams{Name: "server_name", DefaultValue: netbiosHost},
		ProtocolParams{Name: "host_name", DefaultValue: netbiosHost},
		ProtocolParams{Name: "group_name", DefaultValue: netbiosGroup},
		ProtocolParams{Name: "mac", DefaultValue: netbiosMAC})
}

func serveNetBIOS(conn *UDPConnection, request []byte) error {
	if len(request) == 0 {
		return nil
	}
	reader := bytes.NewReader(request)
	var header [12]byte
	for i, field := range [...]string{"TransId", "Flags", "Qdcount", "Ancount", "Nscount", "Arcount"} {
		if _, err := io.ReadFull(reader, header[i*2:i*2+2]); err != nil {
			return fmt.Errorf("decode message header: read field %s: %w", field, err)
		}
	}
	flags := binary.BigEndian.Uint16(header[2:4])
	questions := binary.BigEndian.Uint16(header[4:6])
	var answerName []byte
	var query string
	if flags&0xf800 == 0 {
		for i := range int(questions) {
			name, err := readNetBIOSQuestion(reader)
			if err != nil {
				return fmt.Errorf("decode query record %d: %w", i, err)
			}
			if i == 0 {
				answerName = name
				query = string(name[1 : len(name)-1])
			}
		}
	}
	logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "new message", logrus.Fields{
		"trans_id": binary.BigEndian.Uint16(header[:2]), "flags": flags,
		"questions": questions, "query": query,
	})
	if answerName == nil {
		return nil
	}
	mac, err := net.ParseMAC(conn.GetStringParams("mac", netbiosMAC))
	if err != nil {
		mac, _ = net.ParseMAC(netbiosMAC)
	}

	reply := append([]byte{}, header[:2]...)
	reply = append(reply, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
	reply = append(reply, answerName...)
	reply = append(reply, 0, 0x21, 0, 1)
	reply = append(reply, 0, 0, 0, 0, 0, 101, 3)
	names := []struct {
		key, fallback string
		suffix, flags byte
	}{
		{"server_name", netbiosHost, 0x20, 0x44},
		{"host_name", netbiosHost, 0, 0x44},
		{"group_name", netbiosGroup, 0, 0xc4},
	}
	for _, name := range names {
		value := conn.GetStringParams(name.key, name.fallback)
		value = value[:min(len(value), 15)]
		reply = append(reply, value...)
		reply = append(reply, strings.Repeat(" ", 15-len(value))...)
		reply = append(reply, name.suffix, name.flags, 0)
	}
	reply = append(reply, mac[:6]...)
	reply = append(reply, make([]byte, 40)...)
	_, err = conn.Write(reply)
	return err
}

func readNetBIOSQuestion(reader *bytes.Reader) ([]byte, error) {
	length, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read field Name: read field Clength: %w", err)
	}
	name := make([]byte, int(length)+2)
	name[0] = length
	if _, err := io.ReadFull(reader, name[1:len(name)-1]); err != nil {
		return nil, fmt.Errorf("read field Name: read field Cname: %w", err)
	}
	if name[len(name)-1], err = reader.ReadByte(); err != nil {
		return nil, fmt.Errorf("read field Name: read field Cclass: %w", err)
	}
	var field [2]byte
	for _, name := range [...]string{"Qtype", "QueryClass"} {
		if _, err := io.ReadFull(reader, field[:]); err != nil {
			return nil, fmt.Errorf("read field %s: %w", name, err)
		}
	}
	return name, nil
}
