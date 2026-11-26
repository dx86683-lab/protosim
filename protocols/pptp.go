package protocols

import (
	"encoding/binary"
	"io"
	"time"
)

// PPTP answers Start-Control-Connection-Request only. Any other control
// message, a bad magic cookie or a second request ends the session, which is
// what the reference does.

const pptpMagic = 0x1a2b3c4d

func init() {
	AddProtocol(NewProtocolInfo("pptp", servePPTP, 1723),
		ProtocolParams{Name: "firmware_rev", DefaultValue: 1},
		ProtocolParams{Name: "hostname", DefaultValue: "MikroTik"},
		ProtocolParams{Name: "vendor", DefaultValue: "MikroTik"})
}

func servePPTP(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	var header [2]byte
	if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 || size > 4096 {
		return nil
	}
	message := make([]byte, size)
	copy(message, header[:])
	if _, err := io.ReadFull(session.Conn, message[2:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(message[2:]) != 1 || binary.BigEndian.Uint32(message[4:]) != pptpMagic ||
		binary.BigEndian.Uint16(message[8:]) != 1 {
		return nil
	}
	reply := make([]byte, 156)
	binary.BigEndian.PutUint16(reply[0:], 156)
	binary.BigEndian.PutUint16(reply[2:], 1)
	binary.BigEndian.PutUint32(reply[4:], pptpMagic)
	binary.BigEndian.PutUint16(reply[8:], 2) // Start-Control-Connection-Reply
	binary.BigEndian.PutUint16(reply[12:], 0x0100)
	reply[14] = 1 // result: connection established
	binary.BigEndian.PutUint32(reply[16:], 3)
	binary.BigEndian.PutUint32(reply[20:], 3)
	binary.BigEndian.PutUint16(reply[24:], 5)
	binary.BigEndian.PutUint16(reply[26:], uint16(session.GetIntParams("firmware_rev", 1)))
	copy(reply[28:92], session.GetStringParams("hostname", "MikroTik"))
	copy(reply[92:156], session.GetStringParams("vendor", "MikroTik"))
	if _, err := session.Conn.Write(reply); err != nil {
		return err
	}
	// The reference closes on any further control message.
	_, err := io.ReadFull(session.Conn, header[:1])
	return err
}
