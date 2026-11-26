package protocols

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

const (
	dceHeaderSize  = 16
	dceBind        = 11
	dceBindAck     = 12
	dceBindNak     = 13
	dceSingleFrame = 3
)

var dceNDR = [...]byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00,
}

func init() {
	AddProtocol(NewProtocolInfo("dcerpc", serveDCERPC, 135),
		ProtocolParams{Name: "domain_name", DefaultValue: "DESKTOP-Q1Test"},
		ProtocolParams{Name: "accounts", DefaultValue: []string{"administrator:123456"}})
}

func dceBindResult(request []byte, association [4]byte, endpoint string) []byte {
	if len(request) < 12 || request[8] == 0 {
		return nil
	}
	reply := append([]byte{}, request[:4]...)
	reply = append(reply, association[:]...)
	reply = binary.LittleEndian.AppendUint16(reply, uint16(len(endpoint)+1))
	reply = append(reply, endpoint...)
	reply = append(reply, 0)
	for len(reply)%4 != 0 {
		reply = append(reply, 0)
	}
	reply = append(reply, request[8], 0, 0, 0)
	contexts := request[12:]
	for range int(request[8]) {
		if len(contexts) < 24 || contexts[2] == 0 {
			return nil
		}
		count := int(contexts[2])
		contexts = contexts[24:]
		if len(contexts) < count*len(dceNDR) {
			return nil
		}
		accepted := false
		for range count {
			syntax := contexts[:len(dceNDR)]
			contexts = contexts[len(dceNDR):]
			accepted = accepted || bytes.Equal(syntax, dceNDR[:])
		}
		if accepted {
			reply = append(reply, 0, 0, 0, 0)
			reply = append(reply, dceNDR[:]...)
		} else {
			// Provider rejection: proposed transfer syntaxes not supported.
			reply = append(reply, 2, 0, 2, 0)
			reply = append(reply, make([]byte, len(dceNDR))...)
		}
	}
	if len(contexts) != 0 {
		return nil
	}
	return reply
}

func serveDCERPC(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	var association [4]byte
	_, _ = rand.Read(association[:])
	association[0] = 0x81
	var header [dceHeaderSize]byte
	for {
		if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
			return err
		}
		size := int(binary.LittleEndian.Uint16(header[8:10]))
		if header[0] != 5 || header[1] != 0 || header[4] != 0x10 || size < len(header) {
			return nil
		}
		body := make([]byte, size-len(header))
		if _, err := io.ReadFull(session.Conn, body); err != nil {
			return err
		}
		var reply []byte
		if header[2] == dceBind && header[3]&dceSingleFrame == dceSingleFrame && binary.LittleEndian.Uint16(header[10:12]) == 0 {
			reply = dceBindResult(body, association, "135")
		}
		header[2], header[3] = dceBindAck, dceSingleFrame
		reject := reply == nil
		if reject {
			header[2] = dceBindNak
			reply = []byte{4, 0, 1, 5, 0, 0}
		}
		binary.LittleEndian.PutUint16(header[8:10], uint16(len(header)+len(reply)))
		binary.LittleEndian.PutUint16(header[10:12], 0)
		if _, err := session.Conn.Write(append(header[:len(header):len(header)], reply...)); err != nil {
			return err
		}
		if reject {
			return nil
		}
	}
}
