package protocols

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("tftp", TFTP, 69))
}

// TFTP implements RFC 1350 Trivial File Transfer Protocol (UDP 69).
func TFTP(uc *UDPConnection, b []byte) error {
	if len(b) < 2 {
		return nil
	}
	opcode := binary.BigEndian.Uint16(b[0:2])
	parts := bytes.Split(b[2:], []byte{0})
	filename := ""
	mode := ""
	if len(parts) > 0 {
		filename = string(parts[0])
	}
	if len(parts) > 1 {
		mode = strings.ToLower(string(parts[1]))
	}

	uc.LogWithRemote("tftp_request", uc.RemoteAddr(), logrus.Fields{
		"opcode":   opcode,
		"filename": filename,
		"mode":     mode,
	})

	switch opcode {
	case 1: // RRQ (Read Request)
		if filename == "pxelinux.cfg/default" || filename == "boot.cfg" || filename == "test" {
			data := []byte("DEFAULT linux\nLABEL linux\n  KERNEL vmlinuz\n")
			resp := make([]byte, 4+len(data))
			binary.BigEndian.PutUint16(resp[0:2], 3) // DATA
			binary.BigEndian.PutUint16(resp[2:4], 1) // Block #1
			copy(resp[4:], data)
			_, err := uc.WriteTo(resp, uc.RemoteAddr())
			return err
		}
		// RFC 1350 ERROR code 1: File not found
		errMsg := "File not found"
		resp := make([]byte, 4+len(errMsg)+1)
		binary.BigEndian.PutUint16(resp[0:2], 5) // ERROR
		binary.BigEndian.PutUint16(resp[2:4], 1) // File not found
		copy(resp[4:], errMsg)
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	case 2: // WRQ (Write Request) -> ACK block 0
		resp := []byte{0x00, 0x04, 0x00, 0x00}
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	default:
		// ERROR code 4: Illegal TFTP operation
		errMsg := "Illegal TFTP operation"
		resp := make([]byte, 4+len(errMsg)+1)
		binary.BigEndian.PutUint16(resp[0:2], 5)
		binary.BigEndian.PutUint16(resp[2:4], 4)
		copy(resp[4:], errMsg)
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
}
