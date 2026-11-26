package protocols

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("jdwp", JDWP, 8000),
		ProtocolParams{
			Name:         "vm_version",
			DefaultValue: "17.0.10",
		},
		ProtocolParams{
			Name:         "vm_name",
			DefaultValue: "OpenJDK 64-Bit Server VM",
		},
	)
}

const jdwpHandshake = "JDWP-Handshake"

// JDWP implements the Java Debug Wire Protocol handshake and VirtualMachine/Version query.
func JDWP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hs := make([]byte, len(jdwpHandshake))
	if _, err := io.ReadFull(sc.Conn, hs); err != nil {
		return err
	}
	if string(hs) != jdwpHandshake {
		sc.LogWithRemote("jdwp_invalid_handshake", sc.Conn.RemoteAddr(), logrus.Fields{
			"received": string(hs),
		})
		return nil
	}
	sc.LogWithRemote("jdwp_handshake", sc.Conn.RemoteAddr(), logrus.Fields{
		"handshake": jdwpHandshake,
	})
	if _, err := sc.Conn.Write([]byte(jdwpHandshake)); err != nil {
		return err
	}

	vmVer := sc.GetStringParams("vm_version", "17.0.10")
	vmName := sc.GetStringParams("vm_name", "OpenJDK 64-Bit Server VM")

	// Handle subsequent JDWP command packets (11-byte header: len[4], id[4], flags[1], cmdset[1], cmd[1])
	for {
		hdr := make([]byte, 11)
		if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
			return err
		}
		pktLen := binary.BigEndian.Uint32(hdr[0:4])
		pktID := binary.BigEndian.Uint32(hdr[4:8])
		cmdSet := hdr[9]
		cmd := hdr[10]

		if pktLen > 11 && pktLen < 65536 {
			_, _ = io.CopyN(io.Discard, sc.Conn, int64(pktLen-11))
		}

		sc.LogWithRemote("jdwp_command", sc.Conn.RemoteAddr(), logrus.Fields{
			"id":      pktID,
			"cmd_set": cmdSet,
			"cmd":     cmd,
		})

		var body bytes.Buffer
		switch {
		case cmdSet == 1 && cmd == 1: // VirtualMachine.Version
			writeJDWPString(&body, "Java Debug Interface (Reference Implementation) version 17.0\nJVM version "+vmVer+" ("+vmName+")")
			_ = binary.Write(&body, binary.BigEndian, uint32(17)) // jdwpMajor
			_ = binary.Write(&body, binary.BigEndian, uint32(0))  // jdwpMinor
			writeJDWPString(&body, vmVer)
			writeJDWPString(&body, vmName)
		case cmdSet == 1 && cmd == 7: // VirtualMachine.IDSizes
			for i := 0; i < 5; i++ {
				_ = binary.Write(&body, binary.BigEndian, uint32(8))
			}
		}

		reply := make([]byte, 11+body.Len())
		binary.BigEndian.PutUint32(reply[0:4], uint32(len(reply)))
		binary.BigEndian.PutUint32(reply[4:8], pktID)
		reply[8] = 0x80 // Reply flag
		binary.BigEndian.PutUint16(reply[9:11], 0)
		copy(reply[11:], body.Bytes())

		if _, err := sc.Conn.Write(reply); err != nil {
			return err
		}
	}
}

func writeJDWPString(buf *bytes.Buffer, s string) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(s)))
	buf.WriteString(s)
}
