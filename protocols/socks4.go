package protocols

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("socks4", SOCKS4, 1081))
}

// SOCKS4 implements the SOCKS4 / SOCKS4a CONNECT handshake.
func SOCKS4(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x04 {
		return nil
	}
	cmd := hdr[1]
	dstPort := binary.BigEndian.Uint16(hdr[2:4])
	dstIP := net.IPv4(hdr[4], hdr[5], hdr[6], hdr[7]).String()

	userID, _ := r.ReadString(0x00)
	if len(userID) > 0 {
		userID = userID[:len(userID)-1]
	}

	// SOCKS4a domain name extension (0.0.0.x where x != 0)
	dstHost := dstIP
	if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 && hdr[7] != 0 {
		dom, _ := r.ReadString(0x00)
		if len(dom) > 0 {
			dstHost = dom[:len(dom)-1]
		}
	}

	sc.LogWithRemote("socks4_connect", sc.Conn.RemoteAddr(), logrus.Fields{
		"cmd":      cmd,
		"dst_host": dstHost,
		"dst_port": dstPort,
		"user":     userID,
	})

	// Reply: VN=0x00, CD=0x5a (request granted), DSTPORT, DSTIP
	reply := []byte{0x00, 0x5a, hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]}
	_, err := sc.Conn.Write(reply)
	return err
}
