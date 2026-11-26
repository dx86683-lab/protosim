package protocols

import (
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("ajp", AJP13, 8009))
}

// AJP13 implements Apache JServ Protocol v1.3 (CPing/CPong + Forward Request response).
func AJP13(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	for {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
			return err
		}
		// Client-to-container magic is 0x1234
		if hdr[0] != 0x12 || hdr[1] != 0x34 {
			sc.LogWithRemote("ajp_invalid_magic", sc.Conn.RemoteAddr(), logrus.Fields{
				"magic": binary.BigEndian.Uint16(hdr[0:2]),
			})
			return nil
		}
		pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if pktLen <= 0 || pktLen > 8192 {
			return nil
		}
		payload := make([]byte, pktLen)
		if _, err := io.ReadFull(sc.Conn, payload); err != nil {
			return err
		}
		prefix := payload[0]
		sc.LogWithRemote("ajp_packet", sc.Conn.RemoteAddr(), logrus.Fields{
			"prefix": prefix,
			"length": pktLen,
		})

		switch prefix {
		case 0x0a: // CPing -> respond with CPong (0x4142 0x0001 0x09)
			cpong := []byte{0x41, 0x42, 0x00, 0x01, 0x09}
			if _, err := sc.Conn.Write(cpong); err != nil {
				return err
			}
		case 0x02: // Forward Request -> Send Headers (403 Forbidden) + End Response
			// Send Headers packet: type=0x04, status=403, msg="Forbidden", num_headers=0
			sendHdr := buildAJPPacket([]byte{
				0x04,
				0x01, 0x93, // 403
				0x00, 0x09, 'F', 'o', 'r', 'b', 'i', 'd', 'd', 'e', 'n', 0x00,
				0x00, 0x00, // 0 headers
			})
			endResp := buildAJPPacket([]byte{0x05, 0x01}) // End Response, reuse=true
			if _, err := sc.Conn.Write(append(sendHdr, endResp...)); err != nil {
				return err
			}
		default:
			endResp := buildAJPPacket([]byte{0x05, 0x00})
			if _, err := sc.Conn.Write(endResp); err != nil {
				return err
			}
			return nil
		}
	}
}

func buildAJPPacket(body []byte) []byte {
	pkt := make([]byte, 4+len(body))
	pkt[0] = 0x41 // 'A'
	pkt[1] = 0x42 // 'B'
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(body)))
	copy(pkt[4:], body)
	return pkt
}
