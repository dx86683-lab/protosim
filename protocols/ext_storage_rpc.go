package protocols

import (
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("ceph-mon", CephMon, 6789))
	AddProtocol(NewProtocolInfo("informix", Informix, 9088))
	AddProtocol(NewProtocolInfo("sybase", SybaseTDS, 5001))
	AddProtocol(NewProtocolInfo("thrift", ThriftRPC, 9091))
}

// CephMon implements Ceph Messenger v1 banner greeting (TCP 6789).
func CephMon(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	// Standard Ceph msgr v1 banner: "ceph v027\n" + 16-byte entity_addr
	banner := append([]byte("ceph v027\n"), make([]byte, 16)...)
	if _, err := sc.Conn.Write(banner); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := sc.Conn.Read(buf)
	if n > 0 {
		sc.LogWithRemote("ceph_mon_handshake", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})
	}
	return err
}

// Informix implements Informix SQLI wire handshake response (TCP 9088).
func Informix(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("informix_sqli", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})
	// Minimal Informix SQLI reply packet
	resp := []byte{0x00, 0x10, 0x01, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err = sc.Conn.Write(resp)
	return err
}

// SybaseTDS implements Sybase ASE TDS 5.0 response packet (TCP 5001).
func SybaseTDS(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if pktLen > 8 && pktLen < 16384 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(pktLen-8))
	}
	sc.LogWithRemote("sybase_tds", sc.Conn.RemoteAddr(), logrus.Fields{"packet_type": hdr[0], "length": pktLen})
	// TDS 5.0 Response (type=0x04, status=0x01 EOM) with LOGINACK token (0xad)
	msg := "Adaptive Server Enterprise/16.0"
	body := make([]byte, 0, 16+len(msg))
	body = append(body, 0xad, byte(len(msg)+6), 0x00, 0x05, 0x05, 0x00, 0x00, 0x00, byte(len(msg)))
	body = append(body, []byte(msg)...)
	body = append(body, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // DONE
	resp := make([]byte, 8+len(body))
	resp[0] = 0x04
	resp[1] = 0x01
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)))
	copy(resp[8:], body)
	_, err := sc.Conn.Write(resp)
	return err
}

// ThriftRPC implements Apache Thrift TBinaryProtocol / TFramedTransport exception response (TCP 9091).
func ThriftRPC(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 1024)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("thrift_rpc", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})
	// Thrift TBinaryProtocol EXCEPTION message (0x80010003)
	resp := []byte{
		0x80, 0x01, 0x00, 0x03, // VERSION_1 | EXCEPTION
		0x00, 0x00, 0x00, 0x04, 'p', 'i', 'n', 'g',
		0x00, 0x00, 0x00, 0x01, // seqid=1
		0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'm', 'e', 't', 'h', 'o', 'd',
		0x00, // STOP
	}
	_, err = sc.Conn.Write(resp)
	return err
}
