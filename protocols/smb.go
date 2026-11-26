package protocols

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"time"
)

const (
	smb2HeaderSize           = 64
	smb2NegotiateRequestSize = 36
	smb2Dialect210           = 0x0210
	smb2DialectUpgrade       = 0x02ff
	smbDefaultName           = "NASE83ACA"
	smbDefaultAccount        = "administrator:123456"
)

// SPNEGO NegTokenInit advertises the reference's NTLM mechanism.
var smbNegotiateToken = [...]byte{
	0x60, 0x1c, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
	0xa0, 0x12, 0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
}

var smbDefaultShares = []string{"admin:Home directory", "public:Public directory"}

func init() {
	AddProtocol(NewProtocolInfo("smb", serveSMB, 445),
		ProtocolParams{Name: "domain_name", DefaultValue: smbDefaultName},
		ProtocolParams{Name: "server_name", DefaultValue: smbDefaultName},
		ProtocolParams{Name: "accounts", DefaultValue: []string{smbDefaultAccount}},
		ProtocolParams{Name: "shares", DefaultValue: smbDefaultShares})
}

func serveSMB(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	name := session.GetStringParams("server_name", smbDefaultName)
	state := smbSession{
		server:   name,
		domain:   session.GetStringParams("domain_name", smbDefaultName),
		accounts: session.GetStringsParams("accounts", []string{smbDefaultAccount}),
		shares:   session.GetStringsParams("shares", smbDefaultShares),
	}
	negotiated := false
	for {
		var transport [4]byte
		if _, err := io.ReadFull(session.Conn, transport[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(transport[:])
		if size < 4 || size > 65535 {
			return nil
		}
		wire := make([]byte, size)
		if _, err := io.ReadFull(session.Conn, wire); err != nil {
			return err
		}
		if negotiated {
			closeAfter, err := state.handleRecord(wire, session.Conn)
			if err != nil {
				return err
			}
			if closeAfter {
				return nil
			}
			continue
		}
		dialect, messageID := smbNegotiateRequest(wire)
		if dialect == 0 {
			return nil
		}
		if _, err := session.Conn.Write(smbNegotiateReply(name, dialect, messageID, time.Now())); err != nil {
			return err
		}
		negotiated = dialect != smb2DialectUpgrade
	}
}

func smbNegotiateRequest(wire []byte) (dialect uint16, messageID uint64) {
	le := binary.LittleEndian
	switch string(wire[:4]) {
	case "\xfeSMB":
		if len(wire) < smb2HeaderSize+smb2NegotiateRequestSize ||
			le.Uint16(wire[4:]) != smb2HeaderSize || le.Uint16(wire[12:]) != 0 ||
			le.Uint32(wire[16:])&1 != 0 || le.Uint32(wire[20:]) != 0 {
			return 0, 0
		}
		body := wire[smb2HeaderSize:]
		count := int(le.Uint16(body[2:]))
		if le.Uint16(body) != smb2NegotiateRequestSize || count == 0 ||
			count > (len(body)-smb2NegotiateRequestSize)/2 {
			return 0, 0
		}
		// The reference reports 2.1 even when the offer contains only 3.x.
		return smb2Dialect210, le.Uint64(wire[24:])
	case "\xffSMB":
		if len(wire) < 35 || wire[4] != 0x72 || wire[32] != 0 || int(le.Uint16(wire[33:])) != len(wire)-35 {
			return 0, 0
		}
		for offers := wire[35:]; len(offers) > 0; {
			if offers[0] != 2 {
				return 0, 0
			}
			end := bytes.IndexByte(offers[1:], 0)
			if end < 0 {
				return 0, 0
			}
			if string(offers[1:1+end]) == "SMB 2.???" {
				return smb2DialectUpgrade, 0
			}
			offers = offers[end+2:]
		}
	}
	return 0, 0
}

func smbNegotiateReply(name string, dialect uint16, messageID uint64, now time.Time) []byte {
	const fixedBodySize = 64
	packet := make([]byte, 4+smb2HeaderSize+fixedBodySize+len(smbNegotiateToken))
	binary.BigEndian.PutUint32(packet, uint32(len(packet)-4))
	le := binary.LittleEndian
	header, body := packet[4:4+smb2HeaderSize], packet[4+smb2HeaderSize:]
	copy(header, "\xfeSMB")
	le.PutUint16(header[4:], smb2HeaderSize)
	le.PutUint16(header[14:], 1) // Credits granted.
	le.PutUint32(header[16:], 1) // Server-to-client flag.
	le.PutUint64(header[24:], messageID)
	le.PutUint16(body, fixedBodySize+1)
	le.PutUint16(body[2:], 1)
	le.PutUint16(body[4:], dialect)
	copy(body[8:24], strings.ToLower(name))
	le.PutUint32(body[24:], 4) // Large MTU capability.
	for _, offset := range []int{28, 32, 36} {
		le.PutUint32(body[offset:], 1<<20)
	}
	const unixEpochFileTime = 116444736000000000
	le.PutUint64(body[40:], unixEpochFileTime+uint64(now.UnixNano()/100))
	le.PutUint16(body[56:], smb2HeaderSize+fixedBodySize)
	le.PutUint16(body[58:], uint16(len(smbNegotiateToken)))
	copy(body[fixedBodySize:], smbNegotiateToken[:])
	return packet
}
