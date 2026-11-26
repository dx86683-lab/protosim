package protocols

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("ipmi", IPMI, 623))
	AddProtocol(NewProtocolInfo("jetdirect", JetDirect, 9100))
	AddProtocol(NewProtocolInfo("lpd", LPD, 515))
	AddProtocol(NewProtocolInfo("x11", X11, 6000))
	AddProtocol(NewProtocolInfo("xdmcp", XDMCP, 177))
	AddProtocol(NewProtocolInfo("epmd", EPMD, 4369))
	AddProtocol(NewProtocolInfo("iscsi", ISCSI, 3260))
	AddProtocol(NewProtocolInfo("rexec", Rexec, 512))
	AddProtocol(NewProtocolInfo("rlogin", Rlogin, 513))
	AddProtocol(NewProtocolInfo("rsh", RSH, 514))
	AddProtocol(NewProtocolInfo("afp", AFP, 548))
}

// IPMI implements RMCP/ASF Presence Ping -> Pong and IPMI v1.5/v2.0 Channel Auth Cap (UDP 623).
func IPMI(uc *UDPConnection, b []byte) error {
	if len(b) < 4 || b[0] != 0x06 {
		return nil
	}
	class := b[3]
	uc.LogWithRemote("ipmi_packet", uc.RemoteAddr(), logrus.Fields{
		"rmcp_class": class,
		"length":     len(b),
	})

	switch class {
	case 0x06: // ASF Presence Ping -> ASF Presence Pong
		tag := byte(0x00)
		if len(b) >= 10 {
			tag = b[9]
		}
		pong := []byte{
			0x06, 0x00, 0xff, 0x06, // RMCP v1.0, ASF
			0x00, 0x00, 0x11, 0xbe, // IANA Enterprise 4542 (ASF)
			0x40, tag, 0x00, 0x10, // Presence Pong, len=16
			0x00, 0x00, 0x11, 0xbe, // OEM IANA
			0x00, 0x00, 0x00, 0x00, // OEM defined
			0x81, 0x00, 0x00, 0x00, // IPMI supported (0x81)
			0x00, 0x00, 0x00, 0x00,
		}
		_, err := uc.WriteTo(pong, uc.RemoteAddr())
		return err
	case 0x07: // IPMI Get Channel Authentication Capabilities response
		resp := []byte{
			0x06, 0x00, 0xff, 0x07, // RMCP IPMI
			0x00,                   // AuthType = None
			0x00, 0x00, 0x00, 0x00, // Session Seq
			0x00, 0x00, 0x00, 0x00, // Session ID
			0x10,                   // IPMI Msg Len = 16
			0x81, 0x1c, 0x63,       // rsAddr=0x81, netFn=AppResp(0x07<<2), chk
			0x20, 0x00, 0x38,       // rqAddr=0x20, rqSeq=0, cmd=GetChannelAuthCap(0x38)
			0x00,                   // Completion code: OK
			0x01,                   // Channel 1
			0x97,                   // Auth types supported (IPMI v2.0 + MD5 + Password)
			0x04,                   // Non-null usernames enabled
			0x02,                   // IPMI v2.0 + v1.5
			0x00, 0x00, 0x00, 0x00, // OEM ID + Aux
			0x00,
		}
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
	return nil
}

// JetDirect implements HP JetDirect / PJL printer management (TCP 9100).
func JetDirect(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.TrimSpace(line)
		sc.LogWithRemote("jetdirect_cmd", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd})
		upper := strings.ToUpper(cmd)
		switch {
		case strings.Contains(upper, "INFO ID"):
			_, err = sc.Conn.Write([]byte("@PJL INFO ID\r\n\"HP LaserJet Pro M404dn\"\r\n\x0c"))
		case strings.Contains(upper, "INFO STATUS"):
			_, err = sc.Conn.Write([]byte("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n\x0c"))
		case strings.Contains(upper, "ECHO"):
			_, err = sc.Conn.Write([]byte(cmd + "\r\n\x0c"))
		default:
			_, err = sc.Conn.Write([]byte("@PJL INFO ID\r\n\"HP LaserJet Pro M404dn\"\r\n\x0c"))
		}
		if err != nil {
			return err
		}
	}
}

// LPD implements RFC 1179 Line Printer Daemon (TCP 515).
func LPD(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	sc.LogWithRemote("lpd_request", sc.Conn.RemoteAddr(), logrus.Fields{"raw": strings.TrimSpace(line)})
	if len(line) > 0 && (line[0] == 0x03 || line[0] == 0x04) {
		_, err = sc.Conn.Write([]byte("no entries\n"))
		return err
	}
	_, err = sc.Conn.Write([]byte{0x00})
	return err
}

// X11 implements X Window System TCP 6000 connection setup refusal (standard Nmap X11 fingerprint).
func X11(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 12)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 'l' && hdr[0] != 'B' {
		return nil
	}
	sc.LogWithRemote("x11_connect", sc.Conn.RemoteAddr(), logrus.Fields{"byte_order": string(hdr[0])})

	reason := "No protocol specified\n"
	pad := (4 - (len(reason) % 4)) % 4
	resp := make([]byte, 8+len(reason)+pad)
	resp[0] = 0 // Failed
	resp[1] = byte(len(reason))
	if hdr[0] == 'l' {
		binary.LittleEndian.PutUint16(resp[2:4], 11) // X11
		binary.LittleEndian.PutUint16(resp[6:8], uint16((len(reason)+pad)/4))
	} else {
		binary.BigEndian.PutUint16(resp[2:4], 11)
		binary.BigEndian.PutUint16(resp[6:8], uint16((len(reason)+pad)/4))
	}
	copy(resp[8:], reason)
	_, err := sc.Conn.Write(resp)
	return err
}

// XDMCP implements X Display Manager Control Protocol Query -> Willing (UDP 177).
func XDMCP(uc *UDPConnection, b []byte) error {
	if len(b) < 6 {
		return nil
	}
	opcode := binary.BigEndian.Uint16(b[2:4])
	uc.LogWithRemote("xdmcp_request", uc.RemoteAddr(), logrus.Fields{"opcode": opcode})
	if opcode == 1 || opcode == 2 || opcode == 3 { // BroadcastQuery / Query / IndirectQuery
		var body bytes.Buffer
		writeXDMCPString(&body, "")
		writeXDMCPString(&body, "protosim-x11")
		writeXDMCPString(&body, "Willing to manage")
		resp := make([]byte, 6+body.Len())
		binary.BigEndian.PutUint16(resp[0:2], 1) // version 1
		binary.BigEndian.PutUint16(resp[2:4], 5) // Willing
		binary.BigEndian.PutUint16(resp[4:6], uint16(body.Len()))
		copy(resp[6:], body.Bytes())
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
	return nil
}

func writeXDMCPString(buf *bytes.Buffer, s string) {
	_ = binary.Write(buf, binary.BigEndian, uint16(len(s)))
	buf.WriteString(s)
}

// EPMD implements Erlang Port Mapper Daemon (TCP 4369) NAMES_REQ (0x6e) -> node list.
func EPMD(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	pktLen := int(binary.BigEndian.Uint16(hdr))
	if pktLen <= 0 || pktLen > 4096 {
		return nil
	}
	payload := make([]byte, pktLen)
	if _, err := io.ReadFull(sc.Conn, payload); err != nil {
		return err
	}
	sc.LogWithRemote("epmd_request", sc.Conn.RemoteAddr(), logrus.Fields{"tag": payload[0]})

	if payload[0] == 0x6e { // NAMES_REQ ('n')
		var resp bytes.Buffer
		_ = binary.Write(&resp, binary.BigEndian, uint32(4369))
		resp.WriteString("name rabbit at port 25672\nname couchdb at port 9100\n")
		_, err := sc.Conn.Write(resp.Bytes())
		return err
	}
	return nil
}

// ISCSI implements RFC 3720 iSCSI Login Request -> Login Response (TCP 3260).
func ISCSI(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	bhs := make([]byte, 48)
	if _, err := io.ReadFull(sc.Conn, bhs); err != nil {
		return err
	}
	opcode := bhs[0] & 0x3f
	sc.LogWithRemote("iscsi_pdu", sc.Conn.RemoteAddr(), logrus.Fields{"opcode": opcode})
	if opcode != 0x03 { // Login Request
		return nil
	}
	dataLen := int(bhs[5])<<16 | int(bhs[6])<<8 | int(bhs[7])
	if dataLen > 0 && dataLen < 65536 {
		pad := (4 - (dataLen % 4)) % 4
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(dataLen+pad))
	}
	// Login Response (0x23), Status-Class=0x02 (Initiator Error), Status-Detail=0x01 (Auth Failure)
	resp := make([]byte, 48)
	resp[0] = 0x23
	resp[1] = 0x00
	copy(resp[8:14], bhs[8:14])   // ISID
	copy(resp[16:20], bhs[16:20]) // Initiator Task Tag
	resp[36] = 0x02               // Status-Class: Initiator Error
	resp[37] = 0x01               // Auth Failure
	_, err := sc.Conn.Write(resp)
	return err
}

func Rexec(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, _ := sc.Conn.Read(buf)
	parts := bytes.Split(buf[:n], []byte{0})
	user, pass, cmd := "", "", ""
	if len(parts) > 1 {
		user = string(parts[1])
	}
	if len(parts) > 2 {
		pass = string(parts[2])
	}
	if len(parts) > 3 {
		cmd = string(parts[3])
	}
	sc.LogWithRemote("rexec_auth", sc.Conn.RemoteAddr(), logrus.Fields{
		"username": user, "password": pass, "command": cmd, "accepted": false,
	})
	_, err := sc.Conn.Write([]byte("\x01Login incorrect.\n"))
	return err
}

func Rlogin(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, _ := sc.Conn.Read(buf)
	sc.LogWithRemote("rlogin_request", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:n])})
	_, err := sc.Conn.Write([]byte("\x00Password: "))
	return err
}

func RSH(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, _ := sc.Conn.Read(buf)
	sc.LogWithRemote("rsh_request", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:n])})
	_, err := sc.Conn.Write([]byte("\x01Permission denied.\n"))
	return err
}

// AFP implements Apple Filing Protocol DSI GetStatus (TCP 548).
func AFP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 16)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	cmd := hdr[1]
	reqID := binary.BigEndian.Uint16(hdr[2:4])
	sc.LogWithRemote("afp_dsi", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd, "request_id": reqID})
	if cmd != 3 { // DSIGetStatus
		return nil
	}
	// Minimal AFP ServerInfo payload
	var info bytes.Buffer
	_ = binary.Write(&info, binary.BigEndian, uint16(0)) // machine offset
	_ = binary.Write(&info, binary.BigEndian, uint16(0)) // afp versions offset
	_ = binary.Write(&info, binary.BigEndian, uint16(0)) // uams offset
	_ = binary.Write(&info, binary.BigEndian, uint16(0)) // icon offset
	_ = binary.Write(&info, binary.BigEndian, uint16(0)) // flags
	srvName := "ProtoSim-AFP"
	info.WriteByte(byte(len(srvName)))
	info.WriteString(srvName)

	resp := make([]byte, 16+info.Len())
	resp[0] = 0x01 // Reply
	resp[1] = 0x03 // DSIGetStatus
	binary.BigEndian.PutUint16(resp[2:4], reqID)
	binary.BigEndian.PutUint32(resp[8:12], uint32(info.Len()))
	copy(resp[16:], info.Bytes())
	_, err := sc.Conn.Write(resp)
	return err
}

var _ = fmt.Sprintf
