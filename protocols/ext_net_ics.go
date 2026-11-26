package protocols

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("stun", STUN, 3478))
	AddProtocol(NewProtocolInfo("openvpn", OpenVPN, 1194))
	AddProtocol(NewProtocolInfo("radius", RADIUS, 1812))
	AddProtocol(NewProtocolInfo("tacacs", TACACS, 49))
	AddProtocol(NewProtocolInfo("xmpp", XMPP, 5222))
	AddProtocol(NewProtocolInfo("rtmp", RTMP, 1935))
	AddProtocol(NewProtocolInfo("bitcoin", Bitcoin, 8333))
	AddProtocol(NewProtocolInfo("finger", Finger, 79))
	AddProtocol(NewProtocolInfo("whois", Whois, 43))
	AddProtocol(NewProtocolInfo("ident", Ident, 113))
	AddProtocol(NewProtocolInfo("chargen", Chargen, 19))
	AddProtocol(NewProtocolInfo("daytime", Daytime, 13))
	AddProtocol(NewProtocolInfo("syslog", SyslogUDP, 514))
	AddProtocol(NewProtocolInfo("opcua", OPCUA, 4840))
	AddProtocol(NewProtocolInfo("knx", KNX, 3671))
}

// STUN implements RFC 5389 STUN Binding Request -> Binding Success Response (UDP 3478).
func STUN(uc *UDPConnection, b []byte) error {
	if len(b) < 20 {
		return nil
	}
	msgType := binary.BigEndian.Uint16(b[0:2])
	magic := binary.BigEndian.Uint32(b[4:8])
	uc.LogWithRemote("stun_packet", uc.RemoteAddr(), logrus.Fields{"msg_type": msgType, "magic": magic})
	if msgType != 0x0001 || magic != 0x2112a442 {
		return nil
	}
	ip := net.IPv4(127, 0, 0, 1).To4()
	port := uint16(54321)
	if ua, ok := uc.RemoteAddr().(*net.UDPAddr); ok && ua.IP.To4() != nil {
		ip = ua.IP.To4()
		port = uint16(ua.Port)
	}
	resp := make([]byte, 32)
	binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Success Response
	binary.BigEndian.PutUint16(resp[2:4], 12)     // Attr len
	binary.BigEndian.PutUint32(resp[4:8], 0x2112a442)
	copy(resp[8:20], b[8:20]) // Transaction ID
	// XOR-MAPPED-ADDRESS (0x0020)
	binary.BigEndian.PutUint16(resp[20:22], 0x0020)
	binary.BigEndian.PutUint16(resp[22:24], 8)
	resp[25] = 0x01 // IPv4
	binary.BigEndian.PutUint16(resp[26:28], port^0x2112)
	resp[28] = ip[0] ^ 0x21
	resp[29] = ip[1] ^ 0x12
	resp[30] = ip[2] ^ 0xa4
	resp[31] = ip[3] ^ 0x42
	_, err := uc.WriteTo(resp, uc.RemoteAddr())
	return err
}

// OpenVPN implements OpenVPN UDP P_CONTROL_HARD_RESET_CLIENT_V2 -> SERVER_V2 (UDP 1194).
func OpenVPN(uc *UDPConnection, b []byte) error {
	if len(b) < 14 {
		return nil
	}
	opcode := b[0] >> 3
	uc.LogWithRemote("openvpn_packet", uc.RemoteAddr(), logrus.Fields{"opcode": opcode, "length": len(b)})
	if opcode == 7 { // P_CONTROL_HARD_RESET_CLIENT_V2
		resp := make([]byte, 26)
		resp[0] = (8 << 3) | (b[0] & 0x07) // P_CONTROL_HARD_RESET_SERVER_V2
		copy(resp[1:9], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
		resp[9] = 1 // 1 ACK packet ID
		copy(resp[10:14], b[10:14])
		copy(resp[14:22], b[1:9]) // remote session ID
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
	return nil
}

// RADIUS implements RFC 2865 Access-Request -> Access-Reject with valid MD5 response authenticator (UDP 1812).
func RADIUS(uc *UDPConnection, b []byte) error {
	if len(b) < 20 || b[0] != 1 {
		return nil
	}
	id := b[1]
	reqAuth := b[4:20]
	uc.LogWithRemote("radius_access_request", uc.RemoteAddr(), logrus.Fields{"id": id, "length": len(b)})

	secret := uc.GetStringParams("secret", "testing123")
	resp := make([]byte, 20)
	resp[0] = 3 // Access-Reject
	resp[1] = id
	binary.BigEndian.PutUint16(resp[2:4], 20)
	h := md5.New()
	h.Write(resp[0:4])
	h.Write(reqAuth)
	h.Write([]byte(secret))
	copy(resp[4:20], h.Sum(nil))
	_, err := uc.WriteTo(resp, uc.RemoteAddr())
	return err
}

// TACACS implements RFC 8907 TACACS+ header reply (TCP 49).
func TACACS(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 12)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if hdr[0]>>4 != 0x0c { // TACACS+ major version 12 (0xc)
		return nil
	}
	bodyLen := binary.BigEndian.Uint32(hdr[8:12])
	if bodyLen > 0 && bodyLen < 65536 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(bodyLen))
	}
	sc.LogWithRemote("tacacs_packet", sc.Conn.RemoteAddr(), logrus.Fields{"type": hdr[1], "seq": hdr[2]})

	// Unencrypted TACACS+ reply (flags=0x01 unencrypted, status=FAIL)
	replyBody := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	resp := make([]byte, 12+len(replyBody))
	resp[0] = hdr[0]
	resp[1] = hdr[1]
	resp[2] = hdr[2] + 1
	resp[3] = 0x01 // unencrypted
	copy(resp[4:8], hdr[4:8])
	binary.BigEndian.PutUint32(resp[8:12], uint32(len(replyBody)))
	copy(resp[12:], replyBody)
	_, err := sc.Conn.Write(resp)
	return err
}

// XMPP implements RFC 6120 Jabber/XMPP XML stream negotiation (TCP 5222).
func XMPP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	buf := make([]byte, 1024)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("xmpp_stream", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:min(n, 200)])})
	resp := `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='protosim-1' from='xmpp.protosim.local' version='1.0'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>`
	_, err = sc.Conn.Write([]byte(resp))
	return err
}

// RTMP implements Adobe RTMP C0+C1 -> S0+S1+S2 handshake (TCP 1935).
func RTMP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	c01 := make([]byte, 1537)
	if _, err := io.ReadFull(sc.Conn, c01); err != nil {
		return err
	}
	if c01[0] != 0x03 {
		return nil
	}
	sc.LogWithRemote("rtmp_handshake", sc.Conn.RemoteAddr(), logrus.Fields{"version": c01[0]})
	s012 := make([]byte, 1+1536+1536)
	s012[0] = 0x03
	copy(s012[1+1536:], c01[1:]) // S2 echoes C1
	_, err := sc.Conn.Write(s012)
	return err
}

// Bitcoin implements Bitcoin Mainnet P2P version handshake (TCP 8333).
func Bitcoin(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 24)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if !bytes.Equal(hdr[0:4], []byte{0xf9, 0xbe, 0xb4, 0xd9}) {
		return nil
	}
	cmd := strings.TrimRight(string(hdr[4:16]), "\x00")
	pLen := binary.LittleEndian.Uint32(hdr[16:20])
	if pLen > 0 && pLen < 65536 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(pLen))
	}
	sc.LogWithRemote("bitcoin_p2p", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd, "length": pLen})

	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, int32(70016)) // protocol version
	_ = binary.Write(&payload, binary.LittleEndian, uint64(1))    // services
	_ = binary.Write(&payload, binary.LittleEndian, time.Now().Unix())
	payload.Write(make([]byte, 52)) // addr_recv + addr_from
	_ = binary.Write(&payload, binary.LittleEndian, uint64(0x12345678))
	ua := "/Satoshi:27.0.0/"
	payload.WriteByte(byte(len(ua)))
	payload.WriteString(ua)
	_ = binary.Write(&payload, binary.LittleEndian, int32(840000))
	payload.WriteByte(1)

	verMsg := buildBitcoinFrame("version", payload.Bytes())
	verackMsg := buildBitcoinFrame("verack", nil)
	_, err := sc.Conn.Write(append(verMsg, verackMsg...))
	return err
}

func buildBitcoinFrame(cmd string, payload []byte) []byte {
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	frame := make([]byte, 24+len(payload))
	copy(frame[0:4], []byte{0xf9, 0xbe, 0xb4, 0xd9})
	copy(frame[4:16], []byte(cmd))
	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(payload)))
	copy(frame[20:24], h2[0:4])
	copy(frame[24:], payload)
	return frame
}

func Finger(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	line, err := bufio.NewReader(sc.Conn).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	q := strings.TrimSpace(line)
	sc.LogWithRemote("finger_query", sc.Conn.RemoteAddr(), logrus.Fields{"query": q})
	resp := "Login     Name       Tty      Idle  Login Time   Office\r\nroot      root       tty1        5  Nov 26 08:00\r\n"
	_, err = sc.Conn.Write([]byte(resp))
	return err
}

func Whois(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	line, err := bufio.NewReader(sc.Conn).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	q := strings.TrimSpace(line)
	sc.LogWithRemote("whois_query", sc.Conn.RemoteAddr(), logrus.Fields{"query": q})
	resp := fmt.Sprintf("Domain Name: %s\r\nRegistrar: ProtoSim NIC\r\nStatus: active\r\n", q)
	_, err = sc.Conn.Write([]byte(resp))
	return err
}

func Ident(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	line, err := bufio.NewReader(sc.Conn).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	q := strings.TrimSpace(line)
	sc.LogWithRemote("ident_query", sc.Conn.RemoteAddr(), logrus.Fields{"query": q})
	_, err = sc.Conn.Write([]byte(fmt.Sprintf("%s : ERROR : NO-USER\r\n", q)))
	return err
}

func Chargen(uc *UDPConnection, b []byte) error {
	uc.LogWithRemote("chargen_probe", uc.RemoteAddr(), logrus.Fields{"bytes": len(b)})
	_, err := uc.WriteTo([]byte("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg\r\n"), uc.RemoteAddr())
	return err
}

func Daytime(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	sc.LogWithRemote("daytime_request", sc.Conn.RemoteAddr(), logrus.Fields{})
	_, err := sc.Conn.Write([]byte(time.Now().UTC().Format(time.RFC1123) + "\r\n"))
	return err
}

func SyslogUDP(uc *UDPConnection, b []byte) error {
	uc.LogWithRemote("syslog_message", uc.RemoteAddr(), logrus.Fields{"message": strings.TrimSpace(string(b))})
	return nil
}

// OPCUA implements OPC-UA Binary HEL -> ACK handshake (TCP 4840).
func OPCUA(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if string(hdr[0:3]) != "HEL" {
		return nil
	}
	msgLen := int(binary.LittleEndian.Uint32(hdr[4:8]))
	if msgLen > 8 && msgLen < 65536 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(msgLen-8))
	}
	sc.LogWithRemote("opcua_hello", sc.Conn.RemoteAddr(), logrus.Fields{"length": msgLen})

	// OPC-UA ACK message (28 bytes)
	ack := make([]byte, 28)
	copy(ack[0:4], []byte("ACKF"))
	binary.LittleEndian.PutUint32(ack[4:8], 28)
	binary.LittleEndian.PutUint32(ack[8:12], 0)     // ProtocolVersion
	binary.LittleEndian.PutUint32(ack[12:16], 65536) // ReceiveBufferSize
	binary.LittleEndian.PutUint32(ack[16:20], 65536) // SendBufferSize
	binary.LittleEndian.PutUint32(ack[20:24], 0)     // MaxMessageSize
	binary.LittleEndian.PutUint32(ack[24:28], 0)     // MaxChunkCount
	_, err := sc.Conn.Write(ack)
	return err
}

// KNX implements KNXnet/IP Search Request (0x0201) -> Search Response (0x0202) on UDP 3671.
func KNX(uc *UDPConnection, b []byte) error {
	if len(b) < 6 || b[0] != 0x06 || b[1] != 0x10 {
		return nil
	}
	svcType := binary.BigEndian.Uint16(b[2:4])
	uc.LogWithRemote("knx_packet", uc.RemoteAddr(), logrus.Fields{"service_type": svcType})
	if svcType == 0x0201 { // SEARCH_REQUEST
		resp := []byte{
			0x06, 0x10, 0x02, 0x02, 0x00, 0x26, // Header: KNXnet/IP v1.0, SEARCH_RESPONSE, len=38
			0x08, 0x01, 192, 168, 1, 10, 0x0e, 0x57, // HPAI Control Endpoint
			0x18, 0x01, 0x02, 0x00, 0x11, 0x00, // DIB Device Info
			0x00, 0x00, 0x00, 0x01, 0x02, 0x03, // KNX Serial
			224, 0, 23, 12, // Multicast addr
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
			'K', 'N',
		}
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
	return nil
}
