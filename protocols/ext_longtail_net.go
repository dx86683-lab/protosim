package protocols

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("wireguard", WireGuardUDP, 51820))
	AddProtocol(NewProtocolInfo("rip", RIPv2, 520))
	AddProtocol(NewProtocolInfo("nat-pmp", NATPMP, 5351))
	AddProtocol(NewProtocolInfo("hart-ip", HARTIP, 5094))
	AddProtocol(NewProtocolInfo("codesys", CodeSys, 2455))
	AddProtocol(NewProtocolInfo("proconos", ProConOS, 20547))
	AddProtocol(NewProtocolInfo("gopher", Gopher, 70))
	AddProtocol(NewProtocolInfo("dict", DICT, 2628))
}

// WireGuardUDP records incoming WireGuard Handshake Initiation packets (UDP 51820).
// Per WireGuard spec, unauthenticated peers receive no reply, while ProtoSim records the full probe.
func WireGuardUDP(uc *UDPConnection, b []byte) error {
	msgType := byte(0)
	if len(b) > 0 {
		msgType = b[0]
	}
	uc.LogWithRemote("wireguard_packet", uc.RemoteAddr(), logrus.Fields{"msg_type": msgType, "length": len(b)})
	return nil
}

// RIPv2 implements RFC 2453 RIP Request (cmd=1) -> Response (cmd=2) on UDP 520.
func RIPv2(uc *UDPConnection, b []byte) error {
	if len(b) < 4 {
		return nil
	}
	cmd, ver := b[0], b[1]
	uc.LogWithRemote("rip_packet", uc.RemoteAddr(), logrus.Fields{"command": cmd, "version": ver})
	if cmd == 1 {
		resp := make([]byte, 24)
		resp[0] = 2   // Response
		resp[1] = ver // Echo RIP version (1 or 2)
		if resp[1] == 0 {
			resp[1] = 2
		}
		binary.BigEndian.PutUint16(resp[4:6], 2) // AF_INET
		copy(resp[8:12], []byte{10, 0, 0, 0})    // Network
		copy(resp[12:16], []byte{255, 255, 255, 0})
		binary.BigEndian.PutUint32(resp[20:24], 1) // Metric 1
		_, err := uc.WriteTo(resp, uc.RemoteAddr())
		return err
	}
	return nil
}

// NATPMP implements RFC 6886 NAT-PMP External Address Request -> Response (UDP 5351).
func NATPMP(uc *UDPConnection, b []byte) error {
	if len(b) < 2 {
		return nil
	}
	uc.LogWithRemote("natpmp_request", uc.RemoteAddr(), logrus.Fields{"version": b[0], "opcode": b[1]})
	resp := make([]byte, 12)
	resp[0] = 0          // Version 0
	resp[1] = b[1] | 128 // Response opcode
	binary.BigEndian.PutUint16(resp[2:4], 0)
	binary.BigEndian.PutUint32(resp[4:8], 3600) // Epoch seconds
	copy(resp[8:12], []byte{203, 0, 113, 10})   // External IPv4
	_, err := uc.WriteTo(resp, uc.RemoteAddr())
	return err
}

// HARTIP implements HART-IP Session Initiate Response (TCP 5094).
func HARTIP(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	msgLen := int(binary.BigEndian.Uint16(hdr[6:8]))
	if msgLen > 8 && msgLen < 4096 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(msgLen-8))
	}
	sc.LogWithRemote("hartip_packet", sc.Conn.RemoteAddr(), logrus.Fields{"version": hdr[0], "msg_type": hdr[1], "msg_id": hdr[2]})
	// Session Initiate Response (msg_type=1, msg_id=0, status=0, body=5 bytes)
	resp := []byte{0x01, 0x01, 0x00, 0x00, hdr[4], hdr[5], 0x00, 0x0d, 0x01, 0x00, 0x00, 0x75, 0x30}
	_, err := sc.Conn.Write(resp)
	return err
}

// CodeSys implements CODESYS PLC Runtime greeting/response (TCP 2455).
func CodeSys(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("codesys_probe", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})
	resp := []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x59, 0x53, 0x00}
	_, err = sc.Conn.Write(resp)
	return err
}

// ProConOS implements ProConOS PLC info response (TCP 20547).
func ProConOS(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("proconos_probe", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})
	resp := append([]byte{0xcc, 0x01, 0x00, 0x20}, []byte("ProConOS V4.1.0454\x00ProtoSim-PLC\x00")...)
	_, err = sc.Conn.Write(resp)
	return err
}

// Gopher implements RFC 1436 Gopher menu listing (TCP 70).
func Gopher(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	line, _ := bufio.NewReader(sc.Conn).ReadString('\n')
	sc.LogWithRemote("gopher_selector", sc.Conn.RemoteAddr(), logrus.Fields{"selector": strings.TrimSpace(line)})
	menu := "iWelcome to ProtoSim Gopher Server\tfake\t(NULL)\t0\r\n0About\t/about.txt\tgopher.protosim.local\t70\r\n.\r\n"
	_, err := sc.Conn.Write([]byte(menu))
	return err
}

// DICT implements RFC 2229 Dictionary Server Protocol (TCP 2628).
func DICT(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	if _, err := sc.Conn.Write([]byte("220 dict.protosim.local dictd 1.13.1/rf on Linux <auth.mime> <1001.1@dict.protosim.local>\r\n")); err != nil {
		return err
	}
	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		sc.LogWithRemote("dict_command", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd})
		switch {
		case strings.HasPrefix(cmd, "SHOW DB"):
			_, err = sc.Conn.Write([]byte("110 1 databases present\r\nwn \"WordNet 3.1\"\r\n.\r\n250 ok\r\n"))
		case strings.HasPrefix(cmd, "STATUS"):
			_, err = sc.Conn.Write([]byte("210 status [d/m/c = 0/0/0]\r\n"))
		case cmd == "QUIT":
			_, _ = sc.Conn.Write([]byte("221 bye\r\n"))
			return nil
		default:
			_, err = sc.Conn.Write([]byte(fmt.Sprintf("500 unknown command %q\r\n", cmd)))
		}
		if err != nil {
			return err
		}
	}
}
