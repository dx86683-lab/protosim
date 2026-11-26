package protocols

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const ftpDataConnectionFailed = "425 Data connection failed"

func (s *ftpControl) openLongPort(session *SessionConnection, argument string) string {
	if argument == "" {
		return ftpMissingArgument
	}
	fields := strings.Split(argument, ",")
	if fields[0] != "4" {
		return "522 Network protocol not supported, use 4"
	}
	if len(fields) < 2 || fields[1] != "4" {
		return "522 Network IP length not supported, use 4"
	}
	// The reference only replaces an existing data endpoint with LPRT.
	if s.active == nil && s.passive == nil {
		return ""
	}
	if len(fields) != 9 || fields[6] != "2" {
		return ftpDataConnectionFailed
	}
	ip, port := parseFTPPortFields(fields[2], fields[3], fields[4], fields[5], fields[7], fields[8])
	if s.active != nil {
		endpoint, ok := s.active.RemoteAddr().(*net.TCPAddr)
		if ok && endpoint.IP.Equal(ip) && endpoint.Port == int(port) {
			return ""
		}
	}
	return s.dialActive(session, ip, port, true)
}

func (s *ftpControl) openActive(session *SessionConnection, command, argument string) string {
	if argument == "" {
		return ftpMissingArgument
	}
	var ip net.IP
	var port uint16
	if command == "PORT" {
		ip, port = parseFTPPortFields(strings.Split(argument, ",")...)
	} else {
		var unsupported bool
		ip, port, unsupported = parseFTPExtendedPort(argument)
		if unsupported {
			return "522 Network protocol not supported, use (1,2)"
		}
	}
	return s.dialActive(session, ip, port, false)
}

func (s *ftpControl) dialActive(session *SessionConnection, ip net.IP, port uint16, keepOnFailure bool) string {
	peer, ok := session.Conn.RemoteAddr().(*net.TCPAddr)
	if !ok || !ip.Equal(peer.IP) || port < 1024 || session.DialTCPPeer == nil {
		return ftpDataConnectionFailed
	}
	if !keepOnFailure {
		s.closeData()
	}
	ctx, cancel := context.WithTimeout(context.Background(), ftpTransferTimeout)
	defer cancel()
	connection, err := session.DialTCPPeer(ctx, port)
	if err != nil {
		return ftpDataConnectionFailed
	}
	s.closeData()
	s.active = connection
	return fmt.Sprintf("200 Connection established (%d)", port)
}

func parseFTPPortFields(parts ...string) (net.IP, uint16) {
	if len(parts) != 6 {
		return nil, 0
	}
	var octets [6]byte
	for i, part := range parts {
		value, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, 0
		}
		octets[i] = byte(value)
	}
	ip := net.IPv4(octets[0], octets[1], octets[2], octets[3])
	return ip, uint16(octets[4])<<8 | uint16(octets[5])
}

func parseFTPExtendedPort(argument string) (net.IP, uint16, bool) {
	delimiter := argument[0]
	parts := strings.Split(argument, argument[:1])
	if delimiter < 33 || delimiter > 126 || len(parts) != 5 || parts[4] != "" ||
		(parts[1] != "1" && parts[1] != "2") {
		return nil, 0, true
	}
	ip := net.ParseIP(parts[2])
	if ip == nil || (ip.To4() != nil) != (parts[1] == "1") {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(parts[3], 10, 16)
	if err != nil {
		return nil, 0, false
	}
	return ip, uint16(port), false
}
