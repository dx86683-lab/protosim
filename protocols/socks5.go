package protocols

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const socksReply = "200 OK"

var socksAccounts = []string{"guest:123456"}

func init() {
	AddProtocol(NewProtocolInfo("socks5", serveSOCKS5, 1080),
		ProtocolParams{Name: "auth", DefaultValue: true},
		ProtocolParams{Name: "accounts", DefaultValue: socksAccounts},
		ProtocolParams{Name: "resp_message", DefaultValue: socksReply})
}

func serveSOCKS5(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	method := byte(0)
	if session.GetBoolParams("auth") {
		method = 2
	}
	if !bytes.Contains(methods, []byte{method}) {
		return session.SendString("\x05\xff")
	}
	if _, err := session.Conn.Write([]byte{5, method}); err != nil {
		return err
	}
	if method == 2 {
		ok, err := socks5Authenticate(session, reader)
		if err != nil || !ok {
			return err
		}
	}
	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[2] != 0 {
		return errors.New("invalid SOCKS5 request")
	}

	var size int
	switch request[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return err
		}
		size = int(length[0])
	default:
		return session.SendString("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
	}
	address := make([]byte, size+2)
	if _, err := io.ReadFull(reader, address); err != nil {
		return err
	}
	socks5LogAction(session, request[1], request[3], address[:size], binary.BigEndian.Uint16(address[size:]))
	if request[1] != 1 {
		return session.SendString("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
	}

	// The reference returns a simulated bind address and an inline message.
	reply := [10]byte{5, 0, 0, 1}
	if _, err := rand.Read(reply[8:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(reply[8:]) == 0 {
		binary.BigEndian.PutUint16(reply[8:], 1080)
	}
	_, err := session.Conn.Write(append(reply[:], session.GetStringParams("resp_message", socksReply)...))
	return err
}

func socks5LogAction(session *SessionConnection, command, addressType byte, address []byte, port uint16) {
	if session.Log == nil {
		return
	}
	ip, domain := "0.0.0.0", ""
	if addressType == 3 {
		domain = string(address)
	} else {
		ip = net.IP(address).String()
	}
	fields := map[string]interface{}{"target_ip": ip, "target_fqdn": domain, "target_port": port}
	switch command {
	case 1:
		fields["method"], fields["body"], fields["body_raw"] = "connect", "", ""
	case 2:
		fields["method"] = "bind"
	case 3:
		fields["method"] = "assoc"
	default:
		fields["method"] = fmt.Sprintf("unknown(%d)", command)
	}
	session.LogWithRemote("action", session.Conn.RemoteAddr(), fields)
}

func socks5Authenticate(session *SessionConnection, reader io.Reader) (bool, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return false, err
	}
	if header[0] != 1 || header[1] == 0 {
		return false, errors.New("invalid SOCKS5 credentials frame")
	}
	user := make([]byte, header[1])
	if _, err := io.ReadFull(reader, user); err != nil {
		return false, err
	}
	var length [1]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return false, err
	}
	password := make([]byte, length[0])
	if _, err := io.ReadFull(reader, password); err != nil {
		return false, err
	}
	accounts := session.GetStringsParams("accounts", socksAccounts)
	ok := matchesConfiguredAccount(accounts, string(user), string(password))
	status, event := byte(1), "login failed"
	if ok {
		status, event = 0, "login ok"
	}
	if session.Log != nil {
		session.LogWithRemote(event, session.Conn.RemoteAddr(), map[string]interface{}{"user": string(user)})
	}
	_, err := session.Conn.Write([]byte{1, status})
	return ok, err
}
