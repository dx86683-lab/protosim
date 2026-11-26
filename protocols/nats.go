package protocols

import (
	"bufio"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("nats", NATS, 4222))
}

// NATS implements the NATS client text protocol (TCP 4222).
func NATS(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	info := `INFO {"server_id":"NPROTOSIM0000000000000000000000000000000000000000000001","server_name":"nats-01","version":"2.10.14","proto":1,"go":"go1.22.2","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"client_id":1}` + "\r\n"
	if _, err := sc.Conn.Write([]byte(info)); err != nil {
		return err
	}

	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.TrimSpace(line)
		sc.LogWithRemote("nats_command", sc.Conn.RemoteAddr(), logrus.Fields{
			"command": cmd,
		})
		upper := strings.ToUpper(cmd)
		switch {
		case upper == "PING":
			_, err = sc.Conn.Write([]byte("PONG\r\n"))
		case strings.HasPrefix(upper, "CONNECT"), strings.HasPrefix(upper, "SUB"), strings.HasPrefix(upper, "PUB"):
			_, err = sc.Conn.Write([]byte("+OK\r\n"))
		default:
			_, err = sc.Conn.Write([]byte("-ERR 'Unknown Protocol Operation'\r\n"))
		}
		if err != nil {
			return err
		}
	}
}
