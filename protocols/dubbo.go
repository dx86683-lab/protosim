package protocols

import (
	"bufio"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("dubbo", Dubbo, 20880))
}

// Dubbo implements the Apache Dubbo Telnet & binary magic (0xdabb) listener (TCP 20880).
func Dubbo(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	peek, err := r.Peek(2)
	if err != nil {
		return err
	}

	// Binary Dubbo RPC header magic 0xda 0xbb
	if peek[0] == 0xda && peek[1] == 0xbb {
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		sc.LogWithRemote("dubbo_rpc", sc.Conn.RemoteAddr(), logrus.Fields{
			"bytes": n,
		})
		// Minimal Dubbo response header: magic 0xdabb, flag=0x02 (response), status=20 (OK), 8B reqID, 4B dataLen=2, "{}"
		resp := []byte{0xda, 0xbb, 0x02, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, '{', '}'}
		if n >= 12 {
			copy(resp[4:12], buf[4:12])
		}
		_, err = sc.Conn.Write(resp)
		return err
	}

	// Telnet management interface (used by nuclei/fscan/nmap)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.TrimSpace(line)
		sc.LogWithRemote("dubbo_telnet", sc.Conn.RemoteAddr(), logrus.Fields{
			"command": cmd,
		})
		var out string
		switch {
		case cmd == "ls":
			out = "com.example.user.UserService\r\ncom.example.order.OrderService\r\ndubbo>"
		case cmd == "status":
			out = "OK\r\ndubbo>"
		case cmd == "ps":
			out = "20880\r\ndubbo>"
		case cmd == "pwd":
			out = "/\r\ndubbo>"
		case cmd == "exit" || cmd == "quit":
			return nil
		default:
			out = "dubbo>"
		}
		if _, err := sc.Conn.Write([]byte(out)); err != nil {
			return err
		}
	}
}
