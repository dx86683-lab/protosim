package protocols

import (
	"bufio"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("nntp", NNTP, 119))
}

// NNTP implements RFC 3977 Network News Transfer Protocol (TCP 119).
func NNTP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	if _, err := sc.Conn.Write([]byte("200 news.protosim.local InterNetNews NNRP server INN 2.7.2 ready (posting ok)\r\n")); err != nil {
		return err
	}

	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		sc.LogWithRemote("nntp_command", sc.Conn.RemoteAddr(), logrus.Fields{
			"command": cmd,
		})

		switch {
		case cmd == "CAPABILITIES":
			_, err = sc.Conn.Write([]byte("101 Capability list:\r\nVERSION 2\r\nIMPLEMENTATION INN 2.7.2\r\nREADER\r\nPOST\r\nLIST ACTIVE NEWSGROUPS\r\n.\r\n"))
		case cmd == "LIST" || strings.HasPrefix(cmd, "LIST "):
			_, err = sc.Conn.Write([]byte("215 Newsgroups in form \"group high low status\"\r\ncomp.security.misc 10 1 y\r\n.\r\n"))
		case cmd == "QUIT":
			_, _ = sc.Conn.Write([]byte("205 Bye!\r\n"))
			return nil
		default:
			_, err = sc.Conn.Write([]byte("500 What?\r\n"))
		}
		if err != nil {
			return err
		}
	}
}
