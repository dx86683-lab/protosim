package protocols

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("irc", IRC, 6667),
		ProtocolParams{
			Name:         "server_name",
			DefaultValue: "irc.protosim.local",
		},
	)
}

// IRC implements RFC 1459 Internet Relay Chat greeting & registration (TCP 6667).
func IRC(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	srv := sc.GetStringParams("server_name", "irc.protosim.local")
	_, _ = sc.Conn.Write([]byte(fmt.Sprintf(":%s NOTICE AUTH :*** Looking up your hostname...\r\n", srv)))

	r := bufio.NewReader(sc.Conn)
	nick := "*"
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmdLine := strings.TrimSpace(line)
		parts := strings.Fields(cmdLine)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		sc.LogWithRemote("irc_command", sc.Conn.RemoteAddr(), logrus.Fields{
			"command": cmd,
			"line":    cmdLine,
		})

		switch cmd {
		case "NICK":
			if len(parts) > 1 {
				nick = parts[1]
			}
		case "USER":
			welcome := fmt.Sprintf(
				":%s 001 %s :Welcome to the Internet Relay Network %s\r\n:%s 002 %s :Your host is %s, running version InspIRCd-3.17.0\r\n",
				srv, nick, nick, srv, nick, srv,
			)
			_, err = sc.Conn.Write([]byte(welcome))
		case "PING":
			token := srv
			if len(parts) > 1 {
				token = parts[1]
			}
			_, err = sc.Conn.Write([]byte(fmt.Sprintf(":%s PONG %s :%s\r\n", srv, srv, token)))
		case "QUIT":
			_, _ = sc.Conn.Write([]byte("ERROR :Closing Link\r\n"))
			return nil
		}
		if err != nil {
			return err
		}
	}
}
