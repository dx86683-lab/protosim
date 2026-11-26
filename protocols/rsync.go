package protocols

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("rsync", Rsync, 873),
		ProtocolParams{
			Name:         "version",
			DefaultValue: "31.0",
		},
		ProtocolParams{
			Name:         "modules",
			DefaultValue: []string{"backup\tSystem backup archive", "public\tPublic files"},
		},
	)
}

// Rsync implements the standard rsync daemon wire protocol (TCP 873).
func Rsync(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	ver := sc.GetStringParams("version", "31.0")
	modules := sc.GetStringsParams("modules", []string{
		"backup\tSystem backup archive",
		"public\tPublic files",
	})

	banner := fmt.Sprintf("@RSYNCD: %s\n", ver)
	if _, err := sc.Conn.Write([]byte(banner)); err != nil {
		return err
	}

	reader := bufio.NewReader(sc.Conn)
	clientBanner, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	clientBanner = strings.TrimSpace(clientBanner)
	sc.LogWithRemote("rsync_handshake", sc.Conn.RemoteAddr(), logrus.Fields{
		"client_version": clientBanner,
	})

	req, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	req = strings.TrimSpace(req)
	sc.LogWithRemote("rsync_command", sc.Conn.RemoteAddr(), logrus.Fields{
		"request": req,
	})

	if req == "" || req == "#list" {
		var sb strings.Builder
		for _, m := range modules {
			sb.WriteString(m)
			sb.WriteByte('\n')
		}
		sb.WriteString("@RSYNCD: EXIT\n")
		_, err = sc.Conn.Write([]byte(sb.String()))
		return err
	}

	// Check if requested module exists
	for _, m := range modules {
		name, _, _ := strings.Cut(m, "\t")
		if strings.EqualFold(strings.TrimSpace(name), req) {
			_, err = sc.Conn.Write([]byte("@RSYNCD: OK\n"))
			return err
		}
	}

	_, err = sc.Conn.Write([]byte(fmt.Sprintf("@ERROR: Unknown module '%s'\n@RSYNCD: EXIT\n", req)))
	return err
}
