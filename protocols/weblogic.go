package protocols

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// WebLogic T3 handshake. Request header lines are echoed in first-seen order
// with their last value; configured headers then replace or extend them.

func init() {
	AddProtocol(NewProtocolInfo("weblogic", serveWebLogic, 7001),
		ProtocolParams{Name: "server_version", DefaultValue: "12.2.1.4.0"},
		ProtocolParams{Name: "headers", DefaultValue: []string{"MS:10000000"}})
}

func serveWebLogic(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(session.Conn, 4096)
	var lines []string
	size := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		size += len(line)
		if size > 16384 {
			return errors.New("T3 handshake too large")
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" && len(lines) > 0 {
			break
		}
		lines = append(lines, line)
	}
	version, ok := strings.CutPrefix(lines[0], "t3 ")
	if !ok {
		return errors.New("bad t3 handshake message")
	}
	var keys []string
	values := map[string]string{}
	set := func(k, v string) {
		if _, seen := values[k]; !seen {
			keys = append(keys, k)
		}
		values[k] = v
	}
	fields := logrus.Fields{"Ver": version}
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			set(k, v)
			fields[k] = v
		}
	}
	logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "new message", fields)
	for _, h := range session.GetStringsParams("headers", []string{"MS:10000000"}) {
		if k, v, ok := strings.Cut(h, ":"); ok {
			set(k, v)
		}
	}
	var reply strings.Builder
	reply.WriteString("HELO:" + session.GetStringParams("server_version", "12.2.1.4.0") + ".false\n\n")
	for _, k := range keys {
		reply.WriteString(k + ":" + values[k] + "\n\n")
	}
	if _, err := io.WriteString(session.Conn, reply.String()); err != nil {
		return err
	}
	// Subsequent T3 messages are read and not answered.
	_, err := io.Copy(io.Discard, reader)
	return err
}
