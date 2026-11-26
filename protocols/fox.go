package protocols

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed fixtures/fox-default.json
var foxFixture []byte

var (
	foxDefaults map[string]map[string]string
	foxHeader   = regexp.MustCompile(`^fox (\w) -?[0-9]+ (-?[0-9]+) (\S+) (\S+)$`)
)

const foxMessageLimit = 8192

func init() {
	if err := json.Unmarshal(foxFixture, &foxDefaults); err != nil {
		panic(err)
	}
	AddProtocol(NewProtocolInfo("fox", serveFox, 1911),
		ProtocolParams{Name: "ssl", DefaultValue: false},
		ProtocolParams{Name: "handlers", DefaultValue: foxDefaults})
}

func serveFox(session *SessionConnection) error {
	defer session.DeleteActivity()
	handlers, _ := session.Params["handlers"].(map[string]map[string]string)
	if handlers == nil {
		handlers = foxDefaults
	}

	reader := bufio.NewReaderSize(session.Conn, foxMessageLimit)
	for {
		header, err := reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		size := len(header)
		headerLine := foxLine(header)
		fields := foxHeader.FindStringSubmatch(headerLine)
		if fields == nil {
			return fmt.Errorf("[FOX] bad head line: %s", headerLine)
		}
		line, err := reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if foxLine(line) != "{" {
			return fmt.Errorf("[FOX] bad lpara : %s", headerLine)
		}
		size += len(line)
		values := make(map[string]string)
		for {
			line, err := reader.ReadSlice('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			size += len(line)
			if size > foxMessageLimit {
				return errors.New("FOX request exceeds limit")
			}
			if foxLine(line) == "};;" {
				break
			}
			if key, value, found := strings.Cut(foxLine(line), "="); found {
				values[key] = value
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		// A FOX exchange consumes the remainder of the current read.
		if _, err := reader.Discard(reader.Buffered()); err != nil {
			return err
		}

		channel, method := fields[3], fields[4]
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "message", logrus.Fields{
			"channel": channel, "command": method,
		})
		if configured, found := handlers[method]; found {
			values = configured
		}
		var response strings.Builder
		response.WriteString("fox " + fields[1] + " 0 " + fields[2] + " " + channel + " " + method + "\n{\n")
		// Reply field order varies between reference exchanges.
		for key, value := range values {
			if response.Len()+len(key)+len(value)+6 > foxMessageLimit {
				return errors.New("FOX response exceeds limit")
			}
			response.WriteString(key + "=" + value + "\n")
		}
		response.WriteString("};;\n")
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		if err := session.SendString(response.String()); err != nil {
			return err
		}
	}
}

func foxLine(line []byte) string {
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
}
