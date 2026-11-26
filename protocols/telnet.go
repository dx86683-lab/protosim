package protocols

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/dx86683-lab/protosim/fakeshell"
)

const telnetPassword = "123456"

func init() {
	AddProtocol(NewProtocolInfo("telnet", serveTelnet, 23),
		ProtocolParams{Name: "password", DefaultValue: telnetPassword},
		ProtocolParams{Name: "prompt", DefaultValue: "$ "},
		ProtocolParams{Name: "ssl", DefaultValue: false})
}

func serveTelnet(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	writer := telnetOutput{session.Conn}
	echo, err := negotiateTelnet(writer, reader)
	if err != nil {
		return err
	}
	password := session.GetStringParams("password", telnetPassword)
	for attempts := 0; attempts < 3; attempts++ {
		if err := writer.send("Password: "); err != nil {
			return err
		}
		matched, nul, err := readTelnetPassword(reader, password)
		if err != nil {
			return err
		}
		if nul {
			if err := writer.send("\r\n"); err != nil {
				return err
			}
		}
		if matched {
			logTelnetEvent(session, "login successfully", nil)
			return serveTelnetShell(session, reader, writer, echo)
		}
		logTelnetEvent(session, "login failed", nil)
		if err := writer.send("Login incorrect\r\n"); err != nil {
			return err
		}
	}
	return nil
}

type telnetOutput struct {
	net.Conn
}

func (output telnetOutput) Write(data []byte) (int, error) {
	if err := output.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return output.Conn.Write(data)
}

func (output telnetOutput) send(data string) error {
	_, err := output.Write([]byte(data))
	return err
}

func negotiateTelnet(writer telnetOutput, reader *bufio.Reader) (bool, error) {
	if err := writer.send("\xff\xfb\x01"); err != nil {
		return false, err
	}
	// The measured negotiation examines a whole read at each stage.
	var option [1024]byte
	n, err := reader.Read(option[:])
	if err != nil || string(option[:n]) != "\xff\xfd\x01" {
		return false, err
	}
	if err := writer.send("\xff\xfe\x01\xff\xfb\x03"); err != nil {
		return false, err
	}
	n, err = reader.Read(option[:])
	if err != nil || string(option[:n]) != "\xff\xfd\x03" {
		return true, err
	}
	if err := writer.send("\xff\xfd\x03"); err != nil {
		return false, err
	}
	n, err = reader.Read(option[:])
	if err != nil || string(option[:n]) != "\xff\xfb\x03" {
		return true, err
	}
	return true, writer.send("\xff\xfc\x22")
}

func readTelnetPassword(reader *bufio.Reader, password string) (match, nul bool, err error) {
	// Compare as bytes arrive so long attempts need no additional buffering.
	// The last non-CR byte marks the end after trimming trailing CRs.
	length, trimmedLength := 0, 0
	prefixMatches, trimmedMatches := true, true
	for {
		next, err := reader.ReadByte()
		if err != nil {
			return false, false, err
		}
		if next == '\n' || next == 0 {
			return trimmedMatches && trimmedLength == len(password), next == 0, nil
		}
		same := length < len(password) && password[length] == next
		prefixMatches = prefixMatches && same
		if length <= len(password) {
			length++
		}
		if next != '\r' {
			trimmedLength, trimmedMatches = length, prefixMatches
		}
	}
}

func serveTelnetShell(session *SessionConnection, reader *bufio.Reader, writer telnetOutput, echo bool) error {
	prompt := session.GetStringParams("prompt", "$ ")
	if strings.ContainsAny(prompt, "\r\n") {
		return errors.New("invalid Telnet prompt")
	}
	input := &io.LimitedReader{R: reader}
	shell := fakeshell.NewShell(struct {
		io.Reader
		io.Writer
	}{input, writer}, fakeshell.GetFakeRootUser(), !echo)
	shell.SetPrompt(prompt)
	for {
		input.N = 4096
		args, err := shell.ReadCmdLine()
		if err != nil {
			return err
		}
		if len(args) == 0 {
			continue
		}
		logTelnetEvent(session, "execute command", map[string]interface{}{"cmdline": args})
		if args[0] == "exit" || args[0] == "touch" && len(args) == 1 {
			return nil
		}
		if output := shell.DoCmd(args[0], args[1:]); output != "" {
			if err := shell.OutputLine(output); err != nil {
				return err
			}
		}
	}
}

func logTelnetEvent(session *SessionConnection, event string, fields map[string]interface{}) {
	if session.Log != nil {
		session.LogWithRemote(event, session.Conn.RemoteAddr(), fields)
	}
}
