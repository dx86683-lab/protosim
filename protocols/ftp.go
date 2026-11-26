package protocols

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
)

const ftpWelcome = "Welcome to the FTP Server"
const ftpMissingArgument = "553 action aborted, required param missing"

var ftpDefaultAccounts = []string{"ftp:123456"}

func init() {
	AddProtocol(NewProtocolInfo("ftp", newFTPHandler, 21),
		ProtocolParams{Name: "welcome_message", DefaultValue: ftpWelcome},
		ProtocolParams{Name: "accounts", DefaultValue: ftpDefaultAccounts},
		ProtocolParams{Name: "ssl", DefaultValue: false})
}

type ftpControl struct {
	pendingUser       string
	authenticatedUser string
	directory         string
	renameFrom        string
	restartOffset     int64
	loggedIn          bool
	accounts          []string
	files             *ftpVolume
	passive           net.Listener
	active            net.Conn
}

func newFTPHandler() func(*SessionConnection) error {
	files := newFTPVolume()
	return func(session *SessionConnection) error { return serveFTP(session, files) }
}

func serveFTP(session *SessionConnection, files *ftpVolume) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	welcome := session.GetStringParams("welcome_message", ftpWelcome)
	if strings.ContainsAny(welcome, "\r\n") {
		return errors.New("invalid FTP welcome message")
	}
	if err := session.SendString("220 " + welcome + "\r\n"); err != nil {
		return err
	}
	// Bound the implicit TLS handshake and greeting, then permit idle control
	// sessions while continuing to bound individual writes.
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	reader := bufio.NewReader(session.Conn)
	control := ftpControl{directory: "/", accounts: session.GetStringsParams("accounts", nil), files: files}
	defer control.closeData()
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return err
		}
		request := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		command, argument, _ := strings.Cut(request, " ")
		command = strings.ToUpper(command)
		if command == "QUIT" {
			return sendFTPReply(session, "221 Goodbye")
		}
		reply, err := control.command(session, command, argument)
		if err != nil {
			return err
		}
		if reply == "" {
			continue
		}
		if err := sendFTPReply(session, reply); err != nil {
			return err
		}
	}
}

func sendFTPReply(session *SessionConnection, reply string) error {
	if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	return session.SendString(reply + "\r\n")
}

func (s *ftpControl) reply(command, argument string) string {
	if strings.ContainsAny(argument, "\r\n\x00") {
		return "501 Invalid argument"
	}
	switch command {
	case "USER":
		s.pendingUser = argument
		if argument == "" {
			return ftpMissingArgument
		}
		return "331 User name ok, password required"
	case "PASS":
		if argument == "" {
			return ftpMissingArgument
		}
		if len(s.accounts) != 0 && !matchesConfiguredAccount(s.accounts, s.pendingUser, argument) {
			return "530 Incorrect password, not logged in"
		}
		s.loggedIn = true
		s.authenticatedUser = s.pendingUser
		return "230 Password ok, continue"
	case "FEAT":
		return "211-Extensions supported:\n UTF8\n CLNT\n MLSD\n LPRT\n EPRT\n EPSV\n\r\n211 END"
	case "NOOP", "CLNT":
		return "200 OK"
	case "ALLO":
		return "202 Obsolete"
	case "AUTH", "PBSZ", "PROT", "CCC":
		if argument == "" {
			return ftpMissingArgument
		}
		if command == "CCC" && !s.loggedIn {
			return "530 not logged in"
		}
		return "550 Action not taken"
	case "MODE", "STRU":
		if argument == "" {
			return ftpMissingArgument
		}
		if !s.loggedIn {
			return "530 not logged in"
		}
		if (command == "MODE" && strings.EqualFold(argument, "S")) ||
			(command == "STRU" && strings.EqualFold(argument, "F")) {
			return "200 OK"
		}
		return "504 " + command + " is an obsolete command"
	case "OPTS":
		options := strings.Fields(argument)
		if len(options) != 2 || !strings.EqualFold(options[0], "UTF8") {
			return "550 Unknow params"
		}
		switch strings.ToUpper(options[1]) {
		case "ON":
			return "200 UTF8 mode enabled"
		case "OFF":
			return "550 Unsupported non-utf8 mode"
		default:
			return "550 Unknow params"
		}
	case "SYST", "TYPE", "PWD", "XPWD", "CWD", "XCWD", "CDUP", "XCUP", "MKD", "XMKD", "RMD", "XRMD", "SIZE", "MDTM", "REST", "DELE", "RNFR", "RNTO":
		if !s.loggedIn {
			return "530 not logged in"
		}
	default:
		return "500 Command not found"
	}

	switch command {
	case "SYST":
		return "215 UNIX Type: L8"
	case "TYPE":
		switch strings.ToUpper(argument) {
		case "A":
			return "200 Type set to ASCII"
		case "I":
			return "200 Type set to binary"
		default:
			return "500 Invalid type"
		}
	case "PWD", "XPWD":
		return `257 "` + s.directory + `" is the current directory`
	case "CDUP", "XCUP":
		return s.changeDirectory(path.Dir(s.directory))
	case "REST":
		offset, err := strconv.ParseInt(argument, 10, 64)
		if err != nil {
			return "551 File not available"
		}
		s.restartOffset = offset
		return fmt.Sprintf("350 Start transfer from %d", offset)
	}
	if argument == "" {
		return ftpMissingArgument
	}
	target := s.target(argument)
	switch command {
	case "CWD", "XCWD":
		return s.changeDirectory(target)
	case "MKD", "XMKD":
		s.files.mu.Lock()
		defer s.files.mu.Unlock()
		if err := s.files.MkdirAll(target, 0755); err != nil {
			return "550 Directory create failed: " + err.Error()
		}
		return "257 Directory created"
	case "RMD", "XRMD":
		if target == "/" {
			return "550 Directory delete failed"
		}
		if err := s.files.deleteDirectory(target); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "550 Directory delete failed: open " + target + ": file does not exist"
			}
			return "550 Directory delete failed: " + err.Error()
		}
		return "250 Directory deleted"
	case "SIZE":
		info, err := s.files.Stat(target)
		if err != nil {
			return "450 path " + argument + " not found"
		}
		return fmt.Sprintf("213 %d", ftpDisplaySize(info))
	case "MDTM":
		info, err := s.files.Stat(target)
		if err != nil {
			return "450 File not available"
		}
		return "213 " + info.ModTime().Local().Format("20060102150405")
	case "RNFR":
		s.renameFrom = ""
		s.files.mu.Lock()
		_, err := s.files.Stat(target)
		s.files.mu.Unlock()
		if err != nil {
			return "550 Action not taken: file does not exist"
		}
		if target == "/" {
			return "550 Action not taken"
		}
		s.renameFrom = target
		return "350 Requested file action pending further information."
	case "RNTO":
		from := s.renameFrom
		s.renameFrom = ""
		if err := s.files.renameEntry(from, target); err != nil {
			return "550 Action not taken: " + err.Error()
		}
		return "250 File renamed"
	default: // DELE
		if s.files.deleteFile(target) == nil {
			return "250 File deleted"
		}
		return "550 File delete failed. "
	}
}

func (s *ftpControl) target(argument string) string {
	if path.IsAbs(argument) {
		return path.Clean(argument)
	}
	return path.Join(s.directory, argument)
}

func (s *ftpControl) changeDirectory(target string) string {
	if target != "/" {
		info, err := s.files.Stat(target)
		if err != nil || !info.IsDir() {
			return "550 Directory change to " + target + " failed."
		}
	}
	s.directory = target
	return "250 Directory changed to " + target
}
