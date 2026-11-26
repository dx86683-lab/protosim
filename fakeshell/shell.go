package fakeshell

import (
	"container/ring"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	ETX = 0x3 // control-C
	EOT = 0x4 // control-D
	BEL = 0x7
	BS  = 0x8
	LF  = 0xa
	CR  = 0xd
	ESC = 0x1b
	CSI = '['
	DEL = 0x7f
)

var (
	HistorySize = 200
)

type Shell struct {
	rw io.ReadWriter

	history      *ring.Ring
	historyShift int
	line         []byte
	inEsc        bool
	inCsi        bool
	csiSequence  []byte
	prompt       string
	pwd          string       //当前目录
	user         FakeUserInfo // 用户信息
	disableEcho  bool         //是否对字符进行回显
}

type FakeUserInfo struct {
	Username string
	Password string
	Home     string
	UID      string
}

func GetFakeRootUser() FakeUserInfo {
	return FakeUserInfo{
		Username: "root",
		Password: "",
		Home:     "/root",
		UID:      "0",
	}
}

// userinfo 为 user pass home uid
func NewShell(rw io.ReadWriter, userinfo FakeUserInfo, disableEcho bool) *Shell {
	return &Shell{
		rw:          rw,
		user:        userinfo,
		pwd:         userinfo.Home,
		history:     ring.New(HistorySize),
		disableEcho: disableEcho,
	}
}

func parseCommandLine(command string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for i := 0; i < len(command); i++ {
		c := command[i]

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, errors.New(fmt.Sprintf("Unclosed quote in command line: %s", command))
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}

func (s *Shell) ReadCmdLine() ([]string, error) {
	line, err := s.Read()
	if err != nil {
		return nil, err
	}
	return parseCommandLine(line)
}

func (s *Shell) DoCmd(cmd string, args []string) string {
	switch cmd {
	case "pwd":
		return s.pwd
	case "whoami":
		return s.user.Username
	case "id":
		return "uid=" + s.user.UID + "(" + s.user.Username + ") gid=0(root) groups=0(root)"
	case "cd":
		switch len(args) {
		case 0:
			s.pwd = s.user.Home
		case 1:
			if strings.HasPrefix(args[0], "/") {
				s.pwd = args[0]
			} else {
				s.pwd, _ = filepath.Abs(filepath.Join(s.pwd, args[0]))
			}

		default:
			return "cd: too many arguments"
		}
		return ""
	case "ls":
		var dirs []string
		for i := range args {
			if strings.HasPrefix(args[i], "-") {
				continue
			}
			dirs = append(dirs, args[i])
		}
		if len(dirs) == 0 {
			return ". .."
		}
		out := ""
		for i := range dirs {
			out += fmt.Sprintf("ls: cannot access %s: No such file or directory\r\n", dirs[i])
		}
		return strings.TrimSuffix(out, "\r\n")
	case "exit":
		return "^^^EXIT^^^"
	case "touch":
		if len(args) == 0 {
			return "touch: missing file operand"
		}
		return "touch: " + args[0] + ": Operation not permitted"
	}
	return "command not found: " + cmd
}

// Read blocks until the next line of input, such as a command, is available and returns that
// line. The error will be io.EOF if Control-D was pressed.
func (s *Shell) Read() (string, error) {
	buf := make([]byte, 1)

	_, err := s.rw.Write([]byte(s.prompt))
	if err != nil {
		return "", err
	}

	for {
		amount, err := s.rw.Read(buf)
		if err != nil {
			return "", err
		}

		if amount > 0 {
			ch := buf[0]
			if s.inEsc {
				if s.inCsi {
					s.csiSequence = append(s.csiSequence, ch)
					if ch >= 0x40 || ch <= 0x7e {
						err := s.handleCsiSequence()
						if err != nil {
							return "", err
						}
					}
				} else if ch == CSI {
					s.inCsi = true
				} else {
					//fmt.Printf("Can't handle ESC sequence: %q\n", ch)
					return "", errors.New("unsupported ESC sequence")
				}
			} else {
				switch {
				case ch == ESC:
					s.inEsc = true

				case ch == DEL:
					s.unshiftHistory()
					err := s.del()
					if err != nil {
						return "", err
					}

				case ch == CR || ch == LF:
					return s.finishLine()

				case ch == EOT:
					// control-D, exit
					_, err = s.rw.Write([]byte{CR, LF})
					if err != nil {
						return "", err
					}
					return "", io.EOF

				case ch == ETX:
					// cancel current input line
					s.unshiftHistory()
					_, err = s.rw.Write([]byte("\r\n" + s.prompt))
					if err != nil {
						return "", err
					}
					s.line = nil

				case ch >= ' ' && ch < '~':
					s.unshiftHistory()
					err := s.Add(ch)
					if err != nil {
						return "", err
					}

				default:
					//fmt.Printf("Ignoring: %x\n", ch)
				}
			}
		}
	}
}

func (s *Shell) del() error {
	if len(s.line) > 0 {
		s.line = s.line[:len(s.line)-1]
		_, err := s.rw.Write([]byte{BS, ' ', BS})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Shell) Add(b byte) error {
	s.line = append(s.line, b)
	if !s.disableEcho {
		_, err := s.rw.Write([]byte{b})
		return err
	}
	return nil
}

func (s *Shell) AddString(val string) error {
	if s.line == nil {
		s.line = []byte(val)
	} else {
		s.line = append(s.line, val...)
	}

	_, err := s.rw.Write([]byte(val))
	return err
}

func (s *Shell) finishLine() (string, error) {
	_, err := s.rw.Write([]byte{CR, LF})
	if err != nil {
		return "", err
	}

	line := string(s.line)
	if s.historyShift == 0 && line != "" {
		s.history.Value = line
		s.history = s.history.Next()
	} else {
		// pressed enter on a history item, so don't re-save it
		s.unshiftHistory()
	}
	s.line = nil
	return line, nil
}

func (s *Shell) outputShiftedHistory() error {
	err := s.eraseCurrent()
	if err != nil {
		return err
	}
	err = s.AddString(s.history.Value.(string))
	if err != nil {
		return err
	}
	return err
}

func (s *Shell) SetPrompt(prompt string) {
	s.prompt = prompt
}

func (s *Shell) handleCsiSequence() error {
	s.inEsc = false
	s.inCsi = false

	switch s.csiSequence[len(s.csiSequence)-1] {
	case 'A':
		return s.cursorUp()
	case 'B':
		return s.cursorDown()
	default:
		//fmt.Printf("Ignoring CSI: %s\n", s.csiSequence)
		return nil
	}
}

func (s *Shell) OutputLine(line string) error {
	_, err := s.rw.Write([]byte(line + "\r\n"))
	return err
}

func (s *Shell) unshiftHistory() {
	s.history = s.history.Move(s.historyShift)
	s.historyShift = 0
}

func (s *Shell) cursorUp() error {
	prev := s.history.Prev()
	if prev.Value == nil {
		err := s.Bell()
		if err != nil {
			return err
		}
		return nil
	}

	s.history = prev
	s.historyShift++

	return s.outputShiftedHistory()
}

func (s *Shell) cursorDown() error {
	if s.historyShift <= 0 {
		err := s.Bell()
		if err != nil {
			return err
		}
		return nil
	}

	s.history = s.history.Next()
	s.historyShift--

	if s.historyShift == 0 {
		return s.eraseCurrent()
	} else {
		return s.outputShiftedHistory()
	}
}

func (s *Shell) Bell() error {
	_, err := s.rw.Write([]byte{BEL})
	return err
}

func (s *Shell) eraseCurrent() error {
	amount := len(s.line)
	s.line = nil

	err := s.left(amount)
	if err != nil {
		return err
	}

	for i := 0; i < amount; i++ {
		_, err := s.rw.Write([]byte{' '})
		if err != nil {
			return err
		}
	}

	err = s.left(amount)
	if err != nil {
		return err
	}

	return nil
}

func (s *Shell) left(n int) error {
	for ; n > 0; n-- {
		_, err := s.rw.Write([]byte{BS})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Shell) Refresh() error {
	if err := s.OutputLine(""); err != nil {
		return err
	}
	_, err := s.rw.Write([]byte(fmt.Sprintf("\r\n%s%s", s.prompt, string(s.line))))
	if err != nil {
		return err
	}
	return nil
}
