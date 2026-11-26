package protocols

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	mailboxServer    = "Dovecot"
	imapCapabilities = "IMAP4rev1 LITERAL+ SASL-IR CHILDREN UNSELECT MOVE APPENDLIMIT"
	pop3List         = "+OK 5 messages\r\n0 10\r\n1 10\r\n2 10\r\n3 10\r\n4 10\r\n.\r\n"
	pop3UIDs         = "+OK 5 messages\r\n0 1\r\n1 2\r\n2 3\r\n3 4\r\n4 5\r\n.\r\n"
	imapHeaders      = "From: contact@example.org\r\nTo: contact@example.org\r\nSubject: A little message, just for you\r\n" +
		"Date: Wed, 11 May 2016 14:31:59 +0000\r\nMessage-ID: <0000000@localhost/>\r\nContent-Type: text/plain\r\n\r\n"
	imapText = "Hi there :)"
)

type imapSelection uint8

const (
	imapUnselected imapSelection = iota
	imapReadOnly
	imapReadWrite
)

var mailboxAccounts = []string{"admin:123456", "guest:guest"}

func init() {
	AddProtocol(NewProtocolInfo("imap", newIMAPHandler, 143),
		ProtocolParams{Name: "accounts", DefaultValue: mailboxAccounts},
		ProtocolParams{Name: "allow_insecure_auth", DefaultValue: false},
		ProtocolParams{Name: "server", DefaultValue: mailboxServer},
		ProtocolParams{Name: "ssl", DefaultValue: false})
	AddProtocol(NewProtocolInfo("pop3", servePOP3, 110),
		ProtocolParams{Name: "server_version", DefaultValue: mailboxServer},
		ProtocolParams{Name: "accounts", DefaultValue: mailboxAccounts},
		ProtocolParams{Name: "ssl", DefaultValue: false})
}

func servePOP3(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		return err
	}
	server := session.GetStringParams("server_version", mailboxServer)
	if strings.ContainsAny(server, "\r\n") {
		return errors.New("invalid POP3 server name")
	}
	if err := session.SendString("+OK " + server + " ready\r\n"); err != nil {
		return err
	}
	accounts := session.GetStringsParams("accounts", mailboxAccounts)
	reader := bufio.NewReader(session.Conn)
	var user string
	var loggedIn bool
	for {
		wire, err := reader.ReadSlice('\n')
		if err != nil {
			return err
		}
		command, argument, hasArgument := strings.Cut(strings.TrimSpace(string(wire)), " ")
		command = strings.ToUpper(command)
		firstArgument, _, extraArguments := strings.Cut(argument, " ")
		reply := "-ERR Error executing command " + command + "\r\n"
		switch command {
		case "QUIT":
			return session.SendString("+OK Goodbye\r\n")
		case "CAPA":
			user = ""
			reply = "+OK \r\nUSER\r\nUIDL\r\n.\r\n"
		case "USER":
			if !loggedIn && hasArgument && !extraArguments {
				user = firstArgument
				reply = "+OK \r\n"
			}
		case "PASS":
			switch {
			case loggedIn:
			case user == "":
				reply = "-ERR PASS can be executed only directly after USER command\r\n"
			case !hasArgument || extraArguments:
			case matchesConfiguredAccount(accounts, user, firstArgument):
				loggedIn = true
				reply = "+OK User Successfully Logged on\r\n"
			default:
				user = ""
				reply = "-ERR Invalid username or password\r\n"
			}
		case "STAT":
			if loggedIn {
				reply = "+OK 5 50\r\n"
			}
		case "NOOP", "RSET":
			if loggedIn {
				reply = "+OK \r\n"
			}
		case "LIST", "UIDL", "RETR", "DELE":
			if !loggedIn {
				break
			}
			if !hasArgument {
				switch command {
				case "LIST":
					reply = pop3List
				case "UIDL":
					reply = pop3UIDs
				default:
					reply = "-ERR Missing argument for " + command + " command\r\n" + reply
				}
				break
			}
			id, err := strconv.Atoi(firstArgument)
			if err != nil {
				if !strings.ContainsAny(firstArgument, "\r\n\x00") {
					reply = "-ERR Invalid argument: " + firstArgument + "\r\n" + reply
				}
				break
			}
			switch {
			case command == "RETR":
				reply = "+OK \r\nthis is dummy message\r\n.\r\n"
			case command == "DELE":
				reply = fmt.Sprintf("+OK Message %d deleted\r\n", id)
			case id >= 5:
				reply = "-ERR no such message\r\n"
			case command == "LIST":
				reply = fmt.Sprintf("+OK %d 10\r\n", id)
			default:
				reply = fmt.Sprintf("+OK %d %d\r\n", id, id+1)
			}
		default:
			reply = "-ERR Invalid command " + command + "\r\n"
		}
		if err := session.SendString(reply); err != nil {
			return err
		}
	}
}

func newIMAPHandler() func(*SessionConnection) error {
	listener := &imapListener{accounts: make(map[string]*imapAccount), date: time.Now()}
	return listener.serve
}

func (listener *imapListener) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	server := session.GetStringParams("server", mailboxServer)
	if strings.ContainsAny(server, "\r\n") {
		return errors.New("invalid IMAP server name")
	}
	hasTLS := session.GetBoolParams("ssl") && session.SslConnWraper != nil
	allowLogin := session.GetBoolParams("allow_insecure_auth")
	capability := imapCapability(hasTLS, allowLogin)
	if err := session.SendString("* OK [CAPABILITY " + capability + "] " + server + " Ready\r\n"); err != nil {
		return err
	}

	accounts := session.GetStringsParams("accounts", mailboxAccounts)
	reader := bufio.NewReader(session.Conn)
	var account *imapAccount
	var selected imapSelectedMailbox
	for {
		wire, err := reader.ReadSlice('\n')
		if err != nil {
			return err
		}
		tag, line, _ := strings.Cut(strings.TrimSpace(string(wire)), " ")
		if tag == "" || strings.ContainsAny(tag, "\r\n\t") {
			return errors.New("invalid IMAP tag")
		}
		command, argument, _ := strings.Cut(strings.TrimLeft(line, " "), " ")
		command = strings.ToUpper(command)
		done := "OK " + command + " completed\r\n"
		reply := tag + " BAD Unknown command\r\n"
		switch command {
		case "CAPABILITY":
			reply = "* CAPABILITY " + capability + "\r\n" + tag + " " + done
		case "NOOP":
			reply = tag + " " + done
		case "IDLE":
			if err := session.SendString("+ idling\r\n"); err != nil {
				return err
			}
			line, err := reader.ReadSlice('\n')
			if err != nil {
				return err
			}
			if !strings.EqualFold(strings.TrimSpace(string(line)), "DONE") {
				reply = tag + " NO Expected DONE\r\n"
				break
			}
			reply = tag + " " + done
		case "LOGOUT":
			return session.SendString("* BYE Closing connection\r\n" + tag + " " + done)
		case "STARTTLS":
			if !hasTLS {
				reply = tag + " NO TLS support not enabled\r\n"
				break
			}
			if err := session.SendString(tag + " OK Begin TLS negotiation now\r\n"); err != nil {
				return err
			}
			conn := session.WrapSslConn(session.Conn)
			session.Conn = conn
			if err := conn.Handshake(); err != nil {
				return err
			}
			reader.Reset(conn)
			hasTLS, allowLogin = false, true
			capability = imapCapability(hasTLS, allowLogin)
			continue
		case "LOGIN", "AUTHENTICATE":
			result := "NO Authentication disabled\r\n"
			switch {
			case account != nil:
				result = "NO Already authenticated\r\n"
			case allowLogin:
				user, pass, failure, err := imapCredentials(session, reader, command, argument)
				if err != nil {
					return err
				}
				switch {
				case failure != "":
					result = failure
				case !matchesConfiguredAccount(accounts, user, pass):
					result = "NO Bad username or password\r\n"
				default:
					account = listener.account(user)
					capability = imapCapabilities
					result = "OK [CAPABILITY " + capability + "] " + command + " completed\r\n"
				}
			}
			reply = tag + " " + result
		case "LIST", "LSUB", "STATUS", "SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE":
			reply = tag + " NO Not authenticated\r\n"
			if account != nil {
				reply = account.mailboxReply(tag, command, argument, &selected)
			}
		case "APPEND":
			reply = tag + " NO Not authenticated\r\n"
			if account != nil {
				reply, err = account.appendMessage(session, reader, tag, argument)
				if err != nil {
					return err
				}
			}
		case "CHECK", "CLOSE", "UNSELECT", "SEARCH", "FETCH", "UID", "STORE", "COPY", "EXPUNGE", "MOVE":
			reply = tag + " NO No mailbox selected\r\n"
			if selected.box != nil {
				reply = account.selectedReply(tag, command, argument, &selected)
			}
		}
		if err := session.SendString(reply); err != nil {
			return err
		}
	}
}

func imapCapability(hasTLS, allowLogin bool) string {
	capability := imapCapabilities
	if hasTLS {
		capability += " STARTTLS"
	}
	if allowLogin {
		return capability + " AUTH=PLAIN"
	}
	return capability + " LOGINDISABLED"
}

func imapCredentials(session *SessionConnection, reader *bufio.Reader, command, argument string) (user, pass, failure string, err error) {
	if command == "LOGIN" {
		user, rest, ok := cutIMAPArgument(argument)
		pass, tail, valid := cutIMAPArgument(rest)
		if !ok || !valid || tail != "" {
			return "", "", "BAD Invalid arguments\r\n", nil
		}
		return user, pass, "", nil
	}
	mechanism, response, _ := strings.Cut(argument, " ")
	if !strings.EqualFold(mechanism, "PLAIN") {
		return "", "", "NO Unsupported mechanism\r\n", nil
	}
	if response == "" {
		if err := session.SendString("+\r\n"); err != nil {
			return "", "", "", err
		}
		wire, err := reader.ReadSlice('\n')
		if err != nil {
			return "", "", "", err
		}
		response = strings.TrimSpace(string(wire))
	}
	decoded, err := base64.StdEncoding.DecodeString(response)
	fields := strings.Split(string(decoded), "\x00")
	if err != nil || len(fields) != 3 || fields[1] == "" || fields[0] != "" && fields[0] != fields[1] {
		return "", "", "NO Invalid response\r\n", nil
	}
	return fields[1], fields[2], "", nil
}

// cutIMAPArgument handles atoms and quoted strings for the commands we support.
func cutIMAPArgument(input string) (value, residual string, ok bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", false
	}
	if input[0] != '"' {
		value, residual, _ = strings.Cut(input, " ")
		return value, strings.TrimLeft(residual, " "), true
	}
	var out strings.Builder
	for i := 1; i < len(input); i++ {
		switch input[i] {
		case '"':
			return out.String(), strings.TrimLeft(input[i+1:], " "), true
		case '\\':
			i++
			if i == len(input) {
				return "", "", false
			}
		}
		out.WriteByte(input[i])
	}
	return "", "", false
}

type imapArgumentToken struct {
	text      string
	delimiter byte
	nilAtom   bool
}

func (token imapArgumentToken) isString() bool {
	return token.delimiter == 0 && !token.nilAtom
}

func tokenizeIMAPArguments(input string) ([]imapArgumentToken, bool) {
	var tokens []imapArgumentToken
	for input = strings.TrimSpace(input); input != ""; input = strings.TrimSpace(input) {
		switch input[0] {
		case '(', ')':
			tokens = append(tokens, imapArgumentToken{delimiter: input[0]})
			input = input[1:]
		case '"':
			value, remaining, ok := cutIMAPArgument(input)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, imapArgumentToken{text: value})
			input = remaining
		default:
			end := strings.IndexAny(input, " ()\t")
			if end < 0 {
				end = len(input)
			}
			word := input[:end]
			tokens = append(tokens, imapArgumentToken{text: word, nilAtom: word == "NIL"})
			input = input[end:]
		}
	}
	return tokens, true
}

func takeIMAPArgument(tokens []imapArgumentToken) (argument, remaining []imapArgumentToken) {
	if len(tokens) == 0 || tokens[0].delimiter == ')' {
		return nil, nil
	}
	if tokens[0].delimiter == 0 {
		return tokens[:1], tokens[1:]
	}
	depth := 0
	for i, token := range tokens {
		switch token.delimiter {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return tokens[:i+1], tokens[i+1:]
			}
		}
	}
	return nil, nil
}
