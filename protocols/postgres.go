package protocols

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/auxten/postgresql-parser/pkg/sql/parser"
	"github.com/auxten/postgresql-parser/pkg/sql/sem/tree"
)

const (
	postgresVersion      = "14.0"
	postgresStartup3     = 3 << 16
	postgresSSL          = 80877103
	postgresReadTimeout  = 5 * time.Minute
	postgresWriteTimeout = 15 * time.Second
)

var postgresAccounts = []string{"postgres:123456"}

func init() {
	AddProtocol(NewProtocolInfo("postgres", servePostgres, 5432),
		ProtocolParams{Name: "accounts", DefaultValue: postgresAccounts},
		ProtocolParams{Name: "server_version", DefaultValue: postgresVersion},
		ProtocolParams{Name: "auth", DefaultValue: "plain"})
}

func servePostgres(session *SessionConnection) error {
	defer session.DeleteActivity()
	data, err := readPostgresStartup(session.Conn)
	if err != nil {
		return err
	}
	if len(data) >= 4 && binary.BigEndian.Uint32(data) == postgresSSL {
		if len(data) != 4 {
			return errors.New("invalid PostgreSQL encryption request")
		}
		if err := writePostgres(session, "N"); err != nil {
			return err
		}
		// After declining SSL, the reference expects the startup packet.
		data, err = readPostgresStartup(session.Conn)
		if err != nil {
			return err
		}
	}
	if len(data) < 4 {
		return errors.New("short PostgreSQL startup message")
	}
	if binary.BigEndian.Uint32(data) != postgresStartup3 {
		return errors.New("unsupported PostgreSQL startup message")
	}
	settings, err := postgresSettings(data[4:])
	if err != nil {
		return err
	}
	if err := authenticatePostgres(session, settings["user"]); err != nil {
		return err
	}
	if err := sendPostgresReady(session); err != nil {
		return err
	}
	extended := postgresExtendedSession{session: session}
	for {
		kind, body, err := readPostgresMessage(session.Conn)
		if err != nil {
			return err
		}
		switch kind {
		case 'X':
			return nil
		default:
			if err := extended.handle(kind, string(body)); err != nil {
				return err
			}
		}
	}
}

func authenticatePostgres(session *SessionConnection, user string) error {
	mode := session.GetStringParams("auth", "plain")
	var challenge string
	var event string
	switch mode {
	case "plain":
		challenge = "\x00\x00\x00\x03"
		event = "text_login"
	case "md5":
		var salt [4]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
		challenge = "\x00\x00\x00\x05" + string(salt[:])
		event = "md5_login"
	case "none":
		return nil
	default:
		if err := writePostgres(session, string(postgresError("0A000", "authentication method not supported"))); err != nil {
			return err
		}
		return errors.New("authentication method not supported")
	}
	if err := writePostgres(session, string(postgresFrame(nil, 'R', challenge))); err != nil {
		return err
	}
	kind, response, err := readPostgresMessage(session.Conn)
	if err != nil {
		return err
	}
	password, suffix, terminated := strings.Cut(string(response), "\x00")
	if kind == 'p' && terminated && suffix == "" {
		logPostgres(session, event, map[string]interface{}{"username": user})
		// The reference rejects MD5 responses even for configured synthetic accounts.
		if mode == "plain" && user != "" &&
			matchesPostgresAccount(session.GetStringsParams("accounts", postgresAccounts), user, password) {
			return nil
		}
	}
	message := "password authentication failed for user \"" + user + "\""
	if err := writePostgres(session, string(postgresFrame(nil, 'E', "SFATAL\x00CXX000\x00M"+message+"\x00\x00"))); err != nil {
		return err
	}
	return errors.New(message)
}

func matchesPostgresAccount(accounts []string, user, password string) bool {
	// The final configured entry for a username replaces earlier entries.
	for _, account := range slices.Backward(accounts) {
		name, configuredPassword, valid := strings.Cut(account, ":")
		if valid && name == user {
			return configuredPassword == password
		}
	}
	return false
}

func logPostgres(session *SessionConnection, event string, fields map[string]interface{}) {
	if session.Log != nil {
		session.LogWithRemote(event, session.Conn.RemoteAddr(), fields)
	}
}

func readPostgresBody(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 4 || size > 65536 {
		return nil, errors.New("invalid PostgreSQL frame size")
	}
	data := make([]byte, size-4)
	_, err := io.ReadFull(r, data)
	return data, err
}

func readPostgresStartup(conn net.Conn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(postgresReadTimeout)); err != nil {
		return nil, err
	}
	return readPostgresBody(conn)
}

func readPostgresMessage(conn net.Conn) (byte, []byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(postgresReadTimeout)); err != nil {
		return 0, nil, err
	}
	var kind [1]byte
	if _, err := io.ReadFull(conn, kind[:]); err != nil {
		return 0, nil, err
	}
	data, err := readPostgresBody(conn)
	return kind[0], data, err
}

func writePostgres(session *SessionConnection, reply string) error {
	if err := session.Conn.SetWriteDeadline(time.Now().Add(postgresWriteTimeout)); err != nil {
		return err
	}
	return session.SendString(reply)
}

func postgresSettings(data []byte) (map[string]string, error) {
	settings := make(map[string]string)
	input := string(data)
	for input != "\x00" {
		name, rest, nameOK := strings.Cut(input, "\x00")
		value, more, valueOK := strings.Cut(rest, "\x00")
		if name == "" || !nameOK || !valueOK || len(settings) >= 32 {
			return nil, errors.New("invalid PostgreSQL startup settings")
		}
		settings[name], input = value, more
	}
	return settings, nil
}

func postgresFrame(messages []byte, kind byte, body string) []byte {
	messages = append(messages, kind)
	messages = binary.BigEndian.AppendUint32(messages, uint32(4+len(body)))
	return append(messages, body...)
}

func postgresError(code, message string) []byte {
	return postgresFrame(nil, 'E', "SERROR\x00C"+code+"\x00M"+message+"\x00\x00")
}

func sendPostgresReady(session *SessionConnection) error {
	messages := postgresFrame(nil, 'R', "\x00\x00\x00\x00")
	for _, pair := range [][2]string{
		{"application_name", ""},
		{"client_encoding", "utf8"}, {"server_encoding", "utf8"},
		{"server_version", session.GetStringParams("server_version", postgresVersion)},
	} {
		messages = postgresFrame(messages, 'S', pair[0]+"\x00"+pair[1]+"\x00")
	}
	var backendKey [8]byte
	if _, err := rand.Read(backendKey[:]); err != nil {
		return err
	}
	messages = postgresFrame(messages, 'K', string(backendKey[:]))
	return writePostgres(session, string(postgresFrame(messages, 'Z', "I")))
}

func postgresQueryFixture(query string) []byte {
	statements, err := parser.Parse(query)
	if err != nil {
		return postgresError("XX000", err.Error())
	}
	var messages []byte
	for _, stmt := range statements {
		if _, ok := stmt.AST.(*tree.Select); ok {
			messages = postgresSelectFixture(messages)
		} else {
			messages = postgresFrame(messages, 'E', "SERROR\x00C0A000\x00Munsupported commands execution. Read-only mode.\x00\x00")
		}
	}
	return messages
}

func postgresSelectFixture(messages []byte) []byte {
	description := []byte{0, 3}
	for _, name := range []string{"user", "password", "email"} {
		description = append(description, name...)
		description = append(description, '\x00')
		// Table ID, attribute index, type OID for text, type size, modifier, format.
		description = append(description, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00"...)
	}
	messages = postgresFrame(messages, 'T', string(description))
	row := []byte{0, 3}
	for _, value := range []string{"row 0", "123456", "test@test.com"} {
		row = binary.BigEndian.AppendUint32(row, uint32(len(value)))
		row = append(row, value...)
	}
	messages = postgresFrame(messages, 'D', string(row))
	return postgresFrame(messages, 'C', "SELECT 1\x00")
}
