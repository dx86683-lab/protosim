package protocols

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const mysqlVersion = "5.7.9"
const mysqlCapabilityDatabase = 1 << 3
const mysqlCapabilitySecure = 1 << 15
const mysqlCapabilityLengthEncoded = 1 << 21
const mysqlCapabilityDeprecateEOF = 1 << 24

var mysqlAccounts = []string{"root:123456"}
var mysqlSystemVariables = []string{"datadir:/usr/local/var/mysql/"}

func init() {
	// The reference advertises accounts twice in its protocol catalogue.
	AddProtocol(NewProtocolInfo("mysql", serveMySQL, 3306),
		ProtocolParams{Name: "accounts", DefaultValue: mysqlAccounts},
		ProtocolParams{Name: "server_version", DefaultValue: mysqlVersion},
		ProtocolParams{Name: "accounts", DefaultValue: mysqlAccounts},
		ProtocolParams{Name: "system_variables", DefaultValue: mysqlSystemVariables},
		ProtocolParams{Name: "db_name", DefaultValue: "shop"},
		ProtocolParams{Name: "table_name", DefaultValue: "users"})
}

func serveMySQL(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	version := session.GetStringParams("server_version", mysqlVersion)
	if len(version) > 255 || strings.ContainsRune(version, 0) {
		return errors.New("invalid MySQL server version")
	}
	var scramble [20]byte
	if _, err := rand.Read(scramble[:]); err != nil {
		return err
	}
	for i, value := range scramble {
		if value == 0 {
			scramble[i] = 1
		}
	}

	packet := append([]byte{10}, version...)
	packet = append(packet, 0)
	connectionID := session.ConnectionID
	if connectionID == 0 {
		connectionID = 1
	}
	packet = binary.LittleEndian.AppendUint32(packet, connectionID)
	packet = append(packet, scramble[:8]...)
	// Capabilities, character set, status and challenge length of the
	// reference's protocol 4.1 greeting.
	packet = append(packet, 0, 0x8f, 0xa2, 0x21, 0, 0, 0x3b, 0x01, 21)
	packet = append(packet, make([]byte, 10)...)
	packet = append(packet, scramble[8:]...)
	packet = append(packet, 0)
	packet = append(packet, "mysql_native_password\x00"...)
	if err := writeMySQLPacket(session, 0, packet); err != nil {
		return err
	}

	sequence, login, err := readMySQLPacket(session.Conn)
	if err != nil {
		return err
	}
	if sequence != 1 {
		return errors.New("invalid MySQL handshake response")
	}
	username, token, database, valid := mysqlLoginFields(login)
	if !valid {
		return errors.New("invalid MySQL login fields")
	}
	if !mysqlAuthenticate(session.GetStringsParams("accounts", mysqlAccounts), username, token, scramble[:]) {
		return writeMySQLPacket(session, 2, mysqlErrorPacket(1045, "28000", "Access denied for user '"+username+"'"))
	}
	variables := mysqlGlobalVariableSnapshot()
	connectionUser := username + "@"
	if peer := session.Conn.RemoteAddr(); peer != nil {
		connectionUser += peer.String()
	}
	model := mysqlSimulation{
		schema:           session.GetStringParams("db_name", "shop"),
		table:            session.GetStringParams("table_name", "users"),
		deprecateEOF:     binary.LittleEndian.Uint32(login[:4])&mysqlCapabilityDeprecateEOF != 0,
		sessionVariables: variables,
		autocommitOff:    variables["autocommit"] == "0",
		connectionID:     connectionID,
		connectionUser:   connectionUser,
		foundRows:        1,
	}
	if database != "" && !model.useDatabase(database) {
		return writeMySQLPacket(session, 2, mysqlUnknownDatabase(database))
	}
	if err := writeMySQLPacket(session, 2, mysqlOK(false)); err != nil {
		return err
	}

	for {
		seq, command, err := readMySQLPacket(session.Conn)
		if err != nil {
			return err
		}
		if seq != 0 || len(command) == 0 {
			return errors.New("invalid MySQL command frame")
		}
		input := string(command[1:])
		switch command[0] {
		case 1: // COM_QUIT
			return nil
		case 2: // COM_INIT_DB
			reply := mysqlOK(false)
			if !model.useDatabase(input) {
				reply = mysqlUnknownDatabase(input)
			}
			err = writeMySQLPacket(session, 1, reply)
		case 3: // COM_QUERY
			err = model.query(session, input)
		case 4: // COM_FIELD_LIST
			err = model.fieldList(session, input)
		case 14: // COM_PING
			err = writeMySQLPacket(session, 1, mysqlOK(model.status))
		case 22: // COM_STMT_PREPARE
			err = model.prepare(session, input)
		case 23: // COM_STMT_EXECUTE
			err = model.execute(session, command[1:])
		case 24: // COM_STMT_SEND_LONG_DATA
			if !model.addStream(command[1:]) {
				return nil
			}
		case 25: // COM_STMT_CLOSE
			if len(command) == 5 {
				id := binary.LittleEndian.Uint32(command[1:])
				if stmt := model.statements[id]; stmt != nil {
					model.discardStreams(stmt)
					delete(model.statements, id)
				}
			}
		case 26: // COM_STMT_RESET
			if len(command) != 5 || model.statements[binary.LittleEndian.Uint32(command[1:])] == nil {
				return writeMySQLPacket(session, 1, mysqlErrorPacket(2014, "08S01",
					fmt.Sprintf("commands were executed in an improper order: %v", command)))
			}
			model.discardStreams(model.statements[binary.LittleEndian.Uint32(command[1:])])
			err = writeMySQLPacket(session, 1, mysqlOK(model.status))
		case 27: // COM_SET_OPTION
			reply := mysqlReply{session: session, sequence: 1}
			if len(command) != 3 || binary.LittleEndian.Uint16(command[1:]) > 1 {
				err = reply.send(mysqlErrorPacket(1047, "08S01", fmt.Sprintf("error handling packet: %v", command)))
			} else {
				err = reply.send(model.endPacket(model.status))
			}
		case 28: // COM_STMT_FETCH
			// The reference preserves this spelling in its error packet.
			err = writeMySQLPacket(session, 1, mysqlErrorPacket(1105, "HY000", "unknown error: COM_STMT_FETCH is not suppported"))
		case 31: // COM_RESET_CONNECTION
			clear(model.statements)
			model.streamBytes = 0
			err = writeMySQLPacket(session, 1, mysqlOK(false))
		default:
			err = writeMySQLPacket(session, 1, mysqlErrorPacket(1047, "08S01",
				fmt.Sprintf("command handling not implemented yet: %d", command[0])))
		}
		if err != nil {
			return err
		}
	}
}

func readMySQLPacket(r io.Reader) (byte, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > 65536 {
		return 0, nil, errors.New("MySQL packet exceeds simulator limit")
	}
	body := make([]byte, length)
	_, err := io.ReadFull(r, body)
	return header[3], body, err
}

func mysqlLoginFields(body []byte) (username string, token []byte, database string, ok bool) {
	if len(body) < 33 {
		return "", nil, "", false
	}
	caps := binary.LittleEndian.Uint32(body[:4])
	user, rest, found := bytes.Cut(body[32:], []byte{0})
	if !found || len(user) > 255 || len(rest) == 0 {
		return "", nil, "", false
	}
	if caps&(mysqlCapabilitySecure|mysqlCapabilityLengthEncoded) != 0 {
		// The native-password token is empty or 20 bytes, both of which
		// use the single-byte representation of a length-encoded integer.
		n := int(rest[0])
		if (n != 0 && n != sha1.Size) || n > len(rest)-1 {
			return "", nil, "", false
		}
		token, rest = rest[1:n+1], rest[n+1:]
	} else {
		token, rest, found = bytes.Cut(rest, []byte{0})
		if !found {
			return "", nil, "", false
		}
	}
	if caps&mysqlCapabilityDatabase != 0 {
		db, _, found := bytes.Cut(rest, []byte{0})
		if !found {
			return "", nil, "", false
		}
		database = string(db)
	}
	return string(user), token, database, true
}

func mysqlAuthenticate(accounts []string, username string, token, scramble []byte) bool {
	for _, account := range accounts {
		user, password, ok := strings.Cut(account, ":")
		if !ok || user != username {
			continue
		}
		if password == "" {
			if len(token) == 0 {
				return true
			}
			continue
		}
		first := sha1.Sum([]byte(password))
		second := sha1.Sum(first[:])
		digest := sha1.New()
		digest.Write(scramble)
		digest.Write(second[:])
		for i, value := range digest.Sum(nil) {
			first[i] ^= value
		}
		if subtle.ConstantTimeCompare(token, first[:]) == 1 {
			return true
		}
	}
	return false
}

func writeMySQLPacket(session *SessionConnection, sequence byte, body []byte) error {
	size := len(body)
	packet := append([]byte{byte(size), byte(size >> 8), byte(size >> 16), sequence}, body...)
	_, err := session.Conn.Write(packet)
	return err
}
