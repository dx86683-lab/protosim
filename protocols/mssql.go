package protocols

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	tdsHeaderSize = 8
	tdsSQLBatch   = 0x01
	tdsAttention  = 0x06
	tdsLogin7     = 0x10
	tdsPrelogin   = 0x12
	tdsReply      = 0x04
	tdsEndMessage = 0x01
	tdsEndOptions = 0xff
)

const mssqlDefaultName = "mssql"
const mssqlDefaultAccount = "sa:123456"

func init() {
	AddProtocol(NewProtocolInfo("mssql", serveMSSQL, 1433),
		ProtocolParams{Name: "server_name", DefaultValue: mssqlDefaultName},
		ProtocolParams{Name: "accounts", DefaultValue: []string{mssqlDefaultAccount}})
}

// tdsPreloginOptions validates the extent of every option before replying.
func tdsPreloginOptions(body []byte) bool {
	for pos := 0; pos < len(body); pos += 5 {
		if body[pos] == tdsEndOptions {
			for start := 0; start < pos; start += 5 {
				offset := int(binary.BigEndian.Uint16(body[start+1:]))
				size := int(binary.BigEndian.Uint16(body[start+3:]))
				if offset <= pos || offset > len(body) || size > len(body)-offset {
					return false
				}
			}
			return pos != 0
		}
		if len(body)-pos < 5 {
			return false
		}
	}
	return false
}

func tdsPreloginResponse() []byte {
	options := [...][]byte{
		{17, 8, 0, 1, 0, 0}, // Version 17.8.1.
		{2},                 // Encryption unavailable.
		{0},                 // Default instance.
		nil,                 // Thread ID omitted.
		{0},                 // MARS disabled.
		nil,                 // Trace ID omitted.
	}
	tableLength := 5*len(options) + 1
	response := make([]byte, tdsHeaderSize+tableLength, 48)
	for kind, value := range options {
		entry := response[tdsHeaderSize+5*kind:]
		entry[0] = byte(kind)
		binary.BigEndian.PutUint16(entry[1:], uint16(len(response)-tdsHeaderSize))
		binary.BigEndian.PutUint16(entry[3:], uint16(len(value)))
		response = append(response, value...)
	}
	response[tdsHeaderSize+tableLength-1] = tdsEndOptions
	response[0], response[1], response[6] = tdsReply, tdsEndMessage, 1
	binary.BigEndian.PutUint16(response[2:], uint16(len(response)))
	return response
}

func serveMSSQL(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	var header [tdsHeaderSize]byte
	var version tdsVersion
	loggedIn := false
	for {
		if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(header[2:4]))
		if size < tdsHeaderSize || header[1]&tdsEndMessage == 0 {
			return nil
		}
		body := make([]byte, size-tdsHeaderSize)
		if _, err := io.ReadFull(session.Conn, body); err != nil {
			return err
		}
		var reply []byte
		closeAfter := false
		switch header[0] {
		case tdsPrelogin:
			if loggedIn || !tdsPreloginOptions(body) {
				return nil
			}
			reply = tdsPreloginResponse()
		case tdsLogin7:
			login, ok := parseTDSLogin(body)
			if loggedIn || !ok {
				return nil
			}
			version = login.version
			name := session.GetStringParams("server_name", mssqlDefaultName)
			if len(tdsText(name))/2 > 128 {
				return nil
			}
			accounts := session.GetStringsParams("accounts", []string{mssqlDefaultAccount})
			loggedIn = matchesConfiguredAccount(accounts, login.user, login.password)
			if loggedIn {
				reply = tdsSessionReply(tdsLoginAccepted(name, version))
			} else {
				reply = tdsSessionReply(tdsLoginRejected(login.user, name, version))
				closeAfter = true
			}
		case tdsSQLBatch, tdsAttention:
			if !loggedIn {
				return nil
			}
			reply = tdsSessionReply(tdsDone(nil, version.wideRows && header[0] != tdsAttention))
		default:
			return nil
		}
		if _, err := session.Conn.Write(reply); err != nil {
			return err
		}
		if closeAfter {
			return nil
		}
	}
}
