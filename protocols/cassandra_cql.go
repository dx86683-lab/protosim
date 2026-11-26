package protocols

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/sirupsen/logrus"
)

const (
	cqlError        = 0x00
	cqlStartup      = 0x01
	cqlReady        = 0x02
	cqlAuthenticate = 0x03
	cqlOptions      = 0x05
	cqlSupported    = 0x06
	cqlQuery        = 0x07
	cqlResult       = 0x08
	cqlPrepare      = 0x09
	cqlExecute      = 0x0a
	cqlRegister     = 0x0b
	cqlAuthResponse = 0x0f
	cqlAuthSuccess  = 0x10
	cqlNoReply      = 0xff
)

var cassandraCQLOpcodes = map[byte]string{
	cqlStartup: "STARTUP", cqlOptions: "OPTIONS", cqlQuery: "QUERY",
	cqlResult: "RESULT", cqlPrepare: "PREPARE", cqlExecute: "EXECUTE",
	cqlRegister: "REGISTER", cqlAuthResponse: "AUTH_RESPONSE",
}

var cassandraCQLOptions = map[string][]string{
	"COMPRESSION":       {"snappy", "lz4"},
	"CQL_VERSION":       {"3.4.5"},
	"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5", "6/v6-beta"},
}

func serveCassandraCQL(session *SessionConnection, reader *bufio.Reader, accounts []string) error {
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	for {
		if _, err := reader.Peek(1); err != nil {
			return err
		}
		batch, err := reader.Peek(reader.Buffered())
		if err != nil {
			return err
		}
		if err := handleCassandraCQLBatch(session, accounts, batch); err != nil {
			return err
		}
		if _, err := reader.Discard(len(batch)); err != nil {
			return err
		}
		if err := session.Conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return err
		}
	}
}

func handleCassandraCQLBatch(session *SessionConnection, accounts []string, batch []byte) error {
	version := batch[0]
	if version < 1 || version > 5 {
		message := fmt.Sprintf("Invalid or unsupported protocol version (%d); supported versions are (3/v3, 4/v4, 5/v5, 6/v6-beta)", version&0x7f)
		return writeCassandraCQL(session, []byte{3, 0, 0, 0, cqlError}, cqlError, cassandraCQLError(10, message))
	}
	headerSize := 9
	if version < 3 {
		headerSize = 8
	}
	if len(batch) < headerSize {
		return io.ErrUnexpectedEOF
	}
	opcodeOffset := headerSize - 5
	size := binary.BigEndian.Uint32(batch[opcodeOffset+1 : headerSize])
	if size > uint32(len(batch)-headerSize) {
		return io.ErrUnexpectedEOF
	}
	payload := batch[headerSize : headerSize+int(size)]
	if batch[1]&1 != 0 {
		var err error
		payload, err = decodeCassandraLZ4(payload)
		if err != nil {
			return err
		}
	}
	response, body, err := cassandraCQLResponse(session, accounts, batch[opcodeOffset], payload)
	if err != nil || response == cqlNoReply {
		return err
	}
	return writeCassandraCQL(session, batch[:opcodeOffset+1], response, body)
}

func decodeCassandraLZ4(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, errors.New("short CQL LZ4 length")
	}
	size := binary.BigEndian.Uint32(payload)
	if size > cassandraFrameLimit {
		return nil, errors.New("CQL LZ4 output exceeds limit")
	}
	decoded := make([]byte, size)
	n, err := lz4.UncompressBlock(payload[4:], decoded)
	if err != nil || n != len(decoded) {
		return nil, errors.New("invalid CQL LZ4 block")
	}
	return decoded, nil
}

func cassandraCQLResponse(session *SessionConnection, accounts []string, opcode byte, payload []byte) (byte, []byte, error) {
	remote := session.Conn.RemoteAddr()
	if method, ok := cassandraCQLOpcodes[opcode]; ok {
		logSessionEvent(session.ConfigInfo, remote, "command", logrus.Fields{"method": method, "version": 2})
	}
	switch opcode {
	case cqlOptions:
		body := binary.BigEndian.AppendUint16(nil, uint16(len(cassandraCQLOptions)))
		for name, values := range cassandraCQLOptions {
			body = appendCassandraCQLString(body, name)
			body = binary.BigEndian.AppendUint16(body, uint16(len(values)))
			for _, value := range values {
				body = appendCassandraCQLString(body, value)
			}
		}
		return cqlSupported, body, nil
	case cqlStartup:
		if len(accounts) != 0 {
			return cqlReady, nil, nil
		}
		return cqlAuthenticate, appendCassandraCQLString(nil, "org.apache.cassandra.auth.PasswordAuthenticator"), nil
	case cqlRegister:
		return cqlReady, nil, nil
	case cqlAuthResponse:
		token, ok := takeCassandraString(&payload)
		if !ok || len(token) == 0 || token[0] != 0 {
			return cqlError, cassandraCQLError(256, "Password must not be null"), nil
		}
		user, password, _ := strings.Cut(token[1:], "\x00")
		if cassandraLogin(session, accounts, user, password) {
			return cqlAuthSuccess, []byte{255, 255, 255, 255}, nil
		}
		if password == "" {
			return cqlError, cassandraCQLError(256, "Password must not be null"), nil
		}
		return cqlError, cassandraCQLError(256, "Provided username cassandra and/or password are incorrect"), nil
	case cqlQuery:
		statement, ok := takeCassandraString(&payload)
		if !ok {
			return 0, nil, errors.New("invalid CQL query")
		}
		logSessionEvent(session.ConfigInfo, remote, "query", logrus.Fields{"cmd": statement})
		if keyspace, found := strings.CutPrefix(statement, "USE "); found {
			if len(keyspace) < 2 {
				return 0, nil, errors.New("invalid CQL keyspace")
			}
			message := "Keyspace '" + keyspace[1:len(keyspace)-1] + "' does not exist"
			if len(message) > 65535 {
				return 0, nil, errors.New("CQL keyspace exceeds limit")
			}
			return cqlError, cassandraCQLError(uint32(len(message)), message), nil
		}
		return cqlResult, []byte{0, 0, 0, 0}, nil
	default:
		return cqlNoReply, nil, nil
	}
}

func appendCassandraCQLString(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

func cassandraCQLError(code uint32, message string) []byte {
	return appendCassandraCQLString(binary.BigEndian.AppendUint32(nil, code), message)
}

func writeCassandraCQL(session *SessionConnection, head []byte, opcode byte, body []byte) error {
	reply := bytes.Clone(head)
	reply[0] |= 0x80
	reply[len(reply)-1] = opcode
	reply = binary.BigEndian.AppendUint32(reply, uint32(len(body)))
	if err := session.Conn.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}
	_, err := session.Conn.Write(append(reply, body...))
	return err
}
