package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

const cassandraFrameLimit = 1 << 20

func init() {
	AddProtocol(NewProtocolInfo("cassandra", serveCassandra, 9160),
		ProtocolParams{Name: "version", DefaultValue: 2},
		ProtocolParams{Name: "cluster_name", DefaultValue: "momentum-h85J"},
		ProtocolParams{Name: "cluster_version", DefaultValue: "19.39.0"},
		ProtocolParams{Name: "accounts", DefaultValue: []string{}})
}

func thriftString(field bool, s string) []byte {
	var out []byte
	if field {
		out = []byte{0x0b, 0, 0}
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	return append(out, s...)
}

func serveCassandra(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	var accounts []string
	switch configured := session.Params["accounts"].(type) {
	case []string:
		accounts = configured
	case []any:
		for _, entry := range configured {
			if account, ok := entry.(string); ok {
				accounts = append(accounts, account)
			}
		}
	}
	if session.GetIntParams("version", 2) > 2 {
		return serveCassandraCQL(session, reader, accounts)
	}
	return serveCassandraThrift(session, reader, accounts)
}

func serveCassandraThrift(session *SessionConnection, reader *bufio.Reader, accounts []string) error {
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	for {
		var mark [4]byte
		if _, err := io.ReadFull(reader, mark[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(mark[:])
		if size > cassandraFrameLimit {
			// The incompatible framed input gets no reply.
			if err := session.Conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, reader)
			return bufio.ErrBufferFull
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(reader, frame); err != nil {
			return err
		}
		// One request is dispatched from each buffered read batch.
		if _, err := reader.Discard(reader.Buffered()); err != nil {
			return err
		}
		if len(frame) < 12 {
			return errors.New("short Thrift header")
		}
		header := binary.BigEndian.Uint32(frame)
		if header>>16 != 0x8001 {
			continue
		}
		nameLen := int(binary.BigEndian.Uint32(frame[4:]))
		if nameLen > len(frame)-12 {
			return errors.New("invalid Thrift method name")
		}
		name := string(frame[8 : 8+nameLen])
		seq := frame[8+nameLen : 12+nameLen]
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "command", logrus.Fields{"method": name})
		var body []byte
		switch name {
		case "describe_cluster_name":
			body = append(thriftString(true, session.GetStringParams("cluster_name", "momentum-h85J")), 0)
		case "describe_version":
			body = append(thriftString(true, session.GetStringParams("cluster_version", "19.39.0")), 0)
		case "login":
			body = []byte{0}
			if len(accounts) != 0 {
				user, password, ok := cassandraThriftCredentials(frame[12+nameLen:])
				if ok && !cassandraLogin(session, accounts, user, password) {
					body = append([]byte{12, 0, 1, 11, 0, 1}, thriftString(false, "Username and/or password are incorrect")...)
					body = append(body, 0, 0)
				}
			}
		default:
			body = append(thriftString(false, "X"), 0)
		}
		reply := binary.BigEndian.AppendUint32(nil, header&0xffffff00|2)
		reply = append(reply, thriftString(false, name)...)
		reply = append(reply, seq...)
		reply = append(reply, body...)
		out := binary.BigEndian.AppendUint32(nil, uint32(len(reply)))
		if err := session.Conn.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return err
		}
		if _, err := session.Conn.Write(append(out, reply...)); err != nil {
			return err
		}
	}
}

func cassandraThriftCredentials(args []byte) (user, password string, ok bool) {
	// AuthenticationRequest field 1 contains a map of string keys and values.
	if len(args) < 12 || string(args[:8]) != "\x0c\x00\x01\x0d\x00\x01\x0b\x0b" {
		return "", "", false
	}
	count := binary.BigEndian.Uint32(args[8:12])
	args = args[12:]
	if count > uint32(len(args)/8) {
		return "", "", false
	}
	for range count {
		key, keyOK := takeCassandraString(&args)
		value, valueOK := takeCassandraString(&args)
		if !keyOK || !valueOK {
			return "", "", false
		}
		switch key {
		case "username":
			user = value
		case "password":
			password = value
		}
	}
	return user, password, true
}

func takeCassandraString(input *[]byte) (string, bool) {
	if len(*input) < 4 {
		return "", false
	}
	size := binary.BigEndian.Uint32(*input)
	if size > uint32(len(*input)-4) {
		return "", false
	}
	value := string((*input)[4 : 4+size])
	*input = (*input)[4+size:]
	return value, true
}

func cassandraLogin(session *SessionConnection, accounts []string, user, password string) bool {
	valid := matchesConfiguredAccount(accounts, user, password)
	message := "login failed"
	if valid {
		message = "login ok"
	}
	logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), message, logrus.Fields{"username": user})
	return valid
}
