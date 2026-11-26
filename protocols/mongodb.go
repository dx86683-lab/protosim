package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"time"

	"gopkg.in/mgo.v2/bson"
)

const (
	mongoConfigName = "_mongodb.json"
	mongoOpReply    = 1
	mongoOpQuery    = 2004
	mongoOpMsg      = 2013
	mongoChecksum   = 1
	mongoMoreToCome = 2
	mongoIOTimeout  = 15 * time.Second
)

var mongoCRC = crc32.MakeTable(crc32.Castagnoli)

//go:embed fixtures/mongodb-default.json
var mongoDefault []byte

func init() {
	AddProtocol(NewProtocolInfo("mongodb", serveMongoDB, 27017),
		ProtocolParams{Name: "config_file", DefaultValue: mongoConfigName})
}

func serveMongoDB(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	fixture := session.GetStringParams("config_file", mongoConfigName)
	le := binary.LittleEndian
	for {
		if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		if _, err := reader.Peek(1); err != nil {
			return err
		}
		if err := session.Conn.SetReadDeadline(time.Now().Add(mongoIOTimeout)); err != nil {
			return err
		}
		var header [16]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		size := le.Uint32(header[:4])
		if size < 21 || size > 65536 {
			return errors.New("invalid MongoDB message length")
		}
		payload := make([]byte, size-16)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		requestID := le.Uint32(header[4:8])
		var value bson.M
		var opcode, responseTo, flags uint32
		switch le.Uint32(header[12:16]) {
		case mongoOpQuery:
			_, command, found := bytes.Cut(payload[4:], []byte{0})
			if !found || len(command) < 8 {
				return errors.New("invalid MongoDB OP_QUERY")
			}
			query, selector, err := mongoReadDocument(command[8:])
			if err != nil {
				return err
			}
			if len(selector) != 0 {
				if _, rest, err := mongoReadDocument(selector); err != nil || len(rest) != 0 {
					return errors.New("invalid MongoDB OP_QUERY projection")
				}
			}
			opcode = mongoOpReply
			value, err = mongoLegacyResponse(fixture, query)
			if err != nil {
				var pathError *os.PathError
				if errors.As(err, &pathError) {
					return err
				}
				flags, responseTo = 1, requestID
				value = bson.M{"$err": err.Error()}
			}
		case mongoOpMsg:
			query, err := mongoReadMessage(header[:], payload)
			if err != nil {
				return err
			}
			if le.Uint32(payload[:4])&mongoMoreToCome != 0 {
				continue
			}
			opcode, responseTo = mongoOpMsg, requestID
			value = mongoModernResponse(query)
			if value == nil {
				continue
			}
		default:
			return errors.New("unsupported MongoDB opcode")
		}
		response, err := bson.Marshal(value)
		if err != nil {
			return err
		}
		wire := make([]byte, 21, 36+len(response))
		if opcode == mongoOpReply {
			wire = wire[:36]
			le.PutUint32(wire[16:20], flags)
			le.PutUint32(wire[32:36], 1)
		}
		le.PutUint32(wire[0:4], uint32(len(wire)+len(response)))
		le.PutUint32(wire[8:12], responseTo)
		le.PutUint32(wire[12:16], opcode)
		if err := session.Conn.SetWriteDeadline(time.Now().Add(mongoIOTimeout)); err != nil {
			return err
		}
		if _, err := session.Conn.Write(append(wire, response...)); err != nil {
			return err
		}
	}
}

func mongoReadDocument(payload []byte) (bson.RawD, []byte, error) {
	if len(payload) < 5 {
		return nil, nil, errors.New("invalid MongoDB document size")
	}
	size := binary.LittleEndian.Uint32(payload[:4])
	if size < 5 || size > uint32(len(payload)) {
		return nil, nil, errors.New("invalid MongoDB document size")
	}
	// RawD keeps nested values as opaque BSON while preserving command field order.
	var body bson.RawD
	if err := bson.Unmarshal(payload[:size], &body); err != nil {
		return nil, nil, err
	}
	return body, payload[size:], nil
}

func mongoReadMessage(header, payload []byte) (bson.RawD, error) {
	le := binary.LittleEndian
	flags := le.Uint32(payload[:4])
	if flags&0xffff & ^uint32(mongoChecksum|mongoMoreToCome) != 0 || payload[4] != 0 {
		return nil, errors.New("unsupported MongoDB OP_MSG section or flags")
	}
	if flags&mongoChecksum != 0 {
		if len(payload) < 9 {
			return nil, errors.New("missing MongoDB OP_MSG checksum")
		}
		end := len(payload) - 4
		checksum := crc32.Update(crc32.Checksum(header, mongoCRC), mongoCRC, payload[:end])
		if checksum != le.Uint32(payload[end:]) {
			return nil, errors.New("invalid MongoDB OP_MSG checksum")
		}
		payload = payload[:end]
	}
	query, rest, err := mongoReadDocument(payload[5:])
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("unsupported MongoDB OP_MSG trailing section")
	}
	return query, nil
}

func mongoLegacyResponse(fixture string, query bson.RawD) (bson.M, error) {
	var config struct{ Query map[string]bson.M }
	err := loadResponseFixture(fixture, mongoConfigName, mongoDefault, &config)
	if errors.Is(err, os.ErrNotExist) {
		err = json.Unmarshal(mongoDefault, &config)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected end of JSON input")
	}
	if err != nil {
		return nil, err
	}
	if len(query) != 0 {
		if value := config.Query[query[0].Name]; value != nil {
			return value, nil
		}
	}
	return bson.M{"ok": 1}, nil
}

func mongoModernResponse(query bson.RawD) bson.M {
	for _, element := range query {
		switch element.Name {
		case "isMaster", "ismaster", "hello":
			return bson.M{
				"ismaster": true, "maxBsonObjectSize": 16777216, "maxMessageSizeBytes": 48000000,
				"maxWriteBatchSize": 100000, "localTime": time.Now().UTC(), "logicalSessionTimeoutMinutes": 30,
				"connectionId": 808, "minWireVersion": 0, "maxWireVersion": 3, "readOnly": false, "ok": 1.0,
			}
		case "find":
			return bson.M{"cursor": bson.M{"firstBatch": nil, "id": int64(3), "ns": "aggregate.a1_event"}, "ok": 1}
		}
	}
	return nil
}
