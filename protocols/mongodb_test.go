package protocols

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/mgo.v2/bson"
)

func TestReferenceMongoDBLegacyAndModernSession(t *testing.T) {
	config := filepath.Join(t.TempDir(), "lab.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(config, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"query":{"hello":{"ok":1,"name":"first"}}}`)
	conn, stop := startRound6Server(t, round6Case{Handler: "mongodb", Params: map[string]any{"config_file": config}})
	defer stop()

	const legacy, modern = 2004, 2013
	selector := bson.D{{Name: "included", Value: 1}}
	command := func(name string, value any) bson.D { return bson.D{{Name: name, Value: value}} }
	exchange := func(opcode, id, flags uint32, request, fields bson.D, wantOpcode, wantResponseTo, wantFlags uint32) bson.M {
		t.Helper()
		mongoTestSend(t, conn, opcode, id, flags, request, fields)
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var header [16]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			t.Fatal(err)
		}
		le := binary.LittleEndian
		if got, to := le.Uint32(header[12:]), le.Uint32(header[8:]); got != wantOpcode || to != wantResponseTo {
			t.Fatalf("%s replied with opcode %d, responseTo %d, want %d and %d", request[0].Name, got, to, wantOpcode, wantResponseTo)
		}
		length := le.Uint32(header[:])
		if length < 21 || length > 65536 {
			t.Fatalf("invalid reply length %d", length)
		}
		body := make([]byte, length-16)
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatal(err)
		}
		if len(body) < 5 || le.Uint32(body) != wantFlags {
			t.Fatalf("unexpected reply flags: %x", body)
		}
		offset := 5
		if wantOpcode == 1 {
			offset = 20
		}
		var decoded bson.M
		if len(body) < offset || bson.Unmarshal(body[offset:], &decoded) != nil {
			t.Fatalf("invalid BSON reply: %x", body)
		}
		return decoded
	}
	if got := exchange(legacy, 11, 0, command("hello", 1), selector, 1, 0, 0); got["name"] != "first" {
		t.Fatalf("selector request returned %#v", got)
	}
	if got := exchange(legacy, 12, 0, command("HELLO", 1), nil, 1, 0, 0); len(got) != 1 || got["ok"] != 1 {
		t.Fatalf("case mismatch returned %#v", got)
	}
	write(`{"query":{"hello":{"ok":1,"name":"edited"}}}`)
	if got := exchange(legacy, 13, 0, command("hello", 1), nil, 1, 0, 0); got["name"] != "edited" {
		t.Fatalf("edited configuration returned %#v", got)
	}
	write("{")
	if got := exchange(legacy, 14, 0, command("hello", 1), nil, 1, 14, 1); got["$err"] != "unexpected end of JSON input" {
		t.Fatalf("invalid configuration returned %#v", got)
	}
	if got := exchange(modern, 15, 1, command("isMaster", 1), nil, modern, 15, 0); got["ismaster"] != true || got["maxWireVersion"] != 3 {
		t.Fatalf("checksummed isMaster returned %#v", got)
	} else if stamp, ok := got["localTime"].(time.Time); !ok || time.Since(stamp).Abs() > time.Second {
		t.Fatalf("localTime = %#v", got["localTime"])
	}

	mongoTestSend(t, conn, modern, 16, 0, command("ping", 1), nil)
	if err := conn.SetReadDeadline(time.Now().Add(120 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if n, err := conn.Read(data[:]); n != 0 || !os.IsTimeout(err) {
		t.Fatalf("unhandled modern command read %d bytes, error %v", n, err)
	}
	got := exchange(modern, 17, 65536, command("find", "fixture"), nil, modern, 17, 0)
	cursor, ok := got["cursor"].(bson.M)
	if batch, present := cursor["firstBatch"]; !ok || cursor["id"] != int64(3) || !present || batch != nil || cursor["ns"] != "aggregate.a1_event" {
		t.Fatalf("find returned %#v", got)
	}
}

func mongoTestSend(t *testing.T, conn net.Conn, opcode, id, flags uint32, doc, fields bson.D) {
	t.Helper()
	const legacy = 2004
	le := binary.LittleEndian
	wire := le.AppendUint32(make([]byte, 16), flags)
	if opcode == legacy {
		wire = append(wire, "admin.$cmd\x00"...)
		wire = le.AppendUint32(wire, 0)
		wire = le.AppendUint32(wire, 1)
	} else {
		wire = append(wire, 0)
		doc = append(doc, bson.DocElem{Name: "$db", Value: "admin"})
	}
	for _, body := range []bson.D{doc, fields} {
		if body == nil {
			continue
		}
		encoded, err := bson.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, encoded...)
	}
	checksum := opcode != legacy && flags&1 != 0
	length := len(wire)
	if checksum {
		length += 4
	}
	le.PutUint32(wire[:4], uint32(length))
	le.PutUint32(wire[4:8], id)
	le.PutUint32(wire[12:16], opcode)
	if checksum {
		wire = le.AppendUint32(wire, crc32.Checksum(wire, crc32.MakeTable(crc32.Castagnoli)))
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
}
