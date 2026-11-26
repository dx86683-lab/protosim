package protocols

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

const sipReferenceHeaders = "Via: SIP/2.0/UDP lab;branch=z9hG4bKtest;rport\r\nFrom: <sip:source@lab>;tag=lab\r\nTo: <sip:target@lab>\r\nCall-ID: parity-test\r\nCSeq: 42 REGISTER\r\n"

func TestReferenceTransportSessions(t *testing.T) {
	t.Run("icap", func(t *testing.T) {
		requireReferenceTCP(t, "icap", nil, []referenceExchange{
			{"OPTIONS icap://lab/service ICAP/1.0\r\nHost: lab\r\nEncapsulated: null-body=0\r\n\r\n", "ICAP/1.0 200 OK\r\nIstag: \"GreasySpoon-1.0.8-01\"\r\nMax-Connections: 50\r\nMethods: REQMOD, RESPMOD\r\nService: GreasySpoon service version 1.0.8-01\r\n\r\n"},
		})
		requireReferenceTCP(t, "icap", nil, []referenceExchange{
			{"REQMOD icap://lab/service ICAP/1.0\r\nHost: lab\r\nEncapsulated: null-body=0\r\n\r\n", "ICAP/1.0 400 Bad Request\r\n\r\n"},
		})
	})
	t.Run("rtsp", func(t *testing.T) {
		requireReferenceTCP(t, "rtsp", nil, []referenceExchange{
			{"OPTIONS rtsp://lab/stream RTSP/1.0\r\nCSeq: 25\r\n\r\n", "RTSP/1.0 200 OK\r\nCSeq: 25\r\nPublic: " + rtspPublic + "\r\n\r\n"},
			{"DESCRIBE rtsp://lab/stream RTSP/1.0\r\nCSeq: 26\r\nAccept: application/sdp\r\n\r\n", "RTSP/1.0 404 Not Found\r\nCSeq: 26\r\n\r\n"},
		})
	})
	t.Run("socks5", func(t *testing.T) {
		requireReferenceTCP(t, "socks5", map[string]interface{}{"auth": true, "accounts": []interface{}{"fixture:lab-only"}}, []referenceExchange{
			{"\x05\x02\x00\x02", "\x05\x02"},
			{"\x01\x07fixture\x08lab-only", "\x01\x00"},
			{"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", "\x05\x00\x00\x01\x00\x00\x00\x00"},
		})
	})
	t.Run("postgres", func(t *testing.T) {
		requireReferenceTCP(t, "postgres", map[string]interface{}{"accounts": []interface{}{"fixture:lab-only"}}, []referenceExchange{
			{"\x00\x00\x00\x08\x04\xd2\x16\x2f", "N"},
			{"\x00\x00\x00\x27\x00\x03\x00\x00user\x00fixture\x00database\x00fixture\x00\x00", "R\x00\x00\x00\x08\x00\x00\x00\x03"},
		})
	})
	t.Run("telnet", func(t *testing.T) {
		requireReferenceTCP(t, "telnet", nil, []referenceExchange{
			{"", "\xff\xfb\x01"},
			{"\xff\xfb\x01", "Password: "},
			{"wrong\r\n", "Login incorrect\r\nPassword: "},
			{"123456\n", "$ "},
			{"whoami\n", "\r\nroot\r\n$ "},
		})
	})
}

func TestReferenceSIPRegister(t *testing.T) {
	protocol := GetProtocol("sip")
	if protocol == nil || protocol.DatagramHandler == nil {
		t.Fatal("SIP UDP handler is not registered")
	}
	binding := &BindInfo{}
	handle := protocol.DatagramHandler(binding)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	request := []byte("REGISTER sip:lab SIP/2.0\r\n" + sipReferenceHeaders + "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	if err := handle(NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{BindInfo: binding}), request); err != nil {
		t.Fatal(err)
	}
	var buf [1024]byte
	n, _, err := client.ReadFrom(buf[:])
	want := "SIP/2.0 200 OK\r\n" + sipReferenceHeaders + "Content-Length: 0\r\nMax-Forwards: 70\r\n\r\n"
	if err != nil || string(buf[:n]) != want {
		t.Fatalf("SIP reply %q, %v; want %q", buf[:n], err, want)
	}
}

func TestReferencePostgresRejectsRepeatedSSLRequest(t *testing.T) {
	client, stop := startRound6Server(t, round6Case{Handler: "postgres"})
	defer stop()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	request := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), postgresSSL)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 'N' {
		t.Fatalf("first SSL response = %q, %v", reply, err)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(reply[:]); n != 0 || err != io.EOF {
		t.Fatalf("second SSL response = %q (%d bytes), %v", reply, n, err)
	}
}

func TestReferencePostgresDuplicateAccount(t *testing.T) {
	params := map[string]interface{}{"accounts": []interface{}{"fixture:first", "fixture:second"}}
	challenge := postgresFrame(nil, 'R', "\x00\x00\x00\x03")
	startup := postgresFrame(nil, 0, "\x00\x03\x00\x00user\x00fixture\x00\x00")[1:]
	for _, tc := range []struct {
		password string
		reply    []byte
	}{
		{"first", postgresFrame(nil, 'E', "SFATAL\x00CXX000\x00Mpassword authentication failed for user \"fixture\"\x00\x00")},
		{"second", postgresFrame(nil, 'R', "\x00\x00\x00\x00")},
	} {
		t.Run(tc.password, func(t *testing.T) {
			requireReferenceTCP(t, "postgres", params, []referenceExchange{
				{string(startup), string(challenge)},
				{string(postgresFrame(nil, 'p', tc.password+"\x00")), string(tc.reply)},
			})
		})
	}
}

func TestReferencePostgresQueryFixture(t *testing.T) {
	entry, ok := registor.Load("postgres")
	if !ok {
		t.Fatal("postgres is not registered")
	}
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		defer server.Close()
		entry.(*ProtocolInfo).HandleFunc.(func(*SessionConnection) error)(&SessionConnection{
			Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: map[string]interface{}{"accounts": []interface{}{"fixture:lab-only"}}}},
		})
	}()
	send := func(kind string, payload string) {
		t.Helper()
		frame := binary.BigEndian.AppendUint32([]byte(kind), uint32(4+len(payload)))
		if _, err := client.Write(append(frame, payload...)); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() (byte, []byte) {
		t.Helper()
		var header [5]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			t.Fatal(err)
		}
		n := binary.BigEndian.Uint32(header[1:])
		if n < 4 || n > 4096 {
			t.Fatalf("invalid PostgreSQL frame length %d", n)
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(client, body); err != nil {
			t.Fatal(err)
		}
		return header[0], body
	}
	send("", "\x00\x03\x00\x00user\x00fixture\x00database\x00fixture\x00application_name\x00test-client\x00\x00")
	if kind, data := receive(); kind != 'R' || !bytes.Equal(data, []byte{0, 0, 0, 3}) {
		t.Fatalf("expected cleartext authentication request, got %c %x", kind, data)
	}
	send("p", "lab-only\x00")
	for index, want := range "RSSSSKZ" {
		kind, data := receive()
		if kind != byte(want) {
			t.Fatalf("startup frame %c, want %c", kind, want)
		}
		if index == 1 && string(data) != "application_name\x00\x00" {
			t.Fatalf("unexpected startup application_name: %q", data)
		}
	}
	send("Q", "SELECT 1\x00")
	for _, want := range "TDCZ" {
		kind, body := receive()
		if kind != byte(want) {
			t.Fatalf("query frame %c, want %c", kind, want)
		}
		if kind == 'T' && !(bytes.Contains(body, []byte("user\x00")) && bytes.Contains(body, []byte("email\x00"))) {
			t.Fatalf("unexpected row description %x", body)
		}
		if kind == 'D' && string(body) != "\x00\x03\x00\x00\x00\x05row 0\x00\x00\x00\x06123456\x00\x00\x00\rtest@test.com" {
			t.Fatalf("unexpected row %x", body)
		}
	}
	for _, tc := range []struct {
		query     string
		kinds     string
		errorBody string
	}{
		{"; -- comment", "Z", ""},
		{"SELECT\t42", "TDCZ", ""},
		{"VALUES (1)", "TDCZ", ""},
		{"WITH data AS (SELECT 1) SELECT * FROM data", "TDCZ", ""},
		{"SELECT $$a;b$$; SELECT 3", "TDCTDCZ", ""},
		{"SELECT 1; BEGIN; SELECT 2", "TDCETDCZ", "SERROR\x00C0A000\x00Munsupported commands execution. Read-only mode.\x00\x00"},
		{"SELECT 1; typo; SELECT 2", "EZ", "SERROR\x00CXX000\x00Mat or near \"typo\": syntax error\x00\x00"},
		{"SELECT", "EZ", "SERROR\x00CXX000\x00Mat or near \"EOF\": syntax error\x00\x00"},
	} {
		send("Q", tc.query+"\x00")
		for _, want := range tc.kinds {
			kind, body := receive()
			if kind != byte(want) || kind == 'E' && string(body) != tc.errorBody || kind == 'Z' && string(body) != "I" {
				t.Fatalf("%q: got %c %q, expected %c", tc.query, kind, body, want)
			}
		}
	}
	send("P", "stmt\x00SELECT $1\x00\x00\x01\x00\x00\x00\x17")
	send("B", "portal\x00stmt\x00\x00\x00\x00\x01\x00\x00\x00\x0299\x00\x00")
	send("D", "Pportal\x00")
	send("E", "portal\x00\x00\x00\x00\x00")
	send("S", "")
	for _, expected := range []struct {
		kind byte
		body string
	}{
		{'1', ""},
		{'E', "SERROR\x00C26000\x00Mprepared statement \"stmt\" does not exist\x00\x00"},
		{'Z', "I"},
	} {
		if kind, body := receive(); kind != expected.kind || string(body) != expected.body {
			t.Fatalf("extended query: %c %q; want %c %q", kind, body, expected.kind, expected.body)
		}
	}
	send("E", "portal\x00\x00\x00\x00\x00")
	if kind, body := receive(); kind != 'C' || string(body) != "SET\x00" {
		t.Fatalf("standalone execute: %c %q", kind, body)
	}
	if kind, body := receive(); kind != 'Z' || string(body) != "I" {
		t.Fatalf("ready after execute: %c %q", kind, body)
	}

	expectSilence := func() {
		t.Helper()
		client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var reply [1]byte
		n, err := client.Read(reply[:])
		if timeout, ok := err.(net.Error); n != 0 || !ok || !timeout.Timeout() {
			t.Fatalf("expected queued response, read %d bytes with %v", n, err)
		}
		client.SetReadDeadline(time.Now().Add(time.Second))
	}
	expectKinds := func(kinds string) {
		t.Helper()
		for _, want := range kinds {
			if kind, body := receive(); kind != byte(want) {
				t.Fatalf("got %c %q, want %c", kind, body, want)
			}
		}
	}
	parse := "stmt\x00SELECT 1\x00\x00\x00"
	send("P", parse)
	send("H", "")
	expectSilence()
	send("S", "")
	expectKinds("1EZ")

	send("P", parse)
	send("Q", "SELECT 42\x00")
	expectKinds("1TDCZ")
	send("S", "")
	expectKinds("Z")

	send("D", "Sstmt\x00")
	send("Q", "SELECT 42\x00")
	expectKinds("ETDCZ")
	send("P", parse)
	send("E", "portal\x00\x00\x00\x00\x00")
	expectSilence()
	send("S", "")
	expectKinds("1CZ")

	send("P", "stmt\x00 -- comment\n\x00\x00\x00")
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("expected Parse with no SQL statement to close, read %d bytes with %v", n, err)
	}
}
