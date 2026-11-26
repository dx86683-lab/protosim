package protocols

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type referenceExchange struct{ send, receive string }

func requireReferenceTCP(t *testing.T, name string, params map[string]interface{}, exchanges []referenceExchange, normalizers ...func(string) string) {
	t.Helper()
	requireReferenceTCPHandler(t, referenceTCPHandler(t, name), params, exchanges, normalizers...)
}

func referenceTCPHandler(t *testing.T, name string) func(*SessionConnection) error {
	t.Helper()
	entry, ok := registor.Load(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	switch handler := entry.(*ProtocolInfo).HandleFunc.(type) {
	case func(*SessionConnection) error:
		return handler
	case func() func(*SessionConnection) error:
		return handler()
	default:
		t.Fatal("expected a TCP session handler")
		return nil
	}
}

func requireReferenceTCPHandler(t *testing.T, handle func(*SessionConnection) error, params map[string]interface{}, exchanges []referenceExchange, normalizers ...func(string) string) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go handle(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: params}}})
	for _, exchange := range exchanges {
		if exchange.send != "" {
			if _, err := io.WriteString(client, exchange.send); err != nil {
				t.Fatalf("sending %q: %v", exchange.send, err)
			}
		}
		wire := make([]byte, len(exchange.receive))
		_, err := io.ReadFull(client, wire)
		got, want := string(wire), exchange.receive
		for _, normalize := range normalizers {
			got, want = normalize(got), normalize(want)
		}
		if err != nil || got != want {
			t.Fatalf("after %q: received %q, %v; want %q", exchange.send, wire, err, exchange.receive)
		}
	}
}

func TestReferenceServiceSessions(t *testing.T) {
	const capability = "IMAP4rev1 LITERAL+ SASL-IR CHILDREN UNSELECT MOVE APPENDLIMIT LOGINDISABLED"
	cases := map[string][]referenceExchange{
		"memcache": {{"version\r\n", "VERSION 1.5.16\r\n"}, {"stats\r\n", "STAT pid 1\r\nSTAT uptime "}},
		"imap": {
			{"", "* OK [CAPABILITY " + capability + "] Dovecot Ready\r\n"},
			{"a001 CAPABILITY\r\n", "* CAPABILITY " + capability + "\r\na001 OK CAPABILITY completed\r\n"},
			{"a002 NOOP\r\n", "a002 OK NOOP completed\r\n"},
			{"a003 LOGOUT\r\n", "* BYE Closing connection\r\na003 OK LOGOUT completed\r\n"},
		},
		"pop3": {
			{"", "+OK Dovecot ready\r\n"},
			{"CAPA\r\n", "+OK \r\nUSER\r\nUIDL\r\n.\r\n"},
			{"NOOP\r\n", "-ERR Error executing command NOOP\r\n"},
			{"QUIT\r\n", "+OK Goodbye\r\n"},
		},
		"mqtt": {
			{"\x10\x12\x00\x04MQTT\x04\x02\x00\x1e\x00\x06proto1", "\x20\x02\x01\x00"},
			{"\xc0\x00", "\xd0\x00"},
		},
		"vnc": {{"", "RFB 003.008\n"}, {"RFB 003.008\n", "\x01\x02"}},
	}
	for name, exchanges := range cases {
		t.Run(name, func(t *testing.T) { requireReferenceTCP(t, name, nil, exchanges) })
	}
}

func TestReferenceNTPTimeReply(t *testing.T) {
	entry, ok := registor.Load("ntp")
	if !ok {
		t.Fatal("ntp is not registered")
	}
	handle := entry.(*ProtocolInfo).HandleFunc.(func(*UDPConnection, []byte) error)
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
	request := make([]byte, 48)
	request[0] = 0x23
	binary.BigEndian.PutUint64(request[40:], 0xe93c001001020304)
	if err := handle(NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{BindInfo: &BindInfo{}}), request); err != nil {
		t.Fatal(err)
	}
	var datagram [128]byte
	n, _, err := client.ReadFrom(datagram[:])
	if err != nil || n != 48 {
		t.Fatalf("NTP response length %d: %v", n, err)
	}
	prefix := "\x24\x01\x00\xec\x00\x00\x00\x00\x00\x00\x00\x00NICT"
	if string(datagram[:16]) != prefix || !bytes.Equal(request[40:], datagram[24:32]) {
		t.Fatalf("unexpected NTP response %x", datagram[:n])
	}
	transmit := binary.BigEndian.Uint32(datagram[40:44])
	want := uint32(time.Now().Unix() + 2208988800)
	if delta := int32(transmit - want); delta < -2 || delta > 2 {
		t.Fatalf("NTP transmit timestamp %d does not match server time %d", transmit, want)
	}
}

func TestReferenceConfiguredServiceSessions(t *testing.T) {
	t.Run("imap authenticated mailbox", func(t *testing.T) {
		capability := "IMAP4rev1 LITERAL+ SASL-IR CHILDREN UNSELECT MOVE APPENDLIMIT"
		requireReferenceTCP(t, "imap", map[string]interface{}{
			"accounts": []interface{}{"fixture:lab-only"}, "allow_insecure_auth": true,
		}, []referenceExchange{
			{"", "* OK [CAPABILITY " + capability + " AUTH=PLAIN] Dovecot Ready\r\n"},
			{"a001 LOGIN fixture lab-only\r\n", "a001 OK [CAPABILITY " + capability + "] LOGIN completed\r\n"},
			{"a002 LIST \"\" \"*\"\r\n", "* LIST () \"/\" INBOX\r\na002 OK LIST completed\r\n"},
			{"a003 SELECT INBOX\r\n", "* FLAGS (\\Seen)\r\n* OK [PERMANENTFLAGS (\\*)] Flags permitted.\r\n" +
				"* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDNEXT 7] Predicted next UID\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n" +
				"a003 OK [READ-WRITE] SELECT completed\r\n"},
		})
	})
	t.Run("pop3 authenticated mailbox", func(t *testing.T) {
		requireReferenceTCP(t, "pop3", map[string]interface{}{"accounts": []interface{}{"fixture:lab-only"}}, []referenceExchange{
			{"", "+OK Dovecot ready\r\n"},
			{"USER fixture\r\n", "+OK \r\n"},
			{"PASS lab-only\r\n", "+OK User Successfully Logged on\r\n"},
			{"STAT\r\n", "+OK 5 50\r\n"},
			{"LIST\r\n", "+OK 5 messages\r\n0 10\r\n1 10\r\n2 10\r\n3 10\r\n4 10\r\n.\r\n"},
			{"NOOP\r\n", "+OK \r\n"},
		})
	})
	t.Run("mqtt subscription", func(t *testing.T) {
		requireReferenceTCP(t, "mqtt", nil, []referenceExchange{
			{"\x10\x12\x00\x04MQTT\x04\x02\x00\x1e\x00\x06proto1", "\x20\x02\x01\x00"},
			{"\x82\x08\x00\x01\x00\x03lab\x00", "\x90\x03\x00\x01\x00"},
		})
	})
	t.Run("vnc challenge", func(t *testing.T) {
		requireReferenceTCP(t, "vnc", nil, []referenceExchange{
			{"", "RFB 003.008\n"},
			{"RFB 003.008\n", "\x01\x02"},
			{"\x02", "0123456789abcdef"},
		})
	})
}
