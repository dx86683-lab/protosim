package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

//go:embed fixtures/reference-discovery.json
var discoveryExchanges []byte

type discoveryExchange struct {
	Request, Response string
	SimResponse     string `json:"sim_response"`
	Params            map[string]interface{}
}

func (d discoveryExchange) expectedResponse() string {
	if d.SimResponse != "" {
		return d.SimResponse
	}
	return d.Response
}

func TestReferenceDiscoveryExchanges(t *testing.T) {
	var cases map[string]map[string][]discoveryExchange
	if err := json.Unmarshal(discoveryExchanges, &cases); err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T, wire string) []byte {
		t.Helper()
		frame, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	for name, frames := range cases["tcp"] {
		t.Run(name, func(t *testing.T) {
			exchanges := make([]referenceExchange, 0, len(frames))
			for _, f := range frames {
				exchanges = append(exchanges, referenceExchange{string(decode(t, f.Request)), string(decode(t, f.expectedResponse()))})
			}
			switch name {
			case "amqp":
				requireReferenceTCP(t, name, nil, exchanges, canonicalAMQPStart)
			case "dcerpc":
				requireReferenceTCP(t, name, nil, exchanges, canonicalDCERPCBindAck)
			default:
				requireReferenceTCP(t, name, nil, exchanges)
			}
		})
	}
	for name, frames := range cases["udp"] {
		t.Run(name, func(t *testing.T) {
			for _, f := range frames {
				want := decode(t, f.expectedResponse())
				requireReferenceDatagram(t, name, decode(t, f.Request), want, f.Params)
				if name == "l2tp" && f.Params["host_name"] != nil {
					legacy := map[string]interface{}{
						"hostname": f.Params["host_name"], "vendor_name": f.Params["vendor_name"],
					}
					requireReferenceDatagram(t, name, decode(t, f.Request), want, legacy)
				}
			}
		})
	}
}

func canonicalDCERPCBindAck(wire string) string {
	if len(wire) >= 24 && wire[2] == dceBindAck {
		return wire[:20] + "\x00\x00\x00\x00" + wire[24:]
	}
	return wire
}

func requireReferenceDatagram(t *testing.T, name string, request, want []byte, overrides ...map[string]interface{}) {
	t.Helper()
	var params map[string]any
	if len(overrides) > 0 {
		params = overrides[0]
	}
	got := roundTripDatagram(t, name, params, request)
	if !bytes.Equal(got, want) {
		t.Fatalf("received %x, want %x", got, want)
	}
}

func roundTripDatagram(t *testing.T, name string, params map[string]any, request []byte) []byte {
	t.Helper()
	entry, ok := registor.Load(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	handle, ok := entry.(*ProtocolInfo).HandleFunc.(func(*UDPConnection, []byte) error)
	if !ok {
		t.Fatal("expected a UDP handler")
	}
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
	binding := &BindInfo{Params: params}
	if err := handle(NewUDPConnection(server, client.LocalAddr(), &ConfigInfo{BindInfo: binding}), request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 65535)
	n, _, err := client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	return got[:n]
}

func TestReferenceFoxHello(t *testing.T) {
	testReferenceFoxHello(t, nil)
}

func TestReferenceFoxHelloWithJSONHandlers(t *testing.T) {
	testReferenceFoxHello(t, map[string]interface{}{"handlers": map[string]interface{}{
		"hello": map[string]interface{}{"hostaddress": "s:fixture", "brandid": "s:lab"},
	}})
}

func testReferenceFoxHello(t *testing.T, params map[string]interface{}) {
	t.Helper()
	entry, ok := registor.Load("fox")
	if !ok {
		t.Fatal("fox is not registered")
	}
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	go entry.(*ProtocolInfo).HandleFunc.(func(*SessionConnection) error)(&SessionConnection{
		Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{Params: params}},
	})
	if _, err := io.WriteString(client, "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(client)
	for _, want := range []string{"fox a 0 -1 fox hello\n", "{\n"} {
		if got, err := r.ReadString('\n'); err != nil || got != want {
			t.Fatalf("FOX header %q, %v; want %q", got, err, want)
		}
	}
	var lines []string
	for len(lines) < 40 {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "};;\n" {
			break
		}
		lines = append(lines, strings.TrimSuffix(line, "\n"))
	}
	sort.Strings(lines)
	for _, want := range []string{"fox.version=s:1.0.1", "hostAddress=s:127.0.0.1", "vm.version=s:1.5.0_81-b06"} {
		i := sort.SearchStrings(lines, want)
		if i == len(lines) || lines[i] != want {
			t.Fatalf("FOX field %q missing", want)
		}
	}
}

func TestFoxUsesTypedHandlers(t *testing.T) {
	params := map[string]interface{}{"handlers": map[string]map[string]string{
		"hello": {"hostAddress": "s:fixture", "brandId": "s:lab"},
	}}
	requireReferenceTCP(t, "fox", params, []referenceExchange{
		{"fox a 1 -1 fox hello\n{\n};;\n", "fox a 0 -1 fox hello\n{\nbrandId=s:lab\nhostAddress=s:fixture\n};;\n"},
	}, func(wire string) string {
		lines := strings.Split(wire, "\n")
		if len(lines) == 6 {
			sort.Strings(lines[2:4])
		}
		return strings.Join(lines, "\n")
	})
}

func TestReferenceFoxHalfClose(t *testing.T) {
	const header = "fox b -1 002 fox info"
	const response = "fox b 0 002 fox info\n{\nx=s:lab\n};;\n"
	const emptyResponse = "fox b 0 002 fox info\n{\n};;\n"
	const badHead = "[FOX] bad head line: "
	const badBrace = "[FOX] bad lpara : "

	for _, tc := range []struct {
		name, request, reply, diagnostic string
	}{
		{"partial body", header + "\n{\nx=s:lab\n", response, badHead},
		{"partial opening", header + "\n{", emptyResponse, badHead},
		{"missing opening", header + "\n", "", badBrace + header},
		{"unterminated header", header, "", badBrace + header},
		{"invalid opening", header + "\n {\n", "", badBrace + header},
		{"partial header", "fox b -1", "", badHead + "fox b -1"},
		{"invalid header CRLF", "fox b x 002 fox info\r\n", "", badHead + "fox b x 002 fox info"},
		{"empty connection", "", "", badHead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFoxHalfClose(t, tc.request, tc.reply, tc.diagnostic)
		})
	}
}

func testFoxHalfClose(t *testing.T, request, wantReply, wantDiagnostic string) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		result <- serveFox(&SessionConnection{Conn: conn, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != wantReply {
		t.Fatalf("FOX reply %q, %v, want %q", got, err, wantReply)
	}
	if err := <-result; err == nil || err.Error() != wantDiagnostic {
		t.Fatalf("FOX diagnostic %q, want %q", err, wantDiagnostic)
	}
}

func TestReferenceEIPRegisterAndUnregister(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		defer server.Close()
		result <- serveEIP(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	}()

	var request [28]byte
	le := binary.LittleEndian
	le.PutUint16(request[:2], eipRegisterSession)
	le.PutUint16(request[2:4], 4)
	le.PutUint16(request[24:26], 1)
	copy(request[12:20], "EIP Test")
	for i := 0; i < 2; i++ {
		if _, err := client.Write(request[:]); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(request))
		if _, err := io.ReadFull(client, reply); err != nil {
			t.Fatal(err)
		}
		handle := le.Uint32(reply[4:8])
		if handle == 0 {
			t.Fatal("missing registered session handle")
		}
		le.PutUint32(reply[4:8], 0)
		if !bytes.Equal(reply, request[:]) {
			t.Fatalf("registration reply %x, want %x with a session handle", reply, request)
		}
	}
	le.PutUint16(request[:2], eipUnregisterSession)
	le.PutUint16(request[2:4], 0)
	if _, err := client.Write(request[:24]); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(request[:]); err != io.EOF {
		t.Fatalf("read after unregistration returned %v, want EOF", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestReferenceGESRTPShortHeader(t *testing.T) {
	_, err := readGESRTPHeader(bytes.NewReader(make([]byte, 37)))
	if err == nil || err.Error() != "read field MailboxDst: unexpected EOF" {
		t.Fatalf("short GE-SRTP header returned %v", err)
	}
}

// The reference serializes the AMQP capability table in varying field order.
func canonicalAMQPStart(wire string) string {
	const marker = "\x0ccapabilitiesF"
	before, table, ok := strings.Cut(wire, marker)
	if !ok || len(table) < 4 {
		return wire
	}
	size := int(binary.BigEndian.Uint32([]byte(table[:4])))
	if size > len(table)-4 {
		return wire
	}
	fields := table[4 : size+4]
	var entries []string
	for fields != "" {
		end := int(fields[0]) + 3
		if end > len(fields) || fields[end-2] != 't' {
			return wire
		}
		entries, fields = append(entries, fields[:end]), fields[end:]
	}
	sort.Strings(entries)
	return before + marker + table[:4] + strings.Join(entries, "") + table[size+4:]
}
