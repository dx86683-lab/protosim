package protocols

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

//go:embed fixtures/reference-dns.json
var dnsFixtures []byte

func TestDNSTCPFramingAndReuse(t *testing.T) {
	protocol := GetProtocol("dns")
	if _, ok := protocol.HandleFunc.(func(*SessionConnection) error); !ok || protocol.DatagramHandler == nil {
		t.Fatal("DNS listener does not offer both transports")
	}
	conn, stop := startRound6Server(t, round6Case{Handler: "dns"})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	frame := func(id uint16, name string, malformed bool) []byte {
		request := new(dns.Msg).SetQuestion(name, dns.TypeA)
		request.Id = id
		wire, err := request.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if malformed {
			wire = wire[:len(wire)-1]
		}
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	first := frame(19, "first.example.", false)
	if _, err := conn.Write(first[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(first[1:8]); err != nil {
		t.Fatal(err)
	}
	pipeline := append(bytes.Clone(first[8:]), frame(20, "broken.example.", true)...)
	pipeline = append(pipeline, frame(21, "second.example.", false)...)
	if _, err := conn.Write(pipeline); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		id   uint16
		code int
		q    string
	}{{19, dns.RcodeSuccess, "first.example."}, {20, dns.RcodeFormatError, ""}, {21, dns.RcodeSuccess, "second.example."}} {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, wire); err != nil {
			t.Fatal(err)
		}
		var reply dns.Msg
		if err := reply.Unpack(wire); err != nil || !reply.Response || reply.Id != want.id || reply.Rcode != want.code {
			t.Fatalf("reply %+v, error %v, want %+v", reply, err, want)
		}
		if want.q != "" && (len(reply.Question) != 1 || reply.Question[0].Name != want.q) {
			t.Fatalf("question %v, want %q", reply.Question, want.q)
		}
	}
}

func TestDNSTCPAXFRNotAuthoritative(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "dns"})
	defer stop()
	client := &dns.Client{Net: "tcp", Timeout: time.Second}
	dnsConn := &dns.Conn{Conn: conn}
	for _, test := range []struct {
		name    string
		version int
		rcode   int
	}{
		{"without EDNS", -1, dns.RcodeNotAuth},
		{"with EDNS", 0, dns.RcodeNotAuth},
		{"unsupported EDNS version", 1, dns.RcodeBadVers},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := new(dns.Msg).SetAxfr("fixture.invalid.")
			request.RecursionDesired = true
			request.CheckingDisabled = true
			if test.version >= 0 {
				request.SetEdns0(1232, false)
				request.IsEdns0().SetVersion(uint8(test.version))
			}
			reply, _, err := client.ExchangeWithConn(request, dnsConn)
			if err != nil || reply.Rcode != test.rcode || !reply.Response || reply.Id != request.Id ||
				!reply.RecursionDesired || reply.CheckingDisabled || reply.Authoritative || reply.Truncated ||
				!slices.Equal(reply.Question, request.Question) || len(reply.Answer) != 0 || len(reply.Ns) != 0 {
				t.Fatalf("AXFR reply %v, error %v, want RCODE %d, question echo and no zone records", reply, err, test.rcode)
			}
			if test.version < 0 && len(reply.Extra) != 0 ||
				test.version >= 0 && (len(reply.Extra) != 1 || reply.IsEdns0() == nil) {
				t.Fatalf("unexpected AXFR additional records %v", reply.Extra)
			}
		})
	}
	request := new(dns.Msg).SetQuestion("fixture.invalid.", dns.TypeA)
	reply, _, err := client.ExchangeWithConn(request, dnsConn)
	if err != nil || reply.Rcode != dns.RcodeSuccess || !slices.Equal(reply.Question, request.Question) {
		t.Fatalf("ordinary query after AXFR returned %v, error %v", reply, err)
	}
}

func TestDNSZoneTransferUnknownZone(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			conn, stop := startRound6Server(t, round6Case{Handler: "dns", UDP: transport == "udp"})
			defer stop()
			client := &dns.Client{Net: transport, Timeout: time.Second}
			for _, request := range []*dns.Msg{
				new(dns.Msg).SetAxfr("fixture.invalid."),
				new(dns.Msg).SetIxfr("fixture.invalid.", 42, "ns.fixture.invalid.", "hostmaster.fixture.invalid."),
			} {
				reply, _, err := client.ExchangeWithConn(request, &dns.Conn{Conn: conn})
				if err != nil || !reply.Response || reply.Rcode != dns.RcodeNotAuth ||
					reply.Id != request.Id || !slices.Equal(reply.Question, request.Question) ||
					len(reply.Answer)+len(reply.Ns)+len(reply.Extra) != 0 {
					t.Errorf("%v reply %v, error %v, want NOTAUTH and original question only", request.Question, reply, err)
				}
			}
		})
	}
}

func TestDNSTCPEDNS(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "dns"})
	defer stop()
	client := &dns.Client{Net: "tcp", Timeout: time.Second}
	exchange := func(msg *dns.Msg, code int) *dns.Msg {
		t.Helper()
		reply, _, err := client.ExchangeWithConn(msg, &dns.Conn{Conn: conn})
		if err != nil || reply.Rcode != code {
			t.Fatalf("EDNS reply %v, error %v, want RCODE %d", reply, err, code)
		}
		return reply
	}
	query := func() *dns.Msg {
		return new(dns.Msg).SetQuestion("edns.example.", dns.TypeA).SetEdns0(4096, true)
	}
	request := query()
	request.IsEdns0().Option = []dns.EDNS0{
		&dns.EDNS0_TCP_KEEPALIVE{},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte("unknown")},
	}
	reply := exchange(request, dns.RcodeSuccess)
	opt := reply.IsEdns0()
	if opt == nil || opt.Version() != 0 || !opt.Do() || len(opt.Option) != 1 {
		t.Fatalf("unexpected OPT response %v", opt)
	}
	keepalive, ok := opt.Option[0].(*dns.EDNS0_TCP_KEEPALIVE)
	if !ok || keepalive.Timeout != uint16(dnsTCPTimeout/(100*time.Millisecond)) {
		t.Fatalf("keepalive %v does not report connection timeout", opt.Option[0])
	}
	request = query()
	request.IsEdns0().SetVersion(1)
	reply = exchange(request, dns.RcodeBadVers)
	if opt = reply.IsEdns0(); opt == nil || opt.Version() != 0 || len(reply.Extra) != 1 || len(opt.Option) != 0 {
		t.Fatalf("BADVERS response %v", reply)
	}
	request = query()
	request.SetEdns0(1232, false)
	reply = exchange(request, dns.RcodeFormatError)
	if reply.IsEdns0() == nil || len(reply.Extra) != 1 {
		t.Fatalf("duplicate OPT error response %v", reply)
	}
	reply = exchange(query(), dns.RcodeSuccess)
	if opt = reply.IsEdns0(); opt == nil || len(opt.Option) != 0 {
		t.Fatalf("keepalive appeared without a request %v", reply)
	}
}

func TestDNSUDPErrorReplies(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "dns", UDP: true})
	defer stop()
	for _, test := range []struct {
		name  string
		flags uint16
		count uint16
		rcode uint16
	}{
		{"wrong question count", 0x03b0, 2, dns.RcodeFormatError},
		{"truncated question", 0x0110, 1, dns.RcodeFormatError},
		{"unsupported opcode", 0x2bb0, 1, dns.RcodeNotImplemented},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := make([]byte, 12)
			binary.BigEndian.PutUint16(request, 876)
			binary.BigEndian.PutUint16(request[2:], test.flags)
			binary.BigEndian.PutUint16(request[4:], test.count)
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
			var payload [512]byte
			n, err := conn.Read(payload[:])
			wantFlags := 0x8000 | test.flags&0x7910 | test.rcode
			if err != nil || n != 12 || binary.BigEndian.Uint16(payload[:]) != 876 ||
				binary.BigEndian.Uint16(payload[2:]) != wantFlags || !bytes.Equal(payload[4:n], make([]byte, 8)) {
				t.Fatalf("response %x, error %v, want flags %04x", payload[:n], err, wantFlags)
			}
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Read(payload[:]); err == nil {
				t.Fatalf("unexpected second response %x", payload[:n])
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal(err)
			}
		})
	}
}

func TestDNSUDPEDNSAndPayloadLimit(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "dns", UDP: true})
	defer stop()
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	exchange := func(msg *dns.Msg, want int) *dns.Msg {
		t.Helper()
		reply, _, err := client.ExchangeWithConn(msg, &dns.Conn{Conn: conn})
		if err != nil || reply.Rcode != want {
			t.Fatalf("UDP reply %v, error %v, want RCODE %d", reply, err, want)
		}
		return reply
	}
	request := new(dns.Msg).SetQuestion("edns.example.", dns.TypeA).SetEdns0(1232, true)
	request.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_TCP_KEEPALIVE{}}
	reply := exchange(request, dns.RcodeSuccess)
	if opt := reply.IsEdns0(); opt == nil || !opt.Do() || opt.Version() != 0 || len(opt.Option) != 0 {
		t.Fatalf("UDP EDNS response %v", reply)
	}
	request.Id++
	request.IsEdns0().SetVersion(1)
	reply = exchange(request, dns.RcodeBadVers)
	if opt := reply.IsEdns0(); opt == nil || opt.Version() != 0 || len(reply.Extra) != 1 {
		t.Fatalf("UDP BADVERS response %v", reply)
	}
	request = new(dns.Msg).SetQuestion("edns.example.", dns.TypeA).SetEdns0(1232, false).SetEdns0(1232, false)
	reply = exchange(request, dns.RcodeFormatError)
	if opt := reply.IsEdns0(); opt == nil || len(reply.Extra) != 1 {
		t.Fatalf("UDP duplicate OPT response %v", reply)
	}

	label := string(bytes.Repeat([]byte("x"), 63))
	name := label + "." + label + "." + label + "." + label[:61] + "."
	for _, advertised := range []uint16{0, 256} {
		request = new(dns.Msg).SetQuestion(name, dns.TypeA)
		if advertised != 0 {
			request.SetEdns0(advertised, false)
		}
		wire, err := request.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
		var packet [1024]byte
		n, err := conn.Read(packet[:])
		if err != nil || n > dns.MinMsgSize {
			t.Fatalf("UDP payload size %d with advertised limit %d, error %v", n, advertised, err)
		}
		var result dns.Msg
		if err := result.Unpack(packet[:n]); err != nil || result.Rcode != dns.RcodeSuccess ||
			len(result.Question) != 1 || result.Question[0].Name != name {
			t.Fatalf("UDP long-name reply %v, error %v", result, err)
		}
	}
}

func TestReferenceDNSExchangeAndEvents(t *testing.T) {
	var fixtures struct {
		Cases []struct {
			Request      string
			Replies      []string
			SimReplies []string `json:"sim_replies"`
			ZeroPad      int      `json:"zero_pad"`
		}
		Events          []dnsTestEvent
		OversizedEvents []dnsTestEvent `json:"oversized_events"`
	}
	if err := json.Unmarshal(dnsFixtures, &fixtures); err != nil {
		t.Fatal(err)
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
	var logs bytes.Buffer
	logger := logrus.New()
	logger.Out = &logs
	logger.Formatter = &logrus.JSONFormatter{}
	config := &ConfigInfo{BindInfo: &BindInfo{Params: map[string]any{"appname": "lab-dns"}}, Log: logrus.NewEntry(logger)}
	handle := GetProtocol("dns").DatagramHandler(config.BindInfo)
	conn := NewUDPConnection(server, client.LocalAddr(), config)
	for _, c := range fixtures.Cases {
		wire, err := hex.DecodeString(c.Request)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, make([]byte, c.ZeroPad)...)
		if err := handle(conn, wire); err != nil {
			t.Fatal(err)
		}
		replies := c.Replies
		if c.SimReplies != nil {
			replies = c.SimReplies
		}
		for _, reply := range replies {
			if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var buf [512]byte
			n, _, err := client.ReadFrom(buf[:])
			if err != nil || hex.EncodeToString(buf[:n]) != reply {
				t.Fatalf("request %s: reply %x (%v), want %s", c.Request, buf[:n], err, reply)
			}
		}
		if err := client.SetReadDeadline(time.Now().Add(2 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var extra [512]byte
		if n, _, err := client.ReadFrom(extra[:]); err == nil {
			t.Fatalf("request %s: unexpected DNS reply %x", c.Request, extra[:n])
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	var got []dnsTestEvent
	for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte{'\n'}) {
		var event dnsTestEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		got = append(got, event)
	}
	want := append(fixtures.Events, fixtures.OversizedEvents...)
	byID := func(a, b dnsTestEvent) int { return int(a.ID) - int(b.ID) }
	slices.SortFunc(want, byID)
	slices.SortFunc(got, byID)
	if len(got) != len(want) {
		t.Fatalf("got %d DNS events, want %d", len(got), len(want))
	}
	for i, event := range got {
		if event != want[i] {
			t.Errorf("DNS event %d: got %+v, want %+v", i, event, want[i])
		}
	}
}

type dnsTestEvent struct {
	Msg, Op, Question string
	ID                uint16
	PayloadSize       int `json:"payload_size"`
}
