package protocols

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestReferenceRTSPSessions(t *testing.T) {
	const referenceMethods = "DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, GET_PARAMETER, TEARDOWN"
	serve := func(session *SessionConnection) error { return newRTSPHandler()(session) }
	requireReferenceTextSessions(t, "fixtures/reference-rtsp.json", serve, 554, func(reply string) string {
		return strings.Replace(reply, "\r\nPublic: "+referenceMethods+"\r\n", "\r\nPublic: "+rtspPublic+"\r\n", 1)
	})
}

func TestRTSPConfiguredHeadersPreserveFraming(t *testing.T) {
	params := map[string]interface{}{
		"server": "Fixture/base",
		"headers": []any{
			": invalid", " X-Invalid: invalid", "x-Empty:", "X-Value: first", "X-Value:second: value",
			"cseq: 13", "Content-Length: 12", "Transfer-Encoding: chunked",
		},
	}
	requireReferenceTCP(t, "rtsp", params, []referenceExchange{{
		"OPTIONS * RTSP/1.0\r\nCSeq: 7\r\n\r\n",
		"RTSP/1.0 200 OK\r\nCSeq: 7\r\nPublic: " + rtspPublic +
			"\r\nServer: Fixture/base\r\nX-Value: second: value\r\nx-Empty: \r\n\r\n",
	}})
}

func TestRTSPRejectsInvalidFraming(t *testing.T) {
	for _, header := range []string{
		"Missing Colon\r\n", "X-Value: lone LF\n", "\n",
		"Content-Length: 0\r\nContent-Length: 3\r\n",
		"Content-Length: +0\r\n", "Content-Length:\r\n",
		"Transfer-Encoding: chunked\r\n",
	} {
		t.Run(strconv.Quote(header), func(t *testing.T) {
			client, stop := startRound6Server(t, round6Case{Handler: "rtsp"})
			defer stop()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(client, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"+header+"\r\n"); err != nil {
				t.Fatal(err)
			}
			var reply [1]byte
			if n, err := client.Read(reply[:]); n != 0 || err != io.EOF {
				t.Fatalf("received %q (%v), want silent close", reply[:n], err)
			}
		})
	}
}

func TestRTSPSequenceAndLengthFraming(t *testing.T) {
	requireReferenceTCP(t, "rtsp", nil, []referenceExchange{
		{"OPTIONS * RTSP/1.0\r\nCSeq:\t001 \t\r\nContent-Length:\t3 \t\r\n\r\nxyz" +
			"OPTIONS * RTSP/1.0\r\nCSeq: 2\r\nX-Extension: alpha\r\n beta\r\n\r\n",
			"RTSP/1.0 200 OK\r\nCSeq: 001\r\nPublic: " + rtspPublic + "\r\n\r\n" +
				"RTSP/1.0 200 OK\r\nCSeq: 2\r\nPublic: " + rtspPublic + "\r\n\r\n"},
		{"OPTIONS * RTSP/1.0\r\nCSeq: abc\r\n\r\n", "RTSP/1.0 400 Bad Request\r\n\r\n"},
	})
}

func TestRTSPMethodDiscovery(t *testing.T) {
	var exchange []referenceExchange
	for i, method := range []string{"GET_PARAMETER", "PING", "options"} {
		seq := strconv.Itoa(i + 1)
		exchange = append(exchange, referenceExchange{
			method + " rtsp://fixture.invalid/media RTSP/1.0\r\nCSeq: " + seq + "\r\n\r\n",
			"RTSP/1.0 501 Not Implemented\r\nCSeq: " + seq + "\r\n\r\n",
		})
	}
	exchange = append(exchange, referenceExchange{
		"OPTIONS * RTSP/1.0\r\nCSeq: 7\r\n\r\n",
		"RTSP/1.0 200 OK\r\nCSeq: 7\r\nPublic: OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, TEARDOWN\r\n\r\n",
	})
	requireReferenceTCP(t, "rtsp", map[string]interface{}{"headers": []any{"public: PING"}}, exchange)
}

func TestRTSPTransportOffers(t *testing.T) {
	const uri = "rtsp://fixture.invalid/live/trackID=0"
	for _, tc := range []struct{ name, fields, status string }{
		{"ordered alternatives", "Transport: RTP/AVP;unicast;client_port=5000-5001, RTP/AVP/TCP;unicast;interleaved=3-4", "404 Not Found"},
		{"repeated fields", "Transport: RTP/AVP;unicast;client_port=5000-5001\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1", "404 Not Found"},
		{"quoted delimiters", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;x-flag=\"a,b;c\"", "404 Not Found"},
		{"unsupported offers", "Transport: RTP/AVP/SCTP;unicast, RTP/AVP/TCP;multicast;interleaved=0-1", "461 Unsupported Transport"},
		{"contradictory delivery options", "Transport: RTP/AVP/TCP;unicast;multicast;interleaved=0-1", "400 Bad Request"},
		{"channel overflow", "Transport: RTP/AVP/TCP;unicast;interleaved=256-257", "400 Bad Request"},
		{"quoted token with trailing bytes", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=\"PLAY\"suffix", "400 Bad Request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireReferenceTCP(t, "rtsp", nil, []referenceExchange{{
				"SETUP " + uri + " RTSP/1.0\r\nCSeq: 11\r\n" + tc.fields + "\r\n\r\n",
				"RTSP/1.0 " + tc.status + "\r\nCSeq: 11\r\n\r\n",
			}})
		})
	}
}

func TestRTSPPublishesSessionDescriptionAcrossConnections(t *testing.T) {
	const target = "rtsp://fixture.invalid/live?source=test"
	const sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\na=control:trackID=0\r\n"
	publish := func(body, seq string) string {
		return "ANNOUNCE " + target + " RTSP/1.0\r\nCSeq: " + seq + "\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	describe := func(accept string) string {
		return "DESCRIBE " + target + " RTSP/1.0\r\nCSeq: 8\r\nAccept: " + accept + "\r\n\r\n"
	}
	result := func(body string) string {
		return "RTSP/1.0 200 OK\r\nCSeq: 8\r\nContent-Base: rtsp://fixture.invalid/live/\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nContent-Type: application/sdp\r\n\r\n" + body
	}
	handler := referenceTCPHandler(t, "rtsp")
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{
		{publish(sdp, "1"), "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"},
	})
	updated := strings.Replace(sdp, "s=Fixture", "s=Updated description", 1)
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{
		{describe("application/sdp"), result(sdp)},
		{describe("application/sdp;q=0, */*;q=1"), "RTSP/1.0 406 Not Acceptable\r\nCSeq: 8\r\n\r\n"},
		{publish(updated, "9"), "RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n"},
		{publish("invalid description", "10"), "RTSP/1.0 400 Bad Request\r\nCSeq: 10\r\n\r\n"},
	})
	requireReferenceTCPHandler(t, handler, map[string]interface{}{"headers": []any{"content-type: text/plain"}}, []referenceExchange{
		{describe("application/*"), result(updated)},
	})
	requireReferenceTCP(t, "rtsp", nil, []referenceExchange{
		{describe("application/sdp"), "RTSP/1.0 404 Not Found\r\nCSeq: 8\r\n\r\n"},
	})
}

func TestRTSPPublicationCapacity(t *testing.T) {
	const sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n"
	var exchanges []referenceExchange
	announce := func(index int, status string) {
		target := "rtsp://fixture.invalid/presentation/" + strconv.Itoa(index)
		exchanges = append(exchanges, referenceExchange{
			"ANNOUNCE " + target + " RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(sdp)) + "\r\n\r\n" + sdp,
			"RTSP/1.0 " + status + "\r\nCSeq: 1\r\n\r\n",
		})
	}
	for index := range rtspMaxPresentations {
		announce(index, "200 OK")
	}
	announce(rtspMaxPresentations, "503 Service Unavailable")
	announce(0, "200 OK")
	requireReferenceTCP(t, "rtsp", nil, exchanges)
}

func TestRTSPSetupPublishedTracks(t *testing.T) {
	const uri = "rtsp://fixture.invalid/live"
	const body = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=control:*\r\nm=audio 0 RTP/AVP 0\r\na=control:stream/audio\r\nm=video 0 RTP/AVP 26\r\na=control:stream/video\r\n"
	handler := referenceTCPHandler(t, "rtsp")
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{{
		"ANNOUNCE " + uri + " RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body,
		"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n",
	}})
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	}()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	setup := func(track, offers, id, seq, want string) map[string]string {
		t.Helper()
		headers := "CSeq: " + seq + "\r\nTransport: " + offers + "\r\n"
		if id != "" {
			headers += "Session: " + id + "\r\n"
		}
		if _, err := io.WriteString(client, "SETUP "+uri+track+" RTSP/1.0\r\n"+headers+"\r\n"); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "RTSP/1.0 "+want+"\r\n" {
			t.Fatalf("SETUP %s: %q, %v", track, line, err)
		}
		reply := make(map[string]string)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
			key, value, _ := strings.Cut(strings.TrimSpace(line), ": ")
			reply[key] = value
		}
		if reply["CSeq"] != seq {
			t.Fatalf("CSeq = %q, want %q", reply["CSeq"], seq)
		}
		return reply
	}
	const udp = "RTP/AVP;unicast;client_port=5000-5001"
	const tcp = "RTP/AVP/TCP;unicast"
	setup("/stream/missing", tcp, "", "2", "404 Not Found")
	first := setup("/stream/audio", udp+", "+tcp+";interleaved=3-4", "", "3", "200 OK")
	id := first["Session"]
	if !validRTSPToken(id) || first["Transport"] != tcp+";interleaved=3-4" {
		t.Fatalf("first track transport: %v", first)
	}
	setup("/stream/video", tcp, "unknown", "4", "454 Session Not Found")
	setup("/stream/video", tcp+";interleaved=4-5", id, "5", "461 Unsupported Transport")
	second := setup("/stream/video", tcp, id, "6", "200 OK")
	if second["Session"] != id || second["Transport"] != tcp+";interleaved=0-1" {
		t.Fatalf("second track transport: %v", second)
	}
	teardown := func(target, seq, status string) referenceExchange {
		return referenceExchange{
			"TEARDOWN " + uri + target + " RTSP/1.0\r\nCSeq: " + seq + "\r\nSession: " + id + "\r\n\r\n",
			"RTSP/1.0 " + status + "\r\nCSeq: " + seq + "\r\n\r\n",
		}
	}
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{
		{"OPTIONS * RTSP/1.0\r\nCSeq: 14\r\nSession: " + id + "\r\n\r\n", "RTSP/1.0 200 OK\r\nCSeq: 14\r\nPublic: " + rtspPublic + "\r\n\r\n"},
		teardown("/stream/missing", "7", "404 Not Found"),
		teardown("/stream/audio", "8", "200 OK"),
	})
	reused := setup("/stream/audio", tcp+";interleaved=3-4", id, "9", "200 OK")
	if reused["Session"] != id {
		t.Fatalf("released track changed the session: %v", reused)
	}
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{
		teardown("/", "10", "200 OK"),
		teardown("/", "11", "454 Session Not Found"),
	})
	setup("/stream/audio", tcp, id, "12", "454 Session Not Found")
	replacement := setup("/stream/audio", tcp+";interleaved=0-1", "", "13", "200 OK")
	if replacement["Session"] == id || replacement["Transport"] != tcp+";interleaved=0-1" {
		t.Fatalf("aggregate teardown did not release session and channels: %v", replacement)
	}
	client.Close()
	<-done
	requireReferenceTCPHandler(t, handler, nil, []referenceExchange{
		{"OPTIONS * RTSP/1.0\r\nCSeq: 15\r\nSession: " + replacement["Session"] + "\r\n\r\n", "RTSP/1.0 454 Session Not Found\r\nCSeq: 15\r\n\r\n"},
	})
}

func TestRTSPRelaysInterleavedMedia(t *testing.T) {
	const uri = "rtsp://fixture.invalid/live"
	const sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=control:*\r\nm=audio 0 RTP/AVP 0\r\na=control:audio\r\n"
	handler := referenceTCPHandler(t, "rtsp")
	connect := func() (net.Conn, *bufio.Reader) {
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		client.SetDeadline(time.Now().Add(2 * time.Second))
		go handler(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
		return client, bufio.NewReader(client)
	}
	control := func(conn net.Conn, reader *bufio.Reader, method, path, headers, body, status string) string {
		t.Helper()
		if _, err := io.WriteString(conn, method+" "+uri+path+" RTSP/1.0\r\nCSeq: 1\r\n"+headers+"\r\n"+body); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "RTSP/1.0 "+status+"\r\n" {
			t.Fatalf("%s returned %q (%v), want %s", method, line, err, status)
		}
		var id string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				return id
			}
			if value, ok := strings.CutPrefix(line, "Session: "); ok {
				id = strings.TrimSpace(value)
			}
		}
	}
	pub, pubReader := connect()
	sub, subReader := connect()
	control(pub, pubReader, "ANNOUNCE", "", "Content-Type: application/sdp\r\nContent-Length: "+strconv.Itoa(len(sdp))+"\r\n", sdp, "200 OK")
	pubID := control(pub, pubReader, "SETUP", "/audio", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=\"RECORD\"\r\n", "", "200 OK")
	subID := control(sub, subReader, "SETUP", "/audio", "Transport: RTP/AVP/TCP;unicast;interleaved=8-9\r\n", "", "200 OK")
	control(sub, subReader, "RECORD", "/", "Session: "+subID+"\r\n", "", "455 Method Not Valid in This State")
	control(pub, pubReader, "RECORD", "/", "Session: "+pubID+"\r\n", "", "200 OK")
	control(sub, subReader, "PLAY", "/", "Session: "+subID+"\r\nRange: npt=4-5\r\n", "", "457 Invalid Range")
	control(sub, subReader, "PLAY", "/", "Session: "+subID+"\r\n", "", "200 OK")
	for _, packet := range []string{
		"$\x00\x00\x0d\x80\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\xff",
		"$\x01\x00\x08\x80\xc9\x00\x01\x00\x00\x00\x01",
	} {
		if _, err := io.WriteString(pub, packet); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(packet))
		if _, err := io.ReadFull(subReader, got); err != nil || byte(packet[1])+8 != got[1] || string(got[2:]) != packet[2:] {
			t.Fatalf("interleaved packet %x (%v), source %x", got, err, packet)
		}
	}
	const feedback = "$\x09\x00\x08\x80\xc9\x00\x01\x00\x00\x00\x02"
	if _, err := io.WriteString(sub, feedback); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(feedback))
	if _, err := io.ReadFull(pubReader, got); err != nil || got[1] != 1 || string(got[2:]) != feedback[2:] {
		t.Fatalf("RTCP feedback %x (%v), source %x", got, err, feedback)
	}
	control(sub, subReader, "TEARDOWN", "/", "Session: "+subID+"\r\n", "", "200 OK")
	if _, err := io.WriteString(pub, "$\x00\x00\x0d\x80\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\xff"); err != nil {
		t.Fatal(err)
	}
	control(sub, subReader, "OPTIONS", "/", "", "", "200 OK")
}

func TestReferenceRTSPRequestBounds(t *testing.T) {
	const uriPrefix = "rtsp://fixture.invalid/"
	request := func(uriLength int, headers string) string {
		uri := uriPrefix + strings.Repeat("x", uriLength-len(uriPrefix))
		return "OPTIONS " + uri + " RTSP/1.0\r\nCSeq: 1\r\n" + headers + "\r\n"
	}
	for _, tc := range []struct {
		name   string
		wire   string
		accept bool
	}{
		{"uri at limit", request(2047, ""), true},
		{"uri above limit", request(2048, ""), false},
		{"key at limit", request(30, strings.Repeat("x", 511)+": value\r\n"), true},
		{"key above limit", request(30, strings.Repeat("x", 512)+": value\r\n"), false},
		{"value at limit", request(30, "User-Agent:  "+strings.Repeat("x", 2047)+"\r\n"), true},
		{"value above limit", request(30, "User-Agent: "+strings.Repeat("x", 2048)+"\r\n"), false},
		{"leading tab is excluded from value limit", request(30, "User-Agent:\t"+strings.Repeat("x", 2047)+"\r\n"), true},
		{"255 fields", request(30, strings.Repeat("X-Fixture: "+strings.Repeat("x", 40)+"\r\n", 254)), true},
		{"256 fields", request(30, strings.Repeat("X-Fixture: "+strings.Repeat("x", 40)+"\r\n", 255)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readRTSPRequest(bufio.NewReader(strings.NewReader(tc.wire)))
			if (err == nil) != tc.accept {
				t.Fatalf("readRTSPRequest error = %v, want acceptance %v", err, tc.accept)
			}
		})
	}
}

func TestReferenceRTSPAnnounceBodyLimit(t *testing.T) {
	const limit = 128 * 1024
	const sdp = "v=0\r\no=fixture 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n"
	const label = "a=x-fixture:"
	const response = "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"
	for _, tc := range []struct {
		name string
		size int
		body string
		want string
	}{
		{"at limit", limit, sdp + label + strings.Repeat("x", limit-len(sdp)-len(label)-2) + "\r\n", response},
		{"above limit", limit + 1, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, stop := startRound6Server(t, round6Case{Handler: "rtsp"})
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			header := "ANNOUNCE rtsp://fixture.invalid/live RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(tc.size) + "\r\n\r\n"
			if _, err := io.WriteString(conn, header+tc.body); err != nil {
				t.Fatal(err)
			}
			var reply []byte
			var err error
			if tc.want == "" {
				reply, err = io.ReadAll(conn)
			} else {
				reply = make([]byte, len(tc.want))
				_, err = io.ReadFull(conn, reply)
			}
			if err != nil || string(reply) != tc.want {
				t.Fatalf("ANNOUNCE response = %q (%v), want %q", reply, err, tc.want)
			}
		})
	}
}

func TestRTSPAnnounceTrackEvents(t *testing.T) {
	const session = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Fixture\r\nt=0 0\r\n"
	const dynamic = "m=video 0 RTP/AVP 96\r\n"
	for _, tc := range []struct {
		name, path, tracks, contentType string
		announce                        bool
	}{
		{"dynamic without RTP map", "/live", dynamic, "application/sdp", false},
		{"invalid later media", "/live", dynamic + "a=rtpmap:96 H264/90000\r\nm=audio 0 RTP/AVP 112\r\n", "application/sdp", false},
		{"mapping for an undeclared payload", "/live", dynamic + "a=rtpmap:97 H264/90000\r\n", "application/sdp", false},
		{"all mappings in any order", "/live", "m=audio 0 RTP/AVP 0 96 97\r\na=rtpmap:97 L16/16000/2\r\na=rtpmap:96 L8/8000\r\n", "application/sdp", true},
		{"later format missing its mapping", "/live", "m=audio 0 RTP/AVP 0 96\r\n", "application/sdp", false},
		{"duplicate mapping", "/live", dynamic + "a=rtpmap:96 H264/90000\r\na=rtpmap:96 H264/90000\r\n", "application/sdp", false},
		{"mapping belongs to another media section", "/live", dynamic + "a=rtpmap:96 H264/90000\r\n" + dynamic, "application/sdp", false},
		{"reserved payload number", "/live", "m=video 0 RTP/AVP 72\r\na=rtpmap:72 H264/90000\r\n", "application/sdp", false},
		{"out-of-range RTP payload", "/live", "m=video 0 RTP/AVP 128\r\na=rtpmap:128 H264/90000\r\n", "application/sdp", false},
		{"zero clock rate", "/live", dynamic + "a=rtpmap:96 H264/0\r\n", "application/sdp", false},
		{"zero channels", "/live", "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/16000/0\r\n", "application/sdp", false},
		{"malformed clock rate", "/live", dynamic + "a=rtpmap:96 PRIVATE/no-rate\r\n", "application/sdp", false},
		{"static payload", "/live", "m=audio 0 RTP/AVP 0\r\n", "application/sdp", true},
		{"missing media path", "", dynamic + "a=rtpmap:96 H264/90000\r\n", "application/sdp", false},
		{"content type trailing space", "/live", "m=audio 0 RTP/AVP 0\r\n", "application/sdp ", true},
		{"content type leading tab", "/live", "m=audio 0 RTP/AVP 0\r\n", "\tapplication/sdp", true},
		{"content type case and parameters", "/live", "m=audio 0 RTP/AVP 0\r\n", "Application/SDP; charset=UTF-8", true},
		{"malformed content type", "/live", "m=audio 0 RTP/AVP 0\r\n", "application/sdp; charset", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&output)
			logger.SetFormatter(&logrus.JSONFormatter{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				newRTSPHandler()(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
					BindInfo: &BindInfo{}, Log: logrus.NewEntry(logger),
				}})
			}()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			body := session + tc.tracks
			request := "ANNOUNCE rtsp://fixture.invalid" + tc.path + " RTSP/1.0\r\nCSeq: 1\r\n" +
				"Content-Type: " + tc.contentType + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}
			status := "400 Bad Request"
			if tc.announce {
				status = "200 OK"
			} else if tc.name == "malformed content type" {
				status = "415 Unsupported Media Type"
			}
			want := "RTSP/1.0 " + status + "\r\nCSeq: 1\r\n\r\n"
			reply := make([]byte, len(want))
			if _, err := io.ReadFull(client, reply); err != nil || string(reply) != want {
				t.Fatalf("ANNOUNCE reply %q (%v)", reply, err)
			}
			client.Close()
			<-done
			var events []string
			decoder := json.NewDecoder(&output)
			for decoder.More() {
				var event struct{ Msg string }
				if err := decoder.Decode(&event); err != nil {
					t.Fatal(err)
				}
				events = append(events, event.Msg)
			}
			expected := []string{"session opened"}
			if tc.announce {
				expected = append(expected, "announce request")
			}
			expected = append(expected, "session closed")
			if !slices.Equal(events, expected) {
				t.Fatalf("ANNOUNCE events %q, want %q", events, expected)
			}
		})
	}
}

func TestReferenceICAPSessions(t *testing.T) {
	requireReferenceTextSessions(t, "fixtures/reference-icap.json", serveICAP, 1344, nil)
}

func requireReferenceTextSessions(t *testing.T, path string, serve func(*SessionConnection) error, port uint16, expectedReply func(string) string) {
	t.Helper()
	type textStep struct {
		Send    string
		Receive []string
		Closed  bool
	}
	var fixture struct {
		Listeners map[string]map[string]interface{}
		Cases     []struct {
			Name, Listener string
			Steps          []textStep
			SimSteps     []textStep `json:"sim_steps"`
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			go serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
				BindInfo: &BindInfo{Port: port, Params: fixture.Listeners[test.Listener]},
			}})
			steps := test.Steps
			if test.SimSteps != nil {
				steps = test.SimSteps
			}
			for _, step := range steps {
				if _, err := io.WriteString(client, step.Send); err != nil {
					t.Fatal(err)
				}
				for _, want := range step.Receive {
					if expectedReply != nil {
						want = expectedReply(want)
					}
					want = strings.ReplaceAll(want, "{port}", strconv.Itoa(int(port)))
					reply := make([]byte, len(want))
					if _, err := io.ReadFull(client, reply); err != nil || string(reply) != want {
						t.Fatalf("got %q (%v), want %q", reply, err, want)
					}
				}
				if step.Closed {
					if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatalf("expected close, got %d byte(s) and %v", n, err)
					}
				} else if len(step.Receive) == 0 {
					if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
						t.Fatal(err)
					}
					if n, err := client.Read(make([]byte, 1)); n != 0 || !os.IsTimeout(err) {
						t.Fatalf("expected an open, silent connection, got %d byte(s) and %v", n, err)
					}
					if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
