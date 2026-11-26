package protocols

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestExtendedProtocolsBatch(t *testing.T) {
	t.Run("epmd", func(t *testing.T) {
		c, _ := testSessionPair(t, "epmd", EPMD)
		_, _ = c.Write([]byte{0x00, 0x01, 0x6e})
		buf := make([]byte, 128)
		n, err := c.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "rabbit") {
			t.Fatalf("unexpected epmd reply: %q (%v)", string(buf[:n]), err)
		}
	})

	t.Run("jetdirect_x11_opcua_svn_stomp_gearman_beanstalkd", func(t *testing.T) {
		jc, _ := testSessionPair(t, "jetdirect", JetDirect)
		_, _ = jc.Write([]byte("@PJL INFO ID\r\n"))
		buf := make([]byte, 128)
		n, _ := jc.Read(buf)
		if !strings.Contains(string(buf[:n]), "LaserJet") {
			t.Fatalf("unexpected jetdirect: %q", string(buf[:n]))
		}

		xc, _ := testSessionPair(t, "x11", X11)
		_, _ = xc.Write([]byte{'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		n, _ = xc.Read(buf)
		if n < 8 || buf[0] != 0 || !strings.Contains(string(buf[:n]), "No protocol") {
			t.Fatalf("unexpected x11: %x", buf[:n])
		}

		oc, _ := testSessionPair(t, "opcua", OPCUA)
		_, _ = oc.Write([]byte{'H', 'E', 'L', 'F', 8, 0, 0, 0})
		n, _ = oc.Read(buf)
		if n < 4 || string(buf[:4]) != "ACKF" {
			t.Fatalf("unexpected opcua: %x", buf[:n])
		}

		sc, _ := testSessionPair(t, "svn", SVNDaemon)
		line, _ := bufio.NewReader(sc).ReadString('\n')
		if !strings.Contains(line, "edit-pipeline") {
			t.Fatalf("unexpected svn: %q", line)
		}

		stc, _ := testSessionPair(t, "stomp", STOMP)
		_, _ = stc.Write([]byte("CONNECT\naccept-version:1.2\n\n\x00"))
		n, _ = stc.Read(buf)
		if !strings.Contains(string(buf[:n]), "CONNECTED") {
			t.Fatalf("unexpected stomp: %q", string(buf[:n]))
		}

		gc, _ := testSessionPair(t, "gearman", Gearman)
		_, _ = gc.Write([]byte("version\n"))
		n, _ = gc.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "OK ") {
			t.Fatalf("unexpected gearman: %q", string(buf[:n]))
		}

		bc, _ := testSessionPair(t, "beanstalkd", Beanstalkd)
		_, _ = bc.Write([]byte("stats\r\n"))
		n, _ = bc.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "OK ") {
			t.Fatalf("unexpected beanstalkd: %q", string(buf[:n]))
		}
	})

	t.Run("neo4j_bolt_firebird_db2_fastcgi_grpc_xmpp_bitcoin", func(t *testing.T) {
		buf := make([]byte, 256)

		nb, _ := testSessionPair(t, "neo4j-bolt", Neo4jBolt)
		_, _ = nb.Write([]byte{0x60, 0x60, 0xb0, 0x17, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0})
		n, _ := nb.Read(buf[:4])
		if n != 4 || buf[3] != 4 {
			t.Fatalf("unexpected neo4j-bolt: %x", buf[:n])
		}

		fc, _ := testSessionPair(t, "fastcgi", FastCGI)
		_, _ = fc.Write([]byte{1, 9, 0, 0, 0, 0, 0, 0})
		n, _ = fc.Read(buf)
		if n < 8 || buf[1] != 10 {
			t.Fatalf("unexpected fastcgi: %x", buf[:n])
		}

		gr, _ := testSessionPair(t, "grpc", GRPC)
		_, _ = gr.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
		n, _ = gr.Read(buf)
		if n < 9 || buf[3] != 0x04 {
			t.Fatalf("unexpected grpc h2 settings: %x", buf[:n])
		}

		xm, _ := testSessionPair(t, "xmpp", XMPP)
		_, _ = xm.Write([]byte("<stream:stream to='example.com'>"))
		n, _ = xm.Read(buf)
		if !strings.Contains(string(buf[:n]), "stream:features") {
			t.Fatalf("unexpected xmpp: %q", string(buf[:n]))
		}

		bt, _ := testSessionPair(t, "bitcoin", Bitcoin)
		_, _ = bt.Write(buildBitcoinFrame("version", nil))
		n, _ = bt.Read(buf)
		if n < 24 || string(buf[4:11]) != "version" {
			t.Fatalf("unexpected bitcoin: %x", buf[:n])
		}
	})

	t.Run("http_data_services", func(t *testing.T) {
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		ci := &ConfigInfo{BindInfo: &BindInfo{Handler: "test", Params: map[string]interface{}{}}, Log: logrus.NewEntry(logger)}

		for _, tc := range []struct {
			h    http.Handler
			path string
			want string
		}{
			{HadoopYARN(ci), "/ws/v1/cluster/info", "resourceManagerVersion"},
			{HDFSNameNode(ci), "/jmx", "NameNodeInfo"},
			{ApacheSolr(ci), "/solr/admin/info/system", "solr-spec-version"},
			{CouchDB(ci), "/", "Welcome"},
			{Neo4jHTTP(ci), "/", "neo4j_version"},
		} {
			srv := httptest.NewServer(tc.h)
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil || resp.StatusCode != 200 {
				srv.Close()
				t.Fatalf("GET %s failed: %v", tc.path, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			srv.Close()
			if !strings.Contains(string(b), tc.want) {
				t.Fatalf("GET %s missing %q in %s", tc.path, tc.want, b)
			}
		}
	})

	t.Run("udp_ipmi_stun_radius_knx", func(t *testing.T) {
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		defer pc.Close()
		cl, _ := net.ListenPacket("udp", "127.0.0.1:0")
		defer cl.Close()
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		ci := &ConfigInfo{BindInfo: &BindInfo{Handler: "udp", Params: map[string]interface{}{}}, Log: logrus.NewEntry(logger)}
		uc := NewUDPConnection(pc, cl.LocalAddr(), ci)
		buf := make([]byte, 256)

		// IPMI ASF Ping
		_ = IPMI(uc, []byte{0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x80, 0x01, 0x00, 0x00})
		_ = cl.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := cl.ReadFrom(buf)
		if err != nil || n < 12 || buf[8] != 0x40 {
			t.Fatalf("bad ipmi pong: %x (%v)", buf[:n], err)
		}

		// STUN Binding Request
		stunReq := make([]byte, 20)
		binary.BigEndian.PutUint16(stunReq[0:2], 0x0001)
		binary.BigEndian.PutUint32(stunReq[4:8], 0x2112a442)
		_ = STUN(uc, stunReq)
		n, _, err = cl.ReadFrom(buf)
		if err != nil || binary.BigEndian.Uint16(buf[0:2]) != 0x0101 {
			t.Fatalf("bad stun response: %x (%v)", buf[:n], err)
		}

		// KNX Search Request
		_ = KNX(uc, []byte{0x06, 0x10, 0x02, 0x01, 0x00, 0x06})
		n, _, err = cl.ReadFrom(buf)
		if err != nil || binary.BigEndian.Uint16(buf[2:4]) != 0x0202 {
			t.Fatalf("bad knx response: %x (%v)", buf[:n], err)
		}
	})
}
