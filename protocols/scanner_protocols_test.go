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

func testSessionPair(t *testing.T, proto string, fn func(*SessionConnection) error) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	sc := &SessionConnection{
		Conn: server,
		ConfigInfo: &ConfigInfo{
			BindInfo: &BindInfo{Handler: proto, Params: map[string]interface{}{}},
			Log:      logrus.NewEntry(logger),
		},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- fn(sc)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, errCh
}

func TestNewScannerProtocols(t *testing.T) {
	t.Run("rsync", func(t *testing.T) {
		c, _ := testSessionPair(t, "rsync", Rsync)
		r := bufio.NewReader(c)
		banner, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(banner, "@RSYNCD: 31.0") {
			t.Fatalf("bad rsync banner: %q (%v)", banner, err)
		}
		_, _ = c.Write([]byte("@RSYNCD: 31.0\n#list\n"))
		out, _ := io.ReadAll(r)
		if !strings.Contains(string(out), "backup") || !strings.Contains(string(out), "@RSYNCD: EXIT") {
			t.Fatalf("unexpected rsync list: %q", string(out))
		}
	})

	t.Run("zookeeper", func(t *testing.T) {
		c, _ := testSessionPair(t, "zookeeper", ZooKeeper)
		_, _ = c.Write([]byte("ruok"))
		buf := make([]byte, 32)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "imok" {
			t.Fatalf("expected imok, got %q (%v)", string(buf[:n]), err)
		}
	})

	t.Run("jdwp", func(t *testing.T) {
		c, _ := testSessionPair(t, "jdwp", JDWP)
		_, _ = c.Write([]byte("JDWP-Handshake"))
		hs := make([]byte, 14)
		if _, err := io.ReadFull(c, hs); err != nil || string(hs) != "JDWP-Handshake" {
			t.Fatalf("bad jdwp handshake: %q (%v)", string(hs), err)
		}
		// Send VirtualMachine.Version (len=11, id=1, flags=0, cmdset=1, cmd=1)
		req := []byte{0, 0, 0, 11, 0, 0, 0, 1, 0, 1, 1}
		_, _ = c.Write(req)
		hdr := make([]byte, 11)
		if _, err := io.ReadFull(c, hdr); err != nil || hdr[8] != 0x80 {
			t.Fatalf("bad jdwp reply hdr: %x (%v)", hdr, err)
		}
		pktLen := binary.BigEndian.Uint32(hdr[0:4])
		body := make([]byte, pktLen-11)
		_, _ = io.ReadFull(c, body)
		if !strings.Contains(string(body), "OpenJDK") {
			t.Fatalf("expected OpenJDK in jdwp version reply, got %q", string(body))
		}
	})

	t.Run("ajp13", func(t *testing.T) {
		c, _ := testSessionPair(t, "ajp", AJP13)
		// CPing: 0x1234 0x0001 0x0a
		_, _ = c.Write([]byte{0x12, 0x34, 0x00, 0x01, 0x0a})
		resp := make([]byte, 5)
		if _, err := io.ReadFull(c, resp); err != nil || resp[0] != 0x41 || resp[1] != 0x42 || resp[4] != 0x09 {
			t.Fatalf("expected CPong, got %x (%v)", resp, err)
		}
	})

	t.Run("bgp", func(t *testing.T) {
		c, _ := testSessionPair(t, "bgp", BGP)
		open := make([]byte, 29)
		for i := 0; i < 16; i++ {
			open[i] = 0xff
		}
		binary.BigEndian.PutUint16(open[16:18], 29)
		open[18] = 1
		open[19] = 4
		binary.BigEndian.PutUint16(open[20:22], 65002)
		binary.BigEndian.PutUint16(open[22:24], 90)
		copy(open[24:28], net.IPv4(192, 0, 2, 10).To4())
		_, _ = c.Write(open)

		resp := make([]byte, 48)
		if _, err := io.ReadFull(c, resp); err != nil || resp[18] != 1 || resp[29+18] != 4 {
			t.Fatalf("expected BGP OPEN+KEEPALIVE, got %x (%v)", resp, err)
		}
	})

	t.Run("socks4", func(t *testing.T) {
		c, _ := testSessionPair(t, "socks4", SOCKS4)
		req := []byte{0x04, 0x01, 0x00, 0x50, 93, 184, 216, 34, 0x00}
		_, _ = c.Write(req)
		reply := make([]byte, 8)
		if _, err := io.ReadFull(c, reply); err != nil || reply[0] != 0x00 || reply[1] != 0x5a {
			t.Fatalf("expected SOCKS4 granted reply, got %x (%v)", reply, err)
		}
	})

	t.Run("kafka", func(t *testing.T) {
		c, _ := testSessionPair(t, "kafka", Kafka)
		// ApiVersions v0 request: len=10, api_key=18, api_ver=0, corr_id=7, client_id=""(len=0)
		req := make([]byte, 14)
		binary.BigEndian.PutUint32(req[0:4], 10)
		binary.BigEndian.PutUint16(req[4:6], 18)
		binary.BigEndian.PutUint16(req[6:8], 0)
		binary.BigEndian.PutUint32(req[8:12], 7)
		binary.BigEndian.PutUint16(req[12:14], 0)
		_, _ = c.Write(req)

		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			t.Fatalf("kafka read len: %v", err)
		}
		resp := make([]byte, binary.BigEndian.Uint32(lenBuf))
		_, _ = io.ReadFull(c, resp)
		if binary.BigEndian.Uint32(resp[0:4]) != 7 || binary.BigEndian.Uint16(resp[4:6]) != 0 {
			t.Fatalf("unexpected kafka ApiVersions response: %x", resp)
		}
	})

	t.Run("docker_and_etcd", func(t *testing.T) {
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		ci := &ConfigInfo{BindInfo: &BindInfo{Handler: "docker", Params: map[string]interface{}{}}, Log: logrus.NewEntry(logger)}
		dsrv := httptest.NewServer(DockerAPI(ci))
		defer dsrv.Close()
		resp, err := http.Get(dsrv.URL + "/version")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("docker /version failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "ApiVersion") {
			t.Fatalf("unexpected docker /version: %s", body)
		}

		esrv := httptest.NewServer(EtcdAPI(ci))
		defer esrv.Close()
		resp, err = http.Get(esrv.URL + "/version")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("etcd /version failed: %v", err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "etcdserver") {
			t.Fatalf("unexpected etcd /version: %s", body)
		}
	})

	t.Run("tftp", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		client, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		logger := logrus.New()
		logger.SetOutput(io.Discard)
		ci := &ConfigInfo{BindInfo: &BindInfo{Handler: "tftp"}, Log: logrus.NewEntry(logger)}
		uc := NewUDPConnection(pc, client.LocalAddr(), ci)

		rrq := append([]byte{0x00, 0x01}, []byte("test\x00octet\x00")...)
		if err := TFTP(uc, rrq); err != nil {
			t.Fatalf("TFTP RRQ: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 512)
		n, _, err := client.ReadFrom(buf)
		if err != nil || binary.BigEndian.Uint16(buf[:2]) != 3 {
			t.Fatalf("expected TFTP DATA packet, got %x (%v)", buf[:n], err)
		}
	})

	t.Run("activemq", func(t *testing.T) {
		c, _ := testSessionPair(t, "activemq", ActiveMQ)
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "ActiveMQ") {
			t.Fatalf("expected ActiveMQ OpenWire greeting, got %q (%v)", string(buf[:n]), err)
		}
	})

	t.Run("dubbo", func(t *testing.T) {
		c, _ := testSessionPair(t, "dubbo", Dubbo)
		_, _ = c.Write([]byte("ls\r\n"))
		buf := make([]byte, 256)
		n, err := c.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), "UserService") {
			t.Fatalf("expected Dubbo service list, got %q (%v)", string(buf[:n]), err)
		}
	})

	t.Run("nats", func(t *testing.T) {
		c, _ := testSessionPair(t, "nats", NATS)
		r := bufio.NewReader(c)
		info, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(info, "INFO ") {
			t.Fatalf("expected NATS INFO, got %q (%v)", info, err)
		}
		_, _ = c.Write([]byte("PING\r\n"))
		pong, _ := r.ReadString('\n')
		if strings.TrimSpace(pong) != "PONG" {
			t.Fatalf("expected PONG, got %q", pong)
		}
	})

	t.Run("kerberos", func(t *testing.T) {
		c, _ := testSessionPair(t, "kerberos", Kerberos)
		_, _ = c.Write([]byte{0, 0, 0, 4, 0x6a, 0x02, 0x05, 0x00})
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			t.Fatalf("kerberos read len: %v", err)
		}
		resp := make([]byte, binary.BigEndian.Uint32(lenBuf))
		_, _ = io.ReadFull(c, resp)
		if len(resp) < 10 || resp[0] != 0x7e { // APPLICATION 30 (KRB-ERROR)
			t.Fatalf("expected KRB-ERROR (0x7e), got %x", resp)
		}
	})

	t.Run("irc_and_nntp", func(t *testing.T) {
		ic, _ := testSessionPair(t, "irc", IRC)
		ir := bufio.NewReader(ic)
		_, _ = ir.ReadString('\n')
		_, _ = ic.Write([]byte("NICK bot\r\nUSER bot 0 * :Bot\r\nQUIT\r\n"))
		line, _ := ir.ReadString('\n')
		if !strings.Contains(line, " 001 ") {
			t.Fatalf("expected IRC 001 welcome, got %q", line)
		}

		nc, _ := testSessionPair(t, "nntp", NNTP)
		nr := bufio.NewReader(nc)
		banner, _ := nr.ReadString('\n')
		if !strings.HasPrefix(banner, "200 ") {
			t.Fatalf("expected NNTP 200 banner, got %q", banner)
		}
	})

	t.Run("winrm_ipp_kubelet_clickhouse_consul", func(t *testing.T) {
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		ci := &ConfigInfo{BindInfo: &BindInfo{Handler: "test", Params: map[string]interface{}{}}, Log: logrus.NewEntry(logger)}

		ws := httptest.NewServer(WinRM(ci))
		defer ws.Close()
		resp, err := http.Post(ws.URL+"/wsman", "application/soap+xml", nil)
		if err != nil || resp.StatusCode != 401 {
			t.Fatalf("winrm expected 401, got %v", err)
		}
		resp.Body.Close()

		is := httptest.NewServer(IPP(ci))
		defer is.Close()
		resp, err = http.Post(is.URL+"/ipp/print", "application/ipp", strings.NewReader("\x02\x00\x00\x0b\x00\x00\x00\x01\x03"))
		if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/ipp" {
			t.Fatalf("ipp failed: %v", err)
		}
		resp.Body.Close()

		ks := httptest.NewServer(KubeletAPI(ci))
		defer ks.Close()
		resp, err = http.Get(ks.URL + "/pods")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("kubelet failed: %v", err)
		}
		resp.Body.Close()

		cs := httptest.NewServer(ClickHouseHTTP(ci))
		defer cs.Close()
		resp, err = http.Get(cs.URL + "/?query=SELECT+version()")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("clickhouse failed: %v", err)
		}
		resp.Body.Close()

		co := httptest.NewServer(ConsulAPI(ci))
		defer co.Close()
		resp, err = http.Get(co.URL + "/v1/agent/self")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("consul failed: %v", err)
		}
		resp.Body.Close()
	})
}
