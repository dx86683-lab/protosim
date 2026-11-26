package protocols

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("http-proxy", HTTPProxy, 3128))
	AddProtocol(NewProtocolInfo("fastcgi", FastCGI, 9000))
	AddProtocol(NewProtocolInfo("grpc", GRPC, 50051))
	AddProtocol(NewProtocolInfo("stomp", STOMP, 61613))
	AddProtocol(NewProtocolInfo("gearman", Gearman, 4730))
	AddProtocol(NewProtocolInfo("beanstalkd", Beanstalkd, 11300))
	AddProtocol(NewProtocolInfo("git", GitDaemon, 9418))
	AddProtocol(NewProtocolInfo("svn", SVNDaemon, 3690))
	AddProtocol(NewProtocolInfo("distcc", DistCC, 3632))
}

// HTTPProxy simulates a Squid HTTP forward/CONNECT proxy (TCP 3128).
func HTTPProxy(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	reqLine, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	reqLine = strings.TrimSpace(reqLine)
	sc.LogWithRemote("http_proxy_request", sc.Conn.RemoteAddr(), logrus.Fields{"request_line": reqLine})

	resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Server: squid/6.6\r\n" +
		"Mime-Version: 1.0\r\n" +
		"Content-Type: text/html;charset=utf-8\r\n" +
		"X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0\r\n" +
		"Proxy-Authenticate: Basic realm=\"Squid proxy-caching web server\"\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	_, err = sc.Conn.Write([]byte(resp))
	return err
}

// FastCGI implements PHP-FPM FastCGI binary framing (TCP 9000).
func FastCGI(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 1 { // FCGI_VERSION_1
		return nil
	}
	recType := hdr[1]
	reqID := binary.BigEndian.Uint16(hdr[2:4])
	contentLen := int(binary.BigEndian.Uint16(hdr[4:6]))
	padLen := int(hdr[6])
	if contentLen+padLen > 0 && contentLen+padLen < 65536 {
		_, _ = io.CopyN(io.Discard, sc.Conn, int64(contentLen+padLen))
	}
	sc.LogWithRemote("fastcgi_record", sc.Conn.RemoteAddr(), logrus.Fields{
		"type": recType, "request_id": reqID, "content_len": contentLen,
	})

	switch recType {
	case 9: // FCGI_GET_VALUES -> FCGI_GET_VALUES_RESULT (10)
		var body bytes.Buffer
		writeFCGIKV(&body, "FCGI_MAX_CONNS", "100")
		writeFCGIKV(&body, "FCGI_MAX_REQS", "100")
		writeFCGIKV(&body, "FCGI_MPXS_CONNS", "0")
		resp := make([]byte, 8+body.Len())
		resp[0] = 1
		resp[1] = 10
		binary.BigEndian.PutUint16(resp[2:4], 0)
		binary.BigEndian.PutUint16(resp[4:6], uint16(body.Len()))
		copy(resp[8:], body.Bytes())
		_, err := sc.Conn.Write(resp)
		return err
	default: // FCGI_END_REQUEST (3)
		resp := []byte{1, 3, hdr[2], hdr[3], 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		_, err := sc.Conn.Write(resp)
		return err
	}
}

func writeFCGIKV(buf *bytes.Buffer, k, v string) {
	buf.WriteByte(byte(len(k)))
	buf.WriteByte(byte(len(v)))
	buf.WriteString(k)
	buf.WriteString(v)
}

// GRPC implements HTTP/2 cleartext (h2c) preface detection & SETTINGS frame reply (TCP 50051).
func GRPC(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	preface := make([]byte, 24)
	if _, err := io.ReadFull(sc.Conn, preface); err != nil {
		return err
	}
	sc.LogWithRemote("grpc_h2_preface", sc.Conn.RemoteAddr(), logrus.Fields{
		"is_h2": string(preface) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
	})
	// HTTP/2 SETTINGS frame (length=0, type=0x04, flags=0, stream=0) + SETTINGS ACK
	settings := []byte{
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
	}
	_, err := sc.Conn.Write(settings)
	return err
}

// STOMP implements STOMP 1.2 CONNECT/STOMP -> CONNECTED (TCP 61613).
func STOMP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	frame, err := r.ReadString(0x00)
	if err != nil && len(frame) == 0 {
		return err
	}
	cmd, _, _ := strings.Cut(strings.TrimSpace(frame), "\n")
	sc.LogWithRemote("stomp_frame", sc.Conn.RemoteAddr(), logrus.Fields{"command": strings.TrimSpace(cmd)})
	resp := "CONNECTED\nversion:1.2\nserver:ActiveMQ/5.18.3\nsession:ID:protosim-1\n\n\x00"
	_, err = sc.Conn.Write([]byte(resp))
	return err
}

// Gearman implements Gearman job server text protocol (TCP 4730).
func Gearman(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.ToLower(strings.TrimSpace(line))
		sc.LogWithRemote("gearman_cmd", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd})
		switch cmd {
		case "version":
			_, err = sc.Conn.Write([]byte("OK 1.1.20\n"))
		case "status":
			_, err = sc.Conn.Write([]byte("reverse\t0\t0\t1\n.\n"))
		case "workers":
			_, err = sc.Conn.Write([]byte("12 127.0.0.1 - : reverse\n.\n"))
		default:
			_, err = sc.Conn.Write([]byte("ERR unknown_command Unknown+server+command\n"))
		}
		if err != nil {
			return err
		}
	}
}

// Beanstalkd implements Beanstalkd queue text protocol (TCP 11300).
func Beanstalkd(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	r := bufio.NewReader(sc.Conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.ToLower(strings.TrimSpace(line))
		sc.LogWithRemote("beanstalkd_cmd", sc.Conn.RemoteAddr(), logrus.Fields{"command": cmd})
		switch cmd {
		case "stats":
			yaml := "---\ncurrent-jobs-ready: 0\nversion: 1.13\npid: 1001\n"
			_, err = sc.Conn.Write([]byte(fmt.Sprintf("OK %d\r\n%s\r\n", len(yaml), yaml)))
		case "list-tubes":
			yaml := "---\n- default\n"
			_, err = sc.Conn.Write([]byte(fmt.Sprintf("OK %d\r\n%s\r\n", len(yaml), yaml)))
		case "quit":
			return nil
		default:
			_, err = sc.Conn.Write([]byte("UNKNOWN_COMMAND\r\n"))
		}
		if err != nil {
			return err
		}
	}
}

// GitDaemon implements git:// pkt-line handshake (TCP 9418).
func GitDaemon(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("git_daemon_request", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:n])})
	msg := "ERR access denied or repository not exported\n"
	pkt := fmt.Sprintf("%04x%s", len(msg)+4, msg)
	_, err = sc.Conn.Write([]byte(pkt))
	return err
}

// SVNDaemon implements svn:// greeting (TCP 3690).
func SVNDaemon(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	greeting := "( success ( 2 2 ( ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) ) ) \n"
	if _, err := sc.Conn.Write([]byte(greeting)); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if n > 0 {
		sc.LogWithRemote("svn_client_response", sc.Conn.RemoteAddr(), logrus.Fields{"raw": strings.TrimSpace(string(buf[:n]))})
	}
	return err
}

// DistCC implements distcc daemon protocol (TCP 3632).
func DistCC(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("distcc_request", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:min(n, 64)])})
	_, err = sc.Conn.Write([]byte("DONE00000001STAT00000000SERR00000000SOUT00000000DOTO00000000"))
	return err
}
