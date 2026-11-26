package httpclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	NetworkTypeTCP = "tcp"
	NetworkTypeUDP = "udp"
	NetworkTypeTLS = "tls"
)

func init() {
	proxy.RegisterDialerType("http", newHTTPProxy)
	proxy.RegisterDialerType("https", newHTTPProxy)
}

type DefaultTCPDialer struct {
	Timeout time.Duration
}

func (tcpDialer *DefaultTCPDialer) Dial(network, addr string) (c net.Conn, err error) {
	c, err = net.DialTimeout(network, addr, tcpDialer.Timeout)
	return
}

var defaultTlsConfig = &tls.Config{
	MinVersion:         tls.VersionTLS10,
	InsecureSkipVerify: true,
}

type DefaultTLSDialer struct {
	Timeout time.Duration
}

func (tlsDialer *DefaultTLSDialer) Dial(network, addr string) (c net.Conn, err error) {
	c, err = tls.DialWithDialer(&net.Dialer{Timeout: tlsDialer.Timeout}, NetworkTypeTCP, addr, defaultTlsConfig)
	return
}

// httpProxy is a HTTP/HTTPS connect proxy.
type httpProxy struct {
	host     string
	haveAuth bool
	username string
	password string
	forward  proxy.Dialer
}

func newHTTPProxy(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(httpProxy)
	s.host = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.haveAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}

	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the https client connection.
	c, err := s.forward.Dial(NetworkTypeTCP, s.host)
	if err != nil {
		return nil, err
	}

	// HACK. http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	req.Close = false
	if s.haveAuth {
		req.SetBasicAuth(s.username, s.password)
	}
	//req.Header.Set("User-Agent", "Powerby Gota")

	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.Close()
		err = fmt.Errorf("Connect server using proxy error, StatusCode [%d]", resp.StatusCode)
		return nil, err
	}

	return c, nil
}

// httpsDialer
type httpsDialer struct{}

// HTTPSDialer is a https proxy: one that makes network connections on tls.
var HttpsDialer = httpsDialer{}

// TlsConfig configures TLS connections to HTTPS proxies.
// Set it before starting concurrent requests.
var TlsConfig = &tls.Config{MinVersion: tls.VersionTLS10}

func (d httpsDialer) Dial(network, addr string) (c net.Conn, err error) {
	if !strings.Contains(addr, ":") {
		// 默认端口
		addr = addr + ":443"
	}
	c, err = tls.Dial(NetworkTypeTCP, addr, TlsConfig)
	if err != nil {
		fmt.Println(err)
	}
	return
}

func newSocks5ProxyDialer(network string, proxyAddr *url.URL, timeout time.Duration) (proxy.Dialer, error) {
	var auth *proxy.Auth
	if proxyAddr.User != nil && len(proxyAddr.User.Username()) > 0 {
		password, _ := proxyAddr.User.Password()
		auth = &proxy.Auth{
			User:     proxyAddr.User.Username(),
			Password: password,
		}
	}

	dialer, err := proxy.SOCKS5(network, proxyAddr.Host, auth, &net.Dialer{
		Timeout:   timeout,
		KeepAlive: timeout,
	})
	return dialer, err
}

func newTCPProxyDialer(proxyAddr *url.URL, timeout time.Duration) (proxy.Dialer, error) {
	switch strings.ToLower(proxyAddr.Scheme) {
	case "socks5":
		return newSocks5ProxyDialer(NetworkTypeTCP, proxyAddr, timeout)
	case "http":
		return proxy.FromURL(proxyAddr, &DefaultTCPDialer{Timeout: timeout})
	case "https":
		return proxy.FromURL(proxyAddr, HttpsDialer)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyAddr.Scheme)
	}
}

// GetTCPConnWithProxy 新建连接。 network可以是tcp，udp，tls。  附：udp不要超时设置； 获取tcp连接，如果有proxy的话，则从proxy建立连接
func GetTCPConnWithProxy(network, addr string, proxyAddr *url.URL, timeout time.Duration) (conn net.Conn, err error) {
	var dialer proxy.Dialer

	if len(network) == 0 {
		network = NetworkTypeTCP
	}

	if network == NetworkTypeUDP {
		if proxyAddr != nil { // 内置的proxy不支持udp协议
			return nil, errors.New("udp not implement")
		}
		dialer = &DefaultTCPDialer{}
		conn, err = dialer.Dial(network, addr)
	} else if network == NetworkTypeTLS {
		if proxyAddr != nil {
			dialer, err = newTCPProxyDialer(proxyAddr, timeout)
			if err != nil {
				return nil, err
			}
			conn, err = dialer.Dial(NetworkTypeTCP, addr)
			if err == nil {
				conn = tls.Client(conn, defaultTlsConfig) // 再套一层tls
			}
		} else {
			dialer = &DefaultTLSDialer{
				Timeout: timeout,
			}
			conn, err = dialer.Dial(network, addr)
		}

	} else { // tcp
		dialer = &DefaultTCPDialer{
			Timeout: timeout,
		}
		if proxyAddr != nil {
			dialer, err = newTCPProxyDialer(proxyAddr, timeout)
			if err != nil {
				return nil, err
			}
		}
		conn, err = dialer.Dial(network, addr)
	}

	if err == nil {
		conn.SetDeadline(time.Now().Add(timeout))
	} else {
		if strings.Contains(err.Error(), "authentication failed") {

		}
		if strings.Contains(err.Error(), "unknown code") {
			panic(errors.New(fmt.Sprintf("proxy error: %v", err.Error())))
		}
	}
	return
}

func GetTCPConn(addr string, argv ...interface{}) (conn net.Conn, err error) {
	timeout := time.Second * 15
	if len(argv) > 0 {
		timeout = argv[0].(time.Duration)
	}
	return GetTCPConnWithProxy(NetworkTypeTCP, addr, defaultProxy, timeout)
}

func GetUDPConn(addr string, argv ...interface{}) (conn net.Conn, err error) {
	timeout := time.Second * 15
	if len(argv) > 0 {
		timeout = argv[0].(time.Duration)
	}
	return GetTCPConnWithProxy(NetworkTypeUDP, addr, defaultProxy, timeout)
}

func GetTLSConn(addr string, argv ...interface{}) (conn net.Conn, err error) {
	timeout := time.Second * 15
	if len(argv) > 0 {
		timeout = argv[0].(time.Duration)
	}
	return GetTCPConnWithProxy(NetworkTypeTLS, addr, defaultProxy, timeout)
}

func GetConn(baseprotocol string, addr string, argv ...interface{}) (conn net.Conn, err error) {
	timeout := time.Second * 15
	if len(argv) > 0 {
		timeout = argv[0].(time.Duration)
	}
	return GetTCPConnWithProxy(baseprotocol, addr, defaultProxy, timeout)
}
