package httpclient

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}

// gzip
func NewTestServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/200.html" {
			assert.Equal(t, "gzip", r.Header.Get("Accept-Encoding"), "should be equal")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`OK`))
		} else if r.URL.String() == "/404.html" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`404`))
		} else if r.URL.String() == "/500.html" {
			w.Header().Set("Test-Header", "TestValue")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`header test`))
		} else if r.URL.String() == "/https.html" {
			// 构造重定向到https的请求，并且带上原始的端口号
			w.Header().Set("Location", fmt.Sprintf("https://%s/200.html", r.Host))
			w.WriteHeader(http.StatusFound)
		} else if r.URL.String() == "/302.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/200.html", r.Host))
			w.WriteHeader(http.StatusFound)
		} else if r.URL.String() == "/302_1.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/302_2.html", r.Host))
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302_1`))
		} else if r.URL.String() == "/302_2.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/302_3.html", r.Host))
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302_2`))
		} else if r.URL.String() == "/302_3.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/302_4.html", r.Host))
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302_3`))
		} else if r.URL.String() == "/302_4.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/302_5.html", r.Host))
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302_4`))
		} else if r.URL.String() == "/302_5.html" {
			w.Header().Set("Location", fmt.Sprintf("http://%s/302_6.html", r.Host))
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302_5`))
		} else if r.URL.String() == "/302nolocation.html" {
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`302nolocation`))
		} else if r.URL.String() == "/302out.html" {
			w.Header().Set("Location", "http://baidu.com/test.html")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(`location to out`))
		} else if r.URL.String() == "/gb2312.html" {
			w.Header().Set("Content-Type", "text/html; charset=gb2312")
			w.Write([]byte("\xb0\xa1"))
		} else if r.URL.String() == "/unicode.html" {
			w.Header().Set("Content-Type", "text/html; charset=UTF-16")
			w.Write([]byte("\x55\x4a"))
		} else if r.URL.String() == "/gzip.html" {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/html")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			gz.Write([]byte("test"))
		} else if r.URL.String() == "/gzip_no_data.html" {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/html")
		} else if r.URL.String() == "/chunked.html" {
			flusher, ok := w.(http.Flusher)
			if !ok {
				panic("need flusher!")
			}
			flusher.Flush()

			w.Header().Set("Transfer-Encoding", "chunked")
			w.Header().Set("Content-Type", "application/json")
			//w.Header().Set("Content-Length", "31")
			//w.WriteHeader(http.StatusOK)
			w.Write([]byte("this is just test. "))
			//{\n  "error": "not authorized"\n}

			flusher.Flush()

			w.Write([]byte("this is just test. "))

			flusher.Flush()

			w.Write([]byte("this is just test. "))

			flusher.Flush()
		} else if r.URL.String() == "/chunked1.html" {
			flusher, ok := w.(http.Flusher)
			if !ok {
				panic("need flusher!")
			}
			flusher.Flush()

			w.Header().Set("Transfer-Encoding", "chunked")

			w.Write([]byte("uid=0(root) gid=0(root) groups=0(root)"))

			flusher.Flush()
		} else if r.URL.String() == "/proxy.html" {
			assert.Equal(t, "gzip", r.Header.Get("Proxy"), "should be equal")
		} else if r.URL.String() == "/variable.html" {
			w.Header().Set("Test-Header", "TestValue")
			w.Header().Set("Set-Cookie", "a=b")
			w.Header().Set("X-Powered-By", "abc")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`aaa 1234567890abcdef1234567890abcdef.php bbb
sub hex test: mht111.tmp.mht
sub hex test: |a101|
sub hex test: %A101%
url_encode test: (a b?c)
`))
		} else if r.URL.String() == "/post.html" {
			if r.Method == "POST" && r.FormValue("abc") == "123" {
				w.Write([]byte(`ok`))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`error`))
			}

		} else if r.URL.String() == "/ajax/getemaildata.php?DontCheckLogin=1" {
			if r.Method == "POST" {
				w.Write([]byte(`{"success":true,"code":"","message":"","files":[],"filePath":"D:\\U8SOFT\\turbocrm70\\code\\www\\tmpfile\\mht8947.tmp.mht"}`))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`error`))
			}
		} else if r.URL.String() == "/tmpfile/upd8946.tmp.php" {
			w.Write([]byte(`<title>phpinfo()</title>`))
		} else if r.URL.String() == "/basicauth.html" {
			u, p, ok := r.BasicAuth()
			if ok && u == "testuser" && p == "testpass" {
				w.Write([]byte(`welcome`))
			} else {
				w.Write([]byte(`401`))
			}
		}
	}))
}

func NewTestProxyServer(listenPort string) *http.Server {

	handler := http.DefaultServeMux

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Construct request to send to origin server
		rr := http.Request{
			Method: r.Method,
			URL:    r.URL,
			Body:   r.Body,
			Header: r.Header,
			// TODO: Is this correct for a 0 value?
			//       Perhaps a 0 may need to be reinterpreted as -1?
			ContentLength: r.ContentLength,
			Close:         r.Close,
		}

		// Forward request to origin server
		resp, err := http.DefaultTransport.RoundTrip(&rr)
		if err != nil {
			// TODO: Passthru more error information
			http.Error(w, "Could not reach origin server", 500)
			return
		}
		defer resp.Body.Close()

		// Transfer filtered header from origin server -> client
		respH := w.Header()
		respH.Add("TestHeader", "TestValue")
		w.WriteHeader(resp.StatusCode)

		// Transfer response from origin server -> client
		if resp.ContentLength > 0 {
			// (Ignore I/O errors, since there's nothing we can do)
			io.CopyN(w, resp.Body, resp.ContentLength)
		} else if resp.Close { // TODO: Is this condition right?
			// Copy until EOF or some other error occurs
			for {
				if _, err := io.Copy(w, resp.Body); err != nil {
					break
				}
			}
		}
	})

	s := &http.Server{
		Addr:           listenPort,
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go s.ListenAndServe()
	time.Sleep(time.Second)
	return s
}

func TestDoHttpRequest(t *testing.T) {
	// Start a local HTTP server
	server := NewTestServer(t)
	defer server.Close()

	serverUrl := NewFixUrl(server.URL)

	// err test
	resp, err := DoHttpRequest(serverUrl, NewRequestConfig("   ", "/200.html"))
	assert.NotNil(t, err)

	// 200
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/200.html"))
	assert.Equal(t, 200, resp.StatusCode, "should be 200")

	// 302 默认跳转
	cfg := NewGetRequestConfig("/302.html")
	cfg.FollowRedirect = true
	resp, _ = DoHttpRequest(serverUrl, cfg)
	assert.Equal(t, 200, resp.StatusCode, "should be 200")

	cfg.FollowRedirect = false
	resp, _ = DoHttpRequest(serverUrl, cfg)
	assert.Equal(t, 302, resp.StatusCode, "should be 302")

	cfg = NewGetRequestConfig("/302_1.html")
	cfg.FollowRedirect = true
	cfg.Following = 2
	resp, _ = DoHttpRequest(serverUrl, cfg)
	assert.Equal(t, 302, resp.StatusCode, "should be 302")
	assert.Equal(t, "302_3", resp.RawBody, "should be 302")

	cfg = NewGetRequestConfig("/302out.html")
	cfg.FollowRedirect = true
	cfg.DenyFollwRedirectOutHost = true
	resp, _ = DoHttpRequest(serverUrl, cfg)
	assert.Equal(t, 302, resp.StatusCode, "should be 302")
	u, _ := resp.Location()
	assert.Equal(t, "baidu.com", u.Host, "should be 302")

	// gzip
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/gzip.html"))
	assert.Equal(t, "test", resp.RawBody, "should be unzipped test")

	// gzip
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/variable.html"))
	assert.Contains(t, resp.Cookie, "a=b")

	// gzip
	resp, err = DoHttpRequest(serverUrl, NewGetRequestConfig("/gzip_no_data.html"))
	assert.Nil(t, err)

	// chunked
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/chunked.html"))
	assert.Equal(t, "this is just test. this is just test. this is just test. ", resp.RawBody, "should be chunked test")

	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/chunked1.html"))
	assert.Equal(t, "uid=0(root) gid=0(root) groups=0(root)", resp.RawBody, "should be chunked test")

	//log.Println(resp.RawHttpResponse.Request.URL)
	//time.Sleep(time.Second * 60)

	// proxy
	s := NewTestProxyServer(":12345")
	defer s.Close()

	assertPanic(t, func() {
		SetDefaultProxy(" https://zhidao.baidu.com")
	})

	SetDefaultProxy("http://127.0.0.1:12345")
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/200.html"))
	assert.Equal(t, "TestValue", resp.Header.Get("TestHeader"), "should be 200")

	SetDefaultProxy("")
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/200.html"))
	assert.Equal(t, "", resp.Header.Get("TestHeader"), "should be 200")

	// properties
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/200.html"))
	resp.HeaderString.DeleteByName("Date: ")
	assert.Contains(t, resp.HeaderString.String(), "Content-Type: text/plain; charset=utf-8")
	assert.Equal(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain; charset=utf-8\r\n", resp.HeaderString.SortString(), "should be 200")

	// utf8html
	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/gb2312.html"))
	assert.Equal(t, "啊", resp.Utf8Html, "should be equal")

	resp, _ = DoHttpRequest(serverUrl, NewGetRequestConfig("/unicode.html"))
	assert.Equal(t, "啊", resp.Utf8Html, "should be equal")

	// post
	cfg = NewPostRequestConfig("/post.html")
	cfg.Data = "abc=123"
	cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
	resp, _ = DoHttpRequest(serverUrl, cfg)
	assert.Equal(t, "ok", resp.Utf8Html, "should be ok")

	// err test
	resp, err = DoHttpRequest(serverUrl, NewGetRequestConfig("/302nolocation.html"))
	assert.NotNil(t, err)

	// 认证测试
	resp, err = DoHttpRequest(serverUrl, NewGetRequestConfig("/basicauth.html"))
	assert.Nil(t, err)
	assert.Equal(t, "401", resp.Utf8Html)
	cfg = NewGetRequestConfig("/basicauth.html")
	cfg.BasicAuth = "testuser:testpass"
	resp, err = DoHttpRequest(serverUrl, cfg)
	assert.Nil(t, err)
	assert.Equal(t, "welcome", resp.Utf8Html)

	// 配置的uri是完整的url测试
	resp, err = DoHttpRequest(serverUrl, NewGetRequestConfig("/basicauth.html"))
	assert.Nil(t, err)
	assert.Equal(t, "401", resp.Utf8Html)
	cfg = NewGetRequestConfig("http://127.0.0.1:65432/200.html")
	resp, err = DoHttpRequest(serverUrl, cfg)
	assert.Error(t, err) //应该到新的不可链接的地址报错
}

// 目标是通过host:port重定向到https://host:port的，
// 所以如果url是http://x.com就最好不要写成http://x.com:80
// 否则会导致重定向到https://x.com:80，进行返回"server gave HTTP response to HTTPS client"的错误
func TestDoHttpRequest_HTTP2HTTPS(t *testing.T) {
	server := NewTestServer(t)
	defer server.Close()

	u := NewFixUrl(server.URL + "/https.html")
	//u := NewFixUrl("http://bz.qq.com:80")
	cfg := NewGetRequestConfig(u.Path)
	cfg.DenyFollwRedirectOutHost = true
	cfg.VerifyTls = false
	cfg.Timeout = 10
	//cfg.Header.Store("Host", u.HostInfo)
	_, err := DoHttpRequest(u, cfg)

	assert.NotNil(t, err)
}

func TestDoHttpRequest_Invalid(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("httptest: failed to listen on a port: %v", err))
		}
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				fmt.Printf("accept fail, err: %v\n", err)
				continue
			}

			//create goroutine for each connect
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					var buf [1024]byte
					n, err := conn.Read(buf[:])

					if err != nil {
						fmt.Printf("read from connect failed, err: %v\n", err)
						break
					}
					str := string(buf[:n])
					fmt.Printf("receive from client, data: %v\n", str)

					conn.Write([]byte("HTTP/1.0 200 OK\r\nproccgi -- error reading post data, 0 bytes read, 82 expected\r\nSet-Cookie:hash_key=123,session_id=1234;\r\n\r\ntesttest\r\naaa"))
				}
			}(conn)
		}
	}()

	u := NewFixUrl("http://" + l.Addr().String() + "/test.html")
	cfg := NewGetRequestConfig(u.Path)
	cfg.DenyFollwRedirectOutHost = true
	cfg.VerifyTls = false
	cfg.Timeout = 10
	cfg.InvalidResponse = true
	resp, err := DoHttpRequest(u, cfg)

	assert.Contains(t, resp.RawBody, "expected")
	//assert.NotNil(t, err)
}

func GenX509KeyPair() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         "test.example.com",
			Country:            []string{"CN"},
			Organization:       []string{"example.com"},
			OrganizationalUnit: []string{"test"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1), // Valid for one day
		SubjectKeyId:          []byte{65, 65, 65, 65, 65, 65, 65, 65, 65, 65},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}

func NewTCPTestServer(t *testing.T, enableTls bool) net.Listener {
	var l net.Listener
	var err error
	if !enableTls {
		l, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		cert, err2 := GenX509KeyPair()
		assert.Nil(t, err2)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		l, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	}

	assert.Nil(t, err)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				break
			}

			// echo
			for {
				if _, err := io.Copy(conn, conn); err != nil {
					break
				}
			}
			conn.Close()
		}
	}()

	return l
}

func NewUDPTestServer(t *testing.T) *net.UDPConn {
	l, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	assert.Nil(t, err)

	go func() {
		for {
			buf := make([]byte, 1024)
			n, addr, err := l.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			l.WriteToUDP(buf[:n], addr)
		}
	}()

	return l
}

func TestTCPUDP(t *testing.T) {
	tcpL := NewTCPTestServer(t, false)
	tlsL := NewTCPTestServer(t, true)
	udpL := NewUDPTestServer(t)
	time.Sleep(1 * time.Second)
	defer tcpL.Close()
	defer udpL.Close()
	defer tlsL.Close()

	needle := []byte("\x02\x02AAAABBBBCCCCD\x00")
	check := make([]byte, 1024)

	// tcp
	tcpConn, err := GetTCPConn(tcpL.Addr().String())
	assert.Nil(t, err)
	_, err = tcpConn.Write(needle)
	assert.Nil(t, err)
	n, err := tcpConn.Read(check)
	assert.Nil(t, err)
	assert.Equal(t, needle, check[:n])

	// udp
	udpConn, err := GetUDPConn(udpL.LocalAddr().String())
	assert.Nil(t, err)
	_, err = udpConn.Write(needle)
	assert.Nil(t, err)
	n, err = udpConn.Read(check)
	assert.Nil(t, err)
	assert.Equal(t, needle, check[:n])

	// tls
	tlsConn, err := GetTLSConn(tlsL.Addr().String())
	assert.Nil(t, err)
	_, err = tlsConn.Write(needle)
	assert.Nil(t, err)
	n, err = tlsConn.Read(check)
	assert.Nil(t, err)
	assert.Equal(t, needle, check[:n])
}

//func TestTlsWithSocks5Proxy(t *testing.T) {
//	SetDefaultProxy("socks5://127.0.0.1:1080")
//	tlsConn, err := GetTLSConn("150.116.254.4:8080") // 通过 protocol="https" 到scanner搜索测试目标
//	assert.Nil(t, err)
//	_, err = tlsConn.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(`
//GET / HTTP/1.1
//Host: 150.116.254.4:8080
//Accept-Encoding: gzip, deflate
//Accept: */*
//Accept-Language: en
//User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36
//Connection: close
//
//`, "\r\n", "\n"), "\n", "\r\n")))
//	assert.Nil(t, err)
//	resp := make([]byte, 4096)
//	n, err := tlsConn.Read(resp)
//	assert.Nil(t, err)
//	assert.True(t, n > 0)
//	fmt.Println(string(resp[:n]))
//}
//
//func TestTCPWithSocks5Proxy(t *testing.T) {
//	SetDefaultProxy("socks5://127.0.0.1:1080")
//	tcpConn, err := GetTCPConn("154.94.127.137:80") // 通过 protocol="http" 到scanner搜索测试目标
//	assert.Nil(t, err)
//	_, err = tcpConn.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(`
//GET / HTTP/1.1
//Host: 154.94.127.137:80
//Accept-Encoding: gzip, deflate
//Accept: */*
//Accept-Language: en
//User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36
//Connection: close
//
//`, "\r\n", "\n"), "\n", "\r\n")))
//	assert.Nil(t, err)
//	resp := make([]byte, 4096)
//	n, err := tcpConn.Read(resp)
//	assert.Nil(t, err)
//	assert.True(t, n > 0)
//	fmt.Println(string(resp[:n]))
//}
