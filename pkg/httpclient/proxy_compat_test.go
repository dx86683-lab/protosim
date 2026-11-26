package httpclient

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Both ends of every connection are ephemeral loopback listeners.
func TestLocalHTTPProxyCompatibility(t *testing.T) {
	for _, proxyScheme := range []string{"http", "https"} {
		for _, network := range []string{NetworkTypeTCP, NetworkTypeTLS} {
			t.Run(proxyScheme+"/"+network, func(t *testing.T) {
				targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprint(w, "local proxy response")
				})
				var target *httptest.Server
				if network == NetworkTypeTLS {
					target = httptest.NewTLSServer(targetHandler)
				} else {
					target = httptest.NewServer(targetHandler)
				}
				defer target.Close()
				targetURL, err := url.Parse(target.URL)
				if err != nil {
					t.Fatal(err)
				}

				proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodConnect || r.Host != targetURL.Host {
						http.Error(w, "unexpected CONNECT target", http.StatusBadRequest)
						return
					}
					upstream, err := net.DialTimeout("tcp", targetURL.Host, time.Second)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					defer upstream.Close()
					downstream, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer downstream.Close()
					io.WriteString(downstream, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
					go func() {
						io.Copy(upstream, downstream)
						upstream.Close()
					}()
					io.Copy(downstream, upstream)
				})
				var proxyServer *httptest.Server
				if proxyScheme == "https" {
					proxyServer = httptest.NewTLSServer(proxyHandler)
					roots := x509.NewCertPool()
					roots.AddCert(proxyServer.Certificate())
					previousConfig := TlsConfig
					TlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
					defer func() { TlsConfig = previousConfig }()
				} else {
					proxyServer = httptest.NewServer(proxyHandler)
				}
				defer proxyServer.Close()
				proxyURL, err := url.Parse(proxyServer.URL)
				if err != nil {
					t.Fatal(err)
				}

				conn, err := GetTCPConnWithProxy(network, targetURL.Host, proxyURL, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL.Host)
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "local proxy response" {
					t.Fatalf("unexpected proxy response: %q", body)
				}
			})
		}
	}
}

func TestLocalProxyFailureCompatibility(t *testing.T) {
	t.Run("unsupported scheme", func(t *testing.T) {
		conn, err := GetTCPConnWithProxy(NetworkTypeTCP, "127.0.0.1:1", &url.URL{Scheme: "unsupported"}, time.Second)
		if err == nil || conn != nil {
			t.Fatalf("unsupported proxy returned conn=%v err=%v", conn, err)
		}
	})
	t.Run("malformed response", func(t *testing.T) {
		proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			io.WriteString(conn, "invalid HTTP response\r\n\r\n")
		}))
		defer proxyServer.Close()
		proxyURL, err := url.Parse(proxyServer.URL)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := GetTCPConnWithProxy(NetworkTypeTCP, "127.0.0.1:1", proxyURL, time.Second)
		if err == nil || conn != nil {
			t.Fatalf("malformed proxy returned conn=%v err=%v", conn, err)
		}
	})
}
