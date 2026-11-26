package httpclient

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"github.com/dx86683-lab/protosim/pkg/httpclient/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ProxyConnectTimeout = time.Second * 10 //代理连接超时时间
	defaultUserAgent    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
)

type HeaderString struct {
	Lines []string
}

func (hs *HeaderString) Add(line string) {
	if hs.Lines == nil {
		hs.Lines = make([]string, 0, 5)
	}
	hs.Lines = append(hs.Lines, line)
}

func (hs *HeaderString) DeleteByName(key string) {
	for i, s := range hs.Lines {
		if strings.Contains(s, key) {
			hs.Lines = append(hs.Lines[:i], hs.Lines[i+1:]...)
			return
		}
	}
}

func (hs *HeaderString) String() (header string) {
	for _, s := range hs.Lines {
		header += s + "\r\n"
	}
	return
}

// header 排序后的结果
func (hs *HeaderString) SortString() (header string) {
	header += hs.Lines[0] + "\r\n"
	newLines := hs.Lines[1:len(hs.Lines)]
	sort.Strings(newLines)
	for _, s := range newLines {
		header += s + "\r\n"
	}
	return
}

type HttpResponse struct {
	RawBody      string
	Utf8Html     string //编码后的html
	Title        string //编码后的html
	size         int
	HeaderString *HeaderString
	Cookie       string
	*http.Response
}

func (rsp *HttpResponse) Size() int {
	if rsp.size == 0 {
		rsp.size = len(rsp.Utf8Html)
	}
	return rsp.size
}

var defaultProxyTransport *http.Transport
var defaultProxy *url.URL

func GetDefaultProxy() *url.URL {
	return defaultProxy
}

func SetDefaultProxy(proxy string) {
	if len(proxy) > 0 {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}
		if proxyUrl.Scheme == "socks5" {
			conn, err := GetTCPConnWithProxy("tcp", "127.0.0.1:12345", proxyUrl, ProxyConnectTimeout)
			if err != nil {
				//log.Println(err.Error())
				if strings.Contains(err.Error(), "authentication failed") ||
					strings.Contains(err.Error(), "proxy error") {
					panic(err)
				} else if strings.Contains(err.Error(), "connection refused") {
					// 如果proxy链接断开，但是直接连接没有断开，说明代理是可以用的
					// 这里确保代理能够正常连接
					if c, e := net.DialTimeout("tcp", proxyUrl.Host, ProxyConnectTimeout); e != nil {
						if strings.Contains(e.Error(), "connection refused") {
							panic(err)
						}
					} else {
						c.Close()
					}
				}
			} else {
				conn.Close()
			}
		}

		defaultProxy = proxyUrl
		defaultProxyTransport = &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		}
		//http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
	} else {
		defaultProxyTransport = nil
		defaultProxy = nil
		//http.DefaultTransport = &http.Transport{Proxy: nil}
	}
}

func setFollowing(client *http.Client, followRedirect bool, following int, denyFollwRedirectOutHost bool) {
	if !followRedirect {
		// 不跟踪跳转
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if following > 0 {
		// 指定了跳转次数
		client.CheckRedirect = func(hreq *http.Request, via []*http.Request) error {
			if len(via) > following {
				return http.ErrUseLastResponse
			}

			if denyFollwRedirectOutHost {
				if hreq.URL.Host != via[0].URL.Host {
					return http.ErrUseLastResponse
				}
			}
			return nil
		}
	}
}

func setHeader(httpreq *http.Request, header sync.Map) {
	//httpreq.Header.Add("Accept-Encoding", "br, gzip, deflate")
	header.Range(func(k, v interface{}) bool {
		httpreq.Header.Add(k.(string), v.(string))
		return true
	})
	if host, ok := header.Load("Host"); ok {
		httpreq.Host = host.(string)
	}
	if len(defaultUserAgent) > 0 {
		httpreq.Header.Add("User-Agent", defaultUserAgent)
	}
}

// 设置代理行为，默认从单次，其次从全局
func setProxy(client *http.Client, req *RequestConfig) {
	if req.Proxy != nil {
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(req.Proxy),
		}
	} else if defaultProxyTransport != nil {
		client.Transport = defaultProxyTransport
	}
}

func setVerifyTls(client *http.Client, verifyTls bool) {
	if client.Transport != nil {
		client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: !verifyTls, MinVersion: tls.VersionTLS10}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTls, MinVersion: tls.VersionTLS10},
		}
	}

}

func transformIfGb2312(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	reader := transform.NewReader(bytes.NewReader([]byte(s)), simplifiedchinese.GBK.NewDecoder())
	if d, e := ioutil.ReadAll(reader); e == nil {
		return string(d)
	}

	return s
}

// GetStringInBetween Returns empty string if no start string found
func GetStringInBetween(str string, start string, end string) (result string) {
	//没有起始字符，说明直接从开头开始
	if len(str) > 0 {
		s := strings.Index(str, start)
		if s == -1 {
			return
		}
		s += len(start)
		str = str[s:]
	}

	//没有终止字符，说明直接到末尾
	if len(end) == 0 {
		return str
	}

	e := strings.Index(str, end)
	if e == -1 { //没有结束就是到末尾
		e = len(str)
	}
	return str[:e]
}

func NewHttpResponse(resp *http.Response) (*HttpResponse, error) {
	httpResp := &HttpResponse{
		Response: resp,
	}

	defer resp.Body.Close()

	reader := resp.Body
	var err error
	if !resp.Uncompressed && strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		// Check that the server actually sent compressed data
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err = gzip.NewReader(resp.Body)
			if err != nil {
				reader = nil
			} else {
				defer reader.Close()
			}
		default:
			reader = resp.Body
		}
	}

	var b []byte
	if reader != nil {
		b, err = ioutil.ReadAll(reader)
		if err != nil {
			if len(b) == 0 {
				//log.Println("[WARNING] DoHttpRequest ioutil.ReadAll error:", err)
				return httpResp, err
			}
		}
	}

	headerString := HeaderString{}
	headerString.Add(resp.Proto + " " + resp.Status)
	for k, v := range resp.Header {
		for _, v1 := range v {
			headerString.Add(k + ": " + v1)
		}
	}
	httpResp.HeaderString = &headerString

	httpResp.RawBody = string(b)

	httpResp.Utf8Html = transformIfGb2312(string(encoding.UTF8(resp, string(b))))
	httpResp.Title = GetStringInBetween(httpResp.Utf8Html, "<title>", "</title>")

	for _, c := range resp.Cookies() {
		httpResp.Cookie += c.Name + "=" + c.Value + ";"
	}

	return httpResp, nil
}

type RequestConfig struct {
	Method                   string
	URI                      string
	Data                     string
	Following                int  //跳转次数
	FollowRedirect           bool //是否跳转
	DenyFollwRedirectOutHost bool //是否支持跳转到非ip：port的另外的网站
	Header                   sync.Map
	Timeout                  int
	VerifyTls                bool
	TrackFunction            func(string, string)
	BasicAuth                string   //认证信息 user:pass格式
	Proxy                    *url.URL //代理
	InvalidResponse          bool     //是否会返回错误的格式
}

func NewRequestConfig(method, uri string) *RequestConfig {
	return &RequestConfig{
		Method:         method,
		URI:            uri,
		FollowRedirect: true,
		Following:      3,
		//Header: make(map[string]string),
		Timeout:   15,
		VerifyTls: true,
	}
}

func NewRequestConfigFromRaw(raw string) *RequestConfig {
	// 解决使用 HTTP 代理，如 burp，复现漏洞时，还要根据数据包写代码生成 RequestConfig 的问题，
	// 使用此函数，可以直接从原始 HTTP 请求包生成 RequestConfig。
	// HTTP 标准换行是 \r\n，但是复制成字符串后换行会变成 \n，先按换行符全为 \n 进行处理。
	//POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
	//Host: 10.10.11.20:53736
	//User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
	//Content-Length: 16
	//Accept-Encoding: gzip, deflate
	//Connection: close
	//
	//<?=md5('4c53')?>
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	rawSlice := strings.SplitN(raw, "\n\n", 2)
	header := strings.TrimSpace(rawSlice[0])
	var body string
	if len(rawSlice) > 1 {
		body = strings.TrimSpace(rawSlice[1])
	}

	headerSlice := strings.Split(header, "\n")
	requestLineSlice := strings.Split(headerSlice[0], " ")
	cfg := NewRequestConfig(requestLineSlice[0], requestLineSlice[1])

	for _, line := range headerSlice[1:] {
		if line != "" && strings.Contains(line, ":") {
			lineSlice := strings.SplitN(line, ":", 2)
			cfg.Header.Store(strings.TrimSpace(lineSlice[0]), strings.TrimSpace(lineSlice[1]))
		}
	}
	cfg.Data = strings.ReplaceAll(strings.TrimSpace(body), "\n", "\r\n")

	return cfg
}

func NewGetRequestConfig(uri string) *RequestConfig {
	return NewRequestConfig("GET", uri)
}

func NewPostRequestConfig(uri string) *RequestConfig {
	return NewRequestConfig("POST", uri)
}

func DoHttpRequest(hostinfo *FixUrl, req *RequestConfig) (*HttpResponse, error) {
	jar, err1 := cookiejar.New(nil)
	if err1 != nil {
		log.Fatal(err1)
	}
	client := &http.Client{Jar: jar}

	setFollowing(client, req.FollowRedirect, req.Following, req.DenyFollwRedirectOutHost)
	setProxy(client, req)
	setVerifyTls(client, req.VerifyTls) //默认不进行https验证

	client.Timeout = time.Second * time.Duration(req.Timeout) //设置超时

	var url string
	// 如果是完整的url，则以配置文件为准
	// 用户明确指定了完整的路径，说明请求的地址不一致（比如端口），这时用新的请求地址去访问
	if strings.HasPrefix(req.URI, "http://") || strings.HasPrefix(req.URI, "https://") {
		url = req.URI
	} else {
		url = hostinfo.FixedHostInfo + req.URI
	}

	var httpreq *http.Request
	var err error
	if len(req.Data) > 0 {
		httpreq, err = http.NewRequest(req.Method, url, strings.NewReader(req.Data))
	} else {
		httpreq, err = http.NewRequest(req.Method, url, nil)
	}
	if userPass := strings.Split(req.BasicAuth, ":"); len(req.BasicAuth) > 0 && len(userPass) > 0 {
		httpreq.SetBasicAuth(userPass[0], userPass[1])
	}
	if err != nil {
		//log.Println("[WARNING] DoHttpRequest error:", err)
		return nil, err
	}

	setHeader(httpreq, req.Header)

	if req.TrackFunction != nil {
		//跟踪
		data, _ := httputil.DumpRequest(httpreq, true)
		if len(data) > 0 {
			req.TrackFunction("out", string(data))
		}
	}

	// 测试过程中，服务器返回格式导致原生的http库失败
	if req.InvalidResponse {
		data, _ := httputil.DumpRequest(httpreq, true)
		c, err := GetTCPConn(hostinfo.HostInfo)
		if err != nil {
			return nil, err
		}
		if hostinfo.Scheme() == "https" {
			c = tls.Client(c, &tls.Config{InsecureSkipVerify: !req.VerifyTls, MinVersion: tls.VersionTLS10})
		}
		if _, err := c.Write(data); err != nil {
			return nil, err
		} else {
			p, err := ioutil.ReadAll(c)
			if len(p) > 0 {
				return &HttpResponse{
					RawBody:  string(p),
					Utf8Html: transformIfGb2312(string(p)),
				}, nil
			} else {
				return nil, err
			}
		}
	}

	resp, err := client.Do(httpreq)
	if err != nil {
		//log.Println("[WARNING] DoHttpRequest error:", err)
		return nil, err
	}
	//log.Println(resp)

	httpResp, err := NewHttpResponse(resp)
	if req.TrackFunction != nil {
		//跟踪, 不能把body取出来，否则如果有EOF报错后面的数据就都丢了
		data, _ := httputil.DumpResponse(resp, false)
		if len(data) > 0 {
			req.TrackFunction("in", string(data)+string(httpResp.RawBody))
		}
	}

	return httpResp, err
}

// 最简单的GET请求
func SimpleGetJSON(url string) map[string]interface{} {
	u := NewFixUrl(url)
	cfg := NewGetRequestConfig(u.PathWithQuery())
	cfg.VerifyTls = false
	if resp, err := DoHttpRequest(u, cfg); err == nil {
		var d map[string]interface{}
		if err = json.Unmarshal([]byte(resp.Utf8Html), &d); err == nil {
			return d
		} else {
			return nil
		}
	} else {
		return nil
	}
}

// 最简单的GET请求
func SimpleGet(url string) (*HttpResponse, error) {
	u := NewFixUrl(url)
	cfg := NewGetRequestConfig(u.PathWithQuery())
	cfg.VerifyTls = false
	return DoHttpRequest(u, cfg)
}

// 带有认证的GET请求
func GetWitchBasic(url string, userpass string) (*HttpResponse, error) {
	u := NewFixUrl(url)
	cfg := NewGetRequestConfig(u.PathWithQuery())
	cfg.BasicAuth = userpass
	cfg.VerifyTls = false
	return DoHttpRequest(u, cfg)
}

func SetDefaultUserAgent(ua string) {
	defaultUserAgent = ua
}
