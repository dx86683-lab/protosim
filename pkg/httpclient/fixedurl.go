package httpclient

import (
	"net"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

type FixUrl struct {
	HostInfo        string //ip:port 肯定带端口
	FixedHostInfo   string //scheme://host 不一定带端口，默认情况下会省略
	IP              string
	Port            string
	Path            string // 不包含参数？
	Dir             string // 解析后的
	File            string // 解析后的
	Ext             string // 解析后的
	Method          string
	ContentType     string
	Data            string
	PostDataType    string
	u               *url.URL
	mustIP          string
	ParseWithScheme bool //是否解析的时候自带scheme
}

// 归一化url格式
func NewFixUrl(hostinfo string) *FixUrl {
	fullurl := hostinfo
	hasScheme := strings.Contains(hostinfo, "://")
	if !hasScheme {
		fullurl = "http://" + fullurl
	}
	fullurl = strings.Trim(fullurl, " \t\r\n")

	u, err := url.Parse(fullurl)
	if err != nil {
		//log.Println("[WARNING] url.Parse", err)
		return nil
	}
	// 解决 IPV6 Parse 错误
	ip := u.Hostname()
	port := u.Port()

	if len(port) == 0 {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		}
	}

	// 存在目标是通过host:port重定向到https://host:port的，
	// 所以如果url是http://x.com就最好不要写成http://x.com:80
	// 否则会导致重定向到https://x.com:80，进行返回"server gave HTTP response to HTTPS client"的错误
	fixedHostInfo := u.Scheme + "://"
	if (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
		if strings.Contains(ip, ":") {
			fixedHostInfo += "[" + ip + "]"
		} else {
			fixedHostInfo += ip
		}
	} else {
		fixedHostInfo += u.Host
	}

	dir, file := path.Split(u.Path)

	return &FixUrl{
		HostInfo:        net.JoinHostPort(ip, port),
		u:               u,
		IP:              ip,
		Port:            port,
		Path:            u.Path,
		Dir:             dir,
		File:            file,
		Ext:             filepath.Ext(file),
		FixedHostInfo:   fixedHostInfo,
		Method:          "GET",
		ParseWithScheme: hasScheme,
	}
}

func (fu *FixUrl) Scheme() string {
	return fu.u.Scheme
}

func (fu *FixUrl) String() string {
	if fu == nil || fu.u == nil {
		return ""
	}
	return fu.u.String()
}

func (fu *FixUrl) ResolveReference(ref *url.URL) *url.URL {
	return fu.u.ResolveReference(ref)
}

// 带有参数的路径
// assert.Equal(t, "/index.php?id=123", NewFixUrl("https://1.1.1.1/index.php?id=123").PathWithQuery())
func (fu *FixUrl) PathWithQuery() string {
	if len(fu.u.RawQuery) > 0 {
		return fu.Path + "?" + fu.u.RawQuery
	}
	return fu.Path
}

func (fu *FixUrl) RawQuery() string {
	return fu.u.RawQuery
}

func (fu *FixUrl) Query() url.Values {
	return fu.u.Query()
}

// 获取认证数据
func (fu *FixUrl) GetAuth() string {
	return fu.u.User.String()
}

func IPOfHost(host string) string {
	addr, err := net.LookupIP(host)
	if err != nil {
		return ""
	} else {
		return addr[0].String()
	}
}

// 获取认证数据
func (fu *FixUrl) MustIP() string {
	if len(fu.mustIP) == 0 {
		fu.mustIP = IPOfHost(fu.IP)
	}
	return fu.mustIP
}
