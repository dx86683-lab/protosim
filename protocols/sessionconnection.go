package protocols

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/oschwald/geoip2-golang"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/pkg/ssl"
)

/*
ConfigInfo 所有模块的默认参数
*/
type ConfigInfo struct {
	*BindInfo
	ServerInfo string
	Log        *logrus.Entry
}

var geoReader *geoip2.Reader

// 设置geo db数据库
func SetGeoDB(dbPath string) error {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return errors.Wrap(err, "SetGeoDB")
	}
	if geoReader != nil {
		geoReader.Close()
	}
	geoReader = db
	return nil
}

var logHostName string

// 设置日志记录的主机名
func SetLogHostName(name string) {
	logHostName = name
}

func GetLogHostName() string {
	return logHostName
}

func NewConfigInfo(serverInfo string, bindinfo *BindInfo, log *logrus.Entry) *ConfigInfo {
	return &ConfigInfo{
		ServerInfo: serverInfo,
		BindInfo:   bindinfo,
		Log:        log,
	}
}

var exclusions = make(map[string]bool)

func AddLogRemoteIpExclusion(ip string) {
	addr := net.ParseIP(ip)
	if addr != nil {
		exclusions[ip] = true
	}
}

func IsExclusionIP(remoteIP string) bool {
	_, ok := exclusions[remoteIP]
	return ok
}

func IsExclusion(remoteAddr net.Addr) bool {
	if remoteAddr != nil {
		ip := ""
		switch addr := remoteAddr.(type) {
		case *net.UDPAddr:
			ip = addr.IP.String()
		case *net.TCPAddr:
			ip = addr.IP.String()
		default:
			panic("unknown remoteAddr")
		}
		_, ok := exclusions[ip]
		return ok
	}
	return false
}

// LogWithRemote 记录带有remote的日志
// info 是提示信息
// remoteAddr 是远程信息，需要提取出来ip，方便后续查找
// fieldMaps是数组
func (ci *ConfigInfo) LogWithRemote(info string, remoteAddr net.Addr, fieldMaps ...map[string]interface{}) {
	if IsExclusion(remoteAddr) {
		logrus.Info("[RemoteLogger] skip addr: ", remoteAddr)
		return
	}

	f := ci.BuildRemoteInfo(remoteAddr, fieldMaps...)
	ci.Log.WithFields(f).Info(info)
	ci.AddActivity(remoteAddr, false)
}

// LogInfo 记录日志
func (ci *ConfigInfo) LogInfo(info string, fieldMaps ...map[string]interface{}) {
	var f logrus.Fields
	for i := range fieldMaps {
		copier.Copy(&f, &fieldMaps[i])
	}
	ci.Log.WithFields(f).Info(info)
}

// BuildRemoteInfo 生成结构
func BuildRemoteInfo(remoteAddr net.Addr, fieldMaps ...map[string]interface{}) logrus.Fields {
	var f logrus.Fields
	for i := range fieldMaps {
		copier.Copy(&f, &fieldMaps[i])
	}

	if remoteAddr != nil {
		ip := ""
		var port uint = 0
		switch addr := remoteAddr.(type) {
		case *net.UDPAddr:
			ip = addr.IP.String()
			port = uint(addr.Port)
		case *net.TCPAddr:
			ip = addr.IP.String()
			port = uint(addr.Port)
		default:
			panic("unknown remoteAddr")
		}
		fields := map[string]interface{}{
			"remote_ip":   ip,
			"remote_port": port,
			"transport":   remoteAddr.Network(),
			"remote":      remoteAddr.String(),
			"host":        logHostName,
		}
		if geoReader != nil {
			record, err := geoReader.City(net.ParseIP(ip))
			if err != nil {
				logrus.Errorf("get geo for ip %s error:%s.", ip, err)
				goto SetLogs
			}
			if record.Location.Latitude != 0 || record.Location.Longitude != 0 {
				fields["geoip"] = map[string]interface{}{
					"country_iso_code": record.Country.IsoCode,
					"country_name":     record.Country.Names["en"],
					"city_name":        record.City.Names["en"],
					"location": map[string]float64{
						"lat": record.Location.Latitude,
						"lon": record.Location.Longitude,
					},
				}
			}
		}
	SetLogs:
		lf := logrus.Fields(fields)
		copier.Copy(&f, &lf)
	}

	return f
}

func (ci *ConfigInfo) BuildRemoteInfo(remoteAddr net.Addr, fieldMaps ...map[string]interface{}) logrus.Fields {
	return BuildRemoteInfo(remoteAddr, fieldMaps...)
}

/*
SessionConnection 所有tcp模块的默认参数
*/
type SessionConnection struct {
	ssl.SslConnWraper
	Conn               net.Conn
	ConnectionID       uint32
	ListenEphemeralTCP func() (net.Listener, error)
	DialTCPPeer        func(context.Context, uint16) (net.Conn, error)
	*ConfigInfo
}

func (sc *SessionConnection) DeleteActivity() {
	sc.Conn.Close()
	sc.AddActivity(sc.Conn.RemoteAddr(), true)
}

// drainIgnoredInput keeps a silent session open until the peer stops sending.
func (sc *SessionConnection) drainIgnoredInput(reader io.Reader) {
	sc.suppressRequestCapture()
	_, _ = io.Copy(io.Discard, reader)
}

func (sc *SessionConnection) suppressRequestCapture() {
	if capture, ok := sc.Conn.(interface{ SuppressRequestCapture() }); ok {
		capture.SuppressRequestCapture()
	}
}

func (sc *SessionConnection) SendString(str string) error {
	_, err := sc.Conn.Write([]byte(str))
	return err
}

func (sc *SessionConnection) ReadLine(onByte func([]byte) (bool, error)) (string, error) {
	var buffer [1]byte // Seems like the length of the buffer needs to be small, otherwise will have to wait for buffer to fill up.
	p := buffer[:]

	var line bytes.Buffer

	for {
		// Read 1 byte.
		n, err := sc.Conn.Read(p)
		if n <= 0 && nil == err {
			continue
		} else if n <= 0 && nil != err {
			return "", err
		}

		if p[0] != '\r' && p[0] != '\n' {
			if onByte != nil {
				if ok, err := onByte(p); err != nil {
					return "", err
				} else {
					if ok {
						return strings.TrimRight(line.String(), "\r\n"), nil
					}
				}
			}
		}
		line.WriteByte(p[0])

		//logger.Tracef("Received: %q (%d).", p[0], p[0])

		if '\n' == p[0] {
			return strings.TrimRight(line.String(), "\r\n"), nil
		}
	}
}

/*
ListenConnection 所有tcplistener模块的默认参数
*/
type ListenConnection struct {
	ssl.SslConnWraper
	Listener net.Listener
	*ConfigInfo
}

/*
UDPConnection 所有UDP模块的默认参数
*/
type UDPConnection struct {
	// UDPConn
	net.PacketConn
	remoteAddr net.Addr
	*ConfigInfo
}

func NewUDPConnection(conn net.PacketConn, remoteAddr net.Addr, ci *ConfigInfo) *UDPConnection {
	return &UDPConnection{
		PacketConn: conn,
		remoteAddr: remoteAddr,
		ConfigInfo: ci,
	}
}

//// 实现net.Conn接口  ?? 为什么要重写UDP的接口

func (uc *UDPConnection) Read(b []byte) (int, error) {
	n, _, err := uc.ReadFrom(b)
	return n, err
}

func (uc *UDPConnection) Write(b []byte) (int, error) {
	n, err := uc.WriteTo(b, uc.remoteAddr)
	return n, err
}

func (uc *UDPConnection) RemoteAddr() net.Addr {
	return uc.remoteAddr
}

var _ net.Conn = new(UDPConnection)

// ReadFromUDP 从 UDP 连接中读取数据包
func (uc *UDPConnection) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addrNet, err := uc.PacketConn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}

	udpAddr, ok := addrNet.(*net.UDPAddr)
	if !ok {
		return n, nil, fmt.Errorf("failed to convert net.Addr to *net.UDPAddr")
	}

	return n, udpAddr, nil
}

// WriteToUDP 向指定的 UDP 地址发送数据包
func (uc *UDPConnection) WriteToUDP(respData []byte, raddr *net.UDPAddr) (int, error) {
	n, err := uc.PacketConn.WriteTo(respData, raddr)
	if err != nil {
		return n, err
	}
	return n, nil
}
