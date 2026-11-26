package protocols

import (
	"bufio"
	"net"
	"net/http"
	"net/textproto"
)

func init() {
	AddProtocol(NewProtocolInfo("tcp_echo", TCPEcho, 1234))
	AddProtocol(NewProtocolInfo("udp_echo", UDPEcho, 1234))
	AddProtocol(NewProtocolInfo("tcp_forward", TCPForward, 8079),
		ProtocolParams{
			Name:         "target",
			DefaultValue: "www.bing.com:80",
		},
	)
}

type UDPConn interface {
	RemoteAddr() net.Addr
	Write(b []byte) (n int, err error)
}

type HTTPFunction func(ci *ConfigInfo) http.Handler
type TCPListenerFunction func(lc *ListenConnection) error
type TCPFunction func(sc *SessionConnection) error
type TCPForwardFunction func(client net.Conn, server net.Conn, data []byte, clientToServer bool) error
type UDPFunction func(uc *UDPConnection, b []byte) error

func UDPEcho(uc *UDPConnection, b []byte) error {
	//log.printf("read data from %s", uc.RemoteAddr().String())
	_, err := uc.WriteTo(b, uc.RemoteAddr())
	if err != nil {
		//log.printf("error write connection, %v", err)
		return err
	}
	return nil
}

func TCPEcho(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	reader := bufio.NewReader(sc.Conn)
	tp := textproto.NewReader(reader)
	for {
		d, err := tp.ReadLineBytes()
		if err != nil {
			return err
		}
		_, err = sc.Conn.Write(d)
		if err != nil {
			return err
		}
	}
}

func TCPForward(client net.Conn, server net.Conn, data []byte, clientToServer bool) error {
	// var src, dst net.Conn
	// if clientToServer {
	// 	src = client
	// 	dst = server
	// } else {
	// 	src = server
	// 	dst = client
	// }
	//log.printf("read data from %s to %s: %d", src.RemoteAddr().String(), dst.RemoteAddr().String(), len(data))
	return nil
}
