package ssl

import (
	"net"

	"github.com/CapacitorSet/ja3-server/crypto/tls"
)

type SslConn interface {
	net.Conn
	Handshake() error
}

type CertGenerator interface {
	GenCert(string) (certFile, keyFile string, err error)
}

type SslConnWraper interface {
	InitSslConfig(CertGenerator) error
	GetCertConfig() *tls.Config
	WrapSslConn(conn net.Conn) SslConn
	WrapSslListener(l net.Listener) net.Listener
	GetCert() *tls.Certificate
}
