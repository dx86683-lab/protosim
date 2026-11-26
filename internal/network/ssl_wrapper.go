package network

import (
	"net"

	"github.com/CapacitorSet/ja3-server/crypto/tls"
	"github.com/pkg/errors"

	"github.com/dx86683-lab/protosim/pkg/ssl"
)

// SSLWrapper implements ssl.SslConnWraper while preserving TelemetryConn / TelemetryListener hooks and JA3 capture.
type SSLWrapper struct {
	certFileName string
	certConfig   *tls.Config
}

func NewSSLWrapper(certFileName string) *SSLWrapper {
	return &SSLWrapper{certFileName: certFileName}
}

func (sc *SSLWrapper) GetCert() *tls.Certificate {
	if sc.certConfig != nil && len(sc.certConfig.Certificates) > 0 {
		return &sc.certConfig.Certificates[0]
	}
	return nil
}

func (sc *SSLWrapper) GetCertConfig() *tls.Config {
	return sc.certConfig
}

func (sc *SSLWrapper) InitSslConfig(cci ssl.CertGenerator) error {
	certFile, keyFile, err := cci.GenCert(sc.certFileName)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: make([]tls.Certificate, 1),
	}
	tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return errors.Wrapf(err, "load ssl cert %s", certFile)
	}
	sc.certConfig = tlsConfig
	return nil
}

func (sc *SSLWrapper) WrapSslConn(conn net.Conn) ssl.SslConn {
	if tc, ok := conn.(*TelemetryConn); ok {
		raw := tc.GetConn()
		newConn := tls.Server(raw, sc.certConfig)
		tc.UpdateConn(newConn)
		return tc
	}
	return tls.Server(conn, sc.certConfig)
}

func (sc *SSLWrapper) WrapSslListener(l net.Listener) net.Listener {
	if tl, ok := l.(*TelemetryListener); ok {
		raw := tl.GetListener()
		newL := tls.NewListener(raw, sc.certConfig)
		tl.UpdateListener(newL)
		return tl
	}
	return tls.NewListener(l, sc.certConfig)
}
