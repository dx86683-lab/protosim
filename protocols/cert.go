package protocols

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type CertNameConf struct {
	Org     string `json:"org" mapstructure:"org"`
	Name    string `json:"name" mapstructure:"name"`
	Country string `json:"country" mapstructure:"country"`
}

type CertConfInfo struct {
	Issuer  CertNameConf `json:"issuer" mapstructure:"issuer"`
	Subject CertNameConf `json:"subject" mapstructure:"subject"`
}

var DefaultCertInfo = &CertConfInfo{
	Issuer:  CertNameConf{Name: "localhost"},
	Subject: CertNameConf{Name: "localhost"},
}

func SetCertCommonName(cn string) {
	DefaultCertInfo.Subject.Name = cn
}

func (cci *CertConfInfo) GenCert(target string) (certFile, keyFile string, err error) {
	certFile = target + ".crt"
	keyFile = target + ".key"
	_, e1 := os.Stat(certFile)
	_, e2 := os.Stat(keyFile)
	if (e1 != nil && os.IsNotExist(e1)) || (e2 != nil && os.IsNotExist(e2)) {
		cert, key, err := cci.certWithKeyPair()
		if err != nil {
			logrus.Fatalf("[TLS] failed to generate test certificates: %v", err)
		}
		if err := ioutil.WriteFile(certFile, cert, 0644); err != nil {
			logrus.Fatalf("[TLS] failed to write cert fixture to %s: %v", certFile, err)
		}
		if err := ioutil.WriteFile(keyFile, key, 0644); err != nil {
			logrus.Fatalf("[TLS] failed to write key fixture to %s: %v", keyFile, err)
		}
	}

	return
}

func (cci *CertConfInfo) certWithKeyPair() ([]byte, []byte, error) {
	bits := 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	issuer := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if cci.Issuer.Name != "" {
		issuer.Subject.CommonName = cci.Issuer.Name
	}
	if cci.Issuer.Country != "" {
		issuer.Subject.Country = []string{cci.Issuer.Country}
	}
	if cci.Issuer.Org != "" {
		issuer.Subject.Organization = []string{cci.Issuer.Org}
	}

	subject := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if cci.Subject.Name != "" {
		subject.Subject.CommonName = cci.Subject.Name
	}
	if cci.Subject.Country != "" {
		subject.Subject.Country = []string{cci.Subject.Country}
	}
	if cci.Subject.Org != "" {
		subject.Subject.Organization = []string{cci.Subject.Org}
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &subject, &issuer, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	buf := &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return nil, nil, err
	}

	pemCert := buf.Bytes()

	buf = &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, err
	}
	pemKey := buf.Bytes()

	return pemCert, pemKey, nil
}
