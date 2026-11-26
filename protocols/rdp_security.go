package protocols

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

type rdpIdentity struct {
	key         *rsa.PrivateKey
	certificate []byte
}

var rdpStandardIdentity = sync.OnceValues(newRDPIdentity)

func newRDPIdentity() (*rdpIdentity, error) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ProtoSim RDP Issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ProtoSim RDP"},
		NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	chain := binary.LittleEndian.AppendUint32(nil, 0x80000002)
	chain = binary.LittleEndian.AppendUint32(chain, 2)
	for _, der := range [][]byte{rootDER, leafDER} {
		chain = binary.LittleEndian.AppendUint32(chain, uint32(len(der)))
		chain = append(chain, der...)
	}
	return &rdpIdentity{key: key, certificate: append(chain, make([]byte, 16)...)}, nil
}

const (
	rdpSecExchange       = 0x0001
	rdpSecEncrypt        = 0x0008
	rdpSecInfo           = 0x0040
	rdpSecLicense        = 0x0080
	rdpSecLicenseEncrypt = 0x0200
	rdpSecSecureChecksum = 0x0800
)

var errRDPStandardSecurity = errors.New("invalid RDP standard security exchange")

// The capability set describes the simulated desktop before client activation.
var rdpDemandActive = mustHex(
	"67011100ea03ea03000004005101524450000d00000009000800ea03000001001800010003000002000000000c00000000000000" +
		"01011400080002000000160028000000000000000000010000000000000000000000000000000000000000000000000000000e00" +
		"040002001c0018000100010001000005000400000000010000000100000003005800000000000000000000000000000000000000" +
		"00000100140000000100000022000101010101000001010101010000000101010101010101000101010100000000000000000000" +
		"000040420f0000000000000000000a00080006000000120008000100000008000a000100190019000d0058000500000000000000" +
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000170008000000000018000b000000000000000000000000")

var rdpLicenseValidClient = mustHex("ff031000070000000200000004000000")

func serveRDPStandardSecurity(conn io.ReadWriter, user uint16, identity *rdpIdentity, serverRandom []byte, options rdpStandardOptions) error {
	exchange, err := readRDPSecurityData(conn, user)
	if err != nil {
		return err
	}
	if len(exchange) < 8 || binary.LittleEndian.Uint16(exchange)&^uint16(rdpSecLicenseEncrypt) != rdpSecExchange ||
		binary.LittleEndian.Uint32(exchange[4:]) != uint32(len(exchange)-8) {
		return errRDPStandardSecurity
	}
	clientRandom, err := rdpDecryptClientRandom(identity.key, exchange[8:])
	if err != nil {
		return err
	}
	keys := newRDPStandardKeys(clientRandom, serverRandom)
	clear(clientRandom)
	info, err := readRDPSecurityData(conn, user)
	if err != nil {
		return err
	}
	if len(info) < 12 || binary.LittleEndian.Uint16(info)&^uint16(rdpSecSecureChecksum) != rdpSecInfo|rdpSecEncrypt {
		return errRDPStandardSecurity
	}
	plain, err := keys.open(info)
	if err != nil {
		return err
	}
	valid := acceptRDPClientInfo(plain, options)
	clear(plain)
	if !valid {
		return errRDPStandardSecurity
	}
	return finishRDPConnection(conn, user, &keys, options.imageName)
}

func serveRDPEnhancedSecurity(conn io.ReadWriter, user uint16, imageName string) error {
	info, err := readRDPSecurityData(conn, user)
	if err != nil {
		return err
	}
	if len(info) < 4 || binary.LittleEndian.Uint16(info)&^uint16(rdpSecEncrypt) != rdpSecInfo ||
		!acceptRDPClientInfo(info[4:], rdpStandardOptions{}) {
		return errRDPStandardSecurity
	}
	return finishRDPConnection(conn, user, nil, imageName)
}

func finishRDPConnection(conn io.ReadWriter, user uint16, keys *rdpStandardKeys, imageName string) error {
	if err := writeRDPSecurityData(conn, user, keys, rdpSecLicense, rdpLicenseValidClient); err != nil {
		return err
	}
	if err := writeRDPSecurityData(conn, user, keys, 0, rdpDemandActive); err != nil {
		return err
	}
	return serveRDPActivation(conn, user, keys, imageName)
}

const (
	rdpInfoUnicode      = 0x10
	rdpInfoSmartCardPIN = 0x00040000
)

func acceptRDPClientInfo(info []byte, options rdpStandardOptions) bool {
	if len(info) < 18 {
		return false
	}
	terminatorSize := 1
	flags := binary.LittleEndian.Uint32(info[4:])
	unicode := flags&rdpInfoUnicode != 0
	if unicode {
		terminatorSize = 2
	}
	offset := 18
	var fields [5][]byte
	for i := range fields {
		size := int(binary.LittleEndian.Uint16(info[8+2*i:]))
		end := offset + size + terminatorSize
		if size%terminatorSize != 0 || end > len(info) || !bytes.Equal(info[end-terminatorSize:end], []byte{0, 0}[:terminatorSize]) {
			return false
		}
		fields[i] = info[offset : offset+size]
		offset = end
	}
	if !options.requireAuth {
		return true
	}
	if flags&rdpInfoSmartCardPIN != 0 || len(fields[1]) == 0 {
		return false
	}
	codePage := binary.LittleEndian.Uint32(info)
	if !unicode {
		if codePage != 0 && codePage != 1252 {
			return false
		}
		nonASCII := func(r rune) bool { return r > 0x7f }
		if bytes.IndexFunc(fields[1], nonASCII) >= 0 || bytes.IndexFunc(fields[2], nonASCII) >= 0 {
			return false
		}
	}
	for _, account := range options.accounts {
		name, password, ok := strings.Cut(account, ":")
		if !ok {
			continue
		}
		if !bytes.Equal(encodeRDPAccountField(name, unicode), fields[1]) {
			continue
		}
		passwordWire := encodeRDPAccountField(password, unicode)
		matches := subtle.ConstantTimeCompare(passwordWire, fields[2]) == 1
		clear(passwordWire)
		if matches {
			return true
		}
	}
	return false
}

func encodeRDPAccountField(value string, unicode bool) []byte {
	if !unicode {
		return []byte(value)
	}
	var wire []byte
	for _, unit := range utf16.Encode([]rune(value)) {
		wire = binary.LittleEndian.AppendUint16(wire, unit)
	}
	return wire
}

func readRDPSecurityData(conn io.Reader, user uint16) ([]byte, error) {
	request, err := readRDPData(conn)
	if err != nil {
		return nil, err
	}
	if len(request) < 7 || request[0] != 0x64 || binary.BigEndian.Uint16(request[1:]) != user ||
		binary.BigEndian.Uint16(request[3:]) != rdpGlobalChannel || request[5]&0x30 != 0x30 {
		return nil, errRDPStandardSecurity
	}
	data := readRDPPerPayload(request[6:])
	if len(data) == 0 {
		return nil, errRDPStandardSecurity
	}
	return data, nil
}

func writeRDPSecurityData(conn io.Writer, user uint16, keys *rdpStandardKeys, flags uint16, plain []byte) error {
	if keys == nil {
		if flags&rdpSecLicense != 0 {
			plain = append(binary.LittleEndian.AppendUint32(nil, uint32(rdpSecLicense)), plain...)
		}
		return writeRDPMCSData(conn, user, plain)
	}
	data := binary.LittleEndian.AppendUint32(nil, uint32(flags|rdpSecEncrypt))
	data = append(data, rdpMAC(keys.mac, plain, flags&rdpSecSecureChecksum != 0, keys.sent)...)
	keys.sent++
	ciphertext := make([]byte, len(plain))
	keys.encrypt.XORKeyStream(ciphertext, plain)
	return writeRDPMCSData(conn, user, append(data, ciphertext...))
}

func writeRDPMCSData(conn io.Writer, user uint16, data []byte) error {
	request := binary.BigEndian.AppendUint16([]byte{0x68}, user)
	request = binary.BigEndian.AppendUint16(request, rdpGlobalChannel)
	request = append(request, 0x70)
	length := uint16(len(data))
	if length >= 128 {
		request = binary.BigEndian.AppendUint16(request, length|0x8000)
	} else {
		request = append(request, byte(length))
	}
	return writeRDPData(conn, append(request, data...))
}

// Standard RDP encodes an unpadded little-endian RSA value. Blind the
// private-key operation and keep this key separate from every TLS identity.
func rdpDecryptClientRandom(key *rsa.PrivateKey, encoded []byte) ([]byte, error) {
	size := key.Size()
	if len(encoded) != size+8 || !bytes.Equal(encoded[size:], make([]byte, 8)) {
		return nil, errRDPStandardSecurity
	}
	reversed := bytes.Clone(encoded[:size])
	slices.Reverse(reversed)
	ciphertext := new(big.Int).SetBytes(reversed)
	if ciphertext.Sign() == 0 || ciphertext.Cmp(key.N) >= 0 {
		return nil, errRDPStandardSecurity
	}
	var blinder, inverse *big.Int
	for inverse == nil {
		var err error
		blinder, err = rand.Int(rand.Reader, key.N)
		if err != nil {
			return nil, err
		}
		inverse = new(big.Int).ModInverse(blinder, key.N)
	}
	exponent := big.NewInt(int64(key.E))
	blinded := new(big.Int).Exp(blinder, exponent, key.N)
	blinded.Mul(blinded, ciphertext).Mod(blinded, key.N)
	value := new(big.Int).Exp(blinded, key.D, key.N)
	value.Mul(value, inverse).Mod(value, key.N)
	if value.BitLen() > 256 || new(big.Int).Exp(value, exponent, key.N).Cmp(ciphertext) != 0 {
		return nil, errRDPStandardSecurity
	}
	random := value.FillBytes(make([]byte, 32))
	slices.Reverse(random)
	return random, nil
}

type rdpStandardKeys struct {
	mac              []byte
	encrypt, decrypt *rc4.Cipher
	sent, received   uint32
}

func (keys *rdpStandardKeys) open(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errRDPStandardSecurity
	}
	flags := binary.LittleEndian.Uint16(data)
	if flags&rdpSecEncrypt == 0 {
		return nil, errRDPStandardSecurity
	}
	plain := data[12:]
	keys.decrypt.XORKeyStream(plain, plain)
	mac := rdpMAC(keys.mac, plain, flags&rdpSecSecureChecksum != 0, keys.received)
	keys.received++
	if subtle.ConstantTimeCompare(data[4:12], mac) != 1 {
		clear(plain)
		return nil, errRDPStandardSecurity
	}
	return plain, nil
}

func newRDPStandardKeys(client, server []byte) rdpStandardKeys {
	expand := func(secret []byte, labels ...string) []byte {
		result := make([]byte, 0, 48)
		for _, label := range labels {
			hash := sha1.New()
			hash.Write([]byte(label))
			hash.Write(secret)
			hash.Write(client)
			hash.Write(server)
			result = append(result, rdpMD5(secret, hash.Sum(nil))...)
		}
		return result
	}
	preMaster := append(bytes.Clone(client[:24]), server[:24]...)
	master := expand(preMaster, "A", "BB", "CCC")
	keys := expand(master, "X", "YY", "ZZZ")
	encrypt, _ := rc4.NewCipher(rdpMD5(keys[16:32], client, server))
	decrypt, _ := rc4.NewCipher(rdpMD5(keys[32:48], client, server))
	return rdpStandardKeys{mac: keys[:16], encrypt: encrypt, decrypt: decrypt}
}

func rdpMD5(parts ...[]byte) []byte {
	hash := md5.New()
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}

func rdpMAC(key, data []byte, salted bool, count uint32) []byte {
	sha := sha1.New()
	sha.Write(key)
	sha.Write(bytes.Repeat([]byte{0x36}, 40))
	sha.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(data))))
	sha.Write(data)
	if salted {
		sha.Write(binary.LittleEndian.AppendUint32(nil, count))
	}
	return rdpMD5(key, bytes.Repeat([]byte{0x5c}, 48), sha.Sum(nil))[:8]
}
