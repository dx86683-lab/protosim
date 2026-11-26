package protocols

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	rdpCredSSPVersion          = 6
	rdpCredSSPMaxInitialPDU    = 4096
	rdpCredSSPMaxAuthPDU       = 16384
	rdpNTLMChallengeHeader     = 56
	rdpNTLMFlags               = 0xe28a8235
	rdpNTLMMaxTargetUTF16Bytes = (65535 - 128) / 5
)

var errRDPCredSSPNegotiate = errors.New("invalid initial RDP CredSSP negotiation")
var errRDPCredSSPAuth = errors.New("RDP CredSSP authentication failed")

func serveRDPCredSSP(conn io.ReadWriter, domain string, certificate []byte, accounts []string) error {
	version, request, err := readRDPCredSSP(conn, rdpCredSSPMaxInitialPDU)
	if err != nil {
		return err
	}
	if len(request) != 1 && !(version >= 5 && len(request) == 2 && len(rdpCredSSPOctets(request[1], 0xa5)) == sha256.Size) {
		return errRDPCredSSPNegotiate
	}
	negotiate := rdpCredSSPToken(request[0])
	if !smbNTLMType(negotiate, 1, 32) {
		return errRDPCredSSPNegotiate
	}
	challenge, err := rdpNTLMChallenge(domain)
	if err != nil {
		return err
	}
	if err := writeRDPCredSSP(conn, berTLV(0xa1, berTLV(0x30, berTLV(0x30, berTLV(0xa0, berTLV(4, challenge)))))); err != nil {
		return err
	}
	effectiveVersion := min(version, rdpCredSSPVersion)
	return authenticateRDPCredSSP(conn, effectiveVersion, certificate, accounts, smbNTLM{negotiate: negotiate, challenge: challenge})
}

func readRDPCredSSP(conn io.Reader, limit int) (int, []berElement, error) {
	wire, err := readBERMessageLimit(conn, limit)
	if err != nil {
		return 0, nil, err
	}
	request, err := decodeBER(wire)
	if err != nil || request.Tag != 0x30 || len(request.Children) < 2 {
		return 0, nil, errRDPCredSSPNegotiate
	}
	version, ok := rdpCredSSPField(request.Children[0], 0xa0)
	if !ok || version.Tag != 2 || len(version.Value) == 0 || len(version.Value) > 4 || berInt(version) < 2 {
		return 0, nil, errRDPCredSSPNegotiate
	}
	return berInt(version), request.Children[1:], nil
}

func writeRDPCredSSP(conn io.Writer, field []byte) error {
	_, err := conn.Write(berTLV(0x30, berTLV(0xa0, berIntBytes(2, rdpCredSSPVersion)), field))
	return err
}

func rdpCredSSPToken(field berElement) []byte {
	items, ok := rdpCredSSPField(field, 0xa1)
	if !ok {
		return nil
	}
	item, ok := rdpCredSSPField(items, 0x30)
	if !ok {
		return nil
	}
	nego, ok := rdpCredSSPField(item, 0x30)
	if !ok {
		return nil
	}
	return rdpCredSSPOctets(nego, 0xa0)
}

func rdpCredSSPOctets(field berElement, tag byte) []byte {
	value, ok := rdpCredSSPField(field, tag)
	if !ok || value.Tag != 4 {
		return nil
	}
	return value.Value
}

func authenticateRDPCredSSP(conn io.ReadWriter, version int, certificate []byte, accounts []string, ntlm smbNTLM) error {
	replyVersion, fields, err := readRDPCredSSP(conn, rdpCredSSPMaxAuthPDU)
	if err != nil {
		return err
	}
	modern := version >= 5
	expectedFields := 2
	if modern {
		expectedFields++
	}
	if replyVersion != version || len(fields) != expectedFields {
		return errRDPCredSSPAuth
	}
	message := rdpCredSSPToken(fields[0])
	const requiredFlags uint32 = 0x20080030 // 128-bit session security, extended security, sign and seal.
	if !smbNTLMType(message, 3, 64) || binary.LittleEndian.Uint32(message[60:])&requiredFlags != requiredFlags {
		return errRDPCredSSPAuth
	}
	key := ntlm.authenticateMessage(message, accounts)
	if len(key) == 0 {
		if version >= 3 {
			const statusLogonFailure = 0xc000006d - 1<<32
			_ = writeRDPCredSSP(conn, berTLV(0xa4, berIntBytes(2, statusLogonFailure)))
		}
		return errRDPCredSSPAuth
	}
	defer clear(key)
	var nonce []byte
	if modern {
		nonce = rdpCredSSPOctets(fields[2], 0xa5)
		if len(nonce) != sha256.Size {
			return errRDPCredSSPAuth
		}
	}
	publicKey, err := rdpCredSSPPublicKey(certificate)
	if err != nil {
		return err
	}
	clientBinding, serverBinding := rdpCredSSPBindings(publicKey, nonce)
	keyExchange := binary.LittleEndian.Uint32(message[60:])&(1<<30) != 0
	client, err := newRDPCredSSPSeal(key, "client-to-server", keyExchange)
	if err != nil {
		return err
	}
	server, err := newRDPCredSSPSeal(key, "server-to-client", keyExchange)
	if err != nil {
		return err
	}
	binding := client.open(rdpCredSSPOctets(fields[1], 0xa3))
	if !hmac.Equal(clientBinding, binding) {
		return errRDPCredSSPAuth
	}
	if err := writeRDPCredSSP(conn, berTLV(0xa3, berTLV(4, server.seal(serverBinding)))); err != nil {
		return err
	}
	credentialsVersion, credentials, err := readRDPCredSSP(conn, rdpCredSSPMaxAuthPDU)
	if err != nil {
		return err
	}
	if credentialsVersion != version || len(credentials) != 1 &&
		!(modern && len(credentials) == 2 && hmac.Equal(nonce, rdpCredSSPOctets(credentials[1], 0xa5))) {
		return errRDPCredSSPAuth
	}
	plain := client.open(rdpCredSSPOctets(credentials[0], 0xa2))
	defer clear(plain)
	if !rdpCredSSPPassword(plain, message, accounts) {
		return errRDPCredSSPAuth
	}
	return nil
}

func rdpCredSSPPublicKey(certificate []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 || len(spki.Key.Bytes) == 0 {
		return nil, errRDPCredSSPAuth
	}
	return spki.Key.Bytes, nil
}

func rdpCredSSPBindings(publicKey, nonce []byte) (client, server []byte) {
	if nonce == nil {
		response := append([]byte(nil), publicKey...)
		response[0]++
		return publicKey, response
	}
	hash := func(direction string) []byte {
		digest := sha256.New()
		digest.Write([]byte("CredSSP " + direction + " Binding Hash\x00"))
		digest.Write(nonce)
		digest.Write(publicKey)
		return digest.Sum(nil)
	}
	return hash("Client-To-Server"), hash("Server-To-Client")
}

func rdpCredSSPPassword(plain, authenticate []byte, accounts []string) bool {
	var credentials struct {
		Kind int    `asn1:"explicit,tag:0"`
		Data []byte `asn1:"explicit,tag:1"`
	}
	if rest, err := asn1.Unmarshal(plain, &credentials); err != nil || len(rest) != 0 || credentials.Kind != 1 {
		return false
	}
	var logon struct {
		Domain   []byte `asn1:"explicit,tag:0"`
		Username []byte `asn1:"explicit,tag:1"`
		Password []byte `asn1:"explicit,tag:2"`
	}
	if rest, err := asn1.Unmarshal(credentials.Data, &logon); err != nil || len(rest) != 0 || len(logon.Password)%2 != 0 {
		return false
	}
	user, _ := smbNTLMValue(authenticate, 36)
	domain, _ := smbNTLMValue(authenticate, 28)
	if !hmac.Equal(user, logon.Username) || !hmac.Equal(domain, logon.Domain) {
		return false
	}
	username := smbDecodeUTF16(user)
	for _, account := range accounts {
		name, password, ok := strings.Cut(account, ":")
		if ok && strings.EqualFold(name, username) {
			expected := smbUTF16(password)
			matches := hmac.Equal(expected, logon.Password)
			clear(expected)
			return matches
		}
	}
	return false
}

type rdpCredSSPSeal struct {
	signing     []byte
	cipher      *rc4.Cipher
	sequence    uint32
	keyExchange bool
}

func newRDPCredSSPSeal(key []byte, direction string, keyExchange bool) (rdpCredSSPSeal, error) {
	sealing := rdpMD5(key, []byte("session key to "+direction+" sealing key magic constant\x00"))
	cipher, err := rc4.NewCipher(sealing)
	clear(sealing)
	if err != nil {
		return rdpCredSSPSeal{}, err
	}
	signing := rdpMD5(key, []byte("session key to "+direction+" signing key magic constant\x00"))
	return rdpCredSSPSeal{signing: signing, cipher: cipher, keyExchange: keyExchange}, nil
}

func (s *rdpCredSSPSeal) signature(message []byte) []byte {
	var sequence [4]byte
	binary.LittleEndian.PutUint32(sequence[:], s.sequence)
	s.sequence++
	checksum := smbNTLMMAC(s.signing, sequence[:], message)[:8]
	if s.keyExchange {
		s.cipher.XORKeyStream(checksum, checksum)
	}
	return append(append([]byte{1, 0, 0, 0}, checksum...), sequence[:]...)
}

func (s *rdpCredSSPSeal) seal(message []byte) []byte {
	sealed := make([]byte, 16+len(message))
	s.cipher.XORKeyStream(sealed[16:], message)
	copy(sealed, s.signature(message))
	return sealed
}

func (s *rdpCredSSPSeal) open(sealed []byte) []byte {
	if len(sealed) <= 16 {
		return nil
	}
	message := make([]byte, len(sealed)-16)
	s.cipher.XORKeyStream(message, sealed[16:])
	if !hmac.Equal(sealed[:16], s.signature(message)) {
		clear(message)
		return nil
	}
	return message
}

func rdpCredSSPField(element berElement, tag byte) (berElement, bool) {
	if element.Tag != tag || len(element.Children) != 1 {
		return berElement{}, false
	}
	return element.Children[0], true
}

func rdpNTLMChallenge(domain string) ([]byte, error) {
	target := smbUTF16(domain)
	if len(target) > rdpNTLMMaxTargetUTF16Bytes {
		return nil, errRDPCredSSPNegotiate
	}
	challenge := make([]byte, rdpNTLMChallengeHeader, rdpNTLMChallengeHeader+5*len(target)+32)
	copy(challenge, smbNTLMSignature)
	le := binary.LittleEndian
	le.PutUint32(challenge[8:], 2)
	smbNTLMField(challenge[12:], rdpNTLMChallengeHeader, len(target))
	le.PutUint32(challenge[20:], rdpNTLMFlags)
	if _, err := rand.Read(challenge[24:32]); err != nil {
		return nil, err
	}
	copy(challenge[48:], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 15})
	challenge = append(challenge, target...)
	infoOffset := len(challenge)
	for id := uint16(1); id <= 4; id++ {
		challenge = le.AppendUint16(challenge, id)
		challenge = le.AppendUint16(challenge, uint16(len(target)))
		challenge = append(challenge, target...)
	}
	challenge = le.AppendUint16(challenge, 7)
	challenge = le.AppendUint16(challenge, 8)
	now := time.Now()
	fileTime := (uint64(now.Unix()) + 11644473600) * 10000000
	challenge = le.AppendUint64(challenge, fileTime+uint64(now.Nanosecond()/100))
	challenge = le.AppendUint32(challenge, 0)
	smbNTLMField(challenge[40:], infoOffset, len(challenge)-infoOffset)
	return challenge, nil
}
