package protocols

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const smbNTLMSignature = "NTLMSSP\x00"

var (
	smbSPNEGOOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	smbNTLMOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

type smbNegTokenInit struct {
	Mechanisms []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	Flags      asn1.BitString          `asn1:"explicit,optional,tag:1"`
	Token      []byte                  `asn1:"explicit,tag:2"`
}

type smbNegTokenResp struct {
	State     asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	Mechanism asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	Token     []byte                `asn1:"explicit,tag:2"`
}

type smbNTLM struct {
	negotiate []byte
	challenge []byte
}

func (s *smbNTLM) begin(token []byte, server, domain string) []byte {
	var wrapper struct {
		Mechanism asn1.ObjectIdentifier
		Init      smbNegTokenInit `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.UnmarshalWithParams(token, &wrapper, "application,tag:0")
	hasNTLM := false
	for _, mech := range wrapper.Init.Mechanisms {
		if mech.Equal(smbNTLMOID) {
			hasNTLM = true
			break
		}
	}
	if err != nil || len(rest) != 0 || !wrapper.Mechanism.Equal(smbSPNEGOOID) || !hasNTLM {
		return nil
	}
	request := wrapper.Init.Token
	if !smbNTLMType(request, 1, 32) {
		return nil
	}

	le := binary.LittleEndian
	target := smbUTF16(domain)
	var info []byte
	for i, name := range []string{server, domain, strings.ToLower(server), domain} {
		value := smbUTF16(name)
		if len(value) > 65535 {
			return nil
		}
		info = le.AppendUint16(info, uint16(i+1))
		info = le.AppendUint16(info, uint16(len(value)))
		info = append(info, value...)
	}
	info = append(info, 0, 0, 0, 0)
	const fixedSize = 56
	if fixedSize+len(target)+len(info) > 65000 {
		return nil
	}
	challenge := make([]byte, fixedSize, fixedSize+len(target)+len(info))
	copy(challenge, smbNTLMSignature)
	le.PutUint32(challenge[8:], 2)
	smbNTLMField(challenge[12:], fixedSize, len(target))
	le.PutUint32(challenge[20:], 0xe2898215) // Flags advertised by the reference.
	rand.Read(challenge[24:32])
	smbNTLMField(challenge[40:], fixedSize+len(target), len(info))
	copy(challenge[48:], []byte{6, 1, 0, 0, 0, 0, 0, 15})
	challenge = append(challenge, target...)
	challenge = append(challenge, info...)

	result, err := asn1.MarshalWithParams(smbNegTokenResp{
		State: 1, Mechanism: smbNTLMOID, Token: challenge,
	}, "explicit,tag:1")
	if err != nil {
		return nil
	}
	s.negotiate, s.challenge = request, challenge
	return result
}

func (s *smbNTLM) authenticate(token []byte, accounts []string) []byte {
	var response smbNegTokenResp
	rest, err := asn1.UnmarshalWithParams(token, &response, "explicit,tag:1")
	if err != nil || len(rest) != 0 || !smbNTLMType(response.Token, 3, 64) {
		return nil
	}
	return s.authenticateMessage(response.Token, accounts)
}

func (s *smbNTLM) authenticateMessage(request []byte, accounts []string) []byte {
	if !smbNTLMType(request, 3, 64) || len(s.challenge) < 32 {
		return nil
	}
	nt, ntOffset := smbNTLMValue(request, 20)
	domain, _ := smbNTLMValue(request, 28)
	user, userOffset := smbNTLMValue(request, 36)
	if len(nt) < 48 || nt[16] != 1 || nt[17] != 1 || userOffset == 0 ||
		len(user) == 0 || len(user)%2 != 0 || len(domain)%2 != 0 {
		return nil
	}

	username := smbDecodeUTF16(user)
	var password string
	found := false
	for _, account := range accounts {
		accountUser, secret, ok := strings.Cut(account, ":")
		if ok && strings.EqualFold(username, accountUser) {
			password, found = secret, true
			break
		}
	}
	if !found {
		return nil
	}
	hash := md4.New()
	hash.Write(smbUTF16(password))
	responseKey := smbNTLMMAC(hash.Sum(nil), smbUTF16(strings.ToUpper(username)), domain)
	proof := smbNTLMMAC(responseKey, s.challenge[24:32], nt[16:])
	if !hmac.Equal(proof, nt[:16]) {
		return nil
	}

	key := smbNTLMMAC(responseKey, proof)
	le := binary.LittleEndian
	flags := le.Uint32(request[60:])
	const keyExchange = 1 << 30
	if flags&keyExchange != 0 {
		encrypted, _ := smbNTLMValue(request, 52)
		if len(encrypted) != 16 {
			return nil
		}
		// NTLMv2 uses a 16-byte session base key for RC4 key exchange.
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			return nil
		}
		cipher.XORKeyStream(key, encrypted)
	}
	micOffset := 64
	if flags&(1<<25) != 0 {
		micOffset += 8
	}
	payload := min(ntOffset, userOffset)
	for _, field := range []int{12, 28, 44, 52} {
		if value, offset := smbNTLMValue(request, field); len(value) != 0 {
			payload = min(payload, offset)
		}
	}
	micRequired := smbNTLMMICRequired(nt)
	if payload >= micOffset+16 {
		var zero [16]byte
		mic := request[micOffset : micOffset+16]
		if micRequired || !hmac.Equal(mic, zero[:]) {
			expected := smbNTLMMAC(key, s.negotiate, s.challenge, request[:micOffset], zero[:], request[micOffset+16:])
			if !hmac.Equal(mic, expected) {
				return nil
			}
		}
	} else if micRequired {
		return nil
	}
	return key
}

func smbNTLMMICRequired(nt []byte) bool {
	if len(nt) < 44 {
		return false
	}
	av := nt[44:]
	le := binary.LittleEndian
	for len(av) >= 4 {
		avID := le.Uint16(av[0:2])
		avLen := int(le.Uint16(av[2:4]))
		av = av[4:]
		if avID == 0 {
			break
		}
		if avLen > len(av) {
			break
		}
		if avID == 6 && avLen >= 4 { // MsvAvFlags
			return le.Uint32(av[:4])&0x00000002 != 0
		}
		av = av[avLen:]
	}
	return false
}

func smbNTLMType(wire []byte, messageType uint32, minimum int) bool {
	return len(wire) >= minimum && string(wire[:8]) == smbNTLMSignature &&
		binary.LittleEndian.Uint32(wire[8:]) == messageType
}

func smbNTLMField(field []byte, offset, length int) {
	binary.LittleEndian.PutUint16(field, uint16(length))
	binary.LittleEndian.PutUint16(field[2:], uint16(length))
	binary.LittleEndian.PutUint32(field[4:], uint32(offset))
}

func smbNTLMValue(wire []byte, field int) ([]byte, int) {
	le := binary.LittleEndian
	size, offset := int(le.Uint16(wire[field:])), uint64(le.Uint32(wire[field+4:]))
	if size == 0 || offset < 64 || offset > uint64(len(wire)) || uint64(size) > uint64(len(wire))-offset {
		return nil, 0
	}
	start := int(offset)
	return wire[start : start+size], start
}

func smbNTLMMAC(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}

func smbUTF16(name string) []byte {
	var wire []byte
	for _, unit := range utf16.Encode([]rune(name)) {
		wire = binary.LittleEndian.AppendUint16(wire, unit)
	}
	return wire
}

func smbDecodeUTF16(wire []byte) string {
	units := make([]uint16, len(wire)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(wire[2*i:])
	}
	return string(utf16.Decode(units))
}
