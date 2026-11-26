package protocols

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"testing"
)

func TestRDPCredSSPSealingVector(t *testing.T) {
	// The signing key, sealing key and output are from MS-NLMP 4.2.3.4.
	stream := func() rdpCredSSPSeal {
		cipher, err := rc4.NewCipher(mustHex("04dd7f014d8504d265a25cc86a3a7c06"))
		if err != nil {
			t.Fatal(err)
		}
		return rdpCredSSPSeal{signing: mustHex("60e799be5c72fc92922ae8ebe961fb8d"), cipher: cipher}
	}
	plaintext := smbUTF16("Plaintext")
	packet := mustHex("01000000ff2aeb52f681793a00000000a02372f6530273f3aa1eb90190ce5200c99d")
	sender, receiver := stream(), stream()
	if got := sender.seal(plaintext); !bytes.Equal(got, packet) {
		t.Fatalf("sealed packet = %x, want %x", got, packet)
	}
	if got := receiver.open(packet); !bytes.Equal(got, plaintext) {
		t.Fatalf("decoded packet = %x, want %x", got, plaintext)
	}
	if receiver.open(packet) != nil {
		t.Fatal("replayed packet accepted")
	}
	packet[len(packet)-1] ^= 1
	receiver = stream()
	if receiver.open(packet) != nil {
		t.Fatal("modified packet accepted")
	}
}

func TestRDPCredSSPDelegatedCredentials(t *testing.T) {
	user, domain := smbUTF16("Fixture-User"), smbUTF16("FIXTURE-LAB")
	authenticate := make([]byte, 64, 64+len(user)+len(domain))
	copy(authenticate, smbNTLMSignature)
	binary.LittleEndian.PutUint32(authenticate[8:], 3)
	smbNTLMField(authenticate[28:], len(authenticate), len(domain))
	authenticate = append(authenticate, domain...)
	smbNTLMField(authenticate[36:], len(authenticate), len(user))
	authenticate = append(authenticate, user...)
	accounts := []string{"fixture-user:fixture-only"}
	for _, tc := range []struct {
		name                   string
		domain, user, password []byte
		kind                   int
		want                   bool
	}{
		{"configured account", domain, user, smbUTF16("fixture-only"), 1, true},
		{"different password", domain, user, smbUTF16("fixture-wrong"), 1, false},
		{"different identity", domain, smbUTF16("unknown-fixture"), smbUTF16("fixture-only"), 1, false},
		{"different domain", nil, user, smbUTF16("fixture-only"), 1, false},
		{"unsupported credential kind", domain, user, smbUTF16("fixture-only"), 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passwordCreds := berTLV(0x30, berTLV(0xa0, berTLV(4, tc.domain)),
				berTLV(0xa1, berTLV(4, tc.user)), berTLV(0xa2, berTLV(4, tc.password)))
			credentials := berTLV(0x30, berTLV(0xa0, berIntBytes(2, tc.kind)), berTLV(0xa1, berTLV(4, passwordCreds)))
			if got := rdpCredSSPPassword(credentials, authenticate, accounts); got != tc.want {
				t.Fatalf("delegated credential validation = %t, want %t", got, tc.want)
			}
		})
	}
}
