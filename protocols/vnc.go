package protocols

import (
	"crypto/des"
	"crypto/subtle"
	"errors"
	"io"
	"math/bits"
	"strconv"
	"time"
)

const (
	vncVersion   = "RFB 003.008\n"
	vncChallenge = "0123456789abcdef"
	vncPassword  = "123456"
)

func init() {
	AddProtocol(NewProtocolInfo("vnc", serveVNC, 5900),
		ProtocolParams{Name: "challenge", DefaultValue: vncChallenge},
		ProtocolParams{Name: "password", DefaultValue: vncPassword})
}

func serveVNC(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	challenge := session.GetStringParams("challenge", vncChallenge)
	if len(challenge) != 16 {
		return errors.New("VNC challenge must be 16 bytes")
	}
	if err := session.SendString(vncVersion); err != nil {
		return err
	}
	var version [12]byte
	if _, err := io.ReadFull(session.Conn, version[:]); err != nil {
		return err
	}
	minor, err := strconv.Atoi(string(version[8:11]))
	if string(version[:8]) != "RFB 003." || version[11] != '\n' || version[8] < '0' || version[8] > '9' || err != nil {
		return errors.New("unsupported RFB version")
	}
	hasSecurityTypes := minor >= 7
	hasFailureReason := minor >= 8
	if !hasSecurityTypes {
		if err := session.SendString("\x00\x00\x00\x02"); err != nil {
			return err
		}
	} else {
		if err := session.SendString("\x01\x02"); err != nil {
			return err
		}
		var choice [1]byte
		if _, err := io.ReadFull(session.Conn, choice[:]); err != nil || choice[0] != 2 {
			return err
		}
	}

	if err := session.SendString(challenge); err != nil {
		return err
	}
	var answer [16]byte
	if _, err := io.ReadFull(session.Conn, answer[:]); err != nil {
		return err
	}
	var key [8]byte
	copy(key[:], session.GetStringParams("password", vncPassword))
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	cipher, err := des.NewCipher(key[:])
	if err != nil {
		return err
	}
	var expected [16]byte
	cipher.Encrypt(expected[:8], []byte(challenge[:8]))
	cipher.Encrypt(expected[8:], []byte(challenge[8:]))
	if subtle.ConstantTimeCompare(answer[:], expected[:]) == 1 {
		if err := session.SendString("\x00\x00\x00\x00"); err != nil {
			return err
		}
		return serveVNCDesktop(session.Conn)
	}
	if hasFailureReason {
		return session.SendString("\x00\x00\x00\x01\x00\x00\x00\x10password invalid")
	}
	return session.SendString("\x00\x00\x00\x01")
}
