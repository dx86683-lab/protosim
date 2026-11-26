package protocols

import (
	"encoding/asn1"
	"encoding/binary"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("kerberos", Kerberos, 88),
		ProtocolParams{
			Name:         "realm",
			DefaultValue: "CORP.LOCAL",
		},
	)
}

type krbPrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"general,explicit,tag:1"`
}

type krbError struct {
	PVNO      int              `asn1:"explicit,tag:0"`
	MsgType   int              `asn1:"explicit,tag:1"`
	STime     time.Time        `asn1:"generalized,explicit,tag:4"`
	SUSec     int              `asn1:"explicit,tag:5"`
	ErrorCode int32            `asn1:"explicit,tag:6"`
	Realm     string           `asn1:"general,explicit,tag:9"`
	SName     krbPrincipalName `asn1:"explicit,tag:10"`
}

// Kerberos implements RFC 4120 Kerberos v5 TCP framing (TCP 88) returning a standard KRB-ERROR (KDC_ERR_C_PRINCIPAL_UNKNOWN).
func Kerberos(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	realm := sc.GetStringParams("realm", "CORP.LOCAL")
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(sc.Conn, lenBuf); err != nil {
		return err
	}
	pktLen := int(binary.BigEndian.Uint32(lenBuf))
	if pktLen <= 0 || pktLen > 65536 {
		return nil
	}
	req := make([]byte, pktLen)
	if _, err := io.ReadFull(sc.Conn, req); err != nil {
		return err
	}

	sc.LogWithRemote("kerberos_request", sc.Conn.RemoteAddr(), logrus.Fields{
		"length": pktLen,
		"realm":  realm,
	})

	ke := krbError{
		PVNO:      5,
		MsgType:   30, // KRB_ERROR
		STime:     time.Now().UTC().Truncate(time.Second),
		SUSec:     0,
		ErrorCode: 6, // KDC_ERR_C_PRINCIPAL_UNKNOWN
		Realm:     realm,
		SName: krbPrincipalName{
			NameType:   2,
			NameString: []string{"krbtgt", realm},
		},
	}
	der, err := asn1.MarshalWithParams(ke, "application,explicit,tag:30")
	if err != nil {
		return err
	}

	frame := make([]byte, 4+len(der))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(der)))
	copy(frame[4:], der)
	_, err = sc.Conn.Write(frame)
	return err
}
