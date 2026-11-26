package protocols

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// RDP connection negotiation (X.224 Connection Request / Confirm). The
// reference selects CredSSP when the client offers it and standard RDP
// security otherwise; a request without RDP_NEG_REQ is rejected by closing.

const (
	rdpProtocolRDP    = 0
	rdpProtocolHybrid = 2
	rdpDefaultDomain  = "DESKTOP-Q1Test"
)

var rdpDefaultAccounts = []string{"administrator:123456"}

type rdpStandardOptions struct {
	requireAuth bool
	accounts    []string
	imageName   string
}

func init() {
	AddProtocol(NewProtocolInfo("rdp", serveRDP, 3389),
		ProtocolParams{Name: "domain_name", DefaultValue: rdpDefaultDomain},
		ProtocolParams{Name: "accounts", DefaultValue: rdpDefaultAccounts},
		ProtocolParams{Name: "sec_layer", DefaultValue: "auto"},
		ProtocolParams{Name: "auth", DefaultValue: false},
		ProtocolParams{Name: "image", DefaultValue: rdpDefaultImage})
}

func readTPKT(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 3 {
		return nil, errors.New("not a TPKT frame")
	}
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size < 4 || size > 65535 {
		return nil, errors.New("invalid TPKT length")
	}
	frame := make([]byte, size)
	copy(frame, header[:])
	_, err := io.ReadFull(r, frame[4:])
	return frame, err
}

func serveRDP(session *SessionConnection) error {
	defer session.DeleteActivity()
	layer := session.GetStringParams("sec_layer", "auto")
	switch layer {
	case "auto", "rdp", "credssp":
	default:
		return errors.New("unsupported RDP security layer")
	}
	if err := session.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	frame, err := readTPKT(session.Conn)
	if err != nil {
		return err
	}
	// TPKT(4) LI(1) CR(1) DST-REF(2) SRC-REF(2) CLASS(1) [cookie] RDP_NEG_REQ(8)
	if len(frame) < 19 || frame[5]&0xf0 != 0xe0 {
		return errors.New("expected X.224 connection request")
	}
	neg := frame[len(frame)-8:]
	if neg[0] != 1 || binary.LittleEndian.Uint16(neg[2:]) != 8 {
		return errors.New("missing RDP negotiation request")
	}
	clientProtocols := binary.LittleEndian.Uint32(neg[4:])
	hybridOffered := clientProtocols&rdpProtocolHybrid != 0
	if layer == "credssp" && !hybridOffered {
		return errors.New("RDP client did not offer CredSSP")
	}
	selected := uint32(rdpProtocolRDP)
	if layer != "rdp" && hybridOffered {
		selected = rdpProtocolHybrid
	}
	confirm := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(confirm[15:], selected)
	if _, err := session.Conn.Write(confirm); err != nil {
		return err
	}
	options := rdpStandardOptions{
		requireAuth: session.GetBoolParams("auth"),
		imageName:   session.GetStringParams("image", rdpDefaultImage),
	}
	if selected == rdpProtocolRDP {
		if options.requireAuth {
			options.accounts = session.GetStringsParams("accounts", rdpDefaultAccounts)
		}
		return serveRDPBasicSettings(session.Conn, options, 0)
	}
	if session.SslConnWraper == nil {
		return errors.New("RDP TLS configuration unavailable")
	}
	certificate := session.GetCert()
	if certificate == nil || len(certificate.Certificate) == 0 {
		return errors.New("RDP TLS certificate unavailable")
	}
	secure := session.WrapSslConn(session.Conn)
	session.Conn = secure
	if err := secure.Handshake(); err != nil {
		return err
	}
	if err := serveRDPCredSSP(secure, session.GetStringParams("domain_name", rdpDefaultDomain),
		certificate.Certificate[0], session.GetStringsParams("accounts", rdpDefaultAccounts)); err != nil {
		return err
	}
	return serveRDPBasicSettings(secure, options, clientProtocols)
}
