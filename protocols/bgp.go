package protocols

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("bgp", BGP, 179),
		ProtocolParams{
			Name:         "asn",
			DefaultValue: 65001,
		},
		ProtocolParams{
			Name:         "router_id",
			DefaultValue: "10.0.0.1",
		},
	)
}

// BGP implements RFC 4271 BGP-4 OPEN and KEEPALIVE handshake (TCP 179).
func BGP(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	asn := uint16(sc.GetIntParams("asn", 65001))
	routerID := net.ParseIP(sc.GetStringParams("router_id", "10.0.0.1")).To4()
	if routerID == nil {
		routerID = net.IPv4(10, 0, 0, 1).To4()
	}

	// Read 19-byte BGP header: 16-byte 0xFF marker + 2-byte length + 1-byte type
	hdr := make([]byte, 19)
	if _, err := io.ReadFull(sc.Conn, hdr); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		if hdr[i] != 0xff {
			return nil
		}
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[16:18]))
	msgType := hdr[18]
	if pktLen < 19 || pktLen > 4096 {
		return nil
	}
	body := make([]byte, pktLen-19)
	if len(body) > 0 {
		if _, err := io.ReadFull(sc.Conn, body); err != nil {
			return err
		}
	}

	fields := logrus.Fields{"msg_type": msgType, "length": pktLen}
	if msgType == 1 && len(body) >= 10 { // OPEN
		fields["bgp_version"] = body[0]
		fields["peer_asn"] = binary.BigEndian.Uint16(body[1:3])
		fields["hold_time"] = binary.BigEndian.Uint16(body[3:5])
		fields["peer_router_id"] = net.IP(body[5:9]).String()
	}
	sc.LogWithRemote("bgp_message", sc.Conn.RemoteAddr(), fields)

	// Send BGP OPEN (29 bytes) + KEEPALIVE (19 bytes)
	openMsg := make([]byte, 29)
	for i := 0; i < 16; i++ {
		openMsg[i] = 0xff
	}
	binary.BigEndian.PutUint16(openMsg[16:18], 29)
	openMsg[18] = 1 // OPEN
	openMsg[19] = 4 // BGP-4
	binary.BigEndian.PutUint16(openMsg[20:22], asn)
	binary.BigEndian.PutUint16(openMsg[22:24], 180) // Hold Time
	copy(openMsg[24:28], routerID)
	openMsg[28] = 0 // Optional parameters length

	keepalive := make([]byte, 19)
	for i := 0; i < 16; i++ {
		keepalive[i] = 0xff
	}
	binary.BigEndian.PutUint16(keepalive[16:18], 19)
	keepalive[18] = 4 // KEEPALIVE

	_, err := sc.Conn.Write(append(openMsg, keepalive...))
	return err
}
