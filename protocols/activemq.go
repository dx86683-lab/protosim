package protocols

import (
	"bytes"
	"encoding/binary"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("activemq", ActiveMQ, 61616))
}

// ActiveMQ implements the Apache ActiveMQ OpenWire wire format greeting (TCP 61616).
func ActiveMQ(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	// Standard OpenWire WireFormatInfo frame:
	// [4-byte total len][1-byte type=0x01][8-byte magic "ActiveMQ"][4-byte version=12][4-byte tight/cache flags]
	var body bytes.Buffer
	body.WriteByte(0x01) // WIREFORMAT_INFO
	body.WriteString("ActiveMQ")
	_ = binary.Write(&body, binary.BigEndian, int32(12)) // OpenWire v12
	_ = binary.Write(&body, binary.BigEndian, int32(0))  // Empty marshalled properties

	frame := make([]byte, 4+body.Len())
	binary.BigEndian.PutUint32(frame[0:4], uint32(body.Len()))
	copy(frame[4:], body.Bytes())

	if _, err := sc.Conn.Write(frame); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	n, err := sc.Conn.Read(buf)
	if n > 0 {
		sc.LogWithRemote("activemq_openwire", sc.Conn.RemoteAddr(), logrus.Fields{
			"bytes_received": n,
		})
	}
	return err
}
