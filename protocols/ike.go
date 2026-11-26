package protocols

import (
	"crypto/rand"
	"encoding/binary"
)

// IKE answers every ISAKMP header with an informational exchange carrying a
// NO-PROPOSAL-CHOSEN notification, echoing the initiator SPI and version.

func init() {
	AddProtocol(NewProtocolInfo("ike", serveIKE, 500))
}

func serveIKE(conn *UDPConnection, request []byte) error {
	if len(request) < 28 {
		return nil
	}
	reply := make([]byte, 40)
	copy(reply[:8], request[:8])
	rand.Read(reply[8:16])
	reply[16] = 0x0b // Notification payload
	reply[17] = request[17]
	reply[18] = 0x05 // Informational
	rand.Read(reply[20:24])
	binary.BigEndian.PutUint32(reply[24:], 40)
	// Notification: length 12, DOI IPsec, protocol ISAKMP, NO-PROPOSAL-CHOSEN.
	copy(reply[28:], []byte{0, 0, 0, 12, 0, 0, 0, 1, 1, 0, 0, 14})
	_, err := conn.Write(reply)
	return err
}
