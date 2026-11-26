package protocols

import (
	"encoding/binary"
	"time"
)

const ntpEpochOffset = 2208988800

func init() {
	AddProtocol(NewProtocolInfo("ntp", serveNTP, 123))
}

func serveNTP(conn *UDPConnection, request []byte) error {
	// Only answer a complete unicast time header. The trailing data does not
	// affect the reference's fixed-size response.
	if len(request) < 48 || request[0]&7 != 3 {
		return nil
	}
	version := request[0] & 0x38
	leap := request[0] >> 6
	if version < 1<<3 || version > 4<<3 || leap == 1 || leap == 2 {
		return nil
	}

	now := time.Now()
	// RFC 5905 §6: 32-bit unsigned seconds since 1900-01-01 and 32-bit binary fraction of a second.
	seconds := uint32(now.Unix() + ntpEpochOffset)
	fraction := (uint64(now.Nanosecond()) << 32) / 1_000_000_000
	timestamp := uint64(seconds)<<32 | fraction
	var reply [48]byte
	reply[0], reply[1], reply[2], reply[3] = version|4, 1, request[2], 0xec
	copy(reply[12:], "NICT")
	binary.BigEndian.PutUint32(reply[16:20], seconds)
	copy(reply[24:32], request[40:48])
	binary.BigEndian.PutUint64(reply[32:], timestamp)
	binary.BigEndian.PutUint64(reply[40:], timestamp)
	_, err := conn.Write(reply[:])
	return err
}
