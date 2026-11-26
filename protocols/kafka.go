package protocols

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("kafka", Kafka, 9092))
}

// Kafka implements the Kafka binary wire protocol (ApiVersions v0-v2 & Metadata v0) on TCP 9092.
func Kafka(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	for {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(sc.Conn, lenBuf); err != nil {
			return err
		}
		pktLen := int(binary.BigEndian.Uint32(lenBuf))
		if pktLen < 8 || pktLen > 65536 {
			return nil
		}
		req := make([]byte, pktLen)
		if _, err := io.ReadFull(sc.Conn, req); err != nil {
			return err
		}

		apiKey := int16(binary.BigEndian.Uint16(req[0:2]))
		apiVer := int16(binary.BigEndian.Uint16(req[2:4]))
		corrID := int32(binary.BigEndian.Uint32(req[4:8]))

		sc.LogWithRemote("kafka_request", sc.Conn.RemoteAddr(), logrus.Fields{
			"api_key":        apiKey,
			"api_version":    apiVer,
			"correlation_id": corrID,
		})

		var body bytes.Buffer
		_ = binary.Write(&body, binary.BigEndian, corrID)

		switch apiKey {
		case 18: // ApiVersionsResponse (v0-v2)
			_ = binary.Write(&body, binary.BigEndian, int16(0)) // error_code = 0
			apis := [][3]int16{
				{0, 0, 9},   // Produce
				{1, 0, 12},  // Fetch
				{2, 0, 6},   // ListOffsets
				{3, 0, 11},  // Metadata
				{18, 0, 3},  // ApiVersions
			}
			_ = binary.Write(&body, binary.BigEndian, int32(len(apis)))
			for _, a := range apis {
				_ = binary.Write(&body, binary.BigEndian, a[0])
				_ = binary.Write(&body, binary.BigEndian, a[1])
				_ = binary.Write(&body, binary.BigEndian, a[2])
			}
			if apiVer >= 1 {
				_ = binary.Write(&body, binary.BigEndian, int32(0)) // throttle_time_ms
			}
		case 3: // MetadataResponse (v0)
			// Brokers array (1 broker)
			_ = binary.Write(&body, binary.BigEndian, int32(1))
			_ = binary.Write(&body, binary.BigEndian, int32(1)) // node_id
			host := "kafka-broker-1"
			_ = binary.Write(&body, binary.BigEndian, int16(len(host)))
			body.WriteString(host)
			_ = binary.Write(&body, binary.BigEndian, int32(9092))
			// Topics array (0 topics)
			_ = binary.Write(&body, binary.BigEndian, int32(0))
		default:
			// Generic error_code = 35 (UNSUPPORTED_VERSION)
			_ = binary.Write(&body, binary.BigEndian, int16(35))
		}

		frame := make([]byte, 4+body.Len())
		binary.BigEndian.PutUint32(frame[0:4], uint32(body.Len()))
		copy(frame[4:], body.Bytes())
		if _, err := sc.Conn.Write(frame); err != nil {
			return err
		}
	}
}
