package protocols

import (
	"bufio"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

const geSRTPFrame = 56

var geSRTPFields = [...]struct {
	name     string
	width    int
	reserved bool
}{
	{"Type", 1, false}, {"Reserved1", 1, true},
	{"Seq", 1, false}, {"Reserved2", 1, true},
	{"TextLen", 1, false}, {"Reserved3", 3, true},
	{"Unk0", 1, false}, {"Unk1", 1, false}, {"Reserved5", 7, true},
	{"Unk2", 1, false}, {"Reserved7", 8, true},
	{"TimeS", 1, false}, {"TimeM", 1, false}, {"TimeH", 1, false},
	{"Reserved8", 1, true}, {"Seq2", 1, false}, {"MsgType", 1, false},
	{"MailboxSrc", 4, false}, {"MailboxDst", 4, false},
	{"PacketNo", 1, false}, {"TotalPacketNo", 1, false},
	{"Code", 1, false}, {"Data", 13, false},
}

func init() {
	AddProtocol(NewProtocolInfo("ge-srtp", serveGESRTP, 18245))
}

func serveGESRTP(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	reader := bufio.NewReader(session.Conn)
	for {
		frame, err := readGESRTPHeader(reader)
		if err != nil {
			return err
		}
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "message", logrus.Fields{
			"type": frame[0], "seq": frame[2], "msg_type": frame[31],
			"packet_no": frame[40], "code": geSRTPServiceName(frame[42]),
		})
		switch frame[0] {
		case 0:
			frame[0] = 1
		case 2:
			frame[0] = 3
		}
		frame[42] = 0
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		n, err := session.Conn.Write(frame[:])
		if err != nil {
			return err
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
	}
}

func readGESRTPHeader(reader io.Reader) ([geSRTPFrame]byte, error) {
	var frame [geSRTPFrame]byte
	offset := 0
	for _, field := range geSRTPFields {
		wire := frame[offset : offset+field.width]
		if _, err := io.ReadFull(reader, wire); err != nil {
			return frame, fmt.Errorf("read field %s: %w", field.name, err)
		}
		if field.reserved {
			clear(wire)
		}
		offset += field.width
	}
	return frame, nil
}

func geSRTPServiceName(code byte) string {
	switch code {
	case 0:
		return "STATUS"
	case 4:
		return "GET_READ_SYSTEM_MEMORY"
	default:
		return fmt.Sprintf("Unkown_%d", code) // Spelling used in reference logs.
	}
}
