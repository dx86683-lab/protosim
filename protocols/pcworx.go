package protocols

import (
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

const pcworxSessionID = 0x42

const (
	pcwHello = "\x01\x01\x00\x1a\x00\x00\x00\x00\x78\x80\x00\x03\x00\x0cIBETH01N0_M\x00"
	pcwSetup = "\x01\x05\x00\x16\x00\x01\x00\x00\x78\x80\x00\x42\x00\x00\x00\x06\x00\x04\x02\x95\x00\x00"
	pcwInfo  = "\x01\x06\x00\x0e\x00\x02\x00\x00\x00\x00\x00\x42\x04\x00"
)

var pcworxFields = []struct {
	key, value string
	offset     int
}{
	{"plc_type", "ILC 151 ETH", 30},
	{"model_num", "2700974", 152},
	{"firmware_version", "4.60", 66},
	{"firmware_date", "11/15/17", 79},
	{"firmware_time", "14:05:00", 91},
}

func init() {
	params := make([]ProtocolParams, 0, len(pcworxFields))
	for _, field := range pcworxFields {
		params = append(params, ProtocolParams{Name: field.key, DefaultValue: field.value})
	}
	AddProtocol(NewProtocolInfo("pcworx", servePCWorx, 1962), params...)
}

func servePCWorx(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	var request [512]byte
	for {
		n, err := session.Conn.Read(request[:])
		if n == 0 {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		reply := make([]byte, 20)
		reply[0] = 0x81
		switch string(request[:n]) {
		case pcwHello:
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "handshake", nil)
			reply[17] = pcworxSessionID
		case pcwSetup:
			reply[18] = pcworxSessionID
		case pcwInfo:
			reply = append(reply, make([]byte, 165-len(reply))...)
			for _, field := range pcworxFields {
				value := session.GetStringParams(field.key, field.value)
				if len(value) >= len(reply)-field.offset {
					return nil
				}
				copy(reply[field.offset:], value)
				reply[field.offset+len(value)] = 0
			}
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "get device info", nil)
		default:
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "unsupport command", logrus.Fields{
				"data": hex.EncodeToString(request[:n]),
			})
			return nil
		}
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		written, err := session.Conn.Write(reply)
		if err != nil {
			return err
		}
		if written != len(reply) {
			return io.ErrShortWrite
		}
	}
}
