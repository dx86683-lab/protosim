package protocols

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	redlionManufacturer = "Red Lion Controls"
	redlionModel        = "G306m"
)

func init() {
	AddProtocol(NewProtocolInfo("redlion-crimson3", serveRedLion, 789),
		ProtocolParams{Name: "manufacturer", DefaultValue: redlionManufacturer},
		ProtocolParams{Name: "model", DefaultValue: redlionModel})
}

func serveRedLion(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	var header [2]byte
	var body [255]byte
	var n int
	var readErr error
	for {
		if err := session.Conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		n, readErr = reader.Read(header[:])
		if n != len(header) || header[1] == 0 {
			break
		}
		// Read the body once, using the low length byte as its upper bound.
		// A header received on its own leaves the reader waiting for the body.
		n, readErr = reader.Read(body[:header[1]])
		if n < 3 {
			break
		}

		probe := body[1:3]
		var event, value string
		switch string(probe) {
		case "\x2b\x1b":
			event = "get_manufacturer"
			value = session.GetStringParams("manufacturer", redlionManufacturer)
		case "\x2a\x1a":
			event = "get_model"
			value = session.GetStringParams("model", redlionModel)
		default:
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "unsupport probe", logrus.Fields{"probe": string(probe)})
			return nil
		}
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), event, nil)

		value = value[:min(len(value), 250)]
		reply := []byte{0, byte(len(value) + 5), 1, probe[0], 3, 0}
		reply = append(reply, value...)
		reply = append(reply, 0)
		if err := session.Conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
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
	var timeout net.Error
	if errors.Is(readErr, io.EOF) || (errors.As(readErr, &timeout) && timeout.Timeout()) {
		return nil
	}
	return readErr
}
