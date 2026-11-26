package protocols

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/message/codes"
	udpmessage "github.com/plgd-dev/go-coap/v2/udp/message"
	"github.com/sirupsen/logrus"
)

const coapConfigName = "coap.json"

//go:embed fixtures/coap-default.json
var coapDefault []byte

type coapPage struct {
	Path    string
	Method  codes.Code
	Status  codes.Code
	Body    string
	Options map[string]json.RawMessage
}

func init() {
	AddProtocol(NewProtocolInfo("coap", serveCoAP, 5683),
		ProtocolParams{Name: "config_file", DefaultValue: coapConfigName})
}

func serveCoAP(conn *UDPConnection, payload []byte) error {
	if len(payload) < 4 || len(payload) > 4096 {
		return nil
	}
	request := udpmessage.Message{Options: make(message.Options, 0, 32)}
	if _, err := request.Unmarshal(payload); err != nil {
		return nil
	}
	control := request.Type == udpmessage.Acknowledgement || request.Type == udpmessage.Reset
	// The reference routes request-class codes even in ACK and RST frames.
	// Ignore response-class codes so two listeners cannot keep acknowledging each other.
	if control && request.Code>>5 != 0 {
		return nil
	}
	path, err := request.Options.Path()
	if err != nil && !errors.Is(err, message.ErrOptionNotFound) {
		return nil
	}
	method := request.Code.String()
	if request.Code < codes.GET || request.Code > codes.DELETE {
		method = fmt.Sprintf("Unknown:%d", request.Code)
	}
	logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "new message", logrus.Fields{
		"id": request.MessageID, "method": method, "path": path,
		"payload": string(request.Payload), "type": request.Type.String(),
	})
	var config struct{ Pages []coapPage }
	err = loadResponseFixture(conn.GetStringParams("config_file", coapConfigName), coapConfigName, coapDefault, &config)
	if errors.Is(err, os.ErrNotExist) {
		err = json.Unmarshal(coapDefault, &config)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("unexpected end of JSON input")
	}
	if err != nil {
		return err
	}
	replyType := udpmessage.Acknowledgement
	if request.Type == udpmessage.NonConfirmable {
		replyType = udpmessage.NonConfirmable
	}
	reply := udpmessage.Message{
		Type:      replyType,
		MessageID: request.MessageID,
		Token:     request.Token,
		Code:      codes.NotFound,
	}
	for _, page := range config.Pages {
		if page.Path != path || page.Method != request.Code {
			continue
		}
		if len(page.Body) > 4096 {
			return errors.New("simulated CoAP body exceeds limit")
		}
		reply.Code, reply.Payload = page.Status, []byte(page.Body)
		if raw, ok := page.Options["ContentFormat"]; ok {
			var format *string
			if json.Unmarshal(raw, &format) != nil || format == nil {
				return nil
			}
			if media, err := message.ToMediaType(*format); err == nil {
				reply.Options, _, err = reply.Options.SetUint32(make([]byte, 4), message.ContentFormat, uint32(media))
				if err != nil {
					return err
				}
			}
		}
		if raw, ok := page.Options["MaxAge"]; ok {
			var maxAge *float64
			if json.Unmarshal(raw, &maxAge) != nil || maxAge == nil {
				return nil
			}
			// The reference truncates the JSON number to a signed 64-bit integer
			// and encodes its low 32 bits. Out-of-range numbers encode as zero.
			var seconds uint32
			if *maxAge >= -(1<<63) && *maxAge < 1<<63 {
				seconds = uint32(int64(*maxAge))
			}
			reply.Options, _, err = reply.Options.SetUint32(make([]byte, 4), message.MaxAge, seconds)
			if err != nil {
				return err
			}
		}
		break
	}
	if control && reply.Code>>5 == 0 {
		return nil
	}
	wire, err := reply.Marshal()
	if err != nil {
		return err
	}
	_, err = conn.Write(wire)
	return err
}
