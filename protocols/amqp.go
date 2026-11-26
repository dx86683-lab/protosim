package protocols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const amqp091 = "AMQP\x00\x00\x09\x01"

var amqpDefaults = []ProtocolParams{
	{Name: "version", DefaultValue: "3.6.6"},
	{Name: "product_name", DefaultValue: "RabbitMQ"},
	{Name: "platform", DefaultValue: "Erlang/OTP"},
	{Name: "copyright", DefaultValue: "Copyright (C) 2007-2016 Pivotal Software, Inc."},
	{Name: "host", DefaultValue: "rabbit@rabbitmq-0001"},
	{Name: "accounts", DefaultValue: []string{"guest:guest"}},
}

func init() {
	AddProtocol(NewProtocolInfo("amqp", newAMQPHandler, 5672), amqpDefaults...)
}

const (
	amqpHeartbeat   = "\x08\x00\x00\x00\x00\x00\x00\xce"
	amqpReadTimeout = 90 * time.Second
)

type amqpMethod struct {
	channel, class, id uint16
	body               []byte
}

var amqpMethodNames = map[[2]uint16]string{
	{10, 11}:  "ConnectionStartOk",
	{10, 31}:  "ConnectionTuneOk",
	{10, 40}:  "ConnectionOpen",
	{10, 50}:  "ConnectionClose",
	{10, 51}:  "ConnectionCloseOk",
	{20, 10}:  "ChannelOpen",
	{20, 20}:  "ChannelFlow",
	{20, 40}:  "ChannelClose",
	{20, 41}:  "ChannelCloseOk",
	{40, 10}:  "ExchangeDeclare",
	{40, 20}:  "ExchangeDelete",
	{40, 30}:  "ExchangeBind",
	{40, 40}:  "ExchangeUnbind",
	{50, 10}:  "QueueDeclare",
	{50, 20}:  "QueueBind",
	{50, 30}:  "QueuePurge",
	{50, 40}:  "QueueDelete",
	{50, 50}:  "QueueUnbind",
	{60, 10}:  "BasicQos",
	{60, 20}:  "BasicConsume",
	{60, 30}:  "BasicCancel",
	{60, 31}:  "BasicCancelOk",
	{60, 40}:  "BasicPublish",
	{60, 70}:  "BasicGet",
	{60, 80}:  "BasicAck",
	{60, 90}:  "BasicReject",
	{60, 100}: "BasicRecoverAsync",
	{60, 110}: "BasicRecover",
	{60, 120}: "BasicNack",
	{85, 10}:  "ConfirmSelect",
	{90, 10}:  "TxSelect",
	{90, 20}:  "TxCommit",
	{90, 30}:  "TxRollback",
}

type amqpSession struct {
	*SessionConnection
	writeMu   sync.Mutex
	broker    *amqpBroker
	pushMu    sync.Mutex
	pushReady chan struct{}
	consumers []*amqpConsumer
}

func (broker *amqpBroker) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	conn := session.Conn
	if err := conn.SetReadDeadline(time.Now().Add(amqpReadTimeout)); err != nil {
		return err
	}
	var header [8]byte
	n, err := conn.Read(header[:])
	if n == 0 {
		return nil
	}
	if n != len(header) || string(header[:]) != amqp091 {
		return session.SendString(amqp091)
	}
	if err != nil {
		return err
	}

	a := amqpSession{SessionConnection: session, broker: broker}
	if err := a.send(0, 10, 10, amqpStart(session)); err != nil {
		return err
	}
	start, err := a.read()
	if err != nil {
		return amqpReadError(err)
	}
	switch {
	case start.isConnection(50):
		return a.send(0, 10, 51, nil)
	case !start.isConnection(11):
		return nil
	}
	user, pass, valid := amqpCredentials(start.body)
	if !valid {
		return nil
	}
	accounts := session.GetStringsParams("accounts", []string{"guest:guest"})
	if !matchesConfiguredAccount(accounts, user, pass) {
		logSessionEvent(session.ConfigInfo, conn.RemoteAddr(), "login failed", nil)
		return a.reject(530, "NOT_ALLOWED - login failure", start)
	}
	logSessionEvent(session.ConfigInfo, conn.RemoteAddr(), "login success", nil)
	if err := a.send(0, 10, 30, []byte{0x10, 0, 0, 1, 0, 0, 0, 10}); err != nil {
		return err
	}

	var heartbeat uint16
	for {
		method, err := a.read()
		if err != nil {
			return amqpReadError(err)
		}
		switch {
		case method.isConnection(31):
			if len(method.body) != 8 {
				return nil
			}
			heartbeat = binary.BigEndian.Uint16(method.body[6:])
		case method.isConnection(40):
			if len(method.body) < 3 || int(method.body[0]) > len(method.body)-3 {
				return nil
			}
			vhost := string(method.body[1 : 1+int(method.body[0])])
			if vhost != "/" {
				return a.reject(402, fmt.Sprintf("INVALID_PATH - virtualHost '%s' does not exist", vhost), method)
			}
			if err := a.send(0, 10, 41, []byte{0}); err != nil {
				return err
			}
			return a.serveChannels(heartbeat)
		case method.isConnection(50):
			return a.send(0, 10, 51, nil)
		default:
			return nil
		}
	}
}

func (a *amqpSession) read() (amqpMethod, error) {
	method, err := readAMQPMethod(a.Conn)
	if err == nil {
		if name := amqpMethodNames[[2]uint16{method.class, method.id}]; name != "" {
			logSessionEvent(a.ConfigInfo, a.Conn.RemoteAddr(), "frame method", logrus.Fields{"method": name})
		}
	}
	return method, err
}

func amqpReadError(err error) error {
	var timeout net.Error
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return nil
	}
	return err
}

func (m amqpMethod) isConnection(id uint16) bool {
	return m.channel == 0 && m.class == 10 && m.id == id
}

func (a *amqpSession) reject(code uint16, text string, method amqpMethod) error {
	if err := a.Conn.SetReadDeadline(time.Now().Add(amqpReadTimeout)); err != nil {
		return err
	}
	if err := a.send(0, 10, 50, amqpCloseBody(code, text, method)); err != nil {
		return err
	}
	reply, err := a.read()
	if err != nil {
		return amqpReadError(err)
	}
	if reply.isConnection(50) {
		return a.send(0, 10, 51, nil)
	}
	return nil
}

func (a *amqpSession) serveChannels(heartbeat uint16) error {
	if err := a.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	stopHeartbeat := func() {}
	if heartbeat > 0 {
		stop := make(chan struct{})
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			ticker := time.NewTicker(time.Duration(heartbeat) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					if err := a.write([]byte(amqpHeartbeat)); err != nil {
						return
					}
				}
			}
		}()
		stopHeartbeat = sync.OnceFunc(func() {
			close(stop)
			<-stopped
		})
	}
	defer stopHeartbeat()
	channels := make(map[uint16]*amqpChannel)
	defer a.broker.disconnect(a, channels)
	stopPush := a.startPushDelivery()
	defer stopPush()
	for {
		method, err := a.read()
		if err != nil {
			return amqpReadError(err)
		}
		if method.isConnection(50) {
			stopPush()
			stopHeartbeat()
			return a.send(0, 10, 51, nil)
		}
		channel := method.channel
		if channel == 0 {
			return nil
		}
		if method.class == 20 && method.id == 10 && channels[channel] != nil {
			stopPush()
			stopHeartbeat()
			return a.reject(504, "CHANNEL_ERROR - channel already open", method)
		}
		closed, err := a.handleChannelMethod(channels, method)
		if closed || err != nil {
			return err
		}
	}
}

func (a *amqpSession) handleChannelMethod(channels map[uint16]*amqpChannel, method amqpMethod) (bool, error) {
	channel := method.channel
	state := channels[channel]
	var message *amqpMessage
	var mandatory bool
	if state != nil && method.class == 60 && method.id == 40 {
		var err error
		message, mandatory, err = a.readPublish(method)
		if err != nil {
			return false, err
		}
		// The reference routes a publication when it receives a body frame.
		if len(message.body) == 0 {
			return false, nil
		}
	}
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	switch {
	case method.class == 20 && method.id == 10:
		channels[channel] = &amqpChannel{}
		return false, a.send(channel, 20, 11, []byte{0, 0, 0, 0})
	case state != nil && method.class == 20 && method.id == 40:
		a.broker.releaseChannel(state)
		delete(channels, channel)
		return false, a.send(channel, 20, 41, nil)
	case method.class == 20 && method.id == 41:
		return false, nil
	case state == nil:
		return true, nil
	}
	a.broker.mu.Lock()
	response, failure := a.broker.command(a, state, method, message, mandatory)
	a.broker.mu.Unlock()
	if failure != nil {
		a.broker.releaseChannel(state)
		delete(channels, channel)
		return false, a.send(channel, 20, 40, amqpCloseBody(failure.code, failure.text, method))
	}
	if len(response) != 0 {
		return false, a.write(response)
	}
	return false, nil
}

func amqpStart(session *SessionConnection) []byte {
	properties := []byte{}
	for _, field := range []struct {
		wire, param, fallback string
	}{
		{"product", "product_name", "RabbitMQ"},
		{"version", "version", "3.6.6"},
		{"copyright", "copyright", "Copyright (C) 2007-2016 Pivotal Software, Inc."},
		{"platform", "platform", "Erlang/OTP"},
	} {
		properties = append(properties, byte(len(field.wire)))
		properties = append(properties, field.wire...)
		properties = append(properties, 'S')
		properties = appendAMQPLong(properties, []byte(session.GetStringParams(field.param, field.fallback)))
	}
	capabilities := []byte{}
	for _, feature := range []struct {
		name    string
		enabled byte
	}{
		{"basic.nack", 1}, {"consumer_cancel_notify", 1}, {"connection.blocked", 0},
		{"consumer_priorities", 0}, {"authentication_failure_close", 1}, {"per_consumer_qos", 1},
		{"publisher_confirms", 1}, {"exchange_exchange_bindings", 0},
	} {
		capabilities = append(capabilities, byte(len(feature.name)))
		capabilities = append(capabilities, feature.name...)
		capabilities = append(capabilities, 't', feature.enabled)
	}
	properties = append(properties, "\x0ccapabilitiesF"...)
	properties = appendAMQPLong(properties, capabilities)
	properties = append(properties, "\x04hostS"...)
	properties = appendAMQPLong(properties, []byte(session.GetStringParams("host", "rabbit@rabbitmq-0001")))

	reply := appendAMQPLong([]byte{0, 9}, properties)
	reply = appendAMQPLong(reply, []byte("PLAIN"))
	return appendAMQPLong(reply, []byte("en_US"))
}

func appendAMQPLong(out, data []byte) []byte {
	return append(binary.BigEndian.AppendUint32(out, uint32(len(data))), data...)
}

const amqpFramePayloadLimit = 65536 - 8

type amqpFrame struct {
	kind    byte
	channel uint16
	payload []byte
}

func readAMQPFrame(r io.Reader) (amqpFrame, error) {
	var header [7]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return amqpFrame{}, err
	}
	size := binary.BigEndian.Uint32(header[3:])
	if size > amqpFramePayloadLimit {
		return amqpFrame{}, errors.New("AMQP frame exceeds limit")
	}
	payload := make([]byte, size+1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return amqpFrame{}, err
	}
	if payload[size] != 0xce {
		return amqpFrame{}, errors.New("invalid AMQP frame terminator")
	}
	return amqpFrame{header[0], binary.BigEndian.Uint16(header[1:]), payload[:size]}, nil
}

func readAMQPMethod(r io.Reader) (amqpMethod, error) {
	for {
		f, err := readAMQPFrame(r)
		if err != nil {
			return amqpMethod{}, err
		}
		if f.kind == 8 && f.channel == 0 && len(f.payload) == 0 {
			continue
		}
		if f.kind != 1 || len(f.payload) < 4 {
			return amqpMethod{}, errors.New("expected AMQP method frame")
		}
		return amqpMethod{f.channel, binary.BigEndian.Uint16(f.payload), binary.BigEndian.Uint16(f.payload[2:]), f.payload[4:]}, nil
	}
}

func appendAMQPFrame(packet []byte, kind byte, channel uint16, payload []byte) []byte {
	packet = binary.BigEndian.AppendUint16(append(packet, kind), channel)
	packet = binary.BigEndian.AppendUint32(packet, uint32(len(payload)))
	return append(append(packet, payload...), 0xce)
}

func amqpMethodWire(channel, class, method uint16, body []byte) []byte {
	payload := binary.BigEndian.AppendUint16(nil, class)
	payload = binary.BigEndian.AppendUint16(payload, method)
	return appendAMQPFrame(nil, 1, channel, append(payload, body...))
}

func (a *amqpSession) send(channel, class, method uint16, body []byte) error {
	return a.write(amqpMethodWire(channel, class, method, body))
}

func amqpCloseBody(code uint16, text string, method amqpMethod) []byte {
	body := appendAMQPShort(binary.BigEndian.AppendUint16(nil, code), text)
	body = binary.BigEndian.AppendUint16(body, method.class)
	return binary.BigEndian.AppendUint16(body, method.id)
}

func (a *amqpSession) write(packet []byte) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if err := a.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	n, err := a.Conn.Write(packet)
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func amqpCredentials(body []byte) (string, string, bool) {
	_, tail, ok := cutAMQPLong(body)
	if !ok || len(tail) < 6 || tail[0] != 5 || string(tail[1:6]) != "PLAIN" {
		return "", "", false
	}
	binaryResponse, locale, ok := cutAMQPLong(tail[6:])
	if !ok || len(locale) <= 1 || len(locale) != int(locale[0])+1 {
		return "", "", false
	}
	parts := strings.Split(string(binaryResponse), "\x00")
	if len(parts) != 3 || parts[0] != "" || parts[1] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func cutAMQPLong(data []byte) ([]byte, []byte, bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	length := binary.BigEndian.Uint32(data)
	if length > uint32(len(data)-4) {
		return nil, nil, false
	}
	return data[4 : 4+length], data[4+length:], true
}
