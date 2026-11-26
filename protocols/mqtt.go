package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	maxMQTTPacket      = 1 << 20
	maxMQTTPublication = 16 << 20
	mqttNoConnack      = 0xff
)

var mqttDefaultBroker = newMQTTBroker()

func init() {
	AddProtocol(NewProtocolInfo("mqtt", mqttDefaultBroker.serve, 1883),
		ProtocolParams{Name: "ssl", DefaultValue: false},
		ProtocolParams{Name: "accounts"})
}

type mqttPacket struct {
	header byte
	data   []byte
}

func (p mqttPacket) wire() []byte {
	wire := []byte{p.header}
	for n := len(p.data); ; n >>= 7 {
		part := byte(n & 0x7f)
		if n < 128 {
			wire = append(wire, part)
			break
		}
		wire = append(wire, part|0x80)
	}
	return append(wire, p.data...)
}

type mqttConnection struct {
	id        string
	clean     byte
	keepAlive uint16
	willTopic string
	will      mqttPacket
}

func (b *mqttBroker) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	reader := bufio.NewReader(session.Conn)
	header, data, err := readMQTTPacket(reader, maxMQTTPacket)
	if err != nil {
		return err
	}
	if header != 0x10 {
		return errors.New("expected MQTT CONNECT")
	}
	settings, code := parseMQTTConnect(data, session.GetStringsParams("accounts", nil))
	peer := &mqttPeer{conn: session.Conn}
	if code != mqttNoConnack {
		if err := peer.send(mqttPacket{0x20, []byte{settings.clean, code}}); err != nil {
			return err
		}
	}
	if code != 0 {
		// Refused connections stay silent until the peer closes. Discard input
		// without admitting the connection, even if the client repeats CONNECT.
		capture, _ := session.Conn.(interface{ FlushCapturedRequest() })
		for {
			_, err := reader.Discard(reader.Size())
			if capture != nil {
				capture.FlushCapturedRequest()
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	peer.filters = make(map[string]struct{})
	key := mqttClientKey{listener: session.ServerInfo, id: settings.id}
	b.attach(key, peer)
	defer func() {
		b.detach(key, peer)
		// The reference publishes a configured Will for both disconnect paths.
		if settings.willTopic != "" {
			b.publish(settings.willTopic, settings.will, mqttKeepRetained)
		}
	}()

	// A zero Keep Alive disables the session read deadline. Otherwise each
	// complete packet starts a new window at one and a half times the interval.
	idleTimeout := time.Duration(settings.keepAlive) * 1500 * time.Millisecond
	for {
		var deadline time.Time
		if idleTimeout != 0 {
			deadline = time.Now().Add(idleTimeout)
		}
		if err := session.Conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		header, data, err = readMQTTPacket(reader, maxMQTTPublication)
		if err != nil {
			return err
		}
		switch {
		case header == 0xc0 && len(data) == 0:
			err = peer.send(mqttPacket{header: 0xd0})
		case header == 0xe0 && len(data) == 0:
			return nil
		case header == 0x82:
			err = b.subscribe(peer, data)
		case header == 0xa2:
			err = b.unsubscribe(peer, data)
		case header>>4 == 3:
			err = b.acceptPublication(peer, mqttPacket{header, data})
		case header == 0x40 || header == 0x50 || header == 0x62 || header == 0x70:
			err = mqttAcknowledge(peer, header, data)
		default:
			return errors.New("unsupported MQTT packet")
		}
		if err != nil {
			return err
		}
	}
}

func readMQTTPacket(reader *bufio.Reader, publicationLimit int) (byte, []byte, error) {
	header, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	limit := maxMQTTPacket
	if header>>4 == 3 {
		limit = publicationLimit
	}
	size := 0
	for i := range 4 {
		part, err := reader.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		size += int(part&0x7f) << (7 * i)
		if size > limit {
			break
		}
		if part&0x80 == 0 {
			// Wait for body bytes before allocating for a large publication.
			if size > maxMQTTPacket {
				if _, err := reader.Peek(min(size, reader.Size())); err != nil {
					return header, nil, err
				}
			}
			data := make([]byte, size)
			_, err := io.ReadFull(reader, data)
			return header, data, err
		}
	}
	return 0, nil, errors.New("invalid MQTT packet size")
}

func cutMQTTString(data []byte) (string, []byte, bool) {
	if len(data) < 2 {
		return "", nil, false
	}
	size := int(binary.BigEndian.Uint16(data))
	if len(data)-2 < size {
		return "", nil, false
	}
	return string(data[2 : 2+size]), data[2+size:], true
}

func parseMQTTConnect(data []byte, accounts []string) (mqttConnection, byte) {
	var settings mqttConnection
	protocol, data, ok := cutMQTTString(data)
	if ok && protocol == "MQTT" && len(data) >= 4 && data[0] == 5 {
		return settings, mqttNoConnack
	}
	if !ok || len(data) < 4 ||
		(protocol != "MQTT" || data[0] != 4) && (protocol != "MQIsdp" || data[0] != 3) {
		return settings, 1
	}
	flags := data[1]
	settings.clean = (flags >> 1) & 1
	settings.keepAlive = binary.BigEndian.Uint16(data[2:4])
	if flags&1 != 0 || flags&0x18 == 0x18 || flags&0x04 == 0 && flags&0x38 != 0 {
		return settings, 2
	}
	settings.id, data, ok = cutMQTTString(data[4:])
	if !ok {
		return settings, 2
	}
	if flags&4 != 0 {
		var payload string
		settings.willTopic, data, ok = cutMQTTString(data)
		if !ok || !validMQTTTopic(settings.willTopic) {
			return settings, 2
		}
		payload, data, ok = cutMQTTString(data)
		if !ok {
			return settings, 2
		}
		qos := (flags >> 3) & 3
		will := append(binary.BigEndian.AppendUint16(nil, uint16(len(settings.willTopic))), settings.willTopic...)
		if qos != 0 {
			// The reference constructs Will publications with packet identifier zero.
			will = append(will, 0, 0)
		}
		settings.will = mqttPacket{0x30 | qos<<1 | (flags>>5)&1, append(will, payload...)}
	}
	var user, pass string
	if flags&0x80 != 0 {
		user, data, ok = cutMQTTString(data)
		if !ok {
			return settings, 4
		}
	}
	if flags&0x40 != 0 {
		pass, data, ok = cutMQTTString(data)
		if !ok || flags&0x80 == 0 {
			return settings, 4
		}
	}
	if len(data) != 0 {
		return settings, 4
	}
	if len(accounts) != 0 && !matchesConfiguredAccount(accounts, user, pass) {
		return settings, 5
	}
	return settings, 0
}

func mqttAcknowledge(peer *mqttPeer, header byte, data []byte) error {
	if len(data) != 2 {
		return errors.New("invalid MQTT acknowledgement")
	}
	switch header {
	case 0x50:
		return peer.send(mqttPacket{0x62, data})
	case 0x62:
		return peer.send(mqttPacket{0x70, data})
	default:
		return nil
	}
}
