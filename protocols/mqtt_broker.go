package protocols

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	mqttSubscriptionLimit = 128
	mqttRetainedLimit     = 128
	mqttRetainedByteLimit = 2 * maxMQTTPublication
	mqttReplayByteLimit   = 2 * maxMQTTPublication
)

type mqttRetainAction uint8

const (
	mqttKeepRetained mqttRetainAction = iota
	mqttStoreRetained
	mqttClearRetained
)

type mqttPeer struct {
	conn        net.Conn
	writeMu     sync.Mutex
	filters     map[string]struct{}
	replay      []mqttPacket
	replayBytes int
}

func (p *mqttPeer) send(packet mqttPacket) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.write(packet)
}

func (p *mqttPeer) write(packet mqttPacket) error {
	if err := p.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err := p.conn.Write(packet.wire())
	return err
}

type mqttBroker struct {
	mu            sync.Mutex
	clients       map[mqttClientKey]*mqttPeer
	retained      map[string]mqttPacket
	retainedBytes int
}

type mqttClientKey struct {
	listener string
	id       string
}

func newMQTTBroker() *mqttBroker {
	return &mqttBroker{clients: make(map[mqttClientKey]*mqttPeer), retained: make(map[string]mqttPacket)}
}

func (b *mqttBroker) attach(key mqttClientKey, peer *mqttPeer) {
	b.mu.Lock()
	previous := b.clients[key]
	b.clients[key] = peer
	b.mu.Unlock()
	if previous != nil {
		previous.conn.Close()
		// The replaced peer no longer owns the slot. Send its offline event here.
		b.announce(key.id, false)
	}
	b.announce(key.id, true)
}

func (b *mqttBroker) detach(key mqttClientKey, peer *mqttPeer) {
	b.mu.Lock()
	current := b.clients[key] == peer
	if current {
		delete(b.clients, key)
	}
	b.mu.Unlock()
	if current {
		b.announce(key.id, false)
	}
}

func (b *mqttBroker) announce(id string, online bool) {
	topic := "$SYS/broker/connection/clients/" + id
	payload, err := json.Marshal(struct {
		ClientID  string `json:"clientID"`
		Online    bool   `json:"online"`
		Timestamp string `json:"timestamp"`
	}{id, online, time.Now().UTC().Format(time.RFC3339)})
	if err != nil || len(topic)+len(payload)+2 > maxMQTTPacket {
		return
	}
	data := append(binary.BigEndian.AppendUint16(nil, uint16(len(topic))), topic...)
	b.publish(topic, mqttPacket{0x30, append(data, payload...)}, mqttKeepRetained)
}

func validMQTTTopic(topic string) bool {
	return topic != "" && utf8.ValidString(topic) && !strings.ContainsAny(topic, "+#\x00")
}

func validMQTTFilter(filter string) bool {
	if filter == "" || !utf8.ValidString(filter) || strings.ContainsRune(filter, '\x00') {
		return false
	}
	for {
		part, rest, more := strings.Cut(filter, "/")
		switch part {
		case "#":
			return !more
		case "+":
		default:
			if strings.ContainsAny(part, "+#") {
				return false
			}
		}
		if !more {
			return true
		}
		filter = rest
	}
}

func mqttFilterMatches(filter, topic string) bool {
	for {
		match, nextFilter, filterMore := strings.Cut(filter, "/")
		if match == "#" {
			return true
		}
		level, nextTopic, topicMore := strings.Cut(topic, "/")
		if match != "+" && match != level {
			return false
		}
		if !filterMore {
			return !topicMore
		}
		if !topicMore {
			return nextFilter == "#"
		}
		filter, topic = nextFilter, nextTopic
	}
}

func compareMQTTTopics(a, b string) int {
	for {
		aLevel, aTail, aMore := strings.Cut(a, "/")
		bLevel, bTail, bMore := strings.Cut(b, "/")
		if cmp := strings.Compare(aLevel, bLevel); cmp != 0 {
			return cmp
		}
		if !aMore || !bMore {
			switch {
			case aMore:
				return 1
			case bMore:
				return -1
			default:
				return 0
			}
		}
		a, b = aTail, bTail
	}
}

// A subscription remembers the retained packets present at registration. These
// packets remain in the connection's replay even after UNSUBSCRIBE or overwrite.
func (b *mqttBroker) rememberRetained(peer *mqttPeer, filter string, topics []string) bool {
	start, size := len(peer.replay), peer.replayBytes
	for _, topic := range topics {
		if !mqttFilterMatches(filter, topic) {
			continue
		}
		packet := b.retained[topic]
		size += len(packet.data)
		if size > mqttReplayByteLimit {
			clear(peer.replay[start:])
			peer.replay = peer.replay[:start]
			return false
		}
		peer.replay = append(peer.replay, packet)
	}
	peer.replayBytes = size
	return true
}

func (b *mqttBroker) subscribe(peer *mqttPeer, data []byte) error {
	if len(data) < 3 || binary.BigEndian.Uint16(data) == 0 {
		return errors.New("invalid MQTT SUBSCRIBE")
	}
	reply := append([]byte(nil), data[:2]...)
	type subscription struct {
		filter string
		qos    byte
	}
	var requested []subscription
	for rest := data[2:]; len(rest) != 0; {
		filter, tail, ok := cutMQTTString(rest)
		if !ok || len(tail) == 0 || len(requested) >= mqttSubscriptionLimit {
			return errors.New("invalid MQTT subscription request")
		}
		requested = append(requested, subscription{filter, tail[0]})
		rest = tail[1:]
	}

	// Serialize SUBACK and retained messages ahead of later live deliveries.
	peer.writeMu.Lock()
	defer peer.writeMu.Unlock()
	b.mu.Lock()
	topics := make([]string, 0, len(b.retained))
	for topic := range b.retained {
		topics = append(topics, topic)
	}
	slices.SortFunc(topics, compareMQTTTopics)
	for _, sub := range requested {
		_, active := peer.filters[sub.filter]
		if !validMQTTFilter(sub.filter) || sub.qos > 2 || (!active && len(peer.filters) >= mqttSubscriptionLimit) ||
			!b.rememberRetained(peer, sub.filter, topics) {
			reply = append(reply, 0x80)
			continue
		}
		peer.filters[sub.filter] = struct{}{}
		reply = append(reply, sub.qos)
	}
	b.mu.Unlock()
	if err := peer.write(mqttPacket{0x90, reply}); err != nil {
		return err
	}
	for _, packet := range peer.replay {
		if err := peer.write(packet); err != nil {
			return err
		}
	}
	return nil
}

func (b *mqttBroker) unsubscribe(peer *mqttPeer, data []byte) error {
	if len(data) < 3 || binary.BigEndian.Uint16(data) == 0 {
		return errors.New("invalid MQTT UNSUBSCRIBE")
	}
	var filters []string
	for rest := data[2:]; len(rest) != 0; {
		filter, tail, ok := cutMQTTString(rest)
		if !ok {
			return errors.New("invalid MQTT unsubscribe filter")
		}
		filters = append(filters, filter)
		rest = tail
	}
	b.mu.Lock()
	for _, filter := range filters {
		delete(peer.filters, filter)
	}
	b.mu.Unlock()
	return peer.send(mqttPacket{0xb0, data[:2]})
}

func (b *mqttBroker) acceptPublication(peer *mqttPeer, packet mqttPacket) error {
	topic, payload, ok := cutMQTTString(packet.data)
	qos := (packet.header >> 1) & 3
	if !ok || !validMQTTTopic(topic) || qos == 3 {
		return errors.New("invalid MQTT PUBLISH")
	}
	if qos != 0 {
		if len(payload) < 2 || binary.BigEndian.Uint16(payload) == 0 {
			return errors.New("invalid MQTT PUBLISH identifier")
		}
		if err := peer.send(mqttPacket{0x30 + qos*0x10, payload[:2]}); err != nil {
			return err
		}
		payload = payload[2:]
	}
	action := mqttKeepRetained
	if packet.header&1 != 0 {
		action = mqttStoreRetained
		if len(payload) == 0 {
			action = mqttClearRetained
		}
	}
	b.publish(topic, packet, action)
	return nil
}

func (b *mqttBroker) publish(topic string, packet mqttPacket, retain mqttRetainAction) {
	b.mu.Lock()
	switch retain {
	case mqttStoreRetained:
		previous, existing := b.retained[topic]
		size := b.retainedBytes - len(previous.data) + len(packet.data)
		if (existing || len(b.retained) < mqttRetainedLimit) && size <= mqttRetainedByteLimit {
			b.retained[topic] = packet
			b.retainedBytes = size
		}
	case mqttClearRetained:
		b.retainedBytes -= len(b.retained[topic].data)
		delete(b.retained, topic)
	}
	var recipients []*mqttPeer
	for _, peer := range b.clients {
		for filter := range peer.filters {
			if mqttFilterMatches(filter, topic) {
				recipients = append(recipients, peer)
			}
		}
	}
	b.mu.Unlock()
	for _, peer := range recipients {
		if err := peer.send(packet); err != nil {
			peer.conn.Close()
		}
	}
}
