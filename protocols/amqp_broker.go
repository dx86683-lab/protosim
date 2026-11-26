package protocols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	amqpObjectLimit  = 256
	amqpBindingLimit = 1024
	amqpMessageLimit = 1024
	amqpContentLimit = 1 << 20
	amqpStorageLimit = 16 << 20
)

type amqpBroker struct {
	mu        sync.Mutex
	queues    map[string]*amqpQueue
	exchanges map[string]amqpExchange
	bindings  map[amqpBinding]amqpHeaderBinding
	messages  int
	bytes     int
}

type amqpQueue struct {
	name      string
	owner     *amqpSession
	flags     byte
	ready     []*amqpMessage
	consumers []*amqpConsumer
}

type amqpExchange struct {
	kind  string
	flags byte
}

type amqpBinding struct {
	queue, exchange, key string
	headers              string
}

type amqpMessage struct {
	exchange, key string
	header, body  []byte
}

type amqpDelivery struct {
	tag     uint64
	queue   *amqpQueue
	message *amqpMessage
}

type amqpChannel struct {
	deliveryTag    uint64
	publishTag     uint64
	confirm        bool
	flowPaused     bool
	prefetch       uint16
	consumerID     uint64
	consumers      []*amqpConsumer
	unacknowledged []amqpDelivery
}

type amqpChannelFailure struct {
	code uint16
	text string
}

func newAMQPHandler() func(*SessionConnection) error {
	b := &amqpBroker{
		queues: make(map[string]*amqpQueue),
		exchanges: map[string]amqpExchange{
			"amq.direct": {kind: "direct", flags: 2},
			"amq.fanout": {kind: "fanout", flags: 2},
			"amq.topic":  {kind: "topic", flags: 2},
		},
		bindings: make(map[amqpBinding]amqpHeaderBinding),
	}
	return b.serve
}

func (a *amqpSession) readPublish(method amqpMethod) (*amqpMessage, bool, error) {
	args := amqpArgs{data: method.body}
	args.take(2)
	exchange, key := args.short(), args.short()
	mandatory := args.flags()&1 != 0
	if !args.done() {
		return nil, false, errors.New("invalid AMQP publish arguments")
	}
	message, err := a.readPublication(method.channel, exchange, key)
	return message, mandatory, err
}

func (b *amqpBroker) command(a *amqpSession, ch *amqpChannel, m amqpMethod, message *amqpMessage, mandatory bool) ([]byte, *amqpChannelFailure) {
	switch m.class {
	case 20:
		if m.id == 20 && len(m.body) == 1 {
			active := m.body[0] & 1
			ch.flowPaused = active == 0
			b.notifyChannel(ch)
			return amqpMethodWire(m.channel, 20, 21, []byte{active}), nil
		}
	case 40:
		if m.id == 30 || m.id == 40 {
			return amqpUnsupportedMethod(m, "queue"), nil
		}
		return b.exchangeCommand(m)
	case 50:
		return b.queueCommand(a, m)
	case 60:
		switch m.id {
		case 10:
			if len(m.body) == 7 {
				ch.prefetch = binary.BigEndian.Uint16(m.body[4:])
				b.notifyChannel(ch)
				return amqpMethodWire(m.channel, 60, 11, nil), nil
			}
		case 20:
			return b.consume(a, ch, m)
		case 30:
			return b.cancel(ch, m)
		case 40:
			return b.publish(ch, m, message, mandatory)
		case 70:
			return b.get(a, ch, m)
		case 80, 90, 120:
			return nil, b.acknowledge(ch, m)
		case 100, 110:
			if len(m.body) == 1 {
				return amqpUnsupportedMethod(m, "basic"), nil
			}
		}
	case 85:
		if m.id == 10 && len(m.body) == 1 {
			ch.confirm = true
			if m.body[0]&1 == 0 {
				return amqpMethodWire(m.channel, 85, 11, nil), nil
			}
			return nil, nil
		}
	case 90:
		// The reference recognizes these methods and leaves publications unchanged.
		if len(m.body) == 0 && (m.id == 10 || m.id == 20 || m.id == 30) {
			return nil, nil
		}
	}
	return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
}

func amqpUnsupportedMethod(m amqpMethod, group string) []byte {
	method := amqpMethodNames[[2]uint16{m.class, m.id}]
	text := fmt.Sprintf("NOT_IMPLEMENTED - unable to route %s method %s", group, method)
	return amqpMethodWire(0, 10, 50, amqpCloseBody(540, text, m))
}

func (b *amqpBroker) exchangeCommand(m amqpMethod) ([]byte, *amqpChannelFailure) {
	args := amqpArgs{data: m.body}
	args.take(2)
	name := args.short()
	switch m.id {
	case 10:
		kind, flags := args.short(), args.flags()
		args.table()
		if !args.done() || name == "" {
			return nil, &amqpChannelFailure{503, "COMMAND_INVALID - exchange name is required"}
		}
		exchange, exists := b.exchanges[name]
		if flags&1 != 0 {
			if !exists {
				return nil, amqpNotFound("exchange", name)
			}
		} else {
			switch kind {
			case "direct", "fanout", "topic", "headers":
			default:
				return nil, &amqpChannelFailure{503, "COMMAND_INVALID - unsupported exchange type"}
			}
			switch {
			case exists && exchange != (amqpExchange{kind, flags & 0x0e}):
				return nil, &amqpChannelFailure{406, "PRECONDITION_FAILED - inequivalent exchange declaration"}
			case !exists && len(b.exchanges) >= amqpObjectLimit:
				return nil, &amqpChannelFailure{506, "RESOURCE_ERROR - too many exchanges"}
			default:
				b.exchanges[name] = amqpExchange{kind, flags & 0x0e}
			}
		}
		if flags&0x10 != 0 {
			return nil, nil
		}
		return amqpMethodWire(m.channel, 40, 11, nil), nil
	case 20:
		flags := args.flags()
		if !args.done() {
			break
		}
		if _, exists := b.exchanges[name]; !exists {
			return nil, amqpNotFound("exchange", name)
		}
		if flags&1 != 0 {
			for key := range b.bindings {
				if key.exchange == name {
					return nil, &amqpChannelFailure{406, "PRECONDITION_FAILED - exchange in use"}
				}
			}
		}
		delete(b.exchanges, name)
		for key := range b.bindings {
			if key.exchange == name {
				delete(b.bindings, key)
			}
		}
		if flags&2 != 0 {
			return nil, nil
		}
		return amqpMethodWire(m.channel, 40, 21, nil), nil
	}
	return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
}

func (b *amqpBroker) queueCommand(a *amqpSession, m amqpMethod) ([]byte, *amqpChannelFailure) {
	args := amqpArgs{data: m.body}
	args.take(2)
	name := args.short()
	if m.id == 10 {
		return b.declareQueue(a, m.channel, name, &args)
	}
	q, failure := b.queue(a, name)
	if failure != nil {
		return nil, failure
	}
	var reply uint16
	var body []byte
	var noWait bool
	switch m.id {
	case 20, 50:
		exchange, routingKey := args.short(), args.short()
		if m.id == 20 {
			noWait = args.flags()&1 != 0
		}
		table := args.table()
		if !args.done() {
			return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
		}
		definition, ok := b.exchanges[exchange]
		if !ok {
			return nil, amqpNotFound("exchange", exchange)
		}
		binding := amqpBinding{queue: name, exchange: exchange, key: routingKey}
		var headers amqpHeaderBinding
		if definition.kind == "headers" {
			var failure *amqpChannelFailure
			headers, binding.headers, failure = parseAMQPHeaderBinding(table)
			if failure != nil {
				return nil, failure
			}
		}
		if m.id == 20 {
			if _, exists := b.bindings[binding]; !exists && len(b.bindings) >= amqpBindingLimit {
				return nil, &amqpChannelFailure{506, "RESOURCE_ERROR - too many bindings"}
			}
			b.bindings[binding] = headers
			reply = 21
		} else {
			delete(b.bindings, binding)
			reply = 51
		}
	case 30, 40:
		flags := args.flags()
		if !args.done() {
			return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
		}
		count := len(q.ready)
		if m.id == 30 {
			reply, noWait = 31, flags&1 != 0
			b.purge(q)
		} else {
			if flags&1 != 0 && len(q.consumers) != 0 {
				return nil, &amqpChannelFailure{406, "PRECONDITION_FAILED - queue in use"}
			}
			if flags&2 != 0 && count != 0 {
				return nil, &amqpChannelFailure{406, "PRECONDITION_FAILED - queue not empty"}
			}
			reply, noWait = 41, flags&4 != 0
			b.deleteQueue(q)
		}
		body = binary.BigEndian.AppendUint32(nil, uint32(count))
	default:
		return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
	}
	if noWait {
		return nil, nil
	}
	return amqpMethodWire(m.channel, 50, reply, body), nil
}

func (b *amqpBroker) declareQueue(a *amqpSession, channel uint16, name string, args *amqpArgs) ([]byte, *amqpChannelFailure) {
	flags := args.flags()
	args.table()
	if !args.done() || name == "" {
		return nil, &amqpChannelFailure{503, "COMMAND_INVALID - queue name is required"}
	}
	q, failure := b.queue(a, name)
	if failure != nil {
		if failure.code != 404 || flags&1 != 0 {
			return nil, failure
		}
		if len(b.queues) >= amqpObjectLimit {
			return nil, &amqpChannelFailure{506, "RESOURCE_ERROR - too many queues"}
		}
		q = &amqpQueue{name: name, flags: flags & 0x0e}
		if flags&4 != 0 {
			q.owner = a
		}
		b.queues[name] = q
	} else if flags&1 == 0 && q.flags != flags&0x0e {
		for _, flag := range []struct {
			mask byte
			name string
		}{{2, "durable"}, {4, "exclusive"}, {8, "auto_delete"}} {
			if flags&flag.mask != q.flags&flag.mask {
				return nil, &amqpChannelFailure{406, fmt.Sprintf(
					"PRECONDITION_FAILED - inequivalent arg '%s' for queue '%s': received '%t' but current is '%t'",
					flag.name, name, flags&flag.mask != 0, q.flags&flag.mask != 0)}
			}
		}
	}
	if flags&0x10 != 0 {
		return nil, nil
	}
	body := appendAMQPShort(nil, name)
	body = binary.BigEndian.AppendUint32(body, uint32(len(q.ready)))
	body = binary.BigEndian.AppendUint32(body, uint32(len(q.consumers)))
	return amqpMethodWire(channel, 50, 11, body), nil
}

func (b *amqpBroker) queue(a *amqpSession, name string) (*amqpQueue, *amqpChannelFailure) {
	q := b.queues[name]
	if q == nil {
		return nil, amqpNotFound("queue", name)
	}
	if q.owner != nil && q.owner != a {
		return nil, &amqpChannelFailure{405, fmt.Sprintf("RESOURCE_LOCKED - queue '%s' is locked to another connection", name)}
	}
	return q, nil
}

func amqpNotFound(kind, name string) *amqpChannelFailure {
	return &amqpChannelFailure{404, fmt.Sprintf("NOT_FOUND - %s '%s' not found", kind, name)}
}

func (b *amqpBroker) purge(q *amqpQueue) {
	for _, msg := range q.ready {
		b.forget(msg)
	}
	q.ready = nil
}

func (b *amqpBroker) forget(msg *amqpMessage) {
	b.messages--
	b.bytes -= len(msg.header) + len(msg.body)
}

func (b *amqpBroker) deleteQueue(q *amqpQueue) {
	for len(q.consumers) != 0 {
		b.detachConsumer(q.consumers[0])
	}
	b.purge(q)
	delete(b.queues, q.name)
	for binding := range b.bindings {
		if binding.queue == q.name {
			delete(b.bindings, binding)
		}
	}
}

func (b *amqpBroker) releaseChannel(ch *amqpChannel) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeChannel(ch)
}

func (b *amqpBroker) disconnect(a *amqpSession, channels map[uint16]*amqpChannel) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range channels {
		b.closeChannel(ch)
	}
	for _, q := range b.queues {
		if q.owner == a {
			b.deleteQueue(q)
		}
	}
}

func (b *amqpBroker) closeChannel(ch *amqpChannel) {
	for len(ch.consumers) != 0 {
		b.removeConsumer(ch.consumers[0])
	}
	b.settle(ch, 0, true, true)
}

func (b *amqpBroker) get(a *amqpSession, ch *amqpChannel, m amqpMethod) ([]byte, *amqpChannelFailure) {
	args := amqpArgs{data: m.body}
	args.take(2)
	name, flags := args.short(), args.flags()
	if !args.done() {
		return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
	}
	q, failure := b.queue(a, name)
	if failure != nil {
		return nil, failure
	}
	if len(q.ready) == 0 {
		return amqpMethodWire(m.channel, 60, 72, []byte{0}), nil
	}
	message, tag := b.takeMessage(q, ch, flags&1 != 0)
	body := append(binary.BigEndian.AppendUint64(nil, tag), 0)
	body = appendAMQPShort(body, message.exchange)
	body = appendAMQPShort(body, message.key)
	body = binary.BigEndian.AppendUint32(body, 1)
	return message.appendContent(amqpMethodWire(m.channel, 60, 71, body), m.channel), nil
}

func (b *amqpBroker) takeMessage(q *amqpQueue, ch *amqpChannel, autoAck bool) (*amqpMessage, uint64) {
	message := q.ready[0]
	q.ready[0] = nil
	q.ready = q.ready[1:]
	ch.deliveryTag++
	if autoAck {
		b.forget(message)
	} else {
		ch.unacknowledged = append(ch.unacknowledged, amqpDelivery{ch.deliveryTag, q, message})
	}
	return message, ch.deliveryTag
}

func (b *amqpBroker) acknowledge(ch *amqpChannel, m amqpMethod) *amqpChannelFailure {
	if len(m.body) != 9 {
		return &amqpChannelFailure{503, "COMMAND_INVALID"}
	}
	tag, flags := binary.BigEndian.Uint64(m.body), m.body[8]
	multiple := m.id != 90 && flags&1 != 0
	requeue := m.id == 90 && flags&1 != 0 || m.id == 120 && flags&2 != 0
	if (tag != 0 || !multiple) && !slices.ContainsFunc(ch.unacknowledged, func(d amqpDelivery) bool {
		return d.tag == tag
	}) {
		return &amqpChannelFailure{406, fmt.Sprintf("PRECONDITION_FAILED - unknown delivery tag %d", tag)}
	}
	b.settle(ch, tag, multiple, requeue)
	return nil
}

func (b *amqpBroker) settle(ch *amqpChannel, tag uint64, multiple, requeue bool) {
	deliveries := ch.unacknowledged
	retained := deliveries[:0]
	var requeued map[*amqpQueue][]*amqpMessage
	if requeue {
		requeued = make(map[*amqpQueue][]*amqpMessage)
	}
	for _, d := range deliveries {
		if d.tag != tag && !(multiple && (tag == 0 || d.tag <= tag)) {
			retained = append(retained, d)
			continue
		}
		if requeue && b.queues[d.queue.name] == d.queue {
			requeued[d.queue] = append(requeued[d.queue], d.message)
		} else {
			b.forget(d.message)
		}
	}
	for q, messages := range requeued {
		q.ready = append(messages, q.ready...)
		b.notifyQueue(q)
	}
	clear(deliveries[len(retained):])
	ch.unacknowledged = retained
	b.notifyChannel(ch)
}

func (b *amqpBroker) publish(ch *amqpChannel, m amqpMethod, msg *amqpMessage, mandatory bool) ([]byte, *amqpChannelFailure) {
	targets := make(map[*amqpQueue]struct{})
	if msg.exchange == "" {
		if q := b.queues[msg.key]; q != nil {
			targets[q] = struct{}{}
		}
	} else {
		exchange, exists := b.exchanges[msg.exchange]
		if !exists {
			return nil, amqpNotFound("exchange", msg.exchange)
		}
		var messageHeaders map[string]string
		if exchange.kind == "headers" {
			messageHeaders = amqpPublicationHeaders(msg.header)
		}
		for binding, headers := range b.bindings {
			if binding.exchange != msg.exchange {
				continue
			}
			if exchange.kind == "fanout" || exchange.kind == "direct" && binding.key == msg.key ||
				exchange.kind == "topic" && amqpTopicMatches(binding.key, msg.key) ||
				exchange.kind == "headers" && headers.matches(messageHeaders) {
				targets[b.queues[binding.queue]] = struct{}{}
			}
		}
	}
	size := (len(msg.header) + len(msg.body)) * len(targets)
	if b.messages+len(targets) > amqpMessageLimit || b.bytes+size > amqpStorageLimit {
		return nil, &amqpChannelFailure{506, "RESOURCE_ERROR - message storage full"}
	}
	for queue := range targets {
		queue.ready = append(queue.ready, msg)
		b.notifyQueue(queue)
	}
	b.messages += len(targets)
	b.bytes += size

	var out []byte
	if mandatory && len(targets) == 0 {
		body := appendAMQPShort(binary.BigEndian.AppendUint16(nil, 312), "No route")
		body = appendAMQPShort(body, msg.exchange)
		body = appendAMQPShort(body, msg.key)
		out = msg.appendContent(amqpMethodWire(m.channel, 60, 50, body), m.channel)
	}
	if ch.confirm {
		ch.publishTag++
		body := append(binary.BigEndian.AppendUint64(nil, ch.publishTag), 0)
		out = append(out, amqpMethodWire(m.channel, 60, 80, body)...)
	}
	return out, nil
}

func amqpTopicMatches(pattern, key string) bool {
	segments := strings.Split(key, ".")
	matched := make([]bool, len(segments)+1)
	matched[0] = true
	for _, term := range strings.Split(pattern, ".") {
		if term == "#" {
			for i := 1; i < len(matched); i++ {
				matched[i] = matched[i] || matched[i-1]
			}
			continue
		}
		for i := len(segments); i > 0; i-- {
			matched[i] = matched[i-1] && (term == "*" || term == segments[i-1])
		}
		matched[0] = false
	}
	return matched[len(segments)]
}

func (a *amqpSession) readPublication(channel uint16, exchange, key string) (*amqpMessage, error) {
	if err := a.Conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}
	defer a.Conn.SetReadDeadline(time.Time{})
	frame, err := a.readContentFrame(channel, 2)
	if err != nil {
		return nil, err
	}
	header := frame.payload
	if len(header) < 14 || binary.BigEndian.Uint16(header) != 60 || binary.BigEndian.Uint16(header[2:]) != 0 {
		return nil, errors.New("invalid AMQP content header")
	}
	size := binary.BigEndian.Uint64(header[4:])
	if size > amqpContentLimit {
		return nil, errors.New("AMQP message exceeds content limit")
	}
	message := &amqpMessage{exchange: exchange, key: key, header: header, body: make([]byte, 0, int(size))}
	for len(message.body) < int(size) {
		frame, err := a.readContentFrame(channel, 3)
		if err != nil {
			return nil, err
		}
		if len(frame.payload) == 0 || len(frame.payload) > int(size)-len(message.body) {
			return nil, errors.New("invalid AMQP content body size")
		}
		message.body = append(message.body, frame.payload...)
	}
	return message, nil
}

func (a *amqpSession) readContentFrame(channel uint16, kind byte) (amqpFrame, error) {
	for {
		frame, err := readAMQPFrame(a.Conn)
		if err != nil {
			return amqpFrame{}, err
		}
		if frame.kind == kind && frame.channel == channel {
			return frame, nil
		}
		if frame.kind != 8 || frame.channel != 0 || len(frame.payload) != 0 {
			return amqpFrame{}, errors.New("unexpected AMQP content frame")
		}
	}
}

func (m *amqpMessage) appendContent(out []byte, channel uint16) []byte {
	out = appendAMQPFrame(out, 2, channel, m.header)
	for chunk := m.body; len(chunk) > 0; {
		n := min(len(chunk), amqpFramePayloadLimit)
		out = appendAMQPFrame(out, 3, channel, chunk[:n])
		chunk = chunk[n:]
	}
	return out
}

type amqpArgs struct {
	data []byte
	bad  bool
}

func (a *amqpArgs) take(size int) []byte {
	if size > len(a.data) {
		a.bad = true
		return nil
	}
	p := a.data[:size]
	a.data = a.data[size:]
	return p
}

func (a *amqpArgs) flags() byte {
	if p := a.take(1); len(p) == 1 {
		return p[0]
	}
	return 0
}

func (a *amqpArgs) short() string {
	return string(a.take(int(a.flags())))
}

func (a *amqpArgs) table() []byte {
	data, tail, ok := cutAMQPLong(a.data)
	a.bad = a.bad || !ok
	a.data = tail
	return data
}

func (a *amqpArgs) done() bool {
	return !a.bad && len(a.data) == 0
}

func appendAMQPShort(out []byte, value string) []byte {
	value = value[:min(len(value), 255)]
	return append(append(out, byte(len(value))), value...)
}
