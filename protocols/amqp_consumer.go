package protocols

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"time"
)

type amqpConsumer struct {
	session   *amqpSession
	state     *amqpChannel
	queue     *amqpQueue
	channel   uint16
	tag       string
	autoAck   bool
	exclusive bool
}

func (b *amqpBroker) consume(a *amqpSession, ch *amqpChannel, m amqpMethod) ([]byte, *amqpChannelFailure) {
	args := amqpArgs{data: m.body}
	args.take(2)
	queueName, tag, flags := args.short(), args.short(), args.flags()
	args.table()
	if !args.done() {
		return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
	}
	q, failure := b.queue(a, queueName)
	if failure != nil {
		return nil, failure
	}
	exclusive := flags&4 != 0
	if len(q.consumers) != 0 && (exclusive || q.consumers[0].exclusive) {
		return nil, &amqpChannelFailure{403, fmt.Sprintf("ACCESS_REFUSED - queue is busy by %d consumers", len(q.consumers))}
	}
	if len(q.consumers) >= amqpObjectLimit || len(a.consumers) >= amqpObjectLimit {
		return nil, &amqpChannelFailure{506, "RESOURCE_ERROR - too many consumers"}
	}
	if tag == "" {
		ch.consumerID++
		tag = fmt.Sprintf("%d_%d", time.Now().Unix(), ch.consumerID)
	}
	if slices.ContainsFunc(ch.consumers, func(c *amqpConsumer) bool { return c.tag == tag }) {
		return nil, &amqpChannelFailure{530, "NOT_ALLOWED - consumer tag already in use"}
	}
	c := &amqpConsumer{a, ch, q, m.channel, tag, flags&2 != 0, exclusive}
	q.consumers = append(q.consumers, c)
	ch.consumers = append(ch.consumers, c)
	a.consumers = append(a.consumers, c)
	b.notifyQueue(q)
	if flags&8 != 0 {
		return nil, nil
	}
	return amqpMethodWire(m.channel, 60, 21, appendAMQPShort(nil, tag)), nil
}

func (b *amqpBroker) cancel(ch *amqpChannel, m amqpMethod) ([]byte, *amqpChannelFailure) {
	args := amqpArgs{data: m.body}
	tag, flags := args.short(), args.flags()
	if !args.done() {
		return nil, &amqpChannelFailure{503, "COMMAND_INVALID"}
	}
	for _, c := range ch.consumers {
		if c.tag == tag {
			b.removeConsumer(c)
			if flags&1 != 0 {
				return nil, nil
			}
			return amqpMethodWire(m.channel, 60, 31, appendAMQPShort(nil, tag)), nil
		}
	}
	return amqpMethodWire(m.channel, 20, 40, amqpCloseBody(404, "NOT_FOUND - Consumer not found", m)), nil
}

func (b *amqpBroker) detachConsumer(c *amqpConsumer) {
	match := func(current *amqpConsumer) bool { return current == c }
	c.session.consumers = slices.DeleteFunc(c.session.consumers, match)
	c.state.consumers = slices.DeleteFunc(c.state.consumers, match)
	c.queue.consumers = slices.DeleteFunc(c.queue.consumers, match)
}

func (b *amqpBroker) removeConsumer(c *amqpConsumer) {
	q := c.queue
	b.detachConsumer(c)
	if q.flags&8 != 0 && len(q.consumers) == 0 {
		b.deleteQueue(q)
		return
	}
	b.notifyQueue(q)
}

func (b *amqpBroker) notifyChannel(ch *amqpChannel) {
	for _, c := range ch.consumers {
		b.notifyQueue(c.queue)
	}
}

func (b *amqpBroker) notifyQueue(q *amqpQueue) {
	if c, _ := amqpNextConsumer(q); c != nil {
		c.session.signalPush()
	}
}

func (a *amqpSession) signalPush() {
	select {
	case a.pushReady <- struct{}{}:
	default:
	}
}

func amqpNextConsumer(q *amqpQueue) (*amqpConsumer, int) {
	if len(q.ready) != 0 {
		for i, c := range q.consumers {
			if !c.state.flowPaused && (c.autoAck || c.state.prefetch == 0 || len(c.state.unacknowledged) < int(c.state.prefetch)) {
				return c, i
			}
		}
	}
	return nil, -1
}

func (b *amqpBroker) nextDelivery(a *amqpSession) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range a.consumers {
		q := c.queue
		next, slot := amqpNextConsumer(q)
		if c != next {
			continue
		}
		copy(q.consumers[slot:], q.consumers[slot+1:])
		q.consumers[len(q.consumers)-1] = c
		msg, tag := b.takeMessage(q, c.state, c.autoAck)
		b.notifyQueue(q)

		body := appendAMQPShort(nil, c.tag)
		body = append(binary.BigEndian.AppendUint64(body, tag), 0)
		body = appendAMQPShort(body, msg.exchange)
		body = appendAMQPShort(body, msg.key)
		return msg.appendContent(amqpMethodWire(c.channel, 60, 60, body), c.channel)
	}
	return nil
}

func (a *amqpSession) startPushDelivery() func() {
	a.pushReady = make(chan struct{}, 1)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-a.pushReady:
			}
			a.pushMu.Lock()
			select {
			case <-stop:
				a.pushMu.Unlock()
				return
			default:
			}
			packet := a.broker.nextDelivery(a)
			var err error
			if len(packet) != 0 {
				err = a.write(packet)
			}
			a.pushMu.Unlock()
			if err != nil {
				a.Conn.Close()
				return
			}
			if len(packet) != 0 {
				a.signalPush()
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(stop)
		<-stopped
	})
}
