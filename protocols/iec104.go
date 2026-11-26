package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	iec104Idle          = 20 * time.Second
	iec104ConfirmWait   = 15 * time.Second
	iec104TickInterval  = 100 * time.Millisecond
	iec104SequenceMax   = 0x7fff
	iec104SendWindow    = 13
	iec104ReceiveWindow = 8
)

type iec104Link struct {
	started                      bool
	sent, received, acknowledged uint16
	accepted, receiveAckDeadline time.Time
	unreported                   int
	idleDeadline, testDeadline   time.Time
	sendDeadline                 time.Time
	pending                      []time.Time
	queued                       [][]byte
}

type iec104Input struct {
	io.Reader
	reads uint64
}

func (input *iec104Input) Read(p []byte) (int, error) {
	n, err := input.Reader.Read(p)
	if n > 0 {
		input.reads++
	}
	return n, err
}

func init() {
	AddProtocol(NewProtocolInfo("iec104", serveIEC104, 2404))
}

func serveIEC104(session *SessionConnection) error {
	defer session.DeleteActivity()
	input := &iec104Input{Reader: session.Conn}
	reader := bufio.NewReader(input)
	var lastRead uint64
	accepted := time.Now()
	link := iec104Link{accepted: accepted, idleDeadline: accepted.Add(iec104Idle)}
	var frameDeadline time.Time
	for {
		now := time.Now()
		confirmation := link.confirmationDeadline()
		if !confirmation.IsZero() && !now.Before(confirmation) {
			return nil
		}
		if !frameDeadline.IsZero() && !now.Before(frameDeadline) {
			return errors.New("incomplete IEC 104 frame")
		}
		nextSend := link.nextSend()
		if !nextSend.IsZero() && !now.Before(nextSend) {
			if err := iec104Write(session.Conn, link.sendQueued(nil, now)); err != nil {
				return err
			}
			continue
		}
		if ack := link.receiveAck(now); len(ack) != 0 {
			if err := iec104Write(session.Conn, ack); err != nil {
				return err
			}
		}
		deadline := frameDeadline
		if frameDeadline.IsZero() && link.testDeadline.IsZero() {
			if !now.Before(link.idleDeadline) && reader.Buffered() == 0 {
				if err := iec104Write(session.Conn, iec104UFrame(0x43)); err != nil {
					return err
				}
				link.testDeadline = time.Now().Add(iec104ConfirmWait)
				continue
			}
			deadline = link.idleDeadline
		}
		for _, timer := range [...]time.Time{confirmation, link.receiveAckDeadline, nextSend} {
			if !timer.IsZero() && (deadline.IsZero() || timer.Before(deadline)) {
				deadline = timer
			}
		}
		if err := session.Conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		if frameDeadline.IsZero() {
			if _, err := reader.Peek(1); err == nil {
				frameDeadline = time.Now().Add(iec104ConfirmWait)
			} else if errors.Is(err, io.EOF) {
				return nil
			} else if !iec104TimedOut(err) {
				return err
			}
			continue
		}
		frame, err := readIEC104Frame(reader)
		if iec104TimedOut(err) {
			continue
		}
		if err != nil {
			return err
		}
		frameDeadline = time.Time{}
		now = time.Now()
		if !confirmation.IsZero() && !now.Before(confirmation) {
			return nil
		}
		link.idleDeadline = now.Add(iec104Idle)
		form := iec104FrameForm(frame[2])
		logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "request", logrus.Fields{
			"message_type": form, "raw_data": frame,
		})
		reply, closeConnection := link.reply(frame[2:], form, input.reads != lastRead, now)
		lastRead = input.reads
		if closeConnection {
			return nil
		}
		if len(reply) != 0 {
			if err := iec104Write(session.Conn, reply); err != nil {
				return err
			}
		}
	}
}

func readIEC104Frame(reader *bufio.Reader) ([]byte, error) {
	header, err := reader.Peek(2)
	if err != nil {
		return nil, err
	}
	size := int(header[1])
	if header[0] != 0x68 || size < 4 || size > 253 {
		return nil, errors.New("invalid IEC 104 frame")
	}
	wire, err := reader.Peek(size + 2)
	if err != nil {
		return nil, err
	}
	frame := append([]byte(nil), wire...)
	_, err = reader.Discard(len(frame))
	return frame, err
}

func iec104TimedOut(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

func (link *iec104Link) confirmationDeadline() time.Time {
	if len(link.pending) != 0 && (link.testDeadline.IsZero() || link.pending[0].Before(link.testDeadline)) {
		return link.pending[0]
	}
	return link.testDeadline
}

func (link *iec104Link) acknowledge(n uint16) bool {
	count := int((n - link.acknowledged) & iec104SequenceMax)
	if count > len(link.pending) {
		return false
	}
	remaining := copy(link.pending, link.pending[count:])
	clear(link.pending[remaining:])
	link.pending = link.pending[:remaining]
	link.acknowledged = n
	return true
}

func (link *iec104Link) reply(body []byte, form string, newRead bool, now time.Time) ([]byte, bool) {
	if form == "uAPCI" {
		if len(body) != 4 || body[1] != 0 || body[2] != 0 || body[3] != 0 {
			return nil, false
		}
		var reply []byte
		switch body[0] {
		case 0x07: // STARTDT activation
			link.started = true
			return link.sendQueued(iec104UFrame(0x0b), now), false
		case 0x13: // STOPDT activation
			link.started = false
			return iec104UFrame(0x23), false
		case 0x43: // TESTFR activation
			reply = iec104UFrame(0x83)
		case 0x83: // TESTFR confirmation
			link.testDeadline = time.Time{}
		}
		if newRead {
			reply = link.sendQueued(reply, now)
		}
		return reply, false
	}
	if form == "sAPCI" {
		if len(body) != 4 || body[0] != 1 || body[1] != 0 || body[2]&1 != 0 {
			return nil, false
		}
		previousAck := link.acknowledged
		if !link.acknowledge(binary.LittleEndian.Uint16(body[2:]) >> 1) {
			return nil, true
		}
		if newRead || link.acknowledged != previousAck {
			return link.sendQueued(nil, now), false
		}
		return nil, false
	}
	if !link.started {
		return nil, false
	}
	previousAck := link.acknowledged
	if binary.LittleEndian.Uint16(body[:2])>>1 != link.received ||
		body[2]&1 != 0 || !link.acknowledge(binary.LittleEndian.Uint16(body[2:])>>1) {
		return nil, true
	}
	link.received = (link.received + 1) & iec104SequenceMax
	if link.unreported == 0 {
		// A connection checks for overdue receive confirmations every 100 ms.
		link.receiveAckDeadline = link.tickAfter(now).Add(iec104TickInterval)
	}
	link.unreported++
	var reply []byte
	if link.unreported >= iec104ReceiveWindow {
		reply = link.supervisoryFrame()
	}
	// A new read can release responses to earlier APDUs. Responses to the
	// current APDU enter the queue after this dispatch.
	if newRead || link.acknowledged != previousAck {
		reply = link.sendQueued(reply, now)
	}
	asdu := iec104Interrogation(body[4:])
	if asdu != nil {
		if len(link.pending)+len(link.queued) > iec104SequenceMax-3 {
			return nil, true
		}
		if len(link.queued) == 0 {
			link.sendDeadline = link.tickAfter(now)
		}
		link.queueInterrogation(asdu)
	}
	return reply, false
}

func (link *iec104Link) tickAfter(now time.Time) time.Time {
	tick := now.Sub(link.accepted) / iec104TickInterval
	return link.accepted.Add((tick + 1) * iec104TickInterval)
}

func (link *iec104Link) nextSend() time.Time {
	if !link.started || len(link.pending) == iec104SendWindow {
		return time.Time{}
	}
	return link.sendDeadline
}

func iec104Interrogation(asdu []byte) []byte {
	if len(asdu) < 10 || asdu[0] != 100 || (asdu[4] == 0 && asdu[5] == 0) {
		return nil
	}
	count := int(asdu[1] & 0x7f)
	size := 6 + 4*count
	if asdu[1]&0x80 != 0 {
		size = 9 + count
	}
	if count == 0 || size > len(asdu) {
		return nil
	}
	return asdu[:size]
}

func (link *iec104Link) supervisoryFrame() []byte {
	link.clearReceiveAck()
	return binary.LittleEndian.AppendUint16([]byte{0x68, 4, 1, 0}, link.received<<1)
}

func (link *iec104Link) receiveAck(now time.Time) []byte {
	if link.receiveAckDeadline.IsZero() || now.Before(link.receiveAckDeadline) {
		return nil
	}
	return link.supervisoryFrame()
}

func (link *iec104Link) clearReceiveAck() {
	link.unreported = 0
	link.receiveAckDeadline = time.Time{}
}

func (link *iec104Link) queueInterrogation(request []byte) {
	cause, flags := request[2]&0x3f, request[2]&0xc0
	if cause != 6 && cause != 8 {
		unknownCause := append([]byte(nil), request...)
		unknownCause[2] = 45 | flags
		link.queued = append(link.queued, unknownCause)
		return
	}
	// The reference omits the first information object address in these responses.
	confirmation := append(make([]byte, 0, len(request)-3), request[:6]...)
	confirmation = append(confirmation, request[9:]...)
	if request[6] != 0 || request[7] != 0 || request[8] != 0 {
		confirmation[2] = 47 | flags
		link.queued = append(link.queued, confirmation)
		return
	}
	confirmation[2] = 7 | flags
	termination := append([]byte(nil), confirmation...)
	termination[2] = 10 | flags
	// The reference exposes a single synthetic single-point indication.
	link.queued = append(link.queued,
		confirmation,
		[]byte{1, 1, 20, 0, 0xff, 0xff, 0, 0, 0, 0},
		termination,
	)
}

func (link *iec104Link) sendQueued(dst []byte, now time.Time) []byte {
	if !link.started {
		return dst
	}
	count := min(len(link.queued), iec104SendWindow-len(link.pending))
	if count != 0 {
		link.clearReceiveAck()
	}
	for _, asdu := range link.queued[:count] {
		dst = append(dst, 0x68, byte(4+len(asdu)))
		dst = binary.LittleEndian.AppendUint16(dst, link.sent<<1)
		dst = binary.LittleEndian.AppendUint16(dst, link.received<<1)
		dst = append(dst, asdu...)
		link.sent = (link.sent + 1) & iec104SequenceMax
		link.pending = append(link.pending, now.Add(iec104ConfirmWait))
	}
	remaining := copy(link.queued, link.queued[count:])
	clear(link.queued[remaining:])
	link.queued = link.queued[:remaining]
	if len(link.queued) == 0 {
		link.sendDeadline = time.Time{}
	}
	return dst
}

func iec104FrameForm(control byte) string {
	if control&1 == 0 {
		return "iAPCI"
	}
	if control&3 == 1 {
		return "sAPCI"
	}
	return "uAPCI"
}

func iec104UFrame(control byte) []byte {
	return []byte{0x68, 4, control, 0, 0, 0}
}

func iec104Write(conn net.Conn, frames []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(iec104ConfirmWait)); err != nil {
		return err
	}
	for len(frames) != 0 {
		size := int(frames[1]) + 2
		n, err := conn.Write(frames[:size])
		if err != nil {
			return err
		}
		if n != size {
			return io.ErrShortWrite
		}
		frames = frames[size:]
	}
	return nil
}
