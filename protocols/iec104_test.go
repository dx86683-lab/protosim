package protocols

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func TestIEC104AcknowledgementWindowWraps(t *testing.T) {
	deadline := time.Now().Add(iec104ConfirmWait)
	link := iec104Link{acknowledged: 32766, pending: []time.Time{deadline, deadline, deadline}}
	if link.acknowledge(2) || !link.acknowledge(0) || len(link.pending) != 1 {
		t.Fatal("unexpected acknowledgement window across the sequence wrap")
	}
	if link.acknowledge(32767) || !link.acknowledge(1) || len(link.pending) != 0 {
		t.Fatal("unexpected acknowledgement window after the sequence wrap")
	}
}

func TestReferenceIEC104ReadSequence(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		wire, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	start := decode("07000000")
	read := decode("00000000660105000100010000")
	now := time.Now()
	link := iec104Link{accepted: now}
	if got, closed := link.reply(read, "iAPCI", true, now); len(got) != 0 || closed || link.received != 0 {
		t.Fatalf("read before STARTDT changed link state: %x, closed=%t", got, closed)
	}
	link.reply(start, "uAPCI", true, now)
	if got, closed := link.reply(read, "iAPCI", true, now); len(got) != 0 || closed {
		t.Fatalf("read replied %x, closed=%t", got, closed)
	}
	if got := link.receiveAck(now.Add(200 * time.Millisecond)); !bytes.Equal(got, decode("680401000200")) {
		t.Fatalf("delayed receive acknowledgement = %x", got)
	}
	if got, closed := link.reply(read, "iAPCI", true, now); len(got) != 0 || !closed {
		t.Fatalf("stale send sequence replied %x, closed=%t", got, closed)
	}
}

func TestReferenceIEC104InterrogationWindow(t *testing.T) {
	now := time.Now()
	link := iec104Link{started: true, accepted: now}
	body := []byte{0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	countFrames := func(wire []byte) int {
		t.Helper()
		count := 0
		for len(wire) != 0 {
			if len(wire) < 2 || wire[0] != 0x68 || int(wire[1])+2 > len(wire) {
				t.Fatalf("invalid APDU in reply: %x", wire)
			}
			wire = wire[int(wire[1])+2:]
			count++
		}
		return count
	}
	for i, wanted := range []int{3, 3, 3, 3, 1, 0} {
		now = link.accepted.Add(time.Duration(i)*iec104TickInterval + time.Millisecond)
		binary.LittleEndian.PutUint16(body, uint16(i)<<1)
		immediate, closed := link.reply(body, "iAPCI", true, now)
		if len(immediate) != 0 || closed {
			t.Fatalf("interrogation %d replied immediately: %x, closed=%t", i+1, immediate, closed)
		}
		var wire []byte
		if next := link.nextSend(); !next.IsZero() {
			wire = link.sendQueued(nil, next)
		}
		if got := countFrames(wire); got != wanted {
			t.Fatalf("interrogation %d returned %d APDUs, want %d, closed=%t", i+1, got, wanted, closed)
		}
	}
	if wire := link.receiveAck(now.Add(200 * time.Millisecond)); !bytes.Equal(wire, []byte{0x68, 4, 1, 0, 12, 0}) {
		t.Fatalf("full window replied %x, want supervisory acknowledgement of six requests", wire)
	}
	for _, tc := range []struct{ ack, want byte }{{2, 1}, {28, 4}} {
		wire, closed := link.reply([]byte{1, 0, tc.ack, 0}, "sAPCI", true, now)
		if got := countFrames(wire); got != int(tc.want) || closed {
			t.Fatalf("supervisory acknowledgement %d returned %d APDUs, want %d, closed=%t", tc.ack>>1, got, tc.want, closed)
		}
	}
}

func TestReferenceIEC104ReceiveAcknowledgement(t *testing.T) {
	started := time.Now()
	now := started.Add(10 * time.Millisecond)
	link := iec104Link{started: true, accepted: started}
	read := []byte{0, 0, 0, 0, 102, 1, 5, 0, 1, 0, 1, 0, 0}
	for sequence := uint16(0); sequence < 8; sequence++ {
		binary.LittleEndian.PutUint16(read, sequence<<1)
		got, closed := link.reply(read, "iAPCI", true, now)
		var want []byte
		if sequence == 7 {
			want = []byte{0x68, 4, 1, 0, 16, 0}
		}
		if !bytes.Equal(got, want) || closed || len(link.receiveAck(now)) != 0 {
			t.Fatalf("read %d replied %x, want %x, closed=%t", sequence, got, want, closed)
		}
	}
	binary.LittleEndian.PutUint16(read, 16)
	if got, closed := link.reply(read, "iAPCI", true, now); len(got) != 0 || closed {
		t.Fatalf("ninth read replied %x, closed=%t", got, closed)
	}
	if got := link.receiveAck(started.Add(190 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("acknowledgement before the next timer interval: %x", got)
	}
	if got := link.receiveAck(started.Add(200 * time.Millisecond)); !bytes.Equal(got, []byte{0x68, 4, 1, 0, 18, 0}) {
		t.Fatalf("timed acknowledgement replied %x", got)
	}
	now = started.Add(210 * time.Millisecond)
	binary.LittleEndian.PutUint16(read, 18)
	link.reply(read, "iAPCI", true, now)
	query := []byte{20, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	immediate, closed := link.reply(query, "iAPCI", false, now)
	if len(immediate) != 0 || !link.nextSend().Equal(started.Add(300*time.Millisecond)) {
		t.Fatalf("interrogation did not queue for the next tick: %x, deadline=%v", immediate, link.nextSend())
	}
	got := link.sendQueued(nil, link.nextSend())
	if len(got) != 42 || got[4] != 22 || closed || len(link.receiveAck(started.Add(time.Second))) != 0 {
		t.Fatalf("interrogation did not acknowledge both requests: %x, closed=%t", got, closed)
	}
}

func TestReferenceIEC104NextReadReleasesOlderResponse(t *testing.T) {
	started := time.Now()
	link := iec104Link{started: true, accepted: started}
	query := []byte{0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	if got, closed := link.reply(query, "iAPCI", true, started.Add(time.Millisecond)); len(got) != 0 || closed {
		t.Fatalf("first interrogation replied %x, closed=%t", got, closed)
	}
	binary.LittleEndian.PutUint16(query, 2)
	wire, closed := link.reply(query, "iAPCI", true, started.Add(15*time.Millisecond))
	if len(wire) != 42 || wire[4] != 4 || closed {
		t.Fatalf("second interrogation did not release the first response with N(R)=2: %x, closed=%t", wire, closed)
	}
	if !link.nextSend().Equal(started.Add(100 * time.Millisecond)) {
		t.Fatalf("second response dispatch deadline = %v", link.nextSend())
	}
	wire = link.sendQueued(nil, link.nextSend())
	if len(wire) != 42 || wire[2] != 6 || wire[4] != 4 {
		t.Fatalf("second response did not continue the sequence: %x", wire)
	}
}

func TestReferenceIEC104AcknowledgementWithPartialFrame(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go serveIEC104(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})

	exchange := func(request, want []byte) {
		t.Helper()
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(want))
		if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, want) {
			t.Fatalf("received %x, %v, want %x", reply, err, want)
		}
	}
	exchange(iec104UFrame(0x07), iec104UFrame(0x0b))
	first := []byte{0x68, 13, 0, 0, 0, 0, 102, 1, 5, 0, 1, 0, 1, 0, 0}
	second := append([]byte(nil), first...)
	second[2] = 2
	exchange(append(first, second[:3]...), []byte{0x68, 4, 1, 0, 2, 0})
	exchange(second[3:], []byte{0x68, 4, 1, 0, 4, 0})
	exchange(iec104UFrame(0x43), iec104UFrame(0x83))
}

func TestReferenceIEC104QueuedResponseDuringStop(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go serveIEC104(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})

	exchange := func(request, response string) {
		t.Helper()
		want, err := hex.DecodeString(response)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := hex.DecodeString(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(wire); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("received %x, %v, want %x", got, err, want)
		}
	}
	exchange("680407000000", "68040b000000")
	exchange("680e0000000064010600010000000014680413000000", "680423000000680401000200")
	exchange("680407000000", "68040b000000680b0000020064010700010014680e0200020001011400ffff00000000680b0400020064010a00010014")
}

type iec104DeadlineConn struct {
	net.Conn
	observe   <-chan struct{}
	deadlines chan<- time.Time
}

func (conn iec104DeadlineConn) SetReadDeadline(deadline time.Time) error {
	select {
	case <-conn.observe:
		select {
		case conn.deadlines <- deadline:
		default:
		}
	default:
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func TestReferenceIEC104ScheduledWritesSetConfirmationDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	observe := make(chan struct{})
	deadlines := make(chan time.Time, 1)
	go serveIEC104(&SessionConnection{
		Conn:       iec104DeadlineConn{Conn: server, observe: observe, deadlines: deadlines},
		ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}},
	})
	if _, err := client.Write(iec104UFrame(0x07)); err != nil {
		t.Fatal(err)
	}
	var wire [64]byte
	if _, err := io.ReadFull(client, wire[:6]); err != nil {
		t.Fatal(err)
	}
	query := []byte{0x68, 14, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	for i, size := range []int{13, 16, 13} {
		if i == 2 {
			close(observe)
		}
		n, err := client.Read(wire[:])
		if err != nil || n != size || wire[0] != 0x68 || int(wire[1])+2 != n {
			t.Fatalf("write %d = %x, %v, want one %d-byte APDU", i+1, wire[:n], err, size)
		}
	}
	select {
	case deadline := <-deadlines:
		if delay := time.Until(deadline); delay < 14*time.Second || delay > 16*time.Second {
			t.Fatalf("read deadline %v after scheduled writes, want about 15s", delay)
		}
	case <-time.After(time.Second):
		t.Fatal("no read deadline after the scheduled writes")
	}
}
