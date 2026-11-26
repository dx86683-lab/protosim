package protocols

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestAMQPReferenceConnectionResponses(t *testing.T) {
	wire := func(s string) string {
		t.Helper()
		data, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	t.Run("unsupported header", func(t *testing.T) {
		requireReferenceTCP(t, "amqp", nil, []referenceExchange{{"ABCDEFGH", amqp091}})
	})

	const header = "414d515000000901"
	const goodAuth = "01000000000024000a000b0000000005504c41494e0000000c00677565737400677565737405656e5f5553ce"
	const badAuth = "01000000000024000a000b0000000005504c41494e0000000c006775657374006f7468657205656e5f5553ce"
	const tune = "0100000000000c000a001e100000010000000ace"
	const open = "0100000000000c000a001f100000010000000ace01000000000008000a0028012f0000ce"
	const openOK = "01000000000005000a002900ce"
	const channelOpen = "010001000000050014000a00ce"
	const channelOpenOK = "010001000000080014000b00000000ce"
	start := amqpStart(&SessionConnection{ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	startFrame := wire("0100000000017d000a000a") + string(start) + "\xce"

	t.Run("rejected login", func(t *testing.T) {
		requireReferenceTCP(t, "amqp", nil, []referenceExchange{
			{wire(header), startFrame},
			{wire(badAuth), wire("01000000000026000a003202121b4e4f545f414c4c4f574544202d206c6f67696e206661696c757265000a000bce")},
		})
	})
	t.Run("open and close channel", func(t *testing.T) {
		requireReferenceTCP(t, "amqp", nil, []referenceExchange{
			{wire(header), startFrame},
			{wire(goodAuth), wire(tune)},
			{wire(open), wire(openOK)},
			{wire(channelOpen), wire(channelOpenOK)},
			{wire("0100010000000e0014002800c80362796500000000ce"), wire("0100010000000400140029ce")},
		})
	})
}

func TestAMQPConsumerAcrossConnections(t *testing.T) {
	serve := newAMQPHandler()
	connect := func() net.Conn {
		t.Helper()
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		go serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
		amqpTestWrite(t, client, []byte(amqp091))
		amqpTestMethod(t, client, 10, 10)
		startOK := "\x00\x00\x00\x00\x05PLAIN\x00\x00\x00\x0c\x00guest\x00guest\x05en_US"
		amqpTestWrite(t, client, amqpMethodWire(0, 10, 11, []byte(startOK)))
		amqpTestMethod(t, client, 10, 30)
		amqpTestWrite(t, client, amqpMethodWire(0, 10, 40, []byte("\x01/\x00\x00")))
		amqpTestMethod(t, client, 10, 41)
		amqpTestWrite(t, client, amqpMethodWire(1, 20, 10, []byte{0}))
		amqpTestMethod(t, client, 20, 11)
		return client
	}

	receiver, publisher := connect(), connect()
	amqpTestWrite(t, receiver, amqpMethodWire(1, 50, 10, []byte("\x00\x00\x01q\x00\x00\x00\x00\x00")))
	amqpTestMethod(t, receiver, 50, 11)
	amqpTestWrite(t, receiver, amqpMethodWire(1, 60, 20, []byte("\x00\x00\x01q\x01t\x02\x00\x00\x00\x00")))
	amqpTestMethod(t, receiver, 60, 21)

	publication := amqpMethodWire(1, 60, 40, []byte("\x00\x00\x00\x01q\x00"))
	header := []byte("\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00")
	publication = appendAMQPFrame(publication, 2, 1, header)
	amqpTestWrite(t, publisher, appendAMQPFrame(publication, 3, 1, []byte("ok")))
	deliver := amqpTestMethod(t, receiver, 60, 60)
	if string(deliver) != "\x01t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01q" {
		t.Fatalf("unexpected delivery method body %x", deliver)
	}
	for i, want := range [][]byte{header, []byte("ok")} {
		frame, err := readAMQPFrame(receiver)
		if err != nil || frame.kind != byte(i+2) || frame.channel != 1 || string(frame.payload) != string(want) {
			t.Fatalf("content frame %d = %#v, error %v, want %x", i, frame, err, want)
		}
	}
}

func amqpTestWrite(t *testing.T, conn net.Conn, packet []byte) {
	t.Helper()
	if n, err := conn.Write(packet); err != nil || n != len(packet) {
		t.Fatalf("wrote %d of %d AMQP bytes, error %v", n, len(packet), err)
	}
}

func amqpTestMethod(t *testing.T, conn net.Conn, class, id uint16) []byte {
	t.Helper()
	frame, err := readAMQPFrame(conn)
	if err != nil || frame.kind != 1 || len(frame.payload) < 4 ||
		binary.BigEndian.Uint16(frame.payload) != class || binary.BigEndian.Uint16(frame.payload[2:]) != id {
		t.Fatalf("method frame = %#v, error %v, want class %d and method %d", frame, err, class, id)
	}
	return frame.payload[4:]
}

func TestAMQPQueuedDelivery(t *testing.T) {
	// One channel declares q, publishes "ok", gets it, and sees the empty queue.
	wire := func(s string) string {
		t.Helper()
		p, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(p)
	}
	start := amqpStart(&SessionConnection{ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	requireReferenceTCP(t, "amqp", nil, []referenceExchange{
		{amqp091, wire("0100000000017d000a000a") + string(start) + "\xce"},
		{wire("01000000000024000a000b0000000005504c41494e0000000c00677565737400677565737405656e5f5553ce"), wire("0100000000000c000a001e100000010000000ace")},
		{wire("01000000000008000a0028012f0000ce"), wire("01000000000005000a002900ce")},
		{wire("010001000000050014000a00ce"), wire("010001000000080014000b00000000ce")},
		{wire("0100010000000d0032000a000001710000000000ce"), wire("0100010000000e0032000b01710000000000000000ce")},
		{wire("0100010000000a003c0028000000017100ce0200010000000e003c000000000000000000020000ce030001000000026f6bce"), ""},
		{wire("01000100000009003c00460000017101ce"), wire("01000100000014003c004700000000000000010000017100000001ce0200010000000e003c000000000000000000020000ce030001000000026f6bce")},
		{wire("0100010000000a003c0028000000017100ce0200010000000e003c000000000000000000000000ce"), ""},
		{wire("01000100000009003c00460000017101ce"), wire("01000100000005003c004800ce")},
		{wire("0100010000000f003c00140000017101740200000000ce"), wire("01000100000006003c00150174ce")},
		{wire("01000100000004005a000ace010001000000050014001400ce"), wire("010001000000050014001500ce")},
		{wire("0100010000000a003c0028000000017100ce0200010000000e003c000000000000000000020000ce030001000000026f6bce"), ""},
		{wire("010001000000050014001401ce"), wire("010001000000050014001501ce01000100000012003c003c0174000000000000000200000171ce0200010000000e003c000000000000000000020000ce030001000000026f6bce")},
		{wire("01000100000005003c006e01ce"), wire("01000000000046000a0032021c3b") + "NOT_IMPLEMENTED - unable to route basic method BasicRecover" + wire("003c006ece")},
	})
}

func TestAMQPHeaderBindingTypes(t *testing.T) {
	const number = "\x01nI\x00\x00\x00\x07"
	const text = "\x01kS\x00\x00\x00\x01v"
	binding, key, failure := parseAMQPHeaderBinding([]byte(number + text))
	_, reordered, _ := parseAMQPHeaderBinding([]byte(text + number))
	if failure != nil || key != reordered {
		t.Fatal("the same binding with reordered arguments must have the same identity")
	}
	headers := func(table string) map[string]string {
		header := append([]byte("\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x00\x01x"), appendAMQPLong(nil, []byte(table))...)
		return amqpPublicationHeaders(header)
	}
	if !binding.matches(headers(number+text)) || binding.matches(headers(text)) ||
		binding.matches(headers("\x01nS\x00\x00\x00\x017"+text)) {
		t.Fatal("headers must match every field and preserve the field types")
	}
	any, _, failure := parseAMQPHeaderBinding([]byte("\x07x-matchS\x00\x00\x00\x03any" + number + text))
	if failure != nil || !any.matches(headers(text)) || any.matches(headers("")) {
		t.Fatal("x-match=any requires at least one matching field")
	}
	empty, _, failure := parseAMQPHeaderBinding([]byte("\x07x-matchS\x00\x00\x00\x03all"))
	if failure != nil || !empty.matches(headers(text)) || !empty.matches(headers("")) || empty.matches(nil) {
		t.Fatal("an empty all binding matches messages carrying headers")
	}
}
