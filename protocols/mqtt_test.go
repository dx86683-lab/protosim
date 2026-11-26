package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

//go:embed fixtures/reference-mqtt.json
var mqttFixture []byte

func TestReferenceMQTTLargeRetainedPublication(t *testing.T) {
	broker := newMQTTBroker()
	start := func(id string) net.Conn {
		t.Helper()
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		go func() {
			defer server.Close()
			broker.serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
		}()
		body := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 0}
		body = append(binary.BigEndian.AppendUint16(body, uint16(len(id))), id...)
		writeMQTTTestPacket(t, client, mqttPacket{0x10, body})
		readMQTTTestPacket(t, client, mqttPacket{0x20, []byte{1, 0}})
		return client
	}
	const topic = "synthetic/large-retained/"
	const size = 16 << 20
	writer := start("size-writer")
	var publications []mqttPacket
	for _, suffix := range []string{"a", "b"} {
		name := topic + suffix
		body := make([]byte, size)
		binary.BigEndian.PutUint16(body, uint16(len(name)))
		copy(body[2:], name)
		binary.BigEndian.PutUint16(body[2+len(name):], 7)
		for i := 4 + len(name); i < len(body); i++ {
			body[i] = byte(i) ^ suffix[0]
		}
		publication := mqttPacket{0x33, body}
		writeMQTTTestPacket(t, writer, publication)
		readMQTTTestPacket(t, writer, mqttPacket{0x40, []byte{0, 7}})
		publications = append(publications, publication)
	}
	writeMQTTTestPacket(t, writer, mqttPacket{header: 0xc0})
	readMQTTTestPacket(t, writer, mqttPacket{header: 0xd0})

	reader := start("size-reader")
	filter := topic + "#"
	subscription := append(binary.BigEndian.AppendUint16([]byte{0, 1}, uint16(len(filter))), filter...)
	subscription = append(subscription, 1)
	writeMQTTTestPacket(t, reader, mqttPacket{0x82, subscription})
	readMQTTTestPacket(t, reader, mqttPacket{0x90, []byte{0, 1, 1}})
	for _, publication := range publications {
		readMQTTTestPacket(t, reader, publication)
	}
}

func TestMQTTRetainedByteLimit(t *testing.T) {
	broker := newMQTTBroker()
	full := mqttPacket{data: make([]byte, 16<<20)}
	broker.publish("first", full, mqttStoreRetained)
	broker.publish("second", full, mqttStoreRetained)
	broker.publish("third", full, mqttStoreRetained)
	if _, stored := broker.retained["third"]; stored || broker.retainedBytes != 32<<20 {
		t.Fatalf("retained bytes = %d, third stored = %v", broker.retainedBytes, stored)
	}
	broker.publish("first", mqttPacket{}, mqttClearRetained)
	half := mqttPacket{data: full.data[:len(full.data)/2]}
	broker.publish("second", half, mqttStoreRetained)
	broker.publish("third", full, mqttStoreRetained)
	if len(broker.retained) != 2 || broker.retainedBytes != len(half.data)+len(full.data) {
		t.Fatalf("after clear and replacement: retained entries = %d, bytes = %d", len(broker.retained), broker.retainedBytes)
	}
}

func TestMQTTPacketSizeLimits(t *testing.T) {
	for _, test := range []struct {
		name             string
		header           byte
		packetSize       int
		publicationLimit int
	}{
		{"publish after connect", 0x32, 16<<20 + 1, maxMQTTPublication},
		{"publish before connect", 0x32, 1<<20 + 1, maxMQTTPacket},
		{"subscribe after connect", 0x82, 1<<20 + 1, maxMQTTPublication},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := (mqttPacket{header: test.header, data: make([]byte, test.packetSize)}).wire()
			reader := bufio.NewReader(bytes.NewReader(wire[:len(wire)-test.packetSize]))
			if _, data, err := readMQTTPacket(reader, test.publicationLimit); data != nil || err == nil || err.Error() != "invalid MQTT packet size" {
				t.Fatalf("expected size rejection before reading the body, got %d bytes and %v", len(data), err)
			}
		})
	}
}

func writeMQTTTestPacket(t *testing.T, conn net.Conn, packet mqttPacket) {
	t.Helper()
	if _, err := conn.Write(packet.wire()); err != nil {
		t.Fatal(err)
	}
}

func readMQTTTestPacket(t *testing.T, conn net.Conn, packet mqttPacket) {
	t.Helper()
	want := packet.wire()
	got := make([]byte, len(want))
	n, err := io.ReadFull(conn, got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read %d of %d bytes for MQTT packet %#x (%v)", n, len(want), packet.header, err)
	}
}

func TestReferenceMQTTMessaging(t *testing.T) {
	var steps []struct {
		Client, Open, Send, Receive, Event string
		Close, Online                      bool
		ReceiveUnordered                   []string `json:"receive_unordered"`
	}
	if err := json.Unmarshal(mqttFixture, &steps); err != nil {
		t.Fatal(err)
	}
	clients := map[string]net.Conn{}
	readers := map[string]*bufio.Reader{}
	broker := newMQTTBroker()
	for i, step := range steps {
		if step.Open != "" {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			client, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			listener.Close()
			t.Cleanup(func() { client.Close() })
			clients[step.Client] = client
			readers[step.Client] = bufio.NewReader(client)
			bind := &BindInfo{}
			if step.Open == "auth" {
				bind.Params = map[string]any{"accounts": []any{"fixture:test-only"}}
			}
			go broker.serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: bind, ServerInfo: step.Open}})
			continue
		}
		client := clients[step.Client]
		reader := readers[step.Client]
		if step.Close {
			client.Close()
			continue
		}
		if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("step %d %s: %v", i+1, step.Client, err)
		}
		if step.Send != "" {
			data, err := hex.DecodeString(step.Send)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(data); err != nil {
				t.Fatalf("step %d %s write: %v", i+1, step.Client, err)
			}
		}
		if step.Event != "" {
			header, data, err := readMQTTPacket(reader, maxMQTTPublication)
			if err != nil || header != 0x30 {
				t.Fatalf("step %d: invalid broker event packet %02x (%v)", i+1, header, err)
			}
			topic, payload, ok := cutMQTTString(data)
			var event struct {
				ClientID  string
				Online    bool
				Timestamp time.Time
			}
			if !ok || topic != "$SYS/broker/connection/clients/"+step.Event ||
				json.Unmarshal(payload, &event) != nil || event.ClientID != step.Event ||
				event.Online != step.Online || event.Timestamp.IsZero() {
				t.Fatalf("step %d: invalid broker event %q %s", i+1, topic, payload)
			}
		}
		if len(step.ReceiveUnordered) != 0 {
			var packets []string
			for range step.ReceiveUnordered {
				header, data, err := readMQTTPacket(reader, maxMQTTPublication)
				if err != nil {
					t.Fatalf("step %d %s retained batch: %v", i+1, step.Client, err)
				}
				packets = append(packets, hex.EncodeToString((mqttPacket{header, data}).wire()))
			}
			slices.Sort(packets)
			slices.Sort(step.ReceiveUnordered)
			if !slices.Equal(packets, step.ReceiveUnordered) {
				t.Fatalf("step %d %s retained batch: got %v, want %v", i+1, step.Client, packets, step.ReceiveUnordered)
			}
		}
		switch step.Receive {
		case "":
		case "silence":
			client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var packet [1]byte
			if _, err := reader.Read(packet[:]); err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("step %d %s: expected no packet on an open socket, got %x (%v)", i+1, step.Client, packet, err)
			}
		case "closed":
			var packet [1]byte
			if _, err := reader.Read(packet[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("step %d %s: expected EOF, got %x (%v)", i+1, step.Client, packet, err)
			}
		default:
			expected, err := hex.DecodeString(step.Receive)
			if err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, len(expected))
			if _, err := io.ReadFull(reader, packet); err != nil || hex.EncodeToString(packet) != step.Receive {
				t.Fatalf("step %d %s: got %x (%v), want %s", i+1, step.Client, packet, err, step.Receive)
			}
		}
	}
}

func TestReferenceMQTTKeepAlive(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	broker := newMQTTBroker()
	go broker.serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{}}})
	if err := client.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	exchange := func(request, expected []byte) {
		t.Helper()
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(expected))
		if _, err := io.ReadFull(client, reply); err != nil || string(reply) != string(expected) {
			t.Fatalf("reply = %x (%v), want %x", reply, err, expected)
		}
	}
	connect := mqttPacket{0x10, []byte("\x00\x04MQTT\x04\x02\x00\x01\x00\x04idle")}
	exchange(connect.wire(), []byte{0x20, 2, 1, 0})
	for range 3 {
		time.Sleep(650 * time.Millisecond)
		exchange([]byte{0xc0, 0}, []byte{0xd0, 0})
	}
	started := time.Now()
	if err := client.SetReadDeadline(started.Add(2400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := client.Read(reply[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("expected idle connection close, got %x (%v)", reply, err)
	}
	if waited := time.Since(started); waited < 1200*time.Millisecond {
		t.Fatalf("last PINGREQ did not refresh keepalive, closed after %v", waited)
	}
}

func TestReferenceMQTTRejectedConnectionStaysSilent(t *testing.T) {
	connect := func(level byte, password string) []byte {
		data := append([]byte("\x00\x04MQTT"), level, 0xc2, 0, 1)
		if level == 5 {
			data = append(data, 0) // Empty MQTT 5 properties.
		}
		data = append(data, "\x00\x06client\x00\x07fixture"...)
		data = append(data, 0, byte(len(password)))
		data = append(data, password...)
		return (mqttPacket{header: 0x10, data: data}).wire()
	}
	for _, tc := range []struct {
		name, initialReply string
		connect            []byte
	}{
		{"rejected credentials", "\x20\x02\x01\x05", connect(4, "wrong")},
		{"unsupported MQTT 5", "", connect(5, "test-only")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			broker := newMQTTBroker()
			go broker.serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{
				Params: map[string]any{"accounts": []any{"fixture:test-only"}},
			}}})
			if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			write := func(packet []byte) {
				t.Helper()
				if _, err := client.Write(packet); err != nil {
					t.Fatal(err)
				}
			}
			silence := func() {
				t.Helper()
				if err := client.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, 4)
				if n, err := client.Read(reply); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("expected open, silent connection, got %x (%v)", reply[:n], err)
				}
			}
			write(tc.connect)
			if tc.initialReply != "" {
				if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(tc.initialReply))
				if _, err := io.ReadFull(client, reply); err != nil || string(reply) != tc.initialReply {
					t.Fatalf("initial reply = %x (%v), want %x", reply, err, tc.initialReply)
				}
			} else {
				silence()
			}
			for _, packet := range [][]byte{{0xc0, 0}, connect(4, "test-only"), {0xe0, 0}} {
				write(packet)
				silence()
			}
		})
	}
}
