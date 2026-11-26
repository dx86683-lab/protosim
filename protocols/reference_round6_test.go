package protocols

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// Replays sessions captured from the reference release on the test host.
// Each step sends a request and compares the reply, ignoring masked byte
// ranges that hold random values, timestamps or the client port.

//go:embed fixtures/reference-round6.json
var round6Fixtures []byte

type round6Step struct {
	Send     string   `json:"send"`
	Recv     string   `json:"recv"`
	Mask     [][2]int `json:"mask"`
	EOF      bool     `json:"eof"`
	Silence  bool     `json:"silence"`
	Terminal bool     `json:"terminal"`
}

type round6Case struct {
	Name       string                 `json:"name"`
	Handler    string                 `json:"handler"`
	UDP        bool                   `json:"udp"`
	Params     map[string]interface{} `json:"params"`
	Steps      []round6Step           `json:"steps"`
	SimSteps []round6Step           `json:"sim_steps"`
}

func maskedEqual(got, want []byte, mask [][2]int) bool {
	if len(got) != len(want) {
		return false
	}
	g, w := bytes.Clone(got), bytes.Clone(want)
	for _, m := range mask {
		for i := m[0]; i < m[1] && i < len(g); i++ {
			g[i], w[i] = 0, 0
		}
	}
	return bytes.Equal(g, w)
}

func stableRDPMCS(frame []byte) []byte {
	if len(frame) < 20 || !bytes.Equal(frame[4:9], []byte{2, 0xf0, 0x80, 0x7f, 0x66}) {
		return nil
	}
	response, err := decodeBER(frame[8:])
	if err != nil || len(response.Children) != 4 || response.Children[3].Tag != 4 {
		return nil
	}
	gcc := response.Children[3].Value
	if !bytes.HasPrefix(gcc, []byte(rdpGCCServerHeader)) {
		return nil
	}
	blocks := readRDPPerPayload(gcc[len(rdpGCCServerHeader):])
	stable := bytes.Clone(frame[12 : len(frame)-len(gcc)-4])
	for len(blocks) >= 4 {
		kind := binary.LittleEndian.Uint16(blocks)
		size := int(binary.LittleEndian.Uint16(blocks[2:]))
		if size < 4 || size > len(blocks) {
			return nil
		}
		if kind == 0x0c02 {
			security := blocks[4:size]
			if size != len(blocks) || len(security) < 52 || binary.LittleEndian.Uint32(security[8:]) != 32 ||
				binary.LittleEndian.Uint32(security[12:]) != uint32(len(security)-48) {
				return nil
			}
			return append(stable, security[:12]...)
		}
		stable = append(stable, blocks[:size]...)
		blocks = blocks[size:]
	}
	return nil
}

func startRound6Server(t *testing.T, c round6Case) (net.Conn, func()) {
	t.Helper()
	entry, ok := registor.Load(c.Handler)
	if !ok {
		t.Fatalf("%s is not registered", c.Handler)
	}
	if _, configured := c.Params["fs_path"]; c.Handler == "nfs" && !configured {
		params := map[string]any{"fs_path": t.TempDir()}
		for k, v := range c.Params {
			params[k] = v
		}
		c.Params = params
	}
	ci := &ConfigInfo{BindInfo: &BindInfo{Handler: c.Handler, Params: c.Params, IP: "127.0.0.1"}}
	protocol := entry.(*ProtocolInfo)
	handler := protocol.HandleFunc
	if c.UDP && protocol.DatagramHandler != nil {
		handler = (func(*UDPConnection, []byte) error)(protocol.DatagramHandler(ci.BindInfo))
	}
	if factory, ok := handler.(func() (TCPFunction, UDPFunction)); ok {
		stream, datagram := factory()
		if c.UDP {
			handler = (func(*UDPConnection, []byte) error)(datagram)
		} else {
			handler = (func(*SessionConnection) error)(stream)
		}
	}
	if factory, ok := handler.(func() func(*SessionConnection) error); ok {
		handler = factory()
	}
	switch handle := handler.(type) {
	case func(*UDPConnection, []byte) error:
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 65536)
			for {
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					return
				}
				handle(NewUDPConnection(server, addr, ci), bytes.Clone(buf[:n]))
			}
		}()
		client, err := net.Dial("udp4", server.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		return client, func() { client.Close(); server.Close() }
	case func(*SessionConnection) error:
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handle(&SessionConnection{Conn: conn, ConfigInfo: ci})
			conn.Close()
		}()
		client, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return client, func() { client.Close(); ln.Close() }
	case func(*ConfigInfo) http.Handler:
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: handle(ci)}
		go srv.Serve(ln)
		client, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return client, func() { client.Close(); srv.Close() }
	default:
		t.Fatalf("unsupported handler type %T", handle)
	}
	return nil, nil
}

func runRound6Case(t *testing.T, c round6Case) {
	client, stop := startRound6Server(t, c)
	defer stop()
	steps := c.Steps
	if len(c.SimSteps) > 0 {
		steps = c.SimSteps
	}
	for i, step := range steps {
		send, err := hex.DecodeString(step.Send)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(step.Recv)
		if err != nil {
			t.Fatal(err)
		}
		if len(send) > 0 {
			if _, err := client.Write(send); err != nil {
				if step.EOF || step.Terminal {
					return
				}
				t.Fatalf("step %d: write: %v", i, err)
			}
		}
		switch {
		case len(want) > 0:
			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			if c.Handler == "rdp" && len(send) >= 9 && bytes.Equal(send[7:9], []byte{0x7f, 0x65}) {
				got, err := readTPKT(client)
				actual := stableRDPMCS(got)
				if err != nil || len(actual) == 0 || !bytes.Equal(actual, stableRDPMCS(want)) {
					t.Fatalf("step %d: unexpected RDP MCS settings: %x (%v)", i, got, err)
				}
				continue
			}
			got := make([]byte, len(want))
			if c.UDP {
				buf := make([]byte, 65536)
				n, err := client.Read(buf)
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				got = buf[:n]
			} else if _, err := io.ReadFull(client, got); err != nil {
				t.Fatalf("step %d: read %x: %v; want %x", i, got, err, want)
			}
			if !maskedEqual(got, want, step.Mask) {
				t.Fatalf("step %d: received\n%x\nwant\n%x", i, got, want)
			}
		case step.EOF || step.Terminal:
			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			var b [1]byte
			if n, err := client.Read(b[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("step %d: expected close, got %d bytes, %v", i, n, err)
			}
			return
		case step.Silence:
			client.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			var b [1]byte
			n, err := client.Read(b[:])
			if n > 0 || (!c.UDP && !errors.Is(err, os.ErrDeadlineExceeded)) {
				t.Fatalf("step %d: expected an open connection without reply, got %x (%v)", i, b[:n], err)
			}
		}
	}
}

func TestReferenceRound6Sessions(t *testing.T) {
	t.Chdir(t.TempDir()) // handlers extract their default resource files
	var cases []round6Case
	if err := json.Unmarshal(round6Fixtures, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.SimSteps != nil {
			c.Steps = c.SimSteps
		}
		t.Run(c.Name, func(t *testing.T) { runRound6Case(t, c) })
	}
}
