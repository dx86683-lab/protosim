package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed fixtures/reference-memcache.json
var referenceMemcache []byte

type memcacheTestConn struct{ net.Conn }

func (c memcacheTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func startMemcacheTest(t *testing.T, config *ConfigInfo) (net.Conn, <-chan error) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer server.Close()
		done <- serveMemcache(&SessionConnection{Conn: memcacheTestConn{server}, ConfigInfo: config})
	}()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		<-done
	})
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, done
}

func writeMemcacheTest(t *testing.T, client net.Conn, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if part != "" {
			if _, err := io.WriteString(client, part); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReferenceMemcacheReadBoundary(t *testing.T) {
	client, _ := startMemcacheTest(t, &ConfigInfo{BindInfo: &BindInfo{}})
	for _, step := range []referenceExchange{
		{"version\r\nget q\r\n", "VERSION 1.5.16\r\n"},
		{"set q 0 0 3\r\nabc\r\n", ""},
		{"get q\r\n", "STORED\r\nERROR\r\n"},
		{"get q\r\n", "VALUE q 0 3\r\nget\r\nEND\r\n"},
		{"set q 0 0 3\r\n", ""},
		{"abc\r\nversion\r\n", "STORED\r\n"},
		{"get q\r\n", "VALUE q 0 3\r\nabc\r\nEND\r\n"},
		{"get absent " + strings.Repeat("other ", 1024) + "\r\n", "END\r\n"},
	} {
		// The value reader can acknowledge while the client is still sending the
		// remainder of a write. net.Pipe has no kernel send buffer.
		written := make(chan error, 1)
		go func() {
			_, err := io.WriteString(client, step.send)
			written <- err
		}()
		got := make([]byte, len(step.receive))
		if _, err := io.ReadFull(client, got); err != nil || string(got) != step.receive {
			t.Fatalf("%q returned %q (%v), want %q", step.send, got, err, step.receive)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}

func TestReferenceMemcacheData(t *testing.T) {
	var sessions []struct {
		Name  string
		Steps []struct {
			Command, Body, Response string
			Closed                  bool
		}
	}
	if err := json.Unmarshal(referenceMemcache, &sessions); err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		t.Run(session.Name, func(t *testing.T) {
			client, _ := startMemcacheTest(t, &ConfigInfo{BindInfo: &BindInfo{}})
			for _, step := range session.Steps {
				body := step.Body
				if body != "" {
					if len(body) < 2 || body[len(body)-2:] != "\r\n" {
						t.Fatalf("%q: missing fixture value terminator", step.Command)
					}
					body = body[:len(body)-2]
				}
				writeMemcacheTest(t, client, step.Command, body)
				if step.Closed {
					if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						t.Fatalf("%q: expected close, read %d bytes (%v)", step.Command, n, err)
					}
					continue
				}
				reply := make([]byte, len(step.Response))
				if _, err := io.ReadFull(client, reply); err != nil {
					t.Fatalf("%q: read %q (%v), want %q", step.Command, reply, err, step.Response)
				}
				if string(reply) != step.Response {
					t.Fatalf("%q: reply %q, want %q", step.Command, reply, step.Response)
				}
				if step.Body != "" {
					writeMemcacheTest(t, client, "\r\n")
				}
			}
		})
	}
}

func TestMemcacheStatsCountItemsOnTheCurrentConnection(t *testing.T) {
	type client struct {
		conn   net.Conn
		reader *bufio.Reader
	}
	open := func() client {
		conn, _ := startMemcacheTest(t, &ConfigInfo{BindInfo: &BindInfo{}})
		return client{conn, bufio.NewReader(conn)}
	}
	command := func(c client, request, response string, body ...string) {
		t.Helper()
		writeMemcacheTest(t, c.conn, request)
		writeMemcacheTest(t, c.conn, body...)
		if line, err := c.reader.ReadString('\n'); err != nil || line != response {
			t.Fatalf("%q replied %q (%v), want %q", request, line, err, response)
		}
	}
	count := func(c client, want int) {
		t.Helper()
		if _, err := io.WriteString(c.conn, "stats\r\n"); err != nil {
			t.Fatal(err)
		}
		var items int
		found := false
		for {
			line, err := c.reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "END\r\n" {
				break
			}
			if _, err := fmt.Sscanf(line, "STAT curr_items %d", &items); err == nil {
				found = true
			}
		}
		if !found || items != want {
			t.Fatalf("curr_items = %d (present %t), want %d", items, found, want)
		}
	}

	first, second := open(), open()
	command(first, "set alpha 0 0 1\r\n", "STORED\r\n", "a")
	writeMemcacheTest(t, first.conn, "\r\n")
	command(first, "set beta 0 0 1\r\n", "STORED\r\n", "b")
	writeMemcacheTest(t, first.conn, "\r\n")
	count(first, 2)
	count(second, 0)
	command(second, "set gamma 0 0 1\r\n", "STORED\r\n", "c")
	writeMemcacheTest(t, second.conn, "\r\n")
	command(first, "delete alpha\r\n", "DELETED\r\n")
	count(first, 1)
	command(second, "stats reset\r\n", "RESET\r\n")
	count(second, 1)
}

func TestReferenceMemcacheStatsCounterProgression(t *testing.T) {
	sample := func(conn net.Conn, reader *bufio.Reader) map[string]int {
		t.Helper()
		writeMemcacheTest(t, conn, "stats\r\n")
		result := make(map[string]int)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "END\r\n" {
				return result
			}
			var key string
			var value int
			if _, err := fmt.Sscanf(line, "STAT %s %d", &key, &value); err == nil {
				result[key] = value
			}
		}
	}
	requireRange := func(key string, got, minValue, maxValue int) {
		t.Helper()
		if got < minValue || got > maxValue {
			t.Fatalf("%s = %d, want [%d, %d]", key, got, minValue, maxValue)
		}
	}
	initial := func(stats map[string]int) {
		t.Helper()
		requireRange("bytes_read", stats["bytes_read"], 110, 149)
		requireRange("bytes_written", stats["bytes_written"], 250, 649)
		requireRange("curr_connections", stats["curr_connections"], 1, 4)
	}
	advance := func(before, after map[string]int, requests int) {
		t.Helper()
		requireRange("bytes_read delta", after["bytes_read"]-before["bytes_read"], requests*10, requests*49)
		requireRange("bytes_written delta", after["bytes_written"]-before["bytes_written"], requests*100, requests*499)
	}

	first, _ := startMemcacheTest(t, &ConfigInfo{BindInfo: &BindInfo{}})
	reader := bufio.NewReader(first)
	previous := sample(first, reader)
	initial(previous)
	second, _ := startMemcacheTest(t, &ConfigInfo{BindInfo: &BindInfo{}})
	initial(sample(second, bufio.NewReader(second)))
	current := sample(first, reader)
	advance(previous, current, 1)
	previous = current
	writeMemcacheTest(t, first, "version\r\n")
	if line, err := reader.ReadString('\n'); err != nil || line != "VERSION 1.5.16\r\n" {
		t.Fatalf("VERSION returned %q (%v)", line, err)
	}
	current = sample(first, reader)
	advance(previous, current, 1)
	for range 5 {
		writeMemcacheTest(t, first, "stats reset\r\n")
		if line, err := reader.ReadString('\n'); err != nil || line != "RESET\r\n" {
			t.Fatalf("STATS RESET returned %q (%v)", line, err)
		}
	}
	advance(current, sample(first, reader), 6)
}

func TestReferenceMemcacheCommandEvents(t *testing.T) {
	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetFormatter(&logrus.JSONFormatter{})
	ci := &ConfigInfo{BindInfo: &BindInfo{}, Log: logrus.NewEntry(logger)}
	client, done := startMemcacheTest(t, ci)
	for _, step := range []struct{ command, value, reply string }{
		{"version\r\n", "", "VERSION 1.5.16\r\n"},
		{"unknown event\r\n", "", "ERROR\r\n"},
		{"set bad\r\n", "", "SERVER_ERROR bad command line format\r\n"},
		{"set empty 0 0 0\r\n", "", "ERROR\r\n"},
		{"SeT Name 4 0 5\r\n", "a\r\nbc", "STORED\r\n"},
		{"gEt Name\r\n", "", "VALUE Name 0 5\r\na\r\nbc\r\nEND\r\n"},
	} {
		writeMemcacheTest(t, client, step.command, step.value)
		got := make([]byte, len(step.reply))
		if _, err := io.ReadFull(client, got); err != nil || string(got) != step.reply {
			t.Fatalf("%q returned %q (%v), want %q", step.command, got, err, step.reply)
		}
		if step.value != "" {
			writeMemcacheTest(t, client, "\r\n")
		}
	}
	writeMemcacheTest(t, client, "quit\r\n")
	if _, err := io.ReadAll(client); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	type event struct {
		Msg, Cmd string
		Args     []string
		Body     []byte
	}
	var got []event
	decoder := json.NewDecoder(&logs)
	for {
		var record event
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		got = append(got, record)
	}
	want := []event{
		{"execute command", "version", []string{}, nil},
		{"execute command", "unknown", []string{"event"}, nil},
		{"execute command", "set", []string{"empty", "0", "0", "0"}, []byte{}},
		{"execute command", "set", []string{"Name", "4", "0", "5"}, []byte("a\r\nbc")},
		{"execute command", "get", []string{"Name"}, nil},
		{"execute command", "quit", []string{}, nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Memcached events = %+v, want %+v", got, want)
	}
}
