package protocols

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

//go:embed fixtures/reference-redis.json
var redisFixtures []byte

func TestReferenceRedisSessions(t *testing.T) {
	var fixtures []struct {
		Name, Listener string
		Steps          [][2]json.RawMessage
	}
	if err := json.Unmarshal(redisFixtures, &fixtures); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		redisDatabase.Lock()
		delete(redisDatabase.values, "protosim-fixture")
		delete(redisDatabase.values, "protosim-redis-probe")
		delete(redisDatabase.values, "redis-k1")
		delete(redisDatabase.values, "redis-k2")
		delete(redisDatabase.values, "redis-flush-fixture")
		delete(redisDatabase.values, "redis-value-compat")
		delete(redisDatabase.values, "line-value")
		delete(redisDatabase.values, "fixture-space")
		delete(redisDatabase.values, "fixture other")
		delete(redisDatabase.values, "样本")
		redisDatabase.Unlock()
	})
	// The second session observes state written by the first.
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			params := map[string]interface{}{}
			if fixture.Name == "authenticated" || fixture.Listener == "custom" {
				params["accounts"] = []interface{}{"fixture:lab-only"}
			}
			if fixture.Listener == "custom" {
				params["server_version"] = "6.2.7"
			}
			conn, stop := startRound6Server(t, round6Case{Handler: "redis", Params: params})
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			for _, step := range fixture.Steps {
				var request string
				if json.Unmarshal(step[0], &request) != nil {
					var args []string
					if err := json.Unmarshal(step[0], &args); err != nil {
						t.Fatal(err)
					}
					var frame strings.Builder
					fmt.Fprintf(&frame, "*%d\r\n", len(args))
					for _, arg := range args {
						fmt.Fprintf(&frame, "$%d\r\n%s\r\n", len(arg), arg)
					}
					request = frame.String()
				}
				if _, err := io.WriteString(conn, request); err != nil {
					t.Fatal(err)
				}
				var outcome struct {
					Wire               *string
					SimWire          *string  `json:"sim_wire"`
					AlternateWire      []string `json:"alternate_wire"`
					SimAlternateWire []string `json:"sim_alternate_wire"`
					Closed             bool
					Reset              bool
				}
				_ = json.Unmarshal(step[1], &outcome)
				if outcome.SimWire != nil {
					outcome.Wire = outcome.SimWire
				}
				if len(outcome.SimAlternateWire) > 0 {
					outcome.AlternateWire = outcome.SimAlternateWire
				}
				if outcome.Wire != nil {
					reply := make([]byte, len(*outcome.Wire))
					if _, err := io.ReadFull(reader, reply); err != nil ||
						string(reply) != *outcome.Wire && !slices.Contains(outcome.AlternateWire, string(reply)) {
						t.Fatalf("%s: response %q (%v), want %q or %q", step[0], reply, err, *outcome.Wire, outcome.AlternateWire)
					}
				}
				if outcome.Closed || outcome.Reset {
					reply, err := reader.ReadString('\n')
					if outcome.Reset {
						const wsaConnReset = syscall.Errno(10054)
						reset := errors.Is(err, syscall.ECONNRESET) || runtime.GOOS == "windows" && errors.Is(err, wsaConnReset)
						if !reset || reply != "" {
							t.Fatalf("%s: expected reset, received %q (%v)", step[0], reply, err)
						}
						continue
					}
					if err != io.EOF || reply != "" {
						t.Fatalf("%s: expected close, received %q (%v)", step[0], reply, err)
					}
					continue
				}
				if outcome.Wire != nil {
					continue
				}
				reply, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("%s: %v", step[0], err)
				}
				var literal string
				if json.Unmarshal(step[1], &literal) == nil {
					if reply != literal+"\r\n" {
						t.Fatalf("%s: received %q, want %q", step[0], reply, literal)
					}
					continue
				}
				var want struct {
					Length int
					Digest string `json:"bulk_sha256"`
					Keys   []string
				}
				if err := json.Unmarshal(step[1], &want); err != nil {
					t.Fatal(err)
				}
				if want.Keys != nil {
					if reply != fmt.Sprintf("*%d\r\n", len(want.Keys)) {
						t.Fatalf("%s: unexpected array header %q", step[0], reply)
					}
					keys := make([]string, 0, len(want.Keys))
					for range want.Keys {
						header, err := reader.ReadString('\n')
						if err != nil {
							t.Fatal(err)
						}
						keys = append(keys, string(readRedisFixtureBulk(t, reader, header)))
					}
					slices.Sort(keys)
					if !slices.Equal(keys, want.Keys) {
						t.Fatalf("%s: received keys %q, want %q", step[0], keys, want.Keys)
					}
					continue
				}
				payload := readRedisFixtureBulk(t, reader, reply)
				if digest := fmt.Sprintf("%x", sha256.Sum256(payload)); digest != want.Digest || len(payload) != want.Length {
					t.Fatalf("%v: received %d bytes with checksum %s, want %d bytes with checksum %s",
						step[0], len(payload), digest, want.Length, want.Digest)
				}
			}
		})
	}
}

func readRedisFixtureBulk(t *testing.T, reader *bufio.Reader, header string) []byte {
	t.Helper()
	lengthText, bulk := strings.CutPrefix(strings.TrimSuffix(header, "\r\n"), "$")
	length, err := strconv.Atoi(lengthText)
	if !bulk || !strings.HasSuffix(header, "\r\n") || err != nil || length < 0 || length > 8192 {
		t.Fatalf("unexpected bulk header %q", header)
	}
	payload := make([]byte, length+2)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload[length:]) != "\r\n" {
		t.Fatal("invalid bulk terminator")
	}
	return payload[:length]
}

func TestRedisWildcardFramesKeyLength(t *testing.T) {
	const key = "redis-wildcard-frame"
	t.Cleanup(func() {
		redisDatabase.Lock()
		delete(redisDatabase.values, key)
		redisDatabase.Unlock()
	})
	bulkKey := fmt.Sprintf("*1\r\n$%d\r\n%s\r\n", len(key), key)
	requireReferenceTCP(t, "redis", nil, []referenceExchange{
		{"SET " + key + " a\r\n", "+OK\r\n"},
		{"KEYS *\r\n", bulkKey},
		{"KEYS " + key + "\r\n", bulkKey},
		{"SET " + key + " replacement\r\n", "+OK\r\n"},
		{"KEYS *\r\n", bulkKey},
		{"DEL " + key + "\r\n", "+(integer) 1\r\n"},
	})
}

func TestReferenceRedisLargeRequests(t *testing.T) {
	const key = "redis-large-request"
	t.Cleanup(func() {
		redisDatabase.Lock()
		delete(redisDatabase.values, key)
		redisDatabase.Unlock()
	})
	value := strings.Repeat("z", 64*1024)
	const inlinePrefix = "SET " + key + " "
	inlineValue := strings.Repeat("i", 128*1024-len(inlinePrefix)-len("\r\n"))
	var exists strings.Builder
	fmt.Fprintf(&exists, "*1024\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(key), key)
	for i := 0; i < 1022; i++ {
		exists.WriteString("$7\r\nmissing\r\n")
	}
	exchanges := []struct{ command, send, receive string }{
		{"SET", fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(value), value), "+OK\r\n"},
		{"EXISTS", exists.String(), "+(integer) 1\r\n"},
		{"GET", "GET " + key + "\r\n", "+" + value + "\r\n"},
		{"inline SET", inlinePrefix + inlineValue + "\r\n", "+OK\r\n"},
		{"GET after inline SET", "GET " + key + "\r\n", "+" + inlineValue + "\r\n"},
		{"DEL", "DEL " + key + "\r\n", "+(integer) 1\r\n"},
		{"PING", "PING\r\n", "+PONG\r\n"},
	}
	conn, stop := startRound6Server(t, round6Case{Handler: "redis"})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, exchange := range exchanges {
		if _, err := io.WriteString(conn, exchange.send); err != nil {
			t.Fatalf("%s write: %v", exchange.command, err)
		}
		reply := make([]byte, len(exchange.receive))
		if n, err := io.ReadFull(conn, reply); err != nil || string(reply) != exchange.receive {
			t.Fatalf("%s response did not match the fixture (%d of %d bytes read, %v)", exchange.command, n, len(reply), err)
		}
	}
}

func TestRedisRequestSizeLimit(t *testing.T) {
	value := strings.Repeat("z", 64*1024)
	request := fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(value), value, len(value), value)
	reader := redisCommandReader{source: strings.NewReader(request)}
	_, err := reader.readCommand()
	if err == nil || err.Error() != "RESP request exceeds size limit" {
		t.Fatalf("request over the total size limit returned %v", err)
	}
}

func TestRedisInlineRequestSizeLimit(t *testing.T) {
	request := "SET key " + strings.Repeat("v", 128*1024-len("SET key ")) + "\n"
	reader := redisCommandReader{source: strings.NewReader(request)}
	_, err := reader.readCommand()
	if err == nil || err.Error() != "Redis inline request exceeds size limit" {
		t.Fatalf("inline request over the total size limit returned %v", err)
	}
}
