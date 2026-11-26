package protocols

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const memcacheVersion = "1.5.16"

const (
	memcacheMaxValue  = 1 << 20
	memcacheMaxBytes  = 8 << 20
	memcacheMaxItems  = 1024
	memcacheMaxLine   = 64 << 10
	memcacheIOTimeout = 30 * time.Second
)

var memcacheStats = []string{
	"libevent 2.1.8-stable", "pointer_size 64", "rusage_user 0.029000",
	"rusage_system 0.029000", "max_connections 1024", "curr_connections",
	"rejected_connections 0", "connection_structures 3", "reserved_fds 20",
	"cmd_get 0", "cmd_set 0", "cmd_flush 0", "cmd_touch 0", "get_hits 0",
	"get_misses 0", "get_expired 0", "get_flushed 0", "delete_misses 0",
	"delete_hits 0", "incr_misses 0", "incr_hits 0", "decr_misses 0",
	"decr_hits 0", "cas_misses 0", "cas_hits 0", "cas_badval 0", "touch_hits 0",
	"touch_misses 0", "auth_cmds 0", "auth_errors 0", "bytes_read",
	"bytes_written", "limit_maxbytes 67108864", "accepting_conns 1",
	"listen_disabled_num 0", "time_in_listen_disabled_us 0", "threads 4",
	"conn_yields 0", "hash_power_level 16", "hash_bytes 524288",
	"hash_is_expanding 0", "slab_reassign_rescues 0", "slab_reassign_chunk_rescues 0",
	"slab_reassign_evictions_nomem 0", "slab_reassign_inline_reclaim 0",
	"slab_reassign_busy_items 0", "slab_reassign_busy_deletes 0",
	"slab_reassign_running 0", "slabs_moved 0", "lru_crawler_running 0",
	"lru_crawler_starts 510", "lru_maintainer_juggles 224", "malloc_fails 0",
	"log_worker_dropped 0", "log_worker_written 0", "log_watcher_skipped 0",
	"log_watcher_sent 0", "bytes 0", "curr_items", "total_items 0",
	"slab_global_page_pool 0", "expired_unfetched 0", "evicted_unfetched 0",
	"evicted_active 0", "evictions 0", "reclaimed 0", "crawler_reclaimed 0",
	"crawler_items_checked 0", "lrutail_reflocked 0", "moves_to_cold 0",
	"moves_to_warm 0", "moves_within_lru 0", "direct_reclaims 0", "lru_bumps_dropped 0",
}

var memcacheStarted = time.Now()

func init() {
	AddProtocol(NewProtocolInfo("memcache", serveMemcache, 11211),
		ProtocolParams{Name: "server_version", DefaultValue: memcacheVersion})
}

func serveMemcache(session *SessionConnection) error {
	defer session.DeleteActivity()
	version := session.GetStringParams("server_version", memcacheVersion)
	if strings.ContainsAny(version, "\r\n") {
		return errors.New("invalid Memcached version")
	}
	reader := bufio.NewReader(session.Conn)
	// The reference drops stored items when the connection closes.
	values := make(map[string]string)
	storedBytes := 0
	statsRead, statsWritten := uint64(100), uint64(150)
	for {
		// Idle sessions stay open. Bound reads once the next command starts.
		if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		if _, err := reader.Peek(1); err != nil {
			return err
		}
		if err := session.Conn.SetReadDeadline(time.Now().Add(memcacheIOTimeout)); err != nil {
			return err
		}
		line, err := readMemcacheCommand(reader)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			continue
		}
		reply := "ERROR\r\n"
		command := strings.ToLower(fields[0])
		var valueBody []byte
		recordCommand := true
		switch command {
		case "version":
			if len(fields) == 1 {
				reply = "VERSION " + version + "\r\n"
			}
		case "stats":
			// The reference advances simulated byte counters for each stats
			// command, including subcommands, within the current connection.
			statsRead += 10 + rand.Uint64N(40)
			statsWritten += 100 + rand.Uint64N(400)
			if len(fields) > 1 {
				switch fields[1] {
				case "items":
					reply = "END\r\n"
				case "slabs":
					reply = "STAT active_slabs 0\r\nSTAT total_malloced 0\r\nEND\r\n"
				case "sizes":
					reply = "STAT sizes_status disabled\r\nEND\r\n"
				case "detail":
					reply = "OK\r\n"
				case "reset":
					reply = "RESET\r\n"
				}
			}
			if len(fields) == 1 {
				var response strings.Builder
				fmt.Fprintf(&response, "STAT pid 1\r\nSTAT uptime %d\r\nSTAT time %d\r\nSTAT version %s\r\n",
					int64(time.Since(memcacheStarted)/time.Second), time.Now().Unix(), version)
				for _, entry := range memcacheStats {
					switch entry {
					case "curr_connections":
						fmt.Fprintf(&response, "STAT %s %d\r\n", entry, 1+rand.IntN(4))
					case "curr_items":
						fmt.Fprintf(&response, "STAT %s %d\r\n", entry, len(values))
					case "bytes_read":
						fmt.Fprintf(&response, "STAT %s %d\r\n", entry, statsRead)
					case "bytes_written":
						fmt.Fprintf(&response, "STAT %s %d\r\n", entry, statsWritten)
					default:
						response.WriteString("STAT " + entry + "\r\n")
					}
				}
				response.WriteString("END\r\n")
				reply = response.String()
			}
		case "set", "add":
			reply = "SERVER_ERROR bad command line format\r\n"
			if len(fields) != 5 {
				recordCommand = false
				break
			}
			size, err := strconv.ParseUint(strings.TrimPrefix(fields[4], "+"), 10, 32)
			if err != nil {
				recordCommand = false
				break
			}
			if size == 0 {
				reply = "ERROR\r\n"
				valueBody = []byte{}
				break
			}
			if size > memcacheMaxValue {
				return errors.New("Memcached value exceeds limit")
			}
			valueBody = make([]byte, int(size))
			if _, err := io.ReadFull(session.Conn, valueBody); err != nil {
				return err
			}
			key := fields[1]
			old, exists := values[key]
			reply = "NOT_STORED\r\n"
			if command == "add" && exists || !exists && len(values) >= memcacheMaxItems ||
				storedBytes-len(old)+int(size) > memcacheMaxBytes {
				break
			}
			values[key] = string(valueBody)
			storedBytes += int(size) - len(old)
			reply = "STORED\r\n"
		case "get":
			if len(fields) > 1 {
				reply = "END\r\n"
				if value, ok := values[fields[1]]; ok {
					reply = fmt.Sprintf("VALUE %s 0 %d\r\n%s\r\nEND\r\n", fields[1], len(value), value)
				}
			}
		case "delete":
			if len(fields) >= 2 {
				reply = "NOT_FOUND\r\n"
				if value, ok := values[fields[1]]; ok {
					storedBytes -= len(value)
					delete(values, fields[1])
					reply = "DELETED\r\n"
				}
			}
		}
		if recordCommand {
			logSessionEvent(session.ConfigInfo, session.Conn.RemoteAddr(), "execute command", logrus.Fields{
				"cmd": command, "args": fields[1:], "body": valueBody,
			})
		}
		if command == "quit" {
			return nil
		}
		if err := session.Conn.SetWriteDeadline(time.Now().Add(memcacheIOTimeout)); err != nil {
			return err
		}
		if _, err := session.Conn.Write([]byte(reply)); err != nil {
			return err
		}
	}
}

func readMemcacheCommand(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > memcacheMaxLine {
			return nil, errors.New("Memcached command exceeds limit")
		}
		if err == bufio.ErrBufferFull {
			line = append(line, fragment...)
			continue
		}
		if err != nil {
			return nil, err
		}
		// The reference consumes the rest of this read batch after the command.
		// A storage command reads its value separately from the connection.
		_, err = reader.Discard(reader.Buffered())
		if len(line) == 0 {
			return fragment, err
		}
		return append(line, fragment...), err
	}
}
