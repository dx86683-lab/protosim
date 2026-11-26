package protocols

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	redisVersion         = "3.2.3"
	redisMaxArguments    = 1024
	redisMaxBulkBytes    = 64 * 1024
	redisMaxHeaderBytes  = 4 * 1024
	redisMaxRequestBytes = 128 * 1024
)

//go:embed fixtures/redis-info.txt
var redisInfoDefault string

// The reference's simulated key space is shared by all Redis listeners in
// the process. Authentication remains local to the connection.
var redisDatabase = struct {
	sync.Mutex
	values map[string]string
}{values: make(map[string]string)}

func init() {
	AddProtocol(NewProtocolInfo("redis", serveRedis, 6379),
		ProtocolParams{Name: "server_version", DefaultValue: redisVersion},
		ProtocolParams{Name: "accounts", DefaultValue: []string{}})
}

func serveRedis(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := redisCommandReader{source: session.Conn}
	accounts := session.GetStringsParams("accounts", nil)
	authenticated := len(accounts) == 0
	for {
		args, err := reader.readCommand()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(args) == 0 {
			return nil
		}
		commandName := args[0]
		command := strings.ToUpper(commandName)
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		if command == "QUIT" {
			return session.SendString("+OK\r\n")
		}
		reply := redisReply(session, accounts, &authenticated, command, commandName, args[1:])
		if err := session.SendString(reply); err != nil {
			return err
		}
	}
}

func redisReply(session *SessionConnection, accounts []string, authenticated *bool, command, commandName string, args []string) string {
	if command == "AUTH" {
		if len(args) == 0 || len(args) > 2 {
			return "-ERR syntax error\r\n"
		}
		if len(args) == 2 && matchesConfiguredAccount(accounts, args[0], args[1]) {
			*authenticated = true
			return "+OK\r\n"
		}
		return "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	}

	var wrongCount bool
	switch command {
	case "GET", "KEYS":
		wrongCount = len(args) != 1
	case "SET":
		wrongCount = len(args) < 2
	case "DEL", "EXISTS":
		wrongCount = len(args) == 0
	case "", "PING", "INFO", "SELECT", "DBSIZE", "LASTSAVE", "SAVE", "BGSAVE", "FLUSHDB", "FLUSHALL":
	default:
		name := strings.Map(func(r rune) rune {
			if r < ' ' || r == 127 {
				return -1
			}
			return r
		}, strings.ToLower(command))
		return "-ERR unknown command '" + name + "'\r\n"
	}
	if wrongCount {
		return "-ERR wrong number of arguments for '" + commandName + "' command\r\n"
	}
	if !*authenticated {
		return "-NOAUTH Authentication required.\r\n"
	}
	switch command {
	case "":
		return "\r\n"
	case "PING":
		return "+PONG\r\n"
	case "INFO":
		version := session.GetStringParams("server_version", redisVersion)
		return redisBulkString(strings.Replace(redisInfoDefault, "redis_version:"+redisVersion+"\n", "redis_version:"+version+"\n", 1))
	case "SELECT", "LASTSAVE", "SAVE", "BGSAVE":
		return "+OK\r\n"
	}

	redisDatabase.Lock()
	defer redisDatabase.Unlock()
	values := redisDatabase.values
	switch command {
	case "SET":
		const maxKeys = 1024
		if _, exists := values[args[0]]; !exists && len(values) >= maxKeys {
			return "-ERR simulated key capacity reached\r\n"
		}
		values[args[0]] = args[1]
	case "GET":
		value, exists := values[args[0]]
		if !exists {
			return "+(nil)\r\n"
		}
		// ProtoSim preserves the stored bytes inside its GET simple-string reply.
		return "+" + value + "\r\n"
	case "DEL":
		delete(values, args[0])
		return "+(integer) 1\r\n"
	case "FLUSHDB", "FLUSHALL":
		clear(values)
	case "KEYS":
		if args[0] != "*" {
			if _, found := values[args[0]]; found {
				return "*1\r\n" + redisBulkString(args[0])
			}
			return "+(empty array)\r\n"
		}
		var reply strings.Builder
		fmt.Fprintf(&reply, "*%d\r\n", len(values))
		for key := range values {
			reply.WriteString(redisBulkString(key))
		}
		return reply.String()
	case "EXISTS":
		if _, exists := values[args[0]]; exists {
			return "+(integer) 1\r\n"
		}
		return "+(integer) 0\r\n"
	case "DBSIZE":
		return "+(integer) " + strconv.Itoa(len(values)) + "\r\n"
	}
	return "+OK\r\n"
}

func redisBulkString(value string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

type redisCommandReader struct {
	source io.Reader
	next   [1]byte
	header [64]byte
}

func (reader *redisCommandReader) readCommand() ([]string, error) {
	line, err := reader.readLine(true)
	if err != nil {
		return nil, err
	}
	if line[0] != '*' {
		return strings.Fields(string(line)), nil
	}
	size, err := strconv.Atoi(strings.TrimSuffix(string(line[1:]), "\r\n"))
	if err != nil || size < 1 || size > redisMaxArguments {
		return nil, errors.New("invalid RESP argument count")
	}
	remaining := redisMaxRequestBytes - len(line)
	args := make([]string, 0, size)
	for range size {
		header, err := reader.readLine(false)
		if err != nil {
			return nil, err
		}
		length, err := strconv.Atoi(strings.TrimSuffix(string(header[1:]), "\r\n"))
		if header[0] != '$' || err != nil || length < 0 || length > redisMaxBulkBytes {
			return nil, errors.New("invalid RESP bulk length")
		}
		remaining -= len(header) + length + 2
		if remaining < 0 {
			return nil, errors.New("RESP request exceeds size limit")
		}
		data := make([]byte, length+2)
		if _, err := io.ReadFull(reader.source, data); err != nil {
			return nil, err
		}
		if data[length] != '\r' || data[length+1] != '\n' {
			return nil, errors.New("invalid RESP bulk terminator")
		}
		args = append(args, string(data[:length]))
	}
	return args, nil
}

// Read only through the current line. QUIT leaves any later commands in the
// transport receive queue so TCP can signal that those commands were lost.
func (reader *redisCommandReader) readLine(commandStart bool) ([]byte, error) {
	line := reader.header[:0]
	limit := redisMaxHeaderBytes
	for len(line) < limit {
		if _, err := io.ReadFull(reader.source, reader.next[:]); err != nil {
			return nil, err
		}
		b := reader.next[0]
		line = append(line, b)
		if b == '\n' {
			return line, nil
		}
		if commandStart && len(line) == 1 && b != '*' {
			limit = redisMaxRequestBytes
		}
	}
	if limit == redisMaxRequestBytes {
		return nil, errors.New("Redis inline request exceeds size limit")
	}
	return nil, errors.New("Redis frame header exceeds size limit")
}
