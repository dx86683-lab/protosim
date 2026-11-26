package protocols

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
)

// BitTorrent DHT (BEP 5). The reference answers ping and find_node with a
// node ID chosen at start-up; find_node returns eight random IPv4 and IPv6
// contacts. Other queries and malformed datagrams are ignored.

var (
	dhtNodeOnce sync.Once
	dhtNodeID   [20]byte
)

func init() {
	AddProtocol(NewProtocolInfo("dht", serveDHT, 6881))
}

// bdecode parses one bencoded value. Dictionaries become map[string]any,
// strings are returned as string.
func bdecode(data []byte, depth int) (any, []byte, error) {
	if len(data) == 0 || depth > 16 {
		return nil, nil, errors.New("bencode: truncated")
	}
	switch c := data[0]; {
	case c == 'i':
		end := bytes.IndexByte(data, 'e')
		if end < 0 {
			return nil, nil, errors.New("bencode: bad integer")
		}
		n, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		return n, data[end+1:], err
	case c == 'l' || c == 'd':
		rest := data[1:]
		var list []any
		dict := map[string]any{}
		for len(rest) > 0 && rest[0] != 'e' {
			var key any
			var err error
			if c == 'd' {
				if key, rest, err = bdecode(rest, depth+1); err != nil {
					return nil, nil, err
				}
				if _, ok := key.(string); !ok {
					return nil, nil, errors.New("bencode: bad key")
				}
			}
			var v any
			if v, rest, err = bdecode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			if c == 'd' {
				dict[key.(string)] = v
			} else {
				list = append(list, v)
			}
		}
		if len(rest) == 0 {
			return nil, nil, errors.New("bencode: unterminated")
		}
		if c == 'd' {
			return dict, rest[1:], nil
		}
		return list, rest[1:], nil
	case c >= '0' && c <= '9':
		colon := bytes.IndexByte(data, ':')
		if colon < 0 {
			return nil, nil, errors.New("bencode: bad string")
		}
		n, err := strconv.Atoi(string(data[:colon]))
		if err != nil || n < 0 || n > len(data)-colon-1 {
			return nil, nil, errors.New("bencode: bad string length")
		}
		return string(data[colon+1 : colon+1+n]), data[colon+1+n:], nil
	}
	return nil, nil, errors.New("bencode: unknown type")
}

func bencode(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case string:
		buf.WriteString(strconv.Itoa(len(t)) + ":" + t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('d')
		for _, k := range keys {
			bencode(buf, k)
			bencode(buf, t[k])
		}
		buf.WriteByte('e')
	}
}

func compactAddr(addr net.Addr) string {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return ""
	}
	ip := udp.IP.To4()
	if ip == nil {
		ip = udp.IP.To16()
	}
	return string(ip) + string([]byte{byte(udp.Port >> 8), byte(udp.Port)})
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return string(b)
}

func serveDHT(conn *UDPConnection, request []byte) error {
	dhtNodeOnce.Do(func() { rand.Read(dhtNodeID[:]) })
	v, _, err := bdecode(request, 0)
	if err != nil {
		return nil
	}
	msg, ok := v.(map[string]any)
	if !ok || msg["y"] != "q" {
		return nil
	}
	tid, _ := msg["t"].(string)
	r := map[string]any{"id": string(dhtNodeID[:])}
	switch msg["q"] {
	case "ping":
	case "find_node":
		r["nodes"] = randomString(8 * 26)
		r["nodes6"] = randomString(8 * 38)
	default:
		return nil
	}
	var out bytes.Buffer
	bencode(&out, map[string]any{"ip": compactAddr(conn.RemoteAddr()), "r": r, "t": tid, "y": "r"})
	_, err = conn.Write(out.Bytes())
	return err
}
