package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRPCBindAddressLookup(t *testing.T) {
	const xid = 93
	params := map[string]any{"mapping_table": []string{"100003,3,tcp,2049", "100003,3,udp,12049"}}
	conn, stop := startRound6Server(t, round6Case{Handler: "portmap", Params: params})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	stringsXDR := func(values ...string) []byte {
		var out []byte
		for _, value := range values {
			out = nfsOpaque(out, []byte(value))
		}
		return out
	}
	args := func(program, version uint32, netID string) []byte {
		return append(nfsWords(program, version), stringsXDR(netID, "203.0.113.50.0.111", "")...)
	}
	query := func(rpcbindVersion, procedure, status uint32, request, expected []byte) {
		t.Helper()
		call := append(nfsWords(xid, 0, 2, 100000, rpcbindVersion, procedure, 0, 0, 0, 0), request...)
		if _, err := conn.Write(append(nfsWords(0x80000000|uint32(len(call))), call...)); err != nil {
			t.Fatal(err)
		}
		wire, err := readRPCRecord(reader, 4096)
		want := rpcAcceptedReply(xid, status, expected)[4:]
		if err != nil || string(wire) != string(want) {
			t.Fatalf("RPCBIND v%d procedure %d received %x (%v), want %x", rpcbindVersion, procedure, wire, err, want)
		}
	}
	const tcpAddress = "127.0.0.1.8.1"
	const udpAddress = "127.0.0.1.47.17"
	query(3, 3, 0, args(100003, 3, "udp"), stringsXDR(tcpAddress))
	query(4, 3, 0, args(100003, 99, "udp"), stringsXDR(tcpAddress))
	query(4, 9, 0, args(100003, 3, "udp"), stringsXDR(tcpAddress))
	query(4, 9, 0, args(100003, 99, "tcp"), stringsXDR(""))
	query(4, 3, 0, args(100005, 3, "tcp"), stringsXDR(""))
	query(3, 9, 3, args(100003, 3, ""), nil)
	query(4, 1, 0, args(100003, 3, "tcp"), nfsWords(0))
	query(4, 3, 4, nfsWords(100003, 3, 12), nil)

	var dump, addresses []byte
	for _, mapping := range []struct {
		address, protocol string
		semantics         uint32
	}{{udpAddress, "udp", 1}, {tcpAddress, "tcp", 3}} {
		dump = append(dump, nfsWords(1, 100003, 3)...)
		dump = append(dump, stringsXDR(mapping.protocol, mapping.address, "superuser")...)
		addresses = binary.BigEndian.AppendUint32(addresses, 1)
		addresses = append(addresses, stringsXDR(mapping.address, mapping.protocol)...)
		addresses = binary.BigEndian.AppendUint32(addresses, mapping.semantics)
		addresses = append(addresses, stringsXDR("inet", mapping.protocol)...)
	}
	query(3, 4, 0, nil, binary.BigEndian.AppendUint32(dump, 0))
	query(4, 11, 0, args(100003, 3, "tcp"), binary.BigEndian.AppendUint32(addresses, 0))
}

func TestPortmapV2ReadOnlyRPC(t *testing.T) {
	const xid = 71
	const portmap = 100000
	pack := func(rpcVersion, program, version, procedure uint32, auth, args []byte) string {
		call := append(nfsWords(xid, 0, rpcVersion, program, version, procedure), auth...)
		call = append(call, args...)
		return string(append(nfsWords(0x80000000|uint32(len(call))), call...))
	}
	none := nfsWords(0, 0, 0, 0)
	sys := nfsOpaque(nfsWords(10), []byte("fixture"))
	sys = append(sys, nfsWords(1000, 1000, 1, 1000)...)
	sys = append(nfsOpaque(nfsWords(1), sys), nfsWords(0, 0)...)
	tcp := nfsWords(100003, 3, 6, 12345)
	udp := nfsWords(100003, 3, 17, 0)
	for _, tc := range []struct {
		name string
		in   string
		out  []byte
	}{
		{"GETPORT TCP", pack(2, portmap, 2, 3, none, tcp), rpcAcceptedReply(xid, 0, nfsWords(2049))},
		{"GETPORT UDP with AUTH_SYS", pack(2, portmap, 2, 3, sys, udp), rpcAcceptedReply(xid, 0, nfsWords(12049))},
		{"GETPORT missing version", pack(2, portmap, 2, 3, none, nfsWords(100003, 4, 6, 0)), rpcAcceptedReply(xid, 0, nfsWords(0))},
		{"SET refused", pack(2, portmap, 2, 1, none, tcp), rpcAcceptedReply(xid, 0, nfsWords(0))},
		{"UNSET refused", pack(2, portmap, 2, 2, none, tcp), rpcAcceptedReply(xid, 0, nfsWords(0))},
		{"GETPORT missing argument", pack(2, portmap, 2, 3, none, tcp[:12]), rpcAcceptedReply(xid, 4, nil)},
		{"NULL extra argument", pack(2, portmap, 2, 0, none, nfsWords(0)), rpcAcceptedReply(xid, 4, nil)},
		{"wrong program", pack(2, 100003, 2, 0, none, nil), rpcAcceptedReply(xid, 1, nil)},
		{"wrong program version", pack(2, portmap, 5, 0, none, nil), rpcAcceptedReply(xid, 2, nfsWords(2, 4))},
		{"wrong RPC version", pack(3, portmap, 2, 0, none, nil), nfsWords(0x80000018, xid, 1, 1, 0, 2, 2)},
		{"unsupported procedure", pack(2, portmap, 2, 6, none, nil), rpcAcceptedReply(xid, 3, nil)},
		{"bad credential", pack(2, portmap, 2, 0, nfsWords(0, 4, 1, 0, 0), nil), nfsWords(0x80000014, xid, 1, 1, 1, 1)},
		{"bad verifier", pack(2, portmap, 2, 0, nfsWords(0, 0, 1, 0), nil), nfsWords(0x80000014, xid, 1, 1, 1, 3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireReferenceTCP(t, "portmap", map[string]any{"mapping_table": []string{"100003,3,tcp,2049", "100003,3,udp,12049"}}, []referenceExchange{
				{tc.in, string(tc.out)},
				{pack(2, portmap, 2, 0, none, nil), string(rpcAcceptedReply(xid, 0, nil))},
			})
		})
	}
	null := pack(2, portmap, 2, 0, none, nil)
	callit := pack(2, portmap, 2, 5, none, nfsWords(100003, 3, 0, 0))
	requireReferenceTCP(t, "portmap", nil, []referenceExchange{
		{callit + null + null, string(rpcAcceptedReply(xid, 0, nil)) + string(rpcAcceptedReply(xid, 0, nil))},
	})
}

func TestPortmapConfiguredMappingFields(t *testing.T) {
	params := map[string]any{"mapping_table": []any{
		"+100099,-2,tcp,-3",
		"100003,4294967296,udp,65536",
		"100005,1,UDP,111",
	}}
	var body []byte
	for _, field := range []uint32{
		1, 100005, 1, 6, 111,
		1, 100003, 0, 17, 65536,
		1, 100099, 4294967294, 6, 4294967293,
		0,
	} {
		body = binary.BigEndian.AppendUint32(body, field)
	}
	const xid = 44
	var request []byte
	for _, field := range []uint32{0x80000028, xid, 0, 2, 100000, 2, 4, 0, 0, 0, 0} {
		request = binary.BigEndian.AppendUint32(request, field)
	}
	requireReferenceTCP(t, "portmap", params, []referenceExchange{
		{string(request), string(rpcAcceptedReply(xid, 0, body))},
	})
}

func TestPortmapRejectsInvalidMappingsBeforeRequests(t *testing.T) {
	for _, tc := range []struct{ name, row, diagnostic string }{
		{"program", " 100009,1,tcp,111", "[PORTMAP] invalid program."},
		{"version", "100009,,tcp,111", "[PORTMAP] invalid version."},
		{"port", "100009,1,tcp,111,note", "[PORTMAP] invalid port number."},
		{"missing version", "100009", "[PORTMAP] incomplete mapping row."},
		{"missing protocol", "100009,1", "[PORTMAP] incomplete mapping row."},
		{"missing port", "100009,1,tcp", "[PORTMAP] incomplete mapping row."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePortmapMappings(map[string]any{
				"mapping_table": []any{"100009,1,udp,111", tc.row},
			})
			if err == nil || err.Error() != tc.diagnostic {
				t.Fatalf("diagnostic %v, want %q", err, tc.diagnostic)
			}
		})
	}
}

func TestPortmapInvalidMappingKeepsConnectionSilent(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "portmap", Params: map[string]any{
		"mapping_table": []string{"100009,1,tcp,invalid"},
	}})
	defer stop()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, procedure := range []uint32{0, 4, 0} {
		var request []byte
		for _, field := range []uint32{0x80000028, 44, 0, 2, 100000, 2, procedure, 0, 0, 0, 0} {
			request = binary.BigEndian.AppendUint32(request, field)
		}
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		n, err := conn.Read(b[:])
		var timeout net.Error
		if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("procedure %d returned %x (%v), want an open connection without a reply", procedure, b[:n], err)
		}
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after peer EOF: received %x (%v), want close", b[:n], err)
	}
}
