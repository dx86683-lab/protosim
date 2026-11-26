package protocols

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestMountPathData(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       []byte
		wantStatus uint32
	}{
		{"missing", nil, 4},
		{"short length field", []byte{0, 0, 0}, 4},
		{"empty", nfsWords(0), 4},
		{"missing path data", nfsWords(1), 4},
		{"unpadded path", append(nfsWords(1), '/'), 4},
		{"short path", append(nfsWords(2), '/'), 4},
		{"zero length with data", append(nfsWords(0), '/'), 4},
		{"padded root", nfsOpaque(nil, []byte("/")), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, stop := startRound6Server(t, round6Case{Handler: "nfs"})
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, procedure := range []uint32{1, 3} {
				body := append(nfsWords(17, 0, 2, rpcProgMount, 3, procedure, 0, 0, 0, 0), tc.path...)
				request := append(nfsWords(0x80000000|uint32(len(body))), body...)
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				reply, err := readRPCRecord(conn, 4096)
				wantLength := 24
				if procedure == 1 && tc.wantStatus == 0 {
					wantLength = 60
				}
				if err != nil || len(reply) != wantLength || binary.BigEndian.Uint32(reply[20:]) != tc.wantStatus {
					t.Fatalf("procedure %d: got %x (%v), want RPC status %d and %d bytes", procedure, reply, err, tc.wantStatus, wantLength)
				}
			}
		})
	}
}

func TestNFSRenameAcrossDirectories(t *testing.T) {
	export := t.TempDir()
	for _, directory := range []string{"from/tree", "to/occupied"} {
		if err := os.MkdirAll(filepath.Join(export, directory), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"from/tree/leaf": "leaf", "to/occupied/leaf": "occupied",
		"from/source": "source", "to/target": "old target",
	} {
		if err := os.WriteFile(filepath.Join(export, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	server := &nfsServer{}
	call := func(program, procedure uint32, args []byte) []byte {
		t.Helper()
		status, body := server.respond(program, procedure, export, args, nfsMaxTransfer, nil)
		if status != 0 || len(body) < 4 {
			t.Fatalf("RPC status %d, reply %x", status, body)
		}
		return body
	}
	mount := call(rpcProgMount, 1, nfsOpaque(nil, []byte("/")))
	if len(mount) < 24 || binary.BigEndian.Uint32(mount) != 0 {
		t.Fatalf("MNT reply %x", mount)
	}
	lookup := func(dir []byte, name string) []byte {
		t.Helper()
		reply := call(rpcProgNFS, 3, nfsOpaque(bytes.Clone(dir), []byte(name)))
		if len(reply) < 24 || binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("LOOKUP %q reply %x", name, reply)
		}
		return reply[4:24]
	}
	from, to := lookup(mount[4:24], "from"), lookup(mount[4:24], "to")
	leaf := lookup(lookup(from, "tree"), "leaf")
	source, target := lookup(from, "source"), lookup(to, "target")
	rename := func(oldname, newname string, want uint32) {
		t.Helper()
		args := nfsOpaque(bytes.Clone(from), []byte(oldname))
		args = nfsOpaque(append(args, to...), []byte(newname))
		reply := call(rpcProgNFS, 14, args)
		if len(reply) != 236 || !bytes.Equal(reply[:8], nfsWords(want, 1)) ||
			!bytes.Equal(reply[120:124], nfsWords(1)) {
			t.Fatalf("RENAME %q to %q = %x, status %d wanted with both WCC records", oldname, newname, reply, want)
		}
	}
	rename("tree", "occupied", nfs3ErrExist)
	rename("source", "occupied", nfs3ErrExist)
	rename("missing", "target", nfs3ErrNoEnt)
	rename("source", "target", 0)
	rename("tree", "relocated", 0)
	if moved := lookup(to, "target"); !bytes.Equal(moved, source) {
		t.Fatalf("replacement changed source handle from %x to %x", source, moved)
	}
	if moved := lookup(lookup(to, "relocated"), "leaf"); !bytes.Equal(moved, leaf) {
		t.Fatalf("directory move changed child handle from %x to %x", leaf, moved)
	}
	if reply := call(rpcProgNFS, 1, target); binary.BigEndian.Uint32(reply) != nfs3ErrStale {
		t.Fatalf("overwritten target handle response %x", reply)
	}
}

func TestMountVerifiesBackingDirectory(t *testing.T) {
	parent := t.TempDir()
	export := filepath.Join(parent, "export")
	server := &nfsServer{}
	peer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	path := nfsOpaque(nil, []byte("/"))
	call := func(program, procedure uint32, args []byte) []byte {
		t.Helper()
		status, body := server.respond(program, procedure, export, args, nfsMaxTransfer, peer)
		if status != 0 || len(body) < 4 {
			t.Fatalf("RPC status %d, body %x", status, body)
		}
		return body
	}
	checkRejected := func(want uint32) {
		t.Helper()
		if body := call(rpcProgMount, 1, path); !bytes.Equal(body, nfsWords(want)) {
			t.Fatalf("MNT failure %x, want %d", body, want)
		}
		if body := call(rpcProgMount, 5, nil); !bytes.Equal(body, nfsWords(0)) {
			t.Fatalf("EXPORT listed unavailable directory %x", body)
		}
		if len(server.mounted) != 0 || len(server.handles) != 0 {
			t.Fatal("failed mount created state")
		}
	}
	checkRejected(nfs3ErrNoEnt)
	if err := os.WriteFile(export, nil, 0600); err != nil {
		t.Fatal(err)
	}
	checkRejected(nfs3ErrNotDir)
	if err := os.Remove(export); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(export, 0755); err != nil {
		t.Fatal(err)
	}
	first := call(rpcProgMount, 1, path)
	if len(first) < 24 || binary.BigEndian.Uint32(first) != 0 {
		t.Fatalf("valid mount %x", first)
	}
	if body := call(rpcProgMount, 5, nil); !bytes.Equal(body, nfsWords(1, 1, 0x2f000000, 0, 0)) {
		t.Fatalf("EXPORT omitted backing directory %x", body)
	}
	if err := os.Rename(export, filepath.Join(parent, "old")); err != nil {
		t.Fatal(err)
	}
	if body := call(rpcProgNFS, 1, first[4:24]); !bytes.Equal(body, nfsWords(nfs3ErrStale)) {
		t.Fatalf("old handle with absent export %x", body)
	}
	if err := os.Mkdir(export, 0755); err != nil {
		t.Fatal(err)
	}
	second := call(rpcProgMount, 1, path)
	if len(second) < 24 || binary.BigEndian.Uint32(second) != 0 || bytes.Equal(second[4:24], first[4:24]) {
		t.Fatalf("replacement export mount %x", second)
	}
}

func TestMountClientRecords(t *testing.T) {
	server := &nfsServer{}
	export := t.TempDir()
	first := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	firstUDP := &net.UDPAddr{IP: first.IP, Port: 10002}
	second := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 10001}
	call := func(peer net.Addr, program, procedure uint32, args []byte) (uint32, []byte) {
		t.Helper()
		wire := append(nfsWords(42, 0, 2, program, 3, procedure, 0, 0, 0, 0), args...)
		reply := server.rpcReply(nil, peer, export, wire, nfsMaxTransfer)
		if len(reply) < 28 || !bytes.Equal(reply[4:24], nfsWords(42, 1, 0, 0, 0)) {
			t.Fatalf("RPC reply %x", reply)
		}
		return binary.BigEndian.Uint32(reply[24:]), reply[28:]
	}
	checkDump := func(peers ...string) {
		t.Helper()
		var expected []byte
		for _, host := range peers {
			expected = nfsOpaque(append(expected, nfsWords(1)...), []byte(host))
			expected = nfsOpaque(expected, []byte("/"))
		}
		expected = append(expected, nfsWords(0)...)
		if status, reply := call(second, rpcProgMount, 2, nil); status != 0 || !bytes.Equal(reply, expected) {
			t.Fatalf("DUMP = %d,%x, want %x", status, reply, expected)
		}
	}
	checkDump()
	root := nfsOpaque(nil, []byte("/"))
	var handle []byte
	for _, peer := range []net.Addr{first, firstUDP, second} {
		status, reply := call(peer, rpcProgMount, 1, root)
		if status != 0 || len(reply) < 24 || binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("MOUNT = %d,%x", status, reply)
		}
		handle = reply[4:24]
	}
	if status, reply := call(second, rpcProgMount, 1, nfsOpaque(nil, []byte("/invalid"))); status != 0 ||
		!bytes.Equal(reply, nfsWords(nfs3ErrNoEnt)) {
		t.Fatalf("rejected MOUNT = %d,%x", status, reply)
	}
	checkDump("127.0.0.1", "127.0.0.2")
	for _, procedure := range []uint32{2, 4} {
		if status, _ := call(first, rpcProgMount, procedure, nfsWords(0)); status != 4 {
			t.Fatalf("procedure %d accepted trailing data, RPC status %d", procedure, status)
		}
	}
	if status, body := call(firstUDP, rpcProgMount, 3, root); status != 0 || len(body) != 0 {
		t.Fatalf("UMNT = %d,%x", status, body)
	}
	checkDump("127.0.0.2")
	if status, body := call(first, rpcProgMount, 4, nil); status != 0 || len(body) != 0 {
		t.Fatalf("UMNTALL = %d,%x", status, body)
	}
	checkDump("127.0.0.2")
	if status, _ := call(second, rpcProgMount, 4, nil); status != 0 {
		t.Fatalf("second client UMNTALL status %d", status)
	}
	checkDump()
	if status, reply := call(second, rpcProgNFS, 1, handle); status != 0 || len(reply) != 88 || binary.BigEndian.Uint32(reply) != 0 {
		t.Fatalf("unmount revoked the NFS handle, GETATTR = %d,%x", status, reply)
	}
}

func TestNFSTCPReconnectReplay(t *testing.T) {
	export := t.TempDir()
	server := &nfsServer{}
	first := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
	reconnected := &net.TCPAddr{IP: first.IP, Port: 10002}
	other := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 10001}
	call := func(peer *net.TCPAddr, xid, program, procedure uint32, args []byte) []byte {
		t.Helper()
		body := append(nfsWords(xid, 0, 2, program, 3, procedure, 0, 0, 0, 0), args...)
		reply := server.rpcReply(nil, peer, export, body, nfsMaxTransfer)
		if len(reply) < 32 || !bytes.Equal(reply[4:28], nfsWords(xid, 1, 0, 0, 0, 0)) {
			t.Fatalf("RPC reply %x", reply)
		}
		return reply[28:]
	}
	mount := call(first, 1, rpcProgMount, 1, nfsOpaque(nil, []byte("/")))
	if len(mount) < 24 || binary.BigEndian.Uint32(mount) != 0 {
		t.Fatalf("mount result %x", mount)
	}
	root := mount[4:24]
	child := nfsOpaque(bytes.Clone(root), []byte("reconnect"))
	args := append(bytes.Clone(child), nfsWords(0, 0, 0, 0, 0, 0)...)
	original := call(first, 2, rpcProgNFS, 9, args)
	if binary.BigEndian.Uint32(original) != 0 {
		t.Fatalf("original MKDIR %x", original)
	}
	if replay := call(reconnected, 2, rpcProgNFS, 9, args); !bytes.Equal(replay, original) {
		t.Fatalf("reconnected MKDIR replay %x, want %x", replay, original)
	}
	if different := call(other, 2, rpcProgNFS, 9, args); binary.BigEndian.Uint32(different) != nfs3ErrExist {
		t.Fatalf("different client MKDIR %x", different)
	}
	if different := call(reconnected, 3, rpcProgNFS, 9, args); binary.BigEndian.Uint32(different) != nfs3ErrExist {
		t.Fatalf("different transaction MKDIR %x", different)
	}
	newArgs := nfsOpaque(bytes.Clone(root), []byte("other-directory"))
	newArgs = append(newArgs, nfsWords(0, 0, 0, 0, 0, 0)...)
	if different := call(reconnected, 2, rpcProgNFS, 9, newArgs); binary.BigEndian.Uint32(different) != 0 {
		t.Fatalf("reused XID with a different request %x", different)
	}
}

func TestNFSDatagrams(t *testing.T) {
	if _, ok := GetProtocol("nfs").HandleFunc.(func() (TCPFunction, UDPFunction)); !ok {
		t.Fatal("NFS has no paired datagram handler")
	}
	export := t.TempDir()
	conn, stop := startRound6Server(t, round6Case{Handler: "nfs", UDP: true, Params: map[string]any{"fs_path": export}})
	defer stop()
	call := func(xid, program, proc uint32, args []byte) []byte {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		request := append(nfsWords(xid, 0, 2, program, 3, proc, 0, 0, 0, 0), args...)
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 65535)
		n, err := conn.Read(reply)
		if err != nil || n < 28 || !bytes.Equal(reply[:24], nfsWords(xid, 1, 0, 0, 0, 0)) {
			t.Fatalf("datagram reply %x, %v", reply[:n], err)
		}
		return reply[24:n]
	}
	root := call(1, rpcProgMount, 1, nfsOpaque(nil, []byte("/")))
	if len(root) < 24 || binary.BigEndian.Uint32(root) != 0 {
		t.Fatalf("datagram MOUNT result %x", root)
	}
	handle := root[4:24]
	info := call(2, rpcProgNFS, 19, handle)
	if len(info) != 140 || binary.BigEndian.Uint32(info[92:]) != 8192 || binary.BigEndian.Uint32(info[104:]) != 8192 {
		t.Fatalf("UDP transfer limits %x", info)
	}
	child := nfsOpaque(bytes.Clone(handle), []byte("datagram.txt"))
	mkdir := append(bytes.Clone(child), nfsWords(0, 0, 0, 0, 0, 0)...)
	created := call(3, rpcProgNFS, 9, mkdir)
	if binary.BigEndian.Uint32(created) != 0 || !bytes.Equal(call(3, rpcProgNFS, 9, mkdir), created) {
		t.Fatalf("duplicate MKDIR result %x", created)
	}
	if result := call(4, rpcProgNFS, 9, mkdir); binary.BigEndian.Uint32(result) != nfs3ErrExist {
		t.Fatalf("new XID collision result %x", result)
	}
	if err := os.WriteFile(filepath.Join(export, "large"), bytes.Repeat([]byte("x"), 16384), 0600); err != nil {
		t.Fatal(err)
	}
	file := call(5, rpcProgNFS, 3, nfsOpaque(bytes.Clone(handle), []byte("large")))
	if len(file) < 24 || binary.BigEndian.Uint32(file) != 0 {
		t.Fatalf("datagram LOOKUP result %x", file)
	}
	read := call(6, rpcProgNFS, 6, append(bytes.Clone(file[4:24]), nfsWords(0, 0, 16384)...))
	if len(read) != 104+8192 || binary.BigEndian.Uint32(read[92:]) != 8192 || binary.BigEndian.Uint32(read[96:]) != 0 {
		t.Fatalf("UDP READ length %d", len(read))
	}
}

func TestNFSRPCAuthentication(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "nfs"})
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const xid = 19
	call := func(program, procedure uint32, auth, args []byte) []byte {
		t.Helper()
		body := append(nfsWords(xid, 0, 2, program, 3, procedure), auth...)
		body = append(body, args...)
		if _, err := conn.Write(append(nfsWords(0x80000000|uint32(len(body))), body...)); err != nil {
			t.Fatal(err)
		}
		reply, err := readRPCRecord(conn, 4096)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	authSys := nfsOpaque(nfsWords(1), bytes.Repeat([]byte("x"), 255))
	authSys = append(authSys, nfsWords(1000, 1000, 16)...)
	authSys = append(authSys, make([]byte, 16*4)...)
	sys := nfsOpaque(nfsWords(1), authSys)
	none := nfsWords(0, 0)
	for _, tc := range []struct {
		name string
		auth []byte
		want uint32
	}{
		{"AUTH_NONE", append(bytes.Clone(none), none...), 0},
		{"AUTH_SYS limit values", append(bytes.Clone(sys), none...), 0},
		{"truncated credential", nfsWords(1, 20), 1},
		{"AUTH_NONE with data", append(nfsOpaque(nfsWords(0), nfsWords(99)), none...), 1},
		{"AUTH_SYS missing groups", append(nfsOpaque(nfsWords(1), authSys[:len(authSys)-4]), none...), 1},
		{"credential exceeds 400 bytes", nfsWords(1, 401), 1},
		{"unsupported flavor", append(nfsWords(99, 0), none...), 5},
		{"missing verifier", sys, 3},
		{"nonempty verifier", append(bytes.Clone(sys), nfsWords(0, 4, 1)...), 3},
		{"unexpected verifier flavor", append(bytes.Clone(sys), nfsWords(1, 0)...), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := call(rpcProgNFS, 0, tc.auth, nil)
			expected := rpcAcceptedReply(xid, 0, nil)
			if tc.want != 0 {
				expected = rpcDeniedReply(xid, 1, tc.want)
			}
			if !bytes.Equal(reply, expected[4:]) {
				t.Fatalf("NFS NULL reply %x, want %x", reply, expected[4:])
			}
		})
	}
	reply := call(rpcProgMount, 1, append(bytes.Clone(sys), none...), nfsOpaque(nil, []byte("/")))
	if len(reply) != 60 || !bytes.Equal(reply[48:], nfsWords(2, 1, 0)) {
		t.Fatalf("MOUNT authentication list %x", reply)
	}
}

func TestRejectedMountPathPreservesHandle(t *testing.T) {
	server := &nfsServer{}
	export := t.TempDir()
	valid := nfsOpaque(nil, []byte("/"))
	if status, body := server.respond(rpcProgMount, 1, export, valid, nfsMaxTransfer, nil); status != 0 ||
		len(body) < 24 || binary.BigEndian.Uint32(body) != 0 {
		t.Fatalf("initial mount returned RPC status %d, body %x", status, body)
	}
	handle := server.paths["."]
	empty := nfsWords(0)
	for _, procedure := range []uint32{1, 3} {
		if status, _ := server.respond(rpcProgMount, procedure, export, empty, nfsMaxTransfer, nil); status != 4 {
			t.Fatalf("procedure %d returned RPC status %d, want 4", procedure, status)
		}
		if len(server.handles) != 1 || server.paths["."] != handle {
			t.Fatalf("procedure %d changed the active mount", procedure)
		}
	}
}

func TestNFSFileArgumentErrorsPrecedeStaleHandles(t *testing.T) {
	server := &nfsServer{}
	handle := server.issueHandle(".", nil)
	active := nfsOpaque(nil, handle)
	staleHandle := bytes.Clone(handle)
	staleHandle[0] ^= 1
	stale := nfsOpaque(nil, staleHandle[:])
	export := t.TempDir()
	for _, tc := range []struct {
		name      string
		procedure uint32
		args      []byte
		status    uint32
	}{
		{"getattr missing handle", 1, nil, nfs3ErrInvalid},
		{"getattr missing handle bytes", 1, nfsWords(16), nfs3ErrInvalid},
		{"getattr short handle", 1, append(nfsWords(16), staleHandle[:1]...), nfs3ErrStale},
		{"write missing handle", 7, nil, nfs3ErrInvalid},
		{"mknod unsupported", 11, nil, nfs3ErrNotSupp},
		{"lookup missing name with stale handle", 3, stale, nfs3ErrInvalid},
		{"lookup truncated name with stale handle", 3, append(bytes.Clone(stale), 0, 0, 0, 2, 'a'), nfs3ErrInvalid},
		{"lookup valid name with stale handle", 3, nfsOpaque(bytes.Clone(stale), []byte("fixture")), nfs3ErrStale},
		{"lookup empty name with valid handle", 3, nfsOpaque(bytes.Clone(active), nil), nfs3ErrNoEnt},
		{"read missing fields with stale handle", 6, stale, nfs3ErrInvalid},
		{"read complete fields with stale handle", 6, append(bytes.Clone(stale), nfsWords(0, 0, 8)...), nfs3ErrStale},
		{"readdir missing fields with stale handle", 16, stale, nfs3ErrInvalid},
		{"readdirplus missing max count with stale handle", 17, append(bytes.Clone(stale), nfsWords(0, 0, 0, 0, 4096)...), nfs3ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := server.respond(rpcProgNFS, tc.procedure, export, tc.args, nfsMaxTransfer, nil)
			if status != 0 || len(body) < 4 || binary.BigEndian.Uint32(body) != tc.status {
				t.Fatalf("got RPC status %d with payload %x, want NFS status %d", status, body, tc.status)
			}
		})
	}
}

func TestNFSNonCallLeavesConnectionSilent(t *testing.T) {
	conn, stop := startRound6Server(t, round6Case{Handler: "nfs"})
	defer stop()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, messageType := range []uint32{1, 0} {
		request := nfsWords(0x80000028, 18, messageType, 2, rpcProgNFS, 3, 0, 0, 0, 0, 0)
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("RPC type %d: got %x (%v), want silence", messageType, b[:n], err)
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

func TestNFSDirectoryPagination(t *testing.T) {
	for _, procedure := range []uint32{16, 17} {
		name := "READDIR"
		if procedure == 17 {
			name = "READDIRPLUS"
		}
		t.Run(name, func(t *testing.T) {
			export := t.TempDir()
			for _, name := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
				if err := os.WriteFile(filepath.Join(export, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := &nfsServer{}
			call := func(program, procedure uint32, args []byte) []byte {
				t.Helper()
				status, reply := server.respond(program, procedure, export, args, nfsMaxTransfer, nil)
				if status != 0 || len(reply) < 4 {
					t.Fatalf("RPC status %d, reply %x", status, reply)
				}
				return reply
			}
			mount := call(rpcProgMount, 1, nfsOpaque(nil, []byte("/")))
			handle := mount[4:24]
			request := func(cookie, verifier uint64, count uint32) []byte {
				args := binary.BigEndian.AppendUint64(bytes.Clone(handle), cookie)
				args = binary.BigEndian.AppendUint64(args, verifier)
				args = binary.BigEndian.AppendUint32(args, count)
				if procedure == 17 {
					args = binary.BigEndian.AppendUint32(args, 300)
				}
				return call(rpcProgNFS, procedure, args)
			}

			count := uint32(144) // Room for directory attributes and one name.
			if procedure == 17 {
				count = 42 // Room for one entry's directory data.
			}
			var cookie, verifier uint64
			var names []string
			for page := 0; page < 3; page++ {
				response := request(cookie, verifier, count)
				limit := count
				if procedure == 17 {
					limit = 300
				}
				if len(response) > int(limit)+4 || len(response) < 112 || binary.BigEndian.Uint32(response) != 0 {
					t.Fatalf("directory page violates status or budget: %x", response)
				}
				gotVerifier := binary.BigEndian.Uint64(response[92:100])
				if page != 0 && gotVerifier != verifier {
					t.Fatalf("verifier changed from %x to %x", verifier, gotVerifier)
				}
				verifier = gotVerifier
				entry := response[100:]
				if binary.BigEndian.Uint32(entry) != 1 {
					t.Fatalf("expected one entry: %x", entry)
				}
				fileID := binary.BigEndian.Uint64(entry[4:])
				entry = entry[12:]
				filename, ok := takeNFSOpaque(&entry)
				if !ok || len(entry) < 16 {
					t.Fatalf("malformed directory entry: %x", entry)
				}
				names = append(names, string(filename))
				cookie = binary.BigEndian.Uint64(entry)
				if cookie != uint64(page+1) {
					t.Fatalf("unexpected cookie %d", cookie)
				}
				entry = entry[8:]
				if procedure == 17 {
					if len(entry) < 100 || binary.BigEndian.Uint32(entry) != 1 || binary.BigEndian.Uint32(entry[88:]) != 1 {
						t.Fatalf("missing attributes or handle: %x", entry)
					}
					entry = entry[92:]
					child, ok := takeNFSOpaque(&entry)
					if !ok {
						t.Fatalf("malformed child handle: %x", entry)
					}
					attr := call(rpcProgNFS, 1, nfsOpaque(nil, child))
					if len(attr) != 88 || binary.BigEndian.Uint32(attr) != 0 || binary.BigEndian.Uint64(attr[56:]) != fileID {
						t.Fatalf("child handle or attributes inconsistent: %x", attr)
					}
				}
				if len(entry) != 8 || binary.BigEndian.Uint32(entry) != 0 || (binary.BigEndian.Uint32(entry[4:]) != 0) != (page == 2) {
					t.Fatalf("unexpected page terminator: %x", entry)
				}
			}
			if !slices.Equal(names, []string{"alpha.txt", "beta.txt", "gamma.txt"}) {
				t.Fatalf("directory entries: %v", names)
			}
			if status := binary.BigEndian.Uint32(request(1, verifier^1, count)); status != nfs3ErrBadCookie {
				t.Fatal("wrong verifier did not reject the cookie")
			}
			if status := binary.BigEndian.Uint32(request(99, verifier, count)); status != nfs3ErrBadCookie {
				t.Fatal("out-of-range cookie was accepted")
			}
			if status := binary.BigEndian.Uint32(request(0, 0, 8)); status != nfs3ErrTooSmall {
				t.Fatal("insufficient byte budget did not return TOOSMALL")
			}
			if err := os.WriteFile(filepath.Join(export, "delta.txt"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if status := binary.BigEndian.Uint32(request(1, verifier, count)); status != nfs3ErrBadCookie {
				t.Fatal("directory change did not invalidate the cookie")
			}
			if status := binary.BigEndian.Uint32(call(rpcProgNFS, 1, handle)); status != 0 {
				t.Fatal("directory handle was invalidated")
			}
		})
	}
}

func TestNFSExclusiveCreateReplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux stable create verifier storage")
	}
	export := t.TempDir()
	server := &nfsServer{}
	call := func(program, procedure uint32, args []byte) []byte {
		t.Helper()
		status, reply := server.respond(program, procedure, export, args, nfsMaxTransfer, nil)
		if status != 0 || len(reply) < 4 {
			t.Fatalf("RPC status %d, reply %x", status, reply)
		}
		return reply
	}
	mount := func() []byte {
		t.Helper()
		reply := call(rpcProgMount, 1, nfsOpaque(nil, []byte("/")))
		if len(reply) < 24 || binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("mount result %x", reply)
		}
		return reply[4:24]
	}
	create := func(handle []byte, name string, verifier []byte) []byte {
		args := nfsOpaque(bytes.Clone(handle), []byte(name))
		return call(rpcProgNFS, 8, append(append(args, nfsWords(2)...), verifier...))
	}
	root := mount()
	verifier := []byte{0, 0, 1, 255, 254, 0, 128, 64}
	if reply := create(root, "malformed", verifier[:7]); binary.BigEndian.Uint32(reply) != nfs3ErrInvalid {
		t.Fatalf("truncated verifier result %x", reply)
	}
	reply := create(root, "exclusive", verifier)
	if len(reply) < 28 || !bytes.Equal(reply[:8], nfsWords(0, 1)) {
		t.Fatalf("exclusive create result %x", reply)
	}
	initialHandle := bytes.Clone(reply[8:28])
	file := filepath.Join(export, "exclusive")
	if err := os.WriteFile(file, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, time.Unix(1700000000, 0), time.Unix(1700000001, 0)); err != nil {
		t.Fatal(err)
	}
	again := create(root, "exclusive", verifier)
	if len(again) < 28 || binary.BigEndian.Uint32(again) != 0 || !bytes.Equal(again[8:28], initialHandle) {
		t.Fatalf("same listener replay %x", again)
	}
	server = &nfsServer{}
	root = mount()
	if retry := create(root, "exclusive", verifier); binary.BigEndian.Uint32(retry) != 0 {
		t.Fatalf("post-restart replay %x", retry)
	}
	other := bytes.Clone(verifier)
	other[7]++
	if collision := create(root, "exclusive", other); binary.BigEndian.Uint32(collision) != nfs3ErrExist {
		t.Fatalf("different verifier result %x", collision)
	}
	if err := os.WriteFile(filepath.Join(export, "ordinary"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if collision := create(root, "ordinary", verifier); binary.BigEndian.Uint32(collision) != nfs3ErrExist {
		t.Fatalf("ordinary file collision result %x", collision)
	}
	stat, err := os.Stat(file)
	if err != nil || !stat.ModTime().Equal(time.Unix(1700000001, 0)) {
		t.Fatalf("replay changed metadata %v, %v", stat, err)
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != "preserve" {
		t.Fatalf("replay changed data to %q, %v", got, err)
	}
}

func TestNFSMountFileLifecycle(t *testing.T) {
	base := t.TempDir()
	const content = "fixture export\n"
	if err := os.WriteFile(filepath.Join(base, "note.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	protocol := GetProtocol("nfs")
	var serve func(*SessionConnection) error
	switch handler := protocol.HandleFunc.(type) {
	case func() (TCPFunction, UDPFunction):
		serve, _ = handler()
	case func(*SessionConnection) error:
		serve = handler
	case func() func(*SessionConnection) error:
		serve = handler()
	default:
		t.Fatalf("unexpected NFS handler %T", handler)
	}
	dial := func() net.Conn {
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		go serve(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{BindInfo: &BindInfo{
			Params: map[string]any{"fs_path": base},
		}}})
		return client
	}
	var xid uint32
	request := func(client net.Conn, program, procedure uint32, args []byte) []byte {
		t.Helper()
		xid++
		call := binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(40+len(args)))
		for _, field := range []uint32{xid, 0, 2, program, 3, procedure, 0, 0, 0, 0} {
			call = binary.BigEndian.AppendUint32(call, field)
		}
		if _, err := client.Write(append(call, args...)); err != nil {
			t.Fatal(err)
		}
		result, err := readRPCRecord(client, (1<<20)+4096)
		if err != nil || len(result) < 28 || binary.BigEndian.Uint32(result[:4]) != xid || binary.BigEndian.Uint32(result[20:24]) != 0 {
			t.Fatalf("RPC reply %x, %v", result, err)
		}
		return result[24:]
	}
	primary := dial()
	mountRoot := []byte{0, 0, 0, 1, '/', 0, 0, 0}
	root := request(primary, rpcProgMount, 1, mountRoot)
	if len(root) != 36 || binary.BigEndian.Uint32(root[:4]) != 0 || binary.BigEndian.Uint32(root[4:8]) != 16 {
		t.Fatalf("mount result %x", root)
	}
	attrib := request(primary, rpcProgNFS, 1, root[4:24])
	if len(attrib) != 88 || binary.BigEndian.Uint32(attrib[4:8]) != 2 {
		t.Fatalf("directory attributes %x", attrib)
	}
	fsinfo := request(primary, rpcProgNFS, 19, root[4:24])
	if len(fsinfo) != 140 || binary.BigEndian.Uint32(fsinfo) != 0 ||
		binary.BigEndian.Uint32(fsinfo[92:]) != 1<<20 ||
		binary.BigEndian.Uint32(fsinfo[104:]) != 1<<20 ||
		binary.BigEndian.Uint32(fsinfo[136:])&^0x11 != 0x02 {
		t.Fatalf("FSINFO result %x", fsinfo)
	}
	if runtime.GOOS == "linux" {
		stat := request(primary, rpcProgNFS, 18, root[4:24])
		if len(stat) != 144 || binary.BigEndian.Uint32(stat) != 0 ||
			binary.BigEndian.Uint64(stat[92:]) == 0 ||
			binary.BigEndian.Uint64(stat[100:]) > binary.BigEndian.Uint64(stat[92:]) ||
			binary.BigEndian.Uint64(stat[108:]) > binary.BigEndian.Uint64(stat[100:]) ||
			binary.BigEndian.Uint32(stat[140:]) != 0 {
			t.Fatalf("FSSTAT result %x", stat)
		}
	}
	conf := request(primary, rpcProgNFS, 20, root[4:24])
	if len(conf) != 116 || binary.BigEndian.Uint32(conf) != 0 ||
		binary.BigEndian.Uint32(conf[96:]) == 0 ||
		!bytes.Equal(conf[100:108], nfsWords(1, 1)) {
		t.Fatalf("PATHCONF result %x", conf)
	}
	if runtime.GOOS == "linux" {
		nameMax := int(binary.BigEndian.Uint32(conf[96:]))
		longName := nfsOpaque(bytes.Clone(root[4:24]), bytes.Repeat([]byte("x"), nameMax+1))
		for _, procedure := range []uint32{3, 8, 12} {
			args := longName
			if procedure == 8 {
				args = append(bytes.Clone(longName), nfsWords(1, 0, 0, 0, 0, 0, 0)...)
			}
			if reply := request(primary, rpcProgNFS, procedure, args); binary.BigEndian.Uint32(reply) != 63 {
				t.Fatalf("procedure %d oversized name result %x", procedure, reply)
			}
		}
	}
	for _, procedure := range []uint32{18, 19, 20} {
		stale := request(primary, rpcProgNFS, procedure, nfsOpaque(nil, make([]byte, 16)))
		if !bytes.Equal(stale, nfsWords(nfs3ErrStale, 0)) {
			t.Fatalf("procedure %d stale result %x", procedure, stale)
		}
	}
	lookup := append(append([]byte(nil), root[4:24]...), 0, 0, 0, 8)
	lookup = append(lookup, "note.txt"...)
	file := request(primary, rpcProgNFS, 3, lookup)
	if len(file) != 200 || binary.BigEndian.Uint32(file[:4]) != 0 || binary.BigEndian.Uint32(file[4:8]) != 16 {
		t.Fatalf("lookup result %x", file)
	}
	if runtime.GOOS == "linux" {
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		modified := time.Unix(1700000100, 123456789)
		for _, target := range []string{outside, "../missing", "literal\\target", string(bytes.Repeat([]byte("x"), 300))} {
			name := nfsOpaque(bytes.Clone(root[4:24]), []byte("symlink"))
			attrs := nfsWords(0, 0, 0, 0, 0, 2, uint32(modified.Unix()), uint32(modified.Nanosecond()))
			create := nfsOpaque(append(bytes.Clone(name), attrs...), []byte(target))
			result := request(primary, rpcProgNFS, 10, create)
			if len(result) < 28 || !bytes.Equal(result[:8], nfsWords(0, 1)) {
				t.Fatalf("SYMLINK target %q result %x", target, result)
			}
			link := result[8:28]
			if info, err := os.Lstat(filepath.Join(base, "symlink")); err != nil || !info.ModTime().Equal(modified) {
				t.Fatalf("created symlink attributes %v, %v", info, err)
			}
			reply := request(primary, rpcProgNFS, 5, link)
			if len(reply) < 96 || binary.BigEndian.Uint32(reply) != 0 {
				t.Fatalf("READLINK result %x", reply)
			}
			data := reply[92:]
			if got, ok := takeNFSOpaque(&data); !ok || len(data) != 0 || string(got) != target {
				t.Fatalf("READLINK returned %q, want %q", got, target)
			}
			read := append(bytes.Clone(link), nfsWords(0, 0, 32)...)
			if status := binary.BigEndian.Uint32(request(primary, rpcProgNFS, 6, read)); status == 0 {
				t.Fatalf("READ followed symlink target %q", target)
			}
			if status := binary.BigEndian.Uint32(request(primary, rpcProgNFS, 12, name)); status != 0 {
				t.Fatalf("REMOVE symlink result %d", status)
			}
		}
		if info, err := os.Stat(outside); err != nil || info.ModTime().Equal(modified) {
			t.Fatalf("target attributes changed %v, %v", info, err)
		}
	}
	for _, access := range []struct {
		handle []byte
		mask   uint32
		got    uint32
	}{
		{root[4:24], 0xffffffff, 0x1f},
		{file[4:24], 0xffffffff, 0x0d},
		{file[4:24], 0x03, 0x01},
		{file[4:24], 0, 0},
	} {
		args := binary.BigEndian.AppendUint32(bytes.Clone(access.handle), access.mask)
		reply := request(primary, rpcProgNFS, 4, args)
		if len(reply) != 96 || !bytes.Equal(reply[:8], nfsWords(0, 1)) ||
			binary.BigEndian.Uint32(reply[92:]) != access.got {
			t.Fatalf("ACCESS mask %08x result %x, want %02x", access.mask, reply, access.got)
		}
	}
	if reply := request(primary, rpcProgNFS, 4, root[4:24]); !bytes.Equal(reply, nfsWords(nfs3ErrInvalid, 0)) {
		t.Fatalf("truncated ACCESS result %x", reply)
	}
	stale := append(nfsOpaque(nil, make([]byte, 16)), nfsWords(0x3f)...)
	if reply := request(primary, rpcProgNFS, 4, stale); !bytes.Equal(reply, nfsWords(nfs3ErrStale, 0)) {
		t.Fatalf("stale ACCESS result %x", reply)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		note := filepath.Join(base, "note.txt")
		if err := os.Chmod(note, 0400); err != nil {
			t.Fatal(err)
		}
		args := append(bytes.Clone(file[4:24]), nfsWords(0x3f)...)
		reply := request(primary, rpcProgNFS, 4, args)
		if len(reply) != 96 || binary.BigEndian.Uint32(reply[92:]) != 0x01 {
			t.Fatalf("read-only ACCESS result %x", reply)
		}
		if err := os.Chmod(note, 0600); err != nil {
			t.Fatal(err)
		}
	}
	reader := dial()
	read := binary.BigEndian.AppendUint64(append([]byte(nil), file[4:24]...), 0)
	read = binary.BigEndian.AppendUint32(read, uint32(len(content)))
	data := request(reader, rpcProgNFS, 6, read)
	if len(data) < 104+len(content) || binary.BigEndian.Uint32(data[96:100]) != 1 || string(data[104:104+len(content)]) != content {
		t.Fatalf("read result %x", data)
	}
	write := binary.BigEndian.AppendUint64(append([]byte(nil), file[4:24]...), 1)
	write = append(write, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 'X', 'Y', 0, 0)
	invalidStable := bytes.Clone(write)
	binary.BigEndian.PutUint32(invalidStable[32:], 3)
	if reply := request(reader, rpcProgNFS, 7, invalidStable); binary.BigEndian.Uint32(reply) != nfs3ErrInvalid {
		t.Fatalf("invalid WRITE stable mode %x", reply)
	}
	if reply := request(reader, rpcProgNFS, 7, append(bytes.Clone(write), nfsWords(0)...)); binary.BigEndian.Uint32(reply) != nfs3ErrInvalid {
		t.Fatalf("WRITE trailing arguments %x", reply)
	}
	overflow := bytes.Clone(write)
	binary.BigEndian.PutUint64(overflow[20:], 1<<63-1)
	if reply := request(reader, rpcProgNFS, 7, overflow); binary.BigEndian.Uint32(reply) != 27 {
		t.Fatalf("WRITE range overflow %x", reply)
	}
	if got, err := os.ReadFile(filepath.Join(base, "note.txt")); err != nil || string(got) != content {
		t.Fatalf("invalid WRITE changed contents to %q, %v", got, err)
	}
	written := request(reader, rpcProgNFS, 7, write)
	if len(written) != 136 || binary.BigEndian.Uint32(written) != 0 || binary.BigEndian.Uint32(written[120:124]) != 2 || binary.BigEndian.Uint32(written[124:128]) != 2 {
		t.Fatalf("write result %x", written)
	}
	for _, span := range [][]byte{nfsWords(0, 0, 0), nfsWords(0, 1, 2)} {
		commit := append(bytes.Clone(file[4:24]), span...)
		committed := request(reader, rpcProgNFS, 21, commit)
		if len(committed) != 128 || !bytes.Equal(committed[:8], nfsWords(0, 1)) ||
			!bytes.Equal(committed[120:], written[128:]) {
			t.Fatalf("commit result %x", committed)
		}
	}
	if invalid := request(reader, rpcProgNFS, 21, append(bytes.Clone(file[4:24]), nfsWords(0, 0, 0, 0)...)); binary.BigEndian.Uint32(invalid) != nfs3ErrInvalid {
		t.Fatalf("COMMIT trailing arguments %x", invalid)
	}
	if invalid := request(reader, rpcProgNFS, 21, append(bytes.Clone(root[4:24]), nfsWords(0, 0, 0)...)); binary.BigEndian.Uint32(invalid) != nfs3ErrInvalid {
		t.Fatalf("COMMIT on directory %x", invalid)
	}
	got, err := os.ReadFile(filepath.Join(base, "note.txt"))
	if err != nil || string(got) != "fXYture export\n" {
		t.Fatalf("export contents %q, %v", got, err)
	}
	dir := request(reader, rpcProgNFS, 1, root[4:24])
	if len(dir) != 88 || binary.BigEndian.Uint32(dir) != 0 {
		t.Fatalf("directory handle after file lookup %x", dir)
	}
	remount := request(primary, rpcProgMount, 1, mountRoot)
	if !bytes.Equal(root[4:24], remount[4:24]) {
		t.Fatalf("remount changed directory handle from %x to %x", root[4:24], remount[4:24])
	}
	again := request(primary, rpcProgNFS, 3, lookup)
	if !bytes.Equal(file[4:24], again[4:24]) {
		t.Fatalf("repeat lookup changed the file handle from %x to %x", file[4:24], again[4:24])
	}
	maximum := binary.BigEndian.Uint32(fsinfo[104:])
	payload := bytes.Repeat([]byte("x"), int(maximum)+4)
	largeWrite := append(bytes.Clone(file[4:24]), nfsWords(0, 0, uint32(len(payload)), 2)...)
	largeWrite = nfsOpaque(largeWrite, payload)
	if reply := request(reader, rpcProgNFS, 7, largeWrite); len(reply) != 136 ||
		binary.BigEndian.Uint32(reply) != 0 || binary.BigEndian.Uint32(reply[120:]) != maximum {
		t.Fatalf("short WRITE result %x", reply)
	}
	largeRead := append(bytes.Clone(file[4:24]), nfsWords(0, 0, uint32(len(payload)))...)
	if reply := request(reader, rpcProgNFS, 6, largeRead); len(reply) != 104+int(maximum) ||
		binary.BigEndian.Uint32(reply) != 0 || binary.BigEndian.Uint32(reply[92:]) != maximum ||
		binary.BigEndian.Uint32(reply[96:]) != 1 || !bytes.Equal(reply[104:], payload[:maximum]) {
		t.Fatalf("short READ result length %d", len(reply))
	}
	name := "new.txt"
	create := nfsOpaque(append([]byte(nil), root[4:24]...), []byte(name))
	create = append(create, nfsWords(0, 1, 0600, 0, 0, 0, 0, 0)...)
	created := request(primary, rpcProgNFS, 8, create)
	if len(created) < 28 || !bytes.Equal(created[:8], nfsWords(0, 1)) {
		t.Fatalf("create result %x", created)
	}
	createdPath := filepath.Join(base, name)
	info, err := os.Stat(createdPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 ||
		(runtime.GOOS == "linux" && info.Mode().Perm() != 0600) {
		t.Fatalf("created file info %v, %v", info, err)
	}
	if err := os.WriteFile(createdPath, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if reply := request(primary, rpcProgNFS, 8, create); binary.BigEndian.Uint32(reply) != 0 {
		t.Fatalf("repeated unchecked create %x", reply)
	}
	if got, err := os.ReadFile(createdPath); err != nil || string(got) != "preserve" {
		t.Fatalf("unchecked create changed contents to %q, %v", got, err)
	}
	setMode := append(bytes.Clone(created[8:28]), nfsWords(1, 0640, 0, 0, 0, 0, 0)...)
	if reply := request(primary, rpcProgNFS, 2, append(bytes.Clone(setMode), nfsWords(1, 0, 0)...)); binary.BigEndian.Uint32(reply) != 10002 {
		t.Fatalf("guard mismatch result %x", reply)
	}
	attr := request(primary, rpcProgNFS, 1, created[8:28])
	guard := append(nfsWords(1), attr[80:88]...)
	if reply := request(primary, rpcProgNFS, 2, append(setMode, guard...)); binary.BigEndian.Uint32(reply) != 0 {
		t.Fatalf("guarded setattr result %x", reply)
	}
	if info, err := os.Stat(createdPath); err != nil || (runtime.GOOS == "linux" && info.Mode().Perm() != 0640) {
		t.Fatalf("updated file info %v, %v", info, err)
	}
	badName := "refused.txt"
	badCreate := nfsOpaque(bytes.Clone(root[4:24]), []byte(badName))
	badCreate = append(badCreate, nfsWords(1, 0, 1, 12345, 0, 0, 0, 0)...)
	if reply := request(primary, rpcProgNFS, 8, badCreate); binary.BigEndian.Uint32(reply) != 1 {
		t.Fatalf("ownership request result %x", reply)
	}
	if _, err := os.Stat(filepath.Join(base, badName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected create left a file: %v", err)
	}
	if runtime.GOOS == "linux" {
		setTime := func(parts ...uint32) []byte {
			args := append(bytes.Clone(created[8:28]), nfsWords(0, 0, 0, 0)...)
			args = append(args, nfsWords(parts...)...)
			return request(primary, rpcProgNFS, 2, append(args, nfsWords(0)...))
		}
		stamp := nfsWords(1700000000, 123456789)
		if reply := setTime(2, 1700000000, 123456789, 0); binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("client atime SETATTR result %x", reply)
		}
		if reply := setTime(0, 2, 1700000001, 987654321); binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("client mtime SETATTR result %x", reply)
		}
		check := request(primary, rpcProgNFS, 1, created[8:28])
		if !bytes.Equal(check[64:72], stamp) || !bytes.Equal(check[72:80], nfsWords(1700000001, 987654321)) {
			t.Fatalf("GETATTR changed or lost timestamps %x", check[64:80])
		}
		if reply := setTime(0, 2, 1700000001, 1000000000); binary.BigEndian.Uint32(reply) != nfs3ErrInvalid {
			t.Fatalf("invalid nanoseconds SETATTR result %x", reply)
		}
		if unchanged := request(primary, rpcProgNFS, 1, created[8:28]); !bytes.Equal(check[64:80], unchanged[64:80]) {
			t.Fatalf("invalid timestamp changed attributes %x", unchanged[64:80])
		}
		since := uint32(time.Now().Unix())
		if reply := setTime(0, 1); binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("server time SETATTR result %x", reply)
		}
		check = request(primary, rpcProgNFS, 1, created[8:28])
		if seconds := binary.BigEndian.Uint32(check[72:]); seconds < since ||
			seconds > uint32(time.Now().Unix()) || !bytes.Equal(check[64:72], stamp) {
			t.Fatalf("GETATTR server time result %x", check[64:80])
		}
		if binary.BigEndian.Uint32(fsinfo[136:])&0x10 == 0 {
			t.Fatalf("FSINFO did not advertise timestamp support %x", fsinfo)
		}
		timedName := "timed.txt"
		timedCreate := nfsOpaque(bytes.Clone(root[4:24]), []byte(timedName))
		timedCreate = append(timedCreate, nfsWords(1, 0, 0, 0, 0, 0, 2, 1700000002, 765432100)...)
		if reply := request(primary, rpcProgNFS, 8, timedCreate); binary.BigEndian.Uint32(reply) != 0 {
			t.Fatalf("CREATE with mtime result %x", reply)
		}
		if info, err := os.Stat(filepath.Join(base, timedName)); err != nil ||
			!info.ModTime().Equal(time.Unix(1700000002, 765432100)) {
			t.Fatalf("created file timestamp %v, %v", info, err)
		}
	}
	dir = request(primary, rpcProgNFS, 1, root[4:24])
	if len(dir) != 88 || binary.BigEndian.Uint32(dir) != 0 {
		t.Fatalf("directory handle after create %x", dir)
	}
	subdir := nfsOpaque(bytes.Clone(root[4:24]), []byte("subdir"))
	dirAttrs := nfsWords(1, 0700, 0, 0, 0, 0, 0)
	if runtime.GOOS == "linux" {
		dirAttrs = nfsWords(1, 0700, 0, 0, 0, 0, 2, 1700000003, 123456789)
	}
	mkdir := request(primary, rpcProgNFS, 9, append(bytes.Clone(subdir), dirAttrs...))
	if len(mkdir) < 28 || !bytes.Equal(mkdir[:8], nfsWords(0, 1)) {
		t.Fatalf("mkdir result %x", mkdir)
	}
	subdirPath := filepath.Join(base, "subdir")
	if info, err := os.Stat(subdirPath); err != nil || !info.IsDir() ||
		(runtime.GOOS == "linux" && (info.Mode().Perm() != 0700 ||
			!info.ModTime().Equal(time.Unix(1700000003, 123456789)))) {
		t.Fatalf("created directory info %v, %v", info, err)
	}
	if reply := request(primary, rpcProgNFS, 12, subdir); !bytes.Equal(reply[:8], nfsWords(21, 1)) {
		t.Fatalf("REMOVE directory result %x", reply)
	}
	if reply := request(primary, rpcProgNFS, 13, lookup); !bytes.Equal(reply[:8], nfsWords(20, 1)) {
		t.Fatalf("RMDIR file result %x", reply)
	}
	nestedPath := filepath.Join(subdirPath, "nested")
	if err := os.WriteFile(nestedPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if reply := request(primary, rpcProgNFS, 13, subdir); !bytes.Equal(reply[:8], nfsWords(66, 1)) {
		t.Fatalf("RMDIR nonempty result %x", reply)
	}
	child := nfsOpaque(bytes.Clone(mkdir[8:28]), []byte("nested"))
	if reply := request(primary, rpcProgNFS, 12, child); binary.BigEndian.Uint32(reply) != 0 {
		t.Fatalf("REMOVE child result %x", reply)
	}
	if reply := request(primary, rpcProgNFS, 13, subdir); binary.BigEndian.Uint32(reply) != 0 {
		t.Fatalf("RMDIR empty result %x", reply)
	}
	if reply := request(primary, rpcProgNFS, 1, mkdir[8:28]); binary.BigEndian.Uint32(reply) != nfs3ErrStale {
		t.Fatalf("removed directory handle result %x", reply)
	}
	rename := nfsOpaque(bytes.Clone(root[4:24]), []byte("note.txt"))
	rename = nfsOpaque(append(rename, root[4:24]...), []byte("renamed.txt"))
	if result := request(primary, rpcProgNFS, 14, rename); binary.BigEndian.Uint32(result) != 0 {
		t.Fatalf("rename result %x", result)
	}
	if attr := request(reader, rpcProgNFS, 1, file[4:24]); len(attr) != 88 || binary.BigEndian.Uint32(attr) != 0 {
		t.Fatalf("file handle after rename %x", attr)
	}
	remove := nfsOpaque(bytes.Clone(root[4:24]), []byte("renamed.txt"))
	alias := nfsOpaque(bytes.Clone(root[4:24]), []byte("alias.txt"))
	if runtime.GOOS == "linux" {
		if binary.BigEndian.Uint32(fsinfo[136:])&1 == 0 || binary.BigEndian.Uint32(conf[92:]) < 2 {
			t.Fatalf("hard links not advertised: %x, %x", fsinfo, conf)
		}
		link := append(bytes.Clone(file[4:24]), alias...)
		reply := request(primary, rpcProgNFS, 15, link)
		if len(reply) != 208 || !bytes.Equal(reply[:8], nfsWords(0, 1)) ||
			binary.BigEndian.Uint32(reply[16:]) != 2 {
			t.Fatalf("LINK result %x", reply)
		}
		if result := request(primary, rpcProgNFS, 15, link); binary.BigEndian.Uint32(result) != nfs3ErrExist {
			t.Fatalf("duplicate LINK result %x", result)
		}
		if result := request(primary, rpcProgNFS, 14, append(bytes.Clone(remove), alias...)); binary.BigEndian.Uint32(result) != 0 {
			t.Fatalf("rename between aliases result %x", result)
		}
		lookedUp := request(reader, rpcProgNFS, 3, alias)
		if len(lookedUp) < 24 || !bytes.Equal(lookedUp[4:24], file[4:24]) {
			t.Fatalf("alias LOOKUP returned a different handle %x", lookedUp)
		}
	}
	if result := request(primary, rpcProgNFS, 12, remove); binary.BigEndian.Uint32(result) != 0 {
		t.Fatalf("remove result %x", result)
	}
	if runtime.GOOS == "linux" {
		if attr := request(reader, rpcProgNFS, 1, file[4:24]); len(attr) != 88 || binary.BigEndian.Uint32(attr) != 0 {
			t.Fatalf("surviving alias lost its handle %x", attr)
		}
		if result := request(primary, rpcProgNFS, 12, alias); binary.BigEndian.Uint32(result) != 0 {
			t.Fatalf("remove alias result %x", result)
		}
	}
	if attr := request(reader, rpcProgNFS, 1, file[4:24]); binary.BigEndian.Uint32(attr) != nfs3ErrStale {
		t.Fatalf("removed file handle remained valid: %x", attr)
	}
}
