package protocols

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func TestSMBCompoundSession(t *testing.T) {
	le := binary.LittleEndian
	const sid, tid = uint64(100), uint32(20)
	state := smbSession{id: sid, key: []byte("synthetic-key-01"), trees: map[uint32]*smbTree{tid: {}}}
	var chain []byte
	commands := []uint16{smbCreate, smbQueryInfo, smbClose}
	for i, command := range commands {
		size := []int{56, 40, 24}[i]
		req := make([]byte, smb2HeaderSize+size)
		copy(req, "\xfeSMB")
		le.PutUint16(req[4:], smb2HeaderSize)
		le.PutUint16(req[12:], command)
		le.PutUint64(req[24:], uint64(i+10))
		le.PutUint32(req[36:], tid)
		le.PutUint64(req[40:], sid)
		flags := uint32(smbSigned)
		if i > 0 {
			flags |= smbRelated
			le.PutUint32(req[36:], ^uint32(0))
			le.PutUint64(req[40:], ^uint64(0))
			idOffset := []int{0, 24, 8}[i] + smb2HeaderSize
			copy(req[idOffset:], smbInheritedFileID[:])
		}
		le.PutUint32(req[16:], flags)
		if i < 2 {
			le.PutUint32(req[20:], uint32(len(req)))
		}
		le.PutUint16(req[64:], []uint16{57, 41, 24}[i])
		copy(req[48:64], state.signature(req))
		chain = append(chain, req...)
	}

	var output bytes.Buffer
	closed, err := state.handleRecord(chain, &output)
	if closed || err != nil {
		t.Fatalf("handleRecord closed=%v err=%v", closed, err)
	}
	for i, command := range commands {
		if output.Len() < 4 {
			t.Fatalf("response frame %d missing", i)
		}
		size := int(binary.BigEndian.Uint32(output.Next(4)))
		p := output.Next(size)
		if size < 64 || len(p) != size || le.Uint16(p[12:]) != command ||
			le.Uint32(p[8:]) != 0 || le.Uint32(p[20:]) != 0 || le.Uint64(p[24:]) != uint64(i+10) ||
			le.Uint32(p[16:]) != 9 || !state.validSignature(p) {
			t.Fatalf("response %d = %x", i, p)
		}
		if i > 0 && (le.Uint32(p[36:]) != ^uint32(0) || le.Uint64(p[40:]) != ^uint64(0)) {
			t.Fatalf("response %d did not preserve identifiers", i)
		}
	}
	if output.Len() != 0 || len(state.trees[tid].files) != 0 {
		t.Fatal("compound close did not release the file handle")
	}

	le.PutUint32(chain[20:], uint32(smb2HeaderSize+1))
	closed, err = state.handleRecord(chain, &output)
	if !closed || err != nil || output.Len() != 0 || len(state.trees[tid].files) != 0 {
		t.Fatal("malformed compound offsets should close the connection before dispatch")
	}
}

func TestReferenceSMBInformationClasses(t *testing.T) {
	le := binary.LittleEndian
	const sessionID, treeID = uint64(100), uint32(20)
	fileID := [16]byte{1}
	state := smbSession{
		id: sessionID, key: []byte("synthetic-key-01"), requireSigning: true,
		trees: map[uint32]*smbTree{treeID: {files: map[[16]byte]*smbOpen{fileID: {}}}},
	}
	for _, group := range []struct {
		name     string
		command  uint16
		infoType byte
		classes  []byte
		flags    []byte
		status   uint32
	}{
		{"file", smbQueryInfo, 1, []byte{4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18, 21, 22, 28, 34, 35, 48, 59}, []byte{0}, 0},
		{"filesystem", smbQueryInfo, 2, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0}, 0},
		{"directory", smbQueryDirectory, 0, []byte{1, 2, 3, 12, 37, 38, 60, 63}, []byte{0, 1, 2, 16}, 0xffffffff},
	} {
		for _, class := range group.classes {
			for _, flags := range group.flags {
				t.Run(fmt.Sprintf("%s/%d/%d", group.name, class, flags), func(t *testing.T) {
					request := make([]byte, smb2HeaderSize+40)
					copy(request, "\xfeSMB")
					le.PutUint16(request[4:], smb2HeaderSize)
					le.PutUint16(request[12:], group.command)
					le.PutUint32(request[16:], smbSigned)
					le.PutUint64(request[24:], 1)
					le.PutUint32(request[36:], treeID)
					le.PutUint64(request[40:], sessionID)
					body := request[smb2HeaderSize:]
					if group.command == smbQueryDirectory {
						le.PutUint16(body, 33)
						body[2], body[3] = class, flags
						copy(body[8:24], fileID[:])
						le.PutUint16(body[24:], smb2HeaderSize+32)
						le.PutUint16(body[26:], 2)
						le.PutUint32(body[28:], 4096)
						body[32] = '*'
						request = request[:smb2HeaderSize+34]
					} else {
						le.PutUint16(body, 41)
						body[2], body[3] = group.infoType, class
						le.PutUint32(body[4:], 4096)
						copy(body[24:], fileID[:])
					}
					copy(request[48:64], state.signature(request))
					var output bytes.Buffer
					closed, err := state.handleRecord(request, &output)
					if closed || err != nil {
						t.Fatalf("query closed=%v, err=%v", closed, err)
					}
					reply := output.Bytes()
					wantBody := []byte{9, 0, 0, 0, 0, 0, 0, 0}
					if len(reply) != 4+smb2HeaderSize+len(wantBody) ||
						le.Uint32(reply[4+8:]) != group.status || !state.validSignature(reply[4:]) ||
						!bytes.Equal(reply[4+smb2HeaderSize:], wantBody) {
						t.Fatalf("response = %x, want signed status %#x and body %x", reply, group.status, wantBody)
					}
				})
			}
		}
	}
}

func TestReferenceSMBSRVSVCQueryProfiles(t *testing.T) {
	le := binary.LittleEndian
	open := smbOpen{pipe: true, bound: true}
	shares := []string{"z-share:First share", "archive:Archive", "public:Public view"}
	transceive := func(op uint16, stub []byte) ([]byte, uint32) {
		const ioctlFixedSize = 56
		wire := make([]byte, smb2HeaderSize+ioctlFixedSize+dceHeaderSize+8+len(stub))
		body := wire[smb2HeaderSize:]
		le.PutUint32(body[4:], smbPipeTransceive)
		le.PutUint32(body[24:], smb2HeaderSize+ioctlFixedSize)
		pdu := body[ioctlFixedSize:]
		le.PutUint32(body[28:], uint32(len(pdu)))
		pdu[0], pdu[3], pdu[4] = 5, dceSingleFrame, 0x10
		le.PutUint16(pdu[8:], uint16(len(pdu)))
		le.PutUint32(pdu[12:], 101)
		le.PutUint32(pdu[16:], uint32(len(stub)))
		le.PutUint16(pdu[22:], op)
		copy(pdu[24:], stub)
		return open.ioctl(wire, body, shares)
	}
	enum := func(level uint32) ([]byte, uint32) {
		stub := make([]byte, 32)
		le.PutUint32(stub[4:], level)
		le.PutUint32(stub[8:], level)
		le.PutUint32(stub[12:], 0x20004)
		le.PutUint32(stub[24:], ^uint32(0))
		return transceive(15, stub)
	}
	levelOne, status := enum(1)
	if status != 0 || len(levelOne) != 48+284 {
		t.Fatalf("level 1 enumeration status = %#x, size = %d", status, len(levelOne))
	}
	for _, level := range []uint32{0, 2, 501, 502, 503} {
		t.Run(fmt.Sprintf("enum/%d", level), func(t *testing.T) {
			reply, status := enum(level)
			if status != 0 || !bytes.Equal(reply, levelOne) {
				t.Fatalf("enumeration status = %#x, reply size = %d, want level 1 response", status, len(reply))
			}
		})
	}
	const emptyResponse = "3100000017c0110000000000000000000000000000000000700000000000000070000000000000000000000000000000"
	for _, name := range []string{"z-share", "Z-SHARE", "unlisted"} {
		for _, level := range []uint32{0, 1, 2, 501, 502, 503, 1005} {
			t.Run(fmt.Sprintf("get-info/%s/%d", name, level), func(t *testing.T) {
				stub := le.AppendUint32(smbNDRString(make([]byte, 4), name), level)
				reply, status := transceive(16, stub)
				if status != 0 || hex.EncodeToString(reply) != emptyResponse {
					t.Fatalf("GetInfo status = %#x, reply = %x, want empty IOCTL success", status, reply)
				}
			})
		}
	}
	for _, query := range []struct {
		name   string
		op     uint16
		prefix []byte
		levels []uint32
	}{
		{"connection-enum", 8, smbNDRString(le.AppendUint32(make([]byte, 4), 0x20004), "z-share"), []uint32{0, 1}},
		{"file-enum", 9, make([]byte, 12), []uint32{2, 3}},
		{"session-enum", 12, make([]byte, 12), []uint32{0, 1, 2, 10, 502}},
		{"server-info", 21, make([]byte, 4), []uint32{100, 101, 102, 502, 503}},
	} {
		for _, level := range query.levels {
			t.Run(fmt.Sprintf("%s/%d", query.name, level), func(t *testing.T) {
				stub := le.AppendUint32(bytes.Clone(query.prefix), level)
				if query.op != 21 {
					for _, field := range []uint32{level, 0x2000c, 0, 0, ^uint32(0), 0} {
						stub = le.AppendUint32(stub, field)
					}
				}
				reply, status := transceive(query.op, stub)
				if status != 0 || hex.EncodeToString(reply) != emptyResponse {
					t.Fatalf("status = %#x, reply = %x, want empty IOCTL success", status, reply)
				}
			})
		}
	}
	if reply, status := enum(1); status != 0 || !bytes.Equal(reply, levelOne) {
		t.Fatalf("pipe did not preserve its binding after GetInfo, status = %#x", status)
	}
}

//go:embed fixtures/reference-smb.json
var smbFixtures []byte

func TestReferenceSMBNegotiation(t *testing.T) {
	var cases []round6Case
	if err := json.Unmarshal(smbFixtures, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) { runRound6Case(t, tc) })
	}
}

func TestSMBSessionAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, user, password, domain string
		accounts                     []any
		rejected                     bool
	}{
		{name: "default", user: "administrator", password: "123456"},
		{name: "custom", user: "FIXTURE", password: "lab-only", domain: "OTHER", accounts: []any{"fixture:lab-only"}},
		{name: "denied", user: "fixture", password: "wrong", accounts: []any{"fixture:lab-only"}, rejected: true},
		{name: "unknown", user: "unknown", password: "lab-only", accounts: []any{"fixture:lab-only"}, rejected: true},
		{name: "empty", user: "administrator", password: "123456", accounts: []any{}, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"server_name": "LAB-SMB", "domain_name": "FIXTURE"}
			if tc.accounts != nil {
				params["accounts"] = tc.accounts
			}
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				_ = serveSMB(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
					BindInfo: &BindInfo{Params: params},
				}})
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dialer := &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{User: tc.user, Password: tc.password, Domain: tc.domain},
			}
			session, err := dialer.DialContext(ctx, client)
			if tc.rejected {
				if err == nil || err.Error() != "invalid response error: broken error response format" {
					t.Fatalf("login result: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := session.WithContext(ctx).Logoff(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSMBShareSessions(t *testing.T) {
	largeConfig, largeNames := make([]any, 24), make([]string, 24)
	for i := range largeNames {
		name := fmt.Sprintf("share-%02d", i)
		largeNames[i] = name
		largeConfig[i] = name + ":An isolated synthetic share for compatibility verification"
	}
	for _, tc := range []struct {
		name   string
		shares []any
		want   []string
	}{
		{name: "defaults", want: []string{"admin", "public"}},
		{name: "configured", shares: []any{"z-share:First share", "archive:Archive"}, want: []string{"z-share", "archive"}},
		{name: "empty", shares: []any{}, want: []string{}},
		{name: "large", shares: largeConfig, want: largeNames},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"accounts": []any{"fixture:lab-only"}}
			if tc.shares != nil {
				params["shares"] = tc.shares
			}
			client, server := net.Pipe()
			defer client.Close()
			go serveSMB(&SessionConnection{Conn: server, ConfigInfo: &ConfigInfo{
				BindInfo: &BindInfo{Params: params},
			}})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dialer := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "fixture", Password: "lab-only"}}
			s, err := dialer.DialContext(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			s = s.WithContext(ctx)
			names, err := s.ListSharenames()
			if err != nil || !reflect.DeepEqual(names, tc.want) {
				t.Fatalf("ListSharenames = %v, %v (want %v)", names, err, tc.want)
			}
			share, err := s.Mount("unlisted")
			if err != nil {
				t.Fatal(err)
			}
			share = share.WithContext(ctx)
			if _, err := share.ReadDir("."); err == nil || !strings.Contains(err.Error(), "response error:") {
				t.Fatalf("ReadDir = %v", err)
			}
			if err := share.WriteFile("fixture.txt", []byte("lab-only"), 0600); err != nil {
				t.Fatal(err)
			}
			if info, err := share.Stat("fixture.txt"); err != nil || info.Size() != 0 {
				t.Fatalf("Stat = %v, %v", info, err)
			}
			if err := share.Mkdir("fixture-dir", 0700); err != nil {
				t.Fatal(err)
			}
			if err := share.Rename("fixture.txt", "renamed.txt"); err == nil || !strings.Contains(err.Error(), "response error:") {
				t.Fatalf("Rename = %v", err)
			}
			if err := share.Remove("fixture.txt"); err == nil || !strings.Contains(err.Error(), "response error:") {
				t.Fatalf("Remove = %v", err)
			}
			f, err := share.Open("fixture.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Stat(); err == nil || !strings.Contains(err.Error(), "broken query info response format") {
				t.Fatalf("open handle Stat = %v", err)
			}
			if _, err := f.Statfs(); err == nil || !strings.Contains(err.Error(), "broken query info response format") {
				t.Fatalf("open handle Statfs = %v", err)
			}
			if err := f.Sync(); err == nil || err.Error() != "sync fixture.txt: response error: " {
				t.Fatalf("Sync = %v", err)
			}
			if err := f.Truncate(25); err == nil || err.Error() != "truncate fixture.txt: response error: " {
				t.Fatalf("Truncate = %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if tc.name == "defaults" {
				body, err := share.ReadFile("fixture.txt")
				if len(body) != 0 || err == nil || !strings.Contains(err.Error(), "connection error: EOF") {
					t.Fatalf("ReadFile = %q, %v", body, err)
				}
				return
			}
			if err := share.Umount(); err != nil {
				t.Fatal(err)
			}
			if err := s.Logoff(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
