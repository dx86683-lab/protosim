package protocols

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

const (
	smbTreeConnect    = 3
	smbTreeDisconnect = 4
	smbCreate         = 5
	smbClose          = 6
	smbFlush          = 7
	smbRead           = 8
	smbWrite          = 9
	smbIoctl          = 11
	smbQueryDirectory = 14
	smbQueryInfo      = 16
	smbSetInfo        = 17
	smbTreeDeleted    = 0xc00000c9
	smbFileClosed     = 0xc0000128
	smbResourceLimit  = 0xc000009a
	smbFixtureError   = 0xffffffff
	smbPipeTransceive = 0x0011c017
	smbTreeLimit      = 64
	smbTreeOpenLimit  = 256
)

type smbTree struct {
	ipc   bool
	files map[[16]byte]*smbOpen
}

type smbOpen struct {
	pipe    bool
	bound   bool
	context uint16
}

var smbInheritedFileID = [16]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func (s *smbSession) shareCommand(wire []byte, command uint16, treeID uint32, chain *smbChain, related bool) ([]byte, bool) {
	le := binary.LittleEndian
	body := wire[smb2HeaderSize:]
	if command == smbTreeConnect {
		reply := s.connectTree(wire, body)
		if le.Uint32(reply[4+8:]) == 0 {
			chain.tree = le.Uint32(reply[4+36:])
		}
		return reply, false
	}
	tree := s.trees[treeID]
	if tree == nil {
		return s.reply(wire, smbTreeDeleted, smbErrorBody()), false
	}
	if command == smbTreeDisconnect {
		if len(body) < 4 || le.Uint16(body) != 4 {
			return s.reply(wire, smbInvalidParameter, smbErrorBody()), false
		}
		delete(s.trees, treeID)
		return s.reply(wire, 0, []byte{4, 0, 0, 0}), false
	}
	if command == smbCreate {
		payload, status := tree.create(wire, body)
		if status == 0 {
			copy(chain.file[:], payload[64:80])
		}
		return s.reply(wire, status, payload), false
	}
	payload, status, closeAfter := tree.fileCommand(wire, body, command, s.shares, chain, related)
	if closeAfter {
		return nil, true
	}
	return s.reply(wire, status, payload), false
}

func (s *smbSession) connectTree(wire, body []byte) []byte {
	le := binary.LittleEndian
	if len(body) < 8 || le.Uint16(body) != 9 {
		return s.reply(wire, smbInvalidParameter, smbErrorBody())
	}
	path := smbBuffer(wire, uint32(le.Uint16(body[4:])), uint32(le.Uint16(body[6:])), 8)
	if len(path) == 0 || len(path)%2 != 0 {
		return s.reply(wire, smbInvalidParameter, smbErrorBody())
	}
	unc, ok := strings.CutPrefix(smbDecodeUTF16(path), `\\`)
	host, share, separator := strings.Cut(unc, `\`)
	if !ok || !separator || host == "" || share == "" || strings.ContainsAny(share, "\\\x00") {
		return s.reply(wire, smbInvalidParameter, smbErrorBody())
	}
	if len(s.trees) >= smbTreeLimit {
		return s.reply(wire, smbResourceLimit, smbErrorBody())
	}
	if s.trees == nil {
		s.trees = make(map[uint32]*smbTree)
	}
	var id [4]byte
	for {
		rand.Read(id[:])
		treeID := le.Uint32(id[:])
		if treeID != 0 && s.trees[treeID] == nil {
			s.trees[treeID] = &smbTree{ipc: strings.EqualFold(share, "IPC$")}
			// The reference reports pipe share type even for disk share names.
			reply := []byte{16, 0, 2, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0xa9, 0, 0x1f, 0}
			return s.treeReply(wire, 0, reply, treeID)
		}
	}
}

func (t *smbTree) create(wire, body []byte) ([]byte, uint32) {
	le := binary.LittleEndian
	if len(body) < 56 || le.Uint16(body) != 57 {
		return smbErrorBody(), smbInvalidParameter
	}
	nameLength := uint32(le.Uint16(body[46:]))
	name := smbBuffer(wire, uint32(le.Uint16(body[44:])), nameLength, 56)
	if nameLength != uint32(len(name)) || nameLength%2 != 0 {
		return smbErrorBody(), smbInvalidParameter
	}
	if len(t.files) >= smbTreeOpenLimit {
		return smbErrorBody(), smbResourceLimit
	}
	if t.files == nil {
		t.files = make(map[[16]byte]*smbOpen)
	}
	var id [16]byte
	copy(id[8:], "00000000")
	for {
		rand.Read(id[:8])
		if t.files[id] == nil {
			break
		}
	}
	pipe := t.ipc && strings.EqualFold(strings.TrimLeft(smbDecodeUTF16(name), `\`), "srvsvc")
	t.files[id] = &smbOpen{pipe: pipe}
	reply := make([]byte, 88)
	le.PutUint16(reply, 89)
	copy(reply[64:80], id[:])
	le.PutUint32(reply[80:], 88)
	return reply, 0
}

func (t *smbTree) fileCommand(wire, body []byte, command uint16, shares []string, chain *smbChain, related bool) ([]byte, uint32, bool) {
	le := binary.LittleEndian
	var size, idOffset int
	switch command {
	case smbClose, smbFlush:
		size, idOffset = 24, 8
	case smbQueryDirectory:
		size, idOffset = 33, 8
	case smbQueryInfo:
		size, idOffset = 41, 24
	case smbSetInfo:
		size, idOffset = 33, 16
	case smbRead, smbWrite:
		size, idOffset = 49, 16
	case smbIoctl:
		size, idOffset = 57, 8
	}
	if len(body) < size-size%2 || int(le.Uint16(body)) != size {
		return smbErrorBody(), smbInvalidParameter, false
	}
	id := [16]byte(body[idOffset : idOffset+16])
	if related && id == smbInheritedFileID {
		id = chain.file
	}
	open := t.files[id]
	if open == nil {
		return smbErrorBody(), smbFileClosed, false
	}
	chain.file = id
	switch command {
	case smbClose:
		delete(t.files, id)
		reply := make([]byte, 60)
		le.PutUint16(reply, 60)
		return reply, 0, false
	case smbFlush, smbQueryDirectory, smbSetInfo:
		return []byte{9, 0, 0, 0, 0, 0, 0, 0}, smbFixtureError, false
	case smbQueryInfo:
		return []byte{9, 0, 0, 0, 0, 0, 0, 0}, 0, false
	case smbRead:
		return nil, 0, true
	case smbWrite:
		count := le.Uint32(body[4:])
		data := smbBuffer(wire, uint32(le.Uint16(body[2:])), count, 48)
		if uint32(len(data)) != count {
			return smbErrorBody(), smbInvalidParameter, false
		}
		reply := make([]byte, 16)
		le.PutUint16(reply, 17)
		le.PutUint32(reply[4:], count)
		return reply, 0, false
	case smbIoctl:
		reply, status := open.ioctl(wire, body, shares)
		return reply, status, false
	}
	return smbErrorBody(), smbNotSupported, false
}

func smbBuffer(wire []byte, offset, size uint32, fixedSize int) []byte {
	if size == 0 || offset < uint32(smb2HeaderSize+fixedSize) ||
		offset > uint32(len(wire)) || size > uint32(len(wire))-offset {
		return nil
	}
	return wire[offset : offset+size]
}
