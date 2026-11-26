package protocols

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

const (
	smbSessionSetup     = 1
	smbLogoff           = 2
	smbEcho             = 13
	smbRelated          = 4
	smbSigned           = 8
	smbMoreProcessing   = 0xc0000016
	smbLogonFailure     = 0xc000006d
	smbInvalidParameter = 0xc000000d
	smbNotSupported     = 0xc00000bb
	smbSessionDeleted   = 0xc0000203
	smbAccessDenied     = 0xc0000022
)

type smbSession struct {
	server, domain string
	accounts       []string
	shares         []string
	trees          map[uint32]*smbTree
	id             uint64
	ntlm           smbNTLM
	key            []byte
	requireSigning bool
}

type smbChain struct {
	tree uint32
	file [16]byte
}

func (s *smbSession) handleRecord(wire []byte, writer io.Writer) (bool, error) {
	requests := smbRecordRequests(wire)
	if len(requests) == 0 || len(requests) > 1 && len(s.key) == 0 {
		return true, nil
	}
	var chain smbChain
	for _, request := range requests {
		reply, closeAfter := s.handle(request, &chain)
		if reply != nil {
			if _, err := writer.Write(reply); err != nil {
				return true, err
			}
		}
		if closeAfter {
			return true, nil
		}
	}
	return false, nil
}

func smbRecordRequests(wire []byte) [][]byte {
	le := binary.LittleEndian
	var requests [][]byte
	var related bool
	for {
		if len(wire) < smb2HeaderSize || string(wire[:4]) != "\xfeSMB" ||
			le.Uint16(wire[4:]) != smb2HeaderSize || le.Uint32(wire[16:])&3 != 0 {
			return nil
		}
		currentRelated := le.Uint32(wire[16:])&smbRelated != 0
		switch len(requests) {
		case 0:
			if currentRelated {
				return nil
			}
		case 1:
			related = currentRelated
		default:
			if related != currentRelated {
				return nil
			}
		}
		next := int(le.Uint32(wire[20:]))
		if next == 0 {
			return append(requests, wire)
		}
		if next < smb2HeaderSize || next%8 != 0 || next > len(wire)-smb2HeaderSize {
			return nil
		}
		requests = append(requests, wire[:next])
		wire = wire[next:]
	}
}

func (s *smbSession) handle(wire []byte, chain *smbChain) (reply []byte, closeAfter bool) {
	le := binary.LittleEndian
	command := le.Uint16(wire[12:])
	sessionID := le.Uint64(wire[40:])
	treeID := le.Uint32(wire[36:])
	related := le.Uint32(wire[16:])&smbRelated != 0
	if !related {
		*chain = smbChain{tree: treeID}
	} else {
		if sessionID == ^uint64(0) {
			sessionID = s.id
		}
		if treeID == ^uint32(0) {
			treeID = chain.tree
		}
	}
	if command == smbSessionSetup && len(s.key) == 0 {
		return s.setup(wire)
	}
	if sessionID == 0 || sessionID != s.id || len(s.key) == 0 {
		return s.reply(wire, smbSessionDeleted, smbErrorBody()), true
	}
	signed := le.Uint32(wire[16:])&smbSigned != 0
	if signed && !s.validSignature(wire) || !signed && s.requireSigning {
		return s.reply(wire, smbAccessDenied, smbErrorBody()), true
	}
	switch command {
	case smbLogoff, smbEcho:
		if len(wire) < smb2HeaderSize+4 || le.Uint16(wire[smb2HeaderSize:]) != 4 {
			return s.reply(wire, smbInvalidParameter, smbErrorBody()), true
		}
		reply := s.reply(wire, 0, []byte{4, 0, 0, 0})
		if command == smbLogoff {
			s.key, s.trees, s.id, s.requireSigning = nil, nil, 0, false
		}
		return reply, false
	case smbTreeConnect, smbTreeDisconnect, smbCreate, smbClose, smbFlush, smbRead, smbWrite, smbIoctl,
		smbQueryDirectory, smbQueryInfo, smbSetInfo:
		return s.shareCommand(wire, command, treeID, chain, related)
	default:
		return s.reply(wire, smbNotSupported, smbErrorBody()), false
	}
}

func (s *smbSession) setup(wire []byte) ([]byte, bool) {
	le := binary.LittleEndian
	body := wire[smb2HeaderSize:]
	if len(body) < 24 || le.Uint16(body) != 25 || body[2] != 0 {
		return s.reply(wire, smbInvalidParameter, smbErrorBody()), true
	}
	offset, size := int(le.Uint16(body[12:])), int(le.Uint16(body[14:]))
	if offset < smb2HeaderSize+24 || offset > len(wire) || size > len(wire)-offset {
		return s.reply(wire, smbInvalidParameter, smbErrorBody()), true
	}
	failed := []byte{0xa1, 2, 0x30, 0}
	if s.id == 0 {
		if le.Uint64(wire[40:]) != 0 {
			return s.reply(wire, smbSessionDeleted, smbErrorBody()), true
		}
		token := s.ntlm.begin(wire[offset:offset+size], s.server, s.domain)
		if token == nil {
			return s.reply(wire, smbLogonFailure, smbSetupBody(failed)), true
		}
		var id [8]byte
		rand.Read(id[:])
		s.id = max(le.Uint64(id[:]), 1)
		s.requireSigning = body[3]&2 != 0
		return s.reply(wire, smbMoreProcessing, smbSetupBody(token)), false
	}
	if le.Uint64(wire[40:]) != s.id {
		return s.reply(wire, smbSessionDeleted, smbErrorBody()), true
	}
	key := s.ntlm.authenticate(wire[offset:offset+size], s.accounts)
	if key == nil {
		return s.reply(wire, smbLogonFailure, smbSetupBody(failed)), true
	}
	accepted := []byte{0xa1, 7, 0x30, 5, 0xa0, 3, 0x0a, 1, 0}
	if s.requireSigning {
		s.key = key
	}
	reply := s.reply(wire, 0, smbSetupBody(accepted))
	s.key = key
	s.ntlm = smbNTLM{}
	return reply, false
}

func smbSetupBody(token []byte) []byte {
	body := make([]byte, 8, 8+len(token))
	le := binary.LittleEndian
	le.PutUint16(body, 9)
	le.PutUint16(body[4:], smb2HeaderSize+8)
	le.PutUint16(body[6:], uint16(len(token)))
	return append(body, token...)
}

func smbErrorBody() []byte {
	return []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}
}

func (s *smbSession) reply(request []byte, status uint32, body []byte) []byte {
	return s.treeReply(request, status, body, binary.LittleEndian.Uint32(request[36:]))
}

func (s *smbSession) treeReply(request []byte, status uint32, body []byte, treeID uint32) []byte {
	packet := make([]byte, 4+smb2HeaderSize+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(packet)-4))
	le := binary.LittleEndian
	wire := packet[4:]
	copy(wire, "\xfeSMB")
	le.PutUint16(wire[4:], smb2HeaderSize)
	le.PutUint32(wire[8:], status)
	copy(wire[12:14], request[12:14])
	le.PutUint16(wire[14:], 1)
	le.PutUint32(wire[16:], 1)
	copy(wire[24:32], request[24:32])
	le.PutUint32(wire[36:], treeID)
	sessionID := s.id
	requestFlags := le.Uint32(request[16:])
	if requestFlags&smbRelated != 0 {
		sessionID = le.Uint64(request[40:])
	}
	le.PutUint64(wire[40:], sessionID)
	copy(wire[smb2HeaderSize:], body)
	if len(s.key) != 0 && (s.requireSigning || requestFlags&smbSigned != 0) {
		le.PutUint32(wire[16:], 1|smbSigned)
		copy(wire[48:64], s.signature(wire))
	}
	return packet
}

func (s *smbSession) signature(wire []byte) []byte {
	var zero [16]byte
	mac := hmac.New(sha256.New, s.key)
	mac.Write(wire[:48])
	mac.Write(zero[:])
	mac.Write(wire[64:])
	return mac.Sum(nil)[:16]
}

func (s *smbSession) validSignature(wire []byte) bool {
	return hmac.Equal(wire[48:64], s.signature(wire))
}
