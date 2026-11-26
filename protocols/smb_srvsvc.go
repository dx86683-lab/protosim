package protocols

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"strings"
)

var smbSRVSVCSyntax = [...]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
	3, 0, 0, 0,
}

func (o *smbOpen) ioctl(wire, body []byte, shares []string) ([]byte, uint32) {
	le := binary.LittleEndian
	if !o.pipe || le.Uint32(body[4:]) != smbPipeTransceive {
		return smbErrorBody(), smbNotSupported
	}
	request := smbBuffer(wire, le.Uint32(body[24:]), le.Uint32(body[28:]), 56)
	response := o.srvsvc(request, shares)
	if response == nil {
		return smbErrorBody(), smbInvalidParameter
	}
	const fixedSize = 48
	reply := make([]byte, fixedSize, fixedSize+len(response))
	le.PutUint16(reply, fixedSize+1)
	copy(reply[4:24], body[4:24])
	le.PutUint32(reply[24:], smb2HeaderSize+fixedSize)
	le.PutUint32(reply[32:], smb2HeaderSize+fixedSize)
	le.PutUint32(reply[36:], uint32(len(response)))
	return append(reply, response...), 0
}

func (o *smbOpen) srvsvc(request []byte, shares []string) []byte {
	le := binary.LittleEndian
	if len(request) < dceHeaderSize || request[0] != 5 || request[1] != 0 ||
		request[3]&dceSingleFrame != dceSingleFrame || !bytes.Equal(request[4:8], []byte{0x10, 0, 0, 0}) ||
		int(le.Uint16(request[8:])) != len(request) || le.Uint16(request[10:]) != 0 {
		return nil
	}
	body := request[dceHeaderSize:]
	var response []byte
	var packetType byte
	switch request[2] {
	case dceBind:
		if len(body) < 56 || body[8] != 1 || !bytes.Equal(body[16:36], smbSRVSVCSyntax[:]) {
			return nil
		}
		var association [4]byte
		rand.Read(association[:])
		response = dceBindResult(body, association, `\PIPE\srvsvc`)
		if response == nil {
			return nil
		}
		o.context = le.Uint16(body[12:])
		// The last result contains the accepted transfer syntax for this context.
		o.bound = bytes.Equal(response[len(response)-len(dceNDR):], dceNDR[:])
		packetType = dceBindAck
	case 0: // Request PDU.
		if !o.bound || len(body) < 8 || le.Uint16(body[4:]) != o.context {
			return nil
		}
		stub := body[8:]
		if le.Uint32(body) != uint32(len(stub)) {
			return nil
		}
		serverEnd := smbNDRUniqueStringEnd(stub)
		if serverEnd == 0 {
			return nil
		}
		stub = stub[serverEnd:]
		op := le.Uint16(body[6:])
		if op != 15 {
			if smbSRVEmptyQuery(op, stub) {
				return []byte{}
			}
			return nil
		}
		// NetrShareEnum returns the measured level 1 inventory.
		if !smbSRVHasLevel(stub, 28, 0, 1, 2, 501, 502, 503) {
			return nil
		}
		response = smbShareEnum(shares, o.context)
		if response == nil {
			return nil
		}
		packetType = 2 // Response PDU.
	default:
		return nil
	}
	reply := append([]byte{}, request[:dceHeaderSize]...)
	reply[2] = packetType
	le.PutUint16(reply[8:], uint16(dceHeaderSize+len(response)))
	return append(reply, response...)
}

func smbNDRUniqueStringEnd(stub []byte) int {
	le := binary.LittleEndian
	if len(stub) < 4 {
		return 0
	}
	if le.Uint32(stub) == 0 {
		return 4
	}
	if end := smbNDRStringEnd(stub[4:]); end != 0 {
		return 4 + end
	}
	return 0
}

func smbNDRStringEnd(data []byte) int {
	if len(data) < 12 {
		return 0
	}
	count := binary.LittleEndian.Uint32(data[8:])
	if count > uint32((len(data)-12)/2) {
		return 0
	}
	end := (12 + int(count)*2 + 3) &^ 3
	if end > len(data) {
		return 0
	}
	return end
}

// These read-only calls receive IOCTL success with an empty RPC payload in the reference.
func smbSRVEmptyQuery(op uint16, stub []byte) bool {
	switch op {
	case 8: // NetrConnectionEnum
		return smbSRVListLevel(stub, 1, 0, 1)
	case 9: // NetrFileEnum
		return smbSRVListLevel(stub, 2, 2, 3)
	case 12: // NetrSessionEnum
		return smbSRVListLevel(stub, 2, 0, 1, 2, 10, 502)
	case 16: // NetrShareGetInfo
		end := smbNDRStringEnd(stub)
		return end != 0 && smbSRVHasLevel(stub[end:], 4, 0, 1, 2, 501, 502, 503, 1005)
	case 21: // NetrServerGetInfo
		return smbSRVHasLevel(stub, 4, 100, 101, 102, 502, 503)
	default:
		return false
	}
}

func smbSRVListLevel(stub []byte, qualifiers int, levels ...uint32) bool {
	for range qualifiers {
		end := smbNDRUniqueStringEnd(stub)
		if end == 0 {
			return false
		}
		stub = stub[end:]
	}
	return smbSRVHasLevel(stub, 28, levels...)
}

func smbSRVHasLevel(stub []byte, minSize int, levels ...uint32) bool {
	return len(stub) >= minSize && slices.Contains(levels, binary.LittleEndian.Uint32(stub))
}

func smbShareEnum(shares []string, context uint16) []byte {
	const maxStubSize = 65535 - smb2HeaderSize - 48 - dceHeaderSize
	le := binary.LittleEndian
	if len(shares) > maxStubSize/12 {
		return nil
	}
	count := uint32(len(shares))
	reply := make([]byte, 8)
	le.PutUint16(reply[4:], context)
	for _, field := range [...]uint32{1, 1, 0x2000c, count, 0x20010, count} {
		reply = le.AppendUint32(reply, field)
	}
	const firstReferent = 0x20014
	for i := range shares {
		name := uint32(firstReferent + 8*i)
		reply = le.AppendUint32(reply, name)
		reply = le.AppendUint32(reply, 0) // Disk share type.
		reply = le.AppendUint32(reply, name+4)
	}
	for _, share := range shares {
		name, comment, _ := strings.Cut(share, ":")
		reply = smbNDRString(reply, name)
		reply = smbNDRString(reply, comment)
		if len(reply)+16 > maxStubSize {
			return nil
		}
	}
	for _, field := range [...]uint32{count, firstReferent + count*8, 0, 0} {
		reply = le.AppendUint32(reply, field)
	}
	le.PutUint32(reply, uint32(len(reply)-8))
	return reply
}

func smbNDRString(reply []byte, value string) []byte {
	le := binary.LittleEndian
	data := smbUTF16(value)
	count := uint32(len(data)/2 + 1)
	reply = le.AppendUint32(reply, count)
	reply = le.AppendUint32(reply, 0)
	reply = le.AppendUint32(reply, count)
	reply = append(reply, data...)
	reply = append(reply, 0, 0)
	if len(reply)%4 != 0 {
		reply = append(reply, 0, 0)
	}
	return reply
}
