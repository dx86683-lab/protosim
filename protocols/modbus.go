package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

var modbusDeviceInfo = []string{"Schneider Electric", "ATV630D22N4", "0204", "Device Info test"}

const (
	modbusMaxPDU    = 253
	modbusIOTimeout = 15 * time.Second
)

func init() {
	AddProtocol(NewProtocolInfo("modbus", newModbusHandler, 502),
		ProtocolParams{Name: "server_info", DefaultValue: modbusDeviceInfo})
}

type modbusCounters struct {
	mu       sync.Mutex
	messages uint16
	events   uint16
}

func newModbusHandler() func(*SessionConnection) error {
	return new(modbusCounters).serve
}

func (counters *modbusCounters) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	deviceInfo := session.GetStringsParams("server_info", modbusDeviceInfo)
	reader := bufio.NewReader(session.Conn)
	var history modbusEventHistory
	for {
		// Allow time between requests, and bound each frame once its first byte arrives.
		if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		if _, err := reader.Peek(1); err != nil {
			return err
		}
		if err := session.Conn.SetReadDeadline(time.Now().Add(modbusIOTimeout)); err != nil {
			return err
		}
		var header [7]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint16(header[4:6])
		if binary.BigEndian.Uint16(header[2:4]) != 0 || length < 2 || length > modbusMaxPDU+1 {
			return errors.New("invalid Modbus TCP frame")
		}
		request := make([]byte, length-1)
		if _, err := io.ReadFull(reader, request); err != nil {
			return err
		}

		reply := counters.reply(request, deviceInfo, &history)
		if len(reply) == 0 {
			continue
		}
		binary.BigEndian.PutUint16(header[4:6], uint16(len(reply)+1))
		if err := session.Conn.SetWriteDeadline(time.Now().Add(modbusIOTimeout)); err != nil {
			return err
		}
		if _, err := session.Conn.Write(append(header[:], reply...)); err != nil {
			return err
		}
	}
}

type modbusEventHistory struct {
	events [64]byte
	next   int
	size   int
}

func (history *modbusEventHistory) record(event byte) {
	history.events[history.next] = event
	history.next = (history.next + 1) % len(history.events)
	history.size = min(history.size+1, len(history.events))
}

func (history *modbusEventHistory) appendNewestFirst(reply []byte) []byte {
	index := history.next
	for range history.size {
		index = (index + len(history.events) - 1) % len(history.events)
		reply = append(reply, history.events[index])
	}
	return reply
}

func (counters *modbusCounters) reply(request []byte, info []string, history *modbusEventHistory) []byte {
	history.record(0x80) // Receive event.
	counters.mu.Lock()
	defer counters.mu.Unlock()
	counters.messages++

	var reply []byte
	switch {
	case len(request) == 1 && request[0] == 0x0b:
		reply = binary.BigEndian.AppendUint16([]byte{0x0b, 0, 0}, counters.events)
	case len(request) == 1 && request[0] == 0x0c:
		reply = []byte{0x0c, byte(6 + history.size), 0, 0}
		reply = binary.BigEndian.AppendUint16(reply, counters.events)
		reply = binary.BigEndian.AppendUint16(reply, counters.messages)
		reply = history.appendNewestFirst(reply)
	default:
		reply = modbusReply(request, info)
	}
	if len(reply) == 0 {
		return nil
	}
	if reply[0]&0x80 != 0 {
		if len(reply) == 2 && reply[1] == 4 {
			history.record(0x42) // Send event with a device failure.
		} else {
			history.record(0x41) // Send event with a read exception.
		}
	} else {
		history.record(0x40) // Send event.
		counters.events++
	}
	return reply
}

func modbusReply(request []byte, info []string) []byte {
	switch request[0] {
	case 1, 2, 3, 4:
		if len(request) != 5 {
			return []byte{request[0] | 0x80, 1}
		}
		address := int(binary.BigEndian.Uint16(request[1:3]))
		count := int(binary.BigEndian.Uint16(request[3:5]))
		return modbusReadValues(request[0], address, count)
	case 7:
		if len(request) == 1 {
			return []byte{7, 0}
		}
	case 0x11:
		if len(request) == 1 {
			return append(append([]byte{0x11, 12}, "Unit server"...), 0xff)
		}
	case 0x14:
		return modbusReadFileRecords(request)
	case 0x18:
		if len(request) == 3 {
			if binary.BigEndian.Uint16(request[1:]) >= 15 {
				return nil
			}
			return []byte{0x18, 0, 2, 0, 0}
		}
	case 0x2b:
		if len(request) == 4 && request[1] == 0x0e {
			return modbusIdentification(request[2], request[3], info)
		}
		return []byte{0xab, 3}
	}
	return []byte{request[0] | 0x80, 1}
}

func modbusReadFileRecords(request []byte) []byte {
	const descriptorSize = 7
	if len(request) < 2 || (len(request)-2)%descriptorSize != 0 {
		return []byte{0x94, 4}
	}
	records := request[2:]
	if int(request[1]) != len(records) {
		return []byte{0x94, 3}
	}

	count := 1
	reply := make([]byte, 2, 2+2*(len(records)/descriptorSize))
	reply[0] = 0x14
	for len(records) > 0 {
		record := records[:descriptorSize]
		records = records[descriptorSize:]
		if record[0] != 6 {
			return []byte{0x94, 3}
		}
		if binary.BigEndian.Uint16(record[1:3]) > 3 {
			return []byte{0x94, 2}
		}
		count += 2 + 2*int(binary.BigEndian.Uint16(record[5:7]))
		if count > modbusMaxPDU {
			return []byte{0x94, 1}
		}
		// ProtoSim counts the requested words and emits only an empty descriptor.
		reply = append(reply, 1, 6)
	}
	reply[1] = byte(count)
	return reply
}

func modbusReadValues(function byte, address, count int) []byte {
	limit := 50
	if function >= 3 {
		limit = 10
	}
	if count == 0 || address+count > limit {
		return nil
	}
	if function >= 3 {
		size := 2 * count
		reply := make([]byte, 2+size)
		reply[0], reply[1] = function, byte(size)
		if function == 4 {
			// The reference stores the address as a little-endian input register.
			for i := range count {
				binary.LittleEndian.PutUint16(reply[2+i*2:], uint16(address+i))
			}
		}
		return reply
	}
	size := (count + 7) / 8
	reply := make([]byte, 2+size)
	reply[0], reply[1] = function, byte(size)
	if function == 2 {
		for i := range count {
			if (address+i)%4 >= 2 {
				reply[2+i/8] |= 1 << (i % 8)
			}
		}
	}
	return reply
}

func modbusIdentification(access, first byte, info []string) []byte {
	var end int
	switch access {
	case 1: // Basic identification enumerates the three standard objects.
		end = min(len(info), 3)
	case 2: // Regular identification starts at the first optional object.
		if first >= 3 {
			end = min(len(info), 7)
		}
	case 4: // Individual access covers the basic and regular objects.
		end = min(len(info), int(first)+1, 7)
	}
	if int(first) >= end {
		return []byte{0xab, 3}
	}
	conformity := byte(0x81)
	if len(info) > 7 {
		conformity = 0x83
	} else if len(info) > 3 {
		conformity = 0x82
	}
	reply := []byte{0x2b, 0x0e, access, conformity, 0, 0, 0}
	remaining := modbusMaxPDU - len(reply)
	for id := int(first); id < end; id++ {
		value := info[id]
		cost := len(value) + 2
		if cost > remaining {
			reply[4], reply[5] = 0xff, byte(id)
			break
		}
		remaining -= cost
		reply = append(reply, byte(id), byte(len(value)))
		reply = append(reply, value...)
		reply[6]++
	}
	return reply
}
