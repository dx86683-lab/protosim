package protocols

import (
	"encoding/binary"
	"errors"

	"github.com/sirupsen/logrus"
)

const (
	bacnetDeviceName   = "Bacnet Device"
	bacnetInstanceMask = (1 << 22) - 1
	bacnetMaxText      = 4096
)

var bacnetStringProperties = []struct {
	id        byte
	key, text string
}{
	{121, "vender_name", "BACnet Stack at SourceForge"},
	{44, "firmware_ver", "0.9.1"},
	{12, "software_ver", "1.0"},
	{77, "object_name", bacnetDeviceName},
	{70, "model_name", bacnetDeviceName},
	{28, "description", "For bacnet stack"},
	{58, "location", "SE2-315"},
}

func init() {
	params := []ProtocolParams{
		{Name: "device_id", DefaultValue: 1234},
		{Name: "vender_id", DefaultValue: 260},
	}
	for _, property := range bacnetStringProperties {
		params = append(params, ProtocolParams{Name: property.key, DefaultValue: property.text})
	}
	AddProtocol(NewProtocolInfo("bacnet", serveBACnet, 47808), params...)
}

func serveBACnet(conn *UDPConnection, request []byte) error {
	pdu := bacnetAPDU(request)
	if len(pdu) < 2 {
		return nil
	}
	switch pdu[0] & 0xf0 {
	case 0x10:
		logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "unconfirmed_req", logrus.Fields{"type": pdu[1]})
	case 0:
		if len(pdu) >= 4 && pdu[0]&0x08 == 0 {
			logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "confirmed_req", logrus.Fields{"type": pdu[3]})
		}
	}
	device := uint32(conn.GetIntParams("device_id", 1234)) & bacnetInstanceMask
	vendor := uint32(conn.GetIntParams("vender_id", 260))
	object := 8<<22 | device
	reply := []byte{0x81, 0x0b, 0, 0, 1, 0}
	switch {
	case pdu[0] == 0x10 && pdu[1] == 8 && bacnetWhoIsRange(pdu[2:]):
		reply = append(reply, 0x10, 0, 0xc4)
		reply = binary.BigEndian.AppendUint32(reply, object)
		reply = append(reply, 0x22, 0x05, 0xc4, 0x91, 3)
		reply = appendBACnetUnsigned(reply, 0x20, vendor)
	case len(pdu) >= 11 && pdu[0]&0xf8 == 0 && pdu[3] == 0x0c && pdu[4] == 0x0c:
		id, tail, ok := bacnetTaggedUint(pdu[9:], 1)
		if !ok {
			return nil
		}
		if len(tail) != 0 {
			if _, rest, ok := bacnetTaggedUint(tail, 2); !ok || len(rest) != 0 {
				return nil
			}
		}
		reply = append(reply, 0x30, pdu[2], 0x0c)
		if id >= 1<<22 {
			break
		}
		// The simulated device answers for its configured identifier regardless of
		// the requested object and omits the optional array index from the reply.
		reply = binary.BigEndian.AppendUint32(append(reply, 0x0c), object)
		reply = appendBACnetUnsigned(reply, 0x18, id)
		reply = append(reply, 0x3e)
		valueOffset := len(reply)
		switch id {
		case 75:
			reply = binary.BigEndian.AppendUint32(append(reply, 0xc4), object)
		case 120:
			reply = appendBACnetUnsigned(reply, 0x20, vendor)
		default:
			for _, property := range bacnetStringProperties {
				if uint32(property.id) != id {
					continue
				}
				value := conn.GetStringParams(property.key, property.text)
				if len(value) > bacnetMaxText {
					return errors.New("simulated BACnet string exceeds limit")
				}
				reply = appendBACnetText(reply, value)
				break
			}
		}
		// ASHRAE 135 §20.2.1.3.2: close Context Tag 3 (propertyValue) with 0x3f.
		if len(reply) > valueOffset {
			reply = append(reply, 0x3f)
		}
	default:
		return nil
	}
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	_, err := conn.Write(reply)
	return err
}

func bacnetAPDU(wire []byte) []byte {
	if len(wire) < 8 || wire[0] != 0x81 || (wire[1] != 0x0a && wire[1] != 0x0b) ||
		int(binary.BigEndian.Uint16(wire[2:4])) != len(wire) || wire[4] != 1 || wire[5]&0x80 != 0 {
		return nil
	}
	control, pdu := wire[5], wire[6:]
	if control&0x20 != 0 {
		pdu = bacnetSkipAddress(pdu)
	}
	if control&0x08 != 0 {
		pdu = bacnetSkipAddress(pdu)
	}
	if control&0x20 != 0 && len(pdu) != 0 {
		pdu = pdu[1:] // Hop count follows any source and destination addresses.
	}
	return pdu
}

func bacnetSkipAddress(wire []byte) []byte {
	if len(wire) < 3 || int(wire[2]) > len(wire)-3 {
		return nil
	}
	return wire[3+int(wire[2]):]
}

func bacnetWhoIsRange(wire []byte) bool {
	if len(wire) == 0 {
		return true
	}
	low, rest, ok := bacnetTaggedUint(wire, 0)
	if !ok {
		return false
	}
	high, rest, ok := bacnetTaggedUint(rest, 1)
	// The reference handles a valid range like an unrestricted Who-Is.
	return ok && len(rest) == 0 && low <= high && high < 1<<22
}

func bacnetTaggedUint(wire []byte, tag byte) (uint32, []byte, bool) {
	if len(wire) == 0 || wire[0]&0xf8 != tag<<4|8 {
		return 0, nil, false
	}
	size := int(wire[0] & 7)
	if size < 1 || size > 4 || size >= len(wire) {
		return 0, nil, false
	}
	var value uint32
	for _, octet := range wire[1 : 1+size] {
		value = value<<8 | uint32(octet)
	}
	return value, wire[1+size:], true
}

func appendBACnetText(packet []byte, value string) []byte {
	length := len(value) + 1 // One octet for the character encoding.
	switch {
	case length <= 4:
		packet = append(packet, 0x70|byte(length))
	case length < 254:
		packet = append(packet, 0x75, byte(length))
	default:
		packet = binary.BigEndian.AppendUint16(append(packet, 0x75, 0xfe), uint16(length))
	}
	return append(append(packet, 0), value...)
}

func appendBACnetUnsigned(packet []byte, tag byte, value uint32) []byte {
	switch {
	case value <= 0xff:
		return append(packet, tag|1, byte(value))
	case value <= 0xffff:
		return binary.BigEndian.AppendUint16(append(packet, tag|2), uint16(value))
	case value <= 0xffffff:
		return append(packet, tag|3, byte(value>>16), byte(value>>8), byte(value))
	default:
		return binary.BigEndian.AppendUint32(append(packet, tag|4), value)
	}
}
