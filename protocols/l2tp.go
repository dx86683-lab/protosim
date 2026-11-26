package protocols

import "encoding/binary"

const l2tpControlV2 = 0xc802

func init() {
	AddProtocol(NewProtocolInfo("l2tp", serveL2TP, 1701),
		ProtocolParams{Name: "vendor_id", DefaultValue: 8691},
		ProtocolParams{Name: "host_name", DefaultValue: "DrayTek"},
		ProtocolParams{Name: "vendor_name", DefaultValue: "DrayTek, l2tp"})
}

func serveL2TP(conn *UDPConnection, request []byte) error {
	// Only answer a Start-Control-Connection-Request to the simulator.
	if len(request) < 20 || len(request) > 1024 ||
		binary.BigEndian.Uint16(request[:2]) != l2tpControlV2 ||
		int(binary.BigEndian.Uint16(request[2:4])) != len(request) ||
		binary.BigEndian.Uint32(request[4:8]) != 0 ||
		binary.BigEndian.Uint16(request[12:14]) != 0x8008 ||
		binary.BigEndian.Uint32(request[14:18]) != 0 ||
		binary.BigEndian.Uint16(request[18:20]) != 1 {
		return nil
	}

	host := conn.GetStringParams("host_name", "")
	if host == "" {
		host = conn.GetStringParams("hostname", "DrayTek")
	}
	vendor := conn.GetStringParams("vendor_name", "DrayTek, l2tp")
	if len(host) > 64 || len(vendor) > 64 {
		return nil
	}
	reply := make([]byte, 12)
	binary.BigEndian.PutUint16(reply[:2], l2tpControlV2)
	binary.BigEndian.PutUint16(reply[10:12], binary.BigEndian.Uint16(request[8:10])+1)
	reply = appendL2TPAttribute(reply, 0x8000, 0, []byte{0, 2})
	reply = appendL2TPAttribute(reply, 0x8000, 2, []byte{1, 0})
	reply = appendL2TPAttribute(reply, 0x8000, 7, []byte(host))
	reply = appendL2TPAttribute(reply, 0, 8, []byte(vendor))
	reply = appendL2TPAttribute(reply, 0x8000, 3, []byte{0, 0, 0, 3})
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	_, err := conn.Write(reply)
	return err
}

func appendL2TPAttribute(packet []byte, flags, kind uint16, value []byte) []byte {
	packet = binary.BigEndian.AppendUint16(packet, flags|uint16(len(value)+6))
	packet = binary.BigEndian.AppendUint16(packet, 0)
	packet = binary.BigEndian.AppendUint16(packet, kind)
	return append(packet, value...)
}
