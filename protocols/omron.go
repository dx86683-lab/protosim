package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

const omronModel, omronFirmware = "CP1L-EM30DR-D", "01.60"

var omronRequestFields = [...]string{
	"Icf", "Reserved", "GatewayCount", "DestNetwork", "DestNodeNumber", "DestUnitAddr",
	"SrcNetwork", "SrcNodeNumber", "SrcUnitAddr", "SrvId", "Code", "Code",
}

var omronReadCommands = map[uint16]string{
	0x0101: "MEMORY_AREA_READ",
	0x0201: "PARAMETER_AREA_READ",
	0x0501: "CONTROLLER_DATA_READ",
	0x0502: "CONNECTION_DATA_READ",
	0x0601: "CONTROLLER_STATUS_READ",
	0x0701: "CLOCK_READ",
	0x2102: "ERROR_LOG_READ",
}

func init() {
	AddProtocol(NewProtocolInfo("omron", serveOmron, 9600),
		ProtocolParams{Name: "mode", DefaultValue: omronModel},
		ProtocolParams{Name: "version", DefaultValue: omronFirmware},
		ProtocolParams{Name: "prog_area_size", DefaultValue: 20},
		ProtocolParams{Name: "dm_size", DefaultValue: 0})
}

func serveOmron(conn *UDPConnection, request []byte) error {
	if len(request) == 0 {
		return nil
	}
	if len(request) < len(omronRequestFields) {
		err := io.EOF
		if len(request) == 11 {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read field %s: %w", omronRequestFields[len(request)], err)
	}
	code := binary.BigEndian.Uint16(request[10:12])
	command, known := omronReadCommands[code]
	if !known {
		command = fmt.Sprintf("UNKNOWN_Code%d", code)
	}
	logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "message", logrus.Fields{
		"icf": request[0], "gateway_count": request[2], "dest_node_num": request[4],
		"src_node_num": request[7], "service_id": request[9], "command": command,
	})
	model := conn.GetStringParams("mode", omronModel)
	firmware := conn.GetStringParams("version", omronFirmware)
	programSize, dataMemory := conn.GetIntParams("prog_area_size", 20), conn.GetIntParams("dm_size", 0)
	var reply [106]byte
	reply[0], reply[2] = 0xc0, request[2]
	copy(reply[3:6], request[6:9])
	copy(reply[6:9], request[3:6])
	reply[9], reply[10], reply[11] = request[9], 0x05, 0x01
	copy(reply[14:34], bytes.Repeat([]byte{' '}, 20))
	copy(reply[14:34], model)
	copy(reply[34:44], firmware)
	copy(reply[44:54], firmware)
	// Controller area sizes and capability flags observed in the reference device profile.
	reply[55], reply[73] = 4, 1
	copy(reply[76:84], "\x80\x01\x80\x01\x80\x01\x80\x00")
	copy(reply[91:94], "\x01\x01\x01")
	binary.BigEndian.PutUint16(reply[94:96], uint16(programSize))
	copy(reply[96:100], "\x17\x80\x00\x08")
	reply[100] = byte(dataMemory)
	_, err := conn.Write(reply[:])
	return err
}
