package protocols

import (
	"encoding/hex"
	"net"
	"time"
)

const melsecqIOTimeout = 30 * time.Second

var MelsecqDiscover_cpuType = "Q13UDVCPU"

func init() {
	AddProtocol(NewProtocolInfo("melsecq-discover", MelsecqDiscover, 5007),
		ProtocolParams{Name: "cpu_type", DefaultValue: MelsecqDiscover_cpuType})
}

func MelsecqDiscover(lc *ListenConnection) error {
	// The reference catalogue advertises cpu_type, and the listener reads version.
	cpuType := lc.GetStringParams("version", MelsecqDiscover_cpuType)
	for {
		conn, err := lc.Listener.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = c.SetDeadline(time.Now().Add(melsecqIOTimeout))
			err := handleMelsecqConnection(c, cpuType, func(message string, fields map[string]interface{}) {
				lc.LogWithRemote(message, c.RemoteAddr(), fields)
			})
			lc.AddActivity(c.RemoteAddr(), true)
			if err != nil {
				lc.Log.WithError(err).Debug("MELSEC-Q connection ended")
			}
		}(conn)
	}
}

func handleMelsecqConnection(conn net.Conn, cpuType string, record func(string, map[string]interface{})) error {
	defer conn.Close()

	// The reference keeps the header fixed and appends ten spaces after the model.
	response := []byte("\xd7\x00I\x00\x00\x11\x11\x07\x00\x00\x00\xe4\x03\x00\xff\xff\x03\x00\x006\x00\x9c\x00\x0c\x08\x00\x00\x00\x00\x03\x04\x00\x00\x00\x00\x01\x01\x01\x00\x00\x00" +
		cpuType + "          A\x05\x00\x08\xba\xba$\x02\x01\x1451\x04 \x02\x00\x00\x00")

	// The reference replies once for each TCP read of at least 36 bytes.
	var buffer [1024]byte
	for {
		n, err := conn.Read(buffer[:])
		if n == 0 {
			return nil
		}
		payload := buffer[:n]
		if n < 36 {
			record("invalid packet", map[string]interface{}{
				"data": hex.EncodeToString(payload), "packet_len": n,
			})
			return nil
		}
		record("req command", melsecqFields(payload))
		if _, writeErr := conn.Write(response); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return nil
		}
	}
}

func melsecqFields(payload []byte) map[string]interface{} {
	header := hex.EncodeToString(payload[:1])
	access := hex.EncodeToString(payload[9:11])
	request := hex.EncodeToString(payload[11:13])
	command := hex.EncodeToString(payload[34:36])
	fields := map[string]interface{}{
		"header":       header,
		"frame_type":   melsecqDescription(header, "57", "DatatranslationRequest"),
		"access_type":  melsecqDescription(access, "00ff", "E71 Mounting Station (Local Station)"),
		"request_type": melsecqDescription(request, "ff03", "Request Target Module I/O Number"),
		"command":      command,
	}
	if label, ok := melsecqCommandNames[command]; ok {
		fields["command_type"] = label
	} else {
		fields["command_type"] = "Unknown(" + command + ")"
	}
	if len(payload) > 36 {
		fields["raw_data"] = hex.EncodeToString(payload[36:])
	}
	return fields
}

func melsecqDescription(value, known, description string) string {
	if value == known {
		return description
	}
	return "Unknown(" + value + ")"
}

var melsecqCommandNames = map[string]string{
	"0101": "[MCCPU Model Reading]",
	"1001": "[Remote RUN]",
	"1002": "[Remote STOP]",
	"1003": "[Remote PAUSE]",
	"1005": "[Remote Storage Removal]",
	"1006": "[Remote RESET]",
}
