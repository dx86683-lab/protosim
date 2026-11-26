package protocols

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var portmapDefaultTable = []string{
	"100000,4,tcp,111", "100000,3,tcp,111", "100000,2,tcp,111",
	"100000,4,udp,111", "100000,3,udp,111", "100000,2,udp,111",
}

var errPortmapIncompleteMapping = errors.New("[PORTMAP] incomplete mapping row.")

const (
	portmapProgram        = 100000
	portmapVersion        = 2
	rpcbindVersion3       = 3
	rpcbindVersion4       = 4
	portmapTCP            = 6
	portmapUDP            = 17
	PortmapMaxRequestSize = 4096
)

type portmapMapping struct {
	program, version, protocol, port uint32
}

func init() {
	info := NewProtocolInfo("portmap", servePortmap, 111)
	info.DatagramHandler = newPortmapDatagramHandler
	AddProtocol(info,
		ProtocolParams{Name: "mapping_table", DefaultValue: portmapDefaultTable})
}

func servePortmap(session *SessionConnection) error {
	defer session.DeleteActivity()
	mappings, err := parsePortmapMappings(session.Params)
	if deadlineErr := session.Conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
		return deadlineErr
	}
	if err != nil {
		if session.Log != nil && !errors.Is(err, errPortmapIncompleteMapping) {
			session.Log.Errorf("handler error:%s", err)
		}
		// Drain the connection without dispatching calls under invalid mappings.
		session.drainIgnoredInput(session.Conn)
		return nil
	}
	dumpBody := portmapDumpBody(mappings)
	reader := bufio.NewReader(session.Conn)
	for {
		request, err := readRPCRecord(reader, PortmapMaxRequestSize)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(request) < 8 {
			return errors.New("short RPC call")
		}
		remote := session.Conn.RemoteAddr()
		if binary.BigEndian.Uint32(request[4:8]) != 0 {
			logSessionEvent(session.ConfigInfo, remote, "Invalid RPC message type received", nil)
			return nil
		}
		if len(request) < 12 {
			return errors.New("short RPC call")
		}
		wire, dump := portmapReply(request, mappings, dumpBody, session.Conn.LocalAddr(), portmapTCP)
		if wire == nil {
			continue
		}
		if dump {
			logSessionEvent(session.ConfigInfo, remote, "proc", logrus.Fields{"cmd": "dump"})
		}
		if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		n, err := session.Conn.Write(wire)
		if err != nil {
			return err
		}
		if n != len(wire) {
			return io.ErrShortWrite
		}
	}
}

func newPortmapDatagramHandler(bind *BindInfo) UDPFunction {
	mappings, configErr := parsePortmapMappings(bind.Params)
	dumpBody := portmapDumpBody(mappings)
	return func(conn *UDPConnection, request []byte) error {
		if configErr != nil || len(request) < 12 || len(request) > PortmapMaxRequestSize ||
			binary.BigEndian.Uint32(request[4:]) != 0 {
			return nil
		}
		reply, dump := portmapReply(request, mappings, dumpBody, conn.LocalAddr(), portmapUDP)
		if reply == nil {
			return nil
		}
		if dump {
			logSessionEvent(conn.ConfigInfo, conn.RemoteAddr(), "proc", logrus.Fields{"cmd": "dump"})
		}
		// RPC record marking is used by TCP. UDP carries the message directly.
		payload := reply[4:]
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			return io.ErrShortWrite
		}
		return err
	}
}

func portmapReply(request []byte, mappings []portmapMapping, dumpBody []byte, local net.Addr, protocol uint32) ([]byte, bool) {
	xid := binary.BigEndian.Uint32(request)
	if binary.BigEndian.Uint32(request[8:]) != 2 {
		return rpcDeniedReply(xid, 0, 2, 2), false // RPC_MISMATCH
	}
	if len(request) < 24 {
		return nil, false
	}
	args, authStatus := rpcCallArguments(request[24:])
	if authStatus != 0 {
		return rpcDeniedReply(xid, 1, authStatus), false // AUTH_ERROR
	}
	if binary.BigEndian.Uint32(request[12:]) != portmapProgram {
		return rpcAcceptedReply(xid, 1, nil), false // PROG_UNAVAIL
	}
	version := binary.BigEndian.Uint32(request[16:])
	procedure := binary.BigEndian.Uint32(request[20:])
	if version == rpcbindVersion3 || version == rpcbindVersion4 {
		return rpcbindReply(xid, version, procedure, protocol, rpcbindLocalIP(local), args, mappings)
	}
	if version != portmapVersion {
		return rpcAcceptedReply(xid, 2, nfsWords(portmapVersion, rpcbindVersion4)), false // PROG_MISMATCH
	}
	switch procedure {
	case 0: // NULL
		if len(args) == 0 {
			return rpcAcceptedReply(xid, 0, nil), false
		}
	case 1, 2: // SET and UNSET return false for a read-only table.
		if len(args) == 16 {
			return rpcAcceptedReply(xid, 0, nfsWords(0)), false
		}
	case 3: // GETPORT
		if len(args) == 16 {
			program := binary.BigEndian.Uint32(args)
			version := binary.BigEndian.Uint32(args[4:])
			protocol := binary.BigEndian.Uint32(args[8:])
			for _, mapping := range mappings {
				if mapping.program == program && mapping.version == version && mapping.protocol == protocol {
					return rpcAcceptedReply(xid, 0, nfsWords(mapping.port)), false
				}
			}
			return rpcAcceptedReply(xid, 0, nfsWords(0)), false
		}
	case 4: // DUMP
		if len(args) == 0 {
			return rpcAcceptedReply(xid, 0, dumpBody), true
		}
	case 5: // CALLIT only answers a successful forwarded call.
		return nil, false
	default:
		return rpcAcceptedReply(xid, 3, nil), false // PROC_UNAVAIL
	}
	return rpcAcceptedReply(xid, 4, nil), false // GARBAGE_ARGS
}

func parsePortmapMappings(params map[string]any) ([]portmapMapping, error) {
	table := portmapDefaultTable
	if configured, found := params["mapping_table"]; found {
		switch rows := configured.(type) {
		case nil:
			table = nil
		case []string:
			table = rows
		case []any:
			if len(rows) > 256 {
				return nil, errors.New("simulated portmap table exceeds limit")
			}
			table = make([]string, len(rows))
			for i, entry := range rows {
				row, ok := entry.(string)
				if !ok {
					return nil, errors.New("[PORTMAP] invalid mapping row.")
				}
				table[i] = row
			}
		default:
			return nil, errors.New("[PORTMAP] invalid mapping table.")
		}
	}
	if len(table) > 256 {
		return nil, errors.New("simulated portmap table exceeds limit")
	}
	mappings := make([]portmapMapping, len(table))
	for i, row := range table {
		fields := strings.SplitN(row, ",", 4)
		program, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return nil, errors.New("[PORTMAP] invalid program.")
		}
		if len(fields) < 2 {
			return nil, errPortmapIncompleteMapping
		}
		version, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return nil, errors.New("[PORTMAP] invalid version.")
		}
		if len(fields) < 4 {
			return nil, errPortmapIncompleteMapping
		}
		port, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, errors.New("[PORTMAP] invalid port number.")
		}
		protocol := uint32(portmapTCP)
		if fields[2] == "udp" {
			protocol = portmapUDP
		}
		// The reference prepends each mapping, so DUMP sends rows in reverse.
		mappings[len(table)-1-i] = portmapMapping{uint32(program), uint32(version), protocol, uint32(port)}
	}
	return mappings, nil
}

func portmapDumpBody(mappings []portmapMapping) []byte {
	body := make([]byte, 0, 20*len(mappings)+4)
	for _, mapping := range mappings {
		body = append(body, nfsWords(1, mapping.program, mapping.version, mapping.protocol, mapping.port)...)
	}
	return binary.BigEndian.AppendUint32(body, 0)
}
