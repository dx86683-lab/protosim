package protocols

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	rpcProgNFS        = 100003
	rpcProgMount      = 100005
	nfsDefaultExport  = "./nfs_data"
	nfsMaxTransfer    = 1 << 20
	nfsMaxRPCRecord   = nfsMaxTransfer + 4096 // room for RPC and NFS arguments around the WRITE payload
	nfsReplyBatchSize = 1 << 20
)

func init() {
	AddProtocol(NewProtocolInfo("nfs", newNFSServer, 2049),
		ProtocolParams{Name: "fs_path", DefaultValue: nfsDefaultExport})
}

const rpcMaxFragments = 64

func readRPCRecord(r io.Reader, limit int) ([]byte, error) {
	var record []byte
	for fragments := 0; fragments < rpcMaxFragments; fragments++ {
		var mark [4]byte
		if _, err := io.ReadFull(r, mark[:]); err != nil {
			return nil, err
		}
		v := binary.BigEndian.Uint32(mark[:])
		last := v&0x80000000 != 0
		size := int(v & 0x7fffffff)
		if size == 0 && !last {
			return nil, errors.New("empty non-final RPC fragment")
		}
		if size > limit-len(record) {
			return nil, errors.New("RPC record too large")
		}
		start := len(record)
		record = append(record, make([]byte, size)...)
		if _, err := io.ReadFull(r, record[start:]); err != nil {
			return nil, err
		}
		if last {
			return record, nil
		}
	}
	return nil, errors.New("too many RPC fragments")
}

func rpcAcceptedReply(xid uint32, stat uint32, body []byte) []byte {
	reply := make([]byte, 28, 28+len(body))
	binary.BigEndian.PutUint32(reply[4:], xid)
	binary.BigEndian.PutUint32(reply[8:], 1) // REPLY, MSG_ACCEPTED, AUTH_NULL verifier
	binary.BigEndian.PutUint32(reply[24:], stat)
	reply = append(reply, body...)
	binary.BigEndian.PutUint32(reply[0:], 0x80000000|uint32(len(reply)-4))
	return reply
}

func rpcDeniedReply(xid, reason uint32, detail ...uint32) []byte {
	reply := nfsWords(0x80000000|uint32((4+len(detail))*4), xid, 1, 1, reason)
	return append(reply, nfsWords(detail...)...)
}

type nfsServer struct {
	mu        sync.Mutex
	handles   map[[16]byte]nfsHandle
	paths     map[string][16]byte
	mounted   map[string]struct{}
	verifier  [8]byte
	tcpReplay nfsReplayCache
	udpReplay nfsReplayCache
}

func newNFSServer() (TCPFunction, UDPFunction) {
	server := &nfsServer{}
	rand.Read(server.verifier[:])
	return server.serve, server.serveDatagram
}

var nfsProcedures = [...]string{
	"Null", "GetAttr", "SetAttr", "Lookup", "Access", "ReadLink", "Read",
	"Write", "Create", "Mkdir", "Symlink", "Mknod", "Remove", "Rmdir", "Rename", "Link",
	"ReadDir", "ReadDirPlus", "FSStat", "FSInfo", "PathConf", "Commit",
}

var mountProcedures = [...]string{"Null", "Mount", "Dump", "Umnt", "UmntAll", "Export"}

func (server *nfsServer) serve(session *SessionConnection) error {
	defer session.DeleteActivity()
	if capture, ok := session.Conn.(interface{ CaptureResponsesBeforeWrite() }); ok {
		capture.CaptureResponsesBeforeWrite()
	}
	export := session.GetStringParams("fs_path", nfsDefaultExport)
	if err := session.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	reader := bufio.NewReader(session.Conn)
	for {
		call, err := readRPCRecord(reader, nfsMaxRPCRecord)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// The capture may still hold a record prefix that never became a call.
			session.suppressRequestCapture()
			return nil
		}
		if err != nil {
			return err
		}
		replies, terminal, batchErr := server.collectReplies(session, reader, export, call)
		if len(replies) != 0 {
			if err := session.Conn.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
				return err
			}
			n, err := session.Conn.Write(replies)
			if err != nil {
				return err
			}
			if n != len(replies) {
				return io.ErrShortWrite
			}
		}
		if terminal {
			// The reference leaves this connection silent after a non-CALL.
			session.drainIgnoredInput(reader)
			return nil
		}
		if batchErr != nil {
			return batchErr
		}
	}
}

// collectReplies includes only records already buffered, so a partial next call
// cannot delay a complete reply while the client waits for it.
func (server *nfsServer) collectReplies(session *SessionConnection, reader *bufio.Reader, export string, call []byte) ([]byte, bool, error) {
	var replies []byte
	for {
		if len(call) < 24 {
			return replies, false, errors.New("short RPC call")
		}
		if binary.BigEndian.Uint32(call[4:]) != 0 {
			return replies, true, nil
		}
		reply := server.rpcReply(session.ConfigInfo, session.Conn.RemoteAddr(), export, call, nfsMaxTransfer)
		if len(replies) == 0 {
			replies = reply[:len(reply):len(reply)]
		} else {
			replies = append(replies, reply...)
		}
		if len(replies) >= nfsReplyBatchSize || !hasBufferedRPCRecord(reader) {
			return replies, false, nil
		}
		var err error
		call, err = readRPCRecord(reader, nfsMaxRPCRecord)
		if err != nil {
			return replies, false, err
		}
	}
}

func hasBufferedRPCRecord(reader *bufio.Reader) bool {
	buffered, _ := reader.Peek(reader.Buffered())
	for len(buffered) >= 4 {
		mark := binary.BigEndian.Uint32(buffered)
		size := int(mark & 0x7fffffff)
		if size > len(buffered)-4 {
			return false
		}
		if mark&0x80000000 != 0 {
			return true
		}
		buffered = buffered[4+size:]
	}
	return false
}

func (server *nfsServer) rpcReply(config *ConfigInfo, peer net.Addr, export string, call []byte, transfer uint32) []byte {
	xid := binary.BigEndian.Uint32(call)
	if binary.BigEndian.Uint32(call[8:]) != 2 {
		return rpcDeniedReply(xid, 0, 2, 2)
	}
	prog, proc := binary.BigEndian.Uint32(call[12:]), binary.BigEndian.Uint32(call[20:])
	if prog != rpcProgNFS && prog != rpcProgMount {
		return rpcAcceptedReply(xid, 1, nil)
	}
	if binary.BigEndian.Uint32(call[16:]) != 3 {
		return rpcAcceptedReply(xid, 2, nfsWords(3, 3))
	}
	args, authStatus := rpcCallArguments(call[24:])
	if authStatus != 0 {
		return rpcDeniedReply(xid, 1, authStatus)
	}
	execute := func() []byte {
		service, procedures := "nfs", nfsProcedures[:]
		if prog == rpcProgMount {
			service, procedures = "mount", mountProcedures[:]
		}
		procedure := "Unknown"
		if proc < uint32(len(procedures)) {
			procedure = procedures[proc]
		}
		label := fmt.Sprintf("RPC #%d (%s.%s)", xid, service, procedure)
		logSessionEvent(config, peer, "request", logrus.Fields{"request": label})
		status, body := server.respond(prog, proc, export, args, transfer, peer)
		return rpcAcceptedReply(xid, status, body)
	}
	if prog == rpcProgNFS && nfsMutationProcedure(proc) {
		return server.replayMutation(peer, export, call, execute)
	}
	return execute()
}

func (server *nfsServer) respond(program, procedure uint32, export string, args []byte, transfer uint32, peer net.Addr) (uint32, []byte) {
	server.mu.Lock()
	defer server.mu.Unlock()
	switch program {
	case rpcProgMount:
		return server.mountReply(procedure, export, args, peer)
	case rpcProgNFS:
		if procedure == 0 {
			return 0, nil
		}
		if procedure < uint32(len(nfsProcedures)) {
			return 0, server.fileReply(procedure, export, args, transfer)
		}
	}
	return 3, nil // PROC_UNAVAIL
}
