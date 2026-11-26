package protocols

import (
	"encoding/binary"
	"io"
)

const (
	nfsUDPTransfer   = 8192
	NFSMaxUDPRequest = nfsUDPTransfer + 4096
)

func (server *nfsServer) serveDatagram(conn *UDPConnection, call []byte) error {
	if len(call) < 24 || len(call) > NFSMaxUDPRequest || binary.BigEndian.Uint32(call[4:]) != 0 {
		return nil
	}
	export := conn.GetStringParams("fs_path", nfsDefaultExport)
	wire := server.rpcReply(conn.ConfigInfo, conn.RemoteAddr(), export, call, nfsUDPTransfer)
	payload := wire[4:] // UDP carries an RPC message without a record marker.
	n, err := conn.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}
