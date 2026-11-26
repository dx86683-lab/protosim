package protocols

import (
	"encoding/binary"
	"io"
	"time"
)

// The reference S7 listener reads one TPKT frame and closes the connection
// without replying, in every network mode tested on host 15.

func init() {
	AddProtocol(NewProtocolInfo("s7", serveS7, 102))
}

func serveS7(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(session.Conn, header[:]); err != nil {
		return err
	}
	if size := int(binary.BigEndian.Uint16(header[2:])); size > 4 && size <= 4096 {
		if _, err := io.CopyN(io.Discard, session.Conn, int64(size-4)); err != nil {
			return err
		}
	}
	return nil
}
