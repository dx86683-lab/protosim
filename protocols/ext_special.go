package protocols

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

func init() {
	AddProtocol(NewProtocolInfo("minecraft", Minecraft, 25565))
	AddProtocol(NewProtocolInfo("source-rcon", SourceRCON, 27015))
	AddProtocol(NewProtocolInfo("teamspeak", TeamSpeak3, 9987))
	AddProtocol(NewProtocolInfo("ipfs", IPFSLibp2p, 4001))
}

// Minecraft implements Minecraft Java Edition Server List Ping (TCP 25565).
func Minecraft(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	buf := make([]byte, 512)
	n, err := sc.Conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	sc.LogWithRemote("minecraft_ping", sc.Conn.RemoteAddr(), logrus.Fields{"bytes": n})

	motd := `{"version":{"name":"1.20.4","protocol":765},"players":{"max":20,"online":0},"description":{"text":"ProtoSim Minecraft Server"}}`
	var body bytes.Buffer
	body.WriteByte(0x00) // Status Response Packet ID
	writeMCVarInt(&body, len(motd))
	body.WriteString(motd)

	var frame bytes.Buffer
	writeMCVarInt(&frame, body.Len())
	frame.Write(body.Bytes())
	_, err = sc.Conn.Write(frame.Bytes())
	return err
}

func writeMCVarInt(buf *bytes.Buffer, v int) {
	u := uint32(v)
	for {
		b := byte(u & 0x7f)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if u == 0 {
			break
		}
	}
}

// SourceRCON implements Valve Source RCON TCP packet framing (TCP 27015).
func SourceRCON(sc *SessionConnection) error {
	defer sc.DeleteActivity()

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(sc.Conn, lenBuf); err != nil {
		return err
	}
	pktLen := int(binary.LittleEndian.Uint32(lenBuf))
	if pktLen < 10 || pktLen > 4096 {
		return nil
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(sc.Conn, pkt); err != nil {
		return err
	}
	reqID := int32(binary.LittleEndian.Uint32(pkt[0:4]))
	pktType := int32(binary.LittleEndian.Uint32(pkt[4:8]))
	bodyStr := string(bytes.TrimRight(pkt[8:], "\x00"))
	sc.LogWithRemote("source_rcon", sc.Conn.RemoteAddr(), logrus.Fields{
		"request_id": reqID, "type": pktType, "password": bodyStr, "accepted": false,
	})

	// SERVERDATA_AUTH_RESPONSE (type=2) with id=-1 (auth failed)
	resp := make([]byte, 14)
	binary.LittleEndian.PutUint32(resp[0:4], 10)
	binary.LittleEndian.PutUint32(resp[4:8], 0xffffffff) // -1
	binary.LittleEndian.PutUint32(resp[8:12], 2)
	_, err := sc.Conn.Write(resp)
	return err
}

// TeamSpeak3 implements TeamSpeak 3 UDP init packet handling (UDP 9987).
func TeamSpeak3(uc *UDPConnection, b []byte) error {
	if len(b) < 13 {
		return nil
	}
	uc.LogWithRemote("teamspeak3_packet", uc.RemoteAddr(), logrus.Fields{"length": len(b)})
	// Minimal TS3 init1 response packet
	resp := make([]byte, 32)
	copy(resp[0:8], []byte("TS3INIT1"))
	resp[12] = 0x08 // Init1
	_, err := uc.WriteTo(resp, uc.RemoteAddr())
	return err
}

// IPFSLibp2p implements IPFS / libp2p multistream-select greeting (TCP 4001).
func IPFSLibp2p(sc *SessionConnection) error {
	defer sc.DeleteActivity()
	greeting := "\x13/multistream/1.0.0\n"
	if _, err := sc.Conn.Write([]byte(greeting)); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := sc.Conn.Read(buf)
	if n > 0 {
		sc.LogWithRemote("ipfs_multistream", sc.Conn.RemoteAddr(), logrus.Fields{"raw": string(buf[:n])})
	}
	return err
}
