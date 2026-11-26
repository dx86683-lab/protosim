package protocols

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	rmiCall   = 0x50
	rmiPing   = 0x52
	rmiDgcAck = 0x54
)

// Java RMI registry over the JRMP stream protocol. Lookup returns a serialized
// remote reference with the configured interface and endpoint. The captured
// normal-return UIDs and object number are fixed simulator values.

//go:embed fixtures/rmi-default.json
var rmiDefault []byte

type rmiService struct {
	Name   string `json:"name"`
	Object string `json:"object"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}

type rmiRegistryCache struct {
	mu          sync.Mutex
	initialized bool
	services    []rmiService
}

var javaRMIRegistry rmiRegistryCache

func (c *rmiRegistryCache) load(path string) ([]rmiService, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var config struct {
		Services []rmiService `json:"services"`
	}
	if err := loadResource("java-rmi", path, &config, rmiDefault); err != nil {
		return nil, err
	}
	// The first successfully loaded registry is shared by listeners.
	if !c.initialized {
		c.services = config.Services
		c.initialized = true
	}
	return c.services, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	rmiListHeader   = mustHex("51aced0005770f011672df6800000180cfa1edc08015757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b47020000707870")
	rmiLookupHeader = mustHex("51aced0005770f0140b0257800000180ef4b7319800a737d")
	rmiProxyBody    = mustHex("70787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b7078707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c65720000000000000002020000707872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e030000707870")
	rmiObjectID     = mustHex("6d2bfa41f4f8a9db40b0257800000180ef4b7319800101")
	// JRMP exceptional return with a zero UID and an OpenJDK-serialized
	// NotBoundException with null codebase annotations and an empty stack.
	rmiNotBound = mustHex("51aced0005770f0200000000000000000000000000007372001a6a6176612e726d692e4e6f74426f756e64457863657074696f6e" +
		"e637f9a72d7c3afb02000070787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc402000070787200136a" +
		"6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f54" +
		"68726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461" +
		"636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c0014737570707265737365" +
		"64457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b70787071007e0007707572001e5b4c6a6176612e6c61" +
		"6e672e537461636b5472616365456c656d656e743b02462a3c3cfd2239020000707870000000007372001f6a6176612e7574696c" +
		"2e436f6c6c656374696f6e7324456d7074794c6973747ab817b43ca79ede02000070787078")
)

func init() {
	AddProtocol(NewProtocolInfo("java-rmi", serveJavaRMI, 1099),
		ProtocolParams{Name: "config_file", DefaultValue: "rmi.json"})
}

func javaUTF(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...)
}

func rmiListReturn(services []rmiService) []byte {
	out := bytes.Clone(rmiListHeader)
	out = binary.BigEndian.AppendUint32(out, uint32(len(services)))
	for _, s := range services {
		out = append(out, 0x74)
		out = append(out, javaUTF(s.Name)...)
	}
	return out
}

func rmiLookupReturn(s rmiService) []byte {
	object := s.Object
	if object == "javax.management.remote.rmi.RMIServerImpl_Stub" {
		// This legacy configuration names the concrete stub. A proxy class
		// descriptor contains interfaces, so advertise its public contract.
		object = "javax.management.remote.rmi.RMIServer"
	}
	interfaces := []string{"java.rmi.Remote"}
	if object != "" && object != interfaces[0] {
		interfaces = append(interfaces, object)
	}
	out := bytes.Clone(rmiLookupHeader)
	out = binary.BigEndian.AppendUint32(out, uint32(len(interfaces)))
	for _, name := range interfaces {
		out = append(out, javaUTF(name)...)
	}
	out = append(out, rmiProxyBody...)
	ref := append(javaUTF("UnicastRef"), javaUTF(s.IP)...)
	ref = binary.BigEndian.AppendUint32(ref, uint32(s.Port))
	ref = append(ref, rmiObjectID...)
	if len(ref) <= 255 {
		out = append(out, 0x77, byte(len(ref))) // TC_BLOCKDATA
	} else {
		out = binary.BigEndian.AppendUint32(append(out, 0x7a), uint32(len(ref))) // TC_BLOCKDATALONG
	}
	out = append(out, ref...)
	return append(out, 0x78) // TC_ENDBLOCKDATA
}

func serveJavaRMI(session *SessionConnection) error {
	defer session.DeleteActivity()
	if err := session.Conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}
	r := bufio.NewReader(session.Conn)
	if _, err := r.Peek(1); err != nil {
		return err
	}
	// The reference handles the whole first read as the handshake, including
	// any call that arrived alongside the JRMI prefix.
	handshakeSize := r.Buffered()
	handshake, _ := r.Peek(handshakeSize)
	if !bytes.HasPrefix(handshake, []byte("JRMI")) {
		return errors.New("invalid JRMP header")
	}
	r.Discard(handshakeSize)
	ack := []byte{'N'}
	if tcp, ok := session.Conn.RemoteAddr().(*net.TCPAddr); ok {
		ack = append(ack, javaUTF(tcp.IP.String())...)
		ack = binary.BigEndian.AppendUint32(ack, uint32(tcp.Port))
	}
	if _, err := session.Conn.Write(ack); err != nil {
		return err
	}
	services, err := javaRMIRegistry.load(session.GetStringParams("config_file", "rmi.json"))
	if err != nil {
		_, err = io.Copy(io.Discard, r)
		return err
	}
	if handshakeSize < 7 {
		// A staged header tail is ignored as a read of its own. An operation
		// sent immediately after the acknowledgement can also begin this read.
		next, err := r.Peek(1)
		if err != nil {
			return err
		}
		switch next[0] {
		case rmiCall, rmiPing, rmiDgcAck:
		default:
			r.Discard(r.Buffered())
		}
	}
	for {
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		var reply []byte
		switch kind {
		case 0x00: // client endpoint: rest of UTF host, then port
			n, err := r.ReadByte()
			if err != nil {
				return err
			}
			if _, err := r.Discard(int(n) + 4); err != nil {
				return err
			}
			// The endpoint consumes the rest of the read that completes it.
			r.Discard(r.Buffered())
			continue
		case rmiPing:
			reply = []byte{0x53}
		case rmiDgcAck: // Carries a UID.
			if _, err := r.Discard(14); err != nil {
				return err
			}
			continue
		case rmiCall:
			// ObjectOutputStream header and the 34-byte call block: ObjID(22) op(4) hash(8).
			var head [6 + 34]byte
			if _, err := io.ReadFull(r, head[:]); err != nil {
				return err
			}
			if !bytes.Equal(head[:6], []byte{0xac, 0xed, 0, 5, 0x77, 0x22}) {
				return errors.New("unsupported RMI call encoding")
			}
			if binary.BigEndian.Uint32(head[28:]) != 2 {
				reply = rmiListReturn(services)
				break
			}
			tag, err := r.ReadByte()
			if err != nil {
				return err
			}
			if tag != 0x74 {
				return errors.New("lookup expects a string argument")
			}
			var size [2]byte
			if _, err := io.ReadFull(r, size[:]); err != nil {
				return err
			}
			name := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(r, name); err != nil {
				return err
			}
			for _, s := range services {
				if s.Name == string(name) {
					reply = rmiLookupReturn(s)
					break
				}
			}
			if reply == nil {
				reply = rmiNotBound
			}
		default:
			return errors.New("unsupported JRMP message")
		}
		// A read that completes an operation yields only its first reply.
		r.Discard(r.Buffered())
		if _, err := session.Conn.Write(reply); err != nil {
			return err
		}
	}
}
