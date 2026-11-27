package telemetry

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

var (
	clientMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// BuildSessionPCAP synthesizes a standard Wireshark/tcpdump-compatible libpcap (.pcap) byte stream
// from a Session and its directional PayloadChunks (Ethernet + IPv4 + TCP/UDP).
func BuildSessionPCAP(sess Session, chunks []PayloadChunk) []byte {
	var buf bytes.Buffer

	// Global PCAP Header (little-endian magic 0xa1b2c3d4, v2.4, snaplen 65535, linktype 1=Ethernet)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1)) // DLT_EN10MB

	remoteIP := parseIPv4OrDefault(sess.RemoteIP, net.IPv4(192, 0, 2, 1))
	localIP := parseIPv4OrDefault(sess.LocalIP, net.IPv4(192, 0, 2, 2))
	remotePort := sess.RemotePort
	if remotePort == 0 {
		remotePort = 54321
	}
	localPort := sess.LocalPort
	if localPort == 0 {
		localPort = 80
	}

	isUDP := strings.EqualFold(sess.Transport, "udp")
	var clientSeq uint32 = 1000
	var serverSeq uint32 = 5000
	var ipID uint16 = 1

	baseTS := sess.StartedAt
	if baseTS.IsZero() {
		baseTS = time.Now().UTC()
	}
	lastTS := baseTS
	nextTS := func(candidate time.Time) time.Time {
		if candidate.IsZero() || !candidate.After(lastTS) {
			lastTS = lastTS.Add(time.Millisecond)
			return lastTS
		}
		lastTS = candidate
		return lastTS
	}
	nextID := func() uint16 {
		id := ipID
		ipID++
		return id
	}

	// For TCP sessions, emit a valid 3-way handshake with strictly increasing timestamps and IP IDs.
	if !isUDP {
		writePacket(&buf, baseTS, buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, 0, 0x02, nil)) // SYN
		clientSeq++
		writePacket(&buf, nextTS(baseTS.Add(time.Millisecond)), buildTCPFrame(serverMAC, clientMAC, localIP, remoteIP, localPort, remotePort, nextID(), serverSeq, clientSeq, 0x12, nil)) // SYN-ACK
		serverSeq++
		writePacket(&buf, nextTS(baseTS.Add(2*time.Millisecond)), buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, serverSeq, 0x10, nil)) // ACK
	}

	for _, ch := range chunks {
		if len(ch.Data) == 0 {
			continue
		}
		if isUDP {
			// Preserve single UDP datagram message boundaries (do not split at 1400B).
			part := ch.Data
			if len(part) > 65507 {
				part = part[:65507]
			}
			ts := nextTS(ch.Timestamp)
			if ch.Direction == "out" {
				writePacket(&buf, ts, buildUDPFrame(serverMAC, clientMAC, localIP, remoteIP, localPort, remotePort, nextID(), part))
			} else {
				writePacket(&buf, ts, buildUDPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), part))
			}
			continue
		}
		// Segment TCP streams into <= 1400-byte MSS chunks to stay within Ethernet MTU.
		for offset := 0; offset < len(ch.Data); offset += 1400 {
			end := offset + 1400
			if end > len(ch.Data) {
				end = len(ch.Data)
			}
			part := ch.Data[offset:end]
			ts := nextTS(ch.Timestamp)
			if ch.Direction == "out" {
				writePacket(&buf, ts, buildTCPFrame(serverMAC, clientMAC, localIP, remoteIP, localPort, remotePort, nextID(), serverSeq, clientSeq, 0x18, part))
				serverSeq += uint32(len(part))
				writePacket(&buf, nextTS(ts.Add(time.Microsecond*200)), buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, serverSeq, 0x10, nil))
			} else {
				writePacket(&buf, ts, buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, serverSeq, 0x18, part))
				clientSeq += uint32(len(part))
				writePacket(&buf, nextTS(ts.Add(time.Microsecond*200)), buildTCPFrame(serverMAC, clientMAC, localIP, remoteIP, localPort, remotePort, nextID(), serverSeq, clientSeq, 0x10, nil))
			}
		}
	}

	// Emit clean TCP FIN/ACK teardown so Wireshark/Zeek/Suricata finalize stream reassembly.
	if !isUDP {
		endTS := nextTS(sess.EndedAt)
		writePacket(&buf, endTS, buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, serverSeq, 0x11, nil)) // FIN+ACK
		clientSeq++
		writePacket(&buf, nextTS(endTS.Add(time.Millisecond)), buildTCPFrame(serverMAC, clientMAC, localIP, remoteIP, localPort, remotePort, nextID(), serverSeq, clientSeq, 0x11, nil)) // FIN+ACK
		serverSeq++
		writePacket(&buf, nextTS(endTS.Add(2*time.Millisecond)), buildTCPFrame(clientMAC, serverMAC, remoteIP, localIP, remotePort, localPort, nextID(), clientSeq, serverSeq, 0x10, nil)) // ACK
	}

	return buf.Bytes()
}

func parseIPv4OrDefault(s string, fallback net.IP) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() {
		return fallback.To4()
	}
	if v4 := ip.To4(); v4 != nil && !v4.IsUnspecified() {
		return v4
	}
	return fallback.To4()
}

func writePacket(buf *bytes.Buffer, ts time.Time, frame []byte) {
	_ = binary.Write(buf, binary.LittleEndian, uint32(ts.Unix()))
	_ = binary.Write(buf, binary.LittleEndian, uint32(ts.Nanosecond()/1000))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(frame)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(frame)))
	buf.Write(frame)
}

func buildEthernetHeader(srcMAC, dstMAC []byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	eth[12] = 0x08
	eth[13] = 0x00 // EtherType IPv4
	return eth
}

func buildIPv4Header(srcIP, dstIP net.IP, proto byte, ipID uint16, l4Len int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version 4, IHL 5
	hdr[1] = 0x00
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+l4Len))
	binary.BigEndian.PutUint16(hdr[4:6], ipID)
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000) // DF
	hdr[8] = 64                                  // TTL
	hdr[9] = proto
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	csum := internetChecksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:12], csum)
	return hdr
}

func buildTCPFrame(srcMAC, dstMAC []byte, srcIP, dstIP net.IP, srcPort, dstPort, ipID uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	csum := l4Checksum(srcIP, dstIP, 6, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	ip := buildIPv4Header(srcIP, dstIP, 6, ipID, len(tcp))
	eth := buildEthernetHeader(srcMAC, dstMAC)
	frame := make([]byte, 0, len(eth)+len(ip)+len(tcp))
	frame = append(frame, eth...)
	frame = append(frame, ip...)
	frame = append(frame, tcp...)
	return frame
}

func buildUDPFrame(srcMAC, dstMAC []byte, srcIP, dstIP net.IP, srcPort, dstPort, ipID uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	csum := l4Checksum(srcIP, dstIP, 17, udp)
	binary.BigEndian.PutUint16(udp[6:8], csum)

	ip := buildIPv4Header(srcIP, dstIP, 17, ipID, len(udp))
	eth := buildEthernetHeader(srcMAC, dstMAC)
	frame := make([]byte, 0, len(eth)+len(ip)+len(udp))
	frame = append(frame, eth...)
	frame = append(frame, ip...)
	frame = append(frame, udp...)
	return frame
}

func l4Checksum(srcIP, dstIP net.IP, proto byte, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return internetChecksum(pseudo)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
