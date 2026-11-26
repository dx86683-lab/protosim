package protocols

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type rtspStreamKey struct {
	presentation string
	track        string
}

type rtspStream struct {
	publisher *rtspMediaTrack
	listeners map[*rtspMediaTrack]struct{}
}

type rtspMediaTrack struct {
	key        rtspStreamKey
	pair       rtspChannelPair
	record     bool
	active     bool
	connection *rtspInterleavedConnection
}

type rtspMediaFrame struct {
	source      *rtspMediaTrack
	destination *rtspMediaTrack
	control     bool
	packet      []byte
}

func (server *rtspServer) startMedia(connection *rtspInterleavedConnection, target, id string, record bool, playRange string) string {
	server.mu.Lock()
	defer server.mu.Unlock()
	owner := server.sessions[id]
	if owner == nil {
		return "454 Session Not Found"
	}
	if owner != connection {
		return "455 Method Not Valid in This State"
	}
	session := owner.sessions[id]
	var tracks []*rtspMediaTrack
	if target == session.presentation || target == session.aggregate {
		for _, track := range session.tracks {
			tracks = append(tracks, track)
		}
	} else if track := session.tracks[target]; track != nil {
		tracks = append(tracks, track)
	}
	if len(tracks) == 0 {
		return "404 Not Found"
	}
	if !rtspLiveRange(playRange) {
		return "457 Invalid Range"
	}
	for _, track := range tracks {
		if track.record != record {
			return "455 Method Not Valid in This State"
		}
		if stream := server.streams[track.key]; record && stream != nil && stream.publisher != nil && stream.publisher != track {
			return "455 Method Not Valid in This State"
		}
	}
	for _, track := range tracks {
		stream := server.streams[track.key]
		if stream == nil {
			stream = &rtspStream{listeners: make(map[*rtspMediaTrack]struct{})}
			server.streams[track.key] = stream
		}
		if record {
			stream.publisher = track
			connection.incoming[track.pair[0]] = track
		} else {
			stream.listeners[track] = struct{}{}
		}
		connection.incoming[track.pair[1]] = track
		track.active = true
	}
	return "200 OK"
}

func rtspLiveRange(value string) bool {
	if value == "" || value == "npt=now-" {
		return true
	}
	prefix, ok := strings.CutPrefix(value, "npt=")
	start, end, separated := strings.Cut(prefix, "-")
	number, err := strconv.ParseFloat(start, 64)
	return ok && separated && end == "" && err == nil && number == 0 && strings.Trim(start, "0.") == ""
}

// Call with server.mu held.
func (server *rtspServer) stopMedia(track *rtspMediaTrack) {
	if !track.active {
		return
	}
	stream := server.streams[track.key]
	if track.record {
		stream.publisher = nil
		track.connection.incoming[track.pair[0]] = nil
	} else {
		delete(stream.listeners, track)
	}
	track.connection.incoming[track.pair[1]] = nil
	track.active = false
	if stream.publisher == nil && len(stream.listeners) == 0 {
		delete(server.streams, track.key)
	}
}

func (server *rtspServer) readInterleaved(reader *bufio.Reader, connection *rtspInterleavedConnection) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	packet := make([]byte, int(binary.BigEndian.Uint16(header[2:])))
	if _, err := io.ReadFull(reader, packet); err != nil {
		return err
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	source := connection.incoming[header[1]]
	if source == nil {
		return nil
	}
	control := int(header[1]) == source.pair[1]
	if !validRTSPMediaPacket(packet, control) {
		return nil
	}
	stream := server.streams[source.key]
	if source.record {
		for listener := range stream.listeners {
			listener.enqueueMedia(source, packet, control)
		}
	} else if stream.publisher != nil {
		stream.publisher.enqueueMedia(source, packet, true)
	}
	return nil
}

func validRTSPMediaPacket(packet []byte, control bool) bool {
	if control {
		for len(packet) >= 4 && packet[0]>>6 == 2 {
			size := (int(binary.BigEndian.Uint16(packet[2:])) + 1) * 4
			if size > len(packet) {
				return false
			}
			packet = packet[size:]
			if len(packet) == 0 {
				return true
			}
		}
		return false
	}
	return len(packet) >= 12 && packet[0]>>6 == 2 && len(packet) >= 12+4*int(packet[0]&0x0f)
}

func (track *rtspMediaTrack) enqueueMedia(source *rtspMediaTrack, packet []byte, control bool) {
	select {
	case track.connection.outbound <- rtspMediaFrame{source: source, destination: track, control: control, packet: packet}:
	default:
		// A slow client drops frames independently of the source and other clients.
	}
}

func (server *rtspServer) writeMedia(conn net.Conn, media *rtspInterleavedConnection) {
	for {
		select {
		case <-media.stop:
			return
		case frame := <-media.outbound:
			media.writeMu.Lock()
			server.mu.RLock()
			active := frame.source.active && frame.destination.active
			server.mu.RUnlock()
			var err error
			if active {
				channel := frame.destination.pair[0]
				if frame.control {
					channel = frame.destination.pair[1]
				}
				wire := make([]byte, 4, 4+len(frame.packet))
				wire[0], wire[1] = '$', byte(channel)
				binary.BigEndian.PutUint16(wire[2:], uint16(len(frame.packet)))
				wire = append(wire, frame.packet...)
				err = conn.SetWriteDeadline(time.Now().Add(time.Second))
				if err == nil {
					var n int
					n, err = conn.Write(wire)
					if err == nil && n != len(wire) {
						err = io.ErrShortWrite
					}
				}
			}
			media.writeMu.Unlock()
			if err != nil {
				conn.Close()
				return
			}
		}
	}
}
