package protocols

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// SIPDatagramSize is the maximum IPv4 UDP payload without IP options.
const SIPDatagramSize = 65507

const (
	sipHeaderLimit = 64 << 10
	sipStreamLimit = 1 << 20
	sipIdleTimeout = 2 * time.Minute
)

var errSIPFraming = errors.New("invalid SIP message framing")

func sipBodyLength(header []byte) (int, bool, error) {
	_, fields, ok := bytes.Cut(header, []byte("\r\n"))
	if !ok {
		return 0, false, errSIPFraming
	}
	var value []byte
	var found, reading bool
	for len(fields) != 0 {
		var line []byte
		line, fields, _ = bytes.Cut(fields, []byte("\r\n"))
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if continuation := bytes.Trim(line, " \t"); reading && len(continuation) != 0 {
				if len(value) != 0 {
					return 0, false, errSIPFraming
				}
				value = continuation
			}
			continue
		}
		name, fieldValue, ok := bytes.Cut(line, []byte(":"))
		name = bytes.TrimRight(name, " \t")
		reading = bytes.EqualFold(name, []byte("Content-Length")) || bytes.EqualFold(name, []byte("l"))
		if reading {
			if found || !ok {
				return 0, false, errSIPFraming
			}
			found, value = true, bytes.Trim(fieldValue, " \t")
		}
	}
	if !found {
		return 0, false, nil
	}
	size, err := strconv.ParseUint(string(value), 10, 31)
	return int(size), true, err
}

func serveSIP(conn *UDPConnection, packet []byte) error {
	end := bytes.Index(packet, []byte("\r\n\r\n"))
	if len(packet) > SIPDatagramSize || end < 0 {
		return nil
	}
	bodyStart := end + 4
	length, declared, err := sipBodyLength(packet[:bodyStart])
	if err != nil {
		return nil
	}
	incomplete := declared && length > len(packet)-bodyStart
	if declared && !incomplete {
		packet = packet[:bodyStart+length]
	}
	return replySIP(conn.ConfigInfo, conn.RemoteAddr(), packet, SIPDatagramSize, incomplete, conn.Write)
}

func readSIPStreamFrame(reader *bufio.Reader) ([]byte, error) {
	var header []byte
	for remaining := sipHeaderLimit; ; {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		remaining -= len(line)
		if remaining < 0 || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, errSIPFraming
		}
		if len(line) == 2 && len(header) == 0 {
			continue // RFC 3261 permits CRLF before the start line.
		}
		header = append(header, line...)
		if len(line) == 2 {
			break
		}
	}
	length, declared, err := sipBodyLength(header)
	if err != nil || !declared || length > sipStreamLimit-len(header) {
		return nil, errSIPFraming
	}
	packet := append(header, make([]byte, length)...)
	_, err = io.ReadFull(reader, packet[len(header):])
	return packet, err
}

func serveSIPTCP(session *SessionConnection) error {
	defer session.DeleteActivity()
	conn := session.Conn
	reader := bufio.NewReaderSize(conn, sipHeaderLimit)
	write := func(wire []byte) (int, error) {
		if err := conn.SetWriteDeadline(time.Now().Add(sipIdleTimeout)); err != nil {
			return 0, err
		}
		return conn.Write(wire)
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(sipIdleTimeout)); err != nil {
			return err
		}
		packet, err := readSIPStreamFrame(reader)
		if err != nil {
			var networkError net.Error
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errSIPFraming) ||
				errors.Is(err, bufio.ErrBufferFull) || errors.As(err, &networkError) && networkError.Timeout() {
				return nil
			}
			return err
		}
		if err := replySIP(session.ConfigInfo, conn.RemoteAddr(), packet, sipStreamLimit, false, write); err != nil {
			return err
		}
	}
}
