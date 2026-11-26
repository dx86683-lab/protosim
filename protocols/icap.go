package protocols

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	icapService      = "GreasySpoon service version 1.0.8-01"
	icapHeaderLimit  = 16 * 1024
	icapBodyLimit    = 1024 * 1024
	icapBodyReadSize = 32 * 1024
)

var icapHeaders = []string{`ISTag: "GreasySpoon-1.0.8-01"`}
var errICAPChunkExtension = errors.New("unsupported ICAP chunk extension")

func serveICAP(session *SessionConnection) error {
	defer session.DeleteActivity()
	reader := bufio.NewReader(session.Conn)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return err
	}
	fields := strings.SplitN(strings.TrimRight(string(line), "\r\n"), " ", 3)
	if len(fields) != 3 || fields[0] == "" || fields[1] == "" {
		return errors.New("invalid ICAP request line")
	}
	incoming, err := readTextHeaders(reader, len(line), textHeaderLimits{totalBytes: 8192}, func(_, value string) string {
		return strings.TrimSpace(value)
	})
	if err != nil {
		return err
	}
	encapsulated := incoming.Get("Encapsulated")
	request, err := readICAPEncapsulation(reader, fields[0], encapsulated, incoming.Get("Preview") != "")
	if err != nil {
		return err
	}
	if session.Log != nil {
		incoming.Del("Authorization")
		incoming.Del("Proxy-Authorization")
		target := fields[1]
		if parsed, err := url.Parse(target); err == nil && parsed.User != nil {
			target = parsed.Redacted()
		}
		session.LogWithRemote("new message", session.Conn.RemoteAddr(), map[string]interface{}{
			"method": fields[0], "url": target, "proto": fields[2], "headers": incoming,
		})
	}
	if err := session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}

	response := make(http.Header)
	for _, line := range session.GetStringsParams("headers", icapHeaders) {
		if key, value, ok := strings.Cut(line, ":"); ok && !strings.ContainsAny(line, "\r\n") {
			response.Add(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	switch fields[0] {
	case "OPTIONS":
		response.Set("Max-Connections", "50")
		response.Set("Methods", "REQMOD, RESPMOD")
		response.Set("Service", session.GetStringParams("server", icapService))
	case "REQMOD", "RESPMOD":
		if request == nil {
			return session.SendString("ICAP/1.0 400 Bad Request\r\n\r\n")
		}
		response.Set("Connection", "close")
		response.Set("Encapsulated", encapsulated)
		response.Set("Host", "0.0.0.0:"+strconv.Itoa(int(session.Port)))
	default:
		return session.SendString("ICAP/1.0 400 Bad Request\r\n\r\n")
	}

	var wire bytes.Buffer
	wire.WriteString("ICAP/1.0 200 OK\r\n")
	if err := response.Write(&wire); err != nil {
		return err
	}
	wire.WriteString("\r\n")
	if request != nil && (fields[0] == "REQMOD" || fields[0] == "RESPMOD") {
		// The reference writes the encapsulated HTTP request to this client.
		// A preview can end before the embedded Content-Length is reached.
		_ = request.Write(&wire)
	}
	_, err = session.Conn.Write(wire.Bytes())
	return err
}

func readICAPEncapsulation(reader *bufio.Reader, method, value string, preview bool) (*http.Request, error) {
	if value == "" {
		return nil, nil
	}
	type section struct {
		name   string
		offset int
	}
	var sections []section
	for item := range strings.SplitSeq(value, ", ") {
		name, length, hasLength := strings.Cut(item, "=")
		offset, err := strconv.Atoi(length)
		if !hasLength || err != nil || offset < 0 || offset > icapHeaderLimit ||
			len(sections) == 0 && offset != 0 ||
			len(sections) > 0 && offset <= sections[len(sections)-1].offset {
			return nil, errors.New("invalid ICAP section offset")
		}
		sections = append(sections, section{name, offset})
	}
	var request *http.Request
	for index, section := range sections[:len(sections)-1] {
		length := sections[index+1].offset - section.offset
		header := make([]byte, length)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}
		source := bufio.NewReader(bytes.NewReader(header))
		var err error
		switch section.name {
		case "req-hdr":
			request, err = http.ReadRequest(source)
		case "res-hdr":
			_, err = http.ReadResponse(source, nil)
		default:
			return nil, errors.New("invalid ICAP header section")
		}
		if err != nil {
			return nil, err
		}
	}
	last := sections[len(sections)-1].name
	switch last {
	case "null-body":
		// The embedded request retains its declared Content-Length.
	case "req-body", "res-body", "opt-body":
		adaptRequest := method == "REQMOD" && request != nil
		if !preview && !adaptRequest {
			break
		}
		preserveReads := adaptRequest && !preview && request.ContentLength <= 0
		body, incomplete, err := readICAPChunks(reader, preview, preserveReads)
		if err != nil {
			return nil, err
		}
		if adaptRequest {
			var source io.Reader = bytes.NewReader(body.data)
			if preserveReads {
				source = &body
			}
			if incomplete {
				source = icapIncompleteBody{source}
			}
			request.Body = io.NopCloser(source)
			return request, nil
		}
	default:
		return nil, errors.New("invalid ICAP body section")
	}
	if request != nil && last != "req-body" && request.ContentLength == 0 {
		request.Body = io.NopCloser(bytes.NewReader(nil))
	}
	return request, nil
}

type icapIncompleteBody struct{ io.Reader }

func (body icapIncompleteBody) Read(p []byte) (int, error) {
	n, err := body.Reader.Read(p)
	if err == io.EOF {
		err = errICAPChunkExtension
	}
	return n, err
}

// icapChunkBody replays reads within each validated chunk. Request.Write uses
// those reads to frame a chunked HTTP body. Preview bodies are replayed whole.
type icapChunkBody struct {
	data     []byte
	readEnds []uint32
	offset   int
}

func (body *icapChunkBody) Read(p []byte) (int, error) {
	if len(body.readEnds) == 0 {
		return 0, io.EOF
	}
	end := int(body.readEnds[0])
	n := copy(p, body.data[body.offset:end])
	body.offset += n
	if body.offset == end {
		body.readEnds = body.readEnds[1:]
	}
	return n, nil
}

func readICAPChunks(reader *bufio.Reader, preview, preserveReads bool) (icapChunkBody, bool, error) {
	var body icapChunkBody
	var delimiter [2]byte
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return icapChunkBody{}, false, err
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return icapChunkBody{}, false, errors.New("invalid ICAP chunk line")
		}
		sizeText, extension, extended := strings.Cut(string(line[:len(line)-2]), ";")
		size, err := strconv.ParseUint(strings.TrimRight(sizeText, " \t"), 16, 64)
		if err != nil {
			return icapChunkBody{}, false, errors.New("invalid ICAP chunk size")
		}
		if extended && !(preview && size == 0 && strings.TrimSpace(extension) == "ieof") {
			if preview {
				return icapChunkBody{}, false, errICAPChunkExtension
			}
			// For a non-preview request the reference serializes the embedded
			// request using only the complete chunks before the extension.
			return body, true, nil
		}
		if size == 0 {
			return body, false, nil
		}
		if size > uint64(icapBodyLimit-len(body.data)) {
			return icapChunkBody{}, false, errors.New("ICAP body exceeds limit")
		}
		start := len(body.data)
		body.data = append(body.data, make([]byte, int(size))...)
		if preserveReads {
			for start < len(body.data) {
				end := min(start+icapBodyReadSize, len(body.data))
				n, err := reader.Read(body.data[start:end])
				if err != nil {
					return icapChunkBody{}, false, err
				}
				start += n
				if n > 0 {
					body.readEnds = append(body.readEnds, uint32(start))
				}
			}
		} else if _, err := io.ReadFull(reader, body.data[start:]); err != nil {
			return icapChunkBody{}, false, err
		}
		if _, err := io.ReadFull(reader, delimiter[:]); err != nil {
			return icapChunkBody{}, false, err
		}
		if delimiter != [2]byte{'\r', '\n'} {
			return icapChunkBody{}, false, errors.New("invalid ICAP chunk delimiter")
		}
	}
}
