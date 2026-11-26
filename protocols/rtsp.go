package protocols

import (
	"bufio"
	"crypto/rand"
	"io"
	"maps"
	"mime"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/sdp/v3"
)

const (
	rtspPublic           = "OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, TEARDOWN"
	rtspMaxBodySize      = 128 * 1024
	rtspMaxPresentations = 32
)

type rtspServer struct {
	mu            sync.RWMutex
	presentations map[string]rtspPresentation
	sessions      map[string]*rtspInterleavedConnection
	streams       map[rtspStreamKey]*rtspStream
}

type rtspPresentation struct {
	body      []byte
	aggregate string
	tracks    map[string]struct{}
}

type rtspChannelPair [2]int

type rtspMediaSession struct {
	presentation string
	aggregate    string
	tracks       map[string]*rtspMediaTrack
}

type rtspInterleavedConnection struct {
	channels [256]bool
	sessions map[string]rtspMediaSession
	incoming [256]*rtspMediaTrack
	outbound chan rtspMediaFrame
	stop     chan struct{}
	writeMu  sync.Mutex
	writer   sync.Once
}

func newRTSPHandler() func(*SessionConnection) error {
	server := &rtspServer{
		presentations: make(map[string]rtspPresentation),
		sessions:      make(map[string]*rtspInterleavedConnection),
		streams:       make(map[rtspStreamKey]*rtspStream),
	}
	return server.serve
}

func (server *rtspServer) serve(session *SessionConnection) error {
	logEvent := func(message string, fields map[string]interface{}) {
		if session.Log != nil {
			session.LogWithRemote(message, session.Conn.RemoteAddr(), fields)
		}
	}
	openSessions := 0
	defer func() {
		for range openSessions {
			logEvent("session closed", nil)
		}
	}()
	defer session.DeleteActivity()

	configured := rtspConfiguredHeaders(session)
	reader := bufio.NewReader(session.Conn)
	media := rtspInterleavedConnection{
		sessions: make(map[string]rtspMediaSession),
		outbound: make(chan rtspMediaFrame, 16),
		stop:     make(chan struct{}),
	}
	defer server.closeMediaConnection(&media)
	defer close(media.stop)
	for {
		next, err := reader.Peek(1)
		if err != nil {
			return nil
		}
		if next[0] == '$' {
			if err := server.readInterleaved(reader, &media); err != nil {
				return nil
			}
			continue
		}
		request, err := readRTSPRequest(reader)
		if err != nil || request.version != "RTSP/1.0" {
			return nil
		}
		target, err := url.Parse(request.target)
		wildcard := request.method == "OPTIONS" && request.target == "*"
		if err != nil || !wildcard && (target.Fragment != "" || target.Opaque != "" ||
			target.Scheme != "rtsp" && target.Scheme != "rtsps") {
			return nil
		}

		var body []byte
		lengths := request.headers.Values("Content-Length")
		if len(lengths) > 1 || len(request.headers.Values("Transfer-Encoding")) > 0 {
			return nil
		}
		if len(lengths) == 1 {
			size, err := strconv.Atoi(lengths[0])
			if err != nil || !rtspDecimal(lengths[0]) || size > rtspMaxBodySize {
				return nil
			}
			body = make([]byte, size)
			if _, err := io.ReadFull(reader, body); err != nil {
				return nil
			}
		}

		media.writeMu.Lock()
		headers := make(map[string]string, len(configured)+2)
		status, done := "400 Bad Request", true
		var responseBody []byte
		if sequence := request.headers.Values("CSeq"); len(sequence) == 1 && rtspDecimal(sequence[0]) {
			headers["CSeq"] = sequence[0]
			if len(request.headers.Values("Session")) <= 1 {
				switch request.method {
				case "OPTIONS":
					if id := request.headers.Get("Session"); id != "" && !server.hasMediaSession(id) {
						status, done = "454 Session Not Found", false
						break
					}
					status, done = "200 OK", false
					headers["Public"] = rtspPublic
				case "DESCRIBE":
					if target.Path == "" {
						break
					}
					status, done = "404 Not Found", false
					logEvent("describe request", map[string]interface{}{"url": target.Redacted()})
					if description := server.describe(target.RequestURI()); description != nil {
						if !rtspAcceptsSDP(request.headers.Values("Accept")) {
							status = "406 Not Acceptable"
							break
						}
						status = "200 OK"
						responseBody = description
						headers["Content-Base"] = rtspContentBase(target).String()
						headers["Content-Type"] = "application/sdp"
						headers["Content-Length"] = strconv.Itoa(len(description))
					}
				case "SETUP":
					openSessions++
					logEvent("session opened", nil)
					status = media.setup(server, target.RequestURI(), request.headers.Get("Session"), request.headers.Values("Transport"), headers)
					done = status == "400 Bad Request"
					if status == "404 Not Found" || status == "200 OK" {
						logEvent("setup request", nil)
					}
				case "TEARDOWN":
					status, done = server.teardown(target.RequestURI(), request.headers.Get("Session")), false
				case "PLAY", "RECORD":
					id := request.headers.Get("Session")
					record := request.method == "RECORD"
					status, done = server.startMedia(&media, target.RequestURI(), id, record, request.headers.Get("Range")), false
					if status == "200 OK" {
						headers["Session"] = id
						media.writer.Do(func() { go server.writeMedia(session.Conn, &media) })
					}
				case "ANNOUNCE":
					openSessions++
					logEvent("session opened", nil)
					if target.Path == "" {
						break
					}
					contentType := request.headers.Values("Content-Type")
					if len(contentType) != 1 || !isRTSPSDP(contentType[0]) {
						status, done = "415 Unsupported Media Type", false
						break
					}
					presentation, valid := parseRTSPPresentation(target, body)
					if !valid {
						break
					}
					logEvent("announce request", nil)
					status, done = "200 OK", false
					if !server.publish(target.RequestURI(), presentation) {
						status = "503 Service Unavailable"
					}
				default:
					status, done = "501 Not Implemented", false
				}
			}
		}
		maps.Copy(headers, configured)
		var response strings.Builder
		response.WriteString("RTSP/1.0 " + status + "\r\n")
		for _, key := range slices.Sorted(maps.Keys(headers)) {
			response.WriteString(key + ": " + headers[key] + "\r\n")
		}
		response.WriteString("\r\n")
		response.Write(responseBody)
		err = session.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err == nil {
			err = session.SendString(response.String())
		}
		media.writeMu.Unlock()
		if err != nil || done {
			return err
		}
	}
}

func (server *rtspServer) describe(resource string) []byte {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.presentations[resource].body
}

func (server *rtspServer) publish(resource string, description rtspPresentation) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.presentations[resource]; !exists && len(server.presentations) >= rtspMaxPresentations {
		return false
	}
	server.presentations[resource] = description
	return true
}

// Call with server.mu held so SETUP sees one presentation snapshot.
func (server *rtspServer) findTrack(uri string) (resource, aggregate string) {
	for name, presentation := range server.presentations {
		if _, exists := presentation.tracks[uri]; exists {
			if resource != "" {
				return "", ""
			}
			resource, aggregate = name, presentation.aggregate
		}
	}
	return resource, aggregate
}

func (server *rtspServer) hasMediaSession(id string) bool {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.sessions[id] != nil
}

func (server *rtspServer) closeMediaConnection(connection *rtspInterleavedConnection) {
	server.mu.Lock()
	defer server.mu.Unlock()
	for id, session := range connection.sessions {
		for _, track := range session.tracks {
			server.stopMedia(track)
		}
		delete(server.sessions, id)
	}
}

func (server *rtspServer) teardown(target, id string) string {
	server.mu.Lock()
	defer server.mu.Unlock()
	connection := server.sessions[id]
	if connection == nil {
		return "454 Session Not Found"
	}
	session := connection.sessions[id]
	if target == session.presentation || target == session.aggregate {
		for _, track := range session.tracks {
			server.stopMedia(track)
			connection.channels[track.pair[0]], connection.channels[track.pair[1]] = false, false
		}
		delete(connection.sessions, id)
		delete(server.sessions, id)
		return "200 OK"
	}
	track, ok := session.tracks[target]
	if !ok {
		return "404 Not Found"
	}
	server.stopMedia(track)
	connection.channels[track.pair[0]], connection.channels[track.pair[1]] = false, false
	delete(session.tracks, target)
	if len(session.tracks) == 0 {
		delete(connection.sessions, id)
		delete(server.sessions, id)
	}
	return "200 OK"
}

func rtspContentBase(target *url.URL) *url.URL {
	base := *target
	base.User = nil
	base.RawQuery = ""
	base.ForceQuery = false
	if !strings.HasSuffix(base.EscapedPath(), "/") {
		base.Path += "/"
		if base.RawPath != "" {
			base.RawPath += "/"
		}
	}
	return &base
}

func rtspAcceptsSDP(values []string) bool {
	if len(values) == 0 {
		return true
	}
	bestMatch, quality := 0, 0.0
	for _, value := range values {
		fields, valid := splitRTSPField(value, ',')
		if !valid {
			continue
		}
		for _, field := range fields {
			mediaType, params, err := mime.ParseMediaType(field)
			if err != nil {
				continue
			}
			specificity := 0
			switch mediaType {
			case "application/sdp":
				specificity = 3
			case "application/*":
				specificity = 2
			case "*/*":
				specificity = 1
			}
			q := 1.0
			if weight, ok := params["q"]; ok {
				q, err = strconv.ParseFloat(weight, 64)
				if err != nil || !(q >= 0 && q <= 1) {
					continue
				}
			}
			if specificity > 0 && (specificity > bestMatch || specificity == bestMatch && q > quality) {
				bestMatch, quality = specificity, q
			}
		}
	}
	return quality > 0
}

func rtspDecimal(value string) bool {
	return value != "" && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) == -1
}

func isRTSPSDP(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/sdp"
}

func parseRTSPPresentation(target *url.URL, body []byte) (rtspPresentation, bool) {
	var description sdp.SessionDescription
	if description.Unmarshal(body) != nil || !validRTSPAnnounceTracks(description.MediaDescriptions) {
		return rtspPresentation{}, false
	}
	base := rtspContentBase(target)
	aggregate, _ := description.Attribute("control")
	aggregate = rtspLocalControl(base, aggregate)
	tracks := make(map[string]struct{}, len(description.MediaDescriptions))
	for _, media := range description.MediaDescriptions {
		control, explicit := media.Attribute("control")
		if !explicit {
			if len(description.MediaDescriptions) == 1 {
				tracks[target.RequestURI()] = struct{}{}
				tracks[base.RequestURI()] = struct{}{}
			}
			continue
		}
		if track := rtspLocalControl(base, control); track != "" {
			tracks[track] = struct{}{}
		}
	}
	return rtspPresentation{body: body, aggregate: aggregate, tracks: tracks}, true
}

func rtspLocalControl(base *url.URL, control string) string {
	if control == "*" {
		control = ""
	}
	target, err := base.Parse(control)
	if err != nil || target.Scheme != base.Scheme || !strings.EqualFold(target.Host, base.Host) || target.Fragment != "" {
		return ""
	}
	return target.RequestURI()
}

func validRTSPAnnounceTracks(descriptions []*sdp.MediaDescription) bool {
	if len(descriptions) == 0 {
		return false
	}
	for _, media := range descriptions {
		if len(media.MediaName.Formats) == 0 {
			return false
		}
		switch strings.Join(media.MediaName.Protos, "/") {
		case "RTP/AVP", "RTP/SAVP", "RTP/AVPF", "RTP/SAVPF":
		default:
			return false
		}
		mapped := make(map[uint64]bool, len(media.MediaName.Formats))
		for _, format := range media.MediaName.Formats {
			payload, valid := rtspRTPPayloadType(format)
			if !valid {
				return false
			}
			mapped[payload] = false
		}
		for _, attribute := range media.Attributes {
			if attribute.Key != "rtpmap" {
				continue
			}
			fields := strings.Fields(attribute.Value)
			if len(fields) != 2 || !validRTSPRTPEncoding(fields[1], media.MediaName.Media == "audio") {
				return false
			}
			payload, valid := rtspRTPPayloadType(fields[0])
			seen, declared := mapped[payload]
			if !valid || !declared || seen {
				return false
			}
			mapped[payload] = true
		}
		for payload, hasMapping := range mapped {
			if hasMapping {
				continue
			}
			// Default assignments from the RTP audio/video profile.
			switch payload {
			case 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
				25, 26, 28, 31, 32, 33, 34:
			default:
				return false
			}
		}
	}
	return true
}

func rtspRTPPayloadType(value string) (uint64, bool) {
	payload, err := strconv.ParseUint(value, 10, 7)
	if err != nil || !rtspDecimal(value) {
		return 0, false
	}
	switch payload {
	case 1, 2, 19, 72, 73, 74, 75, 76:
		return 0, false
	default:
		return payload, true
	}
}

func validRTSPRTPEncoding(value string, audio bool) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 2 || len(parts) > 3 || !validRTSPToken(parts[0]) || !rtspPositiveUint32(parts[1]) {
		return false
	}
	if len(parts) == 3 {
		if audio {
			return rtspPositiveUint32(parts[2])
		}
		return validRTSPToken(parts[2])
	}
	return true
}

func rtspPositiveUint32(value string) bool {
	number, err := strconv.ParseUint(value, 10, 32)
	return err == nil && number > 0 && rtspDecimal(value)
}

func rtspConfiguredHeaders(session *SessionConnection) map[string]string {
	headers := make(map[string]string)
	if server := session.GetStringParams("server", ""); server != "" && validRTSPHeaderValue(server) {
		headers["Server"] = server
	}
	for _, line := range session.GetStringsParams("headers", nil) {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !validRTSPToken(key) || !validRTSPHeaderValue(value) {
			continue
		}
		switch strings.ToLower(key) {
		case "cseq", "content-base", "content-length", "content-type", "session", "transfer-encoding", "transport", "public":
			continue
		}
		headers[key] = strings.Trim(value, " \t")
	}
	return headers
}

func (connection *rtspInterleavedConnection) setup(server *rtspServer, track, id string, transports []string, headers map[string]string) string {
	if len(transports) == 0 {
		return "400 Bad Request"
	}
	offers, valid := splitRTSPField(strings.Join(transports, ","), ',')
	if !valid {
		return "400 Bad Request"
	}
	var candidates []rtspTransportChoice
	for _, offer := range offers {
		choice, supported, valid := rtspTransportOffer(offer)
		if !valid {
			return "400 Bad Request"
		}
		if supported {
			candidates = append(candidates, choice)
		}
	}
	if len(candidates) == 0 {
		return "461 Unsupported Transport"
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	session, existing := connection.sessions[id]
	if id != "" && !existing {
		if server.sessions[id] != nil {
			return "459 Aggregate Operation Not Allowed"
		}
		return "454 Session Not Found"
	}
	presentation, aggregate := server.findTrack(track)
	if presentation == "" {
		return "404 Not Found"
	}
	if existing && session.presentation != presentation {
		return "459 Aggregate Operation Not Allowed"
	}

	available := connection.channels
	if previous, exists := session.tracks[track]; exists {
		if previous.active {
			return "455 Method Not Valid in This State"
		}
		available[previous.pair[0]], available[previous.pair[1]] = false, false
	}
	for _, candidate := range candidates {
		pair, found := chooseRTSPChannels(candidate.pair, &available)
		if !found {
			continue
		}
		if !existing {
			id = rand.Text()
			session = rtspMediaSession{presentation: presentation, aggregate: aggregate, tracks: make(map[string]*rtspMediaTrack)}
		}
		available[pair[0]], available[pair[1]] = true, true
		connection.channels = available
		session.tracks[track] = &rtspMediaTrack{
			key:  rtspStreamKey{presentation: presentation, track: track},
			pair: pair, record: candidate.record, connection: connection,
		}
		connection.sessions[id] = session
		server.sessions[id] = connection
		headers["Session"] = id
		headers["Transport"] = "RTP/AVP/TCP;unicast;interleaved=" + strconv.Itoa(pair[0]) + "-" + strconv.Itoa(pair[1])
		if candidate.record {
			headers["Transport"] += `;mode="RECORD"`
		}
		return "200 OK"
	}
	return "461 Unsupported Transport"
}

func chooseRTSPChannels(pair rtspChannelPair, used *[256]bool) (rtspChannelPair, bool) {
	if pair[0] >= 0 {
		if pair[1] == -1 {
			if used[pair[0]] {
				return pair, false
			}
			for control := pair[0] + 1; control < len(used); control++ {
				if !used[control] {
					return rtspChannelPair{pair[0], control}, true
				}
			}
			return pair, false
		}
		return pair, pair[0] < pair[1] && !used[pair[0]] && !used[pair[1]]
	}
	for channel := 0; channel+1 < len(used); channel++ {
		if !used[channel] && !used[channel+1] {
			return rtspChannelPair{channel, channel + 1}, true
		}
	}
	return pair, false
}

type rtspTransportChoice struct {
	pair   rtspChannelPair
	record bool
}

func rtspTransportOffer(offer string) (choice rtspTransportChoice, supported, valid bool) {
	choice.pair = rtspChannelPair{-1, -1}
	fields, valid := splitRTSPField(offer, ';')
	if !valid {
		return choice, false, false
	}
	profile := strings.Split(fields[0], "/")
	if len(profile) < 2 || len(profile) > 3 {
		return choice, false, false
	}
	for _, component := range profile {
		if !validRTSPToken(component) {
			return choice, false, false
		}
	}
	params := make(map[string]bool, len(fields)-1)
	supported = strings.EqualFold(fields[0], "RTP/AVP/TCP")
	for _, field := range fields[1:] {
		key, value, assigned := strings.Cut(field, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !validRTSPToken(key) || params[key] {
			return choice, false, false
		}
		params[key] = true
		value, valid = rtspTransportValue(strings.TrimSpace(value))
		if !valid {
			return choice, false, false
		}
		switch key {
		case "unicast", "multicast", "append":
			if assigned {
				return choice, false, false
			}
		case "interleaved":
			choice.pair, valid = parseRTSPTransportRange(value, 8)
			if !valid {
				return choice, false, false
			}
		case "mode":
			for i, mode := range strings.Split(value, ",") {
				switch strings.ToUpper(strings.TrimSpace(mode)) {
				case "PLAY":
				case "RECORD":
					if i == 0 {
						choice.record = true
					}
				default:
					return choice, false, false
				}
			}
		case "port", "client_port", "server_port":
			if _, valid := parseRTSPTransportRange(value, 16); !valid {
				return choice, false, false
			}
		case "ttl":
			if _, err := strconv.ParseUint(value, 10, 8); err != nil || !rtspDecimal(value) {
				return choice, false, false
			}
		case "destination":
			if assigned && net.ParseIP(value) == nil {
				return choice, false, false
			}
		case "ssrc":
			if _, err := strconv.ParseUint(value, 16, 32); len(value) != 8 || err != nil {
				return choice, false, false
			}
		}
	}
	if params["unicast"] && params["multicast"] {
		return choice, false, false
	}
	return choice, supported && !params["multicast"], true
}

func splitRTSPField(value string, delimiter byte) ([]string, bool) {
	var fields []string
	start := 0
	quoted := false
	for i := 0; i < len(value); i++ {
		char := value[i]
		switch {
		case quoted && char == '\\':
			i++
		case char == '"':
			quoted = !quoted
		case char == delimiter && !quoted:
			fields = append(fields, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	if quoted {
		return nil, false
	}
	return append(fields, strings.TrimSpace(value[start:])), true
}

func rtspTransportValue(value string) (string, bool) {
	if !strings.HasPrefix(value, `"`) {
		return value, !strings.ContainsRune(value, '"')
	}
	var unquoted strings.Builder
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '"':
			return unquoted.String(), i == len(value)-1
		case '\\':
			i++
			if i == len(value) {
				return "", false
			}
		}
		unquoted.WriteByte(value[i])
	}
	return "", false
}

func parseRTSPTransportRange(value string, bits int) (rtspChannelPair, bool) {
	first, second, paired := strings.Cut(value, "-")
	start, err := strconv.ParseUint(first, 10, bits)
	if err != nil || !rtspDecimal(first) {
		return rtspChannelPair{}, false
	}
	if !paired {
		return rtspChannelPair{int(start), -1}, true
	}
	end, err := strconv.ParseUint(second, 10, bits)
	return rtspChannelPair{int(start), int(end)}, err == nil && rtspDecimal(second) && start <= end
}
