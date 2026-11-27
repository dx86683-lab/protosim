package network

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CapacitorSet/ja3-server/crypto/tls"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/telemetry"
)

// SessionTracker maps active (protocol, remoteAddr) pairs to their current Session ID
// so protocol logrus events and credentials link directly to the live session timeline.
type SessionTracker struct {
	mu   sync.RWMutex
	byKey map[string]*activeSessionMeta
}

type activeSessionMeta struct {
	sessionID  string
	scannerTag string
	localPort  uint16
}

func NewSessionTracker() *SessionTracker {
	return &SessionTracker{byKey: make(map[string]*activeSessionMeta)}
}

func (st *SessionTracker) Register(protocol, remoteAddr string, meta *activeSessionMeta) {
	st.mu.Lock()
	st.byKey[strings.ToLower(protocol)+"|"+remoteAddr] = meta
	st.mu.Unlock()
}

func (st *SessionTracker) UpdateTag(protocol, remoteAddr, tag string) {
	st.mu.Lock()
	if m, ok := st.byKey[strings.ToLower(protocol)+"|"+remoteAddr]; ok && tag != "" {
		m.scannerTag = tag
	}
	st.mu.Unlock()
}

func (st *SessionTracker) Unregister(protocol, remoteAddr string) {
	st.mu.Lock()
	delete(st.byKey, strings.ToLower(protocol)+"|"+remoteAddr)
	st.mu.Unlock()
}

func (st *SessionTracker) Lookup(protocol, remoteAddr string) (*activeSessionMeta, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	m, ok := st.byKey[strings.ToLower(protocol)+"|"+remoteAddr]
	return m, ok
}

// TelemetryConn wraps a net.Conn to record directional payloads (bounded to 64 KiB),
// first-packet probe deduplication, JA3 fingerprints, byte counts, and session lifecycle.
type TelemetryConn struct {
	mu          sync.Mutex
	conn        net.Conn
	bus         *telemetry.Bus
	tracker     *SessionTracker
	sessionID   string
	protocol    string
	transport   string
	localIP     string
	localPort   uint16
	remoteIP    string
	remotePort  uint16
	remoteKey   string
	startedAt   time.Time
	probeHash   string
	scannerTag  string
	ja3         string
	bytesIn     int64
	bytesOut    int64
	captured    int
	maxCapture  int
	seq         int
	firstRead   bool
	suppressReq bool
	parseOK     bool
	status      string
	closed      atomic.Bool
}

func NewTelemetryConn(conn net.Conn, bus *telemetry.Bus, tracker *SessionTracker, protocol string, localIP string, localPort uint16) *TelemetryConn {
	rIP, rPort := splitHostPort(conn.RemoteAddr())
	addrIP, addrPort := splitHostPort(conn.LocalAddr())
	lIP := localIP
	if lIP == "" || lIP == "0.0.0.0" || lIP == "::" {
		lIP = addrIP
	}
	lPort := localPort
	if lPort == 0 {
		lPort = addrPort
	}
	maxCap := 65536
	if bus != nil {
		if m := bus.StorageConfig().MaxPayloadBytes; m > 0 {
			maxCap = m
		}
	}
	sid := uuid.NewString()
	now := time.Now().UTC()
	tag := "unknown"
	if bus != nil {
		tag = bus.Attributor().Match(telemetry.AttributionInput{RemoteIP: rIP})
	}
	rKey := ""
	if conn.RemoteAddr() != nil {
		rKey = conn.RemoteAddr().String()
	}

	tc := &TelemetryConn{
		conn:       conn,
		bus:        bus,
		tracker:    tracker,
		sessionID:  sid,
		protocol:   protocol,
		transport:  "tcp",
		localIP:    lIP,
		localPort:  lPort,
		remoteIP:   rIP,
		remotePort: rPort,
		remoteKey:  rKey,
		startedAt:  now,
		scannerTag: tag,
		maxCapture: maxCap,
		parseOK:    true,
		status:     "open",
	}

	if tracker != nil && rKey != "" {
		tracker.Register(protocol, rKey, &activeSessionMeta{
			sessionID:  sid,
			scannerTag: tag,
			localPort:  lPort,
		})
	}
	if bus != nil {
		bus.RecordSession(tc.snapshot("open"))
		bus.RecordEvent(telemetry.Event{
			SessionID: sid,
			Timestamp: now,
			Protocol:  protocol,
			RemoteIP:  rIP,
			LocalPort: lPort,
			Kind:      "conn_open",
			Summary:   fmt.Sprintf("TCP connection from %s:%d", rIP, rPort),
		})
	}
	return tc
}

func (tc *TelemetryConn) SessionID() string { return tc.sessionID }

func (tc *TelemetryConn) GetConn() net.Conn {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.conn
}

func (tc *TelemetryConn) UpdateConn(c net.Conn) {
	tc.mu.Lock()
	tc.conn = c
	tc.mu.Unlock()
}

func (tc *TelemetryConn) SuppressRequestCapture() {
	tc.mu.Lock()
	tc.suppressReq = true
	tc.mu.Unlock()
}

func (tc *TelemetryConn) MarkParseError(reason string) {
	tc.mu.Lock()
	tc.parseOK = false
	tc.status = "parse_error"
	sid := tc.sessionID
	proto := tc.protocol
	rIP := tc.remoteIP
	lPort := tc.localPort
	tc.mu.Unlock()

	if tc.bus != nil && reason != "" {
		tc.bus.RecordEvent(telemetry.Event{
			SessionID: sid,
			Timestamp: time.Now().UTC(),
			Protocol:  proto,
			RemoteIP:  rIP,
			LocalPort: lPort,
			Kind:      "parse_error",
			Summary:   reason,
		})
	}
}

// Handshake implements ssl.SslConn when the underlying connection is a ja3-server tls.Conn.
func (tc *TelemetryConn) Handshake() error {
	tc.mu.Lock()
	c := tc.conn
	tc.mu.Unlock()

	if tlsConn, ok := c.(*tls.Conn); ok {
		err := tlsConn.Handshake()
		if err == nil {
			if fp := tlsConn.JA3Fingerprint; fp != "" {
				sum := md5.Sum([]byte(fp))
				j := hex.EncodeToString(sum[:])
				tc.mu.Lock()
				tc.ja3 = j
				if tc.bus != nil {
					if tag := tc.bus.Attributor().Match(telemetry.AttributionInput{RemoteIP: tc.remoteIP, JA3: j}); tag != "unknown" {
						tc.scannerTag = tag
						if tc.tracker != nil && tc.remoteKey != "" {
							tc.tracker.UpdateTag(tc.protocol, tc.remoteKey, tag)
						}
					}
				}
				tc.mu.Unlock()
			}
		}
		return err
	}
	return nil
}

func (tc *TelemetryConn) Read(b []byte) (int, error) {
	tc.mu.Lock()
	c := tc.conn
	tc.mu.Unlock()

	n, err := c.Read(b)
	if n > 0 {
		tc.onData("in", b[:n])
	}
	return n, err
}

func (tc *TelemetryConn) Write(b []byte) (int, error) {
	tc.mu.Lock()
	c := tc.conn
	tc.mu.Unlock()

	n, err := c.Write(b)
	if n > 0 {
		tc.onData("out", b[:n])
	}
	return n, err
}

func (tc *TelemetryConn) onData(dir string, data []byte) {
	tc.mu.Lock()
	if dir == "in" {
		tc.bytesIn += int64(len(data))
	} else {
		tc.bytesOut += int64(len(data))
	}

	// Check JA3 lazily if underlying conn is TLS and completed handshake inside Read/Write.
	if tc.ja3 == "" {
		if tlsConn, ok := tc.conn.(*tls.Conn); ok {
			if fp := tlsConn.JA3Fingerprint; fp != "" {
				sum := md5.Sum([]byte(fp))
				tc.ja3 = hex.EncodeToString(sum[:])
			}
		}
	}

	var firstPayload []byte
	if dir == "in" && !tc.firstRead && !tc.suppressReq && len(data) > 0 {
		tc.firstRead = true
		firstPayload = make([]byte, len(data))
		copy(firstPayload, data)
	}

	var chunk []byte
	var seq int
	if !tc.suppressReq && tc.captured < tc.maxCapture && len(data) > 0 {
		rem := tc.maxCapture - tc.captured
		take := len(data)
		if take > rem {
			take = rem
		}
		chunk = make([]byte, take)
		copy(chunk, data[:take])
		tc.captured += take
		tc.seq++
		seq = tc.seq
	}

	sid := tc.sessionID
	proto := tc.protocol
	transport := tc.transport
	lPort := tc.localPort
	rIP := tc.remoteIP
	ja3 := tc.ja3
	tc.mu.Unlock()

	if tc.bus == nil {
		return
	}
	if len(firstPayload) > 0 {
		hash, tag := tc.bus.RecordProbeHit(proto, transport, lPort, rIP, ja3, sid, firstPayload)
		tc.mu.Lock()
		tc.probeHash = hash
		if tag != "" && tag != "unknown" {
			tc.scannerTag = tag
			if tc.tracker != nil && tc.remoteKey != "" {
				tc.tracker.UpdateTag(tc.protocol, tc.remoteKey, tag)
			}
		}
		tc.mu.Unlock()
	}
	if len(chunk) > 0 {
		tc.bus.RecordPayload(telemetry.PayloadChunk{
			SessionID: sid,
			Seq:       seq,
			Timestamp: time.Now().UTC(),
			Direction: dir,
			Data:      chunk,
		})
	}
}

func (tc *TelemetryConn) Close() error {
	tc.mu.Lock()
	c := tc.conn
	tc.mu.Unlock()
	err := c.Close()

	if tc.closed.CompareAndSwap(false, true) {
		if tc.tracker != nil && tc.remoteKey != "" {
			tc.tracker.Unregister(tc.protocol, tc.remoteKey)
		}
		if tc.bus != nil {
			tc.mu.Lock()
			status := tc.status
			if status == "open" {
				switch {
				case tc.bytesIn == 0 && tc.bytesOut == 0:
					status = "connect_only"
				case tc.bytesIn == 0 && tc.bytesOut > 0:
					status = "banner_only"
				default:
					status = "closed"
				}
			}
			tc.mu.Unlock()
			snap := tc.snapshot(status)
			tc.bus.RecordSession(snap)
			tc.bus.RecordEvent(telemetry.Event{
				SessionID: snap.ID,
				Timestamp: snap.EndedAt,
				Protocol:  snap.Protocol,
				RemoteIP:  snap.RemoteIP,
				LocalPort: snap.LocalPort,
				Kind:      "conn_close",
				Summary:   fmt.Sprintf("Closed (%s, in=%dB out=%dB, %dms)", snap.Status, snap.BytesIn, snap.BytesOut, snap.DurationMs),
			})
		}
	}
	return err
}

func (tc *TelemetryConn) snapshot(status string) telemetry.Session {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	now := time.Now().UTC()
	dur := now.Sub(tc.startedAt).Milliseconds()
	if dur < 0 {
		dur = 0
	}
	return telemetry.Session{
		ID:         tc.sessionID,
		Protocol:   tc.protocol,
		Transport:  tc.transport,
		RemoteIP:   tc.remoteIP,
		RemotePort: tc.remotePort,
		LocalIP:    tc.localIP,
		LocalPort:  tc.localPort,
		JA3:        tc.ja3,
		ScannerTag: tc.scannerTag,
		ProbeHash:  tc.probeHash,
		StartedAt:  tc.startedAt,
		EndedAt:    now,
		DurationMs: dur,
		BytesIn:    tc.bytesIn,
		BytesOut:   tc.bytesOut,
		ParseOK:    tc.parseOK,
		Status:     status,
	}
}

func (tc *TelemetryConn) LocalAddr() net.Addr                { return tc.GetConn().LocalAddr() }
func (tc *TelemetryConn) RemoteAddr() net.Addr               { return tc.GetConn().RemoteAddr() }
func (tc *TelemetryConn) SetDeadline(t time.Time) error      { return tc.GetConn().SetDeadline(t) }
func (tc *TelemetryConn) SetReadDeadline(t time.Time) error  { return tc.GetConn().SetReadDeadline(t) }
func (tc *TelemetryConn) SetWriteDeadline(t time.Time) error { return tc.GetConn().SetWriteDeadline(t) }

// TelemetryListener wraps a net.Listener so every accepted connection becomes a TelemetryConn.
type TelemetryListener struct {
	mu        sync.Mutex
	listener  net.Listener
	bus       *telemetry.Bus
	tracker   *SessionTracker
	excludeFn func(net.Addr) bool
	protocol  string
	localIP   string
	localPort uint16
}

func NewTelemetryListener(ln net.Listener, bus *telemetry.Bus, tracker *SessionTracker, protocol, localIP string, localPort uint16) *TelemetryListener {
	return &TelemetryListener{
		listener:  ln,
		bus:       bus,
		tracker:   tracker,
		protocol:  protocol,
		localIP:   localIP,
		localPort: localPort,
	}
}

func (tl *TelemetryListener) GetListener() net.Listener {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.listener
}

func (tl *TelemetryListener) UpdateListener(ln net.Listener) {
	tl.mu.Lock()
	tl.listener = ln
	tl.mu.Unlock()
}

func (tl *TelemetryListener) SetExcludeFn(fn func(net.Addr) bool) {
	tl.mu.Lock()
	tl.excludeFn = fn
	tl.mu.Unlock()
}

func (tl *TelemetryListener) Accept() (net.Conn, error) {
	c, err := tl.GetListener().Accept()
	if err != nil {
		return nil, err
	}
	bus := tl.bus
	tl.mu.Lock()
	excl := tl.excludeFn
	tl.mu.Unlock()
	if excl != nil && excl(c.RemoteAddr()) {
		bus = nil
	}
	return NewTelemetryConn(c, bus, tl.tracker, tl.protocol, tl.localIP, tl.localPort), nil
}

func (tl *TelemetryListener) Close() error   { return tl.GetListener().Close() }
func (tl *TelemetryListener) Addr() net.Addr { return tl.GetListener().Addr() }

// TelemetryHook bridges logrus entries emitted by all protocol handlers into telemetry.Bus.
type TelemetryHook struct {
	bus         *telemetry.Bus
	tracker     *SessionTracker
	excludeIPFn func(ip string) bool
}

func NewTelemetryHook(bus *telemetry.Bus, tracker *SessionTracker) *TelemetryHook {
	return &TelemetryHook{bus: bus, tracker: tracker}
}

func (h *TelemetryHook) SetExcludeIPFn(fn func(ip string) bool) {
	h.excludeIPFn = fn
}

func (h *TelemetryHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
	}
}

func (h *TelemetryHook) Fire(entry *logrus.Entry) error {
	if h.bus == nil || entry == nil {
		return nil
	}
	proto := stringField(entry.Data, "protocol")
	if proto == "" {
		proto = stringField(entry.Data, "handler")
	}
	remoteIP := stringField(entry.Data, "remote_ip")
	remoteAddr := stringField(entry.Data, "remote")
	if proto == "" && remoteIP == "" {
		return nil
	}
	if h.excludeIPFn != nil {
		checkIP := remoteIP
		if checkIP == "" && remoteAddr != "" {
			if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
				checkIP = host
			} else {
				checkIP = remoteAddr
			}
		}
		if checkIP != "" && h.excludeIPFn(checkIP) {
			return nil
		}
	}
	if proto == "" {
		proto = "capture"
	}

	var sid string
	var scannerTag string
	var localPort uint16
	if lp, ok := entry.Data["local_port"]; ok {
		switch v := lp.(type) {
		case int:
			localPort = uint16(v)
		case uint16:
			localPort = v
		case float64:
			localPort = uint16(v)
		}
	}
	if localPort == 0 {
		if loc := stringField(entry.Data, "local"); loc != "" {
			if _, portStr, err := net.SplitHostPort(loc); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil {
					localPort = uint16(p)
				}
			}
		}
	}

	if h.tracker != nil && remoteAddr != "" {
		if meta, ok := h.tracker.Lookup(proto, remoteAddr); ok {
			sid = meta.sessionID
			scannerTag = meta.scannerTag
			if localPort == 0 {
				localPort = meta.localPort
			}
		}
	}

	detailData := entry.Data
	if h.bus.StorageConfig().RedactCredentials && len(entry.Data) > 0 {
		redacted := make(logrus.Fields, len(entry.Data))
		for k, v := range entry.Data {
			if isSensitiveEventKey(k) {
				if s, ok := v.(string); ok && s != "" {
					redacted[k] = "***REDACTED***"
					continue
				}
			}
			redacted[k] = v
		}
		detailData = redacted
	}
	detailBytes, _ := json.Marshal(detailData)
	kind := classifyEventKind(entry.Message, detailData)
	h.bus.RecordEvent(telemetry.Event{
		SessionID:  sid,
		Timestamp:  entry.Time.UTC(),
		Protocol:   strings.ToLower(proto),
		RemoteIP:   remoteIP,
		LocalPort:  localPort,
		Kind:       kind,
		Summary:    entry.Message,
		DetailJSON: string(detailBytes),
	})

	// Automatically extract credentials if present in structured fields.
	user := firstNonEmpty(
		stringField(entry.Data, "user"),
		stringField(entry.Data, "username"),
		stringField(entry.Data, "account"),
		stringField(entry.Data, "login"),
	)
	pass := firstNonEmpty(
		stringField(entry.Data, "password"),
		stringField(entry.Data, "pass"),
		stringField(entry.Data, "passwd"),
		stringField(entry.Data, "secret"),
		stringField(entry.Data, "token"),
	)
	if user != "" || pass != "" {
		mech := firstNonEmpty(stringField(entry.Data, "mechanism"), stringField(entry.Data, "auth_type"), entry.Message)
		accepted := false
		if v, ok := entry.Data["accepted"].(bool); ok {
			accepted = v
		} else if v, ok := entry.Data["success"].(bool); ok {
			accepted = v
		}
		h.bus.RecordCredential(telemetry.Credential{
			SessionID:  sid,
			Timestamp:  entry.Time.UTC(),
			Protocol:   strings.ToLower(proto),
			RemoteIP:   remoteIP,
			ScannerTag: scannerTag,
			Username:   user,
			Secret:     pass,
			Mechanism:  mech,
			Accepted:   accepted,
		})
	}
	return nil
}

func classifyEventKind(msg string, fields logrus.Fields) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "auth") || strings.Contains(m, "login") || strings.Contains(m, "password"):
		return "auth"
	case strings.Contains(m, "error") || strings.Contains(m, "fail"):
		return "parse_error"
	case strings.Contains(m, "cmd") || strings.Contains(m, "exec") || strings.Contains(m, "command"):
		return "command"
	case m == "tcp_syn" || m == "udp_packet" || m == "icmp_ping":
		return "capture"
	default:
		if _, ok := fields["username"]; ok {
			return "auth"
		}
		return "request"
	}
}

func stringField(fields logrus.Fields, key string) string {
	if fields == nil {
		return ""
	}
	v, ok := fields[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func isSensitiveEventKey(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "password", "pass", "passwd", "secret", "token", "authorization", "credential", "apikey", "api_key":
		return true
	default:
		return false
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitHostPort(addr net.Addr) (string, uint16) {
	if addr == nil {
		return "", 0
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), uint16(a.Port)
	case *net.UDPAddr:
		return a.IP.String(), uint16(a.Port)
	default:
		h, p, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String(), 0
		}
		pn, _ := strconv.Atoi(p)
		return h, uint16(pn)
	}
}
