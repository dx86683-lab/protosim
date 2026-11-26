package telemetry

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Store provides thread-safe SQLite WAL persistence and analytics for ProtoSim.
type Store struct {
	dbPath string
	db     *sql.DB
	writeM sync.Mutex // serializes multi-statement write transactions cleanly under WAL
}

// OpenStore opens or creates the SQLite WAL database and initializes all tables/indexes.
func OpenStore(dbPath string) (*Store, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA temp_store=MEMORY;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("exec pragma %q: %w", p, err)
		}
	}

	s := &Store{dbPath: dbPath, db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.seedDefaults(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			protocol TEXT NOT NULL,
			transport TEXT NOT NULL,
			remote_ip TEXT NOT NULL,
			remote_port INTEGER NOT NULL DEFAULT 0,
			local_ip TEXT NOT NULL DEFAULT '',
			local_port INTEGER NOT NULL DEFAULT 0,
			country TEXT NOT NULL DEFAULT '',
			ja3 TEXT NOT NULL DEFAULT '',
			scanner_tag TEXT NOT NULL DEFAULT 'unknown',
			probe_hash TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			ended_at INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			bytes_in INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			event_count INTEGER NOT NULL DEFAULT 0,
			parse_ok INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'open'
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_proto_started ON sessions(protocol, started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_remote_ip ON sessions(remote_ip);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_scanner ON sessions(scanner_tag);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_probe ON sessions(probe_hash);`,

		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			ts INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			remote_ip TEXT NOT NULL,
			local_port INTEGER NOT NULL DEFAULT 0,
			kind TEXT NOT NULL,
			summary TEXT NOT NULL DEFAULT '',
			detail_json TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, id ASC);`,
		`CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol, ts DESC);`,

		`CREATE TABLE IF NOT EXISTS probes (
			hash TEXT PRIMARY KEY,
			protocol TEXT NOT NULL,
			transport TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 0,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 1,
			unique_ips INTEGER NOT NULL DEFAULT 1,
			sample_payload BLOB,
			sample_session_id TEXT NOT NULL DEFAULT '',
			scanner_tags TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL DEFAULT 'new',
			note TEXT NOT NULL DEFAULT '',
			pinned INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_probes_last_seen ON probes(last_seen DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_probes_proto_status ON probes(protocol, status);`,

		`CREATE TABLE IF NOT EXISTS probe_ips (
			probe_hash TEXT NOT NULL,
			remote_ip TEXT NOT NULL,
			PRIMARY KEY (probe_hash, remote_ip)
		);`,

		`CREATE TABLE IF NOT EXISTS credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			ts INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			remote_ip TEXT NOT NULL,
			scanner_tag TEXT NOT NULL DEFAULT 'unknown',
			username TEXT NOT NULL DEFAULT '',
			secret TEXT NOT NULL DEFAULT '',
			mechanism TEXT NOT NULL DEFAULT '',
			accepted INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_ts ON credentials(ts DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);`,

		`CREATE TABLE IF NOT EXISTS payloads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			ts INTEGER NOT NULL,
			direction TEXT NOT NULL,
			data BLOB NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_payloads_session ON payloads(session_id, seq ASC);`,

		`CREATE TABLE IF NOT EXISTS test_runs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			scenario TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			ended_at INTEGER NOT NULL DEFAULT 0,
			target_protocols_json TEXT NOT NULL DEFAULT '[]',
			notes TEXT NOT NULL DEFAULT ''
		);`,

		`CREATE TABLE IF NOT EXISTS scanner_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			tag TEXT NOT NULL,
			match_type TEXT NOT NULL,
			pattern TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);`,

		`CREATE TABLE IF NOT EXISTS scenarios (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			config_json TEXT NOT NULL DEFAULT '{}',
			updated_at INTEGER NOT NULL
		);`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

func (s *Store) seedDefaults() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM scanner_rules`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		for _, r := range DefaultScannerRules() {
			if _, err := s.CreateScannerRule(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// ComputeProbeHash computes the canonical deduplication key for a probe.
func ComputeProbeHash(protocol string, port uint16, firstPayload []byte) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(protocol)))
	h.Write([]byte{':'})
	h.Write([]byte(fmt.Sprintf("%d", port)))
	h.Write([]byte{':'})
	h.Write(firstPayload)
	return hex.EncodeToString(h.Sum(nil))
}

// FormatASCII returns a printable ASCII preview where non-printable bytes become '.'.
func FormatASCII(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(data))
	for _, c := range data {
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else if c == '\r' || c == '\n' || c == '\t' {
			b.WriteByte(' ')
		} else if unicode.IsPrint(rune(c)) && c < 128 {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

// BatchWriteItem represents a single write operation queued through the telemetry Bus.
type BatchWriteItem struct {
	Session    *Session
	Event      *Event
	Credential *Credential
	Payload    *PayloadChunk
	ProbeHit   *ProbeHitInput
}

type ProbeHitInput struct {
	Hash       string
	Protocol   string
	Transport  string
	Port       uint16
	Timestamp  time.Time
	RemoteIP   string
	ScannerTag string
	SessionID  string
	Payload    []byte
}

// WriteBatch commits a slice of telemetry records in a single SQLite transaction.
// It returns any newly discovered Probes so the Bus can notify SSE/Webhook subscribers.
func (s *Store) WriteBatch(items []BatchWriteItem) ([]Probe, error) {
	if len(items) == 0 {
		return nil, nil
	}
	s.writeM.Lock()
	defer s.writeM.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	var newProbes []Probe

	for _, it := range items {
		if it.Session != nil {
			sess := it.Session
			parseOK := 0
			if sess.ParseOK {
				parseOK = 1
			}
			_, err := tx.Exec(`
				INSERT INTO sessions (
					id, protocol, transport, remote_ip, remote_port, local_ip, local_port,
					country, ja3, scanner_tag, probe_hash, started_at, ended_at, duration_ms,
					bytes_in, bytes_out, event_count, parse_ok, status
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(id) DO UPDATE SET
					ja3 = CASE WHEN excluded.ja3 != '' THEN excluded.ja3 ELSE sessions.ja3 END,
					scanner_tag = CASE WHEN excluded.scanner_tag != '' AND excluded.scanner_tag != 'unknown' THEN excluded.scanner_tag ELSE sessions.scanner_tag END,
					probe_hash = CASE WHEN excluded.probe_hash != '' THEN excluded.probe_hash ELSE sessions.probe_hash END,
					ended_at = CASE WHEN excluded.ended_at > sessions.ended_at THEN excluded.ended_at ELSE sessions.ended_at END,
					duration_ms = CASE WHEN excluded.duration_ms > sessions.duration_ms THEN excluded.duration_ms ELSE sessions.duration_ms END,
					bytes_in = CASE WHEN excluded.bytes_in > sessions.bytes_in THEN excluded.bytes_in ELSE sessions.bytes_in END,
					bytes_out = CASE WHEN excluded.bytes_out > sessions.bytes_out THEN excluded.bytes_out ELSE sessions.bytes_out END,
					event_count = CASE WHEN excluded.event_count > sessions.event_count THEN excluded.event_count ELSE sessions.event_count END,
					parse_ok = CASE WHEN excluded.parse_ok = 0 THEN 0 ELSE sessions.parse_ok END,
					status = CASE WHEN excluded.status != 'open' THEN excluded.status ELSE sessions.status END
			`,
				sess.ID, sess.Protocol, sess.Transport, sess.RemoteIP, sess.RemotePort,
				sess.LocalIP, sess.LocalPort, sess.Country, sess.JA3, sess.ScannerTag,
				sess.ProbeHash, sess.StartedAt.UnixMilli(), sess.EndedAt.UnixMilli(),
				sess.DurationMs, sess.BytesIn, sess.BytesOut, sess.EventCount, parseOK, sess.Status,
			)
			if err != nil {
				return nil, fmt.Errorf("upsert session: %w", err)
			}
		}

		if it.Event != nil {
			ev := it.Event
			_, err := tx.Exec(`
				INSERT INTO events (session_id, ts, protocol, remote_ip, local_port, kind, summary, detail_json)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`, ev.SessionID, ev.Timestamp.UnixMilli(), ev.Protocol, ev.RemoteIP, ev.LocalPort, ev.Kind, ev.Summary, ev.DetailJSON)
			if err != nil {
				return nil, fmt.Errorf("insert event: %w", err)
			}
			_, _ = tx.Exec(`UPDATE sessions SET event_count = event_count + 1 WHERE id = ?`, ev.SessionID)
		}

		if it.Credential != nil {
			cr := it.Credential
			acc := 0
			if cr.Accepted {
				acc = 1
			}
			_, err := tx.Exec(`
				INSERT INTO credentials (session_id, ts, protocol, remote_ip, scanner_tag, username, secret, mechanism, accepted)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, cr.SessionID, cr.Timestamp.UnixMilli(), cr.Protocol, cr.RemoteIP, cr.ScannerTag, cr.Username, cr.Secret, cr.Mechanism, acc)
			if err != nil {
				return nil, fmt.Errorf("insert credential: %w", err)
			}
		}

		if it.Payload != nil {
			pl := it.Payload
			_, err := tx.Exec(`
				INSERT INTO payloads (session_id, seq, ts, direction, data)
				VALUES (?, ?, ?, ?, ?)
			`, pl.SessionID, pl.Seq, pl.Timestamp.UnixMilli(), pl.Direction, pl.Data)
			if err != nil {
				return nil, fmt.Errorf("insert payload: %w", err)
			}
		}

		if it.ProbeHit != nil {
			p, isNew, err := upsertProbeTx(tx, *it.ProbeHit)
			if err != nil {
				return nil, err
			}
			if isNew {
				p.IsNew = true
				newProbes = append(newProbes, p)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	tx = nil
	return newProbes, nil
}

func upsertProbeTx(tx *sql.Tx, in ProbeHitInput) (Probe, bool, error) {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	tsMs := ts.UnixMilli()

	var existingTags string
	var hitCount int64
	err := tx.QueryRow(`SELECT scanner_tags, hit_count FROM probes WHERE hash = ?`, in.Hash).Scan(&existingTags, &hitCount)
	if err == sql.ErrNoRows {
		tags := []string{}
		if in.ScannerTag != "" {
			tags = append(tags, in.ScannerTag)
		}
		tagsJSON, _ := json.Marshal(tags)
		sample := in.Payload
		if len(sample) > 8192 {
			sample = sample[:8192]
		}
		_, err = tx.Exec(`
			INSERT INTO probes (
				hash, protocol, transport, port, first_seen, last_seen,
				hit_count, unique_ips, sample_payload, sample_session_id,
				scanner_tags, status, note, pinned
			) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, 'new', '', 0)
		`, in.Hash, in.Protocol, in.Transport, in.Port, tsMs, tsMs, sample, in.SessionID, string(tagsJSON))
		if err != nil {
			return Probe{}, false, fmt.Errorf("insert probe: %w", err)
		}
		if in.RemoteIP != "" {
			_, _ = tx.Exec(`INSERT OR IGNORE INTO probe_ips (probe_hash, remote_ip) VALUES (?, ?)`, in.Hash, in.RemoteIP)
		}
		return Probe{
			Hash:            in.Hash,
			Protocol:        in.Protocol,
			Transport:       in.Transport,
			Port:            in.Port,
			FirstSeen:       ts,
			LastSeen:        ts,
			HitCount:        1,
			UniqueIPs:       1,
			SamplePayload:   sample,
			SampleHex:       hex.EncodeToString(sample),
			SampleASCII:     FormatASCII(sample),
			SampleSessionID: in.SessionID,
			ScannerTags:     tags,
			Status:          "new",
		}, true, nil
	}
	if err != nil {
		return Probe{}, false, fmt.Errorf("select probe: %w", err)
	}

	var tags []string
	_ = json.Unmarshal([]byte(existingTags), &tags)
	if in.ScannerTag != "" && !containsString(tags, in.ScannerTag) {
		tags = append(tags, in.ScannerTag)
		sort.Strings(tags)
	}
	tagsJSON, _ := json.Marshal(tags)

	if in.RemoteIP != "" {
		_, _ = tx.Exec(`INSERT OR IGNORE INTO probe_ips (probe_hash, remote_ip) VALUES (?, ?)`, in.Hash, in.RemoteIP)
	}
	var uniqueIPs int64
	_ = tx.QueryRow(`SELECT COUNT(1) FROM probe_ips WHERE probe_hash = ?`, in.Hash).Scan(&uniqueIPs)
	if uniqueIPs == 0 {
		uniqueIPs = 1
	}

	_, err = tx.Exec(`
		UPDATE probes
		SET last_seen = CASE WHEN ? > last_seen THEN ? ELSE last_seen END,
			hit_count = hit_count + 1,
			unique_ips = ?,
			scanner_tags = ?
		WHERE hash = ?
	`, tsMs, tsMs, uniqueIPs, string(tagsJSON), in.Hash)
	if err != nil {
		return Probe{}, false, fmt.Errorf("update probe: %w", err)
	}
	return Probe{Hash: in.Hash, HitCount: hitCount + 1, UniqueIPs: uniqueIPs, ScannerTags: tags}, false, nil
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// QueryOverview returns aggregated KPIs, time-series buckets, and TopN breakdowns.
func (s *Store) QueryOverview(window string) (*OverviewStats, error) {
	now := time.Now().UTC()
	var since time.Time
	var bucketMs int64
	switch window {
	case "1h":
		since = now.Add(-1 * time.Hour)
		bucketMs = 5 * 60 * 1000 // 5m buckets
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		bucketMs = 6 * 3600 * 1000 // 6h buckets
	default:
		window = "24h"
		since = now.Add(-24 * time.Hour)
		bucketMs = 3600 * 1000 // 1h buckets
	}
	sinceMs := since.UnixMilli()

	stats := &OverviewStats{
		Window:          window,
		Timeline:        []TimeBucket{},
		TopProtocols:    []NameCount{},
		TopScanners:     []NameCount{},
		TopSourceIPs:    []NameCount{},
		TopCountries:    []NameCount{},
		RecentNewProbes: []Probe{},
	}

	_ = s.db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE started_at >= ?`, sinceMs).Scan(&stats.TotalSessions)
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM events WHERE ts >= ?`, sinceMs).Scan(&stats.TotalEvents)
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM probes`).Scan(&stats.UniqueProbes)
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM probes WHERE status = 'new'`).Scan(&stats.NewProbes)
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM credentials WHERE ts >= ?`, sinceMs).Scan(&stats.TotalCreds)
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT remote_ip) FROM sessions WHERE started_at >= ?`, sinceMs).Scan(&stats.UniqueIPs)
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE started_at >= ? AND parse_ok = 0`, sinceMs).Scan(&stats.ParseErrorCount)

	if s.dbPath != ":memory:" {
		if fi, err := os.Stat(s.dbPath); err == nil {
			stats.DBSizeBytes = fi.Size()
		}
	}

	// Timeline buckets
	bucketMap := map[int64]*TimeBucket{}
	rows, err := s.db.Query(`
		SELECT (started_at / ?) * ? AS b, COUNT(1)
		FROM sessions WHERE started_at >= ?
		GROUP BY b ORDER BY b ASC
	`, bucketMs, bucketMs, sinceMs)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var b, cnt int64
			if err := rows.Scan(&b, &cnt); err == nil {
				bucketMap[b] = &TimeBucket{
					Bucket:   time.UnixMilli(b).UTC().Format("01-02 15:04"),
					Sessions: cnt,
				}
			}
		}
	}

	evRows, err := s.db.Query(`
		SELECT (ts / ?) * ? AS b, COUNT(1)
		FROM events WHERE ts >= ?
		GROUP BY b ORDER BY b ASC
	`, bucketMs, bucketMs, sinceMs)
	if err == nil {
		defer evRows.Close()
		for evRows.Next() {
			var b, cnt int64
			if err := evRows.Scan(&b, &cnt); err == nil {
				tb, ok := bucketMap[b]
				if !ok {
					tb = &TimeBucket{Bucket: time.UnixMilli(b).UTC().Format("01-02 15:04")}
					bucketMap[b] = tb
				}
				tb.Events = cnt
			}
		}
	}

	keys := make([]int64, 0, len(bucketMap))
	for k := range bucketMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		stats.Timeline = append(stats.Timeline, *bucketMap[k])
	}

	stats.TopProtocols = s.queryTopN(`SELECT protocol, COUNT(1) FROM sessions WHERE started_at >= ? GROUP BY protocol ORDER BY COUNT(1) DESC LIMIT 12`, sinceMs)
	stats.TopScanners = s.queryTopN(`SELECT scanner_tag, COUNT(1) FROM sessions WHERE started_at >= ? GROUP BY scanner_tag ORDER BY COUNT(1) DESC LIMIT 10`, sinceMs)
	stats.TopSourceIPs = s.queryTopN(`SELECT remote_ip, COUNT(1) FROM sessions WHERE started_at >= ? GROUP BY remote_ip ORDER BY COUNT(1) DESC LIMIT 10`, sinceMs)
	stats.TopCountries = s.queryTopN(`SELECT CASE WHEN country='' THEN 'LAN/Unknown' ELSE country END AS c, COUNT(1) FROM sessions WHERE started_at >= ? GROUP BY c ORDER BY COUNT(1) DESC LIMIT 10`, sinceMs)

	probes, _, err := s.QueryProbes(ProbeFilter{Status: "new", Limit: 8})
	if err == nil {
		stats.RecentNewProbes = probes
	}

	return stats, nil
}

func (s *Store) queryTopN(q string, args ...any) []NameCount {
	out := []NameCount{}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Name, &nc.Count); err == nil {
			out = append(out, nc)
		}
	}
	return out
}

// SessionFilter controls pagination & filtering for GET /api/v2/sessions.
type SessionFilter struct {
	Protocol   string
	RemoteIP   string
	ScannerTag string
	ProbeHash  string
	Status     string
	ParseOnly  string // "ok" | "error"
	Page       int
	Limit      int
}

func (s *Store) QuerySessions(f SessionFilter) ([]Session, int64, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	where, args := buildSessionWhere(f)

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM sessions`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (f.Page - 1) * f.Limit
	qArgs := append(append([]any{}, args...), f.Limit, offset)
	rows, err := s.db.Query(`
		SELECT id, protocol, transport, remote_ip, remote_port, local_ip, local_port,
			country, ja3, scanner_tag, probe_hash, started_at, ended_at, duration_ms,
			bytes_in, bytes_out, event_count, parse_ok, status
		FROM sessions`+where+` ORDER BY started_at DESC LIMIT ? OFFSET ?`, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sess)
	}
	return out, total, nil
}

func buildSessionWhere(f SessionFilter) (string, []any) {
	var conds []string
	var args []any
	if f.Protocol != "" {
		conds = append(conds, "protocol = ?")
		args = append(args, f.Protocol)
	}
	if f.RemoteIP != "" {
		conds = append(conds, "remote_ip LIKE ?")
		args = append(args, "%"+f.RemoteIP+"%")
	}
	if f.ScannerTag != "" {
		conds = append(conds, "scanner_tag = ?")
		args = append(args, f.ScannerTag)
	}
	if f.ProbeHash != "" {
		conds = append(conds, "probe_hash = ?")
		args = append(args, f.ProbeHash)
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, f.Status)
	}
	if f.ParseOnly == "ok" {
		conds = append(conds, "parse_ok = 1")
	} else if f.ParseOnly == "error" {
		conds = append(conds, "parse_ok = 0")
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(rs rowScanner) (Session, error) {
	var sess Session
	var startedMs, endedMs int64
	var parseOK int
	err := rs.Scan(
		&sess.ID, &sess.Protocol, &sess.Transport, &sess.RemoteIP, &sess.RemotePort,
		&sess.LocalIP, &sess.LocalPort, &sess.Country, &sess.JA3, &sess.ScannerTag,
		&sess.ProbeHash, &startedMs, &endedMs, &sess.DurationMs,
		&sess.BytesIn, &sess.BytesOut, &sess.EventCount, &parseOK, &sess.Status,
	)
	if err != nil {
		return Session{}, err
	}
	sess.StartedAt = time.UnixMilli(startedMs).UTC()
	if endedMs > 0 {
		sess.EndedAt = time.UnixMilli(endedMs).UTC()
	}
	sess.ParseOK = parseOK != 0
	return sess, nil
}

// GetSessionDetail returns the session plus all its events, credentials, and raw payloads.
func (s *Store) GetSessionDetail(id string) (*SessionDetail, error) {
	row := s.db.QueryRow(`
		SELECT id, protocol, transport, remote_ip, remote_port, local_ip, local_port,
			country, ja3, scanner_tag, probe_hash, started_at, ended_at, duration_ms,
			bytes_in, bytes_out, event_count, parse_ok, status
		FROM sessions WHERE id = ?`, id)
	sess, err := scanSession(row)
	if err != nil {
		return nil, err
	}

	detail := &SessionDetail{
		Session:     sess,
		Events:      []Event{},
		Credentials: []Credential{},
		Payloads:    []PayloadChunk{},
	}

	if evRows, err := s.db.Query(`SELECT id, session_id, ts, protocol, remote_ip, local_port, kind, summary, detail_json FROM events WHERE session_id = ? ORDER BY id ASC`, id); err == nil {
		defer evRows.Close()
		for evRows.Next() {
			var ev Event
			var tsMs int64
			if err := evRows.Scan(&ev.ID, &ev.SessionID, &tsMs, &ev.Protocol, &ev.RemoteIP, &ev.LocalPort, &ev.Kind, &ev.Summary, &ev.DetailJSON); err == nil {
				ev.Timestamp = time.UnixMilli(tsMs).UTC()
				detail.Events = append(detail.Events, ev)
			}
		}
	}

	if crRows, err := s.db.Query(`SELECT id, session_id, ts, protocol, remote_ip, scanner_tag, username, secret, mechanism, accepted FROM credentials WHERE session_id = ? ORDER BY id ASC`, id); err == nil {
		defer crRows.Close()
		for crRows.Next() {
			var cr Credential
			var tsMs int64
			var acc int
			if err := crRows.Scan(&cr.ID, &cr.SessionID, &tsMs, &cr.Protocol, &cr.RemoteIP, &cr.ScannerTag, &cr.Username, &cr.Secret, &cr.Mechanism, &acc); err == nil {
				cr.Timestamp = time.UnixMilli(tsMs).UTC()
				cr.Accepted = acc != 0
				detail.Credentials = append(detail.Credentials, cr)
			}
		}
	}

	if plRows, err := s.db.Query(`SELECT id, session_id, seq, ts, direction, data FROM payloads WHERE session_id = ? ORDER BY seq ASC, id ASC`, id); err == nil {
		defer plRows.Close()
		for plRows.Next() {
			var pl PayloadChunk
			var tsMs int64
			if err := plRows.Scan(&pl.ID, &pl.SessionID, &pl.Seq, &tsMs, &pl.Direction, &pl.Data); err == nil {
				pl.Timestamp = time.UnixMilli(tsMs).UTC()
				pl.Hex = hex.EncodeToString(pl.Data)
				pl.ASCII = FormatASCII(pl.Data)
				detail.Payloads = append(detail.Payloads, pl)
			}
		}
	}

	return detail, nil
}

// QueryEvents lists recent events with optional protocol / remote_ip / kind filter.
func (s *Store) QueryEvents(protocol, remoteIP, kind string, page, limit int) ([]Event, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if page <= 0 {
		page = 1
	}
	var conds []string
	var args []any
	if protocol != "" {
		conds = append(conds, "protocol = ?")
		args = append(args, protocol)
	}
	if remoteIP != "" {
		conds = append(conds, "remote_ip LIKE ?")
		args = append(args, "%"+remoteIP+"%")
	}
	if kind != "" {
		conds = append(conds, "kind = ?")
		args = append(args, kind)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qArgs := append(append([]any{}, args...), limit, (page-1)*limit)
	rows, err := s.db.Query(`SELECT id, session_id, ts, protocol, remote_ip, local_port, kind, summary, detail_json FROM events`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var ev Event
		var tsMs int64
		if err := rows.Scan(&ev.ID, &ev.SessionID, &tsMs, &ev.Protocol, &ev.RemoteIP, &ev.LocalPort, &ev.Kind, &ev.Summary, &ev.DetailJSON); err == nil {
			ev.Timestamp = time.UnixMilli(tsMs).UTC()
			out = append(out, ev)
		}
	}
	return out, total, nil
}

// QueryCredentials lists captured credentials with pagination.
func (s *Store) QueryCredentials(protocol, remoteIP string, page, limit int) ([]Credential, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if page <= 0 {
		page = 1
	}
	var conds []string
	var args []any
	if protocol != "" {
		conds = append(conds, "protocol = ?")
		args = append(args, protocol)
	}
	if remoteIP != "" {
		conds = append(conds, "remote_ip LIKE ?")
		args = append(args, "%"+remoteIP+"%")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM credentials`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qArgs := append(append([]any{}, args...), limit, (page-1)*limit)
	rows, err := s.db.Query(`SELECT id, session_id, ts, protocol, remote_ip, scanner_tag, username, secret, mechanism, accepted FROM credentials`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var cr Credential
		var tsMs int64
		var acc int
		if err := rows.Scan(&cr.ID, &cr.SessionID, &tsMs, &cr.Protocol, &cr.RemoteIP, &cr.ScannerTag, &cr.Username, &cr.Secret, &cr.Mechanism, &acc); err == nil {
			cr.Timestamp = time.UnixMilli(tsMs).UTC()
			cr.Accepted = acc != 0
			out = append(out, cr)
		}
	}
	return out, total, nil
}

// ProbeFilter controls filtering & pagination for the Probe Library.
type ProbeFilter struct {
	Protocol   string
	Status     string
	ScannerTag string
	PinnedOnly bool
	Page       int
	Limit      int
}

func (s *Store) QueryProbes(f ProbeFilter) ([]Probe, int64, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	var conds []string
	var args []any
	if f.Protocol != "" {
		conds = append(conds, "protocol = ?")
		args = append(args, f.Protocol)
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, f.Status)
	}
	if f.ScannerTag != "" {
		conds = append(conds, "scanner_tags LIKE ?")
		args = append(args, "%\""+f.ScannerTag+"\"%")
	}
	if f.PinnedOnly {
		conds = append(conds, "pinned = 1")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM probes`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qArgs := append(append([]any{}, args...), f.Limit, (f.Page-1)*f.Limit)
	rows, err := s.db.Query(`
		SELECT hash, protocol, transport, port, first_seen, last_seen,
			hit_count, unique_ips, sample_payload, sample_session_id,
			scanner_tags, status, note, pinned
		FROM probes`+where+` ORDER BY pinned DESC, last_seen DESC LIMIT ? OFFSET ?`, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Probe{}
	for rows.Next() {
		p, err := scanProbe(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, nil
}

func (s *Store) GetProbe(hash string) (*Probe, error) {
	row := s.db.QueryRow(`
		SELECT hash, protocol, transport, port, first_seen, last_seen,
			hit_count, unique_ips, sample_payload, sample_session_id,
			scanner_tags, status, note, pinned
		FROM probes WHERE hash = ?`, hash)
	p, err := scanProbe(row)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func scanProbe(rs rowScanner) (Probe, error) {
	var p Probe
	var firstMs, lastMs int64
	var tagsJSON string
	var pinned int
	err := rs.Scan(
		&p.Hash, &p.Protocol, &p.Transport, &p.Port, &firstMs, &lastMs,
		&p.HitCount, &p.UniqueIPs, &p.SamplePayload, &p.SampleSessionID,
		&tagsJSON, &p.Status, &p.Note, &pinned,
	)
	if err != nil {
		return Probe{}, err
	}
	p.FirstSeen = time.UnixMilli(firstMs).UTC()
	p.LastSeen = time.UnixMilli(lastMs).UTC()
	p.Pinned = pinned != 0
	p.SampleHex = hex.EncodeToString(p.SamplePayload)
	p.SampleASCII = FormatASCII(p.SamplePayload)
	p.ScannerTags = []string{}
	_ = json.Unmarshal([]byte(tagsJSON), &p.ScannerTags)
	return p, nil
}

// UpdateProbe modifies status, note, and/or pinned flag on a deduplicated probe.
func (s *Store) UpdateProbe(hash string, status *string, note *string, pinned *bool) (*Probe, error) {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	p, err := s.GetProbe(hash)
	if err != nil {
		return nil, err
	}
	if status != nil {
		switch *status {
		case "new", "known", "adopted":
			p.Status = *status
		default:
			return nil, fmt.Errorf("invalid probe status %q", *status)
		}
	}
	if note != nil {
		p.Note = *note
	}
	if pinned != nil {
		p.Pinned = *pinned
	}
	pinInt := 0
	if p.Pinned {
		pinInt = 1
	}
	if _, err := s.db.Exec(`UPDATE probes SET status = ?, note = ?, pinned = ? WHERE hash = ?`, p.Status, p.Note, pinInt, hash); err != nil {
		return nil, err
	}
	return p, nil
}

// ExportProbeSnippet formats a probe payload as hex, python, or go test code.
func ExportProbeSnippet(p *Probe, format string) string {
	hexStr := hex.EncodeToString(p.SamplePayload)
	switch strings.ToLower(format) {
	case "python", "py":
		sockType := "socket.SOCK_STREAM"
		if strings.EqualFold(p.Transport, "udp") {
			sockType = "socket.SOCK_DGRAM"
		}
		return fmt.Sprintf(`import socket

# ProtoSim Probe Export: protocol=%s transport=%s port=%d hash=%s
payload = bytes.fromhex("%s")
sock = socket.socket(socket.AF_INET, %s)
sock.settimeout(5.0)
sock.connect(("127.0.0.1", %d))
sock.sendall(payload)
resp = sock.recv(4096)
print("Response:", resp)
sock.close()
`, p.Protocol, p.Transport, p.Port, p.Hash[:12], hexStr, sockType, p.Port)
	case "go", "golang":
		network := "tcp"
		if strings.EqualFold(p.Transport, "udp") {
			network = "udp"
		}
		return fmt.Sprintf(`package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// ProtoSim Probe Export: protocol=%s transport=%s port=%d hash=%s
func main() {
	payload, _ := hex.DecodeString("%s")
	conn, err := net.DialTimeout("%s", "127.0.0.1:%d", 5*time.Second)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(payload)
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	fmt.Printf("Response (%%d bytes): %%x\n", n, buf[:n])
}
`, p.Protocol, p.Transport, p.Port, p.Hash[:12], hexStr, network, p.Port)
	default:
		return hexStr
	}
}

// --- Test Runs & 61-Protocol Coverage ---

func (s *Store) CreateTestRun(name, scenario, notes string, targetProtocols []string) (*TestRun, error) {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	if name == "" {
		name = "Run " + time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	run := &TestRun{
		ID:              uuid.NewString(),
		Name:            name,
		Scenario:        scenario,
		StartedAt:       time.Now().UTC(),
		TargetProtocols: targetProtocols,
		Notes:           notes,
	}
	tpJSON, _ := json.Marshal(targetProtocols)
	_, err := s.db.Exec(`
		INSERT INTO test_runs (id, name, scenario, started_at, ended_at, target_protocols_json, notes)
		VALUES (?, ?, ?, ?, 0, ?, ?)
	`, run.ID, run.Name, run.Scenario, run.StartedAt.UnixMilli(), string(tpJSON), run.Notes)
	if err != nil {
		return nil, err
	}
	return run, nil
}

func (s *Store) StopTestRun(id string) (*TestRun, error) {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE test_runs SET ended_at = ? WHERE id = ? AND ended_at = 0`, now.UnixMilli(), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Already stopped or missing; return current record
		return s.GetTestRun(id)
	}
	return s.GetTestRun(id)
}

func (s *Store) GetTestRun(id string) (*TestRun, error) {
	row := s.db.QueryRow(`SELECT id, name, scenario, started_at, ended_at, target_protocols_json, notes FROM test_runs WHERE id = ?`, id)
	run, err := scanTestRun(row)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func (s *Store) ListTestRuns() ([]TestRun, error) {
	rows, err := s.db.Query(`SELECT id, name, scenario, started_at, ended_at, target_protocols_json, notes FROM test_runs ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TestRun{}
	for rows.Next() {
		run, err := scanTestRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, nil
}

func scanTestRun(rs rowScanner) (TestRun, error) {
	var run TestRun
	var startMs, endMs int64
	var tpJSON string
	if err := rs.Scan(&run.ID, &run.Name, &run.Scenario, &startMs, &endMs, &tpJSON, &run.Notes); err != nil {
		return TestRun{}, err
	}
	run.StartedAt = time.UnixMilli(startMs).UTC()
	if endMs > 0 {
		t := time.UnixMilli(endMs).UTC()
		run.EndedAt = &t
	}
	run.TargetProtocols = []string{}
	_ = json.Unmarshal([]byte(tpJSON), &run.TargetProtocols)
	return run, nil
}

// GetTestRunCoverage computes the per-protocol coverage matrix for a TestRun.
func (s *Store) GetTestRunCoverage(id string, fallbackProtocols []string) (*TestRunCoverage, error) {
	run, err := s.GetTestRun(id)
	if err != nil {
		return nil, err
	}
	startMs := run.StartedAt.UnixMilli()
	endMs := time.Now().UTC().UnixMilli()
	if run.EndedAt != nil {
		endMs = run.EndedAt.UnixMilli()
	}

	targets := run.TargetProtocols
	if len(targets) == 0 {
		targets = fallbackProtocols
	}

	agg := map[string]*ProtocolCoverageEntry{}
	for _, p := range targets {
		agg[p] = &ProtocolCoverageEntry{Protocol: p, Status: "missed"}
	}

	rows, err := s.db.Query(`
		SELECT protocol,
			COUNT(1) AS sess_cnt,
			COALESCE(SUM(CASE WHEN bytes_in > 0 AND parse_ok = 1 THEN 1 ELSE 0 END), 0) AS hit_cnt,
			COALESCE(SUM(CASE WHEN bytes_in = 0 AND bytes_out > 0 AND parse_ok = 1 THEN 1 ELSE 0 END), 0) AS banner_cnt,
			COALESCE(SUM(CASE WHEN bytes_in = 0 AND bytes_out = 0 THEN 1 ELSE 0 END), 0) AS conn_only_cnt,
			COALESCE(SUM(event_count), 0) AS ev_cnt,
			COALESCE(SUM(CASE WHEN bytes_in > 0 AND parse_ok = 0 THEN 1 ELSE 0 END), 0) AS err_cnt,
			COUNT(DISTINCT CASE WHEN probe_hash != '' THEN probe_hash END) AS uniq_probes,
			COALESCE(AVG(duration_ms), 0) AS avg_ms
		FROM sessions
		WHERE started_at >= ? AND started_at <= ?
		GROUP BY protocol
	`, startMs, endMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var proto string
		var sessCnt, hitCnt, bannerCnt, connOnlyCnt, evCnt, errCnt, uniqProbes int64
		var avgMs float64
		if err := rows.Scan(&proto, &sessCnt, &hitCnt, &bannerCnt, &connOnlyCnt, &evCnt, &errCnt, &uniqProbes, &avgMs); err != nil {
			continue
		}
		entry, ok := agg[proto]
		if !ok {
			entry = &ProtocolCoverageEntry{Protocol: proto}
			agg[proto] = entry
		}
		entry.SessionCount = sessCnt
		entry.HitSessions = hitCnt
		entry.BannerSessions = bannerCnt
		entry.ConnectOnlySessions = connOnlyCnt
		entry.EventCount = evCnt
		entry.ErrorCount = errCnt
		entry.UniqueProbes = uniqProbes
		entry.AvgLatencyMs = avgMs
		switch {
		case hitCnt > 0:
			entry.Status = "hit"
		case bannerCnt > 0:
			entry.Status = "banner_only"
		case errCnt > 0:
			entry.Status = "parse_error"
		case connOnlyCnt > 0 || sessCnt > 0:
			entry.Status = "connect_only"
		default:
			entry.Status = "missed"
		}
	}

	cov := &TestRunCoverage{
		Run:       *run,
		Protocols: make([]ProtocolCoverageEntry, 0, len(agg)),
	}
	for _, e := range agg {
		cov.Protocols = append(cov.Protocols, *e)
		switch e.Status {
		case "hit":
			cov.HitCount++
		case "banner_only":
			cov.BannerOnlyCount++
		case "connect_only":
			cov.ConnectOnlyCount++
		case "parse_error":
			cov.ErrorOnlyCount++
		default:
			cov.MissedCount++
		}
	}
	sort.Slice(cov.Protocols, func(i, j int) bool {
		return cov.Protocols[i].Protocol < cov.Protocols[j].Protocol
	})
	cov.TotalProtocols = len(cov.Protocols)
	if cov.TotalProtocols > 0 {
		cov.CoveragePct = float64(cov.HitCount) * 100.0 / float64(cov.TotalProtocols)
		cov.EffectiveCoveragePct = float64(cov.HitCount+cov.BannerOnlyCount) * 100.0 / float64(cov.TotalProtocols)
	}
	return cov, nil
}

// DiffTestRuns compares two TestRuns protocol-by-protocol.
func (s *Store) DiffTestRuns(baseID, targetID string, fallbackProtocols []string) (*TestRunDiff, error) {
	baseCov, err := s.GetTestRunCoverage(baseID, fallbackProtocols)
	if err != nil {
		return nil, fmt.Errorf("base run: %w", err)
	}
	targetCov, err := s.GetTestRunCoverage(targetID, fallbackProtocols)
	if err != nil {
		return nil, fmt.Errorf("target run: %w", err)
	}

	baseMap := map[string]ProtocolCoverageEntry{}
	targetMap := map[string]ProtocolCoverageEntry{}
	protoSet := map[string]struct{}{}
	for _, e := range baseCov.Protocols {
		baseMap[e.Protocol] = e
		protoSet[e.Protocol] = struct{}{}
	}
	for _, e := range targetCov.Protocols {
		targetMap[e.Protocol] = e
		protoSet[e.Protocol] = struct{}{}
	}

	protos := make([]string, 0, len(protoSet))
	for p := range protoSet {
		protos = append(protos, p)
	}
	sort.Strings(protos)

	diff := &TestRunDiff{
		BaseRun:      baseCov.Run,
		TargetRun:    targetCov.Run,
		BaseCoverage: baseCov.CoveragePct,
		NewCoverage:  targetCov.CoveragePct,
		NewlyHit:     []string{},
		Regressed:    []string{},
		StillHit:     []string{},
		StillMissed:  []string{},
		Details:      make([]DiffEntry, 0, len(protos)),
	}

	for _, p := range protos {
		b := baseMap[p]
		t := targetMap[p]
		if b.Status == "" {
			b.Status = "missed"
		}
		if t.Status == "" {
			t.Status = "missed"
		}
		bHit := b.Status == "hit"
		tHit := t.Status == "hit"
		switch {
		case !bHit && tHit:
			diff.NewlyHit = append(diff.NewlyHit, p)
		case bHit && !tHit:
			diff.Regressed = append(diff.Regressed, p)
		case bHit && tHit:
			diff.StillHit = append(diff.StillHit, p)
		default:
			diff.StillMissed = append(diff.StillMissed, p)
		}
		diff.Details = append(diff.Details, DiffEntry{
			Protocol:       p,
			BaseStatus:     b.Status,
			TargetStatus:   t.Status,
			BaseSessions:   b.SessionCount,
			TargetSessions: t.SessionCount,
		})
	}
	return diff, nil
}

// --- Scanner Rules CRUD ---

func (s *Store) ListScannerRules() ([]ScannerRule, error) {
	rows, err := s.db.Query(`SELECT id, name, tag, match_type, pattern, enabled FROM scanner_rules ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScannerRule{}
	for rows.Next() {
		var r ScannerRule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Tag, &r.MatchType, &r.Pattern, &en); err == nil {
			r.Enabled = en != 0
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Store) CreateScannerRule(r ScannerRule) (*ScannerRule, error) {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	en := 0
	if r.Enabled {
		en = 1
	}
	res, err := s.db.Exec(`INSERT INTO scanner_rules (name, tag, match_type, pattern, enabled) VALUES (?, ?, ?, ?, ?)`,
		r.Name, r.Tag, r.MatchType, r.Pattern, en)
	if err != nil {
		return nil, err
	}
	r.ID, _ = res.LastInsertId()
	return &r, nil
}

func (s *Store) UpdateScannerRule(r ScannerRule) error {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	en := 0
	if r.Enabled {
		en = 1
	}
	_, err := s.db.Exec(`UPDATE scanner_rules SET name=?, tag=?, match_type=?, pattern=?, enabled=? WHERE id=?`,
		r.Name, r.Tag, r.MatchType, r.Pattern, en, r.ID)
	return err
}

func (s *Store) DeleteScannerRule(id int64) error {
	s.writeM.Lock()
	defer s.writeM.Unlock()
	_, err := s.db.Exec(`DELETE FROM scanner_rules WHERE id = ?`, id)
	return err
}

// --- Scenarios CRUD ---

func (s *Store) UpsertScenario(rec ScenarioRecord) error {
	s.writeM.Lock()
	defer s.writeM.Unlock()

	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`
		INSERT INTO scenarios (id, name, description, config_json, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			config_json = excluded.config_json,
			updated_at = excluded.updated_at
	`, rec.ID, rec.Name, rec.Description, rec.ConfigJSON, rec.UpdatedAt.UnixMilli())
	return err
}

func (s *Store) ListScenarios() ([]ScenarioRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, description, config_json, updated_at FROM scenarios ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScenarioRecord{}
	for rows.Next() {
		var r ScenarioRecord
		var tsMs int64
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.ConfigJSON, &tsMs); err == nil {
			r.UpdatedAt = time.UnixMilli(tsMs).UTC()
			out = append(out, r)
		}
	}
	return out, nil
}

// --- Rolling Retention (Preserves `probes` and pinned sessions permanently) ---

// RunRetention prunes sessions/events/credentials/payloads older than retentionDays (or when DB exceeds maxSizeMB)
// while NEVER deleting `probes` or sessions referenced by pinned probes.
func (s *Store) RunRetention(retentionDays int, maxSizeMB int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	s.writeM.Lock()
	defer s.writeM.Unlock()

	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).UnixMilli()
	var totalDeleted int64

	delByCutoff := func(cutMs int64) (int64, error) {
		tx, err := s.db.Begin()
		if err != nil {
			return 0, err
		}
		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()

		// Collect session IDs eligible for deletion (exclude sample_session_id of any pinned probe).
		res, err := tx.Exec(`
			DELETE FROM payloads
			WHERE session_id IN (
				SELECT id FROM sessions
				WHERE started_at < ?
				AND id NOT IN (SELECT sample_session_id FROM probes WHERE pinned = 1 AND sample_session_id != '')
			)
		`, cutMs)
		if err != nil {
			return 0, err
		}
		_, _ = res.RowsAffected()

		_, err = tx.Exec(`
			DELETE FROM events
			WHERE session_id IN (
				SELECT id FROM sessions
				WHERE started_at < ?
				AND id NOT IN (SELECT sample_session_id FROM probes WHERE pinned = 1 AND sample_session_id != '')
			)
		`, cutMs)
		if err != nil {
			return 0, err
		}

		_, err = tx.Exec(`
			DELETE FROM credentials
			WHERE session_id IN (
				SELECT id FROM sessions
				WHERE started_at < ?
				AND id NOT IN (SELECT sample_session_id FROM probes WHERE pinned = 1 AND sample_session_id != '')
			)
		`, cutMs)
		if err != nil {
			return 0, err
		}

		res, err = tx.Exec(`
			DELETE FROM sessions
			WHERE started_at < ?
			AND id NOT IN (SELECT sample_session_id FROM probes WHERE pinned = 1 AND sample_session_id != '')
		`, cutMs)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()

		if err := tx.Commit(); err != nil {
			return 0, err
		}
		tx = nil
		return n, nil
	}

	n, err := delByCutoff(cutoff)
	if err != nil {
		return 0, err
	}
	totalDeleted += n

	// Also enforce DB size ceiling if file-backed.
	if maxSizeMB > 0 && s.dbPath != ":memory:" {
		if fi, err := os.Stat(s.dbPath); err == nil && fi.Size() > int64(maxSizeMB)*1024*1024 {
			// Delete oldest 1000 non-pinned sessions
			var cutMs int64
			err := s.db.QueryRow(`
				SELECT MAX(started_at) FROM (
					SELECT started_at FROM sessions
					WHERE id NOT IN (SELECT sample_session_id FROM probes WHERE pinned = 1 AND sample_session_id != '')
					ORDER BY started_at ASC LIMIT 1000
				)
			`).Scan(&cutMs)
			if err == nil && cutMs > 0 {
				if extra, err := delByCutoff(cutMs + 1); err == nil {
					totalDeleted += extra
				}
			}
		}
	}

	return totalDeleted, nil
}
