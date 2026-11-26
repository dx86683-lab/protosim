package telemetry

import "time"

// Session represents one TCP connection or UDP interaction handled by ProtoSim.
type Session struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"`
	Transport  string    `json:"transport"` // tcp | udp | icmp | syn
	RemoteIP   string    `json:"remote_ip"`
	RemotePort uint16    `json:"remote_port"`
	LocalIP    string    `json:"local_ip"`
	LocalPort  uint16    `json:"local_port"`
	Country    string    `json:"country"`
	JA3        string    `json:"ja3,omitempty"`
	ScannerTag string    `json:"scanner_tag"`
	ProbeHash  string    `json:"probe_hash,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	DurationMs int64     `json:"duration_ms"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	EventCount int       `json:"event_count"`
	ParseOK    bool      `json:"parse_ok"`
	Status     string    `json:"status"` // open | closed | parse_error | timeout
}

// Event represents a structured protocol-level or transport-level milestone inside a session.
type Event struct {
	ID         int64     `json:"id"`
	SessionID  string    `json:"session_id"`
	Timestamp  time.Time `json:"ts"`
	Protocol   string    `json:"protocol"`
	RemoteIP   string    `json:"remote_ip"`
	LocalPort  uint16    `json:"local_port"`
	Kind       string    `json:"kind"` // conn_open | conn_close | auth | command | request | parse_error | catch_all | capture
	Summary    string    `json:"summary"`
	DetailJSON string    `json:"detail_json,omitempty"`
}

// Probe represents a deduplicated unique probe clustered by (protocol, port, first_payload_sha256).
// Probes are preserved permanently across rolling retention cleanups.
type Probe struct {
	Hash            string    `json:"hash"`
	Protocol        string    `json:"protocol"`
	Transport       string    `json:"transport"`
	Port            uint16    `json:"port"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	HitCount        int64     `json:"hit_count"`
	UniqueIPs       int64     `json:"unique_ips"`
	SamplePayload   []byte    `json:"sample_payload,omitempty"`
	SampleHex       string    `json:"sample_hex,omitempty"`
	SampleASCII     string    `json:"sample_ascii,omitempty"`
	SampleSessionID string    `json:"sample_session_id"`
	ScannerTags     []string  `json:"scanner_tags"`
	Status          string    `json:"status"` // new | known | adopted
	Note            string    `json:"note"`
	Pinned          bool      `json:"pinned"`
	IsNew           bool      `json:"is_new,omitempty"`
}

// Credential represents an authentication attempt captured by a protocol handler.
type Credential struct {
	ID         int64     `json:"id"`
	SessionID  string    `json:"session_id"`
	Timestamp  time.Time `json:"ts"`
	Protocol   string    `json:"protocol"`
	RemoteIP   string    `json:"remote_ip"`
	ScannerTag string    `json:"scanner_tag"`
	Username   string    `json:"username"`
	Secret     string    `json:"secret"`
	Mechanism  string    `json:"mechanism"`
	Accepted   bool      `json:"accepted"`
}

// PayloadChunk stores a bounded directional raw byte chunk belonging to a session.
type PayloadChunk struct {
	ID        int64     `json:"id"`
	SessionID string    `json:"session_id"`
	Seq       int       `json:"seq"`
	Timestamp time.Time `json:"ts"`
	Direction string    `json:"direction"` // in | out
	Data      []byte    `json:"data,omitempty"`
	Hex       string    `json:"hex,omitempty"`
	ASCII     string    `json:"ascii,omitempty"`
}

// SessionDetail bundles a session with its full timeline (events, credentials, payloads).
type SessionDetail struct {
	Session     Session        `json:"session"`
	Events      []Event        `json:"events"`
	Credentials []Credential   `json:"credentials"`
	Payloads    []PayloadChunk `json:"payloads"`
}

// TestRun marks a named scanner evaluation window.
type TestRun struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Scenario        string     `json:"scenario"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	TargetProtocols []string   `json:"target_protocols"`
	Notes           string     `json:"notes"`
}

// ProtocolCoverageEntry describes how one protocol performed during a TestRun.
type ProtocolCoverageEntry struct {
	Protocol            string  `json:"protocol"`
	Status              string  `json:"status"` // hit | banner_only | connect_only | parse_error | missed
	SessionCount        int64   `json:"session_count"`
	HitSessions         int64   `json:"hit_sessions"`
	BannerSessions      int64   `json:"banner_sessions"`
	ConnectOnlySessions int64   `json:"connect_only_sessions"`
	EventCount          int64   `json:"event_count"`
	ErrorCount          int64   `json:"error_count"`
	UniqueProbes        int64   `json:"unique_probes"`
	AvgLatencyMs        float64 `json:"avg_latency_ms"`
}

// TestRunCoverage aggregates per-protocol coverage for a TestRun using a 5-state interaction model.
type TestRunCoverage struct {
	Run                  TestRun                 `json:"run"`
	TotalProtocols       int                     `json:"total_protocols"`
	HitCount             int                     `json:"hit_count"`
	BannerOnlyCount      int                     `json:"banner_only_count"`
	ConnectOnlyCount     int                     `json:"connect_only_count"`
	MissedCount          int                     `json:"missed_count"`
	ErrorOnlyCount       int                     `json:"error_only_count"`
	CoveragePct          float64                 `json:"coverage_pct"`           // hit / total (active client-server interaction)
	EffectiveCoveragePct float64                 `json:"effective_coverage_pct"` // (hit + banner_only) / total
	Protocols            []ProtocolCoverageEntry `json:"protocols"`
}

// TestRunDiff compares two TestRuns protocol-by-protocol.
type TestRunDiff struct {
	BaseRun      TestRun          `json:"base_run"`
	TargetRun    TestRun          `json:"target_run"`
	NewlyHit     []string         `json:"newly_hit"`
	Regressed    []string         `json:"regressed"`
	StillHit     []string         `json:"still_hit"`
	StillMissed  []string         `json:"still_missed"`
	BaseCoverage float64          `json:"base_coverage_pct"`
	NewCoverage  float64          `json:"target_coverage_pct"`
	Details      []DiffEntry      `json:"details"`
}

type DiffEntry struct {
	Protocol       string `json:"protocol"`
	BaseStatus     string `json:"base_status"`
	TargetStatus   string `json:"target_status"`
	BaseSessions   int64  `json:"base_sessions"`
	TargetSessions int64  `json:"target_sessions"`
}

// ScannerRule defines one attribution rule for classifying incoming scanners.
type ScannerRule struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Tag       string `json:"tag"`
	MatchType string `json:"match_type"` // cidr | ua | ja3 | payload_regex
	Pattern   string `json:"pattern"`
	Enabled   bool   `json:"enabled"`
}

// ScenarioRecord is a persisted scenario template in SQLite.
type ScenarioRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ConfigJSON  string    `json:"config_json"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NameCount is a generic TopN aggregation pair.
type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// TimeBucket holds time-series counts for Dashboard charts.
type TimeBucket struct {
	Bucket   string `json:"bucket"`
	Sessions int64  `json:"sessions"`
	Events   int64  `json:"events"`
	Probes   int64  `json:"probes"`
}

// OverviewStats is returned by GET /api/v2/overview.
type OverviewStats struct {
	Window          string       `json:"window"`
	TotalSessions   int64        `json:"total_sessions"`
	TotalEvents     int64        `json:"total_events"`
	UniqueProbes    int64        `json:"unique_probes"`
	NewProbes       int64        `json:"new_probes"`
	TotalCreds      int64        `json:"total_credentials"`
	UniqueIPs       int64        `json:"unique_ips"`
	ParseErrorCount int64        `json:"parse_error_count"`
	DBSizeBytes     int64        `json:"db_size_bytes"`
	Timeline        []TimeBucket `json:"timeline"`
	TopProtocols    []NameCount  `json:"top_protocols"`
	TopScanners     []NameCount  `json:"top_scanners"`
	TopSourceIPs    []NameCount  `json:"top_source_ips"`
	TopCountries    []NameCount  `json:"top_countries"`
	RecentNewProbes []Probe      `json:"recent_new_probes"`
}

// LiveMessage is broadcast over SSE /api/v2/stream.
type LiveMessage struct {
	Type       string    `json:"type"` // event | session | new_probe | credential
	Timestamp  time.Time `json:"ts"`
	Protocol   string    `json:"protocol"`
	RemoteIP   string    `json:"remote_ip"`
	LocalPort  uint16    `json:"local_port,omitempty"`
	ScannerTag string    `json:"scanner_tag,omitempty"`
	ProbeHash  string    `json:"probe_hash,omitempty"`
	IsNewProbe bool      `json:"is_new_probe,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Summary    string    `json:"summary"`
}
