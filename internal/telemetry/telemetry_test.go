package telemetry

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dx86683-lab/protosim/internal/config"
)

func TestStoreAndBusEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "protosim.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	storageCfg := config.StorageConfig{
		DBPath:          dbPath,
		PayloadEnabled:  true,
		MaxPayloadBytes: 65536,
		RetentionDays:   30,
		MaxSizeMB:       1024,
	}
	bus := NewBus(store, storageCfg, config.WebhookConfig{})
	defer bus.Close()

	liveCh, unsub := bus.Subscribe()
	defer unsub()

	now := time.Now().UTC()
	payload1 := []byte("GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Nmap Scripting Engine\r\n\r\n")
	hash1, tag1 := bus.RecordProbeHit("http", "tcp", 80, "10.0.0.10", "", "sess-1", payload1)
	if tag1 != "nmap" {
		t.Fatalf("expected scanner tag nmap, got %q", tag1)
	}

	bus.RecordSession(Session{
		ID:         "sess-1",
		Protocol:   "http",
		Transport:  "tcp",
		RemoteIP:   "10.0.0.10",
		RemotePort: 50001,
		LocalIP:    "192.168.124.15",
		LocalPort:  80,
		ScannerTag: tag1,
		ProbeHash:  hash1,
		StartedAt:  now,
		EndedAt:    now.Add(12 * time.Millisecond),
		DurationMs: 12,
		BytesIn:    int64(len(payload1)),
		BytesOut:   128,
		ParseOK:    true,
		Status:     "closed",
	})
	bus.RecordEvent(Event{
		SessionID: "sess-1",
		Timestamp: now,
		Protocol:  "http",
		RemoteIP:  "10.0.0.10",
		LocalPort: 80,
		Kind:      "request",
		Summary:   "GET /",
	})
	bus.RecordCredential(Credential{
		SessionID:  "sess-1",
		Timestamp:  now,
		Protocol:   "http",
		RemoteIP:   "10.0.0.10",
		ScannerTag: tag1,
		Username:   "admin",
		Secret:     "s3cr3t",
		Mechanism:  "basic",
		Accepted:   true,
	})
	bus.RecordPayload(PayloadChunk{
		SessionID: "sess-1",
		Seq:       1,
		Timestamp: now,
		Direction: "in",
		Data:      payload1,
	})
	bus.RecordPayload(PayloadChunk{
		SessionID: "sess-1",
		Seq:       2,
		Timestamp: now.Add(2 * time.Millisecond),
		Direction: "out",
		Data:      []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
	})

	// Second hit from another IP with identical payload -> must deduplicate and bump unique_ips to 2
	hash2, _ := bus.RecordProbeHit("http", "tcp", 80, "10.0.0.11", "", "sess-2", payload1)
	if hash1 != hash2 {
		t.Fatalf("expected identical probe hash, got %s vs %s", hash1, hash2)
	}
	bus.Flush()

	// Verify SSE received new_probe message
	gotNewProbe := false
	timeout := time.After(time.Second)
drain:
	for {
		select {
		case msg := <-liveCh:
			if msg.Type == "new_probe" && msg.ProbeHash == hash1 {
				gotNewProbe = true
				break drain
			}
		case <-timeout:
			break drain
		}
	}
	if !gotNewProbe {
		t.Fatalf("expected new_probe SSE broadcast")
	}

	// Verify probe dedup counts
	probe, err := store.GetProbe(hash1)
	if err != nil {
		t.Fatalf("GetProbe: %v", err)
	}
	if probe.HitCount != 2 || probe.UniqueIPs != 2 {
		t.Fatalf("expected hit_count=2 unique_ips=2, got hit=%d ips=%d", probe.HitCount, probe.UniqueIPs)
	}

	// Verify probe snippet export
	pySnippet := ExportProbeSnippet(probe, "python")
	if !strings.Contains(pySnippet, "bytes.fromhex") {
		t.Fatalf("unexpected python snippet: %s", pySnippet)
	}
	goSnippet := ExportProbeSnippet(probe, "go")
	if !strings.Contains(goSnippet, "hex.DecodeString") {
		t.Fatalf("unexpected go snippet: %s", goSnippet)
	}

	// Verify session detail + PCAP export
	detail, err := store.GetSessionDetail("sess-1")
	if err != nil {
		t.Fatalf("GetSessionDetail: %v", err)
	}
	if len(detail.Events) != 1 || len(detail.Credentials) != 1 || len(detail.Payloads) != 2 {
		t.Fatalf("unexpected detail counts: events=%d creds=%d payloads=%d",
			len(detail.Events), len(detail.Credentials), len(detail.Payloads))
	}
	pcapBytes := BuildSessionPCAP(detail.Session, detail.Payloads)
	if len(pcapBytes) < 24 || binary.LittleEndian.Uint32(pcapBytes[:4]) != 0xa1b2c3d4 {
		t.Fatalf("invalid PCAP header")
	}

	// Verify overview aggregation
	ov, err := store.QueryOverview("24h")
	if err != nil {
		t.Fatalf("QueryOverview: %v", err)
	}
	if ov.TotalSessions != 1 || ov.UniqueProbes != 1 || ov.TotalCreds != 1 {
		t.Fatalf("unexpected overview: %+v", ov)
	}
}

func TestTestRunCoverageAndDiff(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	targets := []string{"http", "ssh", "mysql", "redis"}
	run1, err := store.CreateTestRun("Baseline", "core", "", targets)
	if err != nil {
		t.Fatalf("CreateTestRun 1: %v", err)
	}
	_, err = store.WriteBatch([]BatchWriteItem{
		{Session: &Session{ID: "r1-http", Protocol: "http", Transport: "tcp", RemoteIP: "1.1.1.1", StartedAt: time.Now().UTC(), ParseOK: true, Status: "closed"}},
		{Session: &Session{ID: "r1-ssh", Protocol: "ssh", Transport: "tcp", RemoteIP: "1.1.1.1", StartedAt: time.Now().UTC(), ParseOK: false, Status: "parse_error"}},
	})
	if err != nil {
		t.Fatalf("WriteBatch 1: %v", err)
	}
	if _, err := store.StopTestRun(run1.ID); err != nil {
		t.Fatalf("StopTestRun 1: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	run2, err := store.CreateTestRun("Improved", "core", "", targets)
	if err != nil {
		t.Fatalf("CreateTestRun 2: %v", err)
	}
	_, err = store.WriteBatch([]BatchWriteItem{
		{Session: &Session{ID: "r2-http", Protocol: "http", Transport: "tcp", RemoteIP: "1.1.1.1", StartedAt: time.Now().UTC(), ParseOK: true, Status: "closed"}},
		{Session: &Session{ID: "r2-mysql", Protocol: "mysql", Transport: "tcp", RemoteIP: "1.1.1.1", StartedAt: time.Now().UTC(), ParseOK: true, Status: "closed"}},
	})
	if err != nil {
		t.Fatalf("WriteBatch 2: %v", err)
	}
	if _, err := store.StopTestRun(run2.ID); err != nil {
		t.Fatalf("StopTestRun 2: %v", err)
	}

	diff, err := store.DiffTestRuns(run1.ID, run2.ID, targets)
	if err != nil {
		t.Fatalf("DiffTestRuns: %v", err)
	}
	if len(diff.NewlyHit) != 1 || diff.NewlyHit[0] != "mysql" {
		t.Fatalf("expected NewlyHit=[mysql], got %v", diff.NewlyHit)
	}
	if len(diff.StillHit) != 1 || diff.StillHit[0] != "http" {
		t.Fatalf("expected StillHit=[http], got %v", diff.StillHit)
	}
}

func TestRetentionPreservesProbesAndPinnedSamples(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	oldTS := time.Now().UTC().Add(-45 * 24 * time.Hour)
	hashPinned := ComputeProbeHash("ssh", 22, []byte("SSH-2.0-Pinned"))
	hashNormal := ComputeProbeHash("http", 80, []byte("GET /old HTTP/1.0\r\n\r\n"))

	_, err = store.WriteBatch([]BatchWriteItem{
		{Session: &Session{ID: "old-pinned", Protocol: "ssh", Transport: "tcp", RemoteIP: "2.2.2.2", ProbeHash: hashPinned, StartedAt: oldTS, ParseOK: true, Status: "closed"}},
		{Payload: &PayloadChunk{SessionID: "old-pinned", Seq: 1, Timestamp: oldTS, Direction: "in", Data: []byte("SSH-2.0-Pinned")}},
		{ProbeHit: &ProbeHitInput{Hash: hashPinned, Protocol: "ssh", Transport: "tcp", Port: 22, Timestamp: oldTS, RemoteIP: "2.2.2.2", SessionID: "old-pinned", Payload: []byte("SSH-2.0-Pinned")}},
		{Session: &Session{ID: "old-unpinned", Protocol: "http", Transport: "tcp", RemoteIP: "3.3.3.3", ProbeHash: hashNormal, StartedAt: oldTS, ParseOK: true, Status: "closed"}},
		{Payload: &PayloadChunk{SessionID: "old-unpinned", Seq: 1, Timestamp: oldTS, Direction: "in", Data: []byte("GET /old HTTP/1.0\r\n\r\n")}},
		{ProbeHit: &ProbeHitInput{Hash: hashNormal, Protocol: "http", Transport: "tcp", Port: 80, Timestamp: oldTS, RemoteIP: "3.3.3.3", SessionID: "old-unpinned", Payload: []byte("GET /old HTTP/1.0\r\n\r\n")}},
	})
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	pin := true
	if _, err := store.UpdateProbe(hashPinned, nil, nil, &pin); err != nil {
		t.Fatalf("UpdateProbe: %v", err)
	}

	deleted, err := store.RunRetention(30, 2048)
	if err != nil {
		t.Fatalf("RunRetention: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly 1 old unpinned session deleted, got %d", deleted)
	}

	// Pinned session & its payload must still exist
	if _, err := store.GetSessionDetail("old-pinned"); err != nil {
		t.Fatalf("pinned session should be preserved: %v", err)
	}
	// Unpinned session must be gone, BUT its deduplicated probe MUST still exist permanently!
	if _, err := store.GetSessionDetail("old-unpinned"); err == nil {
		t.Fatalf("unpinned old session should have been deleted")
	}
	if _, err := store.GetProbe(hashNormal); err != nil {
		t.Fatalf("probe must be permanently preserved after retention: %v", err)
	}
}
