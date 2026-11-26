package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dx86683-lab/protosim/internal/config"
	"github.com/dx86683-lab/protosim/internal/network"
	"github.com/dx86683-lab/protosim/internal/telemetry"
	"github.com/dx86683-lab/protosim/web"
)

func TestAPIv2EndToEnd(t *testing.T) {
	store, err := telemetry.OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.Hosts = nil
	bus := telemetry.NewBus(store, cfg.Storage, cfg.Webhook)
	defer bus.Close()

	mgr, err := network.NewManager(cfg, bus)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	srv := NewServer(cfg, bus, mgr, web.DistFS(), "1.0.0-test")
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Seed a session + probe + payload
	now := time.Now().UTC()
	payload := []byte("GET /probe HTTP/1.1\r\nUser-Agent: internal-scanner/2.0\r\n\r\n")
	hash, tag := bus.RecordProbeHit("http", "tcp", 80, "192.168.124.5", "", "api-sess-1", payload)
	bus.RecordSession(telemetry.Session{
		ID:         "api-sess-1",
		Protocol:   "http",
		Transport:  "tcp",
		RemoteIP:   "192.168.124.5",
		RemotePort: 44444,
		LocalIP:    "192.168.124.15",
		LocalPort:  80,
		ScannerTag: tag,
		ProbeHash:  hash,
		StartedAt:  now,
		EndedAt:    now.Add(5 * time.Millisecond),
		DurationMs: 5,
		BytesIn:    int64(len(payload)),
		ParseOK:    true,
		Status:     "closed",
	})
	bus.RecordPayload(telemetry.PayloadChunk{
		SessionID: "api-sess-1",
		Seq:       1,
		Timestamp: now,
		Direction: "in",
		Data:      payload,
	})
	bus.Flush()

	// 1. Health & Overview
	resp, err := http.Get(ts.URL + "/api/v2/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health failed: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/api/v2/overview?window=24h")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("overview failed: %v", err)
	}
	var ov telemetry.OverviewStats
	_ = json.NewDecoder(resp.Body).Decode(&ov)
	resp.Body.Close()
	if ov.TotalSessions != 1 || ov.UniqueProbes != 1 {
		t.Fatalf("unexpected overview: %+v", ov)
	}

	// 2. Probe PATCH + Export
	patchBody := bytes.NewBufferString(`{"status":"adopted","note":"added to internal-scanner","pinned":true}`)
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v2/probes/"+hash, patchBody)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("probe patch failed: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/api/v2/probes/" + hash + "/export?format=python")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("probe export failed: %v", err)
	}
	resp.Body.Close()

	// 3. Session PCAP export
	resp, err = http.Get(ts.URL + "/api/v2/sessions/api-sess-1/pcap")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("session pcap failed: %v", err)
	}
	var hdr [4]byte
	_, _ = resp.Body.Read(hdr[:])
	resp.Body.Close()
	if binary.LittleEndian.Uint32(hdr[:]) != 0xa1b2c3d4 {
		t.Fatalf("expected pcap magic 0xa1b2c3d4, got %x", hdr)
	}

	// 4. TestRun create + coverage
	resp, err = http.Post(ts.URL+"/api/v2/test-runs", "application/json", bytes.NewBufferString(`{"name":"CI Run"}`))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create test-run failed: %v", err)
	}
	var run telemetry.TestRun
	_ = json.NewDecoder(resp.Body).Decode(&run)
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/api/v2/test-runs/" + run.ID + "/coverage")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("coverage failed: %v", err)
	}
	var cov telemetry.TestRunCoverage
	_ = json.NewDecoder(resp.Body).Decode(&cov)
	resp.Body.Close()
	if cov.TotalProtocols != 61 {
		t.Fatalf("expected 61 protocols in coverage, got %d", cov.TotalProtocols)
	}

	// 5. Embedded SPA index
	resp, err = http.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("SPA index failed: %v", err)
	}
	resp.Body.Close()
}
