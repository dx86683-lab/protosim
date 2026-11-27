package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
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
	if cov.TotalProtocols != 159 {
		t.Fatalf("expected 159 protocols in coverage, got %d", cov.TotalProtocols)
	}

	// 5. Embedded SPA index
	resp, err = http.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("SPA index failed: %v", err)
	}
	resp.Body.Close()
}

func TestAPIv2SecurityHardening(t *testing.T) {
	store, err := telemetry.OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.Hosts = nil
	cfg.API.Auth.Enabled = true
	cfg.API.Auth.Token = "s3cr3t-token"

	bus := telemetry.NewBus(store, cfg.Storage, cfg.Webhook)
	defer bus.Close()
	mgr, err := network.NewManager(cfg, bus)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	srv := NewServer(cfg, bus, mgr, web.DistFS(), "1.2.2")
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// 1. Without token -> 401 on protected endpoint, 200 on /health
	resp, err := http.Get(ts.URL + "/api/v2/overview")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %v", resp)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/api/v2/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /health, got %v", resp)
	}
	resp.Body.Close()

	// 2. With valid token -> 200, and no wildcard CORS
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v2/overview", nil)
	req.Header.Set("X-API-Token", "s3cr3t-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %v", resp)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		t.Fatalf("wildcard CORS must not be set")
	}
	resp.Body.Close()

	// 3. Reject dynamic tcp_forward and arbitrary fs_path
	for _, body := range []string{
		`{"protocol":"tcp_forward","port":18079,"params":{"target":"127.0.0.1:22"}}`,
		`{"protocol":"http","port":18080,"params":{"fs_path":"/etc"}}`,
	} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v2/services", bytes.NewBufferString(body))
		req.Header.Set("X-API-Token", "s3cr3t-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %v", body, resp)
		}
		resp.Body.Close()
	}

	// 4. Reject cloud metadata SSRF in webhook URL
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/v2/config/runtime", bytes.NewBufferString(`{"webhook":{"enabled":true,"url":"http://169.254.169.254/latest/meta-data"}}`))
	req.Header.Set("X-API-Token", "s3cr3t-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for metadata webhook SSRF, got %v", resp)
	}
	resp.Body.Close()

	// 5. Server-side auth gate: unauthenticated '/' redirects to '/login' (never returns SPA), '/assets/*' returns 401
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("expected 302 -> /login for unauthenticated '/', got %d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	resp, err = noFollow.Get(ts.URL + "/login")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected public login page, got %v: %v", resp, err)
	}
	loginPage, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Contains(loginPage, []byte(`id="loginForm"`)) {
		t.Fatalf("expected login form, read error: %v", err)
	}
	for _, key := range []string{"protosim.locale", "protosim.theme"} {
		if bytes.Contains(loginPage, []byte(key)) {
			t.Errorf("public login page includes display preference %q", key)
		}
	}

	resp, err = noFollow.Get(ts.URL + "/assets/app.js")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated '/assets/app.js', got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unauthenticated /health must NOT leak services or version
	resp, err = noFollow.Get(ts.URL + "/api/v2/health")
	var hMap map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&hMap)
	resp.Body.Close()
	if _, leaked := hMap["services"]; leaked {
		t.Fatalf("unauthenticated /health must not leak services: %v", hMap)
	}

	// 6. Login via /api/v2/auth/login -> HttpOnly cookie -> '/' and '/api/v2/overview' return 200
	resp, err = noFollow.Post(ts.URL+"/api/v2/auth/login", "application/json", bytes.NewBufferString(`{"token":"s3cr3t-token"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %v", resp)
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	if len(cookies) == 0 || !cookies[0].HttpOnly || cookies[0].Name != sessionCookieName {
		t.Fatalf("expected HttpOnly %s cookie, got %+v", sessionCookieName, cookies)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(cookies[0])
	resp, err = noFollow.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for authenticated '/', got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuntimeConfigUpdateAtomicOnInvalidWebhook(t *testing.T) {
	store, err := telemetry.OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.Storage.RedactCredentials = false
	bus := telemetry.NewBus(store, cfg.Storage, cfg.Webhook)
	defer bus.Close()
	mgr, err := network.NewManager(cfg, bus)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	srv := NewServer(cfg, bus, mgr, nil, "test")
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v2/config/runtime", bytes.NewBufferString(`{
		"storage": {"redact_credentials": true, "payload_enabled": false},
		"webhook": {"enabled": true, "url": "http://169.254.169.254/latest/meta-data"}
	}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT runtime config: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if cfg.Storage.RedactCredentials {
		t.Fatalf("storage config was mutated despite 400 validation failure")
	}
}
