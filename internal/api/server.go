package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/config"
	"github.com/dx86683-lab/protosim/internal/network"
	"github.com/dx86683-lab/protosim/internal/telemetry"
)

// Server exposes the /api/v2/* REST & SSE API and embedded Vue 3 SPA.
type Server struct {
	cfg     *config.Config
	bus     *telemetry.Bus
	store   *telemetry.Store
	mgr     *network.Manager
	webFS   fs.FS
	version string
}

func NewServer(cfg *config.Config, bus *telemetry.Bus, mgr *network.Manager, webFS fs.FS, version string) *Server {
	return &Server{
		cfg:     cfg,
		bus:     bus,
		store:   bus.Store(),
		mgr:     mgr,
		webFS:   webFS,
		version: version,
	}
}

func (s *Server) Router() http.Handler {
	r := mux.NewRouter()
	apiR := r.PathPrefix("/api/v2").Subrouter()
	apiR.Use(s.corsMiddleware)
	apiR.Use(s.authMiddleware)

	apiR.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/overview", s.handleOverview).Methods(http.MethodGet, http.MethodOptions)

	apiR.HandleFunc("/sessions", s.handleSessions).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/sessions/{id}", s.handleSessionDetail).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/sessions/{id}/pcap", s.handleSessionPCAP).Methods(http.MethodGet, http.MethodOptions)

	apiR.HandleFunc("/events", s.handleEvents).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/credentials", s.handleCredentials).Methods(http.MethodGet, http.MethodOptions)

	apiR.HandleFunc("/probes", s.handleProbes).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/probes/{hash}", s.handleProbeGet).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/probes/{hash}", s.handleProbePatch).Methods(http.MethodPatch, http.MethodOptions)
	apiR.HandleFunc("/probes/{hash}/export", s.handleProbeExport).Methods(http.MethodGet, http.MethodOptions)

	apiR.HandleFunc("/test-runs", s.handleTestRunsList).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/test-runs", s.handleTestRunCreate).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/test-runs/diff", s.handleTestRunDiff).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/test-runs/{id}/stop", s.handleTestRunStop).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/test-runs/{id}/coverage", s.handleTestRunCoverage).Methods(http.MethodGet, http.MethodOptions)

	apiR.HandleFunc("/scanner-rules", s.handleScannerRulesList).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/scanner-rules", s.handleScannerRuleCreate).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/scanner-rules/{id}", s.handleScannerRuleUpdate).Methods(http.MethodPut, http.MethodOptions)
	apiR.HandleFunc("/scanner-rules/{id}", s.handleScannerRuleDelete).Methods(http.MethodDelete, http.MethodOptions)

	apiR.HandleFunc("/scenarios", s.handleScenariosList).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/scenarios", s.handleScenarioSave).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/scenarios/apply", s.handleScenarioApply).Methods(http.MethodPost, http.MethodOptions)

	apiR.HandleFunc("/services", s.handleServicesList).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/services", s.handleServiceAdd).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/services/{id}", s.handleServiceDelete).Methods(http.MethodDelete, http.MethodOptions)

	apiR.HandleFunc("/catch-all", s.handleCatchAllUpdate).Methods(http.MethodPut, http.MethodOptions)
	apiR.HandleFunc("/protocols", s.handleProtocolsList).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/config", s.handleConfigGet).Methods(http.MethodGet, http.MethodOptions)
	apiR.HandleFunc("/config/runtime", s.handleConfigRuntimeUpdate).Methods(http.MethodPut, http.MethodOptions)
	apiR.HandleFunc("/retention/run", s.handleRetentionRun).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/upload/rdp", s.handleUploadRDP).Methods(http.MethodPost, http.MethodOptions)
	apiR.HandleFunc("/stream", s.handleSSEStream).Methods(http.MethodGet, http.MethodOptions)

	// Embedded Vue 3 SPA static files with index.html fallback
	if s.webFS != nil {
		r.PathPrefix("/").Handler(s.spaHandler(s.webFS))
	}
	return r
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same-origin by default (no wildcard '*') to prevent cross-site CSRF on LAN instances.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := s.cfg.API.Auth
		if !auth.Enabled || r.URL.Path == "/api/v2/health" {
			next.ServeHTTP(w, r)
			return
		}
		// Check bearer / X-API-Token / query token (for SSE)
		if auth.Token != "" {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok == "" {
				tok = r.Header.Get("X-API-Token")
			}
			if tok == "" {
				tok = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(auth.Token)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Check HTTP Basic Auth
		if auth.Username != "" {
			u, p, ok := r.BasicAuth()
			if ok &&
				subtle.ConstantTimeCompare([]byte(u), []byte(auth.Username)) == 1 &&
				subtle.ConstantTimeCompare([]byte(p), []byte(auth.Password)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ProtoSim"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}

func (s *Server) spaHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
		if clean == "" || clean == "." {
			clean = "index.html"
		}
		if f, err := staticFS.Open(clean); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback to index.html
		data, err := fs.ReadFile(staticFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      s.version,
		"mode":         s.cfg.Network.Mode,
		"scenario":     s.cfg.Scenario,
		"services":     len(s.mgr.ListServices()),
		"auth_enabled": s.cfg.API.Auth.Enabled,
		"time":         time.Now().UTC(),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	stats, err := s.store.QueryOverview(window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.store.QuerySessions(telemetry.SessionFilter{
		Protocol:   q.Get("protocol"),
		RemoteIP:   q.Get("remote_ip"),
		ScannerTag: q.Get("scanner_tag"),
		ProbeHash:  q.Get("probe_hash"),
		Status:     q.Get("status"),
		ParseOnly:  q.Get("parse"),
		Page:       queryInt(q.Get("page"), 1),
		Limit:      queryInt(q.Get("limit"), 50),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	s.bus.Flush()
	id := mux.Vars(r)["id"]
	detail, err := s.store.GetSessionDetail(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleSessionPCAP(w http.ResponseWriter, r *http.Request) {
	s.bus.Flush()
	id := mux.Vars(r)["id"]
	detail, err := s.store.GetSessionDetail(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	pcapData := telemetry.BuildSessionPCAP(detail.Session, detail.Payloads)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="protosim-%s-%s.pcap"`, detail.Session.Protocol, id[:min(8, len(id))]))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pcapData)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.store.QueryEvents(q.Get("protocol"), q.Get("remote_ip"), q.Get("kind"), queryInt(q.Get("page"), 1), queryInt(q.Get("limit"), 50))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.store.QueryCredentials(q.Get("protocol"), q.Get("remote_ip"), queryInt(q.Get("page"), 1), queryInt(q.Get("limit"), 50))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleProbes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.store.QueryProbes(telemetry.ProbeFilter{
		Protocol:   q.Get("protocol"),
		Status:     q.Get("status"),
		ScannerTag: q.Get("scanner_tag"),
		PinnedOnly: q.Get("pinned") == "true" || q.Get("pinned") == "1",
		Page:       queryInt(q.Get("page"), 1),
		Limit:      queryInt(q.Get("limit"), 50),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleProbeGet(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProbe(mux.Vars(r)["hash"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleProbePatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status *string `json:"status"`
		Note   *string `json:"note"`
		Pinned *bool   `json:"pinned"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.store.UpdateProbe(mux.Vars(r)["hash"], body.Status, body.Note, body.Pinned)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleProbeExport(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProbe(mux.Vars(r)["hash"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "hex"
	}
	snippet := telemetry.ExportProbeSnippet(p, format)
	writeJSON(w, http.StatusOK, map[string]any{
		"hash":    p.Hash,
		"format":  format,
		"snippet": snippet,
	})
}

func (s *Server) handleTestRunsList(w http.ResponseWriter, _ *http.Request) {
	runs, err := s.store.ListTestRuns()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": runs})
}

func (s *Server) handleTestRunCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name            string   `json:"name"`
		Scenario        string   `json:"scenario"`
		Notes           string   `json:"notes"`
		TargetProtocols []string `json:"target_protocols"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Scenario == "" {
		body.Scenario = s.cfg.Scenario
	}
	if len(body.TargetProtocols) == 0 {
		for _, svc := range config.Standard61Services(true) {
			body.TargetProtocols = append(body.TargetProtocols, svc.Protocol)
		}
	}
	run, err := s.store.CreateTestRun(body.Name, body.Scenario, body.Notes, body.TargetProtocols)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) handleTestRunStop(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.StopTestRun(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleTestRunCoverage(w http.ResponseWriter, r *http.Request) {
	var fallback []string
	for _, svc := range config.Standard61Services(true) {
		fallback = append(fallback, svc.Protocol)
	}
	cov, err := s.store.GetTestRunCoverage(mux.Vars(r)["id"], fallback)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

func (s *Server) handleTestRunDiff(w http.ResponseWriter, r *http.Request) {
	baseID := r.URL.Query().Get("base")
	targetID := r.URL.Query().Get("target")
	if baseID == "" || targetID == "" {
		writeError(w, http.StatusBadRequest, "base and target query parameters are required")
		return
	}
	var fallback []string
	for _, svc := range config.Standard61Services(true) {
		fallback = append(fallback, svc.Protocol)
	}
	diff, err := s.store.DiffTestRuns(baseID, targetID, fallback)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) handleScannerRulesList(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.store.ListScannerRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (s *Server) handleScannerRuleCreate(w http.ResponseWriter, r *http.Request) {
	var rule telemetry.ScannerRule
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := s.store.CreateScannerRule(rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.bus.ReloadRules()
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleScannerRuleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var rule telemetry.ScannerRule
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.ID = id
	if err := s.store.UpdateScannerRule(rule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.bus.ReloadRules()
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleScannerRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteScannerRule(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.bus.ReloadRules()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleScenariosList(w http.ResponseWriter, _ *http.Request) {
	bindIP := "0.0.0.0"
	if len(s.cfg.Hosts) > 0 && s.cfg.Hosts[0].IP != "" {
		bindIP = s.cfg.Hosts[0].IP
	}
	builtins := config.BuiltinScenarios(bindIP, true)
	custom, _ := s.store.ListScenarios()
	writeJSON(w, http.StatusOK, map[string]any{
		"active":   s.cfg.Scenario,
		"builtins": builtins,
		"custom":   custom,
	})
}

func (s *Server) handleScenarioSave(w http.ResponseWriter, r *http.Request) {
	var rec telemetry.ScenarioRecord
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&rec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rec.ID == "" {
		rec.ID = strings.ToLower(strings.ReplaceAll(rec.Name, " ", "-"))
	}
	if err := s.store.UpsertScenario(rec); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleScenarioApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     string                `json:"id"`
		Preset *config.ScenarioPreset `json:"preset,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var target *config.ScenarioPreset
	if body.Preset != nil {
		target = body.Preset
	} else {
		bindIP := "0.0.0.0"
		if len(s.cfg.Hosts) > 0 && s.cfg.Hosts[0].IP != "" {
			bindIP = s.cfg.Hosts[0].IP
		}
		reqID := body.ID
		if reqID == "all-61-standard" {
			reqID = "all-standard"
		}
		for _, p := range config.BuiltinScenarios(bindIP, true) {
			if p.ID == reqID {
				cp := p
				target = &cp
				break
			}
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "scenario not found")
		return
	}
	started, errs := s.mgr.ApplyScenario(*target)
	writeJSON(w, http.StatusOK, map[string]any{
		"scenario": target.ID,
		"started":  started,
		"errors":   errs,
	})
}

func (s *Server) handleServicesList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     s.mgr.ListServices(),
		"catch_all": s.cfg.CatchAll,
	})
}

var safeFSNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (s *Server) handleServiceAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP       string                 `json:"ip"`
		Protocol string                 `json:"protocol"`
		Port     uint16                 `json:"port"`
		App      string                 `json:"app"`
		Params   map[string]interface{} `json:"params"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	protoLower := strings.ToLower(strings.TrimSpace(body.Protocol))
	if protoLower == "tcp_forward" {
		writeError(w, http.StatusBadRequest, "tcp_forward cannot be created dynamically via API for security reasons")
		return
	}
	if body.Params != nil {
		if rawFS, ok := body.Params["fs_path"]; ok {
			fsStr, _ := rawFS.(string)
			if fsStr != "" && !safeFSNameRe.MatchString(fsStr) {
				writeError(w, http.StatusBadRequest, "fs_path via API only allows built-in static asset names (alphanumeric, '-', '_')")
				return
			}
		}
	}
	if body.IP == "" {
		body.IP = "0.0.0.0"
	}
	err := s.mgr.StartService(body.IP, config.ServiceConfig{
		Protocol: body.Protocol,
		Port:     body.Port,
		App:      body.App,
		Params:   body.Params,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "started"})
}

func (s *Server) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.mgr.StopService(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stopped": id})
}

func (s *Server) handleCatchAllUpdate(w http.ResponseWriter, r *http.Request) {
	var ca config.CatchAllConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&ca); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.UpdateCatchAll(ca); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ca)
}

func (s *Server) handleProtocolsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": network.ListRegisteredProtocols()})
}

func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	cp := *s.cfg
	// Never leak password or webhook secret in GET response
	cp.API.Auth.Password = ""
	cp.API.Auth.Token = ""
	cp.Webhook.Secret = ""
	writeJSON(w, http.StatusOK, cp)
}

func (s *Server) handleConfigRuntimeUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Storage *config.StorageConfig `json:"storage,omitempty"`
		Webhook *config.WebhookConfig `json:"webhook,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Storage != nil {
		s.cfg.Storage.PayloadEnabled = body.Storage.PayloadEnabled
		if body.Storage.MaxPayloadBytes > 0 {
			s.cfg.Storage.MaxPayloadBytes = body.Storage.MaxPayloadBytes
		}
		s.cfg.Storage.RedactCredentials = body.Storage.RedactCredentials
		if body.Storage.RetentionDays > 0 {
			s.cfg.Storage.RetentionDays = body.Storage.RetentionDays
		}
		if body.Storage.MaxSizeMB > 0 {
			s.cfg.Storage.MaxSizeMB = body.Storage.MaxSizeMB
		}
	}
	if body.Webhook != nil {
		if body.Webhook.URL != "" {
			if err := validateWebhookURL(body.Webhook.URL); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		s.cfg.Webhook.Enabled = body.Webhook.Enabled
		s.cfg.Webhook.URL = body.Webhook.URL
		s.cfg.Webhook.OnNewProbe = body.Webhook.OnNewProbe
		if body.Webhook.Secret != "" {
			s.cfg.Webhook.Secret = body.Webhook.Secret
		}
	}
	s.bus.UpdateRuntimeConfig(s.cfg.Storage, s.cfg.Webhook)
	writeJSON(w, http.StatusOK, map[string]any{
		"storage": s.cfg.Storage,
		"webhook": map[string]any{
			"enabled":      s.cfg.Webhook.Enabled,
			"url":          s.cfg.Webhook.URL,
			"on_new_probe": s.cfg.Webhook.OnNewProbe,
		},
	})
}

func (s *Server) handleRetentionRun(w http.ResponseWriter, _ *http.Request) {
	deleted, err := s.store.RunRetention(s.cfg.Storage.RetentionDays, s.cfg.Storage.MaxSizeMB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted_sessions": deleted})
}

func (s *Server) handleUploadRDP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing multipart field 'file'")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 10<<20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ct := http.DetectContentType(data)
	if ct != "image/png" && ct != "image/jpeg" {
		writeError(w, http.StatusBadRequest, "only PNG or JPEG images are allowed")
		return
	}
	if err := os.MkdirAll("./data", 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile("./data/rdp-screen.png", data, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": "./data/rdp-screen.png"})
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid webhook URL: must be http:// or https://")
	}
	host := strings.ToLower(u.Hostname())
	if host == "169.254.169.254" || host == "metadata.google.internal" || host == "100.100.100.200" {
		return fmt.Errorf("webhook URL cannot target cloud metadata endpoints")
	}
	return nil
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := s.bus.Subscribe()
	defer unsub()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(msg)
			if err != nil {
				logrus.Debugf("marshal sse msg: %v", err)
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
