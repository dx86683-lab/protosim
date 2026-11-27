package network

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/config"
	"github.com/dx86683-lab/protosim/internal/telemetry"
)

func TestManagerLocalhostHTTPAndCatchAll(t *testing.T) {
	store, err := telemetry.OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	bus := telemetry.NewBus(store, config.StorageConfig{
		PayloadEnabled:  true,
		MaxPayloadBytes: 65536,
	}, config.WebhookConfig{})
	defer bus.Close()

	cfg := config.DefaultConfig()
	cfg.Network.Mode = config.ModeLocalhost
	cfg.Hosts = []config.HostConfig{
		{
			IP: "127.0.0.1",
			Services: []config.ServiceConfig{
				{Protocol: "http", Port: 28080},
				{Protocol: "redis", Port: 26379},
				{Protocol: "dns", Port: 25353},
			},
		},
	}
	cfg.CatchAll = config.CatchAllConfig{
		Enabled:  true,
		TCPPorts: []uint16{29999},
	}

	mgr, err := NewManager(cfg, bus)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Close()

	// 1. Verify all 61+ protocols registered
	protos := ListRegisteredProtocols()
	if len(protos) < 61 {
		t.Fatalf("expected >= 61 registered protocols, got %d", len(protos))
	}

	// 2. Probe HTTP service with Nmap User-Agent
	conn, err := net.DialTimeout("tcp", "127.0.0.1:28080", 2*time.Second)
	if err != nil {
		t.Fatalf("dial http: %v", err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Nmap Scripting Engine\r\nConnection: close\r\n\r\n"))
	resp, _ := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected HTTP 200 OK, got %q", resp)
	}

	// 3. Probe Redis service
	rconn, err := net.DialTimeout("tcp", "127.0.0.1:26379", 2*time.Second)
	if err != nil {
		t.Fatalf("dial redis: %v", err)
	}
	_, _ = rconn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	rline, _ := bufio.NewReader(rconn).ReadString('\n')
	_ = rconn.Close()
	if !strings.Contains(rline, "PONG") {
		t.Fatalf("expected Redis PONG, got %q", rline)
	}

	// 4. Probe Catch-All TCP port with novel unknown bytes
	cconn, err := net.DialTimeout("tcp", "127.0.0.1:29999", 2*time.Second)
	if err != nil {
		t.Fatalf("dial catchall: %v", err)
	}
	_, _ = cconn.Write([]byte("PROTOSIM-UNKNOWN-PROBE-V1"))
	time.Sleep(50 * time.Millisecond)
	_ = cconn.Close()

	time.Sleep(100 * time.Millisecond)
	bus.Flush()

	// Verify sessions & probes persisted
	sessions, total, err := store.QuerySessions(telemetry.SessionFilter{Limit: 20})
	if err != nil {
		t.Fatalf("QuerySessions: %v", err)
	}
	if total < 3 {
		t.Fatalf("expected at least 3 sessions (http, redis, catch_all), got %d (%+v)", total, sessions)
	}

	probes, pTotal, err := store.QueryProbes(telemetry.ProbeFilter{Limit: 20})
	if err != nil {
		t.Fatalf("QueryProbes: %v", err)
	}
	if pTotal < 3 {
		t.Fatalf("expected at least 3 deduplicated probes, got %d (%+v)", pTotal, probes)
	}

	// Check that HTTP probe was attributed to nmap
	foundNmap := false
	for _, p := range probes {
		if p.Protocol == "http" {
			for _, tag := range p.ScannerTags {
				if tag == "nmap" {
					foundNmap = true
				}
			}
		}
	}
	if !foundNmap {
		t.Fatalf("expected http probe to have scanner tag 'nmap', got %+v", probes)
	}

	// 5. Verify dynamic StopService
	svcs := mgr.ListServices()
	if len(svcs) != 3 {
		t.Fatalf("expected 3 running services, got %d", len(svcs))
	}
	if err := mgr.StopService(svcs[0].ID); err != nil {
		t.Fatalf("StopService: %v", err)
	}
	if got := len(mgr.ListServices()); got != 2 {
		t.Fatalf("expected 2 services after stop, got %d", got)
	}
	fmt.Printf("Verified %d registered protocols, %d sessions, %d probes\n", len(protos), total, pTotal)
}

func TestResolveTunHostIP(t *testing.T) {
	cases := []struct {
		cidr string
		want string
	}{
		{"10.199.0.0/24", "10.199.0.1"},
		{"10.199.0.1/24", "10.199.0.1"},
		{"10.199.0.5/24", "10.199.0.5"},
		{"192.168.0.0/16", "192.168.0.1"},
		{"192.168.50.0/16", "192.168.50.0"},
	}
	for _, tc := range cases {
		ip, ipNet, err := net.ParseCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", tc.cidr, err)
		}
		got := resolveTunHostIP(ip, ipNet).String()
		if got != tc.want {
			t.Errorf("resolveTunHostIP(%q) = %s, want %s", tc.cidr, got, tc.want)
		}
	}
}

func TestManagerExclusions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.TTL = 128
	cfg.Network.Exclusions = []string{"10.0.0.5", "192.168.10.0/24"}
	mgr, err := NewManager(cfg, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if cfg.Network.TTL != 128 {
		t.Fatalf("expected TTL 128, got %d", cfg.Network.TTL)
	}
	if !mgr.isExcluded(&net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 12345}) {
		t.Errorf("expected exact IP 10.0.0.5 to be excluded")
	}
	if !mgr.isExcluded(&net.UDPAddr{IP: net.ParseIP("192.168.10.99"), Port: 5555}) {
		t.Errorf("expected CIDR IP 192.168.10.99 to be excluded")
	}
	if mgr.isExcluded(&net.TCPAddr{IP: net.ParseIP("192.168.11.1"), Port: 12345}) {
		t.Errorf("expected non-matching IP 192.168.11.1 NOT to be excluded")
	}
}

func TestTelemetryHookRedactsEventDetailJSON(t *testing.T) {
	store, err := telemetry.OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	bus := telemetry.NewBus(store, config.StorageConfig{
		PayloadEnabled:    false,
		RedactCredentials: true,
	}, config.WebhookConfig{})
	defer bus.Close()

	hook := NewTelemetryHook(bus, NewSessionTracker())
	entry := &logrus.Entry{
		Time:    time.Now().UTC(),
		Message: "smtp auth attempt",
		Data: logrus.Fields{
			"protocol":  "smtp",
			"remote_ip": "10.0.0.5",
			"username":  "admin",
			"password":  "Sup3rS3cr3t!",
		},
	}
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	bus.Flush()

	events, _, err := store.QueryEvents("", "", "", 1, 10)
	if err != nil || len(events) == 0 {
		t.Fatalf("QueryEvents: %v len=%d", err, len(events))
	}
	if strings.Contains(events[0].DetailJSON, "Sup3rS3cr3t!") {
		t.Fatalf("event detail_json leaked plaintext password: %s", events[0].DetailJSON)
	}
	if !strings.Contains(events[0].DetailJSON, "***REDACTED***") {
		t.Fatalf("expected redacted marker in detail_json: %s", events[0].DetailJSON)
	}
}

func TestApplyScenarioRejectsIncompatibleModeWithoutStoppingServices(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Mode = config.ModeLocalhost
	cfg.Hosts = []config.HostConfig{{
		IP:       "127.0.0.1",
		Services: []config.ServiceConfig{{Protocol: "redis", Port: 28895}},
	}}
	mgr, err := NewManager(cfg, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Close()

	started, errs := mgr.ApplyScenario(config.ScenarioPreset{
		ID:   "virtual-multi-ip-gvisor",
		Mode: config.ModeUserdef,
		Hosts: []config.HostConfig{{
			IP:       "10.99.0.10",
			Services: []config.ServiceConfig{{Protocol: "http", Port: 80}},
		}},
	})
	if started != 0 || len(errs) == 0 {
		t.Fatalf("expected incompatible mode rejection, got started=%d errs=%v", started, errs)
	}
	if got := len(mgr.ListServices()); got != 1 {
		t.Fatalf("expected existing service to remain running, got %d services", got)
	}
}
