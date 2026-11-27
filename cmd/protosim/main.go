package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/api"
	"github.com/dx86683-lab/protosim/internal/config"
	"github.com/dx86683-lab/protosim/internal/network"
	"github.com/dx86683-lab/protosim/internal/telemetry"
	"github.com/dx86683-lab/protosim/web"
)

var Version = "1.3.4"

func main() {
	if len(os.Args) < 2 {
		runCmd(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "gen-config":
		genConfigCmd(os.Args[2:])
	case "list-protocols":
		listProtocolsCmd()
	case "version", "-v", "--version":
		fmt.Printf("ProtoSim %s\n", Version)
	case "-h", "--help", "help":
		printUsage()
	default:
		// Allow flags directly without subcommand (e.g. `protosim -c config.json`)
		if strings.HasPrefix(os.Args[1], "-") {
			runCmd(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`ProtoSim %s — Protocol Scan Simulator & Probe Observatory

Usage:
  protosim run [flags]           Start protocol simulator, SQLite observatory & Web UI
  protosim gen-config [flags]    Generate a ready-to-use JSON/YAML configuration file
  protosim list-protocols        List all 159+ supported protocols and default ports
  protosim version               Print version information
`, Version)
}

func listProtocolsCmd() {
	protos := network.ListRegisteredProtocols()
	fmt.Printf("Registered protocols (%d):\n", len(protos))
	for _, p := range protos {
		fmt.Printf("  %-18s %-4s default_port=%d\n", p.Name, p.Transport, p.DefaultPort)
	}
}

func genConfigCmd(args []string) {
	fs := flag.NewFlagSet("gen-config", flag.ExitOnError)
	out := fs.String("o", "protosim.json", "Output config file path (.json or .yaml)")
	mode := fs.String("mode", config.ModeLocalhost, "Network mode: localhost | userdef | all")
	cidr := fs.String("cidr", "0.0.0.0/24", "Network CIDR or IP")
	listen := fs.String("listen", "0.0.0.0:5555", "Web UI & API listen address")
	scenario := fs.String("scenario", "all-standard", "Preset scenario: all-standard | high-ports-obfuscated | core-20-quick | virtual-multi-ip-gvisor")
	safeSSH := fs.Bool("safe-ssh", true, "Bind simulated SSH to port 2222 instead of 22")
	_ = fs.Parse(args)
	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

	cfg := config.DefaultConfig()
	cfg.Network.Mode = *mode
	cfg.Network.CIDR = *cidr
	cfg.API.Listen = *listen
	cfg.Scenario = *scenario
	for _, p := range config.BuiltinScenarios("0.0.0.0", *safeSSH) {
		if p.ID == *scenario {
			cfg.Hosts = p.Hosts
			if !explicitFlags["mode"] && p.Mode != "" {
				cfg.Network.Mode = p.Mode
			}
			if !explicitFlags["cidr"] && p.Mode != "" && p.Mode != config.ModeLocalhost && len(p.Hosts) > 0 && p.Hosts[0].IP != "" && p.Hosts[0].IP != "0.0.0.0" {
				cfg.Network.CIDR = p.Hosts[0].IP + "/24"
			}
			break
		}
	}
	if err := cfg.Normalize(); err != nil {
		logrus.Fatalf("invalid config: %v", err)
	}
	if err := config.SaveFile(*out, cfg); err != nil {
		logrus.Fatalf("save config %s: %v", *out, err)
	}
	fmt.Printf("Generated %s (scenario=%s, mode=%s, services=%d)\n", *out, cfg.Scenario, cfg.Network.Mode, countServices(cfg))
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to JSON/YAML configuration file")
	listen := fs.String("listen", "", "Override Web UI & API listen address (default 0.0.0.0:5555)")
	mode := fs.String("mode", "", "Override network mode (localhost | userdef | all)")
	dbPath := fs.String("db", "", "Override SQLite database path (default ./data/protosim.db)")
	authToken := fs.String("auth-token", "", "Enable Bearer/X-API-Token auth with this token")
	catchTCP := fs.String("catch-all-tcp", "", "Comma-separated TCP ports for Catch-All probe capture (e.g. 9999,10000)")
	catchUDP := fs.String("catch-all-udp", "", "Comma-separated UDP ports for Catch-All probe capture")
	safeSSH := fs.Bool("safe-ssh", true, "When using default built-in config, bind SSH to 2222")
	_ = fs.Parse(args)

	var cfg *config.Config
	var err error
	if *cfgPath != "" {
		cfg, err = config.LoadFile(*cfgPath)
		if err != nil {
			logrus.Fatalf("load config %s: %v", *cfgPath, err)
		}
	} else {
		cfg = config.DefaultConfig()
		cfg.Hosts = []config.HostConfig{{IP: "0.0.0.0", Services: config.Standard61Services(*safeSSH)}}
	}

	if *listen != "" {
		cfg.API.Listen = *listen
	}
	if *mode != "" {
		cfg.Network.Mode = *mode
	}
	if *dbPath != "" {
		cfg.Storage.DBPath = *dbPath
	}
	if *authToken != "" {
		cfg.API.Auth.Enabled = true
		cfg.API.Auth.Token = *authToken
	}
	if *catchTCP != "" {
		cfg.CatchAll.Enabled = true
		cfg.CatchAll.TCPPorts = parsePorts(*catchTCP)
	}
	if *catchUDP != "" {
		cfg.CatchAll.Enabled = true
		cfg.CatchAll.UDPPorts = parsePorts(*catchUDP)
	}
	if err := cfg.Normalize(); err != nil {
		logrus.Fatalf("config validation failed: %v", err)
	}

	if lvl, err := logrus.ParseLevel(cfg.Network.LogLevel); err == nil {
		logrus.SetLevel(lvl)
	}

	store, err := telemetry.OpenStore(cfg.Storage.DBPath)
	if err != nil {
		logrus.Fatalf("open sqlite store %s: %v", cfg.Storage.DBPath, err)
	}
	defer store.Close()

	bus := telemetry.NewBus(store, cfg.Storage, cfg.Webhook)
	defer bus.Close()

	mgr, err := network.NewManager(cfg, bus)
	if err != nil {
		logrus.Fatalf("init network manager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		logrus.Fatalf("start network manager: %v", err)
	}
	defer mgr.Close()

	// Background hourly rolling retention (never touches `probes` or pinned samples).
	retStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-retStop:
				return
			case <-ticker.C:
				if n, err := store.RunRetention(cfg.Storage.RetentionDays, cfg.Storage.MaxSizeMB); err == nil && n > 0 {
					logrus.Infof("[Retention] pruned %d expired sessions", n)
				}
			}
		}
	}()
	defer close(retStop)

	apiSrv := api.NewServer(cfg, bus, mgr, web.DistFS(), Version)
	httpSrv := &http.Server{
		Addr:              cfg.API.Listen,
		Handler:           apiSrv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if !cfg.API.Auth.Enabled && (strings.HasPrefix(cfg.API.Listen, "0.0.0.0:") || strings.HasPrefix(cfg.API.Listen, ":")) {
			logrus.Warn("[SECURITY] Web UI & API is listening on 0.0.0.0 WITHOUT authentication. Pass --auth-token <secret> or bind 127.0.0.1 when exposed to untrusted networks.")
		}
		logrus.Infof("ProtoSim %s listening Web UI & API on http://%s (mode=%s, services=%d, auth=%v, db=%s)",
			Version, cfg.API.Listen, cfg.Network.Mode, len(mgr.ListServices()), cfg.API.Auth.Enabled, cfg.Storage.DBPath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("API server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logrus.Infof("Received %v, shutting down cleanly...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	mgr.Close()
	bus.Close()
	_ = store.Close()
	_ = json.NewEncoder(os.Stdout) // keep import clean if needed
}

func parsePorts(csv string) []uint16 {
	var out []uint16
	for _, part := range strings.Split(csv, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && p > 0 && p <= 65535 {
			out = append(out, uint16(p))
		}
	}
	return out
}

func countServices(cfg *config.Config) int {
	n := 0
	for _, h := range cfg.Hosts {
		n += len(h.Services)
	}
	return n
}
