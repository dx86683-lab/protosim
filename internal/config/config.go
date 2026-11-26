package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ModeLocalhost = "localhost"
	ModeUserdef   = "userdef"
	ModeAll       = "all"
)

// Config is the root configuration for ProtoSim.
type Config struct {
	Scenario  string          `json:"scenario,omitempty" yaml:"scenario,omitempty"`
	Network   NetworkConfig   `json:"network" yaml:"network"`
	API       APIConfig       `json:"api" yaml:"api"`
	Storage   StorageConfig   `json:"storage" yaml:"storage"`
	CatchAll  CatchAllConfig  `json:"catch_all" yaml:"catch_all"`
	Capture   CaptureConfig   `json:"capture" yaml:"capture"`
	RateLimit RateLimitConfig `json:"rate_limit" yaml:"rate_limit"`
	Webhook   WebhookConfig   `json:"webhook" yaml:"webhook"`
	GeoIP     GeoIPConfig     `json:"geoip" yaml:"geoip"`
	Hosts     []HostConfig    `json:"hosts" yaml:"hosts"`
}

type NetworkConfig struct {
	Mode       string `json:"mode" yaml:"mode"`               // localhost | userdef | all
	CIDR       string `json:"cidr" yaml:"cidr"`               // e.g. 192.168.124.15/24 (bare IP auto-normalized)
	Gateway    string `json:"gateway" yaml:"gateway"`         // optional gateway for TUN modes
	DevName    string `json:"dev_name" yaml:"dev_name"`       // e.g. protosim0
	MTU        int    `json:"mtu" yaml:"mtu"`                 // default 1500
	TimeoutSec int    `json:"timeout_sec" yaml:"timeout_sec"` // per-session idle/read timeout
	LogLevel   string `json:"log_level" yaml:"log_level"`     // debug | info | warn | error
}

type APIConfig struct {
	Listen string     `json:"listen" yaml:"listen"` // default 0.0.0.0:5555
	Auth   AuthConfig `json:"auth" yaml:"auth"`
}

type AuthConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"` // default false (LAN-friendly)
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Token    string `json:"token,omitempty" yaml:"token,omitempty"`
}

type StorageConfig struct {
	DBPath            string `json:"db_path" yaml:"db_path"`                       // default ./data/protosim.db
	PayloadEnabled    bool   `json:"payload_enabled" yaml:"payload_enabled"`       // default true
	MaxPayloadBytes   int    `json:"max_payload_bytes" yaml:"max_payload_bytes"`   // default 65536 (64 KiB)
	RedactCredentials bool   `json:"redact_credentials" yaml:"redact_credentials"` // default false
	RetentionDays     int    `json:"retention_days" yaml:"retention_days"`         // default 30
	MaxSizeMB         int    `json:"max_size_mb" yaml:"max_size_mb"`               // default 2048
}

type CatchAllConfig struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	TCPPorts []uint16 `json:"tcp_ports,omitempty" yaml:"tcp_ports,omitempty"`
	UDPPorts []uint16 `json:"udp_ports,omitempty" yaml:"udp_ports,omitempty"`
}

type CaptureConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Device  string `json:"device,omitempty" yaml:"device,omitempty"`
	BPF     string `json:"bpf,omitempty" yaml:"bpf,omitempty"`
}

type RateLimitConfig struct {
	Enabled     bool    `json:"enabled" yaml:"enabled"` // default false
	PerIPPerSec float64 `json:"per_ip_per_sec" yaml:"per_ip_per_sec"`
	Burst       int     `json:"burst" yaml:"burst"`
}

type WebhookConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"` // default false
	URL        string `json:"url,omitempty" yaml:"url,omitempty"`
	Secret     string `json:"secret,omitempty" yaml:"secret,omitempty"`
	OnNewProbe bool   `json:"on_new_probe" yaml:"on_new_probe"`
}

type GeoIPConfig struct {
	CityDBPath string `json:"city_db_path,omitempty" yaml:"city_db_path,omitempty"`
}

type HostConfig struct {
	IP       string          `json:"ip" yaml:"ip"`
	Services []ServiceConfig `json:"services" yaml:"services"`
}

type ServiceConfig struct {
	Protocol string                 `json:"protocol" yaml:"protocol"`
	Port     uint16                 `json:"port" yaml:"port"`
	App      string                 `json:"app,omitempty" yaml:"app,omitempty"`
	Params   map[string]interface{} `json:"params,omitempty" yaml:"params,omitempty"`
}

// DefaultConfig returns a ready-to-run Config with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Scenario: "all-standard",
		Network: NetworkConfig{
			Mode:       ModeLocalhost,
			CIDR:       "0.0.0.0/24",
			DevName:    "protosim0",
			MTU:        1500,
			TimeoutSec: 30,
			LogLevel:   "info",
		},
		API: APIConfig{
			Listen: "0.0.0.0:5555",
			Auth: AuthConfig{
				Enabled: false,
			},
		},
		Storage: StorageConfig{
			DBPath:            "./data/protosim.db",
			PayloadEnabled:    true,
			MaxPayloadBytes:   65536,
			RedactCredentials: false,
			RetentionDays:     30,
			MaxSizeMB:         2048,
		},
		CatchAll: CatchAllConfig{
			Enabled:  false,
			TCPPorts: []uint16{9999},
			UDPPorts: []uint16{9999},
		},
		Capture: CaptureConfig{
			Enabled: false,
		},
		RateLimit: RateLimitConfig{
			Enabled:     false,
			PerIPPerSec: 50,
			Burst:       100,
		},
		Webhook: WebhookConfig{
			Enabled:    false,
			OnNewProbe: true,
		},
		Hosts: []HostConfig{
			{
				IP:       "0.0.0.0",
				Services: Standard61Services(false),
			},
		},
	}
}

// Normalize applies defaults and fixes bare IPs in CIDR fields.
func (c *Config) Normalize() error {
	if c.Network.Mode == "" {
		c.Network.Mode = ModeLocalhost
	}
	switch c.Network.Mode {
	case ModeLocalhost, ModeUserdef, ModeAll:
	default:
		return fmt.Errorf("invalid network.mode %q (want localhost|userdef|all)", c.Network.Mode)
	}
	if c.Network.CIDR != "" {
		norm, err := NormalizeCIDR(c.Network.CIDR)
		if err != nil {
			return fmt.Errorf("invalid network.cidr %q: %w", c.Network.CIDR, err)
		}
		c.Network.CIDR = norm
	} else {
		c.Network.CIDR = "0.0.0.0/24"
	}
	if c.Network.DevName == "" {
		c.Network.DevName = "protosim0"
	}
	if c.Network.MTU <= 0 {
		c.Network.MTU = 1500
	}
	if c.Network.TimeoutSec <= 0 {
		c.Network.TimeoutSec = 30
	}
	if c.Network.LogLevel == "" {
		c.Network.LogLevel = "info"
	}
	if c.API.Listen == "" {
		c.API.Listen = "0.0.0.0:5555"
	}
	if c.Storage.DBPath == "" {
		c.Storage.DBPath = "./data/protosim.db"
	}
	if c.Storage.MaxPayloadBytes <= 0 {
		c.Storage.MaxPayloadBytes = 65536
	}
	if c.Storage.RetentionDays <= 0 {
		c.Storage.RetentionDays = 30
	}
	if c.Storage.MaxSizeMB <= 0 {
		c.Storage.MaxSizeMB = 2048
	}
	if c.RateLimit.PerIPPerSec <= 0 {
		c.RateLimit.PerIPPerSec = 50
	}
	if c.RateLimit.Burst <= 0 {
		c.RateLimit.Burst = 100
	}
	return nil
}

// NormalizeCIDR converts a bare IPv4/IPv6 address into a valid CIDR string (e.g. 192.168.1.10 -> 192.168.1.10/24).
func NormalizeCIDR(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty address")
	}
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return "", err
		}
		return s, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("not a valid IP or CIDR: %q", s)
	}
	if ip.To4() != nil {
		return ip.String() + "/24", nil
	}
	return ip.String() + "/64", nil
}

// LoadFile loads a JSON or YAML configuration file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	cfg.Hosts = nil
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse yaml %s: %w", path, err)
		}
	default:
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse json %s: %w", path, err)
		}
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveFile persists the configuration as pretty JSON or YAML based on extension.
func SaveFile(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var (
		data []byte
		err  error
	)
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(cfg)
	default:
		data, err = json.MarshalIndent(cfg, "", "  ")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
