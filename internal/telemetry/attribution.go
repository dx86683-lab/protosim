package telemetry

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

// AttributionInput contains signals extracted from a connection or its initial payload.
type AttributionInput struct {
	RemoteIP  string
	UserAgent string
	JA3       string
	Payload   []byte
}

type compiledRule struct {
	rule ScannerRule
	cidr *net.IPNet
	re   *regexp.Regexp
	ua   string
	ja3  string
}

// Attributor matches incoming connections/probes against configurable scanner attribution rules.
type Attributor struct {
	mu    sync.RWMutex
	rules []compiledRule
}

// DefaultScannerRules returns built-in rules recognizing common scanners and tools.
func DefaultScannerRules() []ScannerRule {
	return []ScannerRule{
		{Name: "Nmap HTTP/NSE User-Agent", Tag: "nmap", MatchType: "ua", Pattern: "nmap", Enabled: true},
		{Name: "Nmap Service Probe Payload", Tag: "nmap", MatchType: "payload_regex", Pattern: `(?i)(Nmap|nm@p|GET /nice%20ports|HELP\r\n)`, Enabled: true},
		{Name: "ZGrab / ZGrab2 User-Agent", Tag: "zgrab", MatchType: "ua", Pattern: "zgrab", Enabled: true},
		{Name: "Censys Inspect User-Agent", Tag: "censys", MatchType: "ua", Pattern: "censys", Enabled: true},
		{Name: "Censys CIDR 162.142.125.0/24", Tag: "censys", MatchType: "cidr", Pattern: "162.142.125.0/24", Enabled: true},
		{Name: "Censys CIDR 167.94.138.0/24", Tag: "censys", MatchType: "cidr", Pattern: "167.94.138.0/24", Enabled: true},
		{Name: "Shodan User-Agent", Tag: "shodan", MatchType: "ua", Pattern: "shodan", Enabled: true},
		{Name: "Masscan Payload Signature", Tag: "masscan", MatchType: "payload_regex", Pattern: `(?i)masscan`, Enabled: true},
		{Name: "Nuclei Scanner User-Agent", Tag: "nuclei", MatchType: "ua", Pattern: "nuclei", Enabled: true},
		{Name: "Internal Scanner UA", Tag: "self-scanner", MatchType: "ua", Pattern: "internal-scanner", Enabled: true},
		{Name: "cURL Client", Tag: "curl", MatchType: "ua", Pattern: "curl/", Enabled: true},
		{Name: "Python Requests/Urllib", Tag: "python", MatchType: "ua", Pattern: "python-", Enabled: true},
		{Name: "Go HTTP Client", Tag: "go-client", MatchType: "ua", Pattern: "go-http-client", Enabled: true},
	}
}

func NewAttributor(rules []ScannerRule) *Attributor {
	a := &Attributor{}
	a.Reload(rules)
	return a
}

// Reload compiles and replaces the active attribution rule set atomically.
func (a *Attributor) Reload(rules []ScannerRule) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled || strings.TrimSpace(r.Pattern) == "" || strings.TrimSpace(r.Tag) == "" {
			continue
		}
		cr := compiledRule{rule: r}
		switch strings.ToLower(strings.TrimSpace(r.MatchType)) {
		case "cidr":
			pat := strings.TrimSpace(r.Pattern)
			if !strings.Contains(pat, "/") {
				if ip := net.ParseIP(pat); ip != nil {
					if ip.To4() != nil {
						pat += "/32"
					} else {
						pat += "/128"
					}
				}
			}
			_, ipNet, err := net.ParseCIDR(pat)
			if err != nil {
				continue
			}
			cr.cidr = ipNet
		case "ua":
			cr.ua = strings.ToLower(strings.TrimSpace(r.Pattern))
		case "ja3":
			cr.ja3 = strings.ToLower(strings.TrimSpace(r.Pattern))
		case "payload_regex":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue
			}
			cr.re = re
		default:
			continue
		}
		compiled = append(compiled, cr)
	}
	a.mu.Lock()
	a.rules = compiled
	a.mu.Unlock()
}

// Match returns the first matching scanner tag or "unknown".
func (a *Attributor) Match(in AttributionInput) string {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()

	ua := in.UserAgent
	if ua == "" && len(in.Payload) > 0 {
		ua = ExtractHTTPUserAgent(in.Payload)
	}
	uaLower := strings.ToLower(ua)
	ja3Lower := strings.ToLower(strings.TrimSpace(in.JA3))
	ip := net.ParseIP(strings.TrimSpace(in.RemoteIP))

	// Check higher-specificity rules (cidr, ja3, ua, payload_regex) in order.
	for _, cr := range rules {
		switch cr.rule.MatchType {
		case "cidr":
			if ip != nil && cr.cidr != nil && cr.cidr.Contains(ip) {
				return cr.rule.Tag
			}
		case "ja3":
			if ja3Lower != "" && ja3Lower == cr.ja3 {
				return cr.rule.Tag
			}
		case "ua":
			if uaLower != "" && strings.Contains(uaLower, cr.ua) {
				return cr.rule.Tag
			}
		case "payload_regex":
			if len(in.Payload) > 0 && cr.re != nil && cr.re.Match(in.Payload) {
				return cr.rule.Tag
			}
		}
	}
	return "unknown"
}

// ExtractHTTPUserAgent quickly scans an HTTP request header block for a User-Agent line.
func ExtractHTTPUserAgent(payload []byte) string {
	maxScan := len(payload)
	if maxScan > 4096 {
		maxScan = 4096
	}
	text := string(payload[:maxScan])
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if len(line) > 11 && strings.EqualFold(line[:11], "user-agent:") {
			return strings.TrimSpace(line[11:])
		}
	}
	return ""
}
