package config

import "encoding/json"

// ScenarioPreset describes a reusable host/service layout for ProtoSim.
type ScenarioPreset struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Mode        string       `json:"mode"`
	Hosts       []HostConfig `json:"hosts"`
}

// Standard61Services returns all 61 RFC-verified protocols on their standard ports.
// When safeSSHPort is true, SSH is mapped to 2222 so host SSH on port 22 is not shadowed.
func Standard61Services(safeSSHPort bool) []ServiceConfig {
	sshPort := uint16(22)
	if safeSSHPort {
		sshPort = 2222
	}
	return []ServiceConfig{
		{Protocol: "ajp", Port: 8009},
		{Protocol: "amqp", Port: 5672},
		{Protocol: "bacnet", Port: 47808},
		{Protocol: "bgp", Port: 179},
		{Protocol: "cassandra", Port: 9160},
		{Protocol: "coap", Port: 5683},
		{Protocol: "dcerpc", Port: 135},
		{Protocol: "dht", Port: 6881},
		{Protocol: "dnp3", Port: 20000},
		{Protocol: "dns", Port: 53},
		{Protocol: "docker", Port: 2375},
		{Protocol: "eip", Port: 44818},
		{Protocol: "elasticsearch", Port: 9200},
		{Protocol: "eos", Port: 8888},
		{Protocol: "etcd", Port: 2379},
		{Protocol: "ethereum", Port: 8545},
		{Protocol: "fox", Port: 1911},
		{Protocol: "ftp", Port: 21},
		{Protocol: "ge-srtp", Port: 18245},
		{Protocol: "http", Port: 80},
		{Protocol: "https", Port: 443},
		{Protocol: "icap", Port: 1344},
		{Protocol: "iec104", Port: 2404},
		{Protocol: "ike", Port: 500},
		{Protocol: "imap", Port: 143},
		{Protocol: "java-rmi", Port: 1099},
		{Protocol: "jdwp", Port: 8000},
		{Protocol: "kafka", Port: 9092},
		{Protocol: "l2tp", Port: 1701},
		{Protocol: "ldap", Port: 389},
		{Protocol: "melsecq-discover", Port: 5007},
		{Protocol: "memcache", Port: 11211},
		{Protocol: "modbus", Port: 502},
		{Protocol: "mongodb", Port: 27017},
		{Protocol: "mqtt", Port: 1883},
		{Protocol: "mssql", Port: 1433},
		{Protocol: "mysql", Port: 3306},
		{Protocol: "netbios", Port: 137},
		{Protocol: "nfs", Port: 2049},
		{Protocol: "ntp", Port: 123},
		{Protocol: "omron", Port: 9600},
		{Protocol: "onvif", Port: 3702},
		{Protocol: "pcworx", Port: 1962},
		{Protocol: "pop3", Port: 110},
		{Protocol: "portmap", Port: 111},
		{Protocol: "postgres", Port: 5432},
		{Protocol: "pptp", Port: 1723},
		{Protocol: "rdp", Port: 3389},
		{Protocol: "redis", Port: 6379},
		{Protocol: "redlion-crimson3", Port: 789},
		{Protocol: "rsync", Port: 873},
		{Protocol: "rtsp", Port: 554},
		{Protocol: "s7", Port: 102},
		{Protocol: "sip", Port: 5060},
		{Protocol: "smb", Port: 445},
		{Protocol: "smtp", Port: 25},
		{Protocol: "snmp", Port: 161},
		{Protocol: "socks4", Port: 1081},
		{Protocol: "socks5", Port: 1080},
		{Protocol: "ssdp", Port: 1900},
		{Protocol: "ssh", Port: sshPort},
		{Protocol: "tcp_echo", Port: 1234},
		{Protocol: "telnet", Port: 23},
		{Protocol: "tftp", Port: 69},
		{Protocol: "tns", Port: 1521},
		{Protocol: "udp_echo", Port: 1234},
		{Protocol: "vnc", Port: 5900},
		{Protocol: "weblogic", Port: 7001},
		{Protocol: "wemo", Port: 49152},
		{Protocol: "winbox", Port: 8291},
		{Protocol: "zookeeper", Port: 2181},
	}
}

// HighPortServices maps all 61 protocols onto deterministic non-standard high ports (20001-20061)
// for testing protocol identification independent of port numbers.
func HighPortServices() []ServiceConfig {
	base := Standard61Services(true)
	out := make([]ServiceConfig, 0, len(base))
	for i, svc := range base {
		svc.Port = uint16(20001 + i)
		out = append(out, svc)
	}
	return out
}

// Core20Services provides a lightweight high-frequency protocol set for quick smoke tests.
func Core20Services(safeSSHPort bool) []ServiceConfig {
	sshPort := uint16(22)
	if safeSSHPort {
		sshPort = 2222
	}
	return []ServiceConfig{
		{Protocol: "http", Port: 80},
		{Protocol: "https", Port: 443},
		{Protocol: "ssh", Port: sshPort},
		{Protocol: "ftp", Port: 21},
		{Protocol: "telnet", Port: 23},
		{Protocol: "smtp", Port: 25},
		{Protocol: "dns", Port: 53},
		{Protocol: "pop3", Port: 110},
		{Protocol: "imap", Port: 143},
		{Protocol: "snmp", Port: 161},
		{Protocol: "ldap", Port: 389},
		{Protocol: "smb", Port: 445},
		{Protocol: "modbus", Port: 502},
		{Protocol: "rtsp", Port: 554},
		{Protocol: "mssql", Port: 1433},
		{Protocol: "mqtt", Port: 1883},
		{Protocol: "mysql", Port: 3306},
		{Protocol: "rdp", Port: 3389},
		{Protocol: "postgres", Port: 5432},
		{Protocol: "redis", Port: 6379},
	}
}

// BuiltinScenarios returns the default set of switchable scenarios.
func BuiltinScenarios(bindIP string, safeSSHPort bool) []ScenarioPreset {
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	return []ScenarioPreset{
		{
			ID:          "all-61-standard",
			Name:        "All 61 Protocols (Standard Ports)",
			Description: "Full 61 RFC-verified protocols bound on standard ports (SSH on 2222 when safe mode enabled).",
			Mode:        ModeLocalhost,
			Hosts: []HostConfig{
				{IP: bindIP, Services: Standard61Services(safeSSHPort)},
			},
		},
		{
			ID:          "high-ports-obfuscated",
			Name:        "All 61 Protocols (Non-Standard High Ports)",
			Description: "All 61 protocols shifted to 20001-20061 to test port-agnostic protocol recognition.",
			Mode:        ModeLocalhost,
			Hosts: []HostConfig{
				{IP: bindIP, Services: HighPortServices()},
			},
		},
		{
			ID:          "core-20-quick",
			Name:        "Core 20 Protocols (Quick Lab)",
			Description: "Top 20 common web, remote access, database, and ICS protocols for rapid scanner iteration.",
			Mode:        ModeLocalhost,
			Hosts: []HostConfig{
				{IP: bindIP, Services: Core20Services(safeSSHPort)},
			},
		},
		{
			ID:          "virtual-multi-ip-gvisor",
			Name:        "Virtual Multi-IP Subnet (gVisor)",
			Description: "Three virtual hosts (Web/DB/ICS) for gVisor userdef subnet simulation.",
			Mode:        ModeUserdef,
			Hosts: []HostConfig{
				{
					IP: "10.99.0.10",
					Services: []ServiceConfig{
						{Protocol: "http", Port: 80},
						{Protocol: "https", Port: 443},
						{Protocol: "ssh", Port: 22},
						{Protocol: "ftp", Port: 21},
						{Protocol: "dns", Port: 53},
						{Protocol: "smtp", Port: 25},
					},
				},
				{
					IP: "10.99.0.20",
					Services: []ServiceConfig{
						{Protocol: "mysql", Port: 3306},
						{Protocol: "postgres", Port: 5432},
						{Protocol: "redis", Port: 6379},
						{Protocol: "mongodb", Port: 27017},
						{Protocol: "elasticsearch", Port: 9200},
						{Protocol: "mssql", Port: 1433},
						{Protocol: "tns", Port: 1521},
					},
				},
				{
					IP: "10.99.0.30",
					Services: []ServiceConfig{
						{Protocol: "modbus", Port: 502},
						{Protocol: "s7", Port: 102},
						{Protocol: "bacnet", Port: 47808},
						{Protocol: "iec104", Port: 2404},
						{Protocol: "fox", Port: 1911},
						{Protocol: "omron", Port: 9600},
						{Protocol: "ge-srtp", Port: 18245},
						{Protocol: "melsecq-discover", Port: 5007},
					},
				},
			},
		},
	}
}

// MarshalJSONString encodes a ScenarioPreset as a JSON string for storage.
func (s ScenarioPreset) MarshalJSONString() string {
	b, _ := json.Marshal(s)
	return string(b)
}
