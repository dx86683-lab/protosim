# ProtoSim — Protocol Scan Simulator & Probe Observatory

<p align="center">
  <b>English</b> | <a href="README.zh-CN.md">简体中文</a>
</p>

**ProtoSim** is a standalone, single-binary **protocol scan simulator and probe observatory** designed for developing/benchmarking asset scanners and capturing novel network probes in the wild.

---

## Key Features

- **159 RFC-Verified Protocols**: Full-spectrum protocol matrix covering web, remote access (`winrm`/`winrms`, `ssh`, `rdp`, `vnc`, `telnet`, `x11`, `xdmcp`, `rexec`/`rlogin`/`rsh`), out-of-band & printing (`ipmi`, `jetdirect`, `ipp`, `lpd`), databases & big data (`mysql`, `postgres`, `mssql`, `oracle/tns`, `mongodb`, `redis`, `clickhouse`, `couchdb`, `influxdb`, `neo4j`/`bolt`, `solr`, `hadoop-yarn`, `hdfs`, `firebird`, `db2`, `informix`, `sybase`, `ceph-mon`), cloud-native & DevOps (`k8s-apiserver`, `kubelet`, `docker`, `docker-registry`, `etcd`, `consul`, `vault`, `prometheus`, `minio`, `grafana`, `kibana`, `jenkins`, `kafka`, `nats`, `zookeeper`, `epmd`, `stomp`, `gearman`, `beanstalkd`, `fastcgi`, `grpc`, `thrift`, `http-proxy`, `ajp`, `jdwp`, `activemq`, `dubbo`, `git`, `svn`, `distcc`), ICS/SCADA (`modbus`, `s7`, `bacnet`, `dnp3`, `eip`, `opcua`, `knx`, `hart-ip`, `codesys`, `proconos`, `iec104`, `fox`, `omron`, `ge-srtp`, `pcworx`, `melsecq-discover`, `redlion-crimson3`), and network/TLS/special infrastructure (`bgp`, `rip`, `nat-pmp`, `wireguard`, `kerberos`, `radius`, `tacacs`, `stun`, `openvpn`, `xmpp`, `rtmp`, `bitcoin`, `ipfs`, `minecraft`, `source-rcon`, `teamspeak`, `gopher`, `dict`, `mdns`, `irc`, `nntp`, `tftp`, `rsync`, `socks4/5`, `smtps`/`ldaps`/`imaps`/`pop3s`/`ftps`/`mqtts`/`amqps`).
- **Zero-Dependency SQLite WAL Store**: Built-in pure-Go SQLite (`modernc.org/sqlite`) with asynchronous batched writes, rolling retention (default 30 days / 2 GB), and **permanent preservation of deduplicated probes and pinned samples**.
- **Probe Library (Auto-Clustering)**: Deduplicates incoming probes by `(protocol, port, first_payload_sha256)`, tracking first/last seen, hit counts, unique source IPs, Hex/ASCII previews, triage status (`new` / `known` / `adopted`), and 1-click export to **Hex / Python / Go** reproducer snippets.
- **Scanner Attribution Engine**: Hot-reloadable rule engine matching `cidr`, `ua` (HTTP User-Agent), `ja3` (TLS fingerprint), and `payload_regex` to tag traffic (`nmap`, `zgrab`, `censys`, `shodan`, `masscan`, `self-scanner`, `unknown`, etc.).
- **Test Runs & Full-Protocol Coverage Matrix**: Start/stop named evaluation runs, inspect per-protocol coverage across all 159 protocols (`hit` / `missed` / `parse_error` / average latency), and diff any two runs side by side.
- **Full Session Replay & PCAP Export**: Captures bounded bidirectional payloads (64 KiB cap per session) — always persisting initial bytes even when protocol parsing fails or peers disconnect early — plus optional TCP/UDP **Catch-All** ports and 1-click Wireshark-ready `.pcap` export.
- **Embedded Vue 3 Console**: Single binary (`//go:embed`) bundling 7 observability views built with Vue 3 + Vite + TypeScript + Element Plus + ECharts, listening on `0.0.0.0:5555` by default.

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ([简体中文](docs/ARCHITECTURE.zh-CN.md)) for module layout and database schema details.

```mermaid
flowchart LR
    Scanners["Asset Scanners / Internet Probes"] --> Net["Network Engine (localhost / TUN + gVisor)"]
    Net --> Proto["159 RFC Protocol Handlers + Catch-All"]
    Proto --> Bus["Telemetry Bus (Attribution + Probe Dedup + Batch Writer)"]
    Bus --> DB["SQLite WAL Store"]
    Bus -.SSE.-> API["/api/v2 REST + SSE Server"]
    DB <--> API <--> UI["Embedded Vue 3 Console (:5555)"]
```

---

## Quick Start

```bash
# 1. List all registered protocols and default ports
./bin/protosim list-protocols

# 2. Generate a ready-to-use configuration file (optional)
./bin/protosim gen-config -o protosim.json --scenario all-standard --safe-ssh=true

# 3. Start the simulator and Web UI (default: http://0.0.0.0:5555)
sudo ./bin/protosim run -c protosim.json --catch-all-tcp 9999 --catch-all-udp 9999
```

### CLI Flags (`protosim run`)

| Flag | Description | Default |
|---|---|---|
| `-c` | Path to JSON or YAML config file | Built-in 159-protocol config |
| `--listen` | Web UI & `/api/v2/*` listen address | `0.0.0.0:5555` |
| `--mode` | Network mode (`localhost` \| `userdef` \| `all`) | `localhost` |
| `--db` | SQLite database file path | `./data/protosim.db` |
| `--auth-token` | Enable Bearer / `X-API-Token` authentication | Disabled (LAN-friendly) |
| `--catch-all-tcp` | Comma-separated Catch-All TCP ports | Disabled |
| `--catch-all-udp` | Comma-separated Catch-All UDP ports | Disabled |
| `--safe-ssh` | Map simulated SSH to port `2222` instead of `22` | `true` |

---

## Building from Source

```bash
# 1. Build embedded Vue 3 frontend
cd web && npm install && npm run build && cd ..

# 2. Build standalone Go binary
go build -o bin/protosim ./cmd/protosim
```
