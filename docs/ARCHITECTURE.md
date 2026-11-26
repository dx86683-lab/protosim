# ProtoSim Architecture

<p align="center">
  <b>English</b> | <a href="ARCHITECTURE.zh-CN.md">简体中文</a>
</p>

## 1. Module Overview

- `cmd/protosim/`: CLI entrypoint (`run`, `gen-config`, `list-protocols`, `version`), config loading, hourly rolling retention scheduler, and graceful shutdown.
- `internal/config/`: Strongly typed JSON/YAML configuration model, automatic bare-IP CIDR normalization, and 4 built-in scenario presets (`all-standard`, `high-ports-obfuscated`, `core-20-quick`, `virtual-multi-ip-gvisor`).
- `internal/telemetry/`:
  - `store_sqlite.go`: Pure-Go `modernc.org/sqlite` WAL store with 8 core tables (`sessions`, `events`, `probes`, `credentials`, `payloads`, `test_runs`, `scanner_rules`, `scenarios`) plus `probe_ips` for accurate unique-IP counting.
  - `bus.go`: Bounded asynchronous batch writer (200 ms / 200 items), real-time SSE broadcaster, and optional HMAC-signed new-probe Webhook notifier.
  - `attribution.go`: Thread-safe, hot-reloadable scanner attribution engine (`cidr`, `ua`, `ja3`, `payload_regex`).
  - `pcap.go`: Pure-Go libpcap synthesizer generating Wireshark-compatible Ethernet/IPv4/TCP(UDP) frames with valid checksums and synthetic TCP handshakes.
- `internal/network/`:
  - `manager.go`: Unified orchestrator for `localhost` and TUN + gVisor (`userdef` / `all`) stacks, dynamic service start/stop, 1-click scenario switching, optional per-IP rate limiting, and `pkg/capture` raw packet logging.
  - `telemetry_conn.go`: `TelemetryConn` and `TelemetryListener` transparently wrap every connection to capture bounded payloads (64 KiB/session), JA3 fingerprints, and first-packet probe hashes even on parse failure; `TelemetryHook` bridges structured events and credentials from all 159 protocol handlers into `telemetry.Bus`.
  - `catchall.go`: Configurable TCP/UDP Catch-All listeners for capturing unknown probes.
- `protocols/`: 159 RFC-verified protocol implementations (including `fakeshell`, `fakefs`, `pkg/smtpd`, `pkg/ssl`).
- `internal/api/` & `web/`: `/api/v2/*` REST + SSE server and embedded Vue 3 + Element Plus + ECharts 7-view console.

## 2. Rolling Retention Policy

- Hourly cleanup removes expired `sessions`, `events`, `credentials`, and `payloads` older than `retention_days` (default 30 days) or above `max_size_mb` (default 2048 MB).
- The `probes` deduplication table and any session referenced by a pinned probe (`pinned = 1`) are **permanently preserved**.
