# ProtoSim 架构设计文档

<p align="center">
  <a href="ARCHITECTURE.md">English</a> | <b>简体中文</b>
</p>

## 1. 模块划分

- `cmd/protosim/`：CLI 入口（`run`、`gen-config`、`list-protocols`、`version`），负责加载配置、初始化 SQLite / Telemetry Bus / NetworkManager、定时滚动清理与优雅退出。
- `internal/config/`：强类型 JSON/YAML 配置模型、CIDR 自动规范化与 4 套内置场景模板（`all-standard`、`high-ports-obfuscated`、`core-20-quick`、`virtual-multi-ip-gvisor`）。
- `internal/telemetry/`：
  - `store_sqlite.go`：纯 Go `modernc.org/sqlite` WAL 模式，8 张核心表（`sessions`、`events`、`probes`、`credentials`、`payloads`、`test_runs`、`scanner_rules`、`scenarios`）+ `probe_ips` 辅助去重表。
  - `bus.go`：有界异步批量写入管道（200ms 或 200 条刷盘）、SSE 实时广播与可选 HMAC 签名新探针 Webhook 通知。
  - `attribution.go`：线程安全、可热加载的扫描器归因引擎（`cidr` / `ua` / `ja3` / `payload_regex`）。
  - `pcap.go`：纯 Go 标准 libpcap 合成器，自动为 TCP 会话构造三次握手与带校验和的 Ethernet/IPv4/TCP/UDP 帧。
- `internal/network/`：
  - `manager.go`：统一驱动 `localhost` 与 TUN + gVisor（`userdef` / `all`）网络栈，支持 159 种协议处理器动态启停、场景一键切换、可选按 IP 限流与 `pkg/capture` 旁路抓包。
  - `telemetry_conn.go`：`TelemetryConn` / `TelemetryListener` 透明包裹每条连接，强制在首次读取时生成探针指纹与有界载荷记录（单会话上限 64 KiB，解析失败亦留存）；`TelemetryHook` 自动将全部 159 协议的结构化日志与凭证桥接至 `telemetry.Bus`。
  - `catchall.go`：可选 TCP/UDP Catch-All 监听，捕获未知端口探针。
- `protocols/`：独立维护并验证的 159 种 RFC 级协议实现（含 `fakeshell`、`fakefs`、`pkg/smtpd`、`pkg/ssl`）。
- `internal/api/` + `web/`：`/api/v2/*` REST + SSE 服务端与内嵌 Vue 3 + Element Plus + ECharts 7 大观测视图。

## 2. 滚动保留策略

- 后台每小时按 `retention_days`（默认 30 天）与 `max_size_mb`（默认 2048 MB）自动清理最旧的 `sessions`、`events`、`credentials` 与 `payloads`。
- `probes` 唯一探针库以及被收藏探针（`pinned = 1`）关联的样本会话**永久保留**，不会被滚动策略删除。
