# ProtoSim — 协议扫描模拟器与探针观测平台

<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

**ProtoSim** 是一款面向资产扫描器研发回归测试与公网扫描探针观测的**单机一体化协议模拟与遥测平台**。

---

## 核心特性

- **全量 71 种 RFC 级协议**：覆盖 Web、远程访问、数据库、中间件、云原生（`docker`、`etcd`、`kafka`、`zookeeper`）、Java/应用中间件（`ajp`、`jdwp`、`java-rmi`、`weblogic`）、工控（ICS/SCADA）、物联网与网络设备（`bgp`、`tftp`、`rsync`、`socks4/5`）等 71 种协议，支持 `localhost`、`userdef`（TUN + gVisor 虚拟子网）与 `all` 三种组网模式。
- **零外部依赖的 SQLite WAL 观测库**：内置纯 Go SQLite（`modernc.org/sqlite`），异步批量刷盘与滚动保留（默认 30 天 / 2 GB），且**唯一探针库与收藏样本永久保留**。
- **探针聚类库（Probe Library）**：按 `(protocol, port, first_payload_sha256)` 自动聚类去重，记录首/末次命中时间、命中数、独立来源 IP、Hex/ASCII 视图与归档状态（`new` / `known` / `adopted`），支持一键导出 **Hex / Python / Go** 复现脚本。
- **扫描器身份归因引擎**：支持 `cidr`、`ua`（HTTP User-Agent）、`ja3`（TLS 指纹）、`payload_regex`（首包正则）四维规则打标，自动区分己方扫描器、Nmap、ZGrab、Censys、Shodan、Masscan 等来源并支持前端热更新。
- **测试批次与 61 协议覆盖率矩阵（Test Runs）**：一键开启/结束回归测试窗口，展示 61 协议覆盖状态（命中 / 未命中 / 解析异常 / 平均耗时），支持任意两个批次做覆盖率 Diff 对比。
- **全量会话回放与 PCAP 导出**：默认记录有界原始收发报文（单会话上限 64 KiB），即便协议解析失败或提前断开仍强制留存首包；支持可选 TCP/UDP **Catch-All** 未知探针兜底端口与单会话一键导出标准 `.pcap` 文件。
- **内嵌 Vue 3 控制台单二进制**：通过 `//go:embed` 打包 Vue 3 + Vite + TypeScript + Element Plus + ECharts 7 大观测页面，默认监听 `0.0.0.0:5555`。

---

## 系统架构

详细模块划分与表结构请参阅 [docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md)（[English](docs/ARCHITECTURE.md)）。

```mermaid
flowchart LR
    Scanners["资产扫描器 / 公网探测流量"] --> Net["网络引擎 (localhost / TUN + gVisor)"]
    Net --> Proto["61 种 RFC 协议处理器 + Catch-All"]
    Proto --> Bus["遥测管道 (归因打标 + 探针去重 + 批量写入)"]
    Bus --> DB["SQLite WAL 存储"]
    Bus -.SSE.-> API["/api/v2 REST + SSE 接口"]
    DB <--> API <--> UI["内嵌 Vue 3 控制台 (:5555)"]
```

---

## 快速开始

```bash
# 1. 查看全部已注册协议与默认端口
./bin/protosim list-protocols

# 2. 生成默认配置文件（可选）
./bin/protosim gen-config -o protosim.json --scenario all-61-standard --safe-ssh=true

# 3. 启动模拟器与观测控制台（默认监听 http://0.0.0.0:5555）
sudo ./bin/protosim run -c protosim.json --catch-all-tcp 9999 --catch-all-udp 9999
```

### 常用启动参数（`protosim run`）

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-c` | JSON/YAML 配置文件路径 | 内置全 61 协议默认配置 |
| `--listen` | Web UI 与 `/api/v2/*` 监听地址 | `0.0.0.0:5555` |
| `--mode` | 组网模式（`localhost` \| `userdef` \| `all`） | `localhost` |
| `--db` | SQLite 数据库文件路径 | `./data/protosim.db` |
| `--auth-token` | 一键开启 Bearer / `X-API-Token` 鉴权 | 关闭（默认内网免密） |
| `--catch-all-tcp` | 未知探针兜底监听 TCP 端口（逗号分隔） | 关闭 |
| `--catch-all-udp` | 未知探针兜底监听 UDP 端口（逗号分隔） | 关闭 |
| `--safe-ssh` | 将模拟 SSH 映射到 `2222` 避免遮蔽宿主机 SSH | `true` |

---

## 从源码构建

```bash
# 1. 构建内嵌 Vue 3 前端
cd web && npm install && npm run build && cd ..

# 2. 编译单二进制
go build -o bin/protosim ./cmd/protosim
```
