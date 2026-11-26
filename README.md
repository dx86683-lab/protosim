# ProtoSim — 协议扫描模拟器与探针观测平台

ProtoSim 是一款面向内部资产扫描器研发测试（如 `internal-scanner`）与公网扫描探针观测的**单机一体化协议模拟与遥测平台**：

- **全量 61 种 RFC 级协议**：覆盖 Web/远程访问/数据库/中间件/工控（ICS）/物联网/网络设备等 61 种协议，支持 `localhost`、`userdef`（TUN + gVisor 虚拟子网）与 `all` 三种组网模式。
- **开箱即用的 SQLite WAL 观测库**：零外部数据库依赖，内置异步批量写入、滚动保留（默认 30 天 / 2 GB），且**唯一探针库与收藏样本永久保留**。
- **探针聚类库（Probe Library）**：按 `(protocol, port, first_payload_sha256)` 自动聚类去重，提供 Hex/ASCII 视图、状态归档（`new` / `known` / `adopted`）及一键导出 Hex / Python / Go 复现脚本。
- **扫描器身份归因引擎**：内置 CIDR、HTTP User-Agent、TLS JA3、首包正则规则，自动识别己方扫描器、Nmap、ZGrab、Censys、Shodan、Masscan 等来源并支持 Web 端动态热更新。
- **测试批次与 61 协议覆盖率矩阵（Test Runs）**：一键开启/结束回归测试窗口，展示 61 协议覆盖状态（命中 / 未命中 / 解析异常 / 平均耗时）与双批次 Diff 对比。
- **全量会话回放与 PCAP 导出**：记录有界原始收发报文（默认上限 64 KiB/会话），即使协议解析失败或提前断开仍强制留存首包，支持单会话一键导出标准 `.pcap` 文件。
- **内嵌 Vue 3 + Element Plus + ECharts 单二进制**：通过 `//go:embed` 打包 7 大前端观测页面，默认监听 `0.0.0.0:5555`。

## 快速开始

```bash
# 1. 查看所有支持的协议
./bin/protosim list-protocols

# 2. 生成默认配置文件（可选）
./bin/protosim gen-config -o protosim.json --scenario all-61-standard --safe-ssh=true

# 3. 启动模拟器与观测控制台（默认监听 http://0.0.0.0:5555）
sudo ./bin/protosim run -c protosim.json --catch-all-tcp 9999
```

## CLI 常用参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-c` | JSON/YAML 配置文件路径 | 内置全 61 协议默认配置 |
| `--listen` | Web UI 与 `/api/v2/*` 监听地址 | `0.0.0.0:5555` |
| `--mode` | 组网模式 (`localhost` / `userdef` / `all`) | `localhost` |
| `--db` | SQLite 数据库文件路径 | `./data/protosim.db` |
| `--auth-token` | 一键开启 API/Web Token 鉴权 | 空（默认内网免密） |
| `--catch-all-tcp` | 未知探针兜底监听 TCP 端口列表 | 未启用 |
| `--catch-all-udp` | 未知探针兜底监听 UDP 端口列表 | 未启用 |
| `--safe-ssh` | 将模拟 SSH 映射到 2222 避免遮蔽宿主机 SSH | `true` |

## 离线构建

```bash
# 前端构建
cd web && npm install && npm run build && cd ..

# Go 离线构建（含内嵌 Vue 3 静态资源）
go build -o bin/protosim ./cmd/protosim
```
