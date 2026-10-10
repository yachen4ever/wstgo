# wstgo v0.3.1 → v0.3.3 升级说明（agent 阅读版）

> 事实清单式升级说明：所有数值、日志字符串、文件位置均从 v0.3.3 代码逐字核对。人类运维版见 [upgrade-0.3.1-to-0.3.3.md](upgrade-0.3.1-to-0.3.3.md)。

## 不变的部分（先核对这些，避免误判）

- 鉴权协议不变：BinaryMessage 首字节 `0x01`(nonce)/`0x02`(pubkey+sig)/`0x03`(ok)/`0x04`(fail+reason)，nonce 32B、ed25519 签名 64B、握手超时 10s（auth.go）。
- TOML 结构向后兼容：v0.3.1 的配置文件零修改可运行；`[server.*]`/`[client.*]` 语义不变；新增可选字段仅 `[general] cacert`（client 端）。
- 心跳/缓冲不变：client ping 10s、读超时 30s、32KB 缓冲、64KB 单帧上限（server.go）。
- 重连退避默认值不变：1s 起指数翻倍、最多尝试 5 次（中间等待合计 15s）、404 不重试。
- 二进制可直接替换，无数据/状态迁移，可随时回滚到 v0.3.1。

## 变更 1：白名单热加载（v0.3.2，keys.go / server.go / auth.go）

- v0.3.1 行为：authdir 仅启动时加载一次，新增/移除公钥需重启。
- v0.3.2 起有两个重扫触发点：
  1. `serverHandshake` 中公钥白名单 miss **或白名单为空** → `whitelist.rescan(true)`（带逐文件跳过日志）；两条路径都存在，"先清空再补公钥"的轮换方式不用等周期。
  2. `startReloadLoop()` 每 `authdirRescanInterval = 30s` → `rescan(false)`（静默，不打文件级告警）。
- 限流：`rescanMinInterval = 1s`，全局共享 lastScan；并发触发方在 scanMu 上串行，不放大。
- 替换语义：`readAuthDir` 读盘成功才整体替换 keys（公钥按内容去重，count = len(map)）；读盘失败（含 `errAuthDirMissing`，即目录消失）**保留现状**并打日志。
- 目录不存在：启动时（`loadWhitelistFromDir`）视为空白名单 → 调用方 n==0 拒绝启动；运行期 rescan 视为读盘失败保留现状。两条路径语义不同，别混淆。
- 关键日志（逐字）：
  - `authdir reloaded: %d authorized public key(s) [%s]` —— sameKeySet 判定集合变化才打；集合无变化的重扫完全静默
  - `authdir rescan failed, keeping current whitelist (%d key(s)): %v`
  - `authdir: skipping %s: %v` —— 仅 logSkips=true 的路径（启动 + 未命中重扫）
- 运维语义：新增公钥 → 下一条连接生效；移除 → ≤30s 对**新建**连接生效；**既有连接不受影响**（白名单只在握手时查询）。

## 变更 2：客户端 cacert（v0.3.3，client.go / config.go / main.go）

- 新参数：CLI `client -cacert <path>`；配置 `[general] cacert = "<path>"`（仅 client 模式有意义）。
- 语义：`loadCACertPool(path)`（client.go）——PEM 优先（`AppendCertsFromPEM`，可含多证书）+ DER 整文件兜底 → `tls.Config{RootCAs: pool}`。标准 X.509 全校验（链/有效期/主机名-SAN）；**不合并系统信任池**，只信任指定 CA。
- 互斥（启动即拒，不留二义）：
  - CLI：`log.Fatal("client: -insecure and -cacert are mutually exclusive (pick one way to trust the server)")`
  - 配置：loadConfig 报 `config: general.allow_insecure and general.cacert are mutually exclusive (pick one way to trust the server)`
- 日志：配了 cacert 的客户端启动多一行 `server verification: CA cert <path>`。
- `-insecure` / `allow_insecure` 行为不变（InsecureSkipVerify），文档定位改为仅临时调试。

## 变更 3：证书校验失败快速失败（v0.3.3，client.go dialWithRetry）

- v0.3.1 行为：任何拨号失败（含 x509 错误）都按退避重试 5 次（等待合计 15s）。
- v0.3.3 起：`errors.As` 命中 `x509.UnknownAuthorityError` / `x509.HostnameError` / `x509.CertificateInvalidError` 时**立即返回**，错误串 `dial %s: server certificate rejected: %v`，不进入退避循环。
- 排障含义：日志出现 "server certificate rejected" = CA/SAN/有效期配置问题，重试无意义，不要建议重试。

## 附带（非行为性）

- 重连参数（dialRetry*）与 authDeadline 由 const 改 var——默认值不变，测试注入用。
- server.go 抽出 `buildServerMux(wl, forwards)`（可测试性重构，行为不变）。
- 新增测试套件：config/keys/auth/tunnel 四个 `_test.go`，CI 增加 `go test -race ./...` 步骤。
- 配置模式全链路用例：`TestRunClientConfigWithCACertEndToEnd`（真实 TOML → loadConfig → runClientConfig → cacert 校验 → roundtrip → SIGTERM 收尾）。

## 验证清单

```
go vet ./... && go test -race ./...
wstgo version                     # 期望: wstgo v0.3.3
```

- 服务端升级后：老配置直接启动；向 authdir 增/删公钥文件，观察 `authdir reloaded` 行（≤1s 新增生效需一次新连接触发，≤30s 移除生效）。
- 客户端配 cacert 后：日志出现 `server verification: CA cert ...`；故意给错 CA 应**立即**报 `server certificate rejected`（而非重试 15s）。

## 代码索引

| 文件 | 相关内容 |
|---|---|
| keys.go | 白名单、`rescan`/`startReloadLoop`、`readAuthDir`、`errAuthDirMissing`、`sameKeySet` |
| auth.go | 握手协议；`serverHandshake` 的 miss/空白名单 rescan 挂点；`clientHandshake` 首帧 `[0x04]` 原因透传 |
| client.go | `loadCACertPool`、`dialWithRetry`（TLS 三态 + x509 快速失败）、`runClientConfig` 接线 |
| config.go | `GeneralConfig.Cacert`、validate 互斥校验 |
| deploy/ | `wstgo-client.toml.example`（cacert 示例与注释）、两个 `.service` 注释 |

## 已知边界

- 吊销公钥不中断既有隧道（要立即掐断需重启服务端）。
- 原生 wss（`-tlscert/-tlskey`）仍仅 CLI 子命令模式，配置文件模式无 TLS 字段。
- `cacert` 不合并系统信任池——需要同时信任公共 CA 的场景用系统信任库导入，或两者其一。
