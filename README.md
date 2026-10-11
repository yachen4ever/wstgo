# wstgo

[![Build](https://github.com/yachen4ever/wstgo/actions/workflows/build.yml/badge.svg)](https://github.com/yachen4ever/wstgo/actions/workflows/build.yml)

基于 WebSocket 的 TCP 隧道，使用 ed25519 挑战-响应进行身份认证。推荐用一份 TOML 配置文件跑多端口转发（`run -config`，服务端与客户端各一份）；最简单的单条隧道也可以直接用 CLI 子命令。

```
[目标 TCP 服务 × N（sshd / PostgreSQL / …）]
 |
 |  <= TCP
 |
[wstgo server（run -config server.toml）]  <- 持有已授权客户端的公钥（authdir）
 ||        /ws/ssh1  ->  127.0.0.1:22
 ||        /ws/pgedb ->  127.0.0.1:5432
 || <= WebSocket（ed25519 鉴权）
 ||
[反向代理 nginx（可选，推荐由它终止 TLS）]
 ||
 || <= WebSocket   /ws/<标签>
 ||
[wstgo client（run -config client.toml）]  <- 持有匹配的私钥
 |        127.0.0.1:50022 -> 标签 ssh1
 |        127.0.0.1:55432 -> 标签 pgedb
 | <= TCP
 |
[TCP 客户端（ssh / psql / …）]
```

## 功能特性

- **TCP over WebSocket**：把任意 TCP 服务封装进 WebSocket 传输，便于穿过只放行 HTTP/WS 流量的网络。固定传输参数：32KB 读缓冲、64KB 单帧上限、数据 WS 写超时 10s、TCP 写停滞上限 30s、服务端拨目标超时 5s、客户端单次 WS 拨号超时 10s。
- **配置文件多端口转发**：`run -config` 一个进程转发多个服务（如 SSH + 多个 PG），按标签路由 `/ws/<标签>`，客户端多监听一一对应；`type`（ssh/db）用于配置校验与日志标识。
- **ed25519 挑战-响应鉴权**：私钥永不上网，每次连接使用全新的随机 nonce，抓包无法重放。
- **服务端公钥白名单 + 热加载**：每个授权客户端放一个公钥文件到鉴权目录（文件名不限，无法解析的文件告警跳过，误放私钥会被明确拒绝）。新增公钥放进目录即对下一条连接生效，无需重启；移除/替换 30 秒内对新建连接生效。
- **安全默认**：服务端在未配置任何授权公钥时拒绝启动——不存在"无鉴权"模式；HTTP 层带 10 秒头部超时与 60 秒空闲超时，未认证 slowloris 无法占住连接。
- **心跳保活 + 全路径限时拆除**：客户端每 10 秒发送 WebSocket Ping，双方在收到任意 Ping/Pong 时续约读超时（30 秒无消息即断开），能穿过反向代理的空闲断连策略；任何一侧断开或停止消费，另一端都会在写超时内被及时拆除并通知对端——DB 等场景下隧道故障会快速暴露给应用，便于连接池及时重连，服务端不会积累僵尸连接。
- **指数退避重连**：客户端 WS 拨号失败时按 1s→2s→4s→8s 指数退避重试，最多尝试 5 次（累计最长等待约 15 秒；404 与证书校验失败立即失败并提示）；本地监听遇到瞬时 Accept 错误（如 FD 不足）会短暂等待后重试而不退出。
- **原生 wss 可选**：`-tlscert/-tlskey` 让 wstgo 自身终结 TLS（仅 CLI 模式），无需前置反代即可对外提供 `wss://`；默认关闭，保持「nginx 终止 TLS」的推荐形态不变。
- **服务端证书校验**：客户端 `-cacert` 指定 CA 证书，对自签 `wss://` 服务端走标准 X.509 校验（链 + 有效期 + 主机名/SAN），替代 `-insecure` 的盲连；证书校验失败与 404 一样快速失败不重试。

## 快速开始：配置文件模式（推荐）

四个文件搞定一条多端口隧道：客户端一把私钥、服务端一个公钥目录、两端各一份 TOML。

### 1. 客户端生成密钥对

**`genkey` 只需在客户端运行一次**：客户端保留 `private.pem`，把 `public.pem` 交给服务端。服务端不需要自己的密钥对——它只存放各客户端的公钥。目录下已存在密钥文件时 genkey 会拒绝执行（防止误覆盖服务端白名单仍在引用的旧密钥）。

```
wstgo genkey -dir ./keys
```

### 2. 启动服务端

把客户端的 `public.pem` 放进一个目录（文件名随意），写一份 `server.toml`：

```toml
[general]
run_mode = "server"
bind = "127.0.0.1:8888"            # WS 监听地址；前置 nginx 时保持 127.0.0.1
auth_dir = "/etc/wstgo/auth-keys"  # 授权公钥目录

[server.ssh1]
target = "127.0.0.1:22"
type = "ssh"

[server.pg1]
target = "127.0.0.1:5432"
type = "db"
```

```
wstgo run -config server.toml
```

### 3. 启动客户端

客户端 `[client.<标签>]` 与服务端 `[server.<标签>]` 同名即同一条隧道：

```toml
[general]
run_mode = "client"
url = "wss://tunnel.example.com/ws"   # 基础路径，实际连接 <url>/<标签>
key = "/etc/wstgo/client/private.pem"
cacert = "/etc/wstgo/ca-root.crt"     # 校验自签 wss 服务端的 CA 证书（推荐，见「自签名证书」）；与 allow_insecure 互斥

[client.ssh1]
bind = "127.0.0.1:50022"

[client.pg1]
bind = "127.0.0.1:55432"
```

```
wstgo run -config client.toml
```

`wstgo -config <file>` 是 `wstgo run -config <file>` 的等价简写。

### 4. 连接使用

客户端主机上访问各 `bind` 端口即到达服务端对应转发。穿透 SSH 时推荐写进 `~/.ssh/config`：

```
Host myvps
    HostName 127.0.0.1
    Port 50022
    User yourname
    ServerAliveInterval 15
    ServerAliveCountMax 3
```

之后 `ssh myvps` 体验与直连无异（延迟 = 物理链路 RTT + 少量隧道开销）。`ServerAliveInterval/ServerAliveCountMax` 是 SSH 自身的死连接感知，与隧道层互为双保险：wstgo 每 10s 发心跳、30s 判死后会主动关闭本地 TCP，SSH 随即看到断开；SSH 层这两行让 ssh 在隧道未及时关闭时也能自行放弃，终端不会无限冻结。数据库客户端同理，`psql -h 127.0.0.1 -p 55432 ...` 即像在服务端本机一样连接。

## 配置文件参考

### `[general]` 公共段

| 字段 | 端 | 必填 | 默认 | 说明 |
|------|----|------|------|------|
| `run_mode` | 两端 | 是 | — | `"server"` 或 `"client"` |
| `bind` | server | 是 | — | WS 监听地址（`host:port`） |
| `auth_dir` | server | 是 | — | 授权公钥目录，见「白名单管理」 |
| `url` | client | 是 | — | 服务端基础 URL（`ws://` 或 `wss://`），实际连接 `<url>/<标签>`；不得含 query/fragment（会让标签拼不进路径，校验直接拒绝） |
| `key` | client | 是 | — | 客户端私钥文件路径 |
| `cacert` | client | 否 | — | CA 证书文件路径（PEM/DER），用标准 X.509 语义校验自签 `wss://` 服务端（链 + 有效期 + 主机名/SAN）；**与 `allow_insecure` 互斥**，见「自签名证书」 |
| `allow_insecure` | client | 否 | `false` | 跳过全部 TLS 校验（仅临时调试，有主动中间人风险）；**与 `cacert` 互斥** |

### `[server.<标签>]` / `[client.<标签>]` 转发段

| 字段 | 端 | 必填 | 说明 |
|------|----|------|------|
| `target` | server | 是 | 要转发到的目标 TCP 地址（`host:port`） |
| `bind` | client | 是 | 本地监听的 TCP 地址（`host:port`） |
| `type` | 两端 | 否 | `ssh` / `db`，留空为 generic：用于配置校验（防 typo）与日志标识（转发的建立/断开与流量日志带 `[标签]` 后缀）。当前两类传输参数一致——32KB 缓冲、10s·30s 心跳、no-delay 对交互与吞吐均已最优，字段为将来按类型分化预留。 |

### 规则与说明

- **标签**只允许字母、数字、`-`、`_`（它要作为 URL 路径段）。两端标签必须一致：不一致时服务端返回 404，客户端**立即报错不重试**，日志会提示检查 `[server.*]` 配置。
- 服务端所有转发共享同一份公钥白名单，未授权连接在鉴权阶段即被拒。
- 客户端先绑定全部本地端口再开始服务，任一端口被占用则整体退出（fail fast）；SIGINT/SIGTERM 关闭监听后退出。
- 经 nginx 反代时无需额外配置：`location /ws` 前缀匹配自动覆盖 `/ws/<标签>`；服务端对裸 `/ws` 与未知标签返回 404。
- 放错段的字段按**告警并忽略**处理：`[client]` 段出现在 server 配置里、`url`/`key` 等客户端字段混进 server 的 `[general]`（反之亦然），都只打日志不报错。
- 与 CLI 模式的差异：配置文件模式不提供 TLS 字段（需要 `wss://` 请前置反代，或改用 CLI 模式的 `-tlscert/-tlskey`——两者必须成对给出，只给一个会拒绝启动）；原生 TLS 仅 CLI 模式支持。

可直接部署的完整配置模板见 `deploy/wstgo-server.toml.example` 与 `deploy/wstgo-client.toml.example`（systemd 单元默认引用它们）。

## 白名单管理

服务端把每个已授权客户端的公钥（`genkey` 生成的 `public.pem`，一个客户端一个文件）放进 `auth_dir` 即完成授权。

- **文件名不限**：目录下所有普通文件都会尝试加载为公钥，无法解析的文件启动时告警跳过（全是无效文件时有一条列出全部文件名的汇总告警）；误把私钥放进目录会被明确拒绝并提示（authdir 只放客户端公钥）。内容相同的公钥重复投放多个文件按一个计。
- **启动行为**：目录不存在视为空白名单；一个有效公钥都没有时服务端拒绝启动——不存在"无鉴权"模式。
- **热加载（无需重启）**：
  - **新增授权**：把 `public.pem` 放进目录，下一条连接即生效——服务端遇到白名单外的公钥时会触发一次即时重扫（受 1 秒限流，防止未知公钥轰炸触发高频扫描）。
  - **移除/吊销**：删掉对应文件，30 秒内对新建连接生效（周期重扫）。**已建立的连接不受影响**，需要立即掐断时重启服务端或断开对端。
  - 集合无变化的重扫静默完成，不打日志；只有白名单实际变化时才会出现 `authdir reloaded` 一行。
- **故障安全**：重扫只有读盘成功才整体替换白名单；目录消失、权限变化等读盘失败时保留现有白名单并记日志，瞬时 IO 故障不会把已授权客户端全部拒之门外。
- **审计**：日志以公钥指纹标识客户端，形如 `ed25519:1a2b3c4d5e`（公钥 SHA-256 前 5 字节）。取哈希截断而非原始字节前缀——短前缀可被离线批量碰撞伪造，40bit 哈希让伪造需要 2^40 量级工作量。

白名单变更的日志示例：

```
2026/10/11 01:32:06 authdir reloaded: 2 authorized public key(s) [/etc/wstgo/auth-keys]
2026/10/11 01:32:07 authdir rescan failed, keeping current whitelist (1 key(s)): authdir does not exist: /etc/wstgo/auth-keys
```

## 单隧道 CLI 模式

只转发一个目标时可以不用配置文件，直接用子命令。

### 1. 生成密钥对

同上，`genkey` 只在客户端运行：`wstgo genkey -dir ./keys`，生成 `private.pem`（客户端自留）与 `public.pem`（交给服务端）。

### 2. 启动服务端

```
wstgo server -bind 0.0.0.0:8888 -target 127.0.0.1:22 -authdir ./auth-keys
```

参数：

- `-bind`    监听 WebSocket 的地址（默认 `0.0.0.0:8888`）
- `-target`  要转发到的目标 TCP 服务地址（必填）
- `-authdir` 存放已授权客户端公钥的目录（默认 `./keys`；目录中没有有效公钥时拒绝启动，文件名不限）
- `-tlscert` / `-tlskey` 两者同时提供时启用**原生 `wss://`**（TLS 由 wstgo 自身终结）；默认不提供，监听明文 `ws://`
- `-v`       打印每个字节方向的流量日志（默认关闭，详见下文「日志」一节）

### 3. 启动客户端

```
wstgo client -bind 127.0.0.1:2222 -url wss://tunnel.example.com/ws -key ./private.pem
```

参数：

- `-bind`     客户端本地监听的 TCP 地址（默认 `127.0.0.1:25565`）
- `-url`      服务端的 WebSocket URL（必填，支持 `ws://` 和 `wss://`）
- `-key`      客户端私钥文件路径（默认 `./private.pem`）
- `-cacert`   CA 证书文件（PEM/DER），标准校验自签 `wss://` 服务端（推荐，见下文「自签名证书」；与 `-insecure` 互斥）
- `-v`        打印每个字节方向的流量日志（默认关闭，详见下文「日志」一节）
- `-insecure` 跳过 TLS 证书校验（仅临时调试用，见下文「自签名证书」一节）

### 原生 wss（不前置反代的场景）

```
wstgo server -bind 0.0.0.0:8888 -target 127.0.0.1:22 -authdir ./auth-keys -tlscert ./tls.crt -tlskey ./tls.key
```

客户端照常传 `-url wss://...` 即可；自签名证书配合 `-insecure` 或给客户端导入 CA（见下文「自签名证书与 `-insecure` 参数」）。nginx 与 wstgo 同机时，推荐维持「nginx 终止 TLS + wstgo 明文 ws」的默认形态，两者职责最简单。

## 鉴权协议

握手在 WebSocket 建立后、数据转发前进行。所有握手帧都是 `BinaryMessage`（非二进制握手帧直接拒绝），首字节为类型标识；握手通过后，数据模式只接受 `BinaryMessage`，其 payload 即纯 TCP 字节（无前缀、零开销），非二进制数据帧按协议违例断开。

```
server -> client : [0x01][32 字节随机 nonce]
client -> server : [0x02][32 字节公钥][64 字节对 nonce 的 ed25519 签名]
server -> client : [0x03]                              // 通过，进入数据模式
                   或 [0x04][原因...]                   // 拒绝并断开
```

- nonce 来自 `crypto/rand` 共 32 字节，重放概率可忽略。
- 服务端先在白名单中查找声明的公钥，再调用 `ed25519.Verify` 验签。任一检查失败，客户端都能在 `[0x04]` 帧中看到具体原因（服务端日志也会记录公钥指纹）；服务端在发出 nonce 之前就拒绝的场合（如白名单为空），客户端同样会透出 `[0x04]` 中的原因。
- 握手超时为 10 秒，用于防御慢速认证攻击。
- 握手失败分两类：密钥/协议类错误（"不在白名单"、"签名错误"等拒绝原因）**不会**重试——重试也没用；传输类错误（服务端恰在重启、握手超时等）照常走指数退避重试。网络层面的拨号失败同样重试。

## 密钥格式

密钥以 PEM 格式（`PRIVATE KEY` / `PUBLIC KEY`）封装 PKCS#8 / SPKI DER 编码。纯 Go 标准库实现，不依赖 OpenSSH。使用自带的 `genkey` 子命令生成即可（私钥文件权限 0600）。

## 日志

日志默认输出到 stderr，分两档：

- **默认（安静模式）**：只打运维必要事件——服务/客户端启动（客户端带身份指纹与 CA 校验来源）、隧道建立/断开、鉴权成功/失败、authdir 的加载/重载/跳过文件、未知标签请求、拨号重试、错误。适合生产环境。
- **`-v` 详细模式**：额外打印每个字节方向的流量日志，服务端为 `C→S <字节数>` / `S→C <字节数>`，客户端为 `L→R <字节数>` / `R→L <字节数>`；配置文件模式下每行附带 `[标签]`。适合调试。

示例（配置文件模式服务端，默认——启动时列出全部转发，隧道日志带标签）：

```
2026/10/11 01:49:11 loaded config server.toml (run_mode=server)
2026/10/11 01:49:11 loaded 1 authorized public key(s) from /etc/wstgo/auth-keys
2026/10/11 01:49:11 wstgo server listening on 127.0.0.1:8888, 2 forward(s):
2026/10/11 01:49:11   /ws/ssh1 -> 127.0.0.1:22 (type=ssh)
2026/10/11 01:49:11   /ws/pg1 -> 10.0.0.5:5432 (type=db)
2026/10/11 01:49:38 tunnel established: 1.2.3.4:54321 <-> 127.0.0.1:22 [ssh1] (client=ed25519:1a2b3c4d5e)
2026/10/11 01:50:02 unknown forward "pg9" requested from 1.2.3.4:54330
```

示例（`-v` 详细模式，会多出流量行，配置文件模式带标签）：

```
2026/10/11 01:49:38 C→S [ssh1] 52
2026/10/11 01:49:38 S→C [ssh1] 128
```

## 部署：nginx 反向代理

wstgo 不内置 TLS（CLI 模式的原生 wss 除外），生产环境建议在前端放 nginx 终止 `wss://`。配置时有几个关键的坑要注意。

### 必须的三件套

WebSocket 握手是 HTTP/1.1 的 `Upgrade` 机制，nginx 默认用 HTTP/1.0 代理后端，不传 Upgrade 头，wstgo 收不到握手就会直接断。这三行**缺一不可**：

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### 超时配合心跳

wstgo 的心跳参数：client 每 10s 发 Ping，双方读超时 30s。

nginx 默认 `proxy_read_timeout 60s` 偏短——虽然 WS 握手后 nginx 是透传，Ping/Pong 帧会续约 nginx 超时，但建议调大到 120s，留一次心跳丢失的余量：

```nginx
proxy_read_timeout 120s;
proxy_send_timeout 120s;
```

记住一条规则：**nginx 读超时 > wstgo 读超时 > 2 × 心跳间隔**。当前 120 > 30 > 20，成立（nginx 读超时最低建议 45s，120s 余量更足）。

### 关掉 buffering

隧道是实时字节流，nginx 缓冲有害无益，显式关掉：

```nginx
proxy_buffering off;
```

### 完整示例

```nginx
server {
    listen 443 ssl;
    server_name tunnel.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /ws {
        proxy_pass http://127.0.0.1:8888;

        # WebSocket 三件套（必须）
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # 超时配合 wstgo 心跳
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # 实时流量,不缓冲
        proxy_buffering off;

        # 透传客户端信息（可选）
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

客户端连接：`url = "wss://tunnel.example.com/ws"`（配置文件模式）或 `wstgo client -url wss://tunnel.example.com/ws ...`（CLI 模式）。

### 注意事项

- **路径必须对上**：CLI 模式服务端只注册 `/ws`；配置文件模式注册 `/ws/<标签>`（裸 `/ws` 与未知标签返回 404）。nginx 的 `location /ws` 前缀匹配两者都覆盖，且须与客户端 `url` 的基础路径一致。
- **日志里的 client IP 是 nginx 的**：经反代后 wstgo 看到的 `r.RemoteAddr` 是 `127.0.0.1`。nginx 配的 `X-Real-IP` / `X-Forwarded-For` 头可用于审计（当前 wstgo 尚未读取这些头）。
- **服务端不校验 Origin**：`CheckOrigin` 恒为真。这不是漏洞——完成鉴权需要私钥对 nonce 签名，浏览器页面伪造不了；跨站 WebSocket 握手会在 ed25519 鉴权这一关被拒。
- **慎用 Cloudflare 等 CDN**：免费版对 WS 有空闲断连限制且会限制子协议，wstgo 走 CDN 多半不行，建议直连或自建反代。

### 自签名证书：`-cacert` / 系统信任库 / `-insecure`

服务端 TLS 由自签 CA 签发的证书终结（典型形态：本地 CA 签一张带 IP/域名 SAN 的服务端证书，nginx 终结 TLS）时，客户端有三种做法，推荐程度从高到低：

1. **`-cacert` 指定 CA 证书（推荐，零系统配置）**：客户端带上签发服务端证书的 CA 根证书文件（PEM 或 DER），走标准 X.509 校验——证书链、有效期、主机名/SAN 全部校验。中间人没有 CA 私钥，就造不出能通过校验的证书；比导入系统信任库影响面小（只信任这一个 CA，不动系统证书池）。

   ```bash
   wstgo client -url wss://203.0.113.10:1985/ws -key ./private.pem -cacert local-ca-root.crt
   ```

   配置文件模式对应 `cacert = "/path/to/ca-root.crt"`。**`-cacert` 与 `-insecure` 互斥**，同时给出直接报错退出。

   **SAN 注意事项**：标准校验包含主机名——直连 IP 时叶子证书的 SAN 必须包含这个 IP，否则即便信任了 CA 也会报 `certificate is valid for ... not <IP>`。签发服务端证书时把 IP 写进 SAN 即可（自签 CA 场景这是无代价的）。检查现有证书：`openssl x509 -in leaf.crt -noout -ext subjectAltName`。

2. **导入系统信任库**：把 CA 根证书装进客户端系统（Windows 用 `certutil -addstore Root ca.crt`，Linux 放入 `/usr/local/share/ca-certificates/`），Go 1.18+ 自动读取，无需任何参数。适合这台机器上还有别的工具也要信任同一 CA 的场景。

3. **`-insecure`（仅临时调试）**：跳过全部 TLS 校验。它**关掉的只是服务端身份认证，加密仍在**——被动偷听拿不到内容，但主动中间人可以先与客户端完成 TLS，再向真实服务端发起一条中继连接、原样转发 ed25519 握手（签名只覆盖 nonce、与 TLS 通道无绑定，中继无法被检测），握手照常通过，随后窃听/篡改全部隧道流量。只用于内网临时排查，不要长期运行；长期场景用 `-cacert` 或导入信任库。

## 部署：systemd 常驻

长期运行建议用 systemd 托管，崩溃/重启后 3 秒内自动拉起。`deploy/` 下有 server / client 各一份单元示例和配套 TOML 配置模板，单元默认走配置文件模式（`run -config`，多端口转发）：

```
sudo cp binaries/wstgo-linux-amd64 /usr/local/bin/wstgo
sudo mkdir -p /etc/wstgo
sudo cp deploy/wstgo-server.toml.example /etc/wstgo/wstgo-server.toml
# 编辑 /etc/wstgo/wstgo-server.toml：bind、auth_dir、各转发的 target/标签
sudo cp deploy/wstgo-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wstgo-server
```

单元内置 `Restart=always` 与基础安全加固（文件系统只读、禁止提权）。单隧道场景可按单元内注释切回 CLI 子命令；客户端同理用 `wstgo-client.service` + `wstgo-client.toml.example`。日志用 `journalctl -u wstgo-server -f` 查看。

## 测试

```
go test -race ./...
```

测试覆盖：TOML 配置加载与校验、密钥生成/加载/权限（含重复生成拒绝）、白名单加载与热加载语义（新增拾取、移除吊销、读盘失败保留、限流）、鉴权握手协议（成功/未知公钥/坏签名/畸形帧/空白名单/超时/热加载拾取）、端到端隧道（真实 TCP echo 双向、128KB 多帧、并发连接、配置模式路由与 404、重试发生与耗尽计数、重试后恢复）、桥接生命周期（本地断开传播到 target、target 断开传播到本地、慢消费者写超时拆除、心跳保活空闲连接、静默连接超时拆除）、TLS 服务端校验（cacert 标准链 + IP SAN、错误 CA 拒绝、无 SAN 主机名不匹配、过期证书、证书错误快速失败、insecure 回归）。CI 在每次 push/PR 上跑 vet + `-race` 测试 + 交叉编译。

## 编译

### 当前平台

```
go build -o wstgo .
```

需要 Go 1.26+。依赖仅两个：`github.com/gorilla/websocket`（WebSocket）与 `github.com/BurntSushi/toml`（配置文件模式）。

### 交叉编译多平台

仓库自带两个等价的交叉编译脚本，用 Go 原生 `GOOS/GOARCH` 交叉编译，无需 `gox` 等外部工具。固定目标：

| 平台 | 文件 |
|------|------|
| Linux amd64 | `binaries/wstgo-linux-amd64` |
| Linux arm64 | `binaries/wstgo-linux-arm64` |
| Linux armhf（32 位 ARMv6/v7，树莓派等） | `binaries/wstgo-linux-armhf` |
| Windows amd64 | `binaries/wstgo-windows-amd64.exe` |
| macOS arm64 (Apple Silicon) | `binaries/wstgo-darwin-arm64` |
| macOS amd64 (Intel) | `binaries/wstgo-darwin-amd64` |

```
# macOS / Linux
./crossbuild.sh            # 编译
./crossbuild.sh clean      # 清理 binaries/

# Windows PowerShell
.\crossbuild.ps1           # 编译
.\crossbuild.ps1 -Clean    # 清理 binaries\
```

脚本会从 `git describe --tags --always` 读取版本号，通过 `-ldflags` 注入到 `main.version`，可用 `wstgo version` 查看。`-trimpath -s -w` 去掉本地路径和调试符号，产物更小。`CGO_ENABLED=0` 保证纯静态、跨容器/跨发行版可用。

GitHub Actions 在每次 push 到 `master` 和 PR 上自动跑 vet、`-race` 测试与交叉编译（见 `.github/workflows/build.yml`）；打 tag 时由 release 工作流交叉编译并创建 draft release。

## 文件结构

- `main.go`        命令行入口（子命令：`genkey`、`server`、`client`、`run`）
- `config.go`      TOML 配置文件的加载与校验（`run` 多端口转发模式）
- `keys.go`        密钥对的生成、加载与白名单管理（含热加载）
- `auth.go`        挑战-响应握手协议
- `server.go`      服务端：HTTP 升级 + 鉴权 + TCP 拨号 + 桥接 + 心跳
- `client.go`      客户端：TCP 监听 + WS 拨号(带重试) + 鉴权 + 桥接 + 心跳
- `*_test.go`      配置/密钥/握手/端到端隧道测试
- `deploy/`        systemd 单元与 TOML 配置模板（server / client 各一）

## 已知限制

- TLS 可选而非强制：`-tlscert/-tlskey` 开启原生 `wss://`（仅 CLI 模式），默认关闭（明文 `ws://`）。生产环境要么开原生 TLS，要么用反向代理（nginx、Caddy）在前端终止 `wss://`。
- **CLI 子命令单目标**：`server`/`client` 子命令一次只转发一个目标（保留给最简单的单隧道场景）。多端口转发用配置文件模式 `wstgo run -config <file>`，单进程多转发。
- **不做连接多路复用**：client 端每接受一个本地 TCP 连接，都会向 server 新拨一条独立 WebSocket，而不是把多条 TCP 流复用到同一条 WS 上。10 个本地连接 = 10 条 WS 连接。并发本身不受限（每条连接在独立 goroutine 中处理），但连接数较多时 WS 握手开销会比多路复用方案高。
- **白名单热加载的边界**：移除公钥只对**新建**连接生效，已建立的连接不受影响；需要立即掐断已有隧道时重启服务端。

## 致谢

本项目最初 fork 自 [rinsuki/wstunnel](https://github.com/rinsuki/wstunnel)，第一版基于其代码。感谢 rinsuki 的原始工作（MIT License）。此后项目经历了持续的修改与功能扩展，现作为独立仓库维护；按 MIT 协议要求，[LICENSE](LICENSE) 中保留了原作者的版权声明。
