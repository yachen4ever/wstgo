# wstgo 升级指南：v0.3.1 → v0.3.3

> 面向在服务器/工作机上部署运行 wstgo 的人。给自动化 agent 看的事实清单版见 [upgrade-0.3.1-to-0.3.3-agent.md](upgrade-0.3.1-to-0.3.3-agent.md)。

## 一句话总结

换一个二进制就算升级完成：鉴权协议和配置文件格式没有任何变化，v0.3.1 的 TOML 配置在 v0.3.3 上原样可用。这两个版本带来三个新能力——公钥白名单热加载、cacert 证书校验、证书错误快速失败——全部向后兼容。

## 升级步骤

```
# 1. 获取新二进制：GitHub Release 下载对应平台产物，或自行编译
go build -o wstgo .            # 或 ./crossbuild.sh

# 2. 替换并重启（systemd 部署场景）
sudo cp wstgo-linux-amd64 /usr/local/bin/wstgo
sudo systemctl restart wstgo-server    # 客户端同理：wstgo-client

# 3. 验证
wstgo version                           # 应输出 wstgo v0.3.3
journalctl -u wstgo-server -n 20        # 启动日志形态与升级前一致
```

## 新能力 1：公钥白名单热加载（服务端，v0.3.2）

以前给新客户端授权 = 拷 `public.pem` 进 authdir + 重启服务端。现在：

- **新增授权**：把 `public.pem` 放进 authdir 即可，下一条连接自动生效（服务端遇到陌生公钥会即时重扫目录，最快 1 秒一次防滥用）。
- **吊销**：删掉对应文件，30 秒内对新建连接生效。注意**已建立的连接不会中断**——要立即掐断某条隧道，重启服务端。
- **故障安全**：authdir 读盘失败（目录被误删、权限问题）不会清空白名单，服务端保留现状并打日志。
- 新日志行：`authdir reloaded: N authorized public key(s) [...]`（白名单真的变了才打）、`authdir rescan failed, keeping current whitelist ...`。

## 新能力 2：cacert，自签 wss 不再盲连（客户端，v0.3.3）

`allow_insecure = true` / `-insecure` 跳过了服务端身份校验——主动中间人可以先跟客户端完成 TLS、再向真实服务端中继握手（签名不含通道绑定，挡不住），从而窃听/篡改整条隧道。v0.3.3 起推荐用 cacert 走标准证书校验：

```
# CLI
wstgo client -url wss://<host>:<port>/ws -key private.pem -cacert ca-root.crt

# TOML（[general] 段）
cacert = "/path/to/ca-root.crt"
```

- 校验内容 = 标准 X.509：证书链、有效期、主机名/SAN。**直连 IP 时叶子证书的 SAN 必须包含这个 IP**（检查：`openssl x509 -in leaf.crt -noout -ext subjectAltName`）。
- 只信任 cacert 指定的这一个 CA，不碰系统证书池；支持 PEM 和 DER 两种编码。
- **cacert 与 allow_insecure/-insecure 互斥**，同时配置会拒绝启动——这是有意的，安全开关不留二义。
- `-insecure` 保留，定位改为"仅临时调试"。

迁移三步：把 CA 根证书拷到客户端 → 配置里删 `allow_insecure`、加 `cacert` → 重启客户端。日志出现 `server verification: CA cert ...` 即生效。

## 行为变化：证书错误快速失败

以前证书校验失败（CA 不信任、主机名不匹配）会被当成网络抖动按指数退避重试 15 秒。现在视为配置错误**立即失败**，日志直接给出 `server certificate rejected: ...` 的真实原因。如果你有脚本在盯客户端重试日志的形态，注意这一变化。

## 回滚

随时可以把二进制换回 v0.3.1——没有配置变更、没有协议变更、没有数据。唯一损失是热加载和 cacert 两个能力本身。
