package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// 重连参数：每个本地 TCP 连接独立拨 WS，失败时退避重试。
// var 是为了测试可注入更短的退避参数。
var (
	dialRetryInitial = 1 * time.Second
	dialRetryMax     = 30 * time.Second
	dialRetryMaxNum  = 5 // 最多尝试 5 次，中间退避 1+2+4+8 = 15s（第 5 次失败后不再等待）
	dialTimeout      = 10 * time.Second
)

// loadCACertPool 读取 CA 证书文件，构建用于校验服务端证书的信任池。
// 支持 PEM（可含多张证书，根 + 中间链）与 DER（Windows 分发的 .crt 常为
// DER）两种编码。注意标准 X.509 语义：证书链与主机名/SAN 都会校验，
// 直连 IP 时叶子证书的 SAN 需包含该 IP。
func loadCACertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(data) {
		return pool, nil
	}
	if cert, derErr := x509.ParseCertificate(data); derErr == nil {
		pool.AddCert(cert)
		return pool, nil
	}
	return nil, fmt.Errorf("no certificate found in %s (neither PEM nor DER)", path)
}

// dialWithRetry 带指数退避地拨号 WS 并完成鉴权握手。
// 成功返回已通过鉴权的 WS 连接；失败返回最后一次错误。
// 服务端身份校验三选一（由调用方保证互斥）：
//   - insecure=true：跳过 TLS 证书校验（仅临时调试，有主动中间人风险）
//   - caPool != nil：用指定 CA 做标准链 + 主机名校验（自签 CA 场景推荐）
//   - 都为零值：系统信任库（CA 签发的公共证书场景）
//
// 404 与证书校验失败视为配置错误，不重试。
func dialWithRetry(websocketURL string, priv ed25519.PrivateKey, insecure bool, caPool *x509.CertPool) (*websocket.Conn, error) {
	var lastErr error
	backoff := dialRetryInitial
	for attempt := 1; attempt <= dialRetryMaxNum; attempt++ {
		d := &websocket.Dialer{
			HandshakeTimeout: dialTimeout,
		}
		if insecure {
			d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else if caPool != nil {
			d.TLSClientConfig = &tls.Config{RootCAs: caPool}
		}
		ws, resp, err := d.Dial(websocketURL, nil)
		if err == nil {
			// 与 server 端对称：限制单帧大小，防止对端异常大帧
			ws.SetReadLimit(maxMessageSize)
			err = clientHandshake(ws, priv)
			if err == nil {
				return ws, nil
			}
			ws.Close()
			var ae *authError
			if errors.As(err, &ae) {
				// 密钥/协议问题重试无意义，立即失败
				return nil, err
			}
			// 传输类错误（握手超时、对端恰在重启的 RST 等）按退避重试
			lastErr = err
			log.Printf("handshake attempt %d/%d failed: %v", attempt, dialRetryMaxNum, err)
			if attempt < dialRetryMaxNum {
				time.Sleep(backoff)
				backoff *= 2
				if backoff > dialRetryMax {
					backoff = dialRetryMax
				}
			}
			continue
		}
		// gorilla 约定：握手失败时调用方负责关闭 resp.Body
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if errors.Is(err, websocket.ErrBadHandshake) && resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("dial %s: 404 not found (no [server.*] forward with this label on the server?)", websocketURL)
		}
		// 证书校验失败（CA 不信任 / 主机名不匹配 / 证书过期）是配置错误，
		// 重试也不会好，立即失败——与 404 同等对待。
		var unknownAuth x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		if errors.As(err, &unknownAuth) || errors.As(err, &hostname) || errors.As(err, &invalid) {
			return nil, fmt.Errorf("dial %s: server certificate rejected: %v", websocketURL, err)
		}
		lastErr = err
		log.Printf("dial attempt %d/%d failed: %v", attempt, dialRetryMaxNum, err)
		if attempt < dialRetryMaxNum {
			time.Sleep(backoff)
			backoff *= 2
			if backoff > dialRetryMax {
				backoff = dialRetryMax
			}
		}
	}
	return nil, lastErr
}

// startHeartbeat 在已鉴权的 WS 上定期发 Ping。
// 通过 ctx 退出；Ping 写失败视为连接已死，立即 cancel 触发双向拆除。
// WriteControl 按 gorilla 语义可与数据写并发，无需与 bridge 共享锁。
func startHeartbeat(ws *websocket.Conn, ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(time.Duration(heartbeatInterval.Load()))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Duration(writeWait.Load())))
			if err != nil {
				log.Printf("heartbeat ping failed: %v", err)
				cancel()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// handleLocalConn 处理单个本地 TCP 连接：
// 拨 WS + 鉴权 + 心跳 + 双向桥接。label 为配置模式的转发标签（CLI 模式为空）。
func handleLocalConn(tcp net.Conn, websocketURL string, priv ed25519.PrivateKey, insecure bool, caPool *x509.CertPool, label string) {
	defer tcp.Close()

	ws, err := dialWithRetry(websocketURL, priv, insecure, caPool)
	if err != nil {
		log.Printf("establish tunnel failed%s: %v", labelSuffix(label), err)
		return
	}
	defer ws.Close()

	installHeartbeat(ws) // 续约读超时 + 自动回 Pong

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startHeartbeat(ws, ctx, cancel)

	log.Printf("client tunnel up%s: %s <-> %s", labelSuffix(label), tcp.RemoteAddr(), websocketURL)
	bridge(ws, tcp, ctx, cancel, false, labelSuffix(label))
	log.Printf("client tunnel down%s: %s", labelSuffix(label), tcp.RemoteAddr())
}

func client(bindAddr, websocketURL, keyPath string, insecure bool, caCertPath string) {
	if insecure && caCertPath != "" {
		log.Fatal("client: -insecure and -cacert are mutually exclusive (pick one way to trust the server)")
	}
	var caPool *x509.CertPool
	if caCertPath != "" {
		var err error
		if caPool, err = loadCACertPool(caCertPath); err != nil {
			log.Fatalf("load CA cert %s: %v", caCertPath, err)
		}
		log.Printf("server verification: CA cert %s", caCertPath)
	}

	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("load private key %s: %v", keyPath, err)
	}
	log.Printf("client identity: %s", publicKeyFingerprint(priv.Public().(ed25519.PublicKey)))

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", bindAddr, err)
	}
	log.Printf("wstgo client listening on %s, forwarding to %s", bindAddr, websocketURL)

	for {
		tcp, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				// EMFILE/ENFILE 等瞬时错误：退避重试，不能让整个客户端退出
				log.Printf("accept: %v (transient, retrying)", err)
				time.Sleep(5 * time.Millisecond)
				continue
			}
			log.Printf("accept: %v", err)
			return
		}
		go handleLocalConn(tcp, websocketURL, priv, insecure, caPool, "")
	}
}

// runClientConfig 以配置文件模式启动客户端：每个 [client.<label>] 条目
// 在本地起一个 TCP 监听，转发到服务端 <general.url>/<label> 对应的路径。
// 全部端口先绑定再服务（任一失败整体退出）；SIGINT/SIGTERM 时关闭监听退出。
func runClientConfig(cfg *Config) {
	if cfg.General.AllowInsecure && cfg.General.Cacert != "" {
		log.Fatal("config: general.allow_insecure and general.cacert are mutually exclusive")
	}
	var caPool *x509.CertPool
	if cfg.General.Cacert != "" {
		var err error
		if caPool, err = loadCACertPool(cfg.General.Cacert); err != nil {
			log.Fatalf("load CA cert %s: %v", cfg.General.Cacert, err)
		}
		log.Printf("server verification: CA cert %s", cfg.General.Cacert)
	}

	priv, err := loadPrivateKey(cfg.General.Key)
	if err != nil {
		log.Fatalf("load private key %s: %v", cfg.General.Key, err)
	}
	log.Printf("client identity: %s", publicKeyFingerprint(priv.Public().(ed25519.PublicKey)))

	base := strings.TrimSuffix(cfg.General.URL, "/")

	// 先绑定全部本地端口，任何一个失败即整体退出（fail fast）
	listeners := make(map[string]net.Listener, len(cfg.Client))
	for name, f := range cfg.Client {
		ln, err := net.Listen("tcp", f.Bind)
		if err != nil {
			log.Fatalf("listen %s (%s): %v", f.Bind, name, err)
		}
		listeners[name] = ln
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, name := range slices.Sorted(maps.Keys(listeners)) {
		ln := listeners[name]
		url := base + "/" + name
		log.Printf("forwarding %s -> %s (type=%s)", ln.Addr(), url, typeNameOrGeneric(cfg.Client[name].Type))
		go func() {
			for {
				tcp, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					var ne net.Error
					if errors.As(err, &ne) && ne.Temporary() {
						// 瞬时错误退避重试，避免 FD 压力下某条 forward 静默失联
						log.Printf("accept (%s): %v (transient, retrying)", name, err)
						time.Sleep(5 * time.Millisecond)
						continue
					}
					if ctx.Err() == nil {
						log.Printf("accept (%s): %v", name, err)
					}
					return
				}
				go handleLocalConn(tcp, url, priv, cfg.General.AllowInsecure, caPool, name)
			}
		}()
	}

	<-ctx.Done()
	log.Printf("signal received, closing local listeners")
	for _, ln := range listeners {
		ln.Close()
	}
}
