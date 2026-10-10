package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
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

// dialWithRetry 带指数退避地拨号 WS 并完成鉴权握手。
// 成功返回已通过鉴权的 WS 连接；失败返回最后一次错误。
// insecure=true 时跳过 TLS 证书验证（用于 wss:// + 自签名证书场景）。
// 404 视为配置错误（标签在服务端不存在），不重试。
func dialWithRetry(websocketURL string, priv ed25519.PrivateKey, insecure bool) (*websocket.Conn, error) {
	var lastErr error
	backoff := dialRetryInitial
	for attempt := 1; attempt <= dialRetryMaxNum; attempt++ {
		d := &websocket.Dialer{
			HandshakeTimeout: dialTimeout,
		}
		if insecure {
			d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		ws, resp, err := d.Dial(websocketURL, nil)
		if err == nil {
			// 与 server 端对称：限制单帧大小，防止对端异常大帧
			ws.SetReadLimit(maxMessageSize)
			if err = clientHandshake(ws, priv); err == nil {
				return ws, nil
			}
			// 握手失败通常不可重试（密钥错误/协议不符），直接返回
			ws.Close()
			return nil, err
		}
		if errors.Is(err, websocket.ErrBadHandshake) && resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("dial %s: 404 not found (no [server.*] forward with this label on the server?)", websocketURL)
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
// 通过 ctx 退出。
func startHeartbeat(ws *websocket.Conn, writeMu *sync.Mutex, ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			writeMu.Lock()
			err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
			writeMu.Unlock()
			if err != nil {
				log.Printf("heartbeat ping failed: %v", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// handleLocalConn 处理单个本地 TCP 连接：
// 拨 WS + 鉴权 + 心跳 + 双向桥接。label 为配置模式的转发标签（CLI 模式为空）。
func handleLocalConn(tcp net.Conn, websocketURL string, priv ed25519.PrivateKey, insecure bool, label string) {
	defer tcp.Close()

	ws, err := dialWithRetry(websocketURL, priv, insecure)
	if err != nil {
		log.Printf("establish tunnel failed%s: %v", labelSuffix(label), err)
		return
	}
	defer ws.Close()

	installHeartbeat(ws) // 续约读超时 + 自动回 Pong

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex
	go startHeartbeat(ws, &writeMu, ctx)

	log.Printf("client tunnel up%s: %s <-> %s", labelSuffix(label), tcp.RemoteAddr(), websocketURL)
	bridgeClient(ws, tcp, &writeMu, ctx, labelSuffix(label))
	log.Printf("client tunnel down%s: %s", labelSuffix(label), tcp.RemoteAddr())
}

// bridgeClient 是 client 侧的桥接，与 server 端 bridge 对称。
// 共享 writeMu 以串行化数据写与心跳 Ping 写。tag 为日志后缀。
func bridgeClient(ws *websocket.Conn, tcp net.Conn, writeMu *sync.Mutex, ctx context.Context, tag string) {
	dir1, dir2 := "L\u2192R", "R\u2192L"

	// 协程: TCP -> WS
	go func() {
		buf := make([]byte, ioBufSize)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				writeMu.Lock()
				werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				writeMu.Unlock()
				if werr != nil {
					log.Printf("%s%s write err: %v", dir1, tag, werr)
					tcp.Close()
					return
				}
				if verbose {
					log.Printf("%s%s %d", dir1, tag, n)
				}
			}
			if err != nil {
				tcp.Close()
				return
			}
		}
	}()

	// 主: WS -> TCP
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, buf, err := ws.ReadMessage()
		if err != nil {
			log.Printf("%s%s read err: %v", dir2, tag, err)
			return
		}
		if _, err := tcp.Write(buf); err != nil {
			log.Printf("%s%s write err: %v", dir2, tag, err)
			return
		}
		if verbose {
			log.Printf("%s%s %d", dir2, tag, len(buf))
		}
	}
}

func client(bindAddr, websocketURL, keyPath string, insecure bool) {
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
			log.Printf("accept: %v", err)
			return
		}
		go handleLocalConn(tcp, websocketURL, priv, insecure, "")
	}
}

// runClientConfig 以配置文件模式启动客户端：每个 [client.<label>] 条目
// 在本地起一个 TCP 监听，转发到服务端 <general.url>/<label> 对应的路径。
// 全部端口先绑定再服务（任一失败整体退出）；SIGINT/SIGTERM 时关闭监听退出。
func runClientConfig(cfg *Config) {
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
					if ctx.Err() == nil {
						log.Printf("accept (%s): %v", name, err)
					}
					return
				}
				go handleLocalConn(tcp, url, priv, cfg.General.AllowInsecure, name)
			}
		}()
	}

	<-ctx.Done()
	log.Printf("signal received, closing local listeners")
	for _, ln := range listeners {
		ln.Close()
	}
}
