package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startEchoServer 启动 TCP echo 服务，返回其地址。
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startTunnelServer 用 httptest 起 CLI 形态的服务端（/ws -> target）。
func startTunnelServer(t *testing.T, wl *publicKeyWhitelist, target string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serveTunnel(ws, wl, target, "", r.RemoteAddr)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
}

// startTunnelClient 起本地 TCP 监听，每个连接走真实的 handleLocalConn 路径。
func startTunnelClient(t *testing.T, priv ed25519.PrivateKey, wsURL string, insecure bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleLocalConn(c, wsURL, priv, insecure, "")
		}
	}()
	return ln.Addr().String()
}

// roundtrip 向 conn 写入 payload 并读回，逐字节校验一致。
func roundtrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch over %d bytes", len(payload))
	}
}

func setupTunnel(t *testing.T) (clientAddr string) {
	t.Helper()
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, n, err := loadWhitelistFromDir(dir)
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))
	return startTunnelClient(t, priv, serverURL, false)
}

func TestTunnelEndToEnd(t *testing.T) {
	clientAddr := setupTunnel(t)

	// 小流量（击键级）
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("hello wstgo"))
	conn.Close()

	// 大流量（128KB，跨多个 32KB WS 帧）
	conn2, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn2, payload)
}

func TestTunnelConcurrentConns(t *testing.T) {
	clientAddr := setupTunnel(t)

	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func(i int) {
			conn, err := net.Dial("tcp", clientAddr)
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			payload := bytes.Repeat([]byte{byte('A' + i)}, 64*1024)
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				done <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				done <- err
				return
			}
			if !bytes.Equal(got, payload) {
				done <- io.ErrUnexpectedEOF
				return
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent tunnel failed: %v", err)
		}
	}
}

func TestTunnelWrongKeyRejectedFast(t *testing.T) {
	// 白名单里的公钥与客户端私钥不配对：本地连接应被立即关闭，且不重试
	dir := t.TempDir()
	genTestKeyPair(t, dir) // 白名单公钥与客户端私钥不配对
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))
	privOther, _ := genTestKeyPair(t, t.TempDir())
	clientAddr := startTunnelClient(t, privOther, serverURL, false)

	start := time.Now()
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection should be closed after auth rejection")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("auth rejection should fail fast without retries, took %v", elapsed)
	}
}

func TestDialWithRetry404NoRetry(t *testing.T) {
	priv, _ := genTestKeyPair(t, t.TempDir())
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	url := "ws" + strings.TrimPrefix(s.URL, "http")

	start := time.Now()
	_, err := dialWithRetry(url, priv, false)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error without retry, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("404 must not retry, took %v", elapsed)
	}
}

func TestDialWithRetryBackoffExhausted(t *testing.T) {
	oldInitial, oldMaxNum := dialRetryInitial, dialRetryMaxNum
	dialRetryInitial = time.Millisecond
	dialRetryMaxNum = 3
	t.Cleanup(func() { dialRetryInitial, dialRetryMaxNum = oldInitial, oldMaxNum })

	priv, _ := genTestKeyPair(t, t.TempDir())
	// 拿一个确定无服务的端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	_, err = dialWithRetry("ws://"+closedAddr+"/ws", priv, false)
	if err == nil {
		t.Fatal("dialing a closed port should exhaust retries and fail")
	}
}

func TestConfigModeRouting(t *testing.T) {
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	echoAddr := startEchoServer(t)

	forwards := map[string]ServerForward{
		"echo": {Target: echoAddr, Type: "db"},
	}
	s := httptest.NewServer(buildServerMux(wl, forwards))
	t.Cleanup(s.Close)
	root := "ws" + strings.TrimPrefix(s.URL, "http")

	// 已知标签：经完整客户端路径 roundtrip
	clientAddr := startTunnelClient(t, priv, root+"/ws/echo", false)
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("config-mode routing works"))
	conn.Close()

	// 未知标签：HTTP 404，升级失败
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	_, resp, err := d.Dial(root+"/ws/nope", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown label should 404, got err=%v resp=%v", err, resp)
	}

	// 裸 /ws：404
	_, resp, err = d.Dial(root+"/ws", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bare /ws should 404, got err=%v resp=%v", err, resp)
	}

	// 带二级路径的标签：404
	_, resp, err = d.Dial(root+"/ws/echo/extra", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nested label path should 404, got err=%v resp=%v", err, resp)
	}
}
