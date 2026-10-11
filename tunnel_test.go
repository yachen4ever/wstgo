package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
func startTunnelClient(t *testing.T, priv ed25519.PrivateKey, wsURL string, insecure bool, caPool *x509.CertPool) string {
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
			go handleLocalConn(c, wsURL, priv, insecure, caPool, "")
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
	return startTunnelClient(t, priv, serverURL, false, nil)
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
	clientAddr := startTunnelClient(t, privOther, serverURL, false, nil)

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
	_, err := dialWithRetry(url, priv, false, nil)
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

	_, err = dialWithRetry("ws://"+closedAddr+"/ws", priv, false, nil)
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
	clientAddr := startTunnelClient(t, priv, root+"/ws/echo", false, nil)
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

// ---- TLS / cacert：标准 CA 语义（链 + 主机名/SAN 校验）----

type testTLS struct {
	caPEM  []byte           // CA 证书 PEM（客户端 -cacert 用）
	server *tls.Certificate // 服务端叶子证书
}

// genTestTLS 生成测试用 CA 与叶子证书（ECDSA P-256，生成足够快）。
// withIPSAN 控制叶子证书是否带 127.0.0.1 的 IP SAN；expired=true 时
// 叶子证书签成已过期（NotAfter 在过去）。
func genTestTLS(t *testing.T, withIPSAN bool, expired bool) testTLS {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wstgo test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafNotAfter := time.Now().Add(time.Hour)
	if expired {
		leafNotAfter = time.Now().Add(-time.Hour)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wstgo test leaf"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if withIPSAN {
		leafTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return testTLS{
		caPEM:  caPEM,
		server: &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// startTunnelTLSServer 用给定证书起 wstgo 服务端（原生 wss 形态，/ws -> target）。
func startTunnelTLSServer(t *testing.T, cert tls.Certificate, wl *publicKeyWhitelist, target string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serveTunnel(ws, wl, target, "", r.RemoteAddr)
	})
	s := httptest.NewUnstartedServer(mux)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return "wss" + strings.TrimPrefix(s.URL, "https") + "/ws"
}

func TestLoadCACertPool(t *testing.T) {
	tlsPair := genTestTLS(t, true, false)
	dir := t.TempDir()

	// PEM
	pemPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(pemPath, tlsPair.caPEM, 0o600)
	pool, err := loadCACertPool(pemPath)
	if err != nil || pool == nil {
		t.Fatalf("PEM CA should load: %v", err)
	}

	// DER（Windows 分发的 .crt 常见形态）
	derPath := filepath.Join(dir, "ca.der")
	derBlock, _ := pem.Decode(tlsPair.caPEM)
	os.WriteFile(derPath, derBlock.Bytes, 0o600)
	if _, err := loadCACertPool(derPath); err != nil {
		t.Fatalf("DER CA should load: %v", err)
	}

	// 垃圾文件
	junkPath := filepath.Join(dir, "junk.crt")
	os.WriteFile(junkPath, []byte("not a certificate"), 0o600)
	if _, err := loadCACertPool(junkPath); err == nil || !strings.Contains(err.Error(), "neither PEM nor DER") {
		t.Fatalf("garbage file should error, got %v", err)
	}

	// 文件不存在
	if _, err := loadCACertPool(filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestTunnelWithCACert(t *testing.T) {
	// CA 签发 + 叶子带 IP SAN：标准校验路径下完整隧道可用
	tlsPair := genTestTLS(t, true, false)
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, tlsPair.caPEM, 0o600)
	caPool, err := loadCACertPool(caPath)
	if err != nil {
		t.Fatal(err)
	}

	serverURL := startTunnelTLSServer(t, *tlsPair.server, wl, startEchoServer(t))
	clientAddr := startTunnelClient(t, priv, serverURL, false, caPool)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("cacert verification works"))
	conn.Close()
}

func TestTunnelInsecureAgainstTLS(t *testing.T) {
	// insecure 路径对 TLS 服务端仍然可用（回归保护）
	tlsPair := genTestTLS(t, true, false)
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelTLSServer(t, *tlsPair.server, wl, startEchoServer(t))
	clientAddr := startTunnelClient(t, priv, serverURL, true, nil)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("insecure still works"))
	conn.Close()
}

// failTLSClient 断言"TLS 校验失败的连接应快速失败"（证书错误不重试：
// 默认退避下错误路径要走 15s，3s 预算足以区分两种行为）。
func failTLSClient(t *testing.T, clientAddr string) {
	t.Helper()
	start := time.Now()
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection should be closed after TLS verification failure")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("TLS failure should fail fast without retries, took %v", elapsed)
	}
}

func TestTunnelWrongCARejected(t *testing.T) {
	// 服务端证书由 CA-A 签发，客户端只信任 CA-B：标准校验必须拒绝
	serverTLS := genTestTLS(t, true, false)
	clientTrustedTLS := genTestTLS(t, true, false) // 另一套独立 CA

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelTLSServer(t, *serverTLS.server, wl, startEchoServer(t))

	caPath := filepath.Join(t.TempDir(), "other-ca.pem")
	os.WriteFile(caPath, clientTrustedTLS.caPEM, 0o600)
	caPool, err := loadCACertPool(caPath)
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := startTunnelClient(t, priv, serverURL, false, caPool)
	failTLSClient(t, clientAddr)
}

func TestTunnelCACertHostnameMismatch(t *testing.T) {
	// CA 信任了，但叶子证书没有 IP SAN：标准语义下主机名校验必须失败——
	// 这正是自签证书必须把 IP 写进 SAN 的原因（文档化行为）。
	serverTLS := genTestTLS(t, false, false) // 无 IP SAN
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelTLSServer(t, *serverTLS.server, wl, startEchoServer(t))

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, serverTLS.caPEM, 0o600) // 信任的是正确 CA
	caPool, err := loadCACertPool(caPath)
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := startTunnelClient(t, priv, serverURL, false, caPool)
	failTLSClient(t, clientAddr)
}

func TestCACertInsecureMutuallyExclusiveInConfig(t *testing.T) {
	_, err := loadConfig(writeTempConfig(t, `
[general]
run_mode = "client"
url = "wss://tunnel.example.com/ws"
key = "/tmp/private.pem"
allow_insecure = true
cacert = "/tmp/ca.pem"
[client.ssh1]
bind = "127.0.0.1:50022"
`))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("allow_insecure + cacert should be rejected, got %v", err)
	}
}

func TestRunClientConfigWithCACertEndToEnd(t *testing.T) {
	// 配置文件模式全链路：TOML（含 cacert）→ loadConfig → runClientConfig
	// → 标准 TLS 校验 → 隧道 roundtrip → SIGTERM 收尾（顺带验证信号路径）。
	tlsPair := genTestTLS(t, true, false)
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir) // 生成 private.pem/public.pem 供配置引用
	_ = priv
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, tlsPair.caPEM, 0o600)

	// 先占坑拿一个客户端本地监听端口（runClientConfig 自己 bind）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// 配置模式服务端（buildServerMux + TLS），标签 echo
	wl, n, err := loadWhitelistFromDir(dir) // private.pem 被跳过，public.pem 计 1
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	forwards := map[string]ServerForward{"echo": {Target: startEchoServer(t), Type: "db"}}
	s := httptest.NewUnstartedServer(buildServerMux(wl, forwards))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{*tlsPair.server}}
	s.StartTLS()
	t.Cleanup(s.Close)
	base := "wss" + strings.TrimPrefix(s.URL, "https") + "/ws"

	// 写真实 TOML 配置文件并加载
	cfgPath := filepath.Join(t.TempDir(), "client.toml")
	tomlContent := fmt.Sprintf(`
[general]
run_mode = "client"
url = %q
key = %q
cacert = %q

[client.echo]
bind = "127.0.0.1:%d"
`, base, filepath.Join(dir, "private.pem"), caPath, clientPort)
	os.WriteFile(cfgPath, []byte(tomlContent), 0o600)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	go runClientConfig(cfg)

	// 等 runClientConfig 绑定好本地监听
	addr := fmt.Sprintf("127.0.0.1:%d", clientPort)
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client listener never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	roundtrip(t, conn, []byte("config-mode cacert e2e works"))
	conn.Close()

	// SIGTERM 收尾：本地监听应被关闭（验证配置模式的信号处理路径）
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			break // 拒连 = 监听已关
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after SIGTERM")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---- 桥接生命周期：任何一侧关闭都必须及时传播到另一端 ----

// TestLocalCloseTearsDownTunnel 本地 app 断开后，server 端的 target 连接
// 必须被及时关闭（回归：曾经因心跳续约被永久焊住，泄漏 target 连接）。
func TestLocalCloseTearsDownTunnel(t *testing.T) {
	targetClosed := make(chan struct{}, 1)
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c)
				c.Close()
				select {
				case targetClosed <- struct{}{}:
				default:
				}
			}(c)
		}
	}()

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, tl.Addr().String())
	clientAddr := startTunnelClient(t, priv, serverURL, false, nil)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("ping")) // 先确认隧道可用
	conn.Close()                       // 本地 app 断开

	select {
	case <-targetClosed:
		// 及时拆除 ✓
	case <-time.After(5 * time.Second):
		t.Fatal("server-side target conn STILL OPEN 5s after local close (teardown not propagated)")
	}
}

// TestTargetCloseReachesLocal target 关闭后，客户端本地连接必须很快看到
// 断开（回归：曾经本地 app 挂死到读超时）。
func TestTargetCloseReachesLocal(t *testing.T) {
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		c, err := tl.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			c.Write(buf[:n])
			time.Sleep(200 * time.Millisecond)
			c.Close() // target 主动断开
		}(c)
	}()

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, tl.Addr().String())
	clientAddr := startTunnelClient(t, priv, serverURL, false, nil)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundtrip(t, conn, []byte("ping"))

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected error after target close, got none")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("local conn hung %.1fs after target close (teardown not propagated)", elapsed.Seconds())
	}
}

// TestSlowConsumerWriteDeadline 对端停止消费时，数据写必须在 writeWait
// 内超时拆除（回归：曾经无写超时，心跳续约把死链永久焊住）。
func TestSlowConsumerWriteDeadline(t *testing.T) {
	oldWriteWait := writeWait.Load()
	writeWait.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { writeWait.Store(oldWriteWait) })

	// target 监听：无限写循环在下方启动（对端不读就把中间所有缓冲填满）
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, tl.Addr().String())
	clientAddr := startTunnelClient(t, priv, serverURL, false, nil)

	// "app" 连上后从不读取；从 target 侧观测：server 数据写超时拆除时会
	// 关闭 target 连接，无限写循环立刻报错退出。
	writeFailed := make(chan struct{}, 1)
	go func() {
		c, err := tl.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			chunk := make([]byte, ioBufSize)
			for {
				if _, err := c.Write(chunk); err != nil {
					select {
					case writeFailed <- struct{}{}:
					default:
					}
					return
				}
			}
		}(c)
	}()

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case <-writeFailed:
		// server 写超时 → 拆除 → target 连接被关 ✓
	case <-time.After(5 * time.Second):
		t.Fatal("slow consumer not torn down within 5s (write deadline missing?)")
	}
}

// ---- P2 补齐：证书过期 / 心跳语义 / 重试语义 ----

func TestExpiredCertRejected(t *testing.T) {
	// x509 三分支的第三个：过期证书也必须快速失败不重试
	serverTLS := genTestTLS(t, true, true) // 过期叶子
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelTLSServer(t, *serverTLS.server, wl, startEchoServer(t))

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, serverTLS.caPEM, 0o600) // CA 是信任的，过期的是叶子
	caPool, err := loadCACertPool(caPath)
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := startTunnelClient(t, priv, serverURL, false, caPool)
	failTLSClient(t, clientAddr)
}

// TestHeartbeatKeepsIdleAlive 心跳续约必须让空闲连接活过 readTimeout。
func TestHeartbeatKeepsIdleAlive(t *testing.T) {
	oldHB, oldRT := heartbeatInterval.Load(), readTimeout.Load()
	heartbeatInterval.Store(int64(20 * time.Millisecond))
	readTimeout.Store(int64(200 * time.Millisecond)) // 慢 CI 下给续约留裕量
	t.Cleanup(func() {
		heartbeatInterval.Store(oldHB)
		readTimeout.Store(oldRT)
	})

	clientAddr := setupTunnel(t)
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	time.Sleep(500 * time.Millisecond) // 5 倍 readTimeout 的空闲期
	roundtrip(t, conn, []byte("still alive after idle"))
}

// TestSilentConnDropped 无心跳的静默连接必须在 readTimeout 内被服务端拆除。
func TestSilentConnDropped(t *testing.T) {
	oldRT := readTimeout.Load()
	readTimeout.Store(int64(100 * time.Millisecond))
	t.Cleanup(func() { readTimeout.Store(oldRT) })

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))

	// 原始 WS 客户端：握手完成后不发任何数据、不发心跳
	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial(serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadLimit(maxMessageSize)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("silent conn should be dropped by server")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("silent conn kept alive %.1fs (read timeout not enforced)", elapsed.Seconds())
	}
}

// startFlakyTunnelServer 前 failFirst 次 HTTP 503，之后正常升级。
// 返回尝试计数指针，用于断言重试确实发生。
func startFlakyTunnelServer(t *testing.T, wl *publicKeyWhitelist, target string, failFirst int) (string, *int32) {
	t.Helper()
	var count int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&count, 1) <= int32(failFirst) {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serveTunnel(ws, wl, target, "", r.RemoteAddr)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return "ws" + strings.TrimPrefix(s.URL, "http") + "/ws", &count
}

// TestRetryThenSuccess 瞬态故障（503）后重试必须能恢复隧道——
// 证明退避重试真的发生并最终成功，而不只是耗尽后失败。
func TestRetryThenSuccess(t *testing.T) {
	oldInit := dialRetryInitial
	dialRetryInitial = time.Millisecond
	t.Cleanup(func() { dialRetryInitial = oldInit })

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL, attempts := startFlakyTunnelServer(t, wl, startEchoServer(t), 2)
	clientAddr := startTunnelClient(t, priv, serverURL, false, nil)

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("recovered after transient failures"))
	conn.Close()

	if got := atomic.LoadInt32(attempts); got < 3 {
		t.Fatalf("expected at least 3 dial attempts (2 failures + 1 success), got %d", got)
	}
}

// TestDialRetryExhaustionCounts 重试耗尽时的尝试次数必须精确等于
// dialRetryMaxNum（锚定重试循环本身，而不只是最终错误）。
func TestDialRetryExhaustionCounts(t *testing.T) {
	oldInit, oldMax := dialRetryInitial, dialRetryMaxNum
	dialRetryInitial = time.Millisecond
	dialRetryMaxNum = 3
	t.Cleanup(func() { dialRetryInitial, dialRetryMaxNum = oldInit, oldMax })

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL, attempts := startFlakyTunnelServer(t, wl, startEchoServer(t), 1000)

	_, err = dialWithRetry(serverURL, priv, false, nil)
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	if got := atomic.LoadInt32(attempts); got != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d", got)
	}
}

// ---- P3：单帧上限 / 握手瞬态重试 / 多证书 PEM ----

func TestMaxMessageSizeEnforced(t *testing.T) {
	// 未鉴权对端发 65KB+ 帧（> maxMessageSize）：连接必须被立即拆除，
	// 防止无界内存分配
	dir := t.TempDir()
	genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	readFrame(t, ws) // nonce
	big := make([]byte, maxMessageSize+1)
	_ = ws.WriteMessage(websocket.BinaryMessage, big)

	r := waitResult(t, results)
	if r.err == nil {
		t.Fatal("oversized pre-auth frame should tear the connection down")
	}
}

// TestHandshakeTransientRetry 握手阶段的传输类错误（对端恰在重启时
// 断开）会退避重试；密钥/协议类错误仍不重试。
func TestHandshakeTransientRetry(t *testing.T) {
	oldInit := dialRetryInitial
	dialRetryInitial = time.Millisecond
	t.Cleanup(func() { dialRetryInitial = oldInit })

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	echoAddr := startEchoServer(t)

	var count int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&count, 1) <= 2 {
			// 前两次：升级后立刻断开（不回 nonce），模拟重启中的服务端
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			ws.Close()
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serveTunnel(ws, wl, echoAddr, "", r.RemoteAddr)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	serverURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"

	clientAddr := startTunnelClient(t, priv, serverURL, false, nil)
	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, conn, []byte("recovered after transient handshake failures"))
	conn.Close()

	if got := atomic.LoadInt32(&count); got < 3 {
		t.Fatalf("expected at least 3 handshake attempts, got %d", got)
	}
}

func TestLoadCACertPoolMultiCertPEM(t *testing.T) {
	// 根 CA + 叶子拼在一个 PEM 里：loadCACertPool 注释声称支持，验证之
	tlsPair := genTestTLS(t, true, false)
	leafDER := tlsPair.server.Certificate[0]
	combined := append(append([]byte{}, tlsPair.caPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	p := filepath.Join(t.TempDir(), "chain.pem")
	os.WriteFile(p, combined, 0o600)
	if _, err := loadCACertPool(p); err != nil {
		t.Fatalf("multi-cert PEM should load: %v", err)
	}
}

// ---- 二轮审计收口：生命周期新行为 / 方向标签 / 参数锚定 ----

// TestDirectionLabels 锚定 -v 流量日志的方向语义（回归：server 端曾整体
// 标反——server 的 TCP 连的是 target/S 侧，TCP→WS 应为 S→C）。
func TestDirectionLabels(t *testing.T) {
	d1, d2, logErr := directionLabels(true)
	if d1 != "S→C" || d2 != "C→S" || !logErr {
		t.Fatalf("server labels = %q/%q logTCPErr=%v", d1, d2, logErr)
	}
	d1, d2, logErr = directionLabels(false)
	if d1 != "L→R" || d2 != "R→L" || logErr {
		t.Fatalf("client labels = %q/%q logTCPErr=%v", d1, d2, logErr)
	}
}

// TestHeartbeatPingFailureTearsDownNow 心跳 Ping 写失败必须 cancel 且立即
// 关 ws（回归：曾只 cancel，读阻塞最长 30s 后才拆除）。
func TestHeartbeatPingFailureTearsDownNow(t *testing.T) {
	oldHB, oldWW := heartbeatInterval.Load(), writeWait.Load()
	heartbeatInterval.Store(int64(20 * time.Millisecond))
	writeWait.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() {
		heartbeatInterval.Store(oldHB)
		writeWait.Store(oldWW)
	})

	// 对端握住连接但不读不回：Ping 会填满发送缓冲并在 writeWait 内超时
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		time.Sleep(2 * time.Second)
	}))
	t.Cleanup(s.Close)

	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial("ws"+strings.TrimPrefix(s.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		startHeartbeat(ws, ctx, cancel)
		close(done)
	}()

	select {
	case <-done:
		// Ping 失败路径触发 ✓
	case <-time.After(3 * time.Second):
		t.Fatal("startHeartbeat did not return after peer stopped responding")
	}
	if ctx.Err() == nil {
		t.Fatal("cancel should have been called on ping failure")
	}
	// ws 必须已被关闭：ReadMessage 立即报错（而非等到读超时）
	ws.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("ws should be closed immediately after ping failure")
	}
}

// TestTargetUnreachableCloseReason 拨 target 失败时客户端应收到
// 1011 + "target unreachable"，可与网络故障区分。
func TestTargetUnreachableCloseReason(t *testing.T) {
	oldTDT := targetDialTimeout.Load()
	targetDialTimeout.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { targetDialTimeout.Store(oldTDT) })

	// 死端口：listen 后立即关闭
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, deadAddr)

	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial(serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadLimit(maxMessageSize)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatal(err)
	}

	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = ws.ReadMessage()
	if err == nil {
		t.Fatal("expected close after target dial failure")
	}
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("want CloseError, got %v", err)
	}
	if ce.Code != websocket.CloseInternalServerErr || ce.Text != "target unreachable" {
		t.Fatalf("close = %d %q, want 1011 \"target unreachable\"", ce.Code, ce.Text)
	}
}

// TestDataModeTextFrameTornDown 鉴权后的数据模式同样强制 Binary：
// Text 数据帧按协议违例拆除（握手阶段已有单独测试，这是另一半）。
func TestDataModeTextFrameTornDown(t *testing.T) {
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))

	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial(serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadLimit(maxMessageSize)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatal(err)
	}

	_ = ws.WriteMessage(websocket.TextMessage, []byte("protocol violation"))
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("text data frame should tear down the tunnel")
	}
}

// TestDataDoesNotRenewReadDeadline 数据帧不续约读超时（只有 Ping/Pong
// 续约）：持续有数据但无心跳的连接仍会被判死拆除。这是有意为之且
// 反直觉的语义，测试防止将来被"好心修复"。
func TestDataDoesNotRenewReadDeadline(t *testing.T) {
	oldRT := readTimeout.Load()
	readTimeout.Store(int64(150 * time.Millisecond))
	t.Cleanup(func() { readTimeout.Store(oldRT) })

	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))

	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial(serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadLimit(maxMessageSize)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatal(err)
	}

	// 持续发数据帧（不发 Ping）：读超时仍应到期拆除
	go func() {
		frame := make([]byte, 16)
		for {
			if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	start := time.Now()
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			// 服务端读超时到期 → 拆除 → 本端读到错误
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("data frames appear to renew the read deadline: %.1fs", elapsed.Seconds())
			}
			return
		}
		// echo 回来的数据帧，继续读
	}
}

// TestCloseReasonSanitizedInLog 对端 close 帧的 reason 是对端可控文本，
// 进日志前必须消毒（回归：曾可直接注入换行/ANSI）。
func TestCloseReasonSanitizedInLog(t *testing.T) {
	dir := t.TempDir()
	priv, _ := genTestKeyPair(t, dir)
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverURL := startTunnelServer(t, wl, startEchoServer(t))

	var mu sync.Mutex
	var logBuf bytes.Buffer
	log.SetOutput(&mutexWriter{mu: &mu, w: &logBuf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	ws, _, err := d.Dial(serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ws.SetReadLimit(maxMessageSize)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatal(err)
	}
	// 非 1000/1001 的 close 码会进服务端日志；reason 里塞换行和 ANSI ESC
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(4000, "x\nINJECTED\x1b[31m"),
		time.Now().Add(2*time.Second))
	ws.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		logs := logBuf.String()
		mu.Unlock()
		if strings.Contains(logs, "INJECTED") {
			if strings.Contains(logs, "\nINJECTED") || strings.Contains(logs, "\x1b") {
				t.Fatalf("log injection not sanitized: %q", logs)
			}
			return // 日志里有消毒后的内容 ✓
		}
		if time.Now().After(deadline) {
			t.Fatal("close-reason log line never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type mutexWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (m *mutexWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.w.Write(p)
}

// TestTransportDefaultsAnchored 把 README 记载的传输参数与代码默认值
// 互相锚定，防双向漂移。
func TestTransportDefaultsAnchored(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"heartbeatInterval", time.Duration(heartbeatInterval.Load()), 10 * time.Second},
		{"readTimeout", time.Duration(readTimeout.Load()), 30 * time.Second},
		{"writeWait", time.Duration(writeWait.Load()), 10 * time.Second},
		{"targetDialTimeout", time.Duration(targetDialTimeout.Load()), 5 * time.Second},
		{"dialTimeout (client WS)", dialTimeout, 10 * time.Second},
		{"authDeadline", authDeadline, 10 * time.Second},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, README says %v", tc.name, tc.got, tc.want)
		}
	}
	if dialRetryMaxNum != 5 {
		t.Errorf("dialRetryMaxNum = %d, README says 5 attempts", dialRetryMaxNum)
	}
}
