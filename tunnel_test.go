package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
// withIPSAN 控制叶子证书是否带 127.0.0.1 的 IP SAN。
func genTestTLS(t *testing.T, withIPSAN bool) testTLS {
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
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wstgo test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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
	tlsPair := genTestTLS(t, true)
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
	tlsPair := genTestTLS(t, true)
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
	tlsPair := genTestTLS(t, true)
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
	serverTLS := genTestTLS(t, true)
	clientTrustedTLS := genTestTLS(t, true) // 另一套独立 CA

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
	serverTLS := genTestTLS(t, false) // 无 IP SAN
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
	tlsPair := genTestTLS(t, true)
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
