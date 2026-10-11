package main

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type handshakeResult struct {
	pub ed25519.PublicKey
	err error
}

// startAuthTestServer 起一个只做 serverHandshake 的 WS 测试服务。
// 行为与 serveTunnel 的鉴权段一致：authError 走 sendAuthFail（客户端能看到
// [0x04] 拒绝帧），成功则保持连接读到底。每条连接的结果投递到返回的 channel。
func startAuthTestServer(t *testing.T, wl *publicKeyWhitelist) (wsURL string, results <-chan handshakeResult) {
	t.Helper()
	ch := make(chan handshakeResult, 8)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		ws.SetReadLimit(maxMessageSize)
		pub, err := serverHandshake(ws, wl)
		ch <- handshakeResult{pub, err}
		var ae *authError
		if errors.As(err, &ae) {
			sendAuthFail(ws, ae.reason)
			return
		}
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(s.Close)
	return "ws" + strings.TrimPrefix(s.URL, "http"), ch
}

func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	ws, resp, err := d.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v (resp=%v)", url, err, resp)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

// waitResult 带超时收服务端握手结果，防止测试挂死。
func waitResult(t *testing.T, results <-chan handshakeResult) handshakeResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server handshake result")
		return handshakeResult{}
	}
}

func TestHandshakeSuccess(t *testing.T) {
	dir := t.TempDir()
	priv, pub := genTestKeyPair(t, dir)
	wl, n, err := loadWhitelistFromDir(dir)
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	if err := clientHandshake(ws, priv); err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	r := waitResult(t, results)
	if r.err != nil {
		t.Fatalf("server handshake failed: %v", r.err)
	}
	if string(r.pub) != string(pub) {
		t.Fatal("server saw a different public key than the client's")
	}
}

func authFrame(pub ed25519.PublicKey, sig []byte) []byte {
	msg := make([]byte, lenAuthMsg)
	msg[0] = msgAuth
	copy(msg[1:1+ed25519.PublicKeySize], pub)
	copy(msg[1+ed25519.PublicKeySize:], sig)
	return msg
}

func readFrame(t *testing.T, ws *websocket.Conn) []byte {
	t.Helper()
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, buf, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return buf
}

func expectAuthFail(t *testing.T, ws *websocket.Conn, wantReason string) {
	t.Helper()
	buf := readFrame(t, ws)
	if len(buf) < 1 || buf[0] != msgAuthFail {
		t.Fatalf("want auth-fail frame, got %v", buf)
	}
	if got := string(buf[1:]); got != wantReason {
		t.Fatalf("reject reason = %q, want %q", got, wantReason)
	}
}

func TestHandshakeUnknownKeyRejected(t *testing.T) {
	// 白名单里只有一把无关的公钥；客户端 B 的密钥不在其中
	wldir := t.TempDir()
	genTestKeyPair(t, wldir)
	wl, n, err := loadWhitelistFromDir(wldir)
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	privB, _ := genTestKeyPair(t, t.TempDir())
	url, results := startAuthTestServer(t, wl)
	ws := dialWS(t, url)
	if err := clientHandshake(ws, privB); err == nil || !strings.Contains(err.Error(), "not in whitelist") {
		t.Fatalf("client should see whitelist rejection, got %v", err)
	}
	if r := waitResult(t, results); r.err == nil || !strings.Contains(r.err.Error(), "not in whitelist") {
		t.Fatalf("server should reject unknown key, got %v", r.err)
	}
}

func TestHandshakeBadSignatureRejected(t *testing.T) {
	// 公钥在白名单，但签名用另一把私钥伪造 → signature verification failed
	dir := t.TempDir()
	_, pubW := genTestKeyPair(t, dir)
	wl, n, err := loadWhitelistFromDir(dir)
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	privForged, _ := genTestKeyPair(t, t.TempDir())
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	nonceMsg := readFrame(t, ws)
	if len(nonceMsg) != lenNonceMsg || nonceMsg[0] != msgNonce {
		t.Fatalf("want nonce frame, got %v", nonceMsg)
	}
	sig := ed25519.Sign(privForged, nonceMsg[1:])
	ws.WriteMessage(websocket.BinaryMessage, authFrame(pubW, sig))
	expectAuthFail(t, ws, "signature verification failed")
	if r := waitResult(t, results); r.err == nil || !strings.Contains(r.err.Error(), "signature") {
		t.Fatalf("server should report signature failure, got %v", r.err)
	}
}

func TestHandshakeMalformedAuth(t *testing.T) {
	dir := t.TempDir()
	genTestKeyPair(t, dir) // 白名单目录里放一把公钥
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	readFrame(t, ws) // nonce
	ws.WriteMessage(websocket.BinaryMessage, []byte{0x99, 0x01, 0x02})
	expectAuthFail(t, ws, "malformed handshake message")
	if r := waitResult(t, results); r.err == nil {
		t.Fatal("server should report the malformed auth frame")
	}
}

func TestHandshakeEmptyWhitelist(t *testing.T) {
	wl, n, err := loadWhitelistFromDir(t.TempDir())
	if err != nil || n != 0 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	if err := clientHandshake(ws, mustPriv(t)); err == nil || !strings.Contains(err.Error(), "no authorized public keys") {
		t.Fatalf("client should see empty-whitelist rejection, got %v", err)
	}
	if r := waitResult(t, results); r.err == nil || !strings.Contains(r.err.Error(), "no authorized public keys") {
		t.Fatalf("server should refuse with empty whitelist, got %v", r.err)
	}
}

// mustPriv 生成一把不在任何白名单里的私钥。
func mustPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, _ := genTestKeyPair(t, t.TempDir())
	return priv
}

func TestHandshakeRecoversFromEmptyWhitelist(t *testing.T) {
	// 运行期白名单被清空后再补公钥：未命中/空状态的限流重扫应让新公钥
	// 对下一条连接生效，而不是干等 30 秒周期重扫。
	setRescanMinInterval(t, 0)
	authdir := t.TempDir()
	wl, n, err := loadWhitelistFromDir(authdir) // 空：0 个公钥
	if err != nil || n != 0 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	url, results := startAuthTestServer(t, wl)

	privB, _ := genTestKeyPair(t, t.TempDir())
	ws := dialWS(t, url)
	if err := clientHandshake(ws, privB); err == nil || !strings.Contains(err.Error(), "no authorized public keys") {
		t.Fatalf("empty whitelist should reject, got %v", err)
	}
	waitResult(t, results)

	// 补进公钥后下一条连接即通过（空状态分支也要触发重扫）
	pubB := privB.Public().(ed25519.PublicKey)
	writeAuthKey(t, authdir, "b.pem", pubB)
	ws2 := dialWS(t, url)
	if err := clientHandshake(ws2, privB); err != nil {
		t.Fatalf("connect after refilling empty whitelist should succeed, got %v", err)
	}
	if r := waitResult(t, results); r.err != nil {
		t.Fatalf("server should accept key after empty-state recovery, got %v", r.err)
	}
}

func TestClientHandshakeEarlyReject(t *testing.T) {
	// 服务端在发 nonce 之前就发裸 [0x04]（无 reason）：客户端应报 "rejected"
	// 而不是误导性的 "malformed nonce message"。
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		ws.WriteMessage(websocket.BinaryMessage, []byte{msgAuthFail})
	}))
	t.Cleanup(s.Close)
	url := "ws" + strings.TrimPrefix(s.URL, "http")

	ws := dialWS(t, url)
	priv, _ := genTestKeyPair(t, t.TempDir())
	err := clientHandshake(ws, priv)
	var ae *authError
	if !errors.As(err, &ae) || ae.reason != "rejected" {
		t.Fatalf("bare [0x04] should surface as \"rejected\", got %v", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	old := authDeadline
	authDeadline = 200 * time.Millisecond
	t.Cleanup(func() { authDeadline = old })

	dir := t.TempDir()
	genTestKeyPair(t, dir) // 白名单目录里放一把公钥
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	url, results := startAuthTestServer(t, wl)

	ws := dialWS(t, url)
	readFrame(t, ws) // nonce 正常到达
	// 不回 auth，等握手超时：服务端报错并关闭，客户端随后读到失败
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("server should close the connection after auth deadline")
	}
	// 锚定超时本身（而非任意提前关闭）：服务端错误必须是 deadline 类
	r := waitResult(t, results)
	if r.err == nil {
		t.Fatal("server handshake should fail on deadline")
	}
	if !strings.Contains(r.err.Error(), "i/o timeout") && !strings.Contains(r.err.Error(), "deadline exceeded") {
		t.Fatalf("handshake failure should be a deadline timeout, got %v", r.err)
	}
}

func TestHandshakePicksUpNewlyAddedKey(t *testing.T) {
	setRescanMinInterval(t, 0)
	authdir := t.TempDir()
	genTestKeyPair(t, authdir) // 白名单初始只有这把公钥
	wl, n, err := loadWhitelistFromDir(authdir)
	if err != nil || n != 1 {
		t.Fatalf("whitelist load: n=%d err=%v", n, err)
	}
	url, results := startAuthTestServer(t, wl)

	privB, _ := genTestKeyPair(t, t.TempDir())
	// 第一条连接：B 不在白名单，被拒
	ws := dialWS(t, url)
	if err := clientHandshake(ws, privB); err == nil || !strings.Contains(err.Error(), "not in whitelist") {
		t.Fatalf("first connect should be rejected, got %v", err)
	}
	waitResult(t, results)

	// 把 B 的公钥放进 authdir，不重启：第二条连接应通过（未命中触发重扫）
	pubB := privB.Public().(ed25519.PublicKey)
	writeAuthKey(t, authdir, "b.pem", pubB)
	ws2 := dialWS(t, url)
	if err := clientHandshake(ws2, privB); err != nil {
		t.Fatalf("connect after adding key file should succeed, got %v", err)
	}
	if r := waitResult(t, results); r.err != nil {
		t.Fatalf("server should accept newly whitelisted key, got %v", r.err)
	}
}

// ---- P3：严格帧校验 / 原因消毒 ----

func TestHandshakeTextFrameRejected(t *testing.T) {
	// Text 帧当 nonce：协议要求握手帧一律 Binary，必须拒绝
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		ws.WriteMessage(websocket.TextMessage, []byte{msgNonce, 1, 2, 3})
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(s.Close)
	url := "ws" + strings.TrimPrefix(s.URL, "http")

	ws := dialWS(t, url)
	priv, _ := genTestKeyPair(t, t.TempDir())
	err := clientHandshake(ws, priv)
	if err == nil || !strings.Contains(err.Error(), "non-binary handshake frame") {
		t.Fatalf("text nonce frame should be rejected, got %v", err)
	}
}

func TestHandshakeRejectReasonSanitized(t *testing.T) {
	// 服务端下发的原因串经客户端消毒：控制字符/ANSI 不得进入日志
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		payload := append([]byte{msgAuthFail}, []byte("line1\n\x1b[31mred\x07")...)
		ws.WriteMessage(websocket.BinaryMessage, payload)
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(s.Close)
	url := "ws" + strings.TrimPrefix(s.URL, "http")

	ws := dialWS(t, url)
	priv, _ := genTestKeyPair(t, t.TempDir())
	err := clientHandshake(ws, priv)
	var ae *authError
	if !errors.As(err, &ae) {
		t.Fatalf("want authError, got %v", err)
	}
	if ae.reason != "line1[31mred" {
		t.Fatalf("reason should be sanitized to %q, got %q", "line1[31mred", ae.reason)
	}
}

func TestHandshakeWrongLengthAuthRejected(t *testing.T) {
	// 类型字节对但长度不对的 auth 帧（96 字节 vs 97）：严格长度校验必须拦下
	dir := t.TempDir()
	_, pubW := genTestKeyPair(t, dir)
	_ = pubW
	wl, _, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	url, results := startAuthTestServer(t, wl)

	priv, _ := genTestKeyPair(t, t.TempDir())
	ws := dialWS(t, url)
	nonceMsg := readFrame(t, ws)
	bad := make([]byte, lenAuthMsg-1) // 少 1 字节
	bad[0] = msgAuth
	copy(bad[1:], ed25519.Sign(priv, nonceMsg[1:]))
	ws.WriteMessage(websocket.BinaryMessage, bad)
	expectAuthFail(t, ws, "malformed handshake message")
	if r := waitResult(t, results); r.err == nil {
		t.Fatal("server should report the wrong-length auth frame")
	}
}
