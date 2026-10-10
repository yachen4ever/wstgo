package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genTestKeyPair 在 dir 下生成密钥对并加载回内存，顺带验证签验签回路。
func genTestKeyPair(t *testing.T, dir string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	privPath, pubPath, err := generateKeyPair(dir)
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	priv, err := loadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}
	pub, err := loadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	msg := []byte("test nonce")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		t.Fatal("sign/verify roundtrip failed")
	}
	return priv, pub
}

func pubPEM(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func privPEM(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGenerateKeyPairFilesAndPerms(t *testing.T) {
	dir := t.TempDir()
	genTestKeyPair(t, dir)
	for _, tc := range []struct {
		name string
		perm os.FileMode
	}{
		{"private.pem", 0o600},
		{"public.pem", 0o644},
	} {
		info, err := os.Stat(filepath.Join(dir, tc.name))
		if err != nil {
			t.Fatalf("missing %s: %v", tc.name, err)
		}
		if info.Mode().Perm() != tc.perm {
			t.Errorf("%s perm = %v, want %v", tc.name, info.Mode().Perm(), tc.perm)
		}
	}
	// 重复生成（覆盖已有文件）不应报错
	if _, _, err := generateKeyPair(dir); err != nil {
		t.Fatalf("regenerate into existing dir: %v", err)
	}
}

func TestLoadPublicKeyRejectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	generateKeyPair(dir)
	_, err := loadPublicKey(filepath.Join(dir, "private.pem"))
	if err == nil || !strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("want PRIVATE-key rejection, got %v", err)
	}
}

func TestLoadPrivateKeyRejectsPublicKey(t *testing.T) {
	dir := t.TempDir()
	generateKeyPair(dir)
	_, err := loadPrivateKey(filepath.Join(dir, "public.pem"))
	if err == nil {
		t.Fatal("public.pem should not load as a private key")
	}
}

func TestLoadPrivateKeyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadPrivateKey(filepath.Join(dir, "nonexistent.pem")); err == nil {
		t.Fatal("missing file should error")
	}
	junk := filepath.Join(dir, "junk.pem")
	os.WriteFile(junk, []byte("not a pem at all"), 0o600)
	if _, err := loadPrivateKey(junk); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("garbage file should report no PEM block, got %v", err)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	_, pub := genTestKeyPair(t, t.TempDir())
	fp := publicKeyFingerprint(pub)
	if !strings.HasPrefix(fp, "ed25519:") || len(fp) != len("ed25519:")+8 {
		t.Fatalf("fingerprint format unexpected: %q", fp)
	}
	if got := publicKeyFingerprint(ed25519.PublicKey("ab")); got != "ed25519:?" {
		t.Fatalf("short key fingerprint = %q, want ed25519:?", got)
	}
}

func writeAuthKey(t *testing.T, dir, name string, pub ed25519.PublicKey) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), pubPEM(t, pub), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadWhitelistFromDirMissing(t *testing.T) {
	wl, n, err := loadWhitelistFromDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error at startup: %v", err)
	}
	if n != 0 || wl == nil || wl.count() != 0 {
		t.Fatalf("missing dir should give empty whitelist, got n=%d", n)
	}
}

func TestLoadWhitelistFromDirEmpty(t *testing.T) {
	wl, n, err := loadWhitelistFromDir(t.TempDir())
	if err != nil || n != 0 || wl.count() != 0 {
		t.Fatalf("empty dir should load 0 keys without error, got n=%d err=%v", n, err)
	}
}

func TestLoadWhitelistFromDirMixedFiles(t *testing.T) {
	dir := t.TempDir()
	privA, pubA := genTestKeyPair(t, t.TempDir())
	_, pubB := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, dir, "client-a.pem", pubA)
	writeAuthKey(t, dir, "client-b.txt", pubB) // 文件名不限
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte("not a key"), 0o600)
	os.WriteFile(filepath.Join(dir, "oops.pem"), privPEM(t, privA), 0o600) // 私钥误放应被跳过

	wl, n, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatalf("loadWhitelistFromDir: %v", err)
	}
	if n != 2 || wl.count() != 2 {
		t.Fatalf("want 2 valid keys, got n=%d", n)
	}
	if !wl.contains(pubA) || !wl.contains(pubB) {
		t.Fatal("authorized keys missing from whitelist")
	}
}

func TestLoadWhitelistDeduplicatesSameKey(t *testing.T) {
	dir := t.TempDir()
	_, pub := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, dir, "a.pem", pub)
	writeAuthKey(t, dir, "b.pem", pub)
	_, n, err := loadWhitelistFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate key files should dedupe to 1, got %d", n)
	}
}

// setRescanMinInterval 把 rescanMinInterval 换成 ms 并注册恢复。
func setRescanMinInterval(t *testing.T, ms time.Duration) {
	t.Helper()
	old := rescanMinInterval
	rescanMinInterval = ms
	t.Cleanup(func() { rescanMinInterval = old })
}

func TestWhitelistRescanPicksUpNewKey(t *testing.T) {
	setRescanMinInterval(t, 0)
	authdir := t.TempDir()
	_, pubA := genTestKeyPair(t, t.TempDir())
	_, pubB := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, authdir, "a.pem", pubA)

	wl, n, err := loadWhitelistFromDir(authdir)
	if err != nil || n != 1 {
		t.Fatalf("initial load: n=%d err=%v", n, err)
	}
	if wl.contains(pubB) {
		t.Fatal("B must not be authorized before its key file exists")
	}

	writeAuthKey(t, authdir, "b.pem", pubB)
	wl.rescan(true)
	if !wl.contains(pubB) {
		t.Fatal("rescan should pick up newly added key")
	}
	if !wl.contains(pubA) {
		t.Fatal("existing key must survive rescan")
	}
	if wl.count() != 2 {
		t.Fatalf("whitelist count = %d, want 2", wl.count())
	}
}

func TestWhitelistRescanRemovesRevokedKey(t *testing.T) {
	setRescanMinInterval(t, 0)
	authdir := t.TempDir()
	_, pubA := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, authdir, "a.pem", pubA)
	wl, _, err := loadWhitelistFromDir(authdir)
	if err != nil {
		t.Fatal(err)
	}

	os.Remove(filepath.Join(authdir, "a.pem"))
	wl.rescan(false)
	if wl.contains(pubA) {
		t.Fatal("removed key must be revoked after rescan")
	}
	if wl.count() != 0 {
		t.Fatalf("whitelist count = %d, want 0", wl.count())
	}
}

func TestWhitelistRescanKeepsKeysWhenDirMissing(t *testing.T) {
	setRescanMinInterval(t, 0)
	authdir := t.TempDir()
	_, pubA := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, authdir, "a.pem", pubA)
	wl, _, err := loadWhitelistFromDir(authdir)
	if err != nil {
		t.Fatal(err)
	}

	// 目录整个消失：读盘失败，白名单必须保留现状（不能把已授权客户端全拒了）
	os.RemoveAll(authdir)
	wl.rescan(false)
	if !wl.contains(pubA) {
		t.Fatal("failed rescan must keep current whitelist")
	}
}

func TestWhitelistRescanRateLimited(t *testing.T) {
	// 不改 rescanMinInterval（默认 1s）：加载后立刻重扫应被限流跳过
	authdir := t.TempDir()
	_, pubA := genTestKeyPair(t, t.TempDir())
	_, pubB := genTestKeyPair(t, t.TempDir())
	writeAuthKey(t, authdir, "a.pem", pubA)
	wl, _, err := loadWhitelistFromDir(authdir)
	if err != nil {
		t.Fatal(err)
	}

	writeAuthKey(t, authdir, "b.pem", pubB)
	wl.rescan(true)
	if wl.contains(pubB) {
		t.Fatal("rescan within min interval should be skipped")
	}

	// 把上次扫描时刻拨回限流窗口之外后再扫 → 生效
	wl.mu.Lock()
	wl.lastScan = time.Now().Add(-2 * rescanMinInterval)
	wl.mu.Unlock()
	wl.rescan(true)
	if !wl.contains(pubB) {
		t.Fatal("rescan after rate-limit window should pick up new key")
	}
}

func TestWhitelistReloadLoop(t *testing.T) {
	setRescanMinInterval(t, 0) // 与限流解耦：拾取延迟只取决于周期
	old := authdirRescanInterval
	authdirRescanInterval = 10 * time.Millisecond
	t.Cleanup(func() { authdirRescanInterval = old })

	authdir := t.TempDir()
	_, pubB := genTestKeyPair(t, t.TempDir())
	wl, _, err := loadWhitelistFromDir(authdir) // 空目录，0 个公钥
	if err != nil {
		t.Fatal(err)
	}
	stop := wl.startReloadLoop()
	t.Cleanup(stop) // 先停循环再恢复全局参数，避免竞争

	// 周期重扫应自动拾取新放进来的公钥
	writeAuthKey(t, authdir, "b.pem", pubB)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if wl.contains(pubB) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("reload loop did not pick up new key within 2s")
}

func TestLoadWhitelistAuthdirIsFile(t *testing.T) {
	// authdir 路径是个普通文件（配置错误）：非 IsNotExist 错误应上抛
	f := filepath.Join(t.TempDir(), "not-a-dir")
	os.WriteFile(f, []byte("x"), 0o600)
	_, _, err := loadWhitelistFromDir(f)
	if err == nil {
		t.Fatal("authdir pointing at a file should error")
	}
}

func TestSameKeySet(t *testing.T) {
	_, a := genTestKeyPair(t, t.TempDir())
	_, b := genTestKeyPair(t, t.TempDir())
	ma := map[string]ed25519.PublicKey{string(a): a}
	mb := map[string]ed25519.PublicKey{string(a): a}
	mc := map[string]ed25519.PublicKey{string(b): b}
	md := map[string]ed25519.PublicKey{string(a): a, string(b): b}
	if !sameKeySet(ma, mb) {
		t.Error("identical sets should match")
	}
	if sameKeySet(ma, mc) || sameKeySet(ma, md) {
		t.Error("different sets should not match")
	}
}
