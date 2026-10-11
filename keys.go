package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// keyFileName 是 genkey 默认生成的文件名。
const (
	privKeyFile = "private.pem"
	pubKeyFile  = "public.pem"
)

// generateKeyPair 生成一对 ed25519 密钥，并以 PEM 格式写入 dir。
// 返回私钥/公钥文件路径。目录下已存在密钥文件时拒绝执行——误对在用目录
// 跑 genkey 会不可逆地销毁服务端白名单仍在引用的旧密钥。
func generateKeyPair(dir string) (privPath, pubPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create key dir: %w", err)
	}
	privPath = filepath.Join(dir, privKeyFile)
	pubPath = filepath.Join(dir, pubKeyFile)
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists; refusing to overwrite (delete it first or use another -dir)", p)
		} else if !os.IsNotExist(err) {
			return "", "", fmt.Errorf("stat %s: %w", p, err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}

	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0o600); err != nil {
		return "", "", err
	}
	if err := writePEM(pubPath, "PUBLIC KEY", pubDER, 0o644); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

// loadPrivateKey 从 PEM 文件加载 ed25519 私钥。
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in private key file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an ed25519 private key")
	}
	return ed, nil
}

// loadPublicKey 从 PEM 文件加载 ed25519 公钥。
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in public key file")
	}
	if strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("%q is a PRIVATE key, not a public key (authdir only holds client public keys)", filepath.Base(path))
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ed, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 public key")
	}
	return ed, nil
}

// publicKeyFingerprint 返回公钥的简短指纹，用于日志/审计。
// 形如: ed25519:A1B2C3D4 (公钥前 4 字节的 hex)。
func publicKeyFingerprint(pub ed25519.PublicKey) string {
	if len(pub) < 4 {
		return "ed25519:?"
	}
	return fmt.Sprintf("ed25519:%02X%02X%02X%02X", pub[0], pub[1], pub[2], pub[3])
}

// 白名单热加载：启动加载一次之后，服务端还有两个重扫 authdir 的时机——
//  1. 有连接声明了白名单外的公钥时立即重扫（受 rescanMinInterval 限流，
//     防止未知公钥轰炸触发高频扫描）：新授权客户端的 public.pem 放进
//     authdir 即对下一条连接生效，无需重启；
//  2. 每 authdirRescanInterval 周期重扫一次：公钥的移除/吊销对新建连接生效。
//
// 重扫只有读盘成功才整体替换白名单；读盘失败（目录消失、权限变化等）
// 保留现有白名单并记日志，瞬时 IO 故障不会把已授权客户端全部拒之门外。
var (
	authdirRescanInterval = 30 * time.Second
	rescanMinInterval     = 1 * time.Second
)

// publicKeyWhitelist 是服务端持有的公钥白名单。
// 加载自一个目录下的公钥文件（文件名不限），每文件一个 SPKI PEM 公钥，
// 支持运行期热加载（见 rescan / startReloadLoop）。
type publicKeyWhitelist struct {
	mu       sync.RWMutex
	dir      string
	keys     map[string]ed25519.PublicKey // key = string(pub)
	lastScan time.Time                    // 上次扫描时刻，mu 写锁保护
	scanMu   sync.Mutex                   // 串行化重扫，防并发重复读盘
}

// errAuthDirMissing 标记 authdir 目录不存在。首次加载时视为空白名单
// （随后因 0 个公钥拒绝启动）；运行期重扫时视为读盘失败，保留现状。
var errAuthDirMissing = errors.New("authdir does not exist")

// loadWhitelistFromDir 首次加载 dir 下的全部公钥。
// 目录不存在返回空白名单（不报错）；一个公钥都没加载到时由调用方拒绝启动。
func loadWhitelistFromDir(dir string) (*publicKeyWhitelist, int, error) {
	keys, n, err := readAuthDir(dir, true)
	if err != nil && !errors.Is(err, errAuthDirMissing) {
		return nil, 0, err
	}
	if keys == nil {
		keys = make(map[string]ed25519.PublicKey)
	}
	return &publicKeyWhitelist{dir: dir, keys: keys, lastScan: time.Now()}, n, nil
}

// readAuthDir 扫描 dir 下所有普通文件，尝试解析为 ed25519 公钥。
// 文件名不限（.pem 只是惯例）：解析失败的文件在 logSkips 时告警跳过。
// 返回去重后的公钥集合与数量；目录不存在时返回 errAuthDirMissing。
func readAuthDir(dir string, logSkips bool) (map[string]ed25519.PublicKey, int, error) {
	keys := make(map[string]ed25519.PublicKey)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("%w: %s", errAuthDirMissing, dir)
		}
		return nil, 0, fmt.Errorf("read authdir: %w", err)
	}
	var seen []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seen = append(seen, e.Name())
		pub, err := loadPublicKey(filepath.Join(dir, e.Name()))
		if err != nil {
			if logSkips {
				log.Printf("authdir: skipping %s: %v", e.Name(), err)
			}
			continue
		}
		keys[string(pub)] = pub
	}
	if logSkips && len(keys) == 0 && len(seen) > 0 {
		log.Printf("authdir: none of %d file(s) is a valid ed25519 public key: %s",
			len(seen), strings.Join(seen, ", "))
	}
	return keys, len(keys), nil
}

// rescan 重扫 authdir 并整体替换白名单。距上次扫描不足 rescanMinInterval
// 时直接跳过（限流）；读盘失败保留现状。logSkips 控制是否为解析失败的
// 文件打日志——周期重扫传 false，避免垃圾文件每 30 秒刷一遍告警。
func (w *publicKeyWhitelist) rescan(logSkips bool) {
	w.scanMu.Lock()
	defer w.scanMu.Unlock()

	w.mu.RLock()
	due := time.Since(w.lastScan) >= rescanMinInterval
	w.mu.RUnlock()
	if !due {
		return
	}

	keys, n, err := readAuthDir(w.dir, logSkips)
	w.mu.Lock()
	w.lastScan = time.Now()
	changed := err == nil && !sameKeySet(keys, w.keys)
	if err == nil {
		w.keys = keys
	}
	w.mu.Unlock()
	if err != nil {
		log.Printf("authdir rescan failed, keeping current whitelist (%d key(s)): %v", w.count(), err)
		return
	}
	if changed {
		log.Printf("authdir reloaded: %d authorized public key(s) [%s]", n, w.dir)
	}
}

// sameKeySet 判断两组公钥集合是否完全一致（数量与每个成员）。
func sameKeySet(a, b map[string]ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// startReloadLoop 启动周期重扫，使公钥的移除/替换对新建连接生效。
// 返回 stop 函数：调用后阻塞到循环协程完全退出（测试依赖这一点避免
// 与全局重扫参数的恢复产生数据竞争）。服务端常驻场景忽略返回值即可。
func (w *publicKeyWhitelist) startReloadLoop() (stop func()) {
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(authdirRescanInterval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				w.rescan(false)
			}
		}
	}()
	return func() {
		close(stopCh)
		<-done
	}
}

// contains 返回公钥是否在白名单中。
func (w *publicKeyWhitelist) contains(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.keys[string(pub)]
	return ok
}

// count 返回白名单中公钥数量。
func (w *publicKeyWhitelist) count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.keys)
}
