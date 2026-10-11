package main

import (
	"context"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// 传输参数。用 atomic 是因为测试会注入更短值，而连接协程与测试清理之间
// 没有同步点——普通全局变量会被 race detector 判定为数据竞争。
var (
	heartbeatInterval atomic.Int64 // client 发 Ping 的间隔（默认 10s）
	readTimeout       atomic.Int64 // 任意方向无消息即断开（默认 30s）；DB 场景宁可快速失败让应用重连
	writeWait         atomic.Int64 // 单次 WS 写（数据/控制帧）的超时（默认 10s），防慢消费对端把数据写无限期阻塞
	targetDialTimeout atomic.Int64 // 拨号 -target 的超时（默认 5s）；net.Dial 默认无超时，会挂到 OS 级 TCP 超时
)

const (
	defaultHeartbeatInterval = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteWait         = 10 * time.Second
	defaultTargetDialTimeout = 5 * time.Second
)

func init() {
	heartbeatInterval.Store(int64(defaultHeartbeatInterval))
	readTimeout.Store(int64(defaultReadTimeout))
	writeWait.Store(int64(defaultWriteWait))
	targetDialTimeout.Store(int64(defaultTargetDialTimeout))
}

const (
	// ioBufSize 同时用作 TCP 读缓冲和 WS 单帧上限：大结果集/COPY 场景下
	// 32KB 相比 1KB 显著减少 WS 帧头开销和系统调用次数。
	ioBufSize = 32 * 1024
	// maxMessageSize 须大于对端单帧上限（ioBufSize），防止未鉴权对端
	// 发送超大帧触发无界内存分配。调整 ioBufSize 时需同步调整。
	maxMessageSize = 64 * 1024
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  ioBufSize,
	WriteBufferSize: ioBufSize,
	// 隧道服务端不校验 Origin：鉴权由 ed25519 握手承担。
	CheckOrigin: func(r *http.Request) bool { return true },
}

// verbose 控制是否打印每个字节方向的流量日志（C→S/S→C、L→R/R→L）。
// 默认 false：只打隧道建立/断开、鉴权、错误等运维必要事件。
// 由 -v 命令行开关打开。
var verbose bool

// Server 是 wstgo 服务端（CLI 单目标模式）。
type Server struct {
	DestAddress string
	Whitelist   *publicKeyWhitelist
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade from %s: %v", r.RemoteAddr, err)
		return
	}
	serveTunnel(ws, s.Whitelist, s.DestAddress, "", r.RemoteAddr)
}

// serveTunnel 在已升级的 WS 连接上完成鉴权、拨号目标并桥接，任一步失败
// 即关闭连接。label 为配置文件模式下的转发标签（CLI 模式为空），仅用于日志。
func serveTunnel(ws *websocket.Conn, wl *publicKeyWhitelist, target, label, remoteAddr string) {
	defer ws.Close()
	// 鉴权握手前即生效：握手消息最长 97 字节，64KB 上限只拦异常大帧
	ws.SetReadLimit(maxMessageSize)

	// 1. 鉴权握手
	pub, err := serverHandshake(ws, wl)
	if err != nil {
		fp := "unknown"
		if pub != nil {
			fp = publicKeyFingerprint(pub)
		}
		var ae *authError
		if errors.As(err, &ae) {
			log.Printf("auth failed from %s (%s): %s", remoteAddr, fp, ae.reason)
			sendAuthFail(ws, ae.reason)
		} else {
			log.Printf("auth error from %s (%s): %v", remoteAddr, fp, err)
		}
		return
	}
	log.Printf("tunnel established: %s <-> %s%s (client=%s)",
		remoteAddr, target, labelSuffix(label), publicKeyFingerprint(pub))

	// 2. 心跳与拨号：先装心跳再拨目标——拨号期间（最长 5s）WS 也受读
	// 超时保护，消除握手后到桥接启动之间的 deadline 空窗。
	installHeartbeat(ws)

	// 3. 拨号目标 TCP
	tcp, err := (&net.Dialer{Timeout: time.Duration(targetDialTimeout.Load())}).Dial("tcp", target)
	if err != nil {
		log.Printf("dial target %s: %v", target, err)
		// 带原因关闭，客户端能区分"目标不可达"与网络故障
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "target unreachable"),
			time.Now().Add(time.Duration(writeWait.Load())))
		return
	}
	defer tcp.Close()

	// 4. 双向桥接
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge(ws, tcp, ctx, cancel, true, labelSuffix(label))
	log.Printf("tunnel closed: %s <-> %s%s (client=%s)",
		remoteAddr, target, labelSuffix(label), publicKeyFingerprint(pub))
}

// runServerConfig 以配置文件模式启动服务端：每个 [server.<label>] 转发
// 注册在 /ws/<label> 路径下，鉴权白名单全局共享。
func runServerConfig(cfg *Config) {
	wl, n, err := loadWhitelistFromDir(cfg.General.AuthDir)
	if err != nil {
		log.Fatalf("load authdir %s: %v", cfg.General.AuthDir, err)
	}
	if n == 0 {
		log.Fatalf("no authorized client public keys in %s; refusing to start without authentication\n"+
			"  fix: run `wstgo genkey` on each CLIENT, then copy its public.pem into this dir (any filename works)", cfg.General.AuthDir)
	}
	log.Printf("loaded %d authorized public key(s) from %s", n, cfg.General.AuthDir)
	wl.startReloadLoop()

	mux := buildServerMux(wl, cfg.Server)

	log.Printf("wstgo server listening on %s, %d forward(s):", cfg.General.Bind, len(cfg.Server))
	for _, name := range slices.Sorted(maps.Keys(cfg.Server)) {
		f := cfg.Server[name]
		log.Printf("  /ws/%s -> %s (type=%s)", name, f.Target, typeNameOrGeneric(f.Type))
	}
	// 同 server()：显式超时防 slowloris；hijack 后 deadline 归 wstgo 管
	srv := &http.Server{
		Addr:              cfg.General.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// buildServerMux 构建配置模式服务端路由：/ws/<label> 升级为 WS 并转发到
// 对应 target；裸 /ws 与未知标签显式 404。
func buildServerMux(wl *publicKeyWhitelist, forwards map[string]ServerForward) *http.ServeMux {
	mux := http.NewServeMux()
	// 裸 /ws 在配置模式下没有对应转发，显式 404（避免 ServeMux 307 重定向）。
	// 客户端连 <url>/<label>，漏掉标签时会在这里得到明确提示。
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request to /ws without forward label from %s (expected /ws/<label>)", r.RemoteAddr)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/ws/")
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		fwd, ok := forwards[name]
		if !ok {
			log.Printf("unknown forward %q requested from %s", name, r.RemoteAddr)
			http.NotFound(w, r)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("upgrade from %s: %v", r.RemoteAddr, err)
			return
		}
		serveTunnel(ws, wl, fwd.Target, name, r.RemoteAddr)
	})
	return mux
}

// installHeartbeat 为 WS 连接安装心跳处理：
//   - 设置初始读超时
//   - 收到 Ping 自动回 Pong 并续约
//   - 收到 Pong 续约
//   - 数据模式期间任何 ReadMessage 出错即退出
func installHeartbeat(ws *websocket.Conn) {
	_ = ws.SetReadDeadline(time.Now().Add(time.Duration(readTimeout.Load())))
	ws.SetPingHandler(func(appData string) error {
		_ = ws.SetReadDeadline(time.Now().Add(time.Duration(readTimeout.Load())))
		return ws.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Duration(writeWait.Load())))
	})
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(time.Duration(readTimeout.Load())))
		return nil
	})
}

// bridge 在 WS 与 TCP 之间双向转发数据。鉴权已完成，所有 BinaryMessage
// 的 payload 即 TCP 字节。serverSide 决定日志方向（C→S/S→C 或 L→R/R→L）
// 与 TCP 读错误的静默策略——client 侧本地断开属正常行为，静默。
// 服务端与客户端共用这一份实现（此前各自维护，退出语义已经漂移过一次）。
//
// 生命周期不变量：任何一条退出路径都必须同时关闭 ws 与 tcp 并 cancel。
// 单纯 cancel 唤不醒阻塞中的 ReadMessage/tcp.Read，而心跳会持续续约读超时，
// 所以单侧关闭若不显式通知对端，整条隧道（含 server 端的 target 连接）
// 会被永久焊住。关 tcp 唤醒对端方向的 tcp.Read，关 ws 唤醒本端的
// ReadMessage 并让对端立即感知断开。
func bridge(ws *websocket.Conn, tcp net.Conn, ctx context.Context, cancel context.CancelFunc, serverSide bool, tag string) {
	defer cancel()

	dir1, dir2 := "C\u2192S", "S\u2192C" // TCP→WS / WS→TCP 方向的日志前缀
	logTCPErr := serverSide
	if !serverSide {
		dir1, dir2 = "L\u2192R", "R\u2192L"
		logTCPErr = false
	}

	teardown := func() {
		cancel()
		tcp.Close()
		ws.Close()
	}

	// 协程: TCP -> WS
	go func() {
		buf := make([]byte, ioBufSize)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				// 数据写限时：对端停止消费时 TCP 窗口填满、写会无限期阻塞，
				// 而心跳只证明传输层活着，不证明数据通路在排空。
				_ = ws.SetWriteDeadline(time.Now().Add(time.Duration(writeWait.Load())))
				werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				if werr != nil {
					log.Printf("%s%s write err: %v", dir1, tag, werr)
					teardown()
					return
				}
				if verbose {
					log.Printf("%s%s %d", dir1, tag, n)
				}
			}
			if err != nil {
				if logTCPErr && err != io.EOF {
					log.Printf("%s%s read err: %v", dir1, tag, err)
				}
				teardown()
				return
			}
		}
	}()

	// 主协程: WS -> TCP
	for {
		select {
		case <-ctx.Done():
			teardown()
			return
		default:
		}
		msgType, buf, err := ws.ReadMessage()
		if err != nil {
			if serverSide || !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("%s%s read err: %v", dir2, tag, err)
			}
			teardown()
			return
		}
		if msgType != websocket.BinaryMessage {
			// 协议约定数据帧一律 Binary：非二进制帧按协议违例拆除
			log.Printf("%s%s non-binary data frame, closing", dir2, tag)
			teardown()
			return
		}
		// TCP 写同样限时（对端 app 停止消费会填满接收窗口），上限与
		// 读超时同源：任何方向停滞超过 30s 即视为死链。
		_ = tcp.SetWriteDeadline(time.Now().Add(time.Duration(readTimeout.Load())))
		if _, err := tcp.Write(buf); err != nil {
			log.Printf("%s%s write err: %v", dir2, tag, err)
			teardown()
			return
		}
		if verbose {
			log.Printf("%s%s %d", dir2, tag, len(buf))
		}
	}
}

// server 启动服务端。tlsCert/tlsKey 同时非空时以原生 wss 监听（TLS 由自身终结），
// 默认均为空、监听明文 ws——加密交给前置反代。
func server(bindAddr, destAddr, authDir, tlsCert, tlsKey string) {
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatal("server: -tlscert and -tlskey must be provided together to enable native wss")
	}
	wl, n, err := loadWhitelistFromDir(authDir)
	if err != nil {
		log.Fatalf("load authdir %s: %v", authDir, err)
	}
	if n == 0 {
		log.Fatalf("no authorized client public keys in %s; refusing to start without authentication\n"+
			"  fix: run `wstgo genkey` on each CLIENT, then copy its public.pem into this dir (any filename works)", authDir)
	}
	log.Printf("loaded %d authorized public key(s) from %s", n, authDir)
	wl.startReloadLoop()

	s := &Server{
		DestAddress: destAddr,
		Whitelist:   wl,
	}
	http.HandleFunc("/ws", s.handler)
	// 显式超时防未认证 slowloris 占满连接（头部超时与握手超时同源 10s）。
	// 不设 ReadTimeout/WriteTimeout：WS 升级 hijack 后 deadline 由 wstgo
	// 自己管理，http 层的 deadline 会干扰长连隧道。
	srv := &http.Server{
		Addr:              bindAddr,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if tlsCert != "" {
		log.Printf("wstgo server listening on %s (wss), forwarding to %s", bindAddr, destAddr)
		log.Fatal(srv.ListenAndServeTLS(tlsCert, tlsKey))
	}
	log.Printf("wstgo server listening on %s (ws), forwarding to %s", bindAddr, destAddr)
	log.Fatal(srv.ListenAndServe())
}
