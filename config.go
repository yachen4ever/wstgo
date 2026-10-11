package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/BurntSushi/toml"
)

// knownForwardTypes 是合法的服务类型。当前所有类型的传输参数完全一致
// （32KB 缓冲 / 10s·30s 心跳对 ssh 与 db 均已最优），type 承担配置校验
// （typo 防护）与日志标识，并为将来按类型分化的传输参数预留挂点。
var knownForwardTypes = map[string]bool{
	"ssh": true,
	"db":  true,
}

// Config 对应 wstgo.toml 的 general/server/client 三段。
// 与 run_mode 不匹配的段落加载时告警并忽略。
type Config struct {
	General GeneralConfig
	Server  map[string]ServerForward `toml:"server"`
	Client  map[string]ClientForward `toml:"client"`
}

type GeneralConfig struct {
	RunMode       string `toml:"run_mode"`
	Bind          string `toml:"bind"`           // server: WS 监听地址 host:port
	AuthDir       string `toml:"auth_dir"`       // server: 授权公钥目录
	URL           string `toml:"url"`            // client: 服务端基础 URL，实际连接 <url>/<标签>
	Key           string `toml:"key"`            // client: 私钥路径
	AllowInsecure bool   `toml:"allow_insecure"` // client: 跳过 TLS 证书校验（自签名 wss，仅临时调试）
	Cacert        string `toml:"cacert"`         // client: CA 证书文件（PEM/DER），标准校验自签 wss 服务端；与 allow_insecure 互斥
}

type ServerForward struct {
	Target string `toml:"target"` // 目标 TCP 地址 host:port
	Type   string `toml:"type"`   // 可选：ssh / db
}

type ClientForward struct {
	Bind string `toml:"bind"` // 本地监听地址 host:port
	Type string `toml:"type"` // 可选：ssh / db，仅用于日志
}

func loadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	switch c.General.RunMode {
	case "server":
		if len(c.Client) > 0 {
			log.Printf("config: ignoring [client] section (run_mode=server)")
		}
		if c.General.URL != "" || c.General.Key != "" || c.General.AllowInsecure || c.General.Cacert != "" {
			log.Printf("config: ignoring client-only field(s) in [general]: url/key/allow_insecure/cacert")
		}
		if c.General.Bind == "" {
			return errors.New(`config: general.bind is required ("host:port")`)
		}
		if c.General.AuthDir == "" {
			return errors.New("config: general.auth_dir is required")
		}
		if len(c.Server) == 0 {
			return errors.New("config: at least one [server.<label>] forward is required")
		}
		for name, f := range c.Server {
			if err := validLabel(name); err != nil {
				return fmt.Errorf("config: [server.%s]: %w", name, err)
			}
			if f.Target == "" {
				return fmt.Errorf("config: [server.%s]: target is required", name)
			}
			if err := validType(f.Type); err != nil {
				return fmt.Errorf("config: [server.%s]: %w", name, err)
			}
		}
	case "client":
		if len(c.Server) > 0 {
			log.Printf("config: ignoring [server] section (run_mode=client)")
		}
		if c.General.Bind != "" || c.General.AuthDir != "" {
			log.Printf("config: ignoring server-only field(s) in [general]: bind/auth_dir")
		}
		if c.General.URL == "" {
			return errors.New("config: general.url is required")
		}
		if !strings.HasPrefix(c.General.URL, "ws://") && !strings.HasPrefix(c.General.URL, "wss://") {
			return errors.New(`config: general.url must start with "ws://" or "wss://"`)
		}
		// query 串会让标签拼进 query（<url>/<标签> 的拼接语义），必然 404，直接拒绝
		if strings.Contains(c.General.URL, "?") {
			return errors.New(`config: general.url must not contain a query string`)
		}
		if c.General.Key == "" {
			return errors.New("config: general.key is required")
		}
		if c.General.AllowInsecure && c.General.Cacert != "" {
			return errors.New("config: general.allow_insecure and general.cacert are mutually exclusive (pick one way to trust the server)")
		}
		if len(c.Client) == 0 {
			return errors.New("config: at least one [client.<label>] forward is required")
		}
		for name, f := range c.Client {
			if err := validLabel(name); err != nil {
				return fmt.Errorf("config: [client.%s]: %w", name, err)
			}
			if f.Bind == "" {
				return fmt.Errorf("config: [client.%s]: bind is required", name)
			}
			if err := validType(f.Type); err != nil {
				return fmt.Errorf("config: [client.%s]: %w", name, err)
			}
		}
	default:
		return fmt.Errorf(`config: general.run_mode must be "server" or "client" (got %q)`, c.General.RunMode)
	}
	return nil
}

// validLabel 校验转发标签：标签会成为 URL 路径段（/ws/<label>），只允许
// URL 安全字符。空标签同样拒绝。
func validLabel(name string) error {
	if name == "" {
		return errors.New("empty label")
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return fmt.Errorf("label %q contains invalid characters (allowed: letters, digits, '-', '_')", name)
		}
	}
	return nil
}

func validType(t string) error {
	if t == "" || knownForwardTypes[t] {
		return nil
	}
	return fmt.Errorf("unknown type %q (known: ssh, db; leave empty for generic)", t)
}

// typeNameOrGeneric 用于日志展示，空类型显示为 generic。
func typeNameOrGeneric(t string) string {
	if t == "" {
		return "generic"
	}
	return t
}

// labelSuffix 把转发标签格式化为日志后缀，如 " [pg1]"；空标签返回空串。
func labelSuffix(label string) string {
	if label == "" {
		return ""
	}
	return " [" + label + "]"
}

// runConfig 读取配置文件并按 run_mode 启动服务端或客户端。
func runConfig(path string) {
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	log.Printf("loaded config %s (run_mode=%s)", path, cfg.General.RunMode)
	if cfg.General.RunMode == "server" {
		runServerConfig(cfg)
	} else {
		runClientConfig(cfg)
	}
}
