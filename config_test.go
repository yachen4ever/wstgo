package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wstgo.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerConfig(t *testing.T) {
	path := writeTempConfig(t, `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/etc/wstgo/auth-keys"

[server.ssh1]
target = "127.0.0.1:22"
type = "ssh"

[server.pg1]
target = "127.0.0.1:5432"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.General.RunMode != "server" || cfg.General.Bind != "127.0.0.1:8888" || cfg.General.AuthDir != "/etc/wstgo/auth-keys" {
		t.Fatalf("general section mismatch: %+v", cfg.General)
	}
	if len(cfg.Server) != 2 {
		t.Fatalf("want 2 server forwards, got %d", len(cfg.Server))
	}
	if f := cfg.Server["ssh1"]; f.Target != "127.0.0.1:22" || f.Type != "ssh" {
		t.Fatalf("ssh1 mismatch: %+v", f)
	}
	if f := cfg.Server["pg1"]; f.Target != "127.0.0.1:5432" || f.Type != "" {
		t.Fatalf("pg1 should have empty type: %+v", f)
	}
}

func TestLoadClientConfig(t *testing.T) {
	path := writeTempConfig(t, `
[general]
run_mode = "client"
url = "wss://tunnel.example.com/ws"
key = "/etc/wstgo/client/private.pem"
allow_insecure = false
cacert = "/etc/wstgo/ca-root.crt"

[client.ssh1]
bind = "127.0.0.1:50022"
type = "ssh"

[client.pg1]
bind = "127.0.0.1:55432"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.General.RunMode != "client" || cfg.General.URL != "wss://tunnel.example.com/ws" ||
		cfg.General.Key != "/etc/wstgo/client/private.pem" || cfg.General.AllowInsecure {
		t.Fatalf("general section mismatch: %+v", cfg.General)
	}
	if cfg.General.Cacert != "/etc/wstgo/ca-root.crt" {
		t.Fatalf("cacert should parse: %+v", cfg.General)
	}
	if len(cfg.Client) != 2 {
		t.Fatalf("want 2 client forwards, got %d", len(cfg.Client))
	}
	if f := cfg.Client["ssh1"]; f.Bind != "127.0.0.1:50022" || f.Type != "ssh" {
		t.Fatalf("ssh1 mismatch: %+v", f)
	}
	if f := cfg.Client["pg1"]; f.Bind != "127.0.0.1:55432" || f.Type != "" {
		t.Fatalf("pg1 should have empty type: %+v", f)
	}
}

func TestInvalidServerConfigs(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name: "missing bind",
			toml: `
[general]
run_mode = "server"
auth_dir = "/tmp/k"
[server.ssh1]
target = "127.0.0.1:22"
`,
			wantErr: "bind is required",
		},
		{
			name: "missing auth_dir",
			toml: `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
[server.ssh1]
target = "127.0.0.1:22"
`,
			wantErr: "auth_dir is required",
		},
		{
			name: "no forwards",
			toml: `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"
`,
			wantErr: "at least one [server.<label>]",
		},
		{
			name: "missing target",
			toml: `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"
[server.ssh1]
type = "ssh"
`,
			wantErr: "target is required",
		},
		{
			name: "unknown type",
			toml: `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"
[server.ssh1]
target = "127.0.0.1:22"
type = "http"
`,
			wantErr: "unknown type",
		},
		{
			name: "invalid label (space)",
			toml: `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"
[server."pg 1"]
target = "127.0.0.1:5432"
`,
			wantErr: "invalid characters",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeTempConfig(t, tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestInvalidClientConfigs(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name: "missing url",
			toml: `
[general]
run_mode = "client"
key = "/tmp/private.pem"
[client.ssh1]
bind = "127.0.0.1:50022"
`,
			wantErr: "url is required",
		},
		{
			name: "bad url scheme",
			toml: `
[general]
run_mode = "client"
url = "https://tunnel.example.com/ws"
key = "/tmp/private.pem"
[client.ssh1]
bind = "127.0.0.1:50022"
`,
			wantErr: `must start with "ws://" or "wss://"`,
		},
		{
			name: "missing key",
			toml: `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws"
[client.ssh1]
bind = "127.0.0.1:50022"
`,
			wantErr: "key is required",
		},
		{
			name: "no forwards",
			toml: `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws"
key = "/tmp/private.pem"
`,
			wantErr: "at least one [client.<label>]",
		},
		{
			name: "missing bind",
			toml: `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws"
key = "/tmp/private.pem"
[client.ssh1]
type = "ssh"
`,
			wantErr: "bind is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeTempConfig(t, tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestInvalidRunMode(t *testing.T) {
	_, err := loadConfig(writeTempConfig(t, `
[general]
run_mode = "proxy"
`))
	if err == nil || !strings.Contains(err.Error(), `must be "server" or "client"`) {
		t.Fatalf("want run_mode error, got %v", err)
	}
}

func TestMismatchedSectionsIgnored(t *testing.T) {
	// server 模式带 [client] 段：加载成功，各段内容原样保留（由运行方忽略）
	path := writeTempConfig(t, `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"

[server.ssh1]
target = "127.0.0.1:22"

[client.ssh1]
bind = "127.0.0.1:50022"
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("server mode with [client] section should load: %v", err)
	}
	if len(cfg.Server) != 1 || len(cfg.Client) != 1 {
		t.Fatalf("sections should both be parsed, got server=%d client=%d", len(cfg.Server), len(cfg.Client))
	}
}

func TestValidLabel(t *testing.T) {
	for _, name := range []string{"a", "ssh1", "pg-db_2", "A9", "-_-"} {
		if err := validLabel(name); err != nil {
			t.Errorf("validLabel(%q) should pass, got %v", name, err)
		}
	}
	for _, name := range []string{"", "pg 1", "pg/1", "标签", "a.b", "a+b", "a:b"} {
		if err := validLabel(name); err == nil {
			t.Errorf("validLabel(%q) should fail", name)
		}
	}
}

func TestValidType(t *testing.T) {
	for _, typ := range []string{"", "ssh", "db"} {
		if err := validType(typ); err != nil {
			t.Errorf("validType(%q) should pass, got %v", typ, err)
		}
	}
	for _, typ := range []string{"http", "SSH", "ss h"} {
		if err := validType(typ); err == nil {
			t.Errorf("validType(%q) should fail", typ)
		}
	}
}

func TestTypeNameAndSuffixHelpers(t *testing.T) {
	if got := typeNameOrGeneric(""); got != "generic" {
		t.Errorf("typeNameOrGeneric(\"\") = %q, want generic", got)
	}
	if got := typeNameOrGeneric("db"); got != "db" {
		t.Errorf("typeNameOrGeneric(\"db\") = %q, want db", got)
	}
	if got := labelSuffix(""); got != "" {
		t.Errorf("labelSuffix(\"\") = %q, want empty", got)
	}
	if got := labelSuffix("pg1"); got != " [pg1]" {
		t.Errorf("labelSuffix(\"pg1\") = %q, want \" [pg1]\"", got)
	}
}

func TestRunArgs(t *testing.T) {
	cases := []struct {
		subCmd string
		rest   []string
		want   []string
	}{
		{"run", []string{"-config", "f.toml"}, []string{"-config", "f.toml"}},
		{"run", []string{"-config", "f.toml", "-v"}, []string{"-config", "f.toml", "-v"}},
		{"-config", []string{"f.toml"}, []string{"-config", "f.toml"}},
		{"--config", []string{"f.toml"}, []string{"--config", "f.toml"}},
		{"run", nil, nil},
		{"-config", nil, []string{"-config"}},
	}
	for _, tc := range cases {
		got := runArgs(tc.subCmd, tc.rest)
		if len(got) != len(tc.want) {
			t.Fatalf("runArgs(%q, %v) = %v, want %v", tc.subCmd, tc.rest, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("runArgs(%q, %v) = %v, want %v", tc.subCmd, tc.rest, got, tc.want)
			}
		}
	}
}

func TestURLQueryRejected(t *testing.T) {
	// query 串会让标签拼进 query 必然 404，配置校验直接拒绝
	_, err := loadConfig(writeTempConfig(t, `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws?x=1"
key = "/tmp/private.pem"
[client.ssh1]
bind = "127.0.0.1:50022"
`))
	if err == nil || !strings.Contains(err.Error(), "query string or fragment") {
		t.Fatalf("url with query should be rejected, got %v", err)
	}

	_, err = loadConfig(writeTempConfig(t, `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws#x"
key = "/tmp/private.pem"
[client.ssh1]
bind = "127.0.0.1:50022"
`))
	if err == nil || !strings.Contains(err.Error(), "query string or fragment") {
		t.Fatalf("url with fragment should be rejected, got %v", err)
	}
}

func TestCrossModeFieldWarnings(t *testing.T) {
	// server 模式混入 client 专属字段 / client 模式混入 server 专属字段：
	// 加载成功（告警忽略），不报错
	cfg, err := loadConfig(writeTempConfig(t, `
[general]
run_mode = "server"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/k"
url = "ws://should-be-ignored"
key = "/tmp/also-ignored"
[server.ssh1]
target = "127.0.0.1:22"
`))
	if err != nil {
		t.Fatalf("cross-mode fields should only warn: %v", err)
	}
	if cfg.General.RunMode != "server" {
		t.Fatal("run_mode mismatch")
	}

	cfg, err = loadConfig(writeTempConfig(t, `
[general]
run_mode = "client"
url = "ws://tunnel.example.com/ws"
key = "/tmp/private.pem"
bind = "127.0.0.1:8888"
auth_dir = "/tmp/also-ignored"
[client.ssh1]
bind = "127.0.0.1:50022"
`))
	if err != nil {
		t.Fatalf("cross-mode fields should only warn: %v", err)
	}
	if cfg.General.RunMode != "client" {
		t.Fatal("run_mode mismatch")
	}
}
