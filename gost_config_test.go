package main

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gostTestConfig(t *testing.T, server, bind, target, proxyAddr, password string) []byte {
	t.Helper()
	node := func(kind, addr string) map[string]any {
		return map[string]any{
			"name": "test-node", "addr": addr,
			"connector": map[string]any{"type": kind, "auth": map[string]string{"username": "test-user", "password": password}},
			"dialer":    map[string]string{"type": "tcp"},
		}
	}
	hops := []any{}
	if proxyAddr != "" {
		hops = append(hops, map[string]any{"name": "proxy", "nodes": []any{node("socks5", proxyAddr)}})
	}
	hops = append(hops, map[string]any{"name": "relay", "nodes": []any{node("relay", server)}})
	source := map[string]any{
		"services": []any{map[string]any{
			"name": "mcp", "addr": bind,
			"handler":   map[string]string{"type": "rtcp"},
			"listener":  map[string]string{"type": "rtcp", "chain": "test-chain"},
			"forwarder": map[string]any{"nodes": []any{map[string]string{"name": "mcp", "addr": target}}},
		}},
		"chains": []any{map[string]any{"name": "test-chain", "hops": hops}},
	}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal("无法生成合成 gost 配置")
	}
	return data
}

func TestGostConfig(t *testing.T) {
	for _, proxyAddr := range []string{"", "127.0.0.1:1080"} {
		password := rand.Text()
		cfg, err := parseGostConfig(gostTestConfig(t, "relay.example.com:8420", "127.0.0.1:18765", "127.0.0.1:8765", proxyAddr, password), "127.0.0.1:8765")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.server != "relay.example.com:8420" || cfg.bind != "127.0.0.1:18765" || cfg.auth.Password != password || cfg.muxVersion != 1 || (cfg.proxy != nil) != (proxyAddr != "") {
			t.Fatal("解析结果与合成配置不一致")
		}
	}
}

func TestGostConfigRejectsUnsupportedAndRedactsErrors(t *testing.T) {
	password := rand.Text()
	base := gostTestConfig(t, "relay.example.com:8420", "127.0.0.1:18765", "127.0.0.1:8765", "", password)
	for _, data := range [][]byte{
		[]byte("{" + password),
		append(append([]byte{}, base...), base...),
		[]byte(strings.Replace(string(base), `"rtcp"`, `"tcp"`, 1)),
		[]byte(strings.Replace(string(base), `"relay"`, `"socks5"`, -1)),
		[]byte(strings.Replace(string(base), `"test-chain"`, `"missing-chain"`, 1)),
		[]byte(strings.Replace(string(base), `"127.0.0.1:8765"`, `"127.0.0.1:9000"`, 1)),
		[]byte(strings.Replace(string(base), `"addr":"relay.example.com:8420"`, `"addr":"`+password+`"`, 1)),
		[]byte(strings.Replace(string(base), `"services":`, `"`+password+`":`, 1)),
		[]byte(strings.Replace(string(base), `"relay.example.com:8420"`, `"relay.example.com:99999"`, 1)),
		[]byte(strings.Replace(string(base), `"dialer":{"type":"tcp"}`, `"dialer":{"type":"wss"}`, 1)),
	} {
		_, err := parseGostConfig(data, "127.0.0.1:8765")
		if err == nil {
			t.Fatal("不支持的配置应被拒绝")
		}
		if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "relay.example.com") {
			t.Fatal("配置错误不能包含原始配置值")
		}
	}
}

func TestGostConfigPrivacyBoundary(t *testing.T) {
	root, private := t.TempDir(), t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	data := gostTestConfig(t, "relay.example.com:8420", "127.0.0.1:18765", "127.0.0.1:8765", "", rand.Text())
	path := filepath.Join(private, "gost.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGostConfig(path, root, "127.0.0.1:8765"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGostConfig(path, private, "127.0.0.1:8765"); err == nil {
		t.Fatal("不能把含凭据配置放入 MCP 项目目录")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGostConfig(path, root, "127.0.0.1:8765"); err == nil {
		t.Fatal("配置权限过宽应失败")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGostConfig(path, root, "127.0.0.1:8765"); err == nil {
		t.Fatal("配置父目录权限过宽应失败")
	}
}

func TestRelayLocalTarget(t *testing.T) {
	for input, want := range map[string]string{"0.0.0.0:8765": "127.0.0.1:8765", "[::]:8765": "[::1]:8765", "127.0.0.1:8765": "127.0.0.1:8765"} {
		addr, err := net.ResolveTCPAddr("tcp", input)
		if err != nil || relayLocalTarget(addr) != want {
			t.Fatal("应将通配监听地址转换为本机连接地址")
		}
	}
}
