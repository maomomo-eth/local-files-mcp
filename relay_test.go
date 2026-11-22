package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/relay"
	"github.com/xtaci/smux"
)

func mockRelay(t *testing.T, listener net.Listener, password string) <-chan *smux.Session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sessions := make(chan *smux.Session, 8)
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var request relay.Request
				if _, err := request.ReadFrom(conn); err != nil {
					return
				}
				authorized := false
				for _, f := range request.Features {
					if auth, ok := f.(*relay.UserAuthFeature); ok && auth.Username == "test-user" && auth.Password == password {
						authorized = true
					}
				}
				response := relay.Response{Version: relay.Version1, Status: relay.StatusOK}
				if !authorized {
					response.Status = relay.StatusUnauthorized
				} else if request.Cmd != relay.CmdBind {
					response.Status = relay.StatusBadRequest
				}
				if _, err := response.WriteTo(conn); err != nil || response.Status != relay.StatusOK {
					return
				}
				conn.SetDeadline(time.Time{})
				config := smux.DefaultConfig()
				config.Version = 1
				session, err := smux.Client(conn, config)
				if err != nil {
					return
				}
				defer session.Close()
				select {
				case sessions <- session:
				case <-ctx.Done():
					return
				}
				select {
				case <-ctx.Done():
				case <-session.CloseChan():
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); listener.Close(); workers.Wait() })
	return sessions
}

func relayTestSession(t *testing.T, sessions <-chan *smux.Session) *smux.Session {
	t.Helper()
	select {
	case session := <-sessions:
		return session
	case <-time.After(5 * time.Second):
		t.Fatal("未在期限内建立 relay 会话")
		return nil
	}
}

func TestRelayReconnectAndConcurrentHTTP(t *testing.T) {
	p, _ := testProject(t)
	local := httptest.NewServer(newHandler(p, "", nil, ""))
	defer local.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	password := rand.Text()
	sessions := mockRelay(t, listener, password)
	cfg := &relayConfig{server: listener.Addr().String(), bind: "127.0.0.1:18765", auth: &gostAuth{"test-user", password}, muxVersion: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runRelay(ctx, cfg, strings.TrimPrefix(local.URL, "http://")) }()
	t.Cleanup(func() { cancel(); <-done })
	for cycle := 0; cycle < 2; cycle++ {
		session := relayTestSession(t, sessions)
		transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			stream, err := session.OpenStream()
			if err != nil {
				return nil, err
			}
			response := relay.Response{Version: relay.Version1, Status: relay.StatusOK}
			_, err = response.WriteTo(stream)
			return stream, err
		}}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		var requests sync.WaitGroup
		for i := 0; i < 12; i++ {
			requests.Go(func() {
				response, err := client.Get("http://localhost/healthz")
				if err != nil {
					t.Error("relay 并行 HTTP 转发失败")
					return
				}
				defer response.Body.Close()
				if response.StatusCode != 200 {
					t.Error("relay 转发应保留健康检查响应")
				}
			})
		}
		requests.Wait()
		transport.CloseIdleConnections()
		session.Close()
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("退出应停止 relay 会话和重连等待")
	}
}

func TestRelayAuthAndTLS(t *testing.T) {
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificate.TLS.Clone()
	trusted := x509.NewCertPool()
	trusted.AddCert(certificate.Certificate())
	certificate.Close()
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	password := rand.Text()
	sessions := mockRelay(t, tls.NewListener(plain, serverTLS), password)
	cfg := &relayConfig{server: plain.Addr().String(), bind: "127.0.0.1:18765", auth: &gostAuth{"test-user", password}, muxVersion: 1,
		tls: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"}}
	if session, err := openRelaySession(context.Background(), cfg); err == nil {
		session.Close()
		t.Fatal("不受信任的 TLS 证书应被拒绝")
	}
	cfg.tls.RootCAs = trusted
	cfg.auth = &gostAuth{"test-user", rand.Text()}
	if session, err := openRelaySession(context.Background(), cfg); err == nil {
		session.Close()
		t.Fatal("错误 relay 口令应被拒绝")
	} else if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), cfg.server) {
		t.Fatal("连接错误不能包含凭据或部署地址")
	}
	cfg.auth = &gostAuth{"test-user", password}
	session, err := openRelaySession(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	session.Close()
	relayTestSession(t, sessions).Close()
}

func TestRelayCancelHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := openRelaySession(ctx, &relayConfig{server: listener.Addr().String(), bind: "127.0.0.1:18765", muxVersion: 1})
		done <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("未连接模拟 relay")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消握手应失败")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("取消必须中断阻塞的握手")
	}
}

func unusedTestAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func TestRelayGostV3Integration(t *testing.T) {
	binary := os.Getenv("LOCAL_FILES_MCP_TEST_GOST")
	if binary == "" {
		t.Skip("通过 LOCAL_FILES_MCP_TEST_GOST 指定 gost v3 程序以运行互通测试")
	}
	password := rand.Text()
	relayAddr, proxyAddr, bind := unusedTestAddr(t), unusedTestAddr(t), unusedTestAddr(t)
	service := func(name, kind, addr string) map[string]any {
		handler := map[string]any{"type": kind, "auth": gostAuth{"test-user", password}}
		if kind == "relay" {
			handler["metadata"] = map[string]bool{"bind": true}
		}
		return map[string]any{"name": name, "addr": addr, "handler": handler, "listener": map[string]string{"type": "tcp"}}
	}
	data, err := json.Marshal(map[string]any{"services": []any{service("relay", "relay", relayAddr), service("proxy", "socks5", proxyAddr)}})
	if err != nil {
		t.Fatal("无法生成合成服务配置")
	}
	configPath := filepath.Join(t.TempDir(), "gost-test.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-C", configPath)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("无法启动指定的 gost v3 测试程序")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", relayAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("合成 gost 服务未能就绪")
		}
		time.Sleep(50 * time.Millisecond)
	}
	p, _ := testProject(t)
	token := rand.Text()
	local := httptest.NewServer(newHandler(p, token, nil, ""))
	defer local.Close()
	target := strings.TrimPrefix(local.URL, "http://")
	cfg, err := parseGostConfig(gostTestConfig(t, relayAddr, bind, target, proxyAddr, password), target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runRelay(ctx, cfg, target) }()
	t.Cleanup(func() { cancel(); <-done })
	client := &http.Client{Timeout: 2 * time.Second}
	deadline = time.Now().Add(8 * time.Second)
	for {
		request, _ := http.NewRequest("GET", "http://"+bind+"/healthz", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("SOCKS5 → relay → MCP 的 gost v3 互通失败")
		}
		time.Sleep(100 * time.Millisecond)
	}
	response, err := client.Get("http://" + bind + "/healthz")
	if err != nil {
		t.Fatal("无法验证隧道后的认证")
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("隧道不能绕过 MCP 认证")
	}
	request, _ := http.NewRequest("POST", "http://"+bind+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2025-03-26")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal("无法通过真实 gost v3 调用 MCP")
	}
	defer response.Body.Close()
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || response.StatusCode != 200 || len(result.Result.Tools) != 8 {
		t.Fatal("真实 gost v3 隧道应完整转发 MCP 工具发现")
	}
}
