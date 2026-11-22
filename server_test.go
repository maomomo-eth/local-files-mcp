package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func rpc(t *testing.T, handler http.Handler, method string, params any) map[string]any {
	t.Helper()
	data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-03-26")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d：%s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("响应不是 JSON：%s %v", w.Body.String(), err)
	}
	if response["error"] != nil {
		t.Fatalf("RPC 失败：%v", response["error"])
	}
	return response["result"].(map[string]any)
}

func TestMCPHTTPWorkflow(t *testing.T) {
	p, _ := testProject(t)
	handler := newHandler(p, "", []string{"https://gemini.google.com"}, "")
	for _, version := range []string{"2024-11-05", "2025-03-26", "2025-11-25"} {
		init := rpc(t, handler, "initialize", map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "test", "version": "1"}})
		if init["protocolVersion"] != version {
			t.Fatalf("协议协商失败：%v", init)
		}
	}
	listed := rpc(t, handler, "tools/list", map[string]any{})
	if len(listed["tools"].([]any)) != 8 {
		t.Fatalf("工具数量错误：%v", listed)
	}
	call := func(name string, args map[string]any) map[string]any {
		return rpc(t, handler, "tools/call", map[string]any{"name": name, "arguments": args})
	}
	created := call("write_file", map[string]any{"path": "中文.txt", "content": "你好\n"})
	if created["isError"] == true {
		t.Fatalf("新建失败：%v", created)
	}
	read := call("read_file", map[string]any{"path": "中文.txt"})
	structured := read["structuredContent"].(map[string]any)
	if structured["content"] != "你好\n" {
		t.Fatalf("读取失败：%v", read)
	}
	edited := call("edit_file", map[string]any{"path": "中文.txt", "old_text": "你好", "new_text": "再见", "expected_sha256": structured["sha256"]})
	if edited["isError"] == true {
		t.Fatalf("编辑失败：%v", edited)
	}
	denied := call("read_file", map[string]any{"path": "../secret"})
	if denied["isError"] != true {
		t.Fatalf("越界应返回工具错误：%v", denied)
	}
	search := call("search_files", map[string]any{"query": "再见"})
	if search["isError"] == true {
		t.Fatalf("搜索失败：%v", search)
	}
	version := hash([]byte("再见\n"))
	moved := call("move_file", map[string]any{"source": "中文.txt", "destination": "改名.txt", "expected_sha256": version})
	if moved["isError"] == true || moved["structuredContent"].(map[string]any)["destination"] != "改名.txt" {
		t.Fatalf("移动失败：%v", moved)
	}
	for _, args := range []map[string]any{
		{"path": "改名.txt"},
		{"path": ".git", "expected_sha256": version},
	} {
		if denied := call("delete_file", args); denied["isError"] != true {
			t.Fatalf("不安全的删除应失败：%v", denied)
		}
	}
	deleted := call("delete_file", map[string]any{"path": "改名.txt", "expected_sha256": version})
	if deleted["isError"] == true || deleted["structuredContent"].(map[string]any)["ok"] != true {
		t.Fatalf("删除失败：%v", deleted)
	}
	if missing := call("read_file", map[string]any{"path": "改名.txt"}); missing["isError"] != true {
		t.Fatal("删除后的文件不应存在")
	}
	p.readOnly = true
	readOnly := newHandler(p, "", nil, "")
	listed = rpc(t, readOnly, "tools/list", map[string]any{})
	if len(listed["tools"].([]any)) != 3 {
		t.Fatal("只读模式不能暴露写工具")
	}
}

func TestHTTPAccess(t *testing.T) {
	p, _ := testProject(t)
	handler := newHandler(p, "test-token", []string{"https://gemini.google.com"}, "")
	for _, tc := range []struct {
		origin, token string
		code          int
	}{
		{"", "", 401},
		{"", "Bearer wrong", 401},
		{"", "Bearer test-token", 200},
		{"https://gemini.google.com", "Bearer test-token", 200},
		{"https://attacker.example", "Bearer test-token", 403},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.origin, tc.code), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Authorization", tc.token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("期望 %d，实际 %d", tc.code, w.Code)
			}
		})
	}
}

func TestProxyHost(t *testing.T) {
	p, _ := testProject(t)
	for _, tc := range []struct {
		public, host string
		want         int
	}{
		{"", "attacker.example", 403},
		{"", "mcp.example.com", 403},
		{"mcp.example.com", "mcp.example.com", 200},
		{"mcp.example.com", "mcp.example.com:443", 200},
		{"mcp.example.com", "attacker.example", 403},
		{"", "127.0.0.1:8765", 200},
		{"", "[::1]:8765", 200},
	} {
		h := newHandler(p, "", nil, tc.public)
		req := httptest.NewRequest("GET", "http://localhost/healthz", nil)
		req.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("public=%s Host=%s：期望 %d，实际 %d", tc.public, tc.host, tc.want, w.Code)
		}
	}
}
