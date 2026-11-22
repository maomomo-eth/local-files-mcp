package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testIssuer = "https://mcp.example.com"
const testPassword = "test-owner-password-123456"
const testRedirect = "https://oauth-redirect.googleusercontent.com/r/test-gemini"
const testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

func TestOAuthIssuerNormalization(t *testing.T) {
	for in, want := range map[string]string{"https://MCP.EXAMPLE.COM:443/": "https://mcp.example.com", "https://[::1]:443": "https://[::1]", "https://example.com:8443": "https://example.com:8443"} {
		got, err := validateIssuer(in)
		if err != nil || got != want {
			t.Fatalf("issuer 规范化失败：%s => %s %v", in, got, err)
		}
	}
}

type oauthFixture struct {
	a                        *oauthServer
	p                        *project
	h                        http.Handler
	path                     string
	clientID, secret, method string
}

func newOAuthFixture(t *testing.T, method string) *oauthFixture {
	t.Helper()
	p, root := testProject(t)
	statePath := filepath.Join(t.TempDir(), "private", "oauth.json")
	a, err := openOAuth(testIssuer, statePath, root, false, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	f := &oauthFixture{a: a, p: p, path: statePath, method: method}
	f.h = newHandler(p, "", []string{"https://gemini.google.com"}, "mcp.example.com", a)
	reg := f.request("POST", "/oauth/register", `{"client_name":"Gemini 测试","redirect_uris":["`+testRedirect+`"],"token_endpoint_auth_method":"`+method+`"}`, "application/json", nil)
	if reg.Code != 201 {
		t.Fatalf("注册失败：%d %s", reg.Code, reg.Body.String())
	}
	var data map[string]any
	if err = json.Unmarshal(reg.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	f.clientID = data["client_id"].(string)
	f.secret, _ = data["client_secret"].(string)
	return f
}

func (f *oauthFixture) request(method, path, body, contentType string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, testIssuer+path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *oauthFixture) authQuery() url.Values {
	digest := sha256.Sum256([]byte(testVerifier))
	return url.Values{"client_id": {f.clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"}, "scope": {"mcp"}, "resource": {testIssuer + "/mcp"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "state": {"保持-state-123"}}
}

func (f *oauthFixture) loginPage(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := f.request("GET", "/oauth/authorize?"+f.authQuery().Encode(), "", "", nil)
	if w.Code != 200 {
		t.Fatalf("授权页失败：%d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("授权页必须保留同源表单的 Origin")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self';") {
		t.Fatal("密码表单应仅允许提交本站")
	}
	match := regexp.MustCompile(`name="request_id" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 || len(w.Result().Cookies()) != 1 {
		t.Fatal("授权页缺少防伪标记")
	}
	return match[1], w.Result().Cookies()[0]
}

func (f *oauthFixture) authorizeCode(t *testing.T) string {
	t.Helper()
	id, cookie := f.loginPage(t)
	form := url.Values{"request_id": {id}, "password": {testPassword}, "decision": {"allow"}}
	w := f.request("POST", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", cookie)
	if w.Code != 200 {
		t.Fatalf("授权失败：%d %s", w.Code, w.Body.String())
	}
	u := returnURL(t, w)
	if u.Host != "oauth-redirect.googleusercontent.com" || u.Query().Get("state") != "保持-state-123" || u.Query().Get("code") == "" {
		t.Fatal("授权回调错误")
	}
	return u.Query().Get("code")
}

func returnURL(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	match := regexp.MustCompile(`id="return-link" href="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatal("结果页必须包含自动跳转和手动返回入口")
	}
	u, err := url.Parse(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("结果页必须避免缓存和发送 Referer")
	}
	return u
}

func (f *oauthFixture) tokenRequest(values url.Values, path string) *httptest.ResponseRecorder {
	values.Set("client_id", f.clientID)
	if f.method == "client_secret_post" {
		values.Set("client_secret", f.secret)
	}
	r := httptest.NewRequest("POST", testIssuer+path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.method == "client_secret_basic" {
		r.SetBasicAuth(url.QueryEscape(f.clientID), url.QueryEscape(f.secret))
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *oauthFixture) exchange(t *testing.T, code string) map[string]string {
	t.Helper()
	w := f.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}, "resource": {testIssuer + "/mcp"}}, "/oauth/token")
	if w.Code != 200 {
		t.Fatalf("交换令牌失败：%d %s", w.Code, w.Body.String())
	}
	var out struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Access == "" || out.Refresh == "" {
		t.Fatal("缺少令牌")
	}
	return map[string]string{"access": out.Access, "refresh": out.Refresh}
}

func TestOAuthCompleteFlow(t *testing.T) {
	f := newOAuthFixture(t, "client_secret_post")
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		w := f.request("GET", path, "", "", nil)
		if w.Code != 200 {
			t.Fatal("发现接口不可用", path)
		}
	}
	w := f.request("POST", "/mcp", `{}`, "application/json", nil)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), testIssuer+"/.well-known/oauth-protected-resource/mcp") {
		t.Fatal("缺少 OAuth 发现挑战")
	}
	code := f.authorizeCode(t)
	tokens := f.exchange(t, code)
	if !f.a.validAccess(tokens["access"]) || f.a.validAccess(tokens["refresh"]) {
		t.Fatal("令牌类型未隔离")
	}
	// 确认不是仅发出了令牌，而是令牌真的能调用文件工具。
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"oauth.txt","content":"授权成功"}}}`
	r := httptest.NewRequest("POST", testIssuer+"/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2025-03-26")
	r.Header.Set("Authorization", "Bearer "+tokens["access"])
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "授权成功") {
		t.Fatalf("受保护 MCP 调用失败：%d %s", w.Code, w.Body.String())
	}
	if file, err := f.p.read("oauth.txt"); err != nil || file.Content != "授权成功" {
		t.Fatal("实际文件内容错误")
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{testPassword, f.secret, tokens["access"], tokens["refresh"]} {
		if strings.Contains(string(data), raw) {
			t.Fatal("私密状态不应保存密码、客户端密钥或令牌原文")
		}
	}
	w = f.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}, "/oauth/token")
	if w.Code != 400 {
		t.Fatal("授权码不能重放")
	}
	refresh := f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token")
	if refresh.Code != 200 || !strings.Contains(refresh.Body.String(), tokens["refresh"]) {
		t.Fatal("机密客户端应保留刷新令牌")
	}
	revoked := f.tokenRequest(url.Values{"token": {tokens["refresh"]}}, "/oauth/revoke")
	if revoked.Code != 200 || f.a.validAccess(tokens["access"]) {
		t.Fatal("撤销必须使关联的访问令牌失效")
	}
	if f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token").Code != 400 {
		t.Fatal("已撤销的刷新令牌仍可使用")
	}
}

func TestOAuthInvalidRequests(t *testing.T) {
	f := newOAuthFixture(t, "client_secret_post")
	for _, change := range []struct{ key, value string }{{"redirect_uri", "https://evil.example/callback"}, {"resource", "https://other.example/mcp"}, {"code_challenge_method", "plain"}, {"code_challenge", "bad"}, {"scope", "admin"}, {"client_id", "unknown"}} {
		q := f.authQuery()
		q.Set(change.key, change.value)
		if f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", nil).Code == 200 {
			t.Fatal("应拒绝授权请求", change.key)
		}
	}
	id, cookie := f.loginPage(t)
	form := url.Values{"request_id": {id}, "password": {testPassword}, "decision": {"allow"}}
	if f.request("POST", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", nil).Code != 403 {
		t.Fatal("应拒绝缺少 Cookie 的 CSRF")
	}
	form.Set("password", "wrong")
	if f.request("POST", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", cookie).Code != 403 {
		t.Fatal("应拒绝错误密码")
	}
	code := f.authorizeCode(t)
	for _, change := range []struct{ key, value string }{{"code_verifier", strings.Repeat("x", 43)}, {"redirect_uri", "https://evil.example/callback"}, {"resource", "https://other.example/mcp"}} {
		q := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}
		q.Set(change.key, change.value)
		if f.tokenRequest(q, "/oauth/token").Code != 400 {
			t.Fatal("应拒绝令牌请求", change.key)
		}
	}
	f.secret = "wrong"
	if f.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}}, "/oauth/token").Code != 401 {
		t.Fatal("应拒绝错误客户端密钥")
	}
	for _, redirect := range []string{"https://oauth-redirect.googleusercontent.com.evil.example/r/test", "https://oauth-redirect.googleusercontent.com@evil.example/r/test", "http://oauth-redirect.googleusercontent.com/r/test", "https://oauth-redirect.googleusercontent.com/evil", "https://evil.example/r/test"} {
		body, _ := json.Marshal(registrationInput{Name: "evil", Redirects: []string{redirect}})
		if f.request("POST", "/oauth/register", string(body), "application/json", nil).Code != 400 {
			t.Fatal("应拒绝回调", redirect)
		}
	}
}

func TestOAuthConsentOrigin(t *testing.T) {
	f := newOAuthFixture(t, "client_secret_post")
	id, cookie := f.loginPage(t)
	form := url.Values{"request_id": {id}, "decision": {"allow"}, "password": {testPassword}}
	for _, tc := range []struct {
		origin string
		status int
	}{{"null", 403}, {"https://attacker.example", 403}, {testIssuer, 200}} {
		r := httptest.NewRequest("POST", testIssuer+"/oauth/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tc.origin)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("Origin=%s：期望 %d，实际 %d", tc.origin, tc.status, w.Code)
		}
	}
}

func TestOAuthPersistenceExpiryAndPublicRotation(t *testing.T) {
	f := newOAuthFixture(t, "none")
	tokens := f.exchange(t, f.authorizeCode(t))
	clock := time.Now().Add(2 * time.Hour)
	f.a.now = func() time.Time { return clock }
	if f.a.validAccess(tokens["access"]) {
		t.Fatal("过期访问令牌仍有效")
	}
	w := f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token")
	if w.Code != 200 {
		t.Fatal("刷新失败", w.Body.String())
	}
	var out struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Refresh == tokens["refresh"] {
		t.Fatal("公共客户端必须轮换刷新令牌")
	}
	if f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token").Code != 400 {
		t.Fatal("旧公共刷新令牌应失效")
	}
	f.a.close()
	a, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	a.now = func() time.Time { return clock }
	if a.validAccess(out.Access) {
		t.Fatal("重启后重放撤销必须保持")
	}
	if _, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, ""); err == nil {
		t.Fatal("同一状态文件不能被多个进程使用")
	}
	clock = clock.Add(91 * 24 * time.Hour)
	if a.validAccess(out.Access) {
		t.Fatal("过期授权仍有效")
	}
}

func TestOAuthStateIsolationAndBasic(t *testing.T) {
	f := newOAuthFixture(t, "client_secret_basic")
	_ = f.exchange(t, f.authorizeCode(t))
	f.a.close()
	if _, err := openOAuth("https://other.example", f.path, f.p.root.Name(), false, ""); err == nil {
		t.Fatal("不能跨域复用授权")
	}
	if _, err := openOAuth(testIssuer, f.path, f.p.root.Name(), true, ""); err == nil {
		t.Fatal("不能跨权限复用授权")
	}
	if _, err := openOAuth(testIssuer, f.path, t.TempDir(), false, ""); err == nil {
		t.Fatal("不能跨项目复用授权")
	}
	if _, err := openOAuth(testIssuer, filepath.Join(f.p.root.Name(), "private", "oauth.json"), f.p.root.Name(), false, testPassword); err == nil {
		t.Fatal("状态不能放在项目内部")
	}
	if _, err := openOAuth("http://mcp.example.com", filepath.Join(t.TempDir(), "oauth.json"), f.p.root.Name(), false, testPassword); err == nil {
		t.Fatal("issuer 必须是 HTTPS")
	}
}

func TestOAuthCodeExpiryDenialAndSaveFailure(t *testing.T) {
	f := newOAuthFixture(t, "client_secret_post")
	id, cookie := f.loginPage(t)
	deny := url.Values{"request_id": {id}, "decision": {"deny"}}
	w := f.request("POST", "/oauth/authorize", deny.Encode(), "application/x-www-form-urlencoded", cookie)
	if w.Code != 200 || returnURL(t, w).Query().Get("error") != "access_denied" {
		t.Fatal("取消授权不应签发授权码")
	}
	code := f.authorizeCode(t)
	clock := time.Now().Add(3 * time.Minute)
	f.a.now = func() time.Time { return clock }
	w = f.tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}, "/oauth/token")
	if w.Code != 400 {
		t.Fatal("过期授权码仍可使用")
	}
	count := len(f.a.state.Clients)
	if err := os.Rename(f.path, f.path+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	w = f.request("POST", "/oauth/register", `{"redirect_uris":["`+testRedirect+`"]}`, "application/json", nil)
	if w.Code != 500 || len(f.a.state.Clients) != count {
		t.Fatal("磁盘保存失败时必须回滚客户端注册")
	}
}
