package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

func validateIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("oauth-issuer 必须是域名根路径的 HTTPS 地址，例如 https://mcp.example.com")
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return "https://" + host, nil
}

// 首先限定到 Google 官方回调域名和路径族；注册后再对完整 URI 精确匹配。
func googleRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return false
	}
	if !slices.Contains([]string{"oauth-redirect.googleusercontent.com", "oauth-redirect-sandbox.googleusercontent.com", "oauth-redirect-test.googleusercontent.com"}, u.Host) {
		return false
	}
	return (strings.HasPrefix(u.Path, "/r/") || strings.HasPrefix(u.Path, "/a/")) && len(u.Path) > 3 && !strings.Contains(u.Path, "..")
}

func jsonReply(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func oauthError(w http.ResponseWriter, status int, name, description string) {
	jsonReply(w, status, map[string]string{"error": name, "error_description": description})
}

func (a *oauthServer) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.metadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", a.resourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", a.resourceMetadata)
	mux.HandleFunc("POST /oauth/register", a.register)
	mux.HandleFunc("GET /oauth/authorize", a.authorize)
	mux.HandleFunc("POST /oauth/authorize", a.consent)
	mux.HandleFunc("POST /oauth/token", a.token)
	mux.HandleFunc("POST /oauth/revoke", a.revoke)
}

func (a *oauthServer) metadata(w http.ResponseWriter, _ *http.Request) {
	i := a.issuer
	jsonReply(w, 200, map[string]any{
		"issuer": i, "authorization_endpoint": i + "/oauth/authorize", "token_endpoint": i + "/oauth/token", "registration_endpoint": i + "/oauth/register", "revocation_endpoint": i + "/oauth/revoke",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{oauthScope},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"}, "revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}
func (a *oauthServer) resourceMetadata(w http.ResponseWriter, _ *http.Request) {
	jsonReply(w, 200, map[string]any{"resource": a.issuer + "/mcp", "authorization_servers": []string{a.issuer}, "scopes_supported": []string{oauthScope}, "bearer_methods_supported": []string{"header"}, "resource_name": "本地项目文件"})
}

type registrationInput struct {
	Name      string   `json:"client_name"`
	Redirects []string `json:"redirect_uris"`
	Method    string   `json:"token_endpoint_auth_method"`
	Grants    []string `json:"grant_types"`
	Responses []string `json:"response_types"`
}

func (a *oauthServer) register(w http.ResponseWriter, r *http.Request) {
	if !a.registerLimit.Allow() {
		oauthError(w, 429, "temporarily_unavailable", "注册请求过于频繁")
		return
	}
	var in registrationInput
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&in); err != nil {
		oauthError(w, 400, "invalid_client_metadata", "无效的 JSON")
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		oauthError(w, 400, "invalid_client_metadata", "JSON 包含多余内容")
		return
	}
	if in.Method == "" {
		in.Method = "client_secret_basic"
	}
	if !slices.Contains([]string{"client_secret_basic", "client_secret_post", "none"}, in.Method) || len(in.Name) > 200 || len(in.Redirects) < 1 || len(in.Redirects) > 8 {
		oauthError(w, 400, "invalid_client_metadata", "客户端参数不受支持")
		return
	}
	for _, g := range in.Grants {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata", "仅支持授权码与刷新令牌")
			return
		}
	}
	if len(in.Grants) > 0 && !slices.Contains(in.Grants, "authorization_code") {
		oauthError(w, 400, "invalid_client_metadata", "必须支持授权码")
		return
	}
	for _, v := range in.Responses {
		if v != "code" {
			oauthError(w, 400, "invalid_client_metadata", "仅支持 code 响应类型")
			return
		}
	}
	for _, u := range in.Redirects {
		if len(u) > 2048 || !googleRedirect(u) {
			oauthError(w, 400, "invalid_redirect_uri", "仅允许 Google 官方 OAuth 回调地址")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.state.Clients) >= 256 {
		oauthError(w, 429, "temporarily_unavailable", "客户端数量已达上限")
		return
	}
	id, secret := rand.Text(), ""
	c := oauthClient{Name: in.Name, Redirects: in.Redirects, Method: in.Method}
	if in.Method != "none" {
		secret = rand.Text()
		c.SecretHash = hash([]byte(secret))
	}
	if err := a.commitLocked(func() { a.state.Clients[id] = c }); err != nil {
		oauthError(w, 500, "server_error", "客户端保存失败")
		return
	}
	out := map[string]any{"client_id": id, "client_id_issued_at": a.now().Unix(), "client_name": in.Name, "redirect_uris": in.Redirects, "token_endpoint_auth_method": in.Method, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": oauthScope}
	if secret != "" {
		out["client_secret"] = secret
		out["client_secret_expires_at"] = 0
	}
	jsonReply(w, 201, out)
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权访问本地项目</title><style>body{font:17px system-ui;max-width:640px;margin:60px auto;padding:24px;line-height:1.7}input,button{font:inherit;padding:10px;margin:8px 0}input{box-sizing:border-box;width:100%}button{cursor:pointer}</style>
<h1>授权访问本地项目</h1><p>客户端声明名称：<strong>{{.Name}}</strong></p><p>本次授权允许客户端{{if .ReadOnly}}读取和搜索{{else}}读取、搜索和修改{{end}}服务启动时指定的项目文件。</p>
<p>回调地址：{{.Redirect}}</p><p>仅在你主动从 Gemini 发起连接时继续。此处输入本地服务授权密码，不是 Google 密码。</p>
<form method="post" action="{{.Action}}"><input type="hidden" name="request_id" value="{{.ID}}">
<label>本地服务授权密码<input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label>
<button type="submit" name="decision" value="allow">确认授权</button> <button type="submit" name="decision" value="deny" formnovalidate>取消</button></form></html>`))

var returnPage = template.Must(template.New("return").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="0; url={{.URL}}"><title>{{.Title}}</title>
<style>body{font:17px system-ui;max-width:640px;margin:60px auto;padding:24px;line-height:1.7}a{display:inline-block;padding:12px 18px;background:#174ea6;color:white;border-radius:6px;text-decoration:none}</style></head>
<body><h1>{{.Title}}</h1><p>正在返回 Gemini。如果浏览器未自动跳转，请点击下面的按钮。</p>
<a id="return-link" href="{{.URL}}" rel="noreferrer">继续返回 Gemini</a></body></html>`))

func (a *oauthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			oauthError(w, 400, "invalid_request", "不允许重复的参数")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanLocked()
	c, ok := a.state.Clients[q.Get("client_id")]
	if !ok || !slices.Contains(c.Redirects, q.Get("redirect_uri")) {
		oauthError(w, 400, "invalid_request", "客户端或回调地址不匹配")
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || err != nil || len(challenge) != 32 || len(q.Get("code_challenge")) != 43 {
		oauthError(w, 400, "invalid_request", "必须使用 code 响应和 S256 PKCE")
		return
	}
	if !a.validResource(q.Get("resource")) {
		oauthError(w, 400, "invalid_target", "resource 必须匹配本服务的 /mcp 地址")
		return
	}
	if q.Get("scope") != "" && q.Get("scope") != oauthScope {
		oauthError(w, 400, "invalid_scope", "仅支持 mcp 权限")
		return
	}
	if len(q.Get("state")) > 2048 || len(a.pending) >= 128 {
		oauthError(w, 429, "temporarily_unavailable", "授权请求过多")
		return
	}
	id, cookie := rand.Text(), rand.Text()
	a.pending[id] = oauthRequest{ClientID: q.Get("client_id"), Redirect: q.Get("redirect_uri"), State: q.Get("state"), Challenge: q.Get("code_challenge"), CookieHash: hash([]byte(cookie)), Expires: a.now().Add(5 * time.Minute)}
	w.Header().Set("Cache-Control", "no-store")
	// 表单导航在 no-referrer 下会发送 Origin:null；保留同源信息供提交时校验。
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 表单只提交本站；成功后先提交独立结果页，再开始 Google 的连续导航。
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.SetCookie(w, &http.Cookie{Name: "__Host-local-files-oauth", Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	_ = consentPage.Execute(w, map[string]any{"Name": c.Name, "Redirect": q.Get("redirect_uri"), "Action": a.state.Issuer + "/oauth/authorize", "ReadOnly": a.state.ReadOnly, "ID": id})
}

func parseOAuthForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "无效的表单")
		return false
	}
	for _, v := range r.PostForm {
		if len(v) != 1 {
			oauthError(w, 400, "invalid_request", "不允许重复的参数")
			return false
		}
	}
	return true
}

func (a *oauthServer) consent(w http.ResponseWriter, r *http.Request) {
	if !parseOAuthForm(w, r) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanLocked()
	id := r.PostForm.Get("request_id")
	req, ok := a.pending[id]
	cookie, err := r.Cookie("__Host-local-files-oauth")
	if !ok || err != nil || !equalSecret(hash([]byte(cookie.Value)), req.CookieHash) || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != a.state.Issuer) {
		oauthError(w, 403, "access_denied", "授权请求过期或浏览器校验失败，请从 Gemini 重新连接")
		return
	}
	if r.PostForm.Get("decision") == "deny" {
		delete(a.pending, id)
		a.returnToClient(w, req, "error", "access_denied")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		oauthError(w, 400, "invalid_request", "请选择授权或取消")
		return
	}
	if !a.loginLimit.Allow() {
		w.Header().Set("Retry-After", "5")
		oauthError(w, 429, "access_denied", "密码尝试过于频繁，请稍后重试")
		return
	}
	password := r.PostForm.Get("password")
	if len(password) > 1024 || !equalSecret(passwordHash(password, a.state.PasswordSalt), a.state.PasswordHash) {
		oauthError(w, 403, "access_denied", "授权密码错误，请返回重试")
		return
	}
	if len(a.codes) >= 128 {
		oauthError(w, 429, "temporarily_unavailable", "待交换授权码过多")
		return
	}
	delete(a.pending, id)
	code := rand.Text()
	req.Expires = a.now().Add(2 * time.Minute)
	a.codes[hash([]byte(code))] = req
	http.SetCookie(w, &http.Cookie{Name: "__Host-local-files-oauth", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	a.returnToClient(w, req, "code", code)
}
func (a *oauthServer) returnToClient(w http.ResponseWriter, req oauthRequest, key, value string) {
	u, _ := url.Parse(req.Redirect)
	q := u.Query()
	q.Set(key, value)
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	title := "授权成功"
	if key == "error" {
		title = "已取消授权"
	}
	// 先提交 HTTP 200 的新文档，让后续跨站导航脱离原表单的 CSP 约束。
	// URL 来自已校验的已注册回调，不接收独立的外部跳转参数。
	_ = returnPage.Execute(w, map[string]string{"URL": u.String(), "Title": title})
}

func (a *oauthServer) validResource(resource string) bool {
	return resource == "" || resource == a.state.Issuer+"/mcp"
}

// 必须在持有状态锁时调用。对注册时声明的认证方法严格匹配。
func (a *oauthServer) authenticateClient(r *http.Request) (string, oauthClient, bool) {
	id, secret, method := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), "client_secret_post"
	if r.Header.Get("Authorization") != "" {
		if secret != "" {
			return "", oauthClient{}, false
		}
		basicID, basicSecret, ok := r.BasicAuth()
		if !ok {
			return "", oauthClient{}, false
		}
		var err error
		basicID, err = url.QueryUnescape(basicID)
		if err != nil {
			return "", oauthClient{}, false
		}
		basicSecret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			return "", oauthClient{}, false
		}
		if id != "" && id != basicID {
			return "", oauthClient{}, false
		}
		id, secret, method = basicID, basicSecret, "client_secret_basic"
	} else if secret == "" {
		method = "none"
	}
	c, ok := a.state.Clients[id]
	if !ok || c.Method != method {
		return "", oauthClient{}, false
	}
	if method != "none" && !equalSecret(hash([]byte(secret)), c.SecretHash) {
		return "", oauthClient{}, false
	}
	return id, c, true
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func (a *oauthServer) token(w http.ResponseWriter, r *http.Request) {
	if !parseOAuthForm(w, r) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanLocked()
	id, c, ok := a.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"OAuth\"")
		oauthError(w, 401, "invalid_client", "客户端认证失败")
		return
	}
	if !a.validResource(r.PostForm.Get("resource")) {
		oauthError(w, 400, "invalid_target", "resource 不匹配")
		return
	}
	if scope := r.PostForm.Get("scope"); scope != "" && scope != oauthScope {
		oauthError(w, 400, "invalid_scope", "仅支持 mcp 权限")
		return
	}
	now := a.now()
	var grantID, refresh, codeKey, previousRefresh string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		codeKey = hash([]byte(r.PostForm.Get("code")))
		req, exists := a.codes[codeKey]
		verifier := r.PostForm.Get("code_verifier")
		digest := sha256.Sum256([]byte(verifier))
		if !exists || req.ClientID != id || req.Redirect != r.PostForm.Get("redirect_uri") || !now.Before(req.Expires) || !validVerifier(verifier) || !equalSecret(base64.RawURLEncoding.EncodeToString(digest[:]), req.Challenge) {
			oauthError(w, 400, "invalid_grant", "授权码、回调地址或 PKCE 校验失败")
			return
		}
		grantID, refresh = rand.Text(), rand.Text()
	case "refresh_token":
		refresh = r.PostForm.Get("refresh_token")
		t, exists := a.state.Tokens[hash([]byte(refresh))]
		g, grantExists := a.state.Grants[t.GrantID]
		if !exists || !grantExists || t.Kind != "refresh" || g.ClientID != id || !now.Before(t.Expires) || !now.Before(g.Expires) {
			oauthError(w, 400, "invalid_grant", "刷新令牌无效或已过期")
			return
		}
		grantID = t.GrantID
		// Google 的持久关联保留机密客户端刷新令牌；公共客户端执行轮换。
		if c.Method == "none" {
			previousRefresh = hash([]byte(refresh))
			refresh = rand.Text()
		}
	default:
		oauthError(w, 400, "unsupported_grant_type", "仅支持 authorization_code 和 refresh_token")
		return
	}
	if len(a.state.Tokens) >= 2048 || len(a.state.Grants) >= 512 {
		oauthError(w, 429, "temporarily_unavailable", "令牌数量已达上限")
		return
	}
	access := rand.Text()
	expires := now.Add(90 * 24 * time.Hour)
	if err := a.commitLocked(func() {
		a.state.Grants[grantID] = oauthGrant{ClientID: id, Expires: expires}
		if previousRefresh != "" {
			delete(a.state.Tokens, previousRefresh)
		}
		a.state.Tokens[hash([]byte(access))] = oauthToken{GrantID: grantID, Kind: "access", Expires: now.Add(time.Hour)}
		a.state.Tokens[hash([]byte(refresh))] = oauthToken{GrantID: grantID, Kind: "refresh", Expires: expires}
	}); err != nil {
		oauthError(w, 500, "server_error", "令牌保存失败")
		return
	}
	if codeKey != "" {
		delete(a.codes, codeKey)
	}
	jsonReply(w, 200, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh, "scope": oauthScope})
}

func (a *oauthServer) revoke(w http.ResponseWriter, r *http.Request) {
	if !parseOAuthForm(w, r) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id, _, ok := a.authenticateClient(r)
	if !ok {
		oauthError(w, 401, "invalid_client", "客户端认证失败")
		return
	}
	t, ok := a.state.Tokens[hash([]byte(r.PostForm.Get("token")))]
	g, grantOK := a.state.Grants[t.GrantID]
	if ok && grantOK && g.ClientID == id {
		if err := a.commitLocked(func() {
			delete(a.state.Grants, t.GrantID)
			for key, value := range a.state.Tokens {
				if value.GrantID == t.GrantID {
					delete(a.state.Tokens, key)
				}
			}
		}); err != nil {
			oauthError(w, 500, "server_error", "撤销保存失败")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
}
