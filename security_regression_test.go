package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEditBudgetAndPermissions(t *testing.T) {
	p, dir := testProject(t)
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	p.maxBytes = 64
	original, err := p.write("small", strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.edit("small", "a", strings.Repeat("b", 64), original.SHA256, true); err == nil {
		t.Fatal("放大替换应拒绝")
	}
	if _, err := p.edit("small", "missing", "b", "stale", true); err == nil || !strings.Contains(err.Error(), "版本") {
		t.Fatal("应先检查版本", err)
	}
	got, _ := p.read("small")
	if got != original {
		t.Fatal("失败修改了文件")
	}
	info, _ := os.Stat(filepath.Join(dir, "small"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("新文件应为600")
	}
	if err := os.Chmod(filepath.Join(dir, "small"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := p.write("small", "updated", original.SHA256); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(filepath.Join(dir, "small"))
	if info.Mode().Perm() != 0640 {
		t.Fatal("覆盖应保留权限")
	}
	// mkdir 不调用 Chmod，内核继续应用当前 umask。
	if err := p.mkdir("nested"); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(filepath.Join(dir, "nested"))
	if info.Mode().Perm() != 0700 {
		t.Fatal("目录不能允许其他用户写入")
	}
}

func TestSearchBudgetsAndCancellation(t *testing.T) {
	p, dir := testProject(t)
	data := bytes.Repeat([]byte{0xff}, 2<<20)
	for i := 0; i < 18; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := p.search(context.Background(), ".", "absent", 100)
	if err != nil || !out.Truncated || out.Skipped != 16 {
		t.Fatalf("二进制也应耗尽32MiB预算: %+v %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.search(ctx, ".", "x", 10); err != context.Canceled {
		t.Fatal("取消未传播", err)
	}
	if _, err := p.write("after-cancel", "ok", ""); err != nil {
		t.Fatal("取消未释放锁", err)
	}
}

func TestSearchLargeDirectory(t *testing.T) {
	p, dir := testProject(t)
	for i := 0; i < 20010; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprint(i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	out, err := p.search(context.Background(), ".", "absent", 10)
	if err != nil || !out.Truncated {
		t.Fatal("目录条目应截断", out, err)
	}
}

func TestOAuthStateSizeRollback(t *testing.T) {
	f := newOAuthFixture(t, "none")
	before, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	err = f.a.commitLocked(func() {
		c := f.a.state.Clients[f.clientID]
		c.Name = strings.Repeat("<", maxOAuthStateBytes/6)
		f.a.state.Clients[f.clientID] = c
	})
	if err == nil {
		t.Fatal("实际序列化超限应拒绝")
	}
	after, _ := os.ReadFile(f.path)
	if !bytes.Equal(before, after) || len(f.a.state.Clients[f.clientID].Name) > 200 {
		t.Fatal("超限未回滚")
	}
	f.a.close()
	a, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	a.close()
}

func TestOAuthRegistrationMetadataBudget(t *testing.T) {
	f := newOAuthFixture(t, "none")
	f.a.registerLimit = rate.NewLimiter(rate.Inf, 1)
	redirect := testRedirect + "?q=" + strings.Repeat("<", 1900)
	body, _ := json.Marshal(registrationInput{Redirects: []string{redirect, redirect, redirect, redirect, redirect, redirect, redirect, redirect}})
	// Raw JSON 请求体仍小于16KiB，持久状态转义后明显膨胀。
	body = bytes.ReplaceAll(body, []byte(`\u003c`), []byte("<"))
	rejected := false
	for i := 0; i < 40; i++ {
		w := f.request("POST", "/oauth/register", string(body), "application/json", nil)
		if w.Code == 429 {
			rejected = true
			break
		}
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if !rejected {
		t.Fatal("注册元数据应在总状态之前受限")
	}
	data, _ := os.ReadFile(f.path)
	if len(data) > maxClientMetadataBytes+8192 {
		t.Fatal("注册占用了授权预算")
	}
	_ = f.exchange(t, f.authorizeCode(t))
}

func TestOAuthClientLifecycleAndFairness(t *testing.T) {
	f := newOAuthFixture(t, "none")
	now := f.a.now()
	old := now.Add(-clientIdleTTL - time.Hour)
	for _, id := range []string{"idle", "grant", "pending", "code"} {
		f.a.state.Clients[id] = oauthClient{LastUsed: old}
	}
	f.a.state.Grants["g"] = oauthGrant{ClientID: "grant", Expires: now.Add(time.Hour)}
	f.a.pending["p"] = oauthRequest{ClientID: "pending", Expires: now.Add(time.Minute)}
	f.a.codes["c"] = oauthRequest{ClientID: "code", Expires: now.Add(time.Minute)}
	f.a.cleanLocked()
	if _, ok := f.a.state.Clients["idle"]; ok {
		t.Fatal("陈旧客户端未回收")
	}
	for _, id := range []string{"grant", "pending", "code"} {
		if _, ok := f.a.state.Clients[id]; !ok {
			t.Fatal("活动客户端被淘汰", id)
		}
	}
	for i := 0; i < 4; i++ {
		f.loginPage(t)
	}
	if f.request("GET", "/oauth/authorize?"+f.authQuery().Encode(), "", "", nil).Code != 429 {
		t.Fatal("单客户端配额无效")
	}
	other := f.a.state.Clients[f.clientID]
	f.a.state.Clients["other"] = other
	q := f.authQuery()
	q.Set("client_id", "other")
	if f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", nil).Code != 200 {
		t.Fatal("其他客户端被阻塞")
	}
	f.a.now = func() time.Time { return now.Add(6 * time.Minute) }
	f.a.cleanLocked()
	if len(f.a.pending) != 0 || len(f.a.codes) != 0 {
		t.Fatal("过期流程未清理")
	}
	// 模拟旧版无时间字段，重开应给予宽限并持久化。
	c := f.a.state.Clients[f.clientID]
	c.LastUsed = time.Time{}
	f.a.state.Clients[f.clientID] = c
	if err := f.a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	f.a.close()
	a, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	stamp := a.state.Clients[f.clientID].LastUsed
	if stamp.IsZero() {
		t.Fatal("旧客户端迁移缺失")
	}
	a.close()
	a, err = openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if !a.state.Clients[f.clientID].LastUsed.Equal(stamp) {
		t.Fatal("重启重置生命周期")
	}
}

func TestConsentHashOutsideLockAndSingleUse(t *testing.T) {
	f := newOAuthFixture(t, "none")
	id, cookie := f.loginPage(t)
	started, release := make(chan struct{}), make(chan struct{})
	f.a.hashPassword = func(password, salt string) string { close(started); <-release; return passwordHash(password, salt) }
	form := url.Values{"request_id": {id}, "password": {testPassword}, "decision": {"allow"}}
	done := make(chan int, 1)
	go func() {
		done <- f.request("POST", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", cookie).Code
	}()
	<-started
	// 无耗时断言：只有主协程完成 validAccess 和重复请求后才放行哈希。
	if f.a.validAccess("unknown") {
		t.Fatal("未知令牌有效")
	}
	w := f.request("POST", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", cookie)
	if w.Code == http.StatusOK {
		t.Fatal("并行请求重复签发")
	}
	close(release)
	if <-done != 200 {
		t.Fatal("原请求失败")
	}
	if len(f.a.codes) != 1 {
		t.Fatal("授权码必须只签发一次")
	}
}

func TestPublicRefreshReplayPersistenceAndRollback(t *testing.T) {
	f := newOAuthFixture(t, "none")
	tokens := f.exchange(t, f.authorizeCode(t))
	refresh := func(raw string) int {
		return f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}, "/oauth/token").Code
	}
	if refresh(tokens["refresh"]) != 200 {
		t.Fatal("轮换失败")
	}
	f.a.close()
	a, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	f.h = newHandler(f.p, "", []string{"https://gemini.google.com"}, "mcp.example.com", a)
	defer a.close()
	if err := os.Rename(f.path, f.path+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	if refresh(tokens["refresh"]) != 500 || !a.validAccess(tokens["access"]) {
		t.Fatal("保存失败应回滚撤销")
	}
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.path+".backup", f.path); err != nil {
		t.Fatal(err)
	}
	if refresh(tokens["refresh"]) != 400 || len(a.state.Grants) != 0 || len(a.state.Tokens) != 0 {
		t.Fatal("重放未撤销整条链")
	}
	a.close()
	b, err := openOAuth(testIssuer, f.path, f.p.root.Name(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	if b.validAccess(tokens["access"]) || len(b.state.Grants) != 0 {
		t.Fatal("撤销未持久化")
	}
}

func TestConsumedRecordLimitExpiryAndOldRevoke(t *testing.T) {
	f := newOAuthFixture(t, "none")
	tokens := f.exchange(t, f.authorizeCode(t))
	grantID := f.a.state.Tokens[hash([]byte(tokens["refresh"]))].GrantID
	for i := 0; i < maxConsumedTokens; i++ {
		f.a.state.Consumed[fmt.Sprint(i)] = oauthToken{GrantID: grantID, Kind: "refresh", Expires: time.Now().Add(time.Hour)}
	}
	w := f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token")
	if w.Code != 429 || !f.a.validAccess(tokens["access"]) {
		t.Fatal("满额应拒绝轮换且保留原授权")
	}
	now := time.Now().Add(2 * time.Hour)
	f.a.now = func() time.Time { return now }
	f.a.cleanLocked()
	if len(f.a.state.Consumed) != 0 {
		t.Fatal("消费记录未按TTL回收")
	}
	w = f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token")
	if w.Code != 200 {
		t.Fatal("回收后轮换失败")
	}
	w = f.tokenRequest(url.Values{"token": {tokens["refresh"]}}, "/oauth/revoke")
	if w.Code != 200 || len(f.a.state.Grants) != 0 {
		t.Fatal("旧令牌撤销入口不能定位授权")
	}
}

type cancelAfterRead struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	r.reads++
	p[0] = 'a'
	r.cancel()
	return 1, nil
}
func TestSearchReaderCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancelAfterRead{cancel: cancel}
	reader := &contextReader{ctx: ctx, r: source}
	data, err := io.ReadAll(reader)
	if err != context.Canceled || string(data) != "a" || source.reads != 1 {
		t.Fatal("取消后仍继续读取", err, source.reads)
	}
}

func TestPublicRotationSaveRollback(t *testing.T) {
	f := newOAuthFixture(t, "none")
	tokens := f.exchange(t, f.authorizeCode(t))
	if err := os.Rename(f.path, f.path+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}
	if f.tokenRequest(values, "/oauth/token").Code != 500 {
		t.Fatal("应拒绝无法持久化的轮换")
	}
	if len(f.a.state.Consumed) != 0 || !f.a.validAccess(tokens["access"]) {
		t.Fatal("失败轮换未回滚")
	}
	if _, ok := f.a.state.Tokens[hash([]byte(tokens["refresh"]))]; !ok {
		t.Fatal("失败丢失旧刷新令牌")
	}
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.path+".backup", f.path); err != nil {
		t.Fatal(err)
	}
	if f.tokenRequest(values, "/oauth/token").Code != 200 {
		t.Fatal("回滚后不能重试轮换")
	}
}

func TestOAuthCapacityReclaimsOnlyIdle(t *testing.T) {
	f := newOAuthFixture(t, "none")
	now := time.Now()
	old := now.Add(-clientIdleTTL - time.Hour)
	template := f.a.state.Clients[f.clientID]
	template.LastUsed = old
	for i := 0; i < 255; i++ {
		f.a.state.Clients[fmt.Sprint(i)] = template
	}
	f.a.state.Grants["live"] = oauthGrant{ClientID: "0", Expires: now.Add(time.Hour)}
	f.a.pending["live"] = oauthRequest{ClientID: "1", Expires: now.Add(time.Minute)}
	f.a.codes["live"] = oauthRequest{ClientID: "2", Expires: now.Add(time.Minute)}
	body, _ := json.Marshal(registrationInput{Redirects: []string{testRedirect}})
	if w := f.request("POST", "/oauth/register", string(body), "application/json", nil); w.Code != 201 {
		t.Fatal("满额时未回收陈旧客户端", w.Code)
	}
	if len(f.a.state.Clients) != 5 {
		t.Fatal("回收数量错误", len(f.a.state.Clients))
	}
	for _, id := range []string{"0", "1", "2"} {
		if _, ok := f.a.state.Clients[id]; !ok {
			t.Fatal("容量回收删除活动客户端", id)
		}
	}
}

func TestConfidentialRefreshRemainsStable(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(method, func(t *testing.T) {
			f := newOAuthFixture(t, method)
			tokens := f.exchange(t, f.authorizeCode(t))
			for i := 0; i < 2; i++ {
				w := f.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh"]}}, "/oauth/token")
				var reply struct {
					Refresh string `json:"refresh_token"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || reply.Refresh != tokens["refresh"] || len(f.a.state.Consumed) != 0 {
					t.Fatal("机密客户端刷新行为发生变化")
				}
			}
		})
	}
}
