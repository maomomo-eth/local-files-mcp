package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

const oauthScope = "mcp"
const passwordIterations = 600000

type oauthClient struct {
	Name       string   `json:"name"`
	SecretHash string   `json:"secret_hash,omitempty"`
	Method     string   `json:"method"`
	Redirects  []string `json:"redirects"`
}
type oauthGrant struct {
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}
type oauthToken struct {
	GrantID string    `json:"grant_id"`
	Kind    string    `json:"kind"`
	Expires time.Time `json:"expires"`
}
type oauthState struct {
	Version      int                    `json:"version"`
	Issuer       string                 `json:"issuer"`
	Root         string                 `json:"root"`
	ReadOnly     bool                   `json:"read_only"`
	PasswordSalt string                 `json:"password_salt"`
	PasswordHash string                 `json:"password_hash"`
	Clients      map[string]oauthClient `json:"clients"`
	Grants       map[string]oauthGrant  `json:"grants"`
	Tokens       map[string]oauthToken  `json:"tokens"`
}
type oauthRequest struct {
	ClientID, Redirect, State, Challenge, CookieHash string
	Expires                                          time.Time
}
type oauthServer struct {
	issuer        string
	mu            sync.Mutex
	state         oauthState
	dir           *os.Root
	filename      string
	lock          *os.File
	pending       map[string]oauthRequest
	codes         map[string]oauthRequest
	loginLimit    *rate.Limiter
	registerLimit *rate.Limiter
	now           func() time.Time
}

func passwordHash(password, salt string) string {
	key, _ := pbkdf2.Key(sha256.New, password, []byte(salt), passwordIterations, 32)
	return fmt.Sprintf("%x", key)
}
func equalSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// 私密状态必须位于项目目录外，避免 MCP 自己读到授权凭据。
func openOAuth(issuer, statePath, rootPath string, readOnly bool, password string) (*oauthServer, error) {
	issuer, err := validateIssuer(issuer)
	if err != nil {
		return nil, err
	}
	actualRoot, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, err
	}
	actualRoot, err = filepath.Abs(actualRoot)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(statePath)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(actualRoot, parent); err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return nil, errors.New("OAuth 状态必须保存在允许访问的项目目录之外")
	}
	dir, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*oauthServer, error) { dir.Close(); return nil, err }
	info, err := dir.Stat(".")
	if err != nil {
		return fail(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fail(errors.New("OAuth 状态目录权限必须为 700，请使用独立的私密目录"))
	}
	lock, err := dir.OpenFile(".oauth-lock-"+hash([]byte(filepath.Base(abs)))[:16], os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fail(err)
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return fail(errors.New("OAuth 状态已被其他进程使用"))
	}
	a := &oauthServer{issuer: issuer, dir: dir, filename: filepath.Base(abs), lock: lock, pending: map[string]oauthRequest{}, codes: map[string]oauthRequest{}, loginLimit: rate.NewLimiter(rate.Every(5*time.Second), 5), registerLimit: rate.NewLimiter(rate.Every(3*time.Second), 20), now: time.Now}
	stateFile, err := dir.OpenFile(a.filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer stateFile.Close()
		info, statErr := stateFile.Stat()
		if statErr != nil {
			a.close()
			return nil, statErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
			a.close()
			return nil, errors.New("OAuth 状态必须是权限为 600 的普通文件，且不超过 8 MiB")
		}
		err = json.NewDecoder(stateFile).Decode(&a.state)
		if err != nil {
			a.close()
			return nil, fmt.Errorf("OAuth 状态读取失败：%w", err)
		}
		if a.state.Version != 1 || a.state.Issuer != issuer || a.state.Root != actualRoot || a.state.ReadOnly != readOnly || len(a.state.PasswordHash) != 64 || a.state.PasswordSalt == "" || a.state.Clients == nil || a.state.Grants == nil || a.state.Tokens == nil {
			a.close()
			return nil, errors.New("OAuth 状态与域名、项目目录或只读设置不匹配；请为新配置使用独立状态文件")
		}
	} else if os.IsNotExist(err) {
		if len(password) < 12 || len(password) > 1024 {
			a.close()
			return nil, errors.New("首次启用 OAuth 时，请设置 LOCAL_FILES_MCP_PASSWORD，长度为 12 到 1024 字节")
		}
		salt := rand.Text()
		a.state = oauthState{Version: 1, Issuer: issuer, Root: actualRoot, ReadOnly: readOnly, PasswordSalt: salt, PasswordHash: passwordHash(password, salt), Clients: map[string]oauthClient{}, Grants: map[string]oauthGrant{}, Tokens: map[string]oauthToken{}}
		if err := a.saveLocked(); err != nil {
			a.close()
			return nil, err
		}
	} else {
		a.close()
		return nil, err
	}
	return a, nil
}

func (a *oauthServer) close() { a.lock.Close(); a.dir.Close() }

func (a *oauthServer) saveLocked() error {
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := ".oauth-" + rand.Text()
	f, err := a.dir.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer a.dir.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return a.dir.Rename(tmp, a.filename)
}

// 保存失败时恢复内存快照，不签发无法在重启后验证的令牌。
func (a *oauthServer) commitLocked(change func()) error {
	before, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	change()
	if err := a.saveLocked(); err != nil {
		var restored oauthState
		_ = json.Unmarshal(before, &restored)
		a.state = restored
		return err
	}
	return nil
}

func (a *oauthServer) cleanLocked() {
	now := a.now()
	for k, v := range a.pending {
		if !now.Before(v.Expires) {
			delete(a.pending, k)
		}
	}
	for k, v := range a.codes {
		if !now.Before(v.Expires) {
			delete(a.codes, k)
		}
	}
	for k, v := range a.state.Grants {
		if !now.Before(v.Expires) {
			delete(a.state.Grants, k)
		}
	}
	for k, v := range a.state.Tokens {
		if _, ok := a.state.Grants[v.GrantID]; !ok || !now.Before(v.Expires) {
			delete(a.state.Tokens, k)
		}
	}
}

func (a *oauthServer) validAccess(raw string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.state.Tokens[hash([]byte(raw))]
	g, grantOK := a.state.Grants[t.GrantID]
	return raw != "" && ok && grantOK && t.Kind == "access" && a.now().Before(t.Expires) && a.now().Before(g.Expires)
}
