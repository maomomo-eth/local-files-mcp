package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

type gostAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type gostComponent struct {
	Type     string                     `json:"type"`
	Chain    string                     `json:"chain,omitempty"`
	Auth     *gostAuth                  `json:"auth,omitempty"`
	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
	TLS      *struct {
		ServerName string `json:"serverName,omitempty"`
		CAFile     string `json:"caFile,omitempty"`
		Secure     *bool  `json:"secure,omitempty"`
	} `json:"tls,omitempty"`
}

type gostNode struct {
	Name      string         `json:"name"`
	Addr      string         `json:"addr"`
	Connector *gostComponent `json:"connector,omitempty"`
	Dialer    *gostComponent `json:"dialer,omitempty"`
}

type gostClientConfig struct {
	Services []struct {
		Name      string        `json:"name"`
		Addr      string        `json:"addr"`
		Handler   gostComponent `json:"handler"`
		Listener  gostComponent `json:"listener"`
		Forwarder struct {
			Nodes []gostNode `json:"nodes"`
		} `json:"forwarder"`
	} `json:"services"`
	Chains []struct {
		Name string `json:"name"`
		Hops []struct {
			Name  string     `json:"name"`
			Nodes []gostNode `json:"nodes"`
		} `json:"hops"`
	} `json:"chains"`
}

type relayConfig struct {
	server     string
	bind       string
	auth       *gostAuth
	proxy      *gostNode
	tls        *tls.Config
	muxVersion int
}

// 配置可能含凭据，必须位于 MCP 项目外的私密目录；错误不能带出路径或 JSON 原值。
func loadGostConfig(name, rootPath, listen string) (*relayConfig, error) {
	actualRoot, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, errors.New("无法确定 MCP 项目根目录")
	}
	actual, err := filepath.EvalSymlinks(name)
	if err != nil {
		return nil, errors.New("无法定位 gost 配置文件")
	}
	actual, err = filepath.Abs(actual)
	if err != nil {
		return nil, errors.New("无法确定 gost 配置位置")
	}
	rel, err := filepath.Rel(actualRoot, actual)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return nil, errors.New("gost 配置必须位于 MCP 项目目录外")
	}
	parent, err := os.Stat(filepath.Dir(actual))
	if err != nil || parent.Mode().Perm() != 0700 {
		return nil, errors.New("gost 配置所在目录权限必须为 700")
	}
	f, err := os.OpenFile(actual, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("无法打开 gost 配置文件")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<10 {
		return nil, errors.New("gost 配置必须是权限为 600、大小不超过 64 KiB 的普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("无法读取 gost 配置或配置超过大小限制")
	}
	return parseGostConfig(data, listen)
}

func parseGostConfig(data []byte, listen string) (*relayConfig, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("gost 配置必须使用 UTF-8 编码")
	}
	var source gostClientConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&source); err != nil {
		return nil, errors.New("gost 配置不是受支持的 JSON；仅接受文档列出的 rtcp/relay 配置字段")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("gost 配置包含多余内容")
	}
	if len(source.Services) != 1 || len(source.Chains) != 1 {
		return nil, errors.New("内置 relay 仅支持一个 rtcp 服务和一条连接链")
	}
	s, chain := source.Services[0], source.Chains[0]
	if s.Handler.Type != "rtcp" || s.Listener.Type != "rtcp" || s.Listener.Chain == "" || s.Listener.Chain != chain.Name ||
		s.Handler.Chain != "" || s.Handler.Auth != nil || s.Listener.Auth != nil || s.Handler.TLS != nil || s.Listener.TLS != nil ||
		len(s.Handler.Metadata) != 0 || len(s.Listener.Metadata) != 0 {
		return nil, errors.New("内置 relay 需要通过 listener.chain 引用的 rtcp 服务，不支持额外监听器或处理器选项")
	}
	if len(s.Forwarder.Nodes) != 1 || s.Forwarder.Nodes[0].Addr != listen ||
		s.Forwarder.Nodes[0].Connector != nil || s.Forwarder.Nodes[0].Dialer != nil {
		return nil, errors.New("rtcp 必须仅转发到与 -listen 完全一致的本机 MCP 地址")
	}
	if !validTCPAddress(s.Addr, true) || len(chain.Hops) < 1 || len(chain.Hops) > 2 {
		return nil, errors.New("远端绑定地址或连接链不受支持；仅支持 relay 或 socks5 → relay")
	}
	cfg := &relayConfig{bind: s.Addr, muxVersion: 1}
	for i, hop := range chain.Hops {
		if len(hop.Nodes) != 1 {
			return nil, errors.New("每个连接跳点必须且只能配置一个节点")
		}
		node := hop.Nodes[0]
		if !validTCPAddress(node.Addr, false) || node.Connector == nil || node.Dialer == nil || node.Connector.Chain != "" || node.Dialer.Chain != "" || node.Dialer.Auth != nil {
			return nil, errors.New("gost 节点必须提供地址、connector 和 dialer，且不能嵌套连接链或额外认证")
		}
		if auth := node.Connector.Auth; auth != nil && (len(auth.Username) > 255 || len(auth.Password) > 255) {
			return nil, errors.New("gost 用户名和口令不能超过 255 字节")
		}
		if len(node.Dialer.Metadata) != 0 || node.Connector.TLS != nil {
			return nil, errors.New("不支持额外 dialer metadata 或 connector TLS 设置")
		}
		if i < len(chain.Hops)-1 {
			if node.Connector.Type != "socks5" || node.Dialer.Type != "tcp" || len(node.Connector.Metadata) != 0 || node.Dialer.TLS != nil {
				return nil, errors.New("前置代理仅支持 SOCKS5 over TCP")
			}
			cfg.proxy = &node
			continue
		}
		if node.Connector.Type != "relay" || (node.Dialer.Type != "tcp" && node.Dialer.Type != "tls") {
			return nil, errors.New("末级节点必须是 relay over TCP 或 TLS")
		}
		cfg.server, cfg.auth = node.Addr, node.Connector.Auth
		for key, value := range node.Connector.Metadata {
			if key != "mux.version" || json.Unmarshal(value, &cfg.muxVersion) != nil || (cfg.muxVersion != 1 && cfg.muxVersion != 2) {
				return nil, errors.New("relay metadata 仅支持 mux.version 为 1 或 2")
			}
		}
		if node.Dialer.Type == "tls" {
			host, _, _ := net.SplitHostPort(node.Addr)
			cfg.tls = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
			if options := node.Dialer.TLS; options != nil {
				if options.Secure != nil && !*options.Secure {
					return nil, errors.New("内置 relay TLS 必须校验服务器证书，可通过 caFile 配置信任的 CA")
				}
				if options.ServerName != "" {
					cfg.tls.ServerName = options.ServerName
				}
				if options.CAFile != "" {
					pem, err := os.ReadFile(options.CAFile)
					pool, poolErr := x509.SystemCertPool()
					if poolErr != nil {
						pool = x509.NewCertPool()
					}
					if err != nil || !pool.AppendCertsFromPEM(pem) {
						return nil, errors.New("无法读取或解析 relay TLS CA 证书")
					}
					cfg.tls.RootCAs = pool
				}
			}
		} else if node.Dialer.TLS != nil {
			return nil, errors.New("TLS 设置只能用于 tls dialer")
		}
	}
	return cfg, nil
}

func validTCPAddress(address string, allowWildcard bool) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || (!allowWildcard && host == "") || strings.ContainsAny(host, "\x00\r\n\t /\\@") {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func relayLocalTarget(addr net.Addr) string {
	host, port, _ := net.SplitHostPort(addr.String())
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}
