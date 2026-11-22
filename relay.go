package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/go-gost/relay"
	"github.com/xtaci/smux"
	"golang.org/x/net/proxy"
)

const relayHandshakeTimeout = 10 * time.Second

// 仅接受远端 BIND 流量，始终转发给本机 MCP，不提供通用代理服务。
func runRelay(ctx context.Context, cfg *relayConfig, target string) {
	delay := time.Second
	for ctx.Err() == nil {
		session, err := openRelaySession(ctx, cfg)
		if err == nil {
			delay = time.Second
			log.Print("gost relay：远端端口映射已建立")
			serveRelaySession(ctx, session, target)
			if ctx.Err() == nil {
				log.Print("gost relay：连接已断开，准备重连")
			}
		} else if ctx.Err() == nil {
			// openRelaySession 仅返回固定的脱敏错误，禁止输出网络原始错误。
			log.Printf("gost relay：%s；稍后重试", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func openRelaySession(ctx context.Context, cfg *relayConfig) (*smux.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: relayHandshakeTimeout, KeepAlive: 30 * time.Second}
	var dial proxy.ContextDialer = dialer
	if cfg.proxy != nil {
		var auth *proxy.Auth
		if a := cfg.proxy.Connector.Auth; a != nil {
			auth = &proxy.Auth{User: a.Username, Password: a.Password}
		}
		p, err := proxy.SOCKS5("tcp", cfg.proxy.Addr, auth, dialer)
		if err != nil {
			return nil, errors.New("无法初始化 SOCKS5 代理")
		}
		dial = p.(proxy.ContextDialer)
	}
	conn, err := dial.DialContext(ctx, "tcp", cfg.server)
	if err != nil {
		return nil, errors.New("无法连接 relay 上游或前置代理")
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	transport := conn
	stop := context.AfterFunc(ctx, func() { transport.Close() })
	defer stop()
	if cfg.tls != nil {
		secured := tls.Client(conn, cfg.tls)
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, errors.New("relay TLS 握手或证书校验失败")
		}
		conn = secured
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, errors.New("无法设置 relay 握手超时")
	}
	bind := cfg.bind
	if host, port, _ := net.SplitHostPort(bind); host == "" {
		bind = net.JoinHostPort("0.0.0.0", port)
	}
	address := &relay.AddrFeature{}
	if err := address.ParseFrom(bind); err != nil {
		return nil, errors.New("relay 远端绑定地址无效")
	}
	request := relay.Request{Version: relay.Version1, Cmd: relay.CmdBind}
	if cfg.auth != nil {
		request.Features = append(request.Features, &relay.UserAuthFeature{Username: cfg.auth.Username, Password: cfg.auth.Password})
	}
	request.Features = append(request.Features, &relay.NetworkFeature{Network: relay.NetworkTCP}, address)
	if _, err := request.WriteTo(conn); err != nil {
		return nil, errors.New("relay BIND 请求发送失败")
	}
	var response relay.Response
	if _, err := response.ReadFrom(conn); err != nil {
		return nil, errors.New("relay BIND 响应无效或超时")
	}
	if response.Status != relay.StatusOK {
		return nil, fmt.Errorf("relay 拒绝远端绑定（状态 %d）", response.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, errors.New("无法清除 relay 握手超时")
	}
	mux := smux.DefaultConfig()
	mux.Version = cfg.muxVersion
	session, err := smux.Server(conn, mux)
	if err != nil {
		return nil, errors.New("无法建立 relay 多路复用会话")
	}
	ok = true
	return session, nil
}

func serveRelaySession(ctx context.Context, session *smux.Session, target string) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { session.Close() })
	var workers sync.WaitGroup
	defer func() {
		cancel()
		stop()
		session.Close()
		workers.Wait()
	}()
	// 限制并行转发，避免远端创建无限数量的本机连接和 goroutine。
	slots := make(chan struct{}, 128)
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			stream.Close()
			return
		}
		workers.Go(func() {
			defer func() { <-slots }()
			bridgeRelayStream(ctx, stream, target)
		})
	}
}

func bridgeRelayStream(ctx context.Context, stream net.Conn, target string) {
	defer stream.Close()
	// GOST 每条 BIND 数据流先发送第二个 relay 响应，随后才是原始 HTTP 字节。
	stream.SetReadDeadline(time.Now().Add(relayHandshakeTimeout))
	var peer relay.Response
	if _, err := peer.ReadFrom(stream); err != nil || peer.Status != relay.StatusOK {
		return
	}
	stream.SetReadDeadline(time.Time{})
	dialer := net.Dialer{Timeout: 5 * time.Second}
	local, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer local.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close(); local.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(local, stream)
		local.Close()
		stream.Close()
		close(done)
	}()
	_, _ = io.Copy(stream, local)
	local.Close()
	stream.Close()
	<-done
}
