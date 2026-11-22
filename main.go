package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	rootPath := flag.String("root", "", "允许访问的项目目录（必填）")
	listen := flag.String("listen", "127.0.0.1:8765", "HTTP 监听地址")
	publicHost := flag.String("public-host", "", "隧道转发时允许的公网域名，不含协议、端口和路径")
	readOnly := flag.Bool("read-only", false, "只提供读取、目录查看和搜索工具")
	maxBytes := flag.Int64("max-file-bytes", defaultMaxBytes, "单文件最大字节数，最大 16777216")
	allowedOrigins := flag.String("allowed-origins", "https://gemini.google.com", "允许的 Origin，以逗号分隔；无 Origin 的服务端请求允许通过")
	oauthIssuer := flag.String("oauth-issuer", "", "启用 Gemini OAuth，填写公网 HTTPS 域名根地址")
	oauthStatePath := flag.String("oauth-state", "", "OAuth 私密状态文件，必须在项目目录外的权限为 700 的独立目录中")
	gostConfigPath := flag.String("gost-config", "", "可选：项目目录外的 gost v3 JSON 配置，内置 rtcp/relay 客户端，支持前置 SOCKS5")
	checkGostConfig := flag.Bool("check-gost-config", false, "仅校验 -gost-config 后退出，不启动 HTTP、OAuth 或隧道")
	flag.Parse()
	if *rootPath == "" {
		return errors.New("必须通过 -root 指定允许访问的项目目录")
	}
	if flag.NArg() != 0 {
		return errors.New("存在多余的位置参数，请使用 -help 查看用法")
	}
	if *maxBytes < 1 || *maxBytes > 16<<20 {
		return errors.New("max-file-bytes 必须在 1 到 16777216 之间")
	}
	if strings.ContainsAny(*publicHost, "/:\\ \t\r\n") {
		return errors.New("public-host 只能填写域名，不含协议、端口和路径")
	}
	absRoot, err := filepath.Abs(*rootPath)
	if err != nil {
		return err
	}
	var relayCfg *relayConfig
	if *checkGostConfig && *gostConfigPath == "" {
		return errors.New("check-gost-config 需要同时指定 gost-config")
	}
	if *gostConfigPath != "" {
		relayCfg, err = loadGostConfig(*gostConfigPath, absRoot, *listen)
		if err != nil {
			return err
		}
	}
	if *checkGostConfig {
		log.Print("gost 配置校验通过")
		return nil
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return fmt.Errorf("打开项目目录失败：%w", err)
	}
	defer root.Close()
	p := &project{root: root, maxBytes: *maxBytes, readOnly: *readOnly}
	var auth *oauthServer
	if *oauthIssuer != "" {
		if os.Getenv("LOCAL_FILES_MCP_TOKEN") != "" {
			return errors.New("OAuth 与 LOCAL_FILES_MCP_TOKEN 不能同时启用，请先 unset LOCAL_FILES_MCP_TOKEN")
		}
		if *oauthStatePath == "" {
			return errors.New("启用 OAuth 时必须指定 -oauth-state 私密状态文件")
		}
		auth, err = openOAuth(*oauthIssuer, *oauthStatePath, absRoot, *readOnly, os.Getenv("LOCAL_FILES_MCP_PASSWORD"))
		if err != nil {
			return err
		}
		defer auth.close()
		if *publicHost == "" {
			u, _ := url.Parse(auth.issuer)
			*publicHost = u.Hostname()
		}
		log.Printf("OAuth 已启用：%s；状态文件：%s", auth.issuer, *oauthStatePath)
	} else if *oauthStatePath != "" {
		return errors.New("oauth-state 需要与 oauth-issuer 一起使用")
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(p, os.Getenv("LOCAL_FILES_MCP_TOKEN"), strings.Split(*allowedOrigins, ","), *publicHost, auth),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	if relayCfg != nil {
		relayDone := make(chan struct{})
		go func() {
			defer close(relayDone)
			runRelay(ctx, relayCfg, relayLocalTarget(listener.Addr()))
		}()
		defer func() { stop(); <-relayDone }()
	}
	log.Printf("项目目录：%s；只读：%v；HTTP：%s；MCP 路径：/mcp", absRoot, *readOnly, *listen)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}
