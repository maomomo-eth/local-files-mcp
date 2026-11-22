package main

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type pathInput struct {
	Path string `json:"path,omitempty" jsonschema:"项目根目录内的相对路径，默认是点号"`
}
type listInput struct {
	Path  string `json:"path,omitempty" jsonschema:"目录相对路径，默认是项目根目录"`
	Limit int    `json:"limit,omitempty" jsonschema:"最大条目数量，默认 200，最多 2000"`
}
type searchInput struct {
	Path  string `json:"path,omitempty" jsonschema:"搜索起点的相对路径，默认是项目根目录"`
	Query string `json:"query" jsonschema:"区分大小写的字面搜索内容"`
	Limit int    `json:"limit,omitempty" jsonschema:"最大匹配行数，默认 100，最多 1000"`
}
type writeInput struct {
	Path           string `json:"path" jsonschema:"文件相对路径，父目录必须已存在"`
	Content        string `json:"content" jsonschema:"完整 UTF-8 文件内容"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty" jsonschema:"覆盖已有文件时必须提供 read_file 返回的 sha256；新建时留空"`
}
type editInput struct {
	Path           string `json:"path" jsonschema:"文件相对路径"`
	OldText        string `json:"old_text" jsonschema:"需要精确匹配的原文本"`
	NewText        string `json:"new_text" jsonschema:"替换后的文本"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"read_file 返回的 sha256"`
	ReplaceAll     bool   `json:"replace_all,omitempty" jsonschema:"是否替换全部匹配，默认要求唯一匹配"`
}

type deleteInput struct {
	Path           string `json:"path" jsonschema:"要删除的普通 UTF-8 文件相对路径，禁止根目录 .git 及其内部路径和符号链接"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"read_file 返回的 sha256"`
}

type moveInput struct {
	Source         string `json:"source" jsonschema:"源文件相对路径，必须是普通 UTF-8 文件"`
	Destination    string `json:"destination" jsonschema:"目标相对路径，必须不存在且父目录已存在；禁止根目录 .git 及其内部路径和符号链接"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"源文件 read_file 返回的 sha256"`
}

func tool[I, O any](s *mcp.Server, name, description string, readOnly bool, fn func(context.Context, I) (O, error)) {
	mcp.AddTool(s, &mcp.Tool{
		Name: name, Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: boolPtr(!readOnly)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in I) (*mcp.CallToolResult, O, error) {
		out, err := fn(ctx, in)
		return nil, out, err
	})
}

func boolPtr(v bool) *bool { return &v }

func newMCP(p *project) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "local-files-mcp", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "Access the configured local project using relative paths only. Read files before modifying them and pass their sha256 as expected_sha256. Use edit_file for precise replacements. Paths cannot escape the configured project. No shell execution is available.",
	})
	tool(s, "list_files", "List files and directories in a local project directory. 返回目录条目。", true, func(_ context.Context, in listInput) (listOutput, error) { return p.list(in.Path, in.Limit) })
	tool(s, "read_file", "Read a UTF-8 project file and its SHA-256 version. 读取文件内容和版本。", true, func(_ context.Context, in pathInput) (fileOutput, error) { return p.read(in.Path) })
	tool(s, "search_files", "Recursively search literal text in project files. Does not follow symlinks. 搜索文件内容。", true, func(ctx context.Context, in searchInput) (searchOutput, error) {
		return p.search(ctx, in.Path, in.Query, in.Limit)
	})
	if !p.readOnly {
		tool(s, "write_file", "Create or replace a UTF-8 project file. Existing files require expected_sha256 from read_file. 新建或覆盖文件。", false, func(_ context.Context, in writeInput) (fileOutput, error) {
			return p.write(in.Path, in.Content, in.ExpectedSHA256)
		})
		tool(s, "edit_file", "Precisely replace text in a project file using its expected_sha256 version. 精确替换文件文本。", false, func(_ context.Context, in editInput) (fileOutput, error) {
			return p.edit(in.Path, in.OldText, in.NewText, in.ExpectedSHA256, in.ReplaceAll)
		})
		tool(s, "create_directory", "Create a directory and missing parents inside the project. 创建目录。", false, func(_ context.Context, in pathInput) (map[string]bool, error) {
			err := p.mkdir(in.Path)
			return map[string]bool{"ok": err == nil}, err
		})
		tool(s, "delete_file", "删除普通 UTF-8 文件，必须提供 expected_sha256；禁止目录、根目录 .git 及其内部路径和符号链接；子目录 .git 不受保护规则限制。", false, func(_ context.Context, in deleteInput) (map[string]bool, error) {
			err := p.deleteFile(in.Path, in.ExpectedSHA256)
			return map[string]bool{"ok": err == nil}, err
		})
		tool(s, "move_file", "移动或重命名普通 UTF-8 文件，必须提供源文件 expected_sha256；目标必须不存在，父目录必须已存在；禁止目录、根目录 .git 及其内部路径和符号链接；子目录 .git 不受保护规则限制。", false, func(_ context.Context, in moveInput) (moveOutput, error) {
			return p.moveFile(in.Source, in.Destination, in.ExpectedSHA256)
		})
	}
	return s
}

func newHandler(p *project, token string, origins []string, publicHost string, oauth ...*oauthServer) http.Handler {
	var auth *oauthServer
	if len(oauth) > 0 {
		auth = oauth[0]
	}
	if auth != nil {
		origins = append(slices.Clone(origins), auth.issuer)
	}
	s := newMCP(p)
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: p.maxBytes*6 + (1 << 20),
		// 由下面的 Host 白名单替代 SDK 只允许 localhost 的检查，兼容隧道保留公网 Host。
		DisableLocalhostProtection: true,
	})
	mux := http.NewServeMux()
	if auth != nil {
		auth.mount(mux)
	}
	mux.Handle("/mcp", transport)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && (publicHost == "" || !strings.EqualFold(host, publicHost)) {
			http.Error(w, "不允许的 Host；请通过 -public-host 指定公网域名", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			allowed := false
			for _, candidate := range origins {
				if strings.TrimSpace(candidate) == origin {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "不允许的 Origin", http.StatusForbidden)
				return
			}
		}
		if auth != nil && r.URL.Path == "/mcp" {
			scheme, value, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			if !strings.EqualFold(scheme, "Bearer") || !auth.validAccess(value) {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+auth.issuer+`/.well-known/oauth-protected-resource/mcp", scope="mcp"`)
				oauthError(w, 401, "invalid_token", "需要 OAuth 授权，请在 Gemini 中连接此应用")
				return
			}
		}
		if auth == nil && token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "需要有效的 Bearer Token", http.StatusUnauthorized)
			return
		}
		// 给 JSON 转义留出空间，同时限制单次请求内存占用。
		r.Body = http.MaxBytesReader(w, r.Body, p.maxBytes*6+(1<<20))
		mux.ServeHTTP(w, r)
	})
}
