# 本地项目文件 MCP

用 Go 编写的本地文件 MCP 服务，使用官方 MCP Go SDK 和 Streamable HTTP。启动时通过 `-root` 指定唯一允许访问的目录，可通过 gost 转发至服务器的 HTTPS 端点，供 Gemini 网页版的自定义应用使用。

## 编译和启动

目前面向 Linux，需要 Go 1.25 或更新版本。

```bash
cd "$HOME/dev/go/local-files-mcp"
go build -buildvcs=false -o bin/local-files-mcp .
./bin/local-files-mcp -root "$HOME/dev/js/你的项目"
```

默认监听 `127.0.0.1:8765`。`-root` 必填，目录必须已经存在；所有工具只接收此目录下的相对路径。重启并更改 `-root` 即可切换项目。

```bash
./bin/local-files-mcp -root /绝对路径/项目 -listen 127.0.0.1:8765
./bin/local-files-mcp -root /绝对路径/项目 -read-only
./bin/local-files-mcp -help
curl http://127.0.0.1:8765/healthz
```

## 通过 gost 接入 Gemini

将服务器上的 HTTPS 地址转发到运行本程序的机器的 `127.0.0.1:8765`，保留请求路径和请求头。在 Gemini 的 Add a custom app 中填写：

```text
https://mcp.example.com/mcp
```

如果反向代理保留公网域名作为 Host，启动时同时指定域名：

```bash
./bin/local-files-mcp -root /绝对路径/项目 -public-host mcp.example.com
```

默认 Host 白名单只允许 `localhost`、`127.0.0.1` 和 `::1`；`-public-host` 额外允许一个公网域名。也可以在反向代理中将上游 Host 改为 `localhost`。

本程序提供 HTTP；TLS 由服务器上的反向代理终止。`/mcp` 使用无状态 Streamable HTTP，响应是 JSON，不依赖会话粘滞；客户端对这个端点发送 POST 请求，GET 返回 405 是正常行为。`/healthz` 用于健康检查。

Gemini 网页版的认证使用下方内置 OAuth，无需另装认证网关。未传入 `-oauth-issuer` 且未设置 `LOCAL_FILES_MCP_TOKEN` 时仍为无认证模式，能访问该端点的调用方可以读写整个指定目录。

部署后应验证 OAuth 授权、受保护的文件操作及公网转发。

默认只接受 `https://gemini.google.com` 这个 Origin，同时允许没有 Origin 的服务端请求。额外的 Origin 可通过 `-allowed-origins` 用逗号分隔传入。此检查用于阻止其他网页直接调用，不替代身份认证；本程序不提供浏览器跨域 CORS 接口。

## 启用 Gemini OAuth

实现依据为 [Google 的 OAuth 接入指南](https://developers.google.com/connected-apps/mcp/oauth)和 [MCP 授权规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)。支持动态客户端注册、S256 PKCE、授权确认、令牌刷新、撤销和磁盘持久化。

首次启动前，设置一个至少 12 字节的本地授权密码。密码用于服务自身的授权页面，不是 Google 密码；输入不会回显，也不会作为命令参数记录。

```bash
cd "$HOME/dev/go/local-files-mcp"
unset LOCAL_FILES_MCP_TOKEN
read -rsp '设置本地服务授权密码（至少 12 字节）：' LOCAL_FILES_MCP_PASSWORD
printf '\n'
export LOCAL_FILES_MCP_PASSWORD

./bin/local-files-mcp \
  -root "/你的项目绝对路径" \
  -oauth-issuer "https://mcp.example.com" \
  -oauth-state "$HOME/dev/.local-files-mcp/my-project/oauth.json"
```

`-oauth-issuer` 必须是域名根路径的 HTTPS 地址，不带 `/mcp`。开启 OAuth 后会自动把这个域名加入 Host 白名单，并允许授权页面自身的 Origin。通常无需再传 `-public-host`。

`-oauth-state` 必须位于允许访问的项目目录之外。程序自动创建权限为 `700` 的独立目录，状态文件权限为 `600`；已有目录如果权限不符会拒绝启动。不要将状态目录放入可被其他 MCP 实例访问的项目中。状态文件只保存密码、客户端密钥和令牌的哈希，不保存这些秘密的原文。

后续重启只需使用相同参数，无需再次设置密码环境变量；授权页面继续使用首次设定的密码。已存在状态文件时，重新设置环境变量不会修改密码。状态绑定公网地址、项目路径和只读设置；切换其中任何一项时使用另一份状态文件。一个状态文件同时只允许一个进程使用。

### 配置转发与 Gemini

服务器必须把下面所有路径转发到同一个本地服务，不能只转发 `/mcp`：

| 路径 | 用途 |
| --- | --- |
| `/mcp` | 需要访问令牌的 MCP 接口 |
| `/.well-known/oauth-authorization-server` | OAuth 授权服务器元数据 |
| `/.well-known/oauth-protected-resource` | MCP 资源元数据 |
| `/.well-known/oauth-protected-resource/mcp` | MCP 资源元数据的路径形式 |
| `/oauth/register` | 动态注册客户端 |
| `/oauth/authorize` | 密码验证与授权确认 |
| `/oauth/token` | 交换授权码和刷新令牌 |
| `/oauth/revoke` | 撤销授权 |
| `/healthz` | 不含项目信息的健康检查 |

转发时保留路径、查询参数、POST 请求体、`Authorization` 和 Cookie。TLS 在服务器终止，本地仍使用 HTTP；不要给 OAuth 路径额外套一层需要网页登录的认证，否则 Gemini 后端无法发现或交换令牌。授权页 Cookie 使用 `Secure`，必须通过公网 HTTPS 地址打开。

在 Gemini 网页版操作：

1. 打开 Add a custom app，填写 `https://mcp.example.com/mcp`。
2. 使用动态客户端注册，Client ID 和 Client Secret 无需手填，由 Gemini 自动获取。
3. 打开的授权页会显示客户端声明名称、权限和 Google 回调地址。输入首次设置的本地授权密码，点击确认授权。
4. 授权成功或取消后，结果页会自动导航回 Gemini；若浏览器没有自动跳转，点击“继续返回 Gemini”链接。返回后保存应用，使用 `@应用名` 调用工具。

程序仅接受 Google 官方 OAuth 回调域名中 `/r/` 和 `/a/` 下的地址，并在注册后对完整回调 URI 精确匹配。仅填写用户名密码到 Gemini 的高级设置不能代替上述授权流程。

### systemd 部署示例

[服务示例](deploy/local-files-mcp.service)是系统服务，建议使用专用非 root 用户 `local-files-mcp`。先由管理员创建该用户，并给予它项目所需的读写权限和程序目录的读取、执行权限；再准备其拥有的私密目录和必选环境文件：

```bash
sudo install -d -m 700 -o local-files-mcp -g local-files-mcp /var/lib/local-files-mcp
sudo install -m 600 -o local-files-mcp -g local-files-mcp /dev/null /var/lib/local-files-mcp/oauth.env
sudoedit /var/lib/local-files-mcp/oauth.env
```

首次启动前在文件中填写 `LOCAL_FILES_MCP_PASSWORD="你的至少 12 字节本地授权密码"`，不要复用其他账号口令。环境文件是 systemd 的赋值语法，特殊字符按 systemd 规则引用，不运行 shell 命令。完成首次初始化后可清空密码赋值，但保留这个权限为 `600` 的文件；已有状态不会因此改密码。不要对已有环境文件重复执行上面的 `install /dev/null`，它会清空内容。

按本机路径调整服务的 `WorkingDirectory`、`ExecStart` 和 `EnvironmentFile` 后，将示例安装到 `/etc/systemd/system/`，使用 `sudo systemctl daemon-reload` 和 `sudo systemctl enable --now local-files-mcp`。示例的 `EnvironmentFile=/var/lib/local-files-mcp/oauth.env` 是必选文件，缺失会阻止启动；只有 `EnvironmentFile=-/路径` 才是可选语法，不建议首次部署直接改为可选而遗漏密码初始化。

若使用用户服务，则放入 `~/.config/systemd/user/`，删除 `User`、`Group`，改用当前用户拥有的程序、项目和状态路径，把安装目标改为 `default.target`，使用 `systemctl --user` 管理。系统服务与用户服务的身份、目录权限和环境互不等同。

[nginx 发现端点配置](deploy/nginx-oauth-discovery.conf)仅补充三个元数据路径，仍须另行配置 `/mcp` 和 `/oauth/` 的上游转发；它不能替代完整代理配置。

### 令牌生命周期

- 授权请求有效期为 5 分钟，授权码有效期为 2 分钟且只能使用一次。
- 访问令牌有效期为 1 小时，限定当前服务的 `mcp` 权限。
- 刷新令牌有效期为 90 天，每次刷新延长有效期。机密客户端保留原刷新令牌以兼容 Google 的持久关联；公共客户端采用刷新令牌轮换；重放已消费的旧令牌会撤销整个关联授权。消费哈希最多保存 4096 条，保留至原刷新令牌到期或授权撤销，重启后继续生效。达到记录上限时拒绝新轮换，不淘汰仍有效的记录。
- 调用撤销接口会同时撤销关联的访问令牌和刷新令牌；在 Gemini 取消关联时可使用这个接口。
- 密码尝试和动态注册有速率限制；最多保留 256 个客户端、512 个授权和 2048 个未清理令牌。过期授权和令牌在后续 OAuth 操作中清理。无活动授权、有效待授权请求或未兑换授权码的客户端，闲置 7 天后回收；旧状态升级时给予完整的 7 天宽限期。每个客户端最多有 4 个待授权请求，服务总计最多 128 个；注册和密码限流为服务级，不信任任意 `X-Forwarded-For`。注册元数据按序列化后的实际大小限制为 2 MiB，为授权及令牌预留空间；完整状态读写均不得超过 8 MiB，保存失败会回滚。
- 重启后保留客户端、授权和令牌。正在进行的登录请求和未交换的授权码不持久化，重启后需要重新连接。

### 排查连接

```bash
curl -i https://mcp.example.com/.well-known/oauth-authorization-server
curl -i https://mcp.example.com/.well-known/oauth-protected-resource/mcp
curl -i https://mcp.example.com/mcp
```

前两个应返回 `200` 和 JSON；未携带令牌访问 `/mcp` 应返回 `401`，并包含带 `resource_metadata` 的 `WWW-Authenticate` 头。如果是代理产生的 `404`、HTML 登录页，或只看到 `Bearer` 而没有元数据地址，先检查转发范围和是否启动了最新程序。Gemini 开发者模式中的 Authentication 和 Event Log 可查看连接错误。

## 普通客户端的静态 Token

不使用 OAuth 的普通 MCP 客户端可通过环境变量 `LOCAL_FILES_MCP_TOKEN` 启用固定 Bearer Token，并发送 `Authorization: Bearer ...` 请求头。此模式下 `/healthz` 同样要求 Bearer 认证，健康检查需携带请求头。这个模式不能与 OAuth 同时启用，也不等同于 Gemini 的 Client ID 和 Client Secret。不要由公开网关无条件注入固定 Token 后转发所有请求。

## 可用工具

| 工具 | 参数与行为 |
| --- | --- |
| `list_files` | `path` 默认为 `.`，`limit` 默认为 200，最多 2000；返回单层目录，`truncated` 表示结果截断 |
| `read_file` | `path`；返回完整 UTF-8 内容及 `sha256` |
| `search_files` | `query`、可选 `path` 和 `limit`；递归搜索区分大小写的字面文本，返回路径、行号和匹配行 |
| `write_file` | `path`、`content`、`expected_sha256`；新建文件时省略版本，覆盖时必须传入读取到的版本 |
| `edit_file` | `path`、`old_text`、`new_text`、`expected_sha256`；默认要求唯一匹配，`replace_all: true` 可替换全部 |
| `create_directory` | `path`；递归创建缺失的目录 |

只读模式只注册前三个工具。写文件前父目录必须存在，必要时先调用 `create_directory`。

建议给 Gemini 的指令：

```text
使用这个自定义应用操作项目。先查看目录，再读取需要修改的文件。
修改已有文件时，把 read_file 返回的 sha256 作为 expected_sha256。
优先使用 edit_file 做精确替换，所有路径使用项目目录内的相对路径。
```

## 目录边界和资源限制

- 文件操作通过 Go 的 `os.Root` 完成，拒绝绝对路径、`..` 和越界符号链接。读取允许指向目录内的相对符号链接；写入拒绝以符号链接作为最终目标。搜索不跟随符号链接。
- 单文件默认最大 2 MiB，可用 `-max-file-bytes` 修改，最多 16 MiB。仅支持 UTF-8 文本，拒绝包含 NUL 的二进制内容和 FIFO 等特殊文件。
- 写入使用同目录临时文件和原子替换，新文件权限为 `0600`，覆盖时保留原文件的普通权限位；不会沿着已有硬链接原地覆盖其他位置的同一文件。文件所有者、ACL 和扩展属性不保证保留。
- 同一进程中的工具修改串行执行，过期的 SHA-256 会被拒绝。外部编辑器不受进程锁控制，读取校验与原子替换之间仍可能发生竞争，因此该校验不是跨进程事务。
- 搜索最多访问 20000 个条目、累计实际读取最多 32 MiB（包括非文本和超限文件）；默认返回 100 个匹配行，最多 1000 行，每行最多展示约 2000 字节。`truncated` 表示提前停止，`skipped` 统计已遇到但因格式、类型、读取错误或预算不足跳过的文件或目录，不统计尚未遍历的条目。Linux 搜索通过 `/proc/self/fd` 固定已打开的目录句柄，运行环境需提供 procfs。目录以每批 128 个条目读取，不保证排序；取消会停止后续读取并释放搜索锁。搜索包含隐藏文件，不解释 `.gitignore`。
- 目录限制不是容器隔离：指定目录内已有的挂载点及硬链接仍属于可访问内容。应指定具体项目目录，避免把系统目录作为根目录。

## 验证

```bash
go test -race ./...
go vet ./...
go build -buildvcs=false -o bin/local-files-mcp .
markdownlint-cli2 --config ".markdownlint.json" "README.md"
npx --yes @lint-md/cli --config ".lintmdrc" "README.md"
```

测试覆盖目录越界、符号链接、硬链接写入、特殊文件、UTF-8、文件大小限制、并发版本检查，以及 HTTP 上的 MCP 初始化、工具发现和读写流程。OAuth 测试覆盖元数据发现、动态注册、密码与浏览器校验、PKCE、回调地址和资源绑定、授权码防重放、机密与公共客户端刷新、过期、持久化、撤销，以及访问令牌调用文件工具。

浏览器导航回归位于 `scripts/oauth-navigation-smoke.mjs`。先完成上述编译，再通过本机统一 Playwright 工具目录运行；脚本默认从仓库的 `bin/local-files-mcp` 启动合成服务，可用 `OAUTH_SMOKE_BINARY` 指定其他测试构建：

```bash
export PLAYWRIGHT_BROWSERS_PATH="$HOME/dev/tools/playwright-browsers"
export PLAYWRIGHT_MODULE="$HOME/dev/tools/playwright-global/node_modules/playwright/index.mjs"
# 若本机统一工具使用隔离的系统库，沿用其 run.sh 的共享库路径。
if [ -d "$HOME/dev/tools/playwright-system-deps/root" ]; then
  export LD_LIBRARY_PATH="$HOME/dev/tools/playwright-system-deps/root/usr/lib/x86_64-linux-gnu:$HOME/dev/tools/playwright-system-deps/root/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
node scripts/oauth-navigation-smoke.mjs
```

脚本需要 Node.js、openssl 和本机既有 Playwright，不给业务项目安装依赖。它在仓库 `bin` 下创建并清理临时项目、随机口令和授权状态，通过 Chromium 的主机映射将 Google 与 Gemini 的模拟回调导向本地 HTTPS 服务，不使用账号或真实项目。测试只覆盖本机 Chromium 的自动跳转、手动返回、Origin、state 和 PKCE，不代表所有浏览器均兼容。
