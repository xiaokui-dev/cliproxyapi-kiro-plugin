# Kiro Provider —— CLIProxyAPI 插件

把 **Kiro OAuth 账号**当作 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的上游，
对客户端暴露为标准 **Claude Messages** 接口。插件以 CGO 动态库（`.dylib` / `.so` / `.dll`）形式
被宿主 `dlopen` 加载。

## 功能概览

| 能力 | 说明 |
|---|---|
| OAuth 账号接入 | 声明为 `auth_provider`，识别并托管 Kiro 凭据；宿主按 `refresh_interval_seconds` 自动刷新 token |
| 设备码登录 | AWS Builder ID、组织 IAM Identity Center（IdC）走 OIDC 设备码流程，在宿主管理页发起 |
| Social 导入 | Google / GitHub 账号暂不支持交互登录（受上游 Cognito 回调白名单限制），支持导入现成凭据并自动刷新 |
| 按账号发现模型 | `model.for_auth` 调用 Kiro `ListAvailableModels`，返回**该账号实际可用**的模型，出现在 `GET /v1/models` |
| 非流式对话 | Claude Messages → CodeWhisperer → Claude message，含工具调用与图片输入 |
| 流式对话 | 输出标准 Claude SSE 事件序列（`message_start` / `content_block_*` / `message_delta` / `message_stop`） |
| 用量查询 | 注册 Management API 路由 `GET /v0/management/kiro-usage`，聚合所有 Kiro 凭据的额度 |

## 工作流程

```
客户端 (Claude / OpenAI / Gemini 协议)
      │
      ▼
CLIProxyAPI 宿主  ──(统一转成 Claude Messages)──▶  kiro 插件
      ▲                                              │
      │                                              ▼
      │                              Claude → CodeWhisperer 请求体
      │                                              │
      │                                              ▼
      │                      q.<region>.amazonaws.com/generateAssistantResponse
      │                                              │
      │                              AWS event-stream 帧解析 + 聚合
      └────────(Claude message / SSE)───────────────┘
```

- 宿主已声明会把 openai、gemini 等协议**先转成 Claude** 再交给插件，插件只需处理 Claude 格式。
- 插件回调宿主时统一走 `host.http.do`（复用宿主的 transport / 代理 / 日志），凭据由宿主管理。

## 构建

需要 **Go 1.21+** 与本机 C 工具链（CGO）。在仓库根目录执行：

```bash
gofmt -w .
go test ./...
go vet ./...

# macOS（本机架构，如 arm64）
CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dylib .

# Linux（需在相同 GOOS/GOARCH 的机器或交叉环境上编）
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.so .

# Windows
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dll .
```

> 产物文件名必须是 **`kiro`**（等于插件 ID / `plugin.register` 的 Name），与仓库名无关，不要改。

## 安装到 CLIProxyAPI

### 两个硬约束

1. **宿主必须以 `CGO_ENABLED=1` 构建**，才能 `dlopen` 插件；`CGO_ENABLED=0` 的静态二进制加载不了任何插件。
   —— 判断办法：请求宿主任意端点，看响应头是否有 `X-Cpa-Support-Plugin: 1`。
2. **插件的 `GOOS/GOARCH` 必须与运行宿主一致**。

### 放置动态库

把构建（或从 Release 下载解压）得到的动态库放到宿主插件目录，按平台分目录：

```
plugins/<goos>/<goarch>/kiro.dylib     # macOS，例如 plugins/darwin/arm64/kiro.dylib
plugins/<goos>/<goarch>/kiro.so        # Linux，例如 plugins/linux/amd64/kiro.so
plugins/<goos>/<goarch>/kiro.dll       # Windows
```

### 启用与配置

在宿主 `config.yaml` 中启用插件：

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    kiro:
      enabled: true
      login_method: "AWS Builder ID"   # 登录方式，见下表
      region: us-east-1                # CodeWhisperer 默认区域
```

插件配置字段（`plugins.configs.kiro.*`）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `login_method` | 枚举 | 登录方式：`AWS Builder ID` / `IDC` / `Google` / `GitHub`。留空时回退旧启发式（填了 `start_url` 走 IDC，否则 Builder ID）。 |
| `region` | 字符串 | CodeWhisperer 端点默认 AWS 区域（默认 `us-east-1`），所有登录方式通用。 |
| `start_url` | 字符串 | **仅 IDC 需要**：组织 IAM Identity Center 门户 URL（如 `https://d-xxxx.awsapps.com/start`）。 |
| `idc_region` | 字符串 | **仅 IDC 需要**：组织 IdC OIDC 端点区域（留空回退 `region`，再回退 `us-east-1`）。 |
| `base_url` | 字符串 | 可选：覆盖 `generateAssistantResponse` 端点 URL，一般无需填写。 |

### 登录 / 提供凭据

- **AWS Builder ID**：设 `login_method: "AWS Builder ID"`，保存配置后到宿主「Kiro OAuth」页发起设备码登录，
  浏览器授权即可，无需其它字段。
- **IDC（组织 IAM Identity Center）**：设 `login_method: "IDC"` 并填 `start_url`（必填）、`idc_region`，
  保存后同样在「Kiro OAuth」页发起设备码登录。
- **Google / GitHub**：暂不支持交互登录，请在 **Kiro 桌面应用**登录后导出凭据 JSON，放入宿主 `auth-dir`。
  JSON 需包含 `accessToken`、`refreshToken`、`profileArn`、`authMethod`（=`social`）、`region`（通常 `us-east-1`）；
  导入后插件会经 Kiro auth service 自动刷新。

登录成功后验证：

```bash
curl -s http://127.0.0.1:8317/v1/models | grep -i claude    # 能看到该账号可用的 Kiro 模型
```

用量查询（需先在宿主配置 `remote-management.secret-key`）：

```bash
curl -s -H "Authorization: Bearer <management-key>" \
  http://127.0.0.1:8317/v0/management/kiro-usage
```

## 许可证

[MIT](./LICENSE)
