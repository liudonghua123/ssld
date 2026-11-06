# ssld

**SSL 证书全生命周期控制平面，用 Rust 完整重写 allinssl。**

仓库：<https://github.com/liudonghua123/ssld> · [English](README.en.md) · [MIT](LICENSE)

ssld 对照 allinssl 的全部业务模块重新实现：ACME 签发、DNS-01、证书仓库、凭据与 EAB、ACME 账户、通知渠道、工作流编排、部署目标、监控告警、私有 CA、插件体系、系统设置与概览审计。在此之上补齐了三件事：开放的完整 REST API、面向 AI 助手的高层粗粒度 MCP 服务、以及可配置的 Webhook 事件系统。

按照需求，**不包含 allinssl 的命令行服务控制功能**（数字菜单、服务启停/重启、改端口、改密码、安全入口设置、卸载更新等）。配置全部走配置文件、环境变量或设置 API；停止进程请交给进程管理器（systemd / Docker / Supervisor）。

| 指标 | 数值 |
| --- | --- |
| REST 端点 | 103 |
| MCP 粗粒度工具 | 15 |
| 兼容的 allinssl 原始 `/v1/{group}/{action}` 动作 | 71 |
| DNS 服务商 / 主机凭据 / 部署目标 | 25 / 18 / 32 |
| CA / 密钥算法 / 通知渠道 / 事件类型 | 9 / 6 / 5 / 44 |
| 工作流节点类型 / 导出格式 | 12 / 5 |
| 语言与依赖 | Rust 2021，运行时零外部数据库 |

![ssld 控制台](docs/screenshots/console-desktop.jpg)

<details>
<summary>平板与手机视图</summary>

![平板](docs/screenshots/console-tablet.jpg)
![手机](docs/screenshots/console-mobile.jpg)

</details>

---

## 快速开始

```bash
git clone https://github.com/liudonghua123/ssld.git
cd ssld
cargo build --release
./target/release/ssld        # Windows: target\release\ssld.exe
```

需要 Rust stable（edition 2021）。首次构建会编译依赖，之后 `cargo build --release` 即可。

服务默认监听 `0.0.0.0:7979`，启动后终端会打印：

```
  Console   http://0.0.0.0:7979/
  REST API  http://0.0.0.0:7979/api/v1/health   (103 endpoints)
  MCP       http://0.0.0.0:7979/mcp            (15 coarse tools)
  Events    http://0.0.0.0:7979/api/v1/events/stream
  State     data/state.json
```

本地开箱即用：未设置 `SSLD_API_KEY` 且未显式开启 `SSLD_AUTH_REQUIRED` 时，控制台与 REST API 不强制鉴权。**部署到公网前必须**设置 `SSLD_API_KEY` 或 `SSLD_AUTH_REQUIRED=1`。

```bash
# 生产示例：开启鉴权、改端口、指定数据目录
SSLD_API_KEY='change-me' SSLD_PORT=9443 SSLD_DATA_DIR=/var/lib/ssld ./target/release/ssld

# 健康检查
curl http://127.0.0.1:7979/api/v1/health

# 直接在 MCP 上调用高层工具
curl -s http://127.0.0.1:7979/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fleet_overview","arguments":{}}}'
```

启动参数只有 `--config` / `--port` / `--bind` / `--data-dir` / `--version` / `--help`，没有任何服务控制子命令。

---

## 功能覆盖

| 域 | 实现内容 |
| --- | --- |
| ACME v2 | 自实现 directory / nonce / JWS(ES256) / 账户注册 / EAB / newOrder / DNS-01 / finalize / 证书下载 / RFC 9773 ARI 续期提示与 `replaces` |
| DNS-01 | Cloudflare、acme-dns、Webhook DNS 原生适配；其余云厂商走统一签名 HTTP 层（HMAC-SHA1 查询签名、TC3、AWS SigV4、Bearer、Basic、API Key）；自定义 nameserver 的 UDP TXT 传播校验 |
| 证书 | 导入、解析（SAN/链/指纹/算法）、预览、复用、过期扫描、ZIP/PEM/DER 导出、PFX/JKS 外部转换、批量续期 |
| 部署 | localhost、SSH、Webhook、插件、宝塔/1Panel/SafeLine/LeCDN、腾讯云、阿里云、七牛、百度、华为、火山、Doge、RainYun 等 32 类目标；支持前置/后置命令与幂等跳过 |
| 凭据 | DNS / 主机凭据、EAB、ACME 账户、脱敏展示、连通性测试、站点列表、密钥轮换 |
| 通知 | 邮件、Webhook、钉钉、飞书、企业微信；占位符、DingTalk/Feishu 签名、多账号告警、测试发送 |
| 工作流 | 嵌套节点树、顺序/并行分支、条件分支、执行结果分支、节点输入输出、执行历史与节点日志、手动与计划调度、一键生成证书流水线 |
| 监控 | HTTPS / SMTPS 探测、证书链解析、过期阈值、异常记录、告警抑制、CSV/JSON 批量导入与模板 |
| 私有 CA | Root → Intermediate → Leaf 三级；RSA / ECDSA / SM2（SM2 双证书经外部 openssl）；root 禁止直签 leaf、leaf 有效期不得超过中间 CA、删除约束 |
| 插件 | module 插件（plugin.json / metadata.json 扫描、启用停用、动作与元数据）与 deploy 插件（stdin/stdout 协议） |
| 系统 | 概览与推荐动作、安全审计、操作日志、备份恢复、OpenAPI 索引、兼容网关、登录锁定、验证码、安全入口、API 签名 |
| Webhook | 事件过滤与通配符、HMAC-SHA256 签名、自定义 header 与 body 模板、重试与退避、投递台账、测试发送、重放、统计 |
| 界面 | 单文件式动态控制台，单一 `requestAnimationFrame` 时钟驱动 KPI 计数、runway 扫描、流水线脉冲、健康环扫过、SSE 实时事件流；浅/深色主题跟随系统、双语、响应式、尊重 `prefers-reduced-motion` |

---

## 配置

配置文件默认为 `config/ssld.json`（不存在时用内置默认值），完整示例见 [`config/ssld.example.json`](config/ssld.example.json)。环境变量优先级最高：

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `SSLD_CONFIG` | 配置文件路径 | `config/ssld.json` |
| `SSLD_BIND` / `SSLD_PORT` | 监听地址 / 端口 | `0.0.0.0` / `7979` |
| `SSLD_DATA_DIR` | 状态目录 | `data` |
| `SSLD_API_KEY` | 开放 API 静态密钥，设置后自动强制鉴权 | 空 |
| `SSLD_AUTH_REQUIRED` | 设为 `1` 强制鉴权 | 关 |
| `SSLD_ADMIN_USER` / `SSLD_ADMIN_PASSWORD` | 控制台管理员 | `admin` / `ssld` |
| `SSLD_SECURE_ENTRY` | 安全入口路径 | `/`（关闭） |
| `SSLD_HTTPS` | 启用 HTTPS（配合配置里的 `tls_cert` / `tls_key`） | 关 |
| `SSLD_WEBHOOK_SECRET` / `SSLD_WEBHOOK_OFF` | 默认 Webhook 签名密钥 / 关闭分发 | 空 / 开 |
| `SSLD_MCP_PATH` | MCP 端点路径 | `/mcp` |
| `SSLD_TICK_SECONDS` / `SSLD_SCHEDULER_OFF` | 调度 tick / 关闭调度器 | `10` / 开 |

运行时也可以通过 `PUT /api/v1/settings` 修改设置，无需重启。`config/ssld.json` 与 `data/` 下的状态、日志、证书私钥均已被 `.gitignore` 排除，请从示例文件复制后本地填写，不要提交真实凭据。

### 鉴权方式

- **本地模式**（默认）：无 API key 且不强制鉴权，开箱即用。
- **Bearer / Cookie**：`POST /api/v1/auth/login` 返回 token 并下发 `ssld_session` Cookie。
- **API 签名**：兼容层的 `api_token` + `timestamp` 支持两种方式：
  `sha256(timestamp + sha256(api_key))`，或 `base64(HMAC-SHA256(api_key, timestamp + "." + sha256(api_key)))`。

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/API.md](docs/API.md) | 103 个 REST 端点分组参考、统一响应封装、兼容性网关、鉴权 |
| [docs/MCP.md](docs/MCP.md) | 15 个高层 MCP 工具、资源、JSON-RPC 调用示例与接入方式 |
| [docs/WEBHOOKS.md](docs/WEBHOOKS.md) | 订阅字段、事件与通配符、签名校验、模板、重试、重放与统计 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 模块地图、数据模型、ACME 流程、工作流与调度、存储与安全边界 |
| [README.en.md](README.en.md) | English README |
| [tests/smoke.js](tests/smoke.js) | 端到端冒烟测试脚本 |

---

## 验证结果

在 Windows / Rust stable / MSVC 上完成：

- `cargo check`、`cargo build`：**0 error、0 warning**。
- 前端设计检查（仓库外的设计评审脚本，不随源码分发）：静态规范检查 **0 FAIL**；1440 / 768 / 390 三档视口检查 **0 FAIL、0 WARN**。
- 端到端冒烟测试 `node tests/smoke.js [port]`：**38 / 38 通过**（在全新空状态与使用示例配置下运行），覆盖服务与静态资源、私有 CA 三级与约束、证书导入与 SAN、ZIP 导出、工作流构建与执行、监控批量导入、兼容网关、CLI 控制动作返回 410、Webhook 与事件词表、审计与备份恢复、MCP 工具列表及 5 个高层工具。
- Webhook 专项：签名（与 `crypto.createHmac` 逐字节比对 VALID）、事件过滤（不匹配事件不投递）、自定义 header、模板渲染、投递台账、测试发送、重放、统计、SSE 实时广播全部通过。

### 已知边界

- 状态持久化采用单文件 JSON 原子快照（无 SQLite / 外部数据库），适合单机中小规模；超大规模部署应替换为数据库后端。
- `openssl` / `keytool` 仅在 PFX / JKS / SM2 双证书转换时按需调用，主体逻辑为纯 Rust。
- ACME 只提供 DNS-01（与 allinssl 一致），不支持 HTTP-01 与自定义 CSR。
- 申请真实证书需要有效的 DNS 凭据与网络可达的 ACME CA；冒烟测试使用私有 CA 签发的证书，不触发真实 ACME 下单。

---

## License

[MIT](LICENSE)
