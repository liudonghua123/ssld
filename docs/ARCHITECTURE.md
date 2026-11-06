# 架构说明 / Architecture

## 设计目标

1. **API 完整**：11 个路由分组、15 张数据表对应的全部业务模块均提供 REST 路径。
2. **无 CLI 控制面**：所有配置通过文件 / 环境变量 / 设置 API 完成，服务只负责运行。
3. **API 优先**：每个能力都有一条 REST 路径，MCP、兼容网关、Web 控制台都调用同一服务层。
4. **单一事件漏斗**：所有状态变化产生一个事件，事件日志、SSE、Webhook 三者共享。
5. **零外部运行时依赖**：不需要数据库服务器；原生库依赖为 0（仅 PFX/JKS/SM2 转换时按需调用外部二进制）。

---

## 进程结构

```
                    ┌──────────────────────────────────────────┐
   Browser  ──────▶ │  /  /app.js  /styles.css  (include_str!) │
   MCP client ────▶ │  /mcp                JSON-RPC 2.0        │
   REST client ───▶ │  /api/v1/*            103 endpoints      │
   Legacy client ▶│  /v1/{group}/{action}  gateway        │
                    └──────────────────┬───────────────────────┘
                                       │ auth_middleware (Arc<Core>)
                    ┌──────────────────▼───────────────────────┐
                    │             Service layer                │
                    │ certs · acme · dns · deploy · notify     │
                    │ workflow · monitor · private_ca · access │
                    │ plugin · webhook · overview · scheduler  │
                    └──────────────────┬───────────────────────┘
                                       │ Core::emit(event, source, payload)
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
       event_log (JSON)        EventBus (broadcast)     webhook::spawn_dispatch
                                     │                        │
                                     ▼                        ▼
                            SSE /events/stream        signed HTTP + retries
```

`Core` 是唯一的共享状态（`Arc<Core>`），持有 `Store`、`Config`、事件总线、复用的 `reqwest::Client` 与启动时间。`emit()` 是唯一事件入口，保证任何调用方都不会漏掉日志、实时推送或 Webhook。

---

## 模块地图（27 个 Rust 源文件，约 6,500 行）

| 模块 | 职责 |
| --- | --- |
| `main.rs` | 启动参数、配置加载、scheduler、HTTP/HTTPS 监听 |
| `config.rs` | 配置结构与环境变量覆盖 |
| `error.rs` | `AppError`、统一响应封装 `ok` / `created` / `message` |
| `models.rs` | 全部数据结构（证书、凭据、工作流、订阅、事件……） |
| `store.rs` | JSON 原子快照、`RwLock<Database>`、`next_id` / `trim` |
| `state.rs` | `Core`、`emit()`、操作日志 |
| `events.rs` | `tokio::sync::broadcast` 总线 |
| `providers.rs` | 能力注册表与事件匹配规则（API / UI / MCP 共用） |
| `api.rs` | 103 个 REST 端点、静态资源、SSE、OpenAPI、鉴权中间件 |
| `compat.rs` | 71+ 个原始 `/v1/{group}/{action}` 动作映射，CLI 控制动作返回 410 |
| `mcp.rs` | JSON-RPC 2.0、15 个粗粒度工具、4 个资源 |
| `webhook.rs` | 订阅规范化、模板渲染、签名、重试、投递台账、重放、统计 |
| `acme.rs` | 完整 ACME v2 客户端、JWS、EAB、ARI |
| `crypto.rs` | PEM/X.509 解析、CSR、CA/叶子签发、导出、HMAC、JWK |
| `dns.rs` | 25 个 DNS 适配、UDP TXT 传播校验 |
| `cloud.rs` | 云厂商统一签名 HTTP 层（HMAC-SHA1 / TC3 / SigV4 / Bearer / Basic / API Key） |
| `deploy.rs` | 32 个部署目标、before/after 命令、幂等跳过 |
| `certs.rs` | 证书仓库、导入导出、复用、ACME 申请高层入口 |
| `access.rs` | 凭据、EAB、ACME 账户、连通性测试与脱敏 |
| `notify.rs` | 5 类通知渠道与签名 |
| `workflow.rs` | 嵌套节点树执行器、分支、节点日志 |
| `monitor.rs` | HTTPS/SMTPS 探测、链解析、告警抑制、批量导入 |
| `private_ca.rs` | 三级 CA、SM2 双证书、约束校验 |
| `plugin.rs` | module 插件与 deploy 插件协议 |
| `overview.rs` | 首页聚合与推荐动作、安全审计 |
| `scheduler.rs` | 10 秒 tick：监控、计划工作流、过期扫描、日志清理 |
| `auth.rs` | session、登录锁定、验证码、安全入口、API 签名 |

前端为 `web/index.html` + `styles.css` + `app.js`（约 1,400 行），由 `include_str!` 编译进二进制，部署时只有一个可执行文件。

---

## 数据模型

`store.rs` 的 `Database` 含 15 个核心集合：

| 集合 | 对应原表 / 说明 |
| --- | --- |
| `users`、`sessions`、`settings` | `users`、`settings` + 运行期设置 |
| `access_types`、`accesses`、`eabs`、`acme_accounts` | `access_type`、`access`、`_eab`、`accounts` |
| `certs` | `cert`，增加来源、部署状态、SHA256 |
| `channels` | `report` 通知渠道 |
| `workflows`、`histories`、`workflow_deploys` | `workflow`、`workflow_history`、`workflow_deploy` |
| `monitors`、`err_records` | `monitor`、`err_record` |
| `cas`、`leaves` | `ca`、`leaf` |
| `webhooks`、`deliveries`、`event_log`、`plugins`、`oplogs`、`jobs` | ssld 新增：Webhook、事件、插件、审计、任务状态 |
| `counters` | 自增 id 分配 |

**持久化策略**：`Store::mutate()` 在写锁内修改内存 `Database`，然后写临时文件并原子 rename 到 `data/state.json`。启动时若文件损坏会先备份为 `state.corrupt.<ts>.json` 再重建。没有 SQLite / sqlx / 原生 C 依赖，因此在任何有 Rust 工具链的平台都能直接构建。

取舍：单机中小规模舰队非常适合；写入频繁或需要多节点共享时应替换为数据库后端（服务层已与存储解耦，替换面只在 `store.rs`）。

---

## ACME 签发流程

```
apply_certificate
  ├─ 解析 CA / 目录 URL，要求 EAB（Google / SSL.com / custom）
  ├─ 未强制时查找可复用证书（域名匹配 + 剩余有效期 > end_day）
  ├─ Acme::new          目录发现、nonce、账户密钥（P-256 / ES256）
  ├─ register           带可选 EAB JWS 的账户注册，落库复用 kid
  ├─ ARI                读取 renewalInfo，计算 certID，order 带 replaces
  ├─ newOrder           identifiers（通配符前缀去除）
  ├─ 每个 authz：
  │    ├─ 选 dns-01 challenge，计算 keyAuthorization 与 TXT 值
  │    ├─ dns::set_record  写入 TXT（原生或签名云 API）
  │    ├─ dns::txt_values  对配置的 nameservers 做 UDP TXT 传播校验
  │    ├─ POST challenge url
  │    └─ 轮询直到 valid / invalid
  ├─ finalize          提交 CSR（generate_csr）
  ├─ 下载证书链，拆分 leaf / issuer
  └─ 清理所有 TXT 记录 → save() → emit(cert.issued | cert.renewal.succeeded)
```

传播校验的 `None` 分支（所有 nameserver 都无响应）不会阻断签发，只发 `dns.check_unavailable` 并回退到 CA 侧校验，避免离线环境被卡死。

---

## 工作流与调度

`Workflow.content` 是嵌套 JSON 树：`child_node` 表示后继，`condition_nodes` 表示并行分支，`inputs` 把上游节点输出接到下游。执行器 `workflow::execute()` 递归 `run_node()`，按节点类型分派到 `certs::apply_certificate`、`deploy::deploy`、`notify::notify_many`、`private_ca::workflow_issue` 等服务；每个节点写 `NodeRun` 日志，整次运行写 `WorkflowHistory`。结果分支（`execute_result_branch`）根据上游成功/失败选择后继；部署节点通过 `workflow_deploys` 做幂等跳过。

`scheduler::start()` 每 10 秒（可配 `SSLD_TICK_SECONDS`）执行：到期监控探测、计划工作流（`exec_time` 的 day/week/month 匹配）、证书过期扫描、事件与投递日志清理。`POST /api/v1/renew-expiring` 与 MCP `renew_expiring` 复用同一批量续期逻辑。

---

## 安全边界

| 机制 | 实现 |
| --- | --- |
| 本地/生产模式 | 无 key 时免鉴权便于本机使用；设 `SSLD_API_KEY` 或 `SSLD_AUTH_REQUIRED=1` 后强制鉴权 |
| 登录 | 密码散列、失败计数锁定、验证码、安全入口 Cookie 标记 |
| 开放 API | `api_token` + `timestamp` 双 SHA-256 或 HMAC-SHA256 签名，带 300 秒时间窗与常量时间比较 |
| 敏感信息 | 凭据与 Webhook 密钥在列表接口脱敏为 `******`，更新时回填保留 |
| Webhook | HMAC-SHA256 签名、幂等键、可选跳过 TLS 校验（默认关闭） |
| 路径与路由 | axum 0.8 `{param}` 路由、静态资源 `include_str!` 不读磁盘 |
| 审计 | 所有变更写 `oplogs`，`GET /api/v1/audit` 给出风险清单 |

不在本实现范围内（按需求排除）：数字菜单式服务启停/重启、改端口、改密码、安全入口设置、卸载更新等 CLI 控制功能。这些动作在兼容网关里明确返回 `410 Gone`。

---

## 前端动效

单一 `requestAnimationFrame` 时钟驱动所有循环：KPI 计数、expiry runway 扫描线、流水线脉冲、健康环扫过、事件流淡入。`IntersectionObserver` 负责进入视口才启动的动效；`prefers-reduced-motion` 下全部关闭。SVG 图表的 viewBox 会按容器实际宽度重算并在 resize 时重绘，保证手机端标签维持真实字号。主题通过 `data-theme="system|light|dark"` 与 CSS 变量切换，界面文案中英双语。

设计验证（仓库外的设计评审脚本，不随源码分发）：静态规范检查 0 FAIL；1440 / 768 / 390 三档视口检查 0 FAIL、0 WARN。
