# MCP 服务 / MCP Server

ssld 在 `POST /mcp` 暴露符合 JSON-RPC 2.0 的 streamable HTTP MCP 服务（默认路径可用 `SSLD_MCP_PATH` 修改）。它不是把 103 个 CRUD 端点机械地包一层，而是提供 **15 个面向运维意图的粗粒度工具**：一次调用完成一个完整任务。

## 接入

```json
{
  "mcpServers": {
    "ssld": {
      "url": "http://127.0.0.1:7979/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

本地模式下 `headers` 可省略。生产环境按 README 配置鉴权后再填 token。

支持方法：`initialize`、`ping`、`tools/list`、`tools/call`、`resources/list`、`resources/read`。请求头包含 `Accept: text/event-stream` 时，响应以 `event: message\ndata: {...}\n\n` 形式返回（已实测）。

```bash
# 握手
curl -s http://127.0.0.1:7979/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}'

# 列出工具
curl -s http://127.0.0.1:7979/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# 调用
curl -s http://127.0.0.1:7979/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fleet_overview","arguments":{}}}'
```

`tools/call` 结果放在 `result.content[0].text`（格式化 JSON 字符串）；工具失败时 `result.isError` 为 `true` 且文本中含 `error` 字段。

---

## 15 个工具

### 观察与诊断

| 工具 | 作用 | 主要参数 |
| --- | --- | --- |
| `fleet_overview` | 一次读完整个舰队：证书健康、工作流、监控、Webhook、临期清单与按优先级排序的下一步动作 | `include_events` |
| `inspect_certificate` | 按 id 或域名查证书，返回有效期、链、SHA256、算法及部署位置 | `id` / `domain` |
| `diagnose_domain` | 端到端诊断：本地证书、实时 TLS 链、监控覆盖、Webhook 命中、工作流覆盖与问题清单 | `domain`（必填）、`probe_live` |
| `security_audit` | 审计过期证书、弱签名、监控盲区、明文 Webhook、无签名密钥、无 API key | 无 |
| `list_capabilities` | 列出全部 CA、DNS 商、部署目标、通知渠道、节点类型与事件 | `section` |

### 签发、部署与续期

| 工具 | 作用 | 主要参数 |
| --- | --- | --- |
| `issue_and_deploy` | **一键签发并部署**：申请或复用证书 → 部署到多个目标 → 可选创建监控 | `domains`（必填）、`ca`、`email`、`dns_access_id`、`algorithm`、`deploy_targets`、`deploy_access_id`、`cert_path`、`key_path`、`add_monitor`、`force` |
| `deploy_certificate` | 把已存证书部署到一个或多个目标，支持幂等跳过 | `cert_id`、`targets`（必填）、`access_id`、`cert_path`、`key_path` |
| `renew_expiring` | 批量续期 renewal window 内的证书，逐域名返回结果 | `force`、`dry_run` |
| `private_ca_bootstrap` | 一次创建根 CA、中间 CA 与叶子证书 | `cn`、`leaf_cn`（必填）、`algorithm`、`leaf_sans`、`valid_days`、`name` |

### 编排与监控

| 工具 | 作用 | 主要参数 |
| --- | --- | --- |
| `create_certificate_pipeline` | 声明式创建完整的定时流水线：申请 → 部署 → 通知 | `name`、`domains`（必填）、`ca`、`dns_access_id`、`deploy_target`、`deploy_access_id`、`notify_channel`、`active` |
| `run_workflow` | 立即执行工作流并返回按节点汇总的运行结果 | `workflow_id`（必填）、`exec_type` |
| `monitor_domain` | 把域名加入证书监控并设置告警渠道与阈值 | `target`（必填）、`name`、`monitor_type`、`channels`、`advance_day`、`cycle` |

### Webhook 与凭据

| 工具 | 作用 | 主要参数 |
| --- | --- | --- |
| `configure_webhook` | 创建或更新订阅：事件过滤、HMAC 密钥、重试、自定义 body 模板 | `url`（必填）、`events`、`secret`、`event_mode`、`body_template`、`max_attempts`、`active`、`name`、`id` |
| `delivery_health` | 查看投递成功率、失败与待重试，可直接重放某条投递 | `replay_id`、`limit` |
| `rotate_credentials` | 更新凭据并立即做连通性测试 | `id`、`config`（必填）、`test` |

---

## 资源 / Resources

| URI | 内容 |
| --- | --- |
| `ssld://overview` | 实时舰队聚合 |
| `ssld://events/recent` | 最近 100 条生命周期事件 |
| `ssld://capabilities` | 全部能力注册表 |
| `ssld://openapi` | 完整 REST 端点索引 |

```json
{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"ssld://capabilities"}}
```

---

## 典型对话流

1. `fleet_overview` → 读到「3 张证书将在 30 天内过期，2 个工作流上次失败」。
2. `diagnose_domain {"domain":"shop.example.org"}` → 确认证书链、监控与部署覆盖的缺口。
3. `renew_expiring {"dry_run":true}` → 先看会影响哪些域名。
4. `renew_expiring {"force":false}` → 执行批量续期。
5. `configure_webhook {"url":"https://hooks.internal/ssld","events":["cert.*","monitor.alert"],"secret":"..."}` → 把后续事件推到内部系统。
6. `delivery_health` → 确认投递成功率。

所有工具都通过同一套服务层操作，与 REST API、兼容网关、Web 控制台共享数据与事件，不存在「MCP 看到的状态和界面不一致」的问题。
