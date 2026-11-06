# 可配置 Webhook / Configurable Webhooks

ssld 的每个业务动作都会经由 `Core::emit()` 汇入同一条事件漏斗：写入事件日志 → 广播到 SSE → 分发给所有匹配的 Webhook 订阅。订阅支持事件过滤、签名、自定义请求、重试、投递台账、测试与重放。

---

## 快速上手

```bash
curl -s http://127.0.0.1:7979/api/v1/webhooks \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "platform-events",
    "url": "https://hooks.internal/ssld",
    "events": ["cert.*", "monitor.alert", "workflow.failed"],
    "event_mode": "include",
    "secret": "s3cr3t",
    "method": "POST",
    "headers": {"X-Team": "platform"},
    "content_type": "application/json",
    "body_template": "{\"event\":\"__event__\",\"data\":__payload__}",
    "active": true,
    "max_attempts": 5,
    "backoff_seconds": 60,
    "timeout_seconds": 10,
    "skip_tls_verify": false,
    "description": "fleet events to the platform bus"
  }'

curl -X POST http://127.0.0.1:7979/api/v1/webhooks/<id>/test
curl -s http://127.0.0.1:7979/api/v1/webhook-deliveries
curl -s http://127.0.0.1:7979/api/v1/webhooks/stats
```

也可以用 MCP 的 `configure_webhook` 与 `delivery_health` 完成同样的事。

---

## 订阅字段

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `name` | string | `hook-<id前6位>` | 显示名 |
| `url` | string | 必填 | 必须是 `http://` 或 `https://` |
| `events` | string[] | `[]` | 事件名或前缀通配（`cert.*`、`*`）；空数组在 `include` 模式下表示不过滤 |
| `event_mode` | string | `include` | `include` 只投递匹配事件；`exclude` 投递所有**不**匹配的事件 |
| `secret` | string | 空 | HMAC-SHA256 密钥；为空则不签名 |
| `method` | string | `POST` | `GET` 时事件信息走 query 参数，其余走 body |
| `headers` | object | `{}` | 自定义请求头，值同样支持模板占位符 |
| `content_type` | string | `application/json` | Content-Type |
| `body_template` | string | 见下 | 请求体模板 |
| `active` | bool | `true` | 启停 |
| `max_attempts` | int | `5` | 最大尝试次数（上限 10） |
| `backoff_seconds` | int | `60` | 线性退避基数：第 n 次等待 `backoff_seconds × n` 秒 |
| `timeout_seconds` | int | `10` | 单次请求超时 |
| `skip_tls_verify` | bool | `false` | 跳过 TLS 校验（仅用于自签名的内网接收端） |
| `description` | string | 空 | 备注 |

更新订阅时把 `secret` 传成 `******` 可保留原密钥（与凭据脱敏保持一致）。

---

## 事件与过滤

共 **44** 种事件，完整列表随时可从 `GET /api/v1/capabilities` 的 `events` 取得。分组如下：

| 组 | 事件 |
| --- | --- |
| 证书 | `cert.issued`、`cert.reused`、`cert.imported`、`cert.deleted`、`cert.renewal.started`、`cert.renewal.succeeded`、`cert.renewal.failed`、`cert.deployed`、`cert.deploy_failed`、`cert.expiring`、`cert.expired`、`cert.invalid`、`cert.recovered`、`cert.pushed` |
| 工作流 | `workflow.started`、`workflow.succeeded`、`workflow.failed`、`workflow.partial`、`workflow.node_failed`、`workflow.stopped` |
| 监控 | `monitor.alert`、`monitor.recovered`、`monitor.check_failed` |
| 凭据与 ACME | `access.created`、`access.updated`、`access.deleted`、`access.test_failed`、`acme.account_registered`、`acme.order_failed`、`acme.ari_replacement` |
| DNS 传播 | `dns.propagated`、`dns.check_unavailable` |
| 私有 CA | `ca.created`、`ca.deleted`、`leaf.issued` |
| 通知与插件 | `channel.test`、`notify.failed`、`webhook.delivery_failed`、`webhook.test`、`plugin.enabled`、`plugin.disabled` |
| 系统 | `settings.updated`、`system.started`、`system.audit` |

匹配规则（`providers::matches_event`）：

- 精确匹配 `cert.issued`，或前缀通配 `cert.*`，或全通配 `*`。
- `event_mode: "include"`：命中才投递。
- `event_mode: "exclude"`：命中则**跳过**，其余都投递（适合「除了监控心跳都要」）。
- `events` 为空且 `include`：全部投递；为空且 `exclude`：全部不投递。

未知事件名在创建订阅时会被拒绝；`POST /api/v1/events/emit` 同样只接受注册表中的事件名。

---

## 签名校验

配置了 `secret` 时，每次请求会带：

| Header | 值 |
| --- | --- |
| `X-SSLD-Signature` | `sha256=<hex>` |
| `X-SSLD-Timestamp` | Unix 秒 |
| `X-SSLD-Event` | 事件名 |
| `X-SSLD-Delivery` | 投递 id |
| `X-SSLD-Idempotency-Key` | 事件 id（可用于接收端去重） |

签名原文是 `timestamp + "." + body`，算法 HMAC-SHA256，十六进制输出。签名头名可用配置 `webhook.signature_header` 修改。

Node.js 校验示例：

```js
const crypto = require('crypto');
function verify(secret, headers, rawBody) {
  const expected = 'sha256=' + crypto.createHmac('sha256', secret)
    .update(headers['x-ssld-timestamp'] + '.' + rawBody).digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expected), Buffer.from(headers['x-ssld-signature'] || ''));
}
```

Python 示例：

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(),
    (timestamp + "." + body).encode(), hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, signature)
```

已用接收端逐字节比对验证通过。

---

## 请求体模板

默认模板：

```json
{"id":"__id__","event":"__event__","created_at":"__created_at__","source":"__source__","data":__payload__}
```

可用占位符：

| 占位符 | 替换内容 |
| --- | --- |
| `__event__` | 事件名 |
| `__id__` | 事件 id |
| `__created_at__` / `__timestamp__` | 事件时间戳 |
| `__source__` | 事件来源模块 |
| `__payload__` | 事件 payload 的 JSON 字符串（用于嵌到 JSON 里） |
| `__<顶层字段名>__` | payload 中同名顶层键的值 |

自定义模板示例（适配企业微信机器人）：

```json
{"msgtype":"text","text":{"content":"[ssld] __event__ on __domain__"}}
```

`headers` 里的字符串值同样会经过模板替换，可用于把事件名注入自定义头。

---

## 重试、台账与重放

- 只有 2xx 视为成功；非 2xx 与网络错误都会记录 `error`。
- 失败后按 `backoff_seconds × 当前尝试次数` 线性退避，最多 `max_attempts` 次（内部上限 10）。
- 每次尝试都写入一条 `WebhookDelivery`：`id`、`subscription_id`、`event`、`payload`、`request_body`、`status_code`、`success`、`attempts`、`next_retry`、`error`、`duration_ms`。
- 最终失败会发射 `webhook.delivery_failed` 事件（可能触发其他订阅，注意避免循环订阅）。
- `POST /api/v1/webhooks/{id}/test` 主动发送 `webhook.test`；`POST /api/v1/webhook-deliveries/{id}/redeliver` 用当时的 payload 重放。
- `GET /api/v1/webhooks/stats` 返回订阅数、投递数、成功率、`by_event` 分布与待重试数；MCP `delivery_health` 额外返回最近投递明细并支持 `replay_id`。

### 运维建议

- 生产环境务必配置 `secret`，并使用 HTTPS 接收端。
- 用 `X-SSLD-Idempotency-Key`（事件 id）在接收端幂等去重。
- 避免让 `webhook.delivery_failed` 再触发订阅了 `*` 的同一接收端，否则会形成自激循环。
- 全局默认值由 `config.webhook` 控制；`SSLD_WEBHOOK_OFF=1` 可一键停用分发而保留事件日志与 SSE。
