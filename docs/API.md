# REST API 参考 / REST API Reference

基础路径 `/api/v1`，统一响应封装：

```json
{ "code": 0, "message": "ok", "data": { } }
```

错误时 `code` 为 HTTP 状态码，`message` 为可读原因，`data` 为 `null`。除显式标注的端点外，请求体为 JSON。所有 103 个端点也可通过 `GET /api/v1/endpoints` 与 `GET /api/v1/openapi.json` 以机器可读形式取得。

**鉴权**：本地模式下无需凭证；设置 `SSLD_API_KEY` 或 `SSLD_AUTH_REQUIRED=1` 后需要 `Authorization: Bearer <token>` 或 `ssld_session` Cookie。`POST /api/v1/auth/login` 获取 token。`/api/v1/health`、`/api/v1/version`、`/api/v1/auth/login`、`/api/v1/auth/captcha`、`/api/v1/openapi.json` 与静态资源始终公开。

---

## 1. 系统 / System (8)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 服务状态、版本、启动时间、调度器/MCP/Webhook 开关 |
| GET | `/endpoints` | 返回 `{count, endpoints[]}` |
| GET | `/capabilities` | 全部能力注册表：CA、DNS/主机/部署目标、算法、事件、节点类型、导入导出格式等 |
| GET | `/overview` | 首页聚合：证书分桶、健康分、KPI、推荐动作、近期运行与事件 |
| GET | `/audit` | 安全审计：过期证书、SHA-1、监控盲区、明文 Webhook、无密钥、无 API key |
| GET | `/version` | 版本号 |
| GET | `/settings` | 当前设置（隐藏 `api_key`） |
| PUT | `/settings` | 更新设置，接受 `{ "settings": {"k":"v"} }` 或顶层键值 |

## 2. 认证 / Auth (4)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth/login` | `{username, password, code?, captcha_id?}` → token + Cookie |
| POST | `/auth/logout` | 注销当前 session |
| GET | `/auth/captcha` | 返回内联 SVG 验证码 `{id, image}` |
| POST | `/auth/rotate-key` | 轮换 API key |

## 3. 证书 / Certificates (10)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/certificates?search=&status=&limit=` | 列表 |
| POST | `/certificates/import` | 导入 `{cert, key, issuer_cert}`，解析 PEM 并校验配对 |
| POST | `/certificates/apply` | ACME 申请。见下方 ApplyRequest |
| POST | `/certificates/preview` | `{cert}` 只解析不入库 |
| GET | `/certificates/{id}` | 详情 |
| GET | `/certificates/{id}/inspect` | `{certificate, parsed, deployed_to}`；`parsed` 含 SAN、有效期、SHA256、算法 |
| GET | `/certificates/{id}/export?format=zip\|pem\|der\|pfx\|jks` | 二进制下载 |
| GET | `/certificates/{id}/download` | 同上，默认 zip |
| DELETE | `/certificates/{ids}` | 逗号分隔批量删除 |

`POST /certificates/apply` 主要字段：

```json
{
  "domains": ["www.example.org", "*.example.org"],
  "ca": "letsencrypt", "cadirurl": "", "email": "ops@example.org",
  "algorithm": "RSA2048", "dns_access_id": 1, "eab_id": 0, "account_id": 0,
  "end_day": 30, "max_wait": 120, "certificate_timeout": 60,
  "ari_enabled": true, "skip_check": false, "force": false,
  "workflow_id": 0, "history_id": ""
}
```

支持 CA：`letsencrypt`、`zerossl`、`google`、`sslcom`、`sslcom-rsa`、`sslcom-ecc`、`buypass`、`litessl`、`custom`（custom 必须给 `cadirurl`；Google / SSL.com / custom 需要 EAB）。算法：`RSA2048` / `RSA3072` / `RSA4096` / `RSA8192` / `EC256` / `EC384`。

## 4. 凭据、EAB 与 ACME 账户 / Access, EAB, Accounts (18)

| 方法 | 路径 |
| --- | --- |
| GET / POST | `/accesses` |
| GET / PUT / DELETE | `/accesses/{id}`、`/accesses/{ids}` |
| POST | `/accesses/{id}/test` 连通性测试 |
| GET | `/accesses/{id}/sites` 凭据下站点列表 |
| GET | `/access-types` DNS / 主机类型枚举 |
| GET / POST | `/eab` |
| PUT / DELETE | `/eab/{id}`、`/eab/{ids}` |
| GET / POST | `/acme/accounts` |
| PUT / DELETE | `/acme/accounts/{id}`、`/acme/accounts/{ids}` |
| GET | `/acme/cas` CA 目录列表 |

凭据创建示例：

```json
{ "name": "cloudflare-prod", "kind": "dns", "provider": "cloudflare",
  "config": { "token": "..." } }
```

`config` 中的密钥在列表接口返回为 `******`；更新时传回 `******` 会保留原值。

## 5. 通知渠道 / Notification channels (5)

| 方法 | 路径 |
| --- | --- |
| GET / POST | `/channels` |
| PUT / DELETE | `/channels/{id}`、`/channels/{ids}` |
| POST | `/channels/{id}/test` |

类型：`mail`、`webhook`、`dingtalk`、`feishu`、`workwx`。

## 6. 工作流 / Workflows (14)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET / POST | `/workflows` | 列表 / 创建 |
| POST | `/workflows/build` | 一键生成「申请 → 部署 → 通知」流水线 |
| GET / PUT / DELETE | `/workflows/{id}`、`/workflows/{ids}` | 详情 / 更新 / 删除 |
| POST | `/workflows/{id}/execute?exec_type=manual` | 执行并返回运行记录 |
| POST | `/workflows/{id}/active` | 启停 |
| POST | `/workflows/{id}/exec-type` | 切换 manual / auto |
| POST | `/workflows/{id}/stop` | 停止运行 |
| GET | `/workflows/{id}/history` | 该工作流的运行历史 |
| GET / DELETE | `/workflow-runs`、`/workflow-runs/{ids}` | 全局运行记录 |
| GET | `/workflow-runs/{id}/log` | 节点级执行日志 |

`POST /workflows/build` 请求体：

```json
{ "name": "edge pipeline", "domains": ["shop.example.org"], "ca": "letsencrypt",
  "dns_access_id": 1, "deploy_target": "localhost", "deploy_access_id": 0,
  "notify_channel": "", "active": true }
```

节点类型：`start`、`end`、`default`、`branch`、`condition`、`execute_result_branch`、`execute_result_condition`、`apply`、`deploy`、`upload`、`notify`、`private_ca`。

## 7. 监控 / Monitors (10)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET / POST | `/monitors` | 列表 / 创建 |
| POST | `/monitors/import` | `{format: "csv"\|"json", content}` 批量导入 |
| GET | `/monitors/template?type=csv` | 下载导入模板 |
| GET / PUT / DELETE | `/monitors/{id}`、`/monitors/{ids}` | CRUD |
| POST | `/monitors/{id}/check` | 立即探测 |
| POST | `/monitors/{id}/toggle` | 启停 |
| GET | `/monitors/{id}/errors` | 异常记录 |
| GET | `/monitors/{id}/detail` | 详情与证书链 |

监控类型：`https`、`smtp`。

## 8. 私有 CA / Private CA (8)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET / POST | `/ca` | CA 列表 / 创建（`root_id: 0` 为根 CA） |
| DELETE | `/ca/{ids}` | 删除（存在中间 CA 时阻止删除根 CA） |
| GET | `/ca/{id}/download` | 下载 CA 证书 |
| GET / POST | `/leaves` | 叶子列表 / 签发 |
| DELETE | `/leaves/{ids}` | 删除 |
| GET | `/leaves/{id}/download` | 下载叶子 PEM（原始 PEM，非 JSON 封装） |

签发叶子示例（`san` 同时接受数组、逗号分隔字符串、以及 `{dns_names:[], ip_addresses:[]}` 对象；IP 字面量自动转为 iPAddress SAN）：

```json
{ "ca_id": 2, "cn": "shop.example.org",
  "san": ["shop.example.org", "api.example.org", "10.0.0.12"],
  "algorithm": "ecdsa", "key_length": 256, "valid_days": 365 }
```

约束：根 CA 不能直接签发叶子；叶子有效期不能超过中间 CA 剩余寿命；`sm2` 走外部 openssl 双证书路径。

## 9. Webhook / Webhooks (12)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET / POST | `/webhooks` | 列表 / 创建订阅 |
| GET | `/webhooks/stats` | 投递统计 |
| GET / PUT / DELETE | `/webhooks/{id}`、`/webhooks/{ids}` | CRUD |
| POST | `/webhooks/{id}/toggle` | 启停 |
| POST | `/webhooks/{id}/test` | 发送测试事件 |
| GET | `/webhook-deliveries` | 投递台账 |
| POST | `/webhook-deliveries/{id}/redeliver` | 重放 |

详见 [WEBHOOKS.md](WEBHOOKS.md)。

## 10. 事件 / Events (3)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/events?limit=` | 事件日志 |
| GET | `/events/stream` | SSE 实时流，每条 `event: <事件名>` + JSON `data` |
| POST | `/events/emit` | `{event, payload}` 手动发射；事件名必须来自能力注册表 |

SSE 示例：

```
event: cert.imported
data: {"id":"...","event":"cert.imported","source":"api","payload":{},"created_at":"..."}
```

## 11. 插件 / Plugins (10)

| 方法 | 路径 |
| --- | --- |
| GET | `/plugins` |
| POST | `/plugins/scan`、`/plugins/register` |
| POST | `/plugins/{id}/enable`、`/plugins/{id}/disable`、`/plugins/{id}/restart` |
| GET | `/plugins/{id}/actions`、`/plugins/{id}/metadata`、`/plugins/bootstrap` |

## 12. 运维 / Operations (5)

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/oplogs` | 操作审计日志 |
| POST | `/renew-expiring` | 立即批量续期（`{"force": false}`） |
| GET | `/backup` | 下载完整 state JSON（**原始文档，无封装**） |
| POST | `/restore` | `{"state": "<backup JSON 字符串>"}`，会先自动留一份 `state.backup.json`，需重启生效 |
| GET | `/openapi.json` | OpenAPI 3.1 索引 |

---

## 兼容性网关 / Compatibility gateway

原有 allinssl 的 `POST /v1/{group}/{action}`（form-urlencoded 或 JSON）继续可用，共 71 个业务动作映射到与 REST 相同的服务层。分组：`login`、`cert`、`access`、`acme_account`、`workflow`、`monitor`、`report`、`setting`、`overview`、`private_ca`、`plugins`，另加 ssld 扩展组 `webhook`、`events`。

```bash
curl -X POST http://127.0.0.1:7979/v1/overview/get_overviews
curl -X POST http://127.0.0.1:7979/v1/cert/get_list -d 'limit=5&search='
```

配置了 `api_key` 时，兼容请求需带 `api_token` 与 `timestamp`（见 README 的签名公式）。

**按需求排除的 CLI 服务控制动作** `setting/shutdown` 与 `setting/restart` 返回 `410 Gone`：

```json
{"code":410,"message":"shutdown is a CLI service-control action and is intentionally not implemented in ssld; use the REST API or your process manager","data":null}
```
