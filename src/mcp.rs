//! Model Context Protocol server (Streamable HTTP / JSON-RPC 2.0) served on
//! the same port as the REST API. The tools are deliberately coarse grained:
//! each one completes a real operator job instead of exposing CRUD primitives.
use crate::error::AppError;
use crate::state::Shared;
use axum::{body::Bytes, extract::State, http::{header, HeaderMap, StatusCode}, response::{IntoResponse, Response}, Json};
use serde_json::{json, Value};

pub const TOOL_DEFS: &[(&str, &str)] = &[
    ("fleet_overview", "Read the whole fleet: certificate health, workflows, monitors, webhooks, expirations and prioritised next actions."),
    ("issue_and_deploy", "One call that issues or reuses a certificate via ACME and deploys it to one or more targets, optionally adding a monitor."),
    ("renew_expiring", "Renew every certificate inside the renewal window (or force all) and report per-domain results."),
    ("inspect_certificate", "Look up a certificate by id or domain and return validity, chain, fingerprints and where it was deployed."),
    ("deploy_certificate", "Deploy an existing stored certificate to one or more targets with idempotent skip."),
    ("create_certificate_pipeline", "Create a complete scheduled workflow: apply, deploy, notify, with one declarative call."),
    ("run_workflow", "Execute a workflow now and return a compact run summary with per-node outcomes."),
    ("monitor_domain", "Add a domain to certificate monitoring with alert channels and thresholds."),
    ("configure_webhook", "Create or update a webhook subscription with event filters, HMAC secret, retries and a custom body template."),
    ("delivery_health", "Inspect webhook delivery success rates, failures and pending retries, and optionally replay a delivery."),
    ("diagnose_domain", "End-to-end diagnosis of a domain: stored certificate, live TLS chain, monitors, webhooks and workflow coverage."),
    ("list_capabilities", "List every supported CA, DNS provider, deploy target, notification channel, workflow node and event type."),
    ("private_ca_bootstrap", "Create a root CA, an intermediate CA and a leaf certificate in one call."),
    ("security_audit", "Audit the fleet for expired certificates, weak signatures, missing monitors and insecure webhooks."),
    ("rotate_credentials", "Update a stored provider credential and immediately test connectivity."),
];
pub const TOOL_COUNT: usize = TOOL_DEFS.len();

fn schema(names: &[(&str, &str, &str)], required: &[&str]) -> Value {
    let props: serde_json::Map<String, Value> = names.iter().map(|(name, kind, desc)| {
        (name.to_string(), json!({ "type": kind, "description": desc }))
    }).collect();
    json!({ "type": "object", "properties": Value::Object(props),
        "required": required.iter().map(|s| Value::String(s.to_string())).collect::<Vec<_>>() })
}

fn tool_defs() -> Vec<Value> {
    let s = |names: &[(&str, &str, &str)], required: &[&str]| schema(names, required);
    let strs = &("string", "string", "");
    let _ = strs;
    vec![
        json!({"name":"fleet_overview", "description":TOOL_DEFS[0].1, "inputSchema": s(&[("include_events","boolean","Include the recent event stream")], &[])}),
        json!({"name":"issue_and_deploy", "description":TOOL_DEFS[1].1, "inputSchema": s(&[
            ("domains","array","Domains to cover, wildcards allowed"),("ca","string","CA id, default letsencrypt"),
            ("email","string","ACME contact email"),("dns_access_id","integer","Credential id for DNS-01"),
            ("algorithm","string","RSA2048 / EC256 / ..."),("deploy_targets","array","Target ids, e.g. localhost, webhook"),
            ("deploy_access_id","integer","Credential id for deployment"),("cert_path","string","Target cert path for local/ssh"),
            ("key_path","string","Target key path for local/ssh"),("add_monitor","boolean","Create an expiry monitor afterwards"),
            ("force","boolean","Force reissuance even inside the renewal window")], &["domains"])}),
        json!({"name":"renew_expiring", "description":TOOL_DEFS[2].1, "inputSchema": s(&[
            ("force","boolean","Renew all certificates, not just those near expiry"),
            ("dry_run","boolean","Only list what would be renewed")], &[])}),
        json!({"name":"inspect_certificate", "description":TOOL_DEFS[3].1, "inputSchema": s(&[
            ("id","integer","Certificate id"),("domain","string","Or a domain to match")], &[])}),
        json!({"name":"deploy_certificate", "description":TOOL_DEFS[4].1, "inputSchema": s(&[
            ("cert_id","integer","Certificate id"),("targets","array","Deploy target ids"),
            ("access_id","integer","Host credential id"),("cert_path","string","Target cert path"),
            ("key_path","string","Target key path")], &["cert_id","targets"])}),
        json!({"name":"create_certificate_pipeline", "description":TOOL_DEFS[5].1, "inputSchema": s(&[
            ("name","string","Workflow name"),("domains","array","Domains"),
            ("ca","string","CA id"),("dns_access_id","integer","DNS credential id"),
            ("deploy_target","string","Deploy target id"),("deploy_access_id","integer","Host credential id"),
            ("notify_channel","string","Notification channel id or kind"),("active","boolean","Enable scheduling")], &["name","domains"])}),
        json!({"name":"run_workflow", "description":TOOL_DEFS[6].1, "inputSchema": s(&[
            ("workflow_id","integer","Workflow id"),("exec_type","string","manual or auto")], &["workflow_id"])}),
        json!({"name":"monitor_domain", "description":TOOL_DEFS[7].1, "inputSchema": s(&[
            ("target","string","Domain or host:port"),("name","string","Display name"),
            ("monitor_type","string","https or smtp"),("channels","array","Notification channel ids or kinds"),
            ("advance_day","integer","Days before expiry to alert"),("cycle","integer","Probe interval in minutes")], &["target"])}),
        json!({"name":"configure_webhook", "description":TOOL_DEFS[8].1, "inputSchema": s(&[
            ("name","string","Subscription name"),("url","string","Destination URL"),
            ("events","array","Event names or prefixes like cert.*; empty means all"),
            ("secret","string","HMAC-SHA256 secret"),("event_mode","string","include or exclude"),
            ("body_template","string","Body template with __event__ / __payload__ placeholders"),
            ("max_attempts","integer","Retry count"),("active","boolean","Enable the subscription"),
            ("id","string","Existing subscription id to update")], &["url"])}),
        json!({"name":"delivery_health", "description":TOOL_DEFS[9].1, "inputSchema": s(&[
            ("replay_id","string","Replay a failed delivery id"),("limit","integer","Recent deliveries to return")], &[])}),
        json!({"name":"diagnose_domain", "description":TOOL_DEFS[10].1, "inputSchema": s(&[
            ("domain","string","Domain to diagnose"),("probe_live","boolean","Probe the live TLS endpoint")], &["domain"])}),
        json!({"name":"list_capabilities", "description":TOOL_DEFS[11].1, "inputSchema": s(&[
            ("section","string","Optional section: dns / deploy / ca / events / all")], &[])}),
        json!({"name":"private_ca_bootstrap", "description":TOOL_DEFS[12].1, "inputSchema": s(&[
            ("name","string","CA name"),("cn","string","Root common name"),
            ("algorithm","string","rsa / ecdsa"),("leaf_cn","string","Leaf common name"),
            ("leaf_sans","array","Leaf SAN dns names"),("valid_days","integer","Leaf validity")], &["cn","leaf_cn"])}),
        json!({"name":"security_audit", "description":TOOL_DEFS[13].1, "inputSchema": s(&[], &[])}),
        json!({"name":"rotate_credentials", "description":TOOL_DEFS[14].1, "inputSchema": s(&[
            ("id","integer","Credential id"),("config","object","New credential fields"),
            ("test","boolean","Test connectivity after updating")], &["id","config"])}),
    ]
}

fn resources() -> Vec<Value> {
    vec![
        json!({"uri":"ssld://overview","name":"Fleet overview","mimeType":"application/json","description":"Live aggregate of the whole certificate fleet"}),
        json!({"uri":"ssld://events/recent","name":"Recent events","mimeType":"application/json","description":"Last 100 emitted lifecycle events"}),
        json!({"uri":"ssld://capabilities","name":"Capability catalog","mimeType":"application/json","description":"All providers, targets, algorithms and events"}),
        json!({"uri":"ssld://openapi","name":"REST API index","mimeType":"application/json","description":"Complete list of REST endpoints"}),
    ]
}

fn result(id: Value, value: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": value })
}
fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}
fn text_result(data: Value, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&data).unwrap_or_default() }],
        "structuredContent": data, "isError": is_error })
}

pub async fn handle(State(core): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Json(error(Value::Null, -32700, format!("parse error: {e}"))).into_response(),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let response = match method.as_str() {
        "initialize" => result(id, json!({
            "protocolVersion": params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18"),
            "capabilities": { "tools": { "listChanged": false }, "resources": { "subscribe": false, "listChanged": false },
                "logging": {}, "prompts": { "listChanged": false } },
            "serverInfo": { "name": "ssld", "version": env!("CARGO_PKG_VERSION"),
                "description": "SSL certificate lifecycle control plane" },
            "instructions": "Use the coarse tools to operate the whole certificate lifecycle. Start with fleet_overview."
        })),
        "notifications/initialized" | "notifications/cancelled" => {
            return StatusCode::ACCEPTED.into_response();
        }
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({ "tools": tool_defs() })),
        "resources/list" => result(id, json!({ "resources": resources() })),
        "resources/templates/list" => result(id, json!({ "resourceTemplates": [] })),
        "prompts/list" => result(id, json!({ "prompts": [] })),
        "resources/read" => {
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            let data = match uri {
                "ssld://overview" => crate::overview::overview(&core),
                "ssld://events/recent" => {
                    let mut rows = core.store.snapshot().event_log; rows.reverse(); rows.truncate(100);
                    json!({ "events": rows })
                }
                "ssld://capabilities" => crate::providers::catalog(),
                "ssld://openapi" => json!({ "endpoints": crate::api::ENDPOINTS }),
                _ => return Json(error(id, -32602, format!("unknown resource: {uri}"))).into_response(),
            };
            result(id, json!({ "contents": [{ "uri": uri, "mimeType": "application/json",
                "text": serde_json::to_string_pretty(&data).unwrap_or_default() }] }))
        }
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(&core, &name, args).await {
                Ok(v) => result(id, text_result(v, false)),
                Err(e) => result(id, text_result(json!({ "error": e.to_string(), "tool": name }), true)),
            }
        }
        other => error(id, -32601, format!("method not found: {other}")),
    };
    if accept.contains("text/event-stream") {
        let payload = serde_json::to_string(&response).unwrap_or_default();
        let sse = format!("event: message\ndata: {payload}\n\n");
        return ([(header::CONTENT_TYPE, "text/event-stream".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::HeaderName::from_static("mcp-session-id"), "ssld-local".to_string())], sse).into_response();
    }
    let mut resp = Json(response).into_response();
    resp.headers_mut().insert("Mcp-Session-Id", "ssld-local".parse().unwrap());
    resp
}

fn sv(args: &Value, k: &str, d: &str) -> String {
    args.get(k).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| d.into())
}
fn iv(args: &Value, k: &str, d: i64) -> i64 {
    args.get(k).and_then(|v| v.as_i64())
        .or_else(|| args.get(k).and_then(|v| v.as_str()).and_then(|s| s.parse().ok())).unwrap_or(d)
}
fn bv(args: &Value, k: &str, d: bool) -> bool { args.get(k).and_then(|v| v.as_bool()).unwrap_or(d) }
fn av(args: &Value, k: &str) -> Vec<String> {
    match args.get(k) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => vec![],
    }
}

async fn call_tool(core: &Shared, name: &str, a: Value) -> Result<Value, AppError> {
    match name {
        "fleet_overview" => {
            let mut data = crate::overview::overview(core);
            if bv(&a, "include_events", true) {
                let mut rows = core.store.snapshot().event_log; rows.reverse(); rows.truncate(20);
                data.as_object_mut().unwrap().insert("live_events".into(), json!(rows));
            }
            Ok(data)
        }
        "issue_and_deploy" => {
            let domains = av(&a, "domains");
            if domains.is_empty() { return Err(AppError::bad_request("domains is required")); }
            let req = crate::certs::ApplyRequest {
                domains: domains.clone(), ca: sv(&a, "ca", ""), cadirurl: sv(&a, "cadirurl", ""),
                email: sv(&a, "email", ""), algorithm: sv(&a, "algorithm", ""),
                dns_access_id: iv(&a, "dns_access_id", 0), eab_id: iv(&a, "eab_id", 0),
                account_id: iv(&a, "account_id", 0), end_day: iv(&a, "end_day", 0),
                max_wait: iv(&a, "max_wait", 120) as u64,
                certificate_timeout: iv(&a, "certificate_timeout", 60) as u64,
                ari_enabled: bv(&a, "ari_enabled", true), skip_check: bv(&a, "skip_check", false),
                force: bv(&a, "force", false), workflow_id: 0, history_id: String::new(),
            };
            let outcome = crate::certs::apply_certificate(core, req).await?;
            let mut deployments = Vec::new();
            let targets = av(&a, "deploy_targets");
            for target in &targets {
                let access_id = iv(&a, "deploy_access_id", 0);
                let access = core.store.snapshot().accesses.into_iter().find(|x| x.id == access_id);
                let params = json!({ "certPath": sv(&a, "cert_path", "data/deployed/cert.pem"),
                    "keyPath": sv(&a, "key_path", "data/deployed/key.pem"),
                    "domain": domains.first().cloned().unwrap_or_default(),
                    "url": sv(&a, "url", ""), "skip": 1 });
                let req = crate::deploy::DeployRequest {
                    target: target.clone(), access, cert: outcome.cert.clone(), params,
                    workflow_id: 0, node_id: String::new(),
                };
                match crate::deploy::deploy(core, req).await {
                    Ok((skipped, detail)) => deployments.push(json!({ "target": target, "ok": true, "skipped": skipped, "detail": detail })),
                    Err(e) => deployments.push(json!({ "target": target, "ok": false, "error": e.to_string() })),
                }
            }
            let mut monitored = Value::Null;
            if bv(&a, "add_monitor", false) {
                for d in &domains {
                    let m = crate::monitor::create(core, crate::models::MonitorInput {
                        name: format!("ssld {d}"), target: d.clone(), monitor_type: "https".into(),
                        report_types: av(&a, "channels"), active: true, cycle: 60,
                        repeat_send_gap: 10, advance_day: 30,
                    })?;
                    monitored = json!(m.id);
                }
            }
            Ok(json!({ "certificate": { "id": outcome.cert.id, "domains": outcome.cert.domains,
                "sha256": outcome.cert.sha256, "end_time": outcome.cert.end_time },
                "reused": outcome.reused, "renewed": outcome.renewed,
                "deployments": deployments, "monitor_id": monitored,
                "summary": format!("certificate {} for {} domain(s), {} deployment(s)",
                    if outcome.reused { "reused" } else { "issued" }, domains.len(), deployments.len()) }))
        }
        "renew_expiring" => {
            if bv(&a, "dry_run", false) {
                let threshold = core.setting("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30);
                let rows = crate::certs::list(core, "", "1", 0);
                let db = core.store.snapshot();
                let expired = db.certs.iter().filter(|c| crate::crypto::days_left(&c.end_time) < 0).count();
                Ok(json!({ "dry_run": true, "threshold_days": threshold,
                    "would_renew": rows.len() + expired, "expired": expired }))
            } else { Ok(crate::scheduler::renew_expiring(core, bv(&a, "force", false)).await) }
        }
        "inspect_certificate" => {
            let id = iv(&a, "id", 0);
            let domain = sv(&a, "domain", "");
            let cert = if id > 0 { Some(crate::certs::get(core, id)?) }
                else { core.store.snapshot().certs.into_iter().find(|c| c.domains.iter().any(|d| d.contains(&domain))) };
            match cert {
                Some(c) => Ok(crate::certs::inspect(core, c.id).await?),
                None => Err(AppError::not_found("no matching certificate")),
            }
        }
        "deploy_certificate" => {
            let cert = crate::certs::get(core, iv(&a, "cert_id", 0))?;
            let targets = av(&a, "targets");
            let mut results = Vec::new();
            for t in targets {
                let access = core.store.snapshot().accesses.into_iter().find(|x| x.id == iv(&a, "access_id", 0));
                let params = json!({ "certPath": sv(&a, "cert_path", "data/deployed/cert.pem"),
                    "keyPath": sv(&a, "key_path", "data/deployed/key.pem"),
                    "domain": cert.domains.first().cloned().unwrap_or_default(), "skip": 1 });
                let outcome = crate::deploy::deploy(core, crate::deploy::DeployRequest {
                    target: t.clone(), access, cert: cert.clone(), params,
                    workflow_id: 0, node_id: String::new(),
                }).await;
                results.push(match outcome {
                    Ok((s, d)) => json!({ "target": t, "ok": true, "skipped": s, "detail": d }),
                    Err(e) => json!({ "target": t, "ok": false, "error": e.to_string() }),
                });
            }
            Ok(json!({ "cert_id": cert.id, "results": results }))
        }
        "create_certificate_pipeline" => {
            let domains = av(&a, "domains");
            let tree = crate::workflow::build_tree(&sv(&a, "name", "Certificate pipeline"), &domains,
                &sv(&a, "ca", "letsencrypt"), iv(&a, "dns_access_id", 0),
                &sv(&a, "deploy_target", "localhost"), iv(&a, "deploy_access_id", 0),
                &sv(&a, "notify_channel", ""));
            let w = crate::workflow::create(core, crate::models::WorkflowInput {
                name: sv(&a, "name", "Certificate pipeline"), content: tree,
                active: bv(&a, "active", true), exec_type: "auto".into(),
                exec_time: None, cron: String::new(),
            })?;
            Ok(json!({ "workflow_id": w.id, "name": w.name, "domains": domains,
                "next": "call run_workflow to execute it now, or wait for the daily schedule" }))
        }
        "run_workflow" => {
            let h = crate::workflow::execute(core, iv(&a, "workflow_id", 0), &sv(&a, "exec_type", "manual")).await?;
            Ok(json!({ "run_id": h.id, "status": h.status, "workflow_id": h.workflow_id,
                "started_at": h.created_at, "finished_at": h.end_time,
                "nodes": h.nodes.iter().map(|n| json!({ "name": n.name, "type": n.node_type,
                    "status": n.status, "message": n.message })).collect::<Vec<_>>(),
                "summary": format!("{} node(s), status {}", h.nodes.len(), h.status) }))
        }
        "monitor_domain" => {
            let m = crate::monitor::create(core, crate::models::MonitorInput {
                name: sv(&a, "name", ""), target: sv(&a, "target", ""),
                monitor_type: sv(&a, "monitor_type", "https"),
                report_types: av(&a, "channels"), active: true,
                cycle: iv(&a, "cycle", 60), repeat_send_gap: 10,
                advance_day: iv(&a, "advance_day", 30),
            })?;
            let check = crate::monitor::check(core, m.id).await?;
            Ok(json!({ "monitor_id": m.id, "target": m.target, "first_check": check }))
        }
        "configure_webhook" => {
            let input = crate::models::WebhookInput {
                name: sv(&a, "name", ""), url: sv(&a, "url", ""), events: av(&a, "events"),
                event_mode: sv(&a, "event_mode", "include"),
                secret: if sv(&a, "secret", "").is_empty() { core.config.default_webhook_secret() } else { sv(&a, "secret", "") },
                method: sv(&a, "method", "POST"), headers: a.get("headers").cloned().unwrap_or(json!({})),
                body_template: sv(&a, "body_template", ""), active: bv(&a, "active", true),
                max_attempts: iv(&a, "max_attempts", 5) as u32,
                backoff_seconds: iv(&a, "backoff_seconds", 60) as u64,
                timeout_seconds: iv(&a, "timeout_seconds", 10) as u64,
                skip_tls_verify: bv(&a, "skip_tls_verify", false),
                content_type: sv(&a, "content_type", "application/json"),
                description: sv(&a, "description", ""),
            };
            let id = sv(&a, "id", "");
            let sub = if id.is_empty() { crate::webhook::create(core, input)? }
                else { crate::webhook::update(core, &id, input)? };
            Ok(json!({ "subscription": { "id": sub.id, "name": sub.name, "url": sub.url,
                "events": sub.events, "event_mode": sub.event_mode, "active": sub.active,
                "signed": !sub.secret.is_empty(), "max_attempts": sub.max_attempts },
                "hint": "Send a test event with POST /api/v1/webhooks/{id}/test" }))
        }
        "delivery_health" => {
            let mut data = crate::webhook::stats(core);
            let replay = sv(&a, "replay_id", "");
            if !replay.is_empty() {
                data.as_object_mut().unwrap().insert("replay".into(), json!(crate::webhook::redeliver(core, &replay).await?));
            }
            let limit = iv(&a, "limit", 10) as usize;
            let mut rows = core.store.snapshot().deliveries; rows.reverse(); rows.truncate(limit);
            data.as_object_mut().unwrap().insert("recent".into(), json!(rows));
            Ok(data)
        }
        "diagnose_domain" => {
            let domain = sv(&a, "domain", "");
            let db = core.store.snapshot();
            let certs: Vec<Value> = db.certs.iter().filter(|c| c.domains.iter().any(|d| d.contains(&domain)))
                .map(|c| json!({ "id": c.id, "days_left": crate::crypto::days_left(&c.end_time),
                    "issuer": c.issuer, "sha256": c.sha256 })).collect();
            let monitors: Vec<Value> = db.monitors.iter().filter(|m| m.target.contains(&domain))
                .map(|m| json!({ "id": m.id, "valid": m.valid, "last_time": m.last_time })).collect();
            let workflows: Vec<Value> = db.workflows.iter()
                .filter(|w| w.content.to_string().contains(&domain))
                .map(|w| json!({ "id": w.id, "name": w.name, "active": w.active })).collect();
            let hooks = db.webhooks.iter().filter(|h| h.active).count();
            drop(db);
            let live = if bv(&a, "probe_live", true) { crate::monitor::probe(&domain, "https") } else { Value::Null };
            let mut issues = Vec::new();
            if certs.is_empty() { issues.push("no stored certificate covers this domain"); }
            if monitors.is_empty() { issues.push("no monitor watches this domain"); }
            if workflows.is_empty() { issues.push("no workflow automates this domain"); }
            if hooks == 0 { issues.push("no active webhook subscription receives events"); }
            Ok(json!({ "domain": domain, "certificates": certs, "monitors": monitors,
                "workflows": workflows, "active_webhooks": hooks, "live_tls": live,
                "issues": issues, "healthy": issues.is_empty() }))
        }
        "list_capabilities" => {
            let section = sv(&a, "section", "all");
            let cat = crate::providers::catalog();
            if section == "all" { Ok(cat) }
            else {
                let mut out = serde_json::Map::new();
                out.insert(section.clone(), cat.get(&section).cloned()
                    .unwrap_or(json!({ "error": "unknown section" })));
                Ok(Value::Object(out))
            }
        }
        "private_ca_bootstrap" => {
            let root = crate::private_ca::create_ca(core, crate::models::CaConfig {
                name: sv(&a, "name", "ssld Root CA"), cn: sv(&a, "cn", "ssld Root CA"),
                o: sv(&a, "o", "ssld"), c: sv(&a, "c", "CN"),
                algorithm: sv(&a, "algorithm", "rsa"), key_length: 2048,
                valid_days: 3650, root_id: 0,
            }).await?;
            let inter = crate::private_ca::create_ca(core, crate::models::CaConfig {
                name: format!("{} Intermediate", root.name), cn: format!("{} Intermediate", root.cn),
                o: root.o.clone(), c: root.c.clone(), algorithm: root.algorithm.clone(),
                key_length: 2048, valid_days: 1825, root_id: root.id,
            }).await?;
            let sans: Vec<String> = av(&a, "leaf_sans");
            let leaf = crate::private_ca::issue_leaf(core, crate::models::LeafConfig {
                ca_id: inter.id, cn: sv(&a, "leaf_cn", ""),
                san: json!({ "dns_names": sans }), usage: 0, key_length: 2048,
                valid_days: iv(&a, "valid_days", 365), algorithm: String::new(),
            }).await?;
            Ok(json!({ "root_ca_id": root.id, "intermediate_ca_id": inter.id,
                "leaf_id": leaf.id, "leaf_cn": leaf.cn, "not_after": leaf.not_after }))
        }
        "security_audit" => Ok(crate::overview::audit(core)),
        "rotate_credentials" => {
            let id = iv(&a, "id", 0);
            let old = crate::access::raw(core, id)?;
            let cfg = a.get("config").cloned().unwrap_or(json!({}));
            let merged = crate::access::merge_secret(&old.config, &cfg);
            let updated = crate::access::update(core, id, crate::models::AccessInput {
                name: old.name, kind: old.kind, provider: old.provider, config: merged,
            }).await?;
            let test = if bv(&a, "test", true) { Some(crate::access::test(core, id).await?) } else { None };
            Ok(json!({ "credential": { "id": updated.id, "provider": updated.provider }, "test": test }))
        }
        other => Err(AppError::bad_request(format!("unknown tool: {other}"))),
    }
}
