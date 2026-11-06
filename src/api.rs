//! Complete REST surface. Every business function of allinssl is reachable
//! here, plus events, webhooks, MCP, plugins and audit. A compatibility
//! gateway for the original `/v1/{group}/{action}` form lives in `compat.rs`.
use crate::error::{created, message, ok, AppError, Result};
use crate::models::*;
use crate::state::Shared;
use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{sse::Event as SseEvent, sse::KeepAlive, Html, IntoResponse, Redirect, Response, Sse},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use futures::stream::Stream;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;

pub const ENDPOINTS: &[&str] = &[
    "GET /api/v1/health", "GET /api/v1/endpoints", "GET /api/v1/capabilities",
    "GET /api/v1/overview", "GET /api/v1/audit", "GET /api/v1/version",
    "GET /api/v1/settings", "PUT /api/v1/settings", "POST /api/v1/auth/login",
    "POST /api/v1/auth/logout", "GET /api/v1/auth/captcha", "POST /api/v1/auth/rotate-key",
    "GET /api/v1/certificates", "POST /api/v1/certificates/import", "POST /api/v1/certificates/apply",
    "POST /api/v1/certificates/preview", "GET /api/v1/certificates/{id}",
    "GET /api/v1/certificates/{id}/inspect", "GET /api/v1/certificates/{id}/export",
    "DELETE /api/v1/certificates/{ids}", "GET /api/v1/certificates/{id}/download",
    "GET /api/v1/accesses", "POST /api/v1/accesses", "GET /api/v1/accesses/{id}",
    "PUT /api/v1/accesses/{id}", "DELETE /api/v1/accesses/{ids}",
    "POST /api/v1/accesses/{id}/test", "GET /api/v1/accesses/{id}/sites",
    "GET /api/v1/access-types", "GET /api/v1/eab", "POST /api/v1/eab",
    "PUT /api/v1/eab/{id}", "DELETE /api/v1/eab/{ids}",
    "GET /api/v1/acme/accounts", "POST /api/v1/acme/accounts",
    "PUT /api/v1/acme/accounts/{id}", "DELETE /api/v1/acme/accounts/{ids}",
    "GET /api/v1/acme/cas", "GET /api/v1/channels", "POST /api/v1/channels",
    "PUT /api/v1/channels/{id}", "DELETE /api/v1/channels/{ids}",
    "POST /api/v1/channels/{id}/test",
    "GET /api/v1/workflows", "POST /api/v1/workflows", "POST /api/v1/workflows/build",
    "GET /api/v1/workflows/{id}", "PUT /api/v1/workflows/{id}", "DELETE /api/v1/workflows/{ids}",
    "POST /api/v1/workflows/{id}/execute", "POST /api/v1/workflows/{id}/active",
    "POST /api/v1/workflows/{id}/exec-type", "POST /api/v1/workflows/{id}/stop",
    "GET /api/v1/workflows/{id}/history", "GET /api/v1/workflow-runs",
    "GET /api/v1/workflow-runs/{id}/log", "DELETE /api/v1/workflow-runs/{ids}",
    "GET /api/v1/monitors", "POST /api/v1/monitors", "POST /api/v1/monitors/import",
    "GET /api/v1/monitors/template", "GET /api/v1/monitors/{id}", "PUT /api/v1/monitors/{id}",
    "DELETE /api/v1/monitors/{ids}", "POST /api/v1/monitors/{id}/check",
    "POST /api/v1/monitors/{id}/toggle", "GET /api/v1/monitors/{id}/errors",
    "GET /api/v1/monitors/{id}/detail", "GET /api/v1/ca", "POST /api/v1/ca",
    "DELETE /api/v1/ca/{ids}", "GET /api/v1/ca/{id}/download",
    "GET /api/v1/leaves", "POST /api/v1/leaves", "DELETE /api/v1/leaves/{ids}",
    "GET /api/v1/leaves/{id}/download",
    "GET /api/v1/webhooks", "POST /api/v1/webhooks", "GET /api/v1/webhooks/stats",
    "GET /api/v1/webhooks/{id}", "PUT /api/v1/webhooks/{id}", "DELETE /api/v1/webhooks/{ids}",
    "POST /api/v1/webhooks/{id}/toggle", "POST /api/v1/webhooks/{id}/test",
    "GET /api/v1/webhook-deliveries", "POST /api/v1/webhook-deliveries/{id}/redeliver",
    "GET /api/v1/events", "GET /api/v1/events/stream", "POST /api/v1/events/emit",
    "GET /api/v1/plugins", "POST /api/v1/plugins/scan", "POST /api/v1/plugins/register",
    "POST /api/v1/plugins/{id}/enable", "POST /api/v1/plugins/{id}/disable",
    "POST /api/v1/plugins/{id}/restart", "GET /api/v1/plugins/{id}/actions",
    "GET /api/v1/plugins/{id}/metadata", "GET /api/v1/plugins/bootstrap",
    "GET /api/v1/oplogs", "POST /api/v1/renew-expiring", "GET /api/v1/backup",
    "POST /api/v1/restore", "GET /api/v1/openapi.json",
];
pub const ENDPOINT_COUNT: usize = ENDPOINTS.len();

fn parse<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| AppError::bad_request(format!("body: {e}")))
}
fn q(query: &HashMap<String, String>, key: &str, default: &str) -> String {
    query.get(key).cloned().unwrap_or_else(|| default.into())
}
fn ids(v: Value) -> String {
    v.get("ids").and_then(|x| x.as_str()).map(str::to_string)
        .or_else(|| v.get("id").and_then(|x| x.as_i64()).map(|n| n.to_string()))
        .unwrap_or_default()
}

pub fn router(core: Shared) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/endpoints", get(endpoints))
        .route("/capabilities", get(capabilities))
        .route("/overview", get(overview))
        .route("/audit", get(audit))
        .route("/version", get(version))
        .route("/settings", get(settings_get).put(settings_put))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/captcha", get(captcha))
        .route("/auth/rotate-key", post(rotate_key))
        .route("/certificates", get(certs_list).post(certs_import))
        .route("/certificates/import", post(certs_import))
        .route("/certificates/apply", post(certs_apply))
        .route("/certificates/preview", post(certs_preview))
        .route("/certificates/{id}", get(cert_get).delete(certs_delete))
        .route("/certificates/{id}/inspect", get(cert_inspect))
        .route("/certificates/{id}/export", get(cert_export))
        .route("/certificates/{id}/download", get(cert_export))
        .route("/accesses", get(accesses_list).post(access_create))
        .route("/accesses/{id}", get(access_get).put(access_update).delete(access_delete))
        .route("/accesses/{id}/test", post(access_test))
        .route("/accesses/{id}/sites", get(access_sites))
        .route("/access-types", get(access_types))
        .route("/eab", get(eab_list).post(eab_create))
        .route("/eab/{id}", put(eab_update).delete(eab_delete))
        .route("/acme/accounts", get(accounts_list).post(account_create))
        .route("/acme/accounts/{id}", put(account_update).delete(account_delete))
        .route("/acme/cas", get(ca_list))
        .route("/channels", get(channels_list).post(channel_create))
        .route("/channels/{id}", put(channel_update).delete(channel_delete))
        .route("/channels/{id}/test", post(channel_test))
        .route("/workflows", get(workflows_list).post(workflow_create))
        .route("/workflows/build", post(workflow_build))
        .route("/workflows/{id}", get(workflow_get).put(workflow_update).delete(workflow_delete))
        .route("/workflows/{id}/execute", post(workflow_execute))
        .route("/workflows/{id}/active", post(workflow_active))
        .route("/workflows/{id}/exec-type", post(workflow_exec_type))
        .route("/workflows/{id}/stop", post(workflow_stop))
        .route("/workflows/{id}/history", get(workflow_history))
        .route("/workflow-runs", get(runs_list).delete(runs_delete))
        .route("/workflow-runs/{ids}", axum::routing::delete(runs_delete_path))
        .route("/workflow-runs/{id}/log", get(run_log))
        .route("/monitors", get(monitors_list).post(monitor_create))
        .route("/monitors/import", post(monitor_import))
        .route("/monitors/template", get(monitor_template))
        .route("/monitors/{id}", get(monitor_get).put(monitor_update).delete(monitor_delete))
        .route("/monitors/{id}/check", post(monitor_check))
        .route("/monitors/{id}/toggle", post(monitor_toggle))
        .route("/monitors/{id}/errors", get(monitor_errors))
        .route("/monitors/{id}/detail", get(monitor_detail))
        .route("/ca", get(ca_records).post(ca_create))
        .route("/ca/{id}", delete(ca_delete))
        .route("/ca/{id}/download", get(ca_download))
        .route("/leaves", get(leaves_list).post(leaf_create))
        .route("/leaves/{id}", delete(leaves_delete))
        .route("/leaves/{id}/download", get(leaf_download))
        .route("/webhooks", get(hooks_list).post(hook_create))
        .route("/webhooks/stats", get(hooks_stats))
        .route("/webhooks/{id}", get(hook_get).put(hook_update).delete(hook_delete))
        .route("/webhooks/{id}/toggle", post(hook_toggle))
        .route("/webhooks/{id}/test", post(hook_test))
        .route("/webhook-deliveries", get(deliveries))
        .route("/webhook-deliveries/{id}/redeliver", post(redeliver))
        .route("/events", get(events_list))
        .route("/events/stream", get(events_stream))
        .route("/events/emit", post(events_emit))
        .route("/plugins", get(plugins_list))
        .route("/plugins/scan", post(plugins_scan))
        .route("/plugins/register", post(plugins_register))
        .route("/plugins/{id}/enable", post(plugin_enable))
        .route("/plugins/{id}/disable", post(plugin_disable))
        .route("/plugins/{id}/restart", post(plugin_restart))
        .route("/plugins/{id}/actions", get(plugin_actions))
        .route("/plugins/{id}/metadata", get(plugin_metadata))
        .route("/plugins/bootstrap", get(plugins_bootstrap))
        .route("/oplogs", get(oplogs))
        .route("/renew-expiring", post(renew_expiring))
        .route("/backup", get(backup))
        .route("/restore", post(restore))
        .route("/openapi.json", get(openapi));

    let protected = Router::new()
        .nest("/api/v1", api)
        .route("/v1/{group}/{action}", axum::routing::post(crate::compat::compat_post).get(crate::compat::compat_get))
        .route(&core.config.mcp.path.clone(), post(crate::mcp::handle))
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles))
        .route("/favicon.svg", get(favicon))
        .fallback(get(spa_fallback))
        .layer(middleware::from_fn_with_state(Arc::clone(&core), auth_middleware))
        .with_state(core.clone());
    protected
}

// --- middleware ------------------------------------------------------------

async fn auth_middleware(State(core): State<Shared>, req: Request, next: Next) -> std::result::Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let public = path == "/" || path == "/index.html" || path == "/app.js" || path == "/styles.css"
        || path == "/favicon.svg" || path == "/api/v1/health" || path == "/api/v1/auth/captcha"
        || path == "/api/v1/auth/login" || path == "/api/v1/version" || path.ends_with("/openapi.json")
        // Compatibility endpoints authenticate inside compat.rs, which can
        // inspect the form body carrying api_token / timestamp.
        || path.starts_with("/v1/");
    let mcp_path = core.config.mcp.path.clone();
    if public || (path == mcp_path && !core.config.mcp.require_auth) { return Ok(next.run(req).await); }
    // Local mode: no API key configured and auth not explicitly required.
    // Production deployments set SSLD_API_KEY or SSLD_AUTH_REQUIRED=1.
    let local_mode = core.setting("api_key").unwrap_or_default().is_empty()
        && core.config.auth.api_key.is_empty() && !core.config.auth.require_auth;
    if local_mode { return Ok(next.run(req).await); }

    // Secure entry: visiting the configured path marks the browser and sends it
    // to the login page. Any other path without that mark behaves as a 404.
    if crate::auth::is_secure_enabled(&core) {
        let entry = crate::auth::secure_entry(&core);
        if path.trim_end_matches('/') == entry.trim_end_matches('/') {
            let mut res = Redirect::temporary("/login").into_response();
            let cookie = format!("ssld_secure=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600");
            res.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
            return Ok(res);
        }
        let has_cookie = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok())
            .map(|c| c.contains("ssld_secure=1")).unwrap_or(false);
        if !has_cookie && !has_token(&core, &req) {
            return Ok((StatusCode::NOT_FOUND, Html("<h1>404</h1>")).into_response());
        }
    }

    if has_token(&core, &req) {
        if let Some(t) = session_token(&req) { crate::auth::touch(&core, &t); }
        core.oplog("api", "request", &path, json!({}));
        return Ok(next.run(req).await);
    }
    Err(AppError::unauthorized("authentication required"))
}

fn session_token(req: &Request) -> Option<String> {
    if let Some(v) = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") { return Some(t.trim().to_string()); }
    }
    req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').find_map(|p| p.trim().strip_prefix("ssld_session=").map(str::to_string)))
}

fn has_token(core: &Shared, req: &Request) -> bool {
    if let Some(t) = session_token(req) {
        if crate::auth::session(core, &t).is_some() { return true; }
        let key = core.setting("api_key").unwrap_or_else(|| core.config.auth.api_key.clone());
        if !key.is_empty() && crate::crypto::constant_time_eq(&t, &key) { return true; }
    }
    if let Some(v) = req.headers().get("X-API-Key").and_then(|v| v.to_str().ok()) {
        let key = core.setting("api_key").unwrap_or_else(|| core.config.auth.api_key.clone());
        if !key.is_empty() && crate::crypto::constant_time_eq(v, &key) { return true; }
    }
    let query = req.uri().query().unwrap_or("");
    let pairs: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let token = pairs.get("api_token").cloned().unwrap_or_default();
    let ts = pairs.get("timestamp").cloned().unwrap_or_default();
    if !token.is_empty() && crate::auth::check_api_signature(core, &token, &ts) { return true; }
    false
}

// --- static assets ---------------------------------------------------------

async fn index() -> Html<&'static str> { Html(include_str!("../web/index.html")) }
async fn app_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], include_str!("../web/app.js"))
}
async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../web/styles.css"))
}
async fn favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], include_str!("../web/favicon.svg"))
}
async fn spa_fallback(State(_core): State<Shared>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    if path.starts_with("/api/") || path.starts_with("/v1/") || path.contains("/mcp") {
        return Json(json!({ "code": 404, "message": "requested resource not found", "data": Value::Null })).into_response();
    }
    Html(include_str!("../web/index.html")).into_response()
}

// --- system ----------------------------------------------------------------

async fn health(State(core): State<Shared>) -> Json<Value> {
    ok(json!({ "status": "ok", "service": "ssld", "version": env!("CARGO_PKG_VERSION"),
        "started_at": core.started_at, "uptime_seconds": (chrono::Utc::now().timestamp()
            - chrono::DateTime::parse_from_rfc3339(&core.started_at).map(|d| d.timestamp()).unwrap_or(0)),
        "scheduler": core.config.scheduler.enabled, "mcp": core.config.mcp.enabled,
        "webhooks": core.config.webhook.enabled }))
}
async fn endpoints() -> Json<Value> { ok(json!({ "count": ENDPOINT_COUNT, "endpoints": ENDPOINTS })) }
async fn capabilities() -> Json<Value> { ok(crate::providers::catalog()) }
async fn overview(State(core): State<Shared>) -> Json<Value> { ok(crate::overview::overview(&core)) }
async fn audit(State(core): State<Shared>) -> Json<Value> { ok(crate::overview::audit(&core)) }
async fn version() -> Json<Value> { ok(json!({ "version": env!("CARGO_PKG_VERSION"), "name": "ssld", "license": "MIT", "language": "Rust" })) }
async fn openapi() -> Json<Value> { ok(super_api_document()) }

fn super_api_document() -> Value {
    let paths: Value = Value::Object(ENDPOINTS.iter().map(|e| {
        let mut parts = e.splitn(2, ' ');
        let method = parts.next().unwrap_or("GET").to_lowercase();
        let path = parts.next().unwrap_or("/");
        (path.to_string(), json!({ method: { "summary": e, "tags": [path.split('/').nth(3).unwrap_or("system")] } }))
    }).collect());
    json!({ "openapi": "3.1.0", "info": { "title": "ssld API", "version": env!("CARGO_PKG_VERSION"),
        "description": "Complete SSL certificate lifecycle control plane" },
        "paths": paths, "components": { "securitySchemes": {
            "bearerAuth": { "type": "http", "scheme": "bearer" },
            "apiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" } } } })
}

async fn settings_get(State(core): State<Shared>) -> Json<Value> {
    let mut s = core.store.snapshot().settings;
    s.remove("api_key");
    for k in s.keys().filter(|k| k.starts_with("captcha:")).cloned().collect::<Vec<_>>() { s.remove(&k); }
    ok(json!({ "settings": s, "runtime": {
        "bind": core.config.server.bind, "port": core.config.server.port,
        "mcp_path": core.config.mcp.path, "tick_seconds": core.config.scheduler.tick_seconds,
        "data_dir": core.config.storage.data_dir } }))
}

async fn settings_put(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let updates = body.get("settings").cloned().unwrap_or(body.clone());
    let obj = updates.as_object().ok_or_else(|| AppError::bad_request("settings must be an object"))?;
    let allowed = ["timeout", "secure", "https", "renew_before_days", "default_ca", "default_algorithm",
        "ari_enabled", "webhook_enabled", "mcp_enabled", "theme", "language", "plugin_dir", "log_path",
        "workflow_log_path", "api_key", "username", "password"];
    let mut changed = Vec::new();
    for (k, v) in obj {
        if !allowed.contains(&k.as_str()) { continue; }
        let value = match v { Value::String(s) => s.clone(), _ => v.to_string() };
        if k == "password" {
            let salt = "ssld-static-salt";
            core.store.mutate(|db| {
                db.settings.insert("password_hash".into(), crate::auth::hash_password(&value, salt));
                if let Some(u) = db.users.first_mut() { u.password_hash = crate::auth::hash_password(&value, salt); }
            })?;
        } else if k == "username" {
            core.store.mutate(|db| { if let Some(u) = db.users.first_mut() { u.username = value.clone(); } db.settings.insert("username".into(), value.clone()); })?;
        } else {
            core.store.mutate(|db| { db.settings.insert(k.clone(), value.clone()); })?;
        }
        changed.push(k.clone());
    }
    let _ = core.emit("settings.updated", "settings", json!({ "keys": changed })).await;
    Ok(ok(json!({ "updated": changed })))
}

async fn login(State(core): State<Shared>, Json(body): Json<Value>) -> Result<impl IntoResponse> {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let captcha_code = body.get("code").and_then(|v| v.as_str());
    if let Some(id) = body.get("captcha_id").and_then(|v| v.as_str()) {
        if !crate::auth::verify_captcha(&core, id, captcha_code.unwrap_or("")) {
            return Err(AppError::bad_request("captcha mismatch"));
        }
    }
    let session = crate::auth::login(&core, &username, &password, captcha_code)?;
    let cookie = format!("ssld_session={}; Path=/; HttpOnly; SameSite=Lax", session.token);
    let mut res = ok(json!({ "token": session.token, "username": username, "expires_in": core.config.auth.session_timeout })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
    Ok(res)
}

async fn logout(State(core): State<Shared>, req: Request) -> Json<Value> {
    if let Some(t) = session_token(&req) { crate::auth::logout(&core, &t); }
    message("signed out")
}
async fn captcha(State(core): State<Shared>) -> Json<Value> { ok(crate::auth::captcha(&core)) }
async fn rotate_key(State(core): State<Shared>) -> Json<Value> { ok(json!({ "api_key": crate::auth::rotate_key(&core) })) }

// --- certificates ----------------------------------------------------------

async fn certs_list(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let limit = q(&query, "limit", "0").parse().unwrap_or(0);
    ok(json!({ "list": crate::certs::list(&core, &q(&query, "search", ""), &q(&query, "status", ""), limit) }))
}
async fn cert_get(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::certs::get(&core, id)?)) }
async fn certs_import(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let cert = crate::certs::import(&core, parse::<CertInput>(body)?).await?;
    Ok(ok(json!({ "id": cert.id, "domains": cert.domains, "sha256": cert.sha256 })))
}
async fn certs_apply(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let outcome = crate::certs::apply_certificate(&core, parse::<crate::certs::ApplyRequest>(body)?).await?;
    Ok(ok(json!({ "cert_id": outcome.cert.id, "domains": outcome.cert.domains,
        "end_time": outcome.cert.end_time, "reused": outcome.reused, "renewed": outcome.renewed, "detail": outcome.detail })))
}
async fn certs_preview(Json(body): Json<Value>) -> Result<Json<Value>> {
    Ok(ok(crate::certs::preview(body.get("cert").and_then(|v| v.as_str()).unwrap_or(""))?))
}
async fn certs_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> {
    Ok(ok(json!({ "deleted": crate::certs::delete(&core, &ids).await? })))
}
async fn cert_inspect(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> {
    Ok(ok(crate::certs::inspect(&core, id).await?))
}
async fn cert_export(State(core): State<Shared>, Path(id): Path<i64>, Query(query): Query<HashMap<String, String>>) -> Result<Response> {
    let format = q(&query, "format", "zip");
    let (bytes, mime, name) = crate::certs::export(&core, id, &format)?;
    Ok(([(header::CONTENT_TYPE, mime.to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], bytes).into_response())
}

// --- credentials -----------------------------------------------------------

async fn accesses_list(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    ok(json!({ "list": crate::access::list(&core, &q(&query, "kind", ""), &q(&query, "search", "")) }))
}
async fn access_get(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> {
    let a = crate::access::raw(&core, id)?;
    Ok(ok(json!({ "id": a.id, "name": a.name, "kind": a.kind, "provider": a.provider, "config": crate::access::mask(&a.config) })))
}
async fn access_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    Ok(ok(crate::access::create(&core, parse(body)?).await?))
}
async fn access_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> {
    Ok(ok(crate::access::update(&core, id, parse(body)?).await?))
}
async fn access_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> {
    Ok(ok(json!({ "deleted": crate::access::delete(&core, &ids).await? })))
}
async fn access_test(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::access::test(&core, id).await?)) }
async fn access_sites(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::access::get_sites(&core, id).await?)) }
async fn access_types(State(core): State<Shared>) -> Json<Value> {
    ok(json!({ "list": core.store.snapshot().access_types }))
}
async fn eab_list(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::access::eabs(&core) })) }
async fn eab_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::access::eab_create(&core, parse(body)?)?)) }
async fn eab_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::access::eab_update(&core, id, parse(body)?)?)) }
async fn eab_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::access::eab_delete(&core, &ids)? }))) }
async fn accounts_list(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::access::accounts(&core) })) }
async fn account_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::access::account_create(&core, parse(body)?)?)) }
async fn account_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::access::account_update(&core, id, parse(body)?)?)) }
async fn account_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::access::account_delete(&core, &ids)? }))) }
async fn ca_list(State(core): State<Shared>) -> Json<Value> { ok(crate::access::ca_list(&core)) }

// --- notification channels -------------------------------------------------

fn channel_from(v: Value) -> Result<ReportChannel> { parse(v) }
async fn channels_list(State(core): State<Shared>) -> Json<Value> {
    ok(json!({ "list": core.store.snapshot().channels.into_iter().map(|mut c| {
        c.config = crate::access::mask(&c.config); c
    }).collect::<Vec<_>>() }))
}
async fn channel_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let ch = core.store.mutate(|db| {
        let mut c = channel_from(body.clone())?;
        c.id = crate::store::next_id(db, "channel"); c.created_at = now(); c.updated_at = now();
        db.channels.push(c.clone()); Ok::<_, AppError>(c)
    })??;
    Ok(ok(ch))
}
async fn channel_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let old = core.store.snapshot().channels.into_iter().find(|c| c.id == id)
        .ok_or_else(|| AppError::not_found("channel not found"))?;
    let mut ch: ReportChannel = parse(body)?;
    ch.config = crate::access::merge_secret(&old.config, &ch.config);
    ch.id = id; ch.created_at = old.created_at; ch.updated_at = now();
    let out = ch.clone();
    core.store.mutate(|db| { if let Some(s) = db.channels.iter_mut().find(|c| c.id == id) { *s = ch; } })?;
    Ok(ok(out))
}
async fn channel_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    let n = core.store.mutate(|db| { let b = db.channels.len(); db.channels.retain(|c| !set.contains(&c.id)); b - db.channels.len() })?;
    Ok(ok(json!({ "deleted": n })))
}
async fn channel_test(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::notify::test(&core, id).await?)) }

// --- workflows -------------------------------------------------------------

async fn workflows_list(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::workflow::list(&core) })) }
async fn workflow_get(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::workflow::get(&core, id)?)) }
async fn workflow_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::workflow::create(&core, parse(body)?)?)) }
async fn workflow_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::workflow::update(&core, id, parse(body)?)?)) }
async fn workflow_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::workflow::delete(&core, &ids)? }))) }
async fn workflow_execute(State(core): State<Shared>, Path(id): Path<i64>, Query(query): Query<HashMap<String, String>>) -> Result<Json<Value>> {
    let exec_type = q(&query, "exec_type", "manual");
    Ok(ok(crate::workflow::execute(&core, id, &exec_type).await?))
}
async fn workflow_active(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    crate::workflow::set_active(&core, id, active)?; Ok(ok(json!({ "id": id, "active": active })))
}
async fn workflow_exec_type(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let t = body.get("exec_type").and_then(|v| v.as_str()).unwrap_or("manual").to_string();
    crate::workflow::set_exec_type(&core, id, &t)?; Ok(ok(json!({ "id": id, "exec_type": t })))
}
async fn workflow_stop(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let run_id = body.get("run_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    crate::workflow::stop(&core, &run_id)?; Ok(ok(json!({ "stopped": run_id })))
}
async fn workflow_history(State(core): State<Shared>, Path(id): Path<i64>) -> Json<Value> { ok(json!({ "list": crate::workflow::history(&core, Some(id), 50) })) }
async fn runs_list(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let wf = q(&query, "workflow_id", "").parse().ok();
    ok(json!({ "list": crate::workflow::history(&core, wf, q(&query, "limit", "50").parse().unwrap_or(50)) }))
}
async fn runs_delete(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    Ok(ok(json!({ "deleted": crate::workflow::delete_history(&core, &ids(body))? })))
}
async fn runs_delete_path(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> {
    Ok(ok(json!({ "deleted": crate::workflow::delete_history(&core, &ids)? })))
}
async fn run_log(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::workflow::exec_log(&core, &id)?)) }
async fn workflow_build(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("Certificate pipeline").to_string();
    let domains: Vec<String> = body.get("domains").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .or_else(|| body.get("domains").and_then(|v| v.as_str()).map(|s| s.split(',').map(|x| x.trim().to_string()).collect()))
        .unwrap_or_default();
    if domains.is_empty() { return Err(AppError::bad_request("domains is required")); }
    let tree = crate::workflow::build_tree(&name, &domains,
        body.get("ca").and_then(|v| v.as_str()).unwrap_or("letsencrypt"),
        body.get("dns_access_id").and_then(|v| v.as_i64()).unwrap_or(0),
        body.get("deploy_target").and_then(|v| v.as_str()).unwrap_or("localhost"),
        body.get("deploy_access_id").and_then(|v| v.as_i64()).unwrap_or(0),
        body.get("notify_channel").and_then(|v| v.as_str()).unwrap_or(""));
    let input = WorkflowInput { name, content: tree, active: body.get("active").and_then(|v| v.as_bool()).unwrap_or(true),
        exec_type: "auto".into(), exec_time: None, cron: String::new() };
    Ok(ok(crate::workflow::create(&core, input)?))
}

// --- monitors --------------------------------------------------------------

async fn monitors_list(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    ok(json!({ "list": crate::monitor::list(&core, &q(&query, "search", "")) }))
}
async fn monitor_get(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::monitor::get(&core, id)?)) }
async fn monitor_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::monitor::create(&core, parse(body)?)?)) }
async fn monitor_update(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::monitor::update(&core, id, parse(body)?)?)) }
async fn monitor_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::monitor::delete(&core, &ids)? }))) }
async fn monitor_check(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::monitor::check(&core, id).await?)) }
async fn monitor_toggle(State(core): State<Shared>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    crate::monitor::toggle(&core, id, active)?; Ok(ok(json!({ "id": id, "active": active })))
}
async fn monitor_errors(State(core): State<Shared>, Path(id): Path<i64>) -> Json<Value> { ok(json!({ "list": crate::monitor::err_records(&core, id) })) }
async fn monitor_detail(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Json<Value>> { Ok(ok(crate::monitor::detail(&core, id)?)) }
async fn monitor_import(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    Ok(ok(crate::monitor::import(&core, body.get("content").and_then(|v| v.as_str()).unwrap_or(""),
        body.get("format").and_then(|v| v.as_str()).unwrap_or("csv")).await?))
}
async fn monitor_template(Query(query): Query<HashMap<String, String>>) -> Response {
    let format = q(&query, "type", "csv");
    let content = crate::monitor::template(&format);
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
      (header::CONTENT_DISPOSITION, format!("attachment; filename=\"monitor-template.{format}\""))], content).into_response()
}

// --- private CA ------------------------------------------------------------

async fn ca_records(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::private_ca::ca_list(&core) })) }
async fn ca_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::private_ca::create_ca(&core, parse(body)?).await?)) }
async fn ca_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::private_ca::delete_ca(&core, &ids).await? }))) }
async fn ca_download(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Response> {
    let (content, name) = crate::private_ca::download(&core, id, "ca")?;
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file".to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], content).into_response())
}
async fn leaves_list(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::private_ca::leaf_list(&core) })) }
async fn leaf_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::private_ca::issue_leaf(&core, parse(body)?).await?)) }
async fn leaves_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::private_ca::delete_leaf(&core, &ids)? }))) }
async fn leaf_download(State(core): State<Shared>, Path(id): Path<i64>) -> Result<Response> {
    let (content, name) = crate::private_ca::download(&core, id, "leaf")?;
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file".to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], content).into_response())
}

// --- webhooks / events -----------------------------------------------------

async fn hooks_list(State(core): State<Shared>) -> Json<Value> {
    ok(json!({ "list": core.store.snapshot().webhooks.into_iter().map(|mut w| { w.secret = if w.secret.is_empty() { String::new() } else { "******".into() }; w }).collect::<Vec<_>>() }))
}
async fn hook_get(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> {
    let mut w = core.store.snapshot().webhooks.into_iter().find(|w| w.id == id)
        .ok_or_else(|| AppError::not_found("webhook not found"))?;
    w.secret = if w.secret.is_empty() { String::new() } else { "******".into() };
    Ok(ok(w))
}
async fn hook_create(State(core): State<Shared>, Json(body): Json<Value>) -> Result<impl IntoResponse> {
    Ok(created(crate::webhook::create(&core, parse(body)?)?))
}
async fn hook_update(State(core): State<Shared>, Path(id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let old = core.store.snapshot().webhooks.into_iter().find(|w| w.id == id);
    let mut input: WebhookInput = parse(body)?;
    if input.secret == "******" { input.secret = old.map(|o| o.secret).unwrap_or_default(); }
    Ok(ok(crate::webhook::update(&core, &id, input)?))
}
async fn hook_delete(State(core): State<Shared>, Path(ids): Path<String>) -> Result<Json<Value>> { Ok(ok(json!({ "deleted": crate::webhook::delete(&core, &ids)? }))) }
async fn hook_toggle(State(core): State<Shared>, Path(id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    Ok(ok(crate::webhook::toggle(&core, &id, active)?))
}
async fn hook_test(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::webhook::test(&core, &id).await?)) }
async fn hooks_stats(State(core): State<Shared>) -> Json<Value> { ok(crate::webhook::stats(&core)) }
async fn deliveries(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let event = q(&query, "event", "");
    let mut rows: Vec<WebhookDelivery> = core.store.snapshot().deliveries.into_iter()
        .filter(|d| event.is_empty() || d.event == event).collect();
    rows.reverse();
    rows.truncate(q(&query, "limit", "100").parse().unwrap_or(100));
    ok(json!({ "list": rows }))
}
async fn redeliver(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::webhook::redeliver(&core, &id).await?)) }
async fn events_list(State(core): State<Shared>, Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let limit = q(&query, "limit", "100").parse().unwrap_or(100);
    let mut rows = core.store.snapshot().event_log;
    rows.reverse(); rows.truncate(limit);
    ok(json!({ "list": rows, "catalog": crate::providers::EVENTS.iter().map(|(id, name, desc)|
        json!({"id": id, "name": name, "description": desc})).collect::<Vec<_>>() }))
}
async fn events_emit(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let event = body.get("event").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !crate::providers::event_exists(&event) { return Err(AppError::bad_request(format!("unknown event: {event}"))); }
    let payload = body.get("payload").cloned().unwrap_or(json!({}));
    Ok(ok(core.emit(&event, "api", payload).await))
}
async fn events_stream(State(core): State<Shared>) -> Sse<impl Stream<Item = std::result::Result<SseEvent, Infallible>>> {
    let rx = core.bus.subscribe();
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let name = ev.event.clone();
                    let e = SseEvent::default().event(name).json_data(&ev)
                        .unwrap_or_else(|_| SseEvent::default().data("{}"));
                    return Some((Ok::<_, Infallible>(e), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Some((Ok::<_, Infallible>(SseEvent::default().comment("closed")), rx));
                }
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// --- plugins ---------------------------------------------------------------

async fn plugins_list(State(core): State<Shared>) -> Json<Value> { ok(json!({ "list": crate::plugin::plugins(&core) })) }
async fn plugins_scan(State(core): State<Shared>) -> Result<Json<Value>> { Ok(ok(crate::plugin::scan(&core)?)) }
async fn plugins_register(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> { Ok(ok(crate::plugin::register(&core, parse(body)?)?)) }
async fn plugin_enable(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::plugin::set_enabled(&core, &id, true).await?)) }
async fn plugin_disable(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::plugin::set_enabled(&core, &id, false).await?)) }
async fn plugin_restart(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> {
    let _ = crate::plugin::set_enabled(&core, &id, false).await?;
    Ok(ok(crate::plugin::set_enabled(&core, &id, true).await?))
}
async fn plugin_actions(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::plugin::actions(&core, &id)?)) }
async fn plugin_metadata(State(core): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>> { Ok(ok(crate::plugin::raw_metadata(&core, &id)?)) }
async fn plugins_bootstrap(State(core): State<Shared>) -> Json<Value> { ok(crate::plugin::bootstrap(&core)) }

// --- operations ------------------------------------------------------------

async fn oplogs(State(core): State<Shared>) -> Json<Value> {
    let mut rows = core.store.snapshot().oplogs; rows.reverse(); rows.truncate(200);
    ok(json!({ "list": rows }))
}
async fn renew_expiring(State(core): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    ok(crate::scheduler::renew_expiring(&core, body.get("force").and_then(|v| v.as_bool()).unwrap_or(false)).await)
}
async fn backup(State(core): State<Shared>) -> Result<Response> {
    let bytes = std::fs::read(core.store.path())?;
    Ok(([(header::CONTENT_TYPE, "application/json".to_string()),
        (header::CONTENT_DISPOSITION, "attachment; filename=\"ssld-backup.json\"".to_string())], bytes).into_response())
}
async fn restore(State(core): State<Shared>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let raw = body.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let db: crate::store::Database = serde_json::from_str(&raw).map_err(|e| AppError::bad_request(format!("state: {e}")))?;
    let backup = core.store.path().with_extension("backup.json");
    let _ = std::fs::copy(core.store.path(), &backup);
    std::fs::write(core.store.path(), serde_json::to_string_pretty(&db)?)?;
    Ok(ok(json!({ "restored": true, "backup": backup.display().to_string(),
        "note": "restart ssld to reload the restored state" })))
}
