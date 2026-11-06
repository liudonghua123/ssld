//! Legacy `POST /v1/{group}/{action}` form-API compatibility gateway.
//! All 71 original business actions are mapped onto the same service layer as
//! the modern REST API. CLI control actions (shutdown / restart / service
//! toggles) are deliberately not implemented and return 410 Gone.
use crate::error::{ok, AppError, Result};
use crate::state::Shared;
use axum::{body::Bytes, extract::{Path, Query, State}, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::{json, Value};
use std::collections::HashMap;

type Params = HashMap<String, String>;

fn s(p: &Params, key: &str) -> String { p.get(key).cloned().unwrap_or_default() }
fn i(p: &Params, key: &str) -> i64 { p.get(key).and_then(|v| v.parse().ok()).unwrap_or(0) }
fn b(p: &Params, key: &str, default: bool) -> bool {
    match p.get(key).map(String::as_str) { Some("1" | "true" | "on") => true, Some("0" | "false") => false, _ => default }
}
fn j(p: &Params, key: &str) -> Value {
    let raw = s(p, key);
    if raw.is_empty() { return Value::Null; }
    serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
}
/// Service-layer functions return typed models; the compatibility envelope
/// wants an untyped JSON value. This keeps every action on one code path.
fn val<T: serde::Serialize>(x: T) -> Result<Value> { Ok(serde_json::to_value(x)?) }

fn parse_body(bytes: &[u8]) -> Params {
    let text = String::from_utf8_lossy(bytes);
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&text) {
        return m.into_iter().map(|(k, v)| (k, match v {
            Value::String(s) => s, Value::Null => String::new(), other => other.to_string()
        })).collect();
    }
    url::form_urlencoded::parse(bytes).into_owned().collect()
}

fn authenticate(core: &Shared, p: &Params) -> Result<()> {
    let key = core.setting("api_key").unwrap_or_else(|| core.config.auth.api_key.clone());
    if key.is_empty() { return Ok(()); }
    let token = s(p, "api_token");
    let ts = s(p, "timestamp");
    if !token.is_empty() && crate::auth::check_api_signature(core, &token, &ts) { return Ok(()); }
    Err(AppError::unauthorized("api_token signature required (or configure no api_key for local use)"))
}

pub async fn compat_post(State(core): State<Shared>, Path((group, action)): Path<(String, String)>, body: Bytes) -> Response {
    let mut p = parse_body(&body);
    for (k, _) in p.clone() { if k.starts_with("__") { p.remove(&k); } }
    compat(core, group, action, p, HashMap::new()).await
}
pub async fn compat_get(State(core): State<Shared>, Path((group, action)): Path<(String, String)>, Query(query): Query<HashMap<String, String>>) -> Response {
    compat(core, group, action, HashMap::new(), query).await
}

async fn compat(core: Shared, group: String, action: String, mut p: Params, query: HashMap<String, String>) -> Response {
    for (k, v) in query { p.entry(k).or_insert(v); }
    let is_login = group == "login" && (action == "sign" || action == "get_code");
    if !is_login {
        if let Err(e) = authenticate(&core, &p) { return e.into_response(); }
    }
    match dispatch(&core, &group, &action, &p).await {
        Ok(v) => ok(v).into_response(),
        Err(e) => e.into_response(),
    }
}

fn gone(what: &str) -> Result<Value> {
    Err(AppError::new(StatusCode::GONE,
        format!("{what} is a CLI service-control action and is intentionally not implemented in ssld; use the REST API or your process manager")))
}

async fn dispatch(core: &Shared, group: &str, action: &str, p: &Params) -> Result<Value> {
    match (group, action) {
        // --- auth ----------------------------------------------------------
        ("login", "sign") => {
            let session = crate::auth::login(core, &s(p, "username"), &s(p, "password"), p.get("code").map(String::as_str))?;
            Ok(json!({ "token": session.token, "username": session.username }))
        }
        ("login", "sign-out") => { crate::auth::logout(core, &s(p, "token")); Ok(json!({ "signed_out": true })) }
        ("login", "get_code") => Ok(crate::auth::captcha(core)),

        // --- certificates --------------------------------------------------
        ("cert", "get_list") => Ok(json!({ "list": crate::certs::list(core, &s(p, "search"), &s(p, "status"), i(p, "limit") as usize) })),
        ("cert", "upload_cert") => {
            let c = crate::certs::import(core, serde_json::from_value(json!({
                "cert": s(p, "cert"), "key": s(p, "key"), "issuer_cert": s(p, "issuer_cert")
            }))?).await?;
            Ok(json!({ "id": c.id }))
        }
        ("cert", "apply_cert") => {
            let domains: Vec<String> = if p.contains_key("domains") {
                p.get("domains").map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default()
            } else { j(p, "domains").as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default() };
            let out = crate::certs::apply_certificate(core, crate::certs::ApplyRequest {
                domains, ca: s(p, "ca"), cadirurl: s(p, "cadirurl"), email: s(p, "email"),
                algorithm: s(p, "algorithm"), dns_access_id: i(p, "provider_id"),
                eab_id: i(p, "eabId"), account_id: i(p, "account_id"),
                end_day: i(p, "end_day"), max_wait: i(p, "max_wait") as u64,
                certificate_timeout: i(p, "certificate_timeout") as u64,
                ari_enabled: b(p, "ari_enabled", false), skip_check: b(p, "skip_check", false),
                force: b(p, "force", false), workflow_id: i(p, "workflow_id"), history_id: s(p, "history_id"),
            }).await?;
            Ok(json!({ "cert_id": out.cert.id, "reused": out.reused }))
        }
        ("cert", "del_cert") => Ok(json!({ "deleted": crate::certs::delete(core, &s(p, "ids")).await? })),
        ("cert", "download") => {
            let (bytes, _, _) = crate::certs::export(core, i(p, "id"), "zip")?;
            Ok(json!({ "filename": format!("cert-{}.zip", i(p, "id")), "size": bytes.len(),
                "base64": crate::crypto::b64(&bytes) }))
        }

        // --- credentials ---------------------------------------------------
        ("access", "get_list") => Ok(json!({ "list": crate::access::list(core, &s(p, "type"), &s(p, "search")) })),
        ("access", "get_all") => Ok(json!({ "list": crate::access::list(core, "", "") })),
        ("access", "add_access") => val(crate::access::create(core, serde_json::from_value(json!({
            "name": s(p, "name"), "kind": s(p, "type"), "provider": s(p, "provider"), "config": j(p, "config")
        }))?).await?),
        ("access", "upd_access") => val(crate::access::update(core, i(p, "id"), serde_json::from_value(json!({
            "name": s(p, "name"), "kind": s(p, "type"), "provider": s(p, "provider"), "config": j(p, "config")
        }))?).await?),
        ("access", "del_access") => Ok(json!({ "deleted": crate::access::delete(core, &s(p, "ids")).await? })),
        ("access", "test_access") => Ok(crate::access::test(core, i(p, "id")).await?),
        ("access", "get_sites") => Ok(crate::access::get_sites(core, i(p, "id")).await?),
        ("access", "get_eab_list" | "get_all_eab") => Ok(json!({ "list": crate::access::eabs(core) })),
        ("access", "add_eab" | "upd_eab") => {
            let e = crate::models::Eab { id: i(p, "id"), name: s(p, "name"), kid: s(p, "kid"),
                hmac_encoded: s(p, "hmac_encoded"), ca: s(p, "ca"), mail: s(p, "mail"),
                created_at: String::new(), updated_at: String::new() };
            if action == "add_eab" { val(crate::access::eab_create(core, e)?) }
            else { val(crate::access::eab_update(core, i(p, "id"), e)?) }
        },
        ("access", "del_eab") => Ok(json!({ "deleted": crate::access::eab_delete(core, &s(p, "ids"))? })),
        ("access", "get_plugin_actions") => Ok(crate::plugin::actions(core, &s(p, "name"))?),
        ("access", "get_plugins") => Ok(json!({ "list": crate::plugin::plugins(core) })),
        ("access", "get_plugin_raw_metadata") => Ok(crate::plugin::raw_metadata(core, &s(p, "name"))?),

        // --- ACME accounts -------------------------------------------------
        ("acme_account", "get_list") => Ok(json!({ "list": crate::access::accounts(core) })),
        ("acme_account", "get_ca_list") => Ok(crate::access::ca_list(core)),
        ("acme_account", "add_account" | "upd_account") => {
            let a = crate::models::AcmeAccount { id: i(p, "id"), email: s(p, "email"), ca: s(p, "type"),
                private_key: s(p, "private_key"), registration: j(p, "registration"), kid: s(p, "Kid"),
                hmac_encoded: s(p, "HmacEncoded"), cadirurl: s(p, "CADirURL"),
                created_at: String::new(), updated_at: String::new() };
            if action == "add_account" { val(crate::access::account_create(core, a)?) }
            else { val(crate::access::account_update(core, i(p, "id"), a)?) }
        },
        ("acme_account", "del_account") => Ok(json!({ "deleted": crate::access::account_delete(core, &s(p, "ids"))? })),

        // --- workflows -----------------------------------------------------
        ("workflow", "get_list") => Ok(json!({ "list": crate::workflow::list(core) })),
        ("workflow", "add_workflow") => val(crate::workflow::create(core, serde_json::from_value(json!({
            "name": s(p, "name"), "content": j(p, "content"), "active": b(p, "active", true),
            "exec_type": s(p, "exec_type"), "exec_time": j(p, "exec_time"), "cron": s(p, "cron")
        }))?)?),
        ("workflow", "upd_workflow") => val(crate::workflow::update(core, i(p, "id"), serde_json::from_value(json!({
            "name": s(p, "name"), "content": j(p, "content"), "active": b(p, "active", true),
            "exec_type": s(p, "exec_type"), "exec_time": j(p, "exec_time"), "cron": s(p, "cron")
        }))?)?),
        ("workflow", "del_workflow") => Ok(json!({ "deleted": crate::workflow::delete(core, &s(p, "ids"))? })),
        ("workflow", "exec_type") => { crate::workflow::set_exec_type(core, i(p, "id"), &s(p, "exec_type"))?; Ok(json!({ "ok": true })) }
        ("workflow", "active") => { crate::workflow::set_active(core, i(p, "id"), b(p, "active", true))?; Ok(json!({ "ok": true })) }
        ("workflow", "execute_workflow") => val(crate::workflow::execute(core, i(p, "id"), "manual").await?),
        ("workflow", "get_workflow_history") => Ok(json!({ "list": crate::workflow::history(core, Some(i(p, "id")), 50) })),
        ("workflow", "get_exec_log") => Ok(crate::workflow::exec_log(core, &s(p, "id"))?),
        ("workflow", "stop") => { crate::workflow::stop(core, &s(p, "id"))?; Ok(json!({ "stopped": true })) }
        ("workflow", "del_workflow_history") => Ok(json!({ "deleted": crate::workflow::delete_history(core, &s(p, "ids"))? })),

        // --- monitors ------------------------------------------------------
        ("monitor", "get_list") => Ok(json!({ "list": crate::monitor::list(core, &s(p, "search")) })),
        ("monitor", "add_monitor" | "upd_monitor") => {
            let m = crate::models::MonitorInput { name: s(p, "name"), target: s(p, "target"),
                monitor_type: s(p, "monitor_type"),
                report_types: s(p, "report_types").split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
                active: b(p, "active", true), cycle: i(p, "cycle"), repeat_send_gap: i(p, "repeat_send_gap"),
                advance_day: i(p, "advance_day") };
            if action == "add_monitor" { val(crate::monitor::create(core, m)?) }
            else { val(crate::monitor::update(core, i(p, "id"), m)?) }
        },
        ("monitor", "del_monitor") => Ok(json!({ "deleted": crate::monitor::delete(core, &s(p, "ids"))? })),
        ("monitor", "set_monitor") => { crate::monitor::toggle(core, i(p, "id"), b(p, "active", true))?; Ok(json!({ "ok": true })) }
        ("monitor", "get_monitor_info") => Ok(crate::monitor::detail(core, i(p, "id"))?),
        ("monitor", "get_err_record") => Ok(json!({ "list": crate::monitor::err_records(core, i(p, "id")) })),
        ("monitor", "file_add_monitor") => Ok(crate::monitor::import(core, &s(p, "content"), &s(p, "type")).await?),
        ("monitor", "template") => Ok(json!({ "content": crate::monitor::template(&s(p, "type")) })),

        // --- notification channels -----------------------------------------
        ("report", "get_list") => Ok(json!({ "list": core.store.snapshot().channels })),
        ("report", "add_report" | "upd_report") => {
            let ch = crate::models::ReportChannel { id: i(p, "id"), name: s(p, "name"),
                kind: s(p, "type"), config: j(p, "config"),
                created_at: String::new(), updated_at: crate::models::now() };
            if action == "add_report" {
                val(core.store.mutate(|db| {
                    let mut c = ch; c.id = crate::store::next_id(db, "channel");
                    c.created_at = crate::models::now(); c.updated_at = c.created_at.clone();
                    db.channels.push(c.clone()); Ok::<_, AppError>(c)
                })??)
            } else {
                let out = ch.clone();
                core.store.mutate(|db| { if let Some(s) = db.channels.iter_mut().find(|c| c.id == ch.id) { *s = ch; } })?;
                val(out)
            }
        }
        ("report", "del_report") => {
            let set: Vec<i64> = s(p, "ids").split(',').filter_map(|x| x.trim().parse().ok()).collect();
            Ok(json!({ "deleted": core.store.mutate(|db| { let n = db.channels.len(); db.channels.retain(|c| !set.contains(&c.id)); n - db.channels.len() })? }))
        }
        ("report", "notify_test") => Ok(crate::notify::test(core, i(p, "id")).await?),

        // --- settings ------------------------------------------------------
        ("setting", "get_setting") => {
            let mut s = core.store.snapshot().settings; s.remove("api_key");
            Ok(json!({ "settings": s }))
        }
        ("setting", "save_setting") => {
            let mut changed = Vec::new();
            for (k, v) in p.iter().filter(|(k, _)| !k.starts_with("api_") && *k != "timestamp") {
                let _ = core.store.mutate(|db| { db.settings.insert(k.clone(), v.clone()); });
                changed.push(k.clone());
            }
            let _ = core.emit("settings.updated", "compat", json!({ "keys": changed })).await;
            Ok(json!({ "updated": changed }))
        }
        ("setting", "get_version") => Ok(json!({ "version": env!("CARGO_PKG_VERSION"), "new_version": false })),
        ("setting", "download_data") => Ok(json!({ "state": std::fs::read_to_string(core.store.path())? })),
        ("setting", "upload_data") => {
            let raw = s(p, "state");
            let db: crate::store::Database = serde_json::from_str(&raw).map_err(|e| AppError::bad_request(format!("state: {e}")))?;
            std::fs::write(core.store.path(), serde_json::to_string_pretty(&db)?)?;
            Ok(json!({ "restored": true }))
        }
        ("setting", "shutdown" | "restart") => gone(action),

        // --- overview ------------------------------------------------------
        ("overview", "get_overviews") => Ok(crate::overview::overview(core)),

        // --- private CA ----------------------------------------------------
        ("private_ca", "get_ca_list") => Ok(json!({ "list": crate::private_ca::ca_list(core) })),
        ("private_ca", "create_root_ca") => val(crate::private_ca::create_ca(core, serde_json::from_value(json!({
            "name": s(p, "name"), "cn": s(p, "cn"), "o": s(p, "o"), "c": s(p, "c"),
            "algorithm": s(p, "algorithm"), "key_length": i(p, "key_length"),
            "valid_days": i(p, "valid_days"), "root_id": 0
        }))?).await?),
        ("private_ca", "create_intermediate_ca") => val(crate::private_ca::create_ca(core, serde_json::from_value(json!({
            "name": s(p, "name"), "cn": s(p, "cn"), "o": s(p, "o"), "c": s(p, "c"),
            "algorithm": s(p, "algorithm"), "key_length": i(p, "key_length"),
            "valid_days": i(p, "valid_days"), "root_id": i(p, "root_id")
        }))?).await?),
        ("private_ca", "del_ca") => Ok(json!({ "deleted": crate::private_ca::delete_ca(core, &s(p, "ids")).await? })),
        ("private_ca", "create_leaf_cert") => val(crate::private_ca::issue_leaf(core, serde_json::from_value(json!({
            "ca_id": i(p, "ca_id"), "cn": s(p, "cn"), "san": j(p, "san"), "usage": i(p, "usage"),
            "key_length": i(p, "key_length"), "valid_days": i(p, "valid_days"), "algorithm": s(p, "algorithm")
        }))?).await?),
        ("private_ca", "get_leaf_cert_list") => Ok(json!({ "list": crate::private_ca::leaf_list(core) })),
        ("private_ca", "del_leaf_cert") => Ok(json!({ "deleted": crate::private_ca::delete_leaf(core, &s(p, "ids"))? })),
        ("private_ca", "download_cert") => {
            let (content, name) = crate::private_ca::download(core, i(p, "id"), &s(p, "type"))?;
            Ok(json!({ "filename": name, "content": content }))
        }

        // --- plugins -------------------------------------------------------
        ("plugins", "bootstrap") => Ok(crate::plugin::bootstrap(core)),
        ("plugins", "list") => Ok(json!({ "list": crate::plugin::plugins(core) })),
        ("plugins", "enable") => val(crate::plugin::set_enabled(core, &s(p, "id"), true).await?),
        ("plugins", "disable" | "restart") => val(crate::plugin::set_enabled(core, &s(p, "id"), false).await?),

        // --- ssld extensions -----------------------------------------------
        ("webhook", a) => extension(core, a, p).await,
        ("events", a) => extension(core, &format!("events.{a}"), p).await,
        (g, a) => Err(AppError::not_found(format!("unknown compatibility action: {g}/{a}"))),
    }
}

async fn extension(core: &Shared, action: &str, p: &Params) -> Result<Value> {
    match action {
        "get_list" => Ok(json!({ "list": crate::webhook::list(core) })),
        "add" | "upd" => {
            let input = crate::models::WebhookInput {
                name: s(p, "name"), url: s(p, "url"),
                events: s(p, "events").split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
                event_mode: s(p, "event_mode"), secret: s(p, "secret"), method: s(p, "method"),
                headers: j(p, "headers"), body_template: s(p, "body_template"),
                active: b(p, "active", true), max_attempts: i(p, "max_attempts") as u32,
                backoff_seconds: i(p, "backoff_seconds") as u64, timeout_seconds: i(p, "timeout_seconds") as u64,
                skip_tls_verify: b(p, "skip_tls_verify", false), content_type: s(p, "content_type"),
                description: s(p, "description"),
            };
            if action == "add" { val(crate::webhook::create(core, input)?) }
            else { val(crate::webhook::update(core, &s(p, "id"), input)?) }
        },
        "del" => Ok(json!({ "deleted": crate::webhook::delete(core, &s(p, "ids"))? })),
        "test" => val(crate::webhook::test(core, &s(p, "id")).await?),
        "stats" => Ok(crate::webhook::stats(core)),
        "events.get_list" => Ok(json!({ "list": core.store.snapshot().event_log })),
        _ => Err(AppError::not_found(format!("unknown webhook action: {action}"))),
    }
}

