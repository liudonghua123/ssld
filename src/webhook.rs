//! Configurable webhook subsystem: subscriptions with event filters, HMAC
//! signatures, custom headers and body templates, automatic retries with
//! backoff, a delivery ledger, manual redelivery and test sends.
use crate::error::{AppError, Result};
use crate::models::{now, uid, EventRecord, WebhookDelivery, WebhookInput, WebhookSubscription};
use crate::state::Shared;
use crate::store::{next_id, trim};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn normalise(input: WebhookInput, existing: Option<WebhookSubscription>) -> Result<WebhookSubscription> {
    if input.url.trim().is_empty() { return Err(AppError::bad_request("webhook url is required")); }
    if !input.url.starts_with("http://") && !input.url.starts_with("https://") {
        return Err(AppError::bad_request("webhook url must be http(s)"));
    }
    for e in &input.events {
        if !e.ends_with(".*") && !crate::providers::event_exists(e) && e != "*" {
            return Err(AppError::bad_request(format!("unknown event: {e}")));
        }
    }
    let old = existing.unwrap_or_default();
    let method = if input.method.is_empty() { "POST".into() } else { input.method.to_uppercase() };
    let mode = if input.event_mode.is_empty() { "include".into() } else { input.event_mode.clone() };
    let content_type = if input.content_type.is_empty() { "application/json".into() } else { input.content_type.clone() };
    let body_template = if input.body_template.is_empty() {
        "{\"id\":\"__id__\",\"event\":\"__event__\",\"created_at\":\"__created_at__\",\"source\":\"__source__\",\"data\":__payload__}".into()
    } else { input.body_template.clone() };
    let old_id = old.id;
    let generated_name = format!("hook-{}", &old_id[..old_id.len().min(6)]);
    Ok(WebhookSubscription {
        id: if old_id.is_empty() { uid() } else { old_id },
        name: if input.name.is_empty() { generated_name } else { input.name },
        url: input.url, events: input.events, event_mode: mode,
        secret: input.secret, method, headers: input.headers, body_template,
        active: input.active, max_attempts: input.max_attempts.max(1),
        backoff_seconds: input.backoff_seconds, timeout_seconds: input.timeout_seconds,
        skip_tls_verify: input.skip_tls_verify, content_type,
        created_at: if old.created_at.is_empty() { now() } else { old.created_at },
        updated_at: now(), description: input.description,
    })
}

pub fn list(core: &Shared) -> Vec<WebhookSubscription> { core.store.snapshot().webhooks }

pub fn create(core: &Shared, input: WebhookInput) -> Result<WebhookSubscription> {
    let sub = normalise(input, None)?;
    core.store.mutate(|db| db.webhooks.push(sub.clone()))?;
    core.oplog("api", "webhook.create", &sub.id, json!({"url": sub.url, "events": sub.events}));
    Ok(sub)
}

pub fn update(core: &Shared, id: &str, input: WebhookInput) -> Result<WebhookSubscription> {
    let old = core.store.snapshot().webhooks.into_iter().find(|w| w.id == id)
        .ok_or_else(|| AppError::not_found("webhook subscription not found"))?;
    let sub = normalise(input, Some(old))?;
    core.store.mutate(|db| {
        if let Some(slot) = db.webhooks.iter_mut().find(|w| w.id == id) { *slot = sub.clone(); }
    })?;
    core.oplog("api", "webhook.update", id, json!({"url": sub.url}));
    Ok(sub)
}

pub fn delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let n = core.store.mutate(|db| {
        let before = db.webhooks.len();
        db.webhooks.retain(|w| !set.contains(&w.id));
        before - db.webhooks.len()
    })?;
    core.oplog("api", "webhook.delete", ids, json!({"deleted": n}));
    Ok(n)
}

pub fn toggle(core: &Shared, id: &str, active: bool) -> Result<WebhookSubscription> {
    let sub = core.store.mutate(|db| {
        let slot = db.webhooks.iter_mut().find(|w| w.id == id)
            .ok_or_else(|| AppError::not_found("webhook subscription not found"))?;
        slot.active = active; slot.updated_at = now();
        Ok::<_, AppError>(slot.clone())
    })??;
    Ok(sub)
}

fn render(template: &str, ev: &EventRecord) -> String {
    let mut out = template.to_string();
    let payload_json = serde_json::to_string(&ev.payload).unwrap_or_else(|_| "{}".into());
    out = out.replace("__payload__", &payload_json);
    let meta = json!({
        "id": ev.id, "event": ev.event, "created_at": ev.created_at, "source": ev.source
    });
    for key in ["id", "event", "created_at", "source", "timestamp"] {
        let token = format!("__{key}__");
        if !out.contains(&token) { continue; }
        let value = if key == "timestamp" { Value::String(chrono::Utc::now().timestamp().to_string()) }
            else { meta.get(key).cloned().unwrap_or(Value::Null) };
        let plain = match &value { Value::String(s) => s.clone(), _ => value.to_string() };
        let escaped = serde_json::to_string(&plain).unwrap_or_default();
        let escaped = escaped.trim_matches('"').to_string();
        out = out.replace(&token, &escaped);
    }
    // Any top level payload key can be used as __key__.
    if let Some(obj) = ev.payload.as_object() {
        for (k, v) in obj {
            let token = format!("__{k}__");
            if !out.contains(&token) { continue; }
            let plain = match v { Value::String(s) => s.clone(), _ => v.to_string() };
            let escaped = serde_json::to_string(&plain).unwrap_or_default().trim_matches('"').to_string();
            out = out.replace(&token, &escaped);
        }
    }
    out
}

fn build_client(core: &Shared, sub: &WebhookSubscription) -> reqwest::Client {
    if !sub.skip_tls_verify {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(sub.timeout_seconds.max(1)))
            .user_agent(&core.config.webhook.user_agent);
        if sub.skip_tls_verify { builder = builder.danger_accept_invalid_certs(true); }
        builder.build().unwrap_or_else(|_| core.http.clone())
    } else {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(sub.timeout_seconds.max(1)))
            .danger_accept_invalid_certs(true)
            .user_agent(&core.config.webhook.user_agent)
            .build().unwrap_or_else(|_| core.http.clone())
    }
}

fn record_delivery(core: &Shared, mut d: WebhookDelivery) {
    let cap = core.config.storage.max_delivery_log;
    let _ = core.store.mutate(|db| {
        if let Some(slot) = db.deliveries.iter_mut().find(|x| x.id == d.id) { *slot = d.clone(); }
        else { d.id = if d.id.is_empty() { uid() } else { d.id.clone() }; db.deliveries.push(d.clone()); }
        trim(&mut db.deliveries, cap);
    });
}

/// Send one event to one subscription, retrying with linear backoff.
pub async fn deliver(core: Shared, sub: WebhookSubscription, ev: EventRecord) -> WebhookDelivery {
    let delivery_id = uid();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let body = render(&sub.body_template, &ev);
    let signature = if sub.secret.is_empty() { String::new() }
        else { format!("sha256={}", crate::crypto::hmac_sha256_hex(&sub.secret, format!("{timestamp}.{body}").as_bytes())) };
    let mut d = WebhookDelivery {
        id: delivery_id.clone(), subscription_id: sub.id.clone(), subscription_name: sub.name.clone(),
        event: ev.event.clone(), payload: ev.payload.clone(), request_body: body.clone(),
        status_code: 0, success: false, attempts: 0, next_retry: String::new(),
        error: String::new(), duration_ms: 0, created_at: now(),
    };
    let client = build_client(&core, &sub);
    let max = sub.max_attempts.min(10).max(1);
    for attempt in 1..=max {
        d.attempts = attempt;
        let start = Instant::now();
        let mut req = if sub.method == "GET" {
            client.get(&sub.url).query(&[("event", &ev.event), ("id", &ev.id), ("payload", &body)])
        } else {
            client.request(
                reqwest::Method::from_bytes(sub.method.as_bytes()).unwrap_or(reqwest::Method::POST),
                &sub.url,
            ).body(body.clone())
        };
        req = req.header("Content-Type", sub.content_type.as_str())
            .header("X-SSLD-Event", ev.event.as_str())
            .header("X-SSLD-Delivery", delivery_id.as_str())
            .header("X-SSLD-Idempotency-Key", ev.id.as_str())
            .header("X-SSLD-Timestamp", timestamp.as_str())
            .header(core.config.webhook.signature_header.as_str(), signature.as_str());
        if let Some(obj) = sub.headers.as_object() {
            for (k, v) in obj {
                let val = match v { Value::String(s) => render(s, &ev), _ => render(&v.to_string(), &ev) };
                req = req.header(k, val);
            }
        }
        match req.send().await {
            Ok(resp) => {
                d.status_code = resp.status().as_u16() as i64;
                d.duration_ms = start.elapsed().as_millis() as u64;
                if resp.status().is_success() {
                    d.success = true; d.error.clear(); d.next_retry.clear();
                    record_delivery(&core, d.clone());
                    return d;
                }
                d.error = format!("HTTP {}", resp.status());
            }
            Err(e) => {
                d.status_code = 0;
                d.duration_ms = start.elapsed().as_millis() as u64;
                d.error = e.to_string();
            }
        }
        if attempt < max {
            let delay = sub.backoff_seconds.saturating_mul(attempt as u64).max(1);
            d.next_retry = (chrono::Utc::now() + chrono::Duration::seconds(delay as i64)).to_rfc3339();
            record_delivery(&core, d.clone());
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }
    record_delivery(&core, d.clone());
    let _ = core.emit("webhook.delivery_failed", "webhook", json!({
        "subscription_id": sub.id, "subscription_name": sub.name,
        "event": ev.event, "attempts": d.attempts, "error": d.error
    })).await;
    d
}

pub fn spawn_dispatch(core: Shared, ev: EventRecord) {
    if !core.config.webhook.enabled { return; }
    let subs: Vec<WebhookSubscription> = core.store.snapshot().webhooks.into_iter()
        .filter(|s| s.active && crate::providers::matches_event(&s.events, &ev.event, &s.event_mode))
        .collect();
    if subs.is_empty() { return; }
    tokio::spawn(async move {
        for sub in subs {
            let _ = deliver(Arc::clone(&core), sub, ev.clone()).await;
        }
    });
}

pub async fn test(core: &Shared, id: &str) -> Result<WebhookDelivery> {
    let sub = core.store.snapshot().webhooks.into_iter().find(|w| w.id == id)
        .ok_or_else(|| AppError::not_found("webhook subscription not found"))?;
    let ev = crate::events::record("webhook.test", "webhook", json!({
        "message": "This is a test delivery from ssld.",
        "subscription": sub.name,
        "url": sub.url
    }));
    let _ = core.store.mutate(|db| { db.event_log.push(ev.clone()); });
    Ok(deliver(Arc::clone(core), sub, ev).await)
}

pub async fn redeliver(core: &Shared, delivery_id: &str) -> Result<WebhookDelivery> {
    let snapshot = core.store.snapshot();
    let old = snapshot.deliveries.into_iter().find(|d| d.id == delivery_id)
        .ok_or_else(|| AppError::not_found("delivery not found"))?;
    let sub = snapshot.webhooks.into_iter().find(|w| w.id == old.subscription_id)
        .ok_or_else(|| AppError::not_found("subscription no longer exists"))?;
    let ev = crate::events::record(&old.event, "replay", old.payload.clone());
    Ok(deliver(Arc::clone(core), sub, ev).await)
}

pub fn stats(core: &Shared) -> Value {
    let db = core.store.snapshot();
    let total = db.deliveries.len();
    let ok = db.deliveries.iter().filter(|d| d.success).count();
    let pending = db.deliveries.iter().filter(|d| !d.success && !d.next_retry.is_empty()).count();
    let by_event = db.deliveries.iter().fold(serde_json::Map::new(), |mut m, d| {
        let e = m.entry(d.event.clone()).or_insert(json!(0));
        if let Some(n) = e.as_i64() { *e = json!(n + 1); }
        m
    });
    let _ = next_id; // keep helper import visible for future aggregate counters
    json!({
        "subscriptions": db.webhooks.len(),
        "active_subscriptions": db.webhooks.iter().filter(|w| w.active).count(),
        "deliveries": total, "succeeded": ok, "failed": total - ok, "pending_retry": pending,
        "success_rate": if total == 0 { 0.0 } else { (ok as f64 / total as f64 * 1000.0).round() / 10.0 },
        "by_event": Value::Object(by_event)
    })
}
