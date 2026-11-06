//! Aggregations for the console home screen, MCP fleet tools and audits.
use crate::crypto;
use crate::state::Shared;
use serde_json::{json, Value};

pub fn overview(core: &Shared) -> Value {
    let db = core.store.snapshot();
    let threshold: i64 = db.settings.get("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let mut expiring = 0; let mut expired = 0; let mut valid = 0;
    let mut buckets = vec![0i64; 5];
    let mut upcoming: Vec<Value> = Vec::new();
    for c in &db.certs {
        let d = crypto::days_left(&c.end_time);
        if d < 0 { expired += 1; buckets[0] += 1; }
        else if d <= threshold { expiring += 1; buckets[1] += 1; }
        else if d <= 60 { buckets[2] += 1; valid += 1; }
        else if d <= 180 { buckets[3] += 1; valid += 1; }
        else { buckets[4] += 1; valid += 1; }
        upcoming.push(json!({ "id": c.id, "domains": c.domains, "days_left": d, "end_time": c.end_time }));
    }
    upcoming.sort_by_key(|v| v["days_left"].as_i64().unwrap_or(0));
    upcoming.truncate(8);
    let workflows_auto = db.workflows.iter().filter(|w| w.exec_type == "auto").count();
    let workflows_failed = db.workflows.iter().filter(|w| w.last_run_status == "fail" || w.last_run_status == "partial").count();
    let monitors_bad = db.monitors.iter().filter(|m| m.valid == -1).count();
    let deliveries_failed = db.deliveries.iter().filter(|d| !d.success).count();
    let mut recent: Vec<Value> = db.histories.iter().rev().take(5).map(|h| json!({
        "id": h.id, "workflow_id": h.workflow_id, "name": h.workflow_name,
        "status": h.status, "exec_type": h.exec_type, "created_at": h.created_at, "end_time": h.end_time
    })).collect();
    recent.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
    let mut events: Vec<Value> = db.event_log.iter().rev().take(12).map(|e| json!({
        "id": e.id, "event": e.event, "source": e.source, "created_at": e.created_at
    })).collect();
    events.reverse();
    let problems = expired * 3 + expiring + workflows_failed * 2 + monitors_bad * 2 + deliveries_failed;
    let health = (100 - problems * 4).max(0);
    json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_started_at": core.started_at,
        "health_score": health,
        "certificates": { "total": db.certs.len(), "valid": valid, "expiring": expiring, "expired": expired,
            "expiry_buckets": { "expired": buckets[0], "0_30_days": buckets[1], "31_60_days": buckets[2],
                "61_180_days": buckets[3], "over_180_days": buckets[4] } },
        "workflows": { "total": db.workflows.len(), "auto": workflows_auto,
            "active": db.workflows.iter().filter(|w| w.active).count(), "last_run_failed": workflows_failed,
            "runs": db.histories.len() },
        "monitors": { "total": db.monitors.len(), "active": db.monitors.iter().filter(|m| m.active).count(),
            "exception": monitors_bad, "error_records": db.err_records.len() },
        "webhooks": crate::webhook::stats(core),
        "credentials": { "total": db.accesses.len(),
            "dns": db.accesses.iter().filter(|a| a.kind == "dns").count(),
            "host": db.accesses.iter().filter(|a| a.kind == "host").count() },
        "notification_channels": db.channels.len(),
        "private_ca": { "cas": db.cas.len(), "leaves": db.leaves.len() },
        "plugins": { "total": db.plugins.len(), "enabled": db.plugins.iter().filter(|p| p.enabled).count() },
        "upcoming_expirations": upcoming,
        "recent_runs": recent,
        "recent_events": events,
        "recommendations": recommendations(expired, expiring, workflows_failed, monitors_bad, deliveries_failed, db.webhooks.len())
    })
}

fn recommendations(expired: usize, expiring: usize, wf: usize, mon: usize, del: usize, hooks: usize) -> Vec<Value> {
    let mut out = Vec::new();
    if expired > 0 { out.push(json!({ "severity": "critical", "text": format!("{expired} certificates have expired. Run a renewal now."), "action": "renew_expiring" })); }
    if expiring > 0 { out.push(json!({ "severity": "warning", "text": format!("{expiring} certificates enter the renewal window soon."), "action": "renew_expiring" })); }
    if wf > 0 { out.push(json!({ "severity": "warning", "text": format!("{wf} workflows last ended in failure or partial state."), "action": "inspect_workflows" })); }
    if mon > 0 { out.push(json!({ "severity": "warning", "text": format!("{mon} monitors are reporting an anomaly."), "action": "inspect_monitors" })); }
    if del > 0 { out.push(json!({ "severity": "info", "text": format!("{del} webhook deliveries need attention."), "action": "inspect_deliveries" })); }
    if hooks == 0 { out.push(json!({ "severity": "info", "text": "No webhook subscriptions yet. Events are only visible in the console.", "action": "configure_webhook" })); }
    if out.is_empty() { out.push(json!({ "severity": "ok", "text": "Fleet is healthy. Nothing needs attention.", "action": "none" })); }
    out
}

pub fn audit(core: &Shared) -> Value {
    let db = core.store.snapshot();
    let mut findings: Vec<Value> = Vec::new();
    for c in &db.certs {
        let d = crypto::days_left(&c.end_time);
        if d < 0 { findings.push(json!({ "cert_id": c.id, "severity": "critical", "finding": "expired", "domains": c.domains })); }
        else if d <= 14 { findings.push(json!({ "cert_id": c.id, "severity": "high", "finding": "expires within 14 days", "days_left": d, "domains": c.domains })); }
        if c.key_algorithm == "RSA" && c.signature_algorithm.contains("1.2.840.113549.1.1.5") {
            findings.push(json!({ "cert_id": c.id, "severity": "medium", "finding": "SHA-1 signature", "domains": c.domains }));
        }
        if !db.monitors.iter().any(|m| c.domains.iter().any(|d| m.target.contains(d))) {
            findings.push(json!({ "cert_id": c.id, "severity": "low", "finding": "no monitor covers these domains", "domains": c.domains }));
        }
    }
    for w in &db.webhooks {
        if w.active && w.url.starts_with("http://") {
            findings.push(json!({ "subscription_id": w.id, "severity": "medium", "finding": "webhook uses plaintext HTTP" }));
        }
        if w.active && w.secret.is_empty() {
            findings.push(json!({ "subscription_id": w.id, "severity": "medium", "finding": "webhook has no HMAC secret" }));
        }
    }
    if core.setting("api_key").unwrap_or_default().is_empty() {
        findings.push(json!({ "severity": "info", "finding": "open API signature key is not set" }));
    }
    json!({ "checked_at": chrono::Utc::now().to_rfc3339(),
        "findings": findings, "count": findings.len(),
        "critical": findings.iter().filter(|f| f["severity"] == "critical").count() })
}
