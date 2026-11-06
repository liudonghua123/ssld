//! Background scheduler: monitor probes, scheduled workflows, expiry events,
//! webhook retry bookkeeping and log retention.
use crate::state::Shared;
use serde_json::json;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub fn start(core: Shared) -> JoinHandle<()> {
    tokio::spawn(async move {
        let tick = core.config.scheduler.tick_seconds.max(1);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(tick));
        let mut last_minute = -1i64;
        loop {
            interval.tick().await;
            if !core.config.scheduler.enabled { continue; }
            let now = chrono::Utc::now();
            let minute = now.timestamp() / 60;

            crate::monitor::run_due(&core).await;

            if minute != last_minute {
                last_minute = minute;
                run_scheduled_workflows(&core, &now).await;
                scan_expiry(&core).await;
                cleanup(&core).await;
            }
        }
    })
}

async fn run_scheduled_workflows(core: &Shared, now: &chrono::DateTime<chrono::Utc>) {
    let db = core.store.snapshot();
    let candidates: Vec<i64> = db.workflows.iter()
        .filter(|w| w.active && w.exec_type == "auto")
        .filter(|w| crate::workflow::schedule_matches(&w.exec_time, now))
        .filter(|w| !db.histories.iter().any(|h| h.workflow_id == w.id
            && h.exec_type == "auto"
            && chrono::DateTime::parse_from_rfc3339(&h.created_at)
                .map(|d| d.timestamp() / 60 == now.timestamp() / 60).unwrap_or(false)))
        .map(|w| w.id).collect();
    drop(db);
    for id in candidates {
        let c = Arc::clone(core);
        tokio::spawn(async move {
            if let Err(e) = crate::workflow::execute(&c, id, "auto").await {
                tracing::warn!("scheduled workflow {id}: {e}");
            }
        });
    }
}

async fn scan_expiry(core: &Shared) {
    let db = core.store.snapshot();
    let threshold: i64 = db.settings.get("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let mut to_emit = Vec::new();
    for c in &db.certs {
        let d = crate::crypto::days_left(&c.end_time);
        let event = if d < 0 { Some("cert.expired") }
            else if d <= threshold { Some("cert.expiring") } else { None };
        if let Some(ev) = event {
            let marker = format!("expiry_notified:{}:{ev}:{}", c.id, c.end_time);
            if !db.settings.contains_key(&marker) { to_emit.push((ev, c.clone(), d, marker)); }
        }
    }
    drop(db);
    for (event, cert, days, marker) in to_emit {
        let _ = core.store.mutate(|db| { db.settings.insert(marker, chrono::Utc::now().to_rfc3339()); });
        let _ = core.emit(event, "scheduler", json!({
            "cert_id": cert.id, "domains": cert.domains, "days_left": days,
            "end_time": cert.end_time, "sha256": cert.sha256
        })).await;
    }
}

async fn cleanup(core: &Shared) {
    let _ = core.store.mutate(|db| {
        let cutoff = chrono::Utc::now().timestamp() - core.config.auth.session_timeout;
        db.sessions.retain(|s| chrono::DateTime::parse_from_rfc3339(&s.last_seen)
            .map(|d| d.timestamp() > cutoff).unwrap_or(false));
        let max_events = core.config.storage.max_event_log;
        let max_deliveries = core.config.storage.max_delivery_log;
        crate::store::trim(&mut db.event_log, max_events);
        crate::store::trim(&mut db.deliveries, max_deliveries);
    });
    let log_dir = std::path::PathBuf::from(&core.config.storage.workflow_log_dir);
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86400);
        for e in entries.flatten() {
            if let Ok(m) = e.metadata() {
                if m.modified().map(|t| t < cutoff).unwrap_or(false) { let _ = std::fs::remove_file(e.path()); }
            }
        }
    }
}

/// Manual trigger for the renewal scan used by MCP / REST coarse tools.
pub async fn renew_expiring(core: &Shared, force: bool) -> serde_json::Value {
    let db = core.store.snapshot();
    let threshold: i64 = db.settings.get("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let targets: Vec<(i64, Vec<String>)> = db.certs.iter()
        .filter(|c| force || crate::crypto::days_left(&c.end_time) <= threshold)
        .map(|c| (c.id, c.domains.clone())).collect();
    let dns_access = db.accesses.iter().find(|a| a.kind == "dns").cloned();
    drop(db);
    let mut results = Vec::new();
    for (id, domains) in targets {
        let Some(access) = dns_access.clone() else { break; };
        let req = crate::certs::ApplyRequest {
            domains: domains.clone(), dns_access_id: access.id, force: true,
            end_day: threshold, workflow_id: 0, history_id: String::new(),
            ..Default::default()
        };
        match crate::certs::apply_certificate(core, req).await {
            Ok(o) => results.push(json!({ "previous_cert_id": id, "ok": true, "new_cert_id": o.cert.id, "domains": o.cert.domains })),
            Err(e) => results.push(json!({ "previous_cert_id": id, "ok": false, "error": e.to_string(), "domains": domains })),
        }
    }
    json!({ "attempted": results.len(), "succeeded": results.iter().filter(|r| r["ok"] == true).count(), "results": results })
}
