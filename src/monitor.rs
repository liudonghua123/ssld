//! Certificate monitoring: HTTPS / SMTPS probes, chain parsing, expiry
//! thresholds, anomaly records, alert suppression and batch import.
use crate::crypto;
use crate::error::{AppError, Result};
use crate::models::{now, uid, ErrRecord, Monitor, MonitorInput};
use crate::state::Shared;
use crate::store::{next_id, trim};
use serde_json::{json, Value};

pub fn list(core: &Shared, search: &str) -> Vec<Value> {
    core.store.snapshot().monitors.into_iter()
        .filter(|m| search.is_empty() || m.name.contains(search) || m.target.contains(search))
        .map(|m| json!({
            "id": m.id, "name": m.name, "target": m.target, "monitor_type": m.monitor_type,
            "report_types": m.report_types, "active": m.active, "valid": m.valid,
            "cycle": m.cycle, "advance_day": m.advance_day, "repeat_send_gap": m.repeat_send_gap,
            "last_time": m.last_time, "except_end_time": m.except_end_time,
            "created_at": m.created_at, "updated_at": m.updated_at,
            "info": m.info
        })).collect()
}

pub fn get(core: &Shared, id: i64) -> Result<Monitor> {
    core.store.snapshot().monitors.into_iter().find(|m| m.id == id)
        .ok_or_else(|| AppError::not_found("monitor not found"))
}

pub fn create(core: &Shared, input: MonitorInput) -> Result<Monitor> {
    if input.target.trim().is_empty() { return Err(AppError::bad_request("target is required")); }
    let ts = now();
    let m = Monitor {
        id: 0, name: if input.name.is_empty() { input.target.clone() } else { input.name },
        target: input.target, monitor_type: if input.monitor_type.is_empty() { "https".into() } else { input.monitor_type },
        report_types: input.report_types, active: input.active,
        info: Value::Null, last_time: String::new(), except_end_time: String::new(),
        updated_at: ts.clone(), created_at: ts,
        cycle: input.cycle.max(1), repeat_send_gap: input.repeat_send_gap.max(1),
        advance_day: if input.advance_day <= 0 { 30 } else { input.advance_day },
        valid: 0, error_streak: 0,
    };
    Ok(core.store.mutate(|db| { let mut x = m; x.id = next_id(db, "monitor"); db.monitors.push(x.clone()); x })?)
}

pub fn update(core: &Shared, id: i64, input: MonitorInput) -> Result<Monitor> {
    let old = get(core, id)?;
    let m = Monitor {
        id, name: input.name, target: input.target,
        monitor_type: if input.monitor_type.is_empty() { old.monitor_type } else { input.monitor_type },
        report_types: input.report_types, active: input.active, info: old.info,
        last_time: old.last_time, except_end_time: old.except_end_time, updated_at: now(),
        created_at: old.created_at, cycle: input.cycle.max(1),
        repeat_send_gap: input.repeat_send_gap.max(1), advance_day: input.advance_day.max(1),
        valid: old.valid, error_streak: old.error_streak,
    };
    core.store.mutate(|db| { if let Some(s) = db.monitors.iter_mut().find(|x| x.id == id) { *s = m.clone(); } })?;
    Ok(m)
}

pub fn delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.monitors.len();
        db.monitors.retain(|m| !set.contains(&m.id));
        db.err_records.retain(|e| !set.contains(&e.monitor_id));
        before - db.monitors.len()
    })?)
}

pub fn toggle(core: &Shared, id: i64, active: bool) -> Result<()> {
    core.store.mutate(|db| {
        let m = db.monitors.iter_mut().find(|x| x.id == id)
            .ok_or_else(|| AppError::not_found("monitor not found"))?;
        m.active = active; m.updated_at = now(); Ok::<(), AppError>(())
    })?
}

pub fn err_records(core: &Shared, monitor_id: i64) -> Vec<Value> {
    let mut rows: Vec<Value> = core.store.snapshot().err_records.into_iter()
        .filter(|e| monitor_id == 0 || e.monitor_id == monitor_id)
        .map(|e| json!({ "id": e.id, "monitor_id": e.monitor_id, "created_at": e.created_at, "msg": e.msg, "info": e.info })).collect();
    rows.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
    rows.truncate(200);
    rows
}

pub fn detail(core: &Shared, id: i64) -> Result<Value> {
    let m = get(core, id)?;
    let seven_days_ago = (chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339();
    let errors = core.store.snapshot().err_records.into_iter()
        .filter(|e| e.monitor_id == id && e.created_at > seven_days_ago).count();
    Ok(json!({ "monitor": m, "chain": m.info, "errors_last_7_days": errors,
        "recent_records": err_records(core, id) }))
}

pub fn template(format: &str) -> String {
    let header = "name,target,monitor_type,report_types,cycle,repeat_send_gap,active,advance_day\n";
    let sample = "Example site,example.com,https,,60,10,1,30\n";
    match format {
        "json" => "[\n  {\"name\":\"Example site\",\"target\":\"example.com\",\"monitor_type\":\"https\",\"report_types\":[],\"cycle\":60,\"repeat_send_gap\":10,\"active\":true,\"advance_day\":30}\n]\n".into(),
        "csv" | "txt" => format!("{header}{sample}"),
        _ => format!("{header}{sample}"),
    }
}

fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    let t = target.trim().trim_start_matches("https://").trim_start_matches("http://");
    if let Some((h, p)) = t.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() { return (h.to_string(), port); }
    }
    (t.trim_end_matches('/').to_string(), default_port)
}

/// Probe a target and return a certificate chain description.
pub fn probe(target: &str, monitor_type: &str) -> Value {
    let (host, port) = split_host_port(target, if monitor_type == "smtp" { 465 } else { 443 });
    let mut args: Vec<String> = vec!["s_client".into(), "-connect".into(), format!("{host}:{port}"),
        "-servername".into(), host.clone(), "-showcerts".into()];
    if monitor_type == "smtp" {
        args.push("-starttls".into()); args.push("smtp".into());
    }
    let output = std::process::Command::new("openssl")
        .args(&args).stdin(std::process::Stdio::null()).output();
    let text = match output {
        Ok(o) => format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        Err(_) => String::new(),
    };
    if !text.contains("BEGIN CERTIFICATE") {
        // Honest fallback: report reachability only, never pretend to have a chain.
        use std::net::ToSocketAddrs;
        let reachable = format!("{host}:{port}").to_socket_addrs().ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok())
            .unwrap_or(false);
        return json!({
            "host": host, "port": port, "valid": reachable, "probe": "tcp",
            "verify_error": if reachable { "openssl s_client unavailable: chain not inspected" } else { "connection failed" },
            "chain": [], "days_left": Value::Null
        });
    }
    let mut blocks: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains("BEGIN CERTIFICATE") { inside = true; cur.clear(); }
        if inside { cur.push_str(line); cur.push('\n'); }
        if line.contains("END CERTIFICATE") { inside = false; blocks.push(cur.trim().into()); }
    }
    let verify_ok = text.contains("Verify return code: 0 (ok)") || text.contains("Verify return code: 0");
    let verify_error = if verify_ok { String::new() } else {
        text.lines().find(|l| l.contains("Verify return code")).unwrap_or("chain verification failed").trim().into()
    };
    let mut chain = Vec::new();
    for b in &blocks {
        if let Ok(p) = crypto::parse_certificate(b) { chain.push(json!(p)); }
    }
    let leaf = chain.first().cloned().unwrap_or(json!({}));
    let days_left = leaf.get("days_left").and_then(|v| v.as_i64());
    let valid = verify_ok && days_left.unwrap_or(-1) > 0;
    json!({
        "host": host, "port": port, "probe": "openssl", "valid": valid,
        "verify_error": verify_error, "chain": chain,
        "common_name": leaf.get("subject_cn"), "ca": leaf.get("issuer"),
        "not_before": leaf.get("not_before"), "not_after": leaf.get("not_after"),
        "days_left": days_left, "sha256": leaf.get("sha256"),
        "signature_algorithm": leaf.get("signature_algorithm"),
        "sans": leaf.get("domains")
    })
}

/// Run one monitor: update state, write anomaly records and emit / notify.
pub async fn check(core: &Shared, id: i64) -> Result<Value> {
    let m = get(core, id)?;
    let info = probe(&m.target, &m.monitor_type);
    let days = info.get("days_left").and_then(|v| v.as_i64()).unwrap_or(-1);
    let verify_error = info.get("verify_error").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut problems: Vec<String> = Vec::new();
    if !info.get("valid").and_then(|v| v.as_bool()).unwrap_or(false) {
        problems.push(if verify_error.is_empty() { "certificate chain verification failed".into() } else { verify_error.clone() });
    }
    if days >= 0 && days <= m.advance_day { problems.push(format!("certificate expires in {days} days")); }
    if days < 0 { problems.push("certificate has expired".into()); }
    let healthy = problems.is_empty();
    let msg = problems.join("; ");
    let ts = now();
    let (was_broken, streak) = core.store.mutate(|db| {
        let slot = db.monitors.iter_mut().find(|x| x.id == id)
            .ok_or_else(|| AppError::not_found("monitor not found"))?;
        let was = slot.valid == -1;
        slot.valid = if healthy { 1 } else { -1 };
        slot.info = info.clone();
        slot.last_time = ts.clone();
        slot.updated_at = ts.clone();
        slot.error_streak = if healthy { 0 } else { slot.error_streak + 1 };
        if !healthy { slot.except_end_time = ts.clone(); }
        Ok::<_, AppError>((was, slot.error_streak))
    })??;
    if !healthy {
        let rec = ErrRecord { id: uid(), monitor_id: id, created_at: ts.clone(), info: info.clone(), msg: msg.clone() };
        let _ = core.store.mutate(|db| { db.err_records.push(rec); trim(&mut db.err_records, 2000); });
        let _ = core.emit("monitor.check_failed", "monitor", json!({
            "id": id, "name": m.name, "target": m.target, "problems": problems
        })).await;
        let should_alert = !was_broken || streak >= m.repeat_send_gap.max(1);
        if should_alert {
            let subject = "ssld certificate monitor alert";
            let body = format!("Monitor: {}\nType: {}\nTarget: {}\nProblem: {}\nChecked at: {}\nPlease review.",
                m.name, m.monitor_type, m.target, msg, ts);
            let results = crate::notify::notify_many(core, &m.report_types, subject, &body,
                &json!({ "monitor_id": id, "target": m.target, "days_left": days })).await;
            let _ = core.emit("monitor.alert", "monitor", json!({
                "id": id, "name": m.name, "target": m.target, "message": msg, "notifications": results
            })).await;
        }
    } else if was_broken {
        let _ = core.emit("monitor.recovered", "monitor", json!({ "id": id, "name": m.name, "target": m.target })).await;
        let _ = core.emit("cert.recovered", "monitor", json!({ "target": m.target, "days_left": days })).await;
    }
    Ok(json!({ "id": id, "healthy": healthy, "problems": problems, "info": info, "checked_at": ts }))
}

pub async fn import(core: &Shared, text: &str, format: &str) -> Result<Value> {
    let rows = crate::certs::parse_monitor_batch(text, format)?;
    let mut created = 0;
    for row in rows {
        let input: MonitorInput = serde_json::from_value(row)?;
        let _ = create(core, input)?;
        created += 1;
    }
    Ok(json!({ "imported": created }))
}

pub async fn run_due(core: &Shared) {
    let now_ts = chrono::Utc::now().timestamp();
    let due: Vec<i64> = core.store.snapshot().monitors.iter().filter(|m| {
        if !m.active { return false; }
        match chrono::DateTime::parse_from_rfc3339(&m.last_time) {
            Ok(t) => now_ts - t.timestamp() >= m.cycle.max(1) * 60,
            Err(_) => true,
        }
    }).map(|m| m.id).collect();
    for id in due {
        if let Err(e) = check(core, id).await {
            tracing::warn!("monitor {id}: {e}");
        }
    }
}
