//! Certificate repository, import, export, reuse logic and the high level
//! `apply_certificate` operation shared by REST, workflows and MCP tools.
use crate::acme::{self, IssueRequest, IssueResult};
use crate::crypto;
use crate::error::{AppError, Result};
use crate::models::{now, Access, Cert, CertInput, Eab};
use crate::state::Shared;
use crate::store::next_id;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub fn list(core: &Shared, search: &str, status: &str, limit: usize) -> Vec<Value> {
    let threshold = core.setting("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let mut rows: Vec<Value> = core.store.snapshot().certs.into_iter().filter_map(|c| {
        let days = crypto::days_left(&c.end_time);
        let state = if days < 0 { "expired" } else if days <= threshold { "expiring" } else { "valid" };
        if !search.is_empty() && !c.domains.iter().any(|d| d.contains(search)) && !c.issuer.contains(search) { return None; }
        if status == "-1" && state != "expired" { return None; }
        if status == "1" && state != "expiring" { return None; }
        if status == "2" && state != "valid" { return None; }
        Some(json!({
            "id": c.id, "source": c.source, "sha256": c.sha256,
            "domains": c.domains, "issuer": c.issuer,
            "start_time": c.start_time, "end_time": c.end_time,
            "days_left": days, "status": state,
            "key_algorithm": c.key_algorithm, "signature_algorithm": c.signature_algorithm,
            "serial": c.serial, "workflow_id": c.workflow_id,
            "created_at": c.created_at, "updated_at": c.updated_at
        }))
    }).collect();
    rows.sort_by(|a, b| a["days_left"].as_i64().cmp(&b["days_left"].as_i64()));
    if limit > 0 { rows.truncate(limit); }
    rows
}

pub fn get(core: &Shared, id: i64) -> Result<Cert> {
    core.store.snapshot().certs.into_iter().find(|c| c.id == id)
        .ok_or_else(|| AppError::not_found("certificate not found"))
}

pub fn find_matching(core: &Shared, domains: &[String], end_day: i64) -> Option<Cert> {
    core.store.snapshot().certs.into_iter()
        .filter(|c| domains.iter().all(|d| c.domains.contains(d)))
        .filter(|c| crypto::days_left(&c.end_time) > end_day)
        .max_by_key(|c| c.id)
}

pub fn save(core: &Shared, source: &str, cert_pem: &str, key_pem: &str, issuer_pem: &str,
            history_id: &str, workflow_id: i64) -> Result<Cert> {
    crypto::validate_pair(cert_pem, key_pem)?;
    let p = crypto::parse_certificate(cert_pem)?;
    let existing = core.store.snapshot().certs.into_iter().find(|c| c.sha256 == p.sha256);
    if let Some(c) = existing { return Ok(c); }
    let ts = now();
    let cert = Cert {
        id: 0, source: source.into(), sha256: p.sha256.clone(), history_id: history_id.into(),
        key: key_pem.into(), cert: cert_pem.into(), issuer_cert: issuer_pem.into(),
        domains: p.domains, created_at: ts.clone(), updated_at: ts, issuer: p.issuer,
        start_time: p.not_before, end_time: p.not_after, end_day: p.days_left,
        workflow_id, signature_algorithm: p.signature_algorithm, key_algorithm: p.key_algorithm,
        serial: p.serial,
    };
    let saved = core.store.mutate(|db| {
        let mut c = cert.clone(); c.id = next_id(db, "cert");
        db.certs.push(c.clone()); c
    })?;
    Ok(saved)
}

pub async fn import(core: &Shared, input: CertInput) -> Result<Cert> {
    let cert = save(core, "upload", &input.cert, &input.key, &input.issuer_cert, "", 0)?;
    let _ = core.emit("cert.imported", "cert", json!({ "id": cert.id, "domains": cert.domains, "issuer": cert.issuer })).await;
    Ok(cert)
}

pub async fn delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    let n = core.store.mutate(|db| {
        let before = db.certs.len();
        db.certs.retain(|c| !set.contains(&c.id));
        before - db.certs.len()
    })?;
    let _ = core.emit("cert.deleted", "cert", json!({ "ids": set, "deleted": n })).await;
    Ok(n)
}

pub fn export(core: &Shared, id: i64, format: &str) -> Result<(Vec<u8>, &'static str, String)> {
    crypto::export_bundle(&get(core, id)?, format)
}

pub async fn inspect(core: &Shared, id: i64) -> Result<Value> {
    let c = get(core, id)?;
    let parsed = crypto::parse_certificate(&c.cert)?;
    let deploys: Vec<Value> = core.store.snapshot().workflow_deploys.iter()
        .filter(|d| d.cert_hash == c.sha256)
        .map(|d| json!({"workflow_id": d.workflow_id, "node_id": d.node_id, "status": d.status, "at": d.updated_at}))
        .collect();
    Ok(json!({ "certificate": c, "parsed": parsed, "deployed_to": deploys }))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplyRequest {
    pub domains: Vec<String>,
    pub ca: String,
    pub cadirurl: String,
    pub email: String,
    pub algorithm: String,
    pub dns_access_id: i64,
    pub eab_id: i64,
    pub account_id: i64,
    pub end_day: i64,
    pub max_wait: u64,
    pub certificate_timeout: u64,
    pub ari_enabled: bool,
    pub skip_check: bool,
    pub force: bool,
    pub workflow_id: i64,
    pub history_id: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplyOutcome {
    pub cert: Cert,
    pub reused: bool,
    pub renewed: bool,
    pub detail: Value,
}

fn eab_for(core: &Shared, ca: &str, eab_id: i64) -> Option<Eab> {
    let db = core.store.snapshot();
    if eab_id > 0 { return db.eabs.into_iter().find(|e| e.id == eab_id); }
    let kind = if ca == "letsencrypt" { "letsencrypt" } else { ca };
    db.eabs.iter().find(|e| e.ca == kind).cloned()
}

/// Issue (or reuse) a certificate. This is the single implementation behind
/// `POST /api/v1/certificates/apply`, the workflow `apply` node and the MCP
/// `issue_and_deploy` tool.
pub async fn apply_certificate(core: &Shared, req: ApplyRequest) -> Result<ApplyOutcome> {
    if req.domains.is_empty() { return Err(AppError::bad_request("domains is required")); }
    let db = core.store.snapshot();
    let end_day = if req.end_day > 0 { req.end_day } else {
        core.setting("renew_before_days").and_then(|v| v.parse().ok()).unwrap_or(30)
    };
    let ca = if req.ca.is_empty() { core.setting("default_ca").unwrap_or_else(|| "letsencrypt".into()) } else { req.ca.clone() };
    let algorithm = if req.algorithm.is_empty() { core.setting("default_algorithm").unwrap_or_else(|| "RSA2048".into()) } else { req.algorithm.clone() };
    let cadirurl = if !req.cadirurl.is_empty() { req.cadirurl.clone() }
        else if ca == "custom" { return Err(AppError::bad_request("custom CA requires cadirurl")) }
        else if let Some(v) = db.settings.get("ca_directory_override") { v.clone() }
        else { crate::providers::ca_directory(&ca).ok_or_else(|| AppError::bad_request(format!("unknown CA: {ca}")))? };
    let email = if req.email.is_empty() { core.config.acme.contact_email.clone() } else { req.email.clone() };
    if email.is_empty() { return Err(AppError::bad_request("contact email is required for ACME registration")); }

    if !req.force {
        if let Some(existing) = find_matching(core, &req.domains, end_day) {
            let _ = core.emit("cert.reused", "cert", json!({ "id": existing.id, "domains": req.domains, "days_left": crypto::days_left(&existing.end_time) })).await;
            return Ok(ApplyOutcome { cert: existing, reused: true, renewed: false,
                detail: json!({ "reason": "existing certificate still outside renewal window" }) });
        }
    }
    let dns_access: Access = db.accesses.iter().find(|a| a.id == req.dns_access_id && a.kind == "dns")
        .cloned().ok_or_else(|| AppError::not_found("DNS credential not found"))?;
    let account = db.acme_accounts.iter().find(|a| a.id == req.account_id && a.ca == ca).cloned()
        .or_else(|| db.acme_accounts.iter().find(|a| a.ca == ca).cloned());
    let eab = eab_for(core, &ca, req.eab_id);
    if matches!(ca.as_str(), "google" | "sslcom" | "sslcom-rsa" | "sslcom-ecc" | "custom") && eab.is_none() {
        return Err(AppError::bad_request(format!("{ca} requires EAB credentials")));
    }
    let had_existing = db.certs.iter().any(|c| req.domains.iter().all(|d| c.domains.contains(d)));
    if had_existing {
        let _ = core.emit("cert.renewal.started", "acme", json!({ "domains": req.domains, "ca": ca })).await;
    }
    drop(db);

    let issue_req = IssueRequest {
        domains: req.domains.clone(), ca: ca.clone(), cadirurl, email, algorithm,
        dns_access, eab, account, max_wait: req.max_wait.max(1),
        certificate_timeout: req.certificate_timeout.max(10),
        ari_enabled: req.ari_enabled || core.config.acme.ari_enabled,
        replaces_cert_id: None, nameservers: core.config.acme.nameservers.clone(),
        skip_check: req.skip_check || core.config.acme.skip_dns_check,
    };
    let outcome: std::result::Result<IssueResult, AppError> = acme::issue(core, issue_req).await;
    match outcome {
        Ok(issued) => {
            let cert = save(core, "workflow", &issued.cert_pem, &issued.key_pem, &issued.issuer_pem, &req.history_id, req.workflow_id)?;
            let event = if had_existing { "cert.renewal.succeeded" } else { "cert.issued" };
            let _ = core.emit(event, "acme", json!({
                "id": cert.id, "domains": cert.domains, "issuer": cert.issuer,
                "sha256": cert.sha256, "ca": ca, "end_time": cert.end_time
            })).await;
            Ok(ApplyOutcome { cert, reused: false, renewed: had_existing,
                detail: json!({ "ca": issued.ca, "domains": issued.domains,
                    "account_id": issued.account_id, "ari": issued.renewal_info }) })
        }
        Err(e) => {
            if had_existing {
                let _ = core.emit("cert.renewal.failed", "acme", json!({ "domains": req.domains, "error": e.to_string() })).await;
            }
            Err(e)
        }
    }
}

/// Parse a PEM pasted into the UI without storing it.
pub fn preview(pem: &str) -> Result<Value> { Ok(serde_json::to_value(crypto::parse_certificate(pem)?)?) }

/// Import monitor batch lines: `name,target,type,channels,cycle,gap,active,advance`.
pub fn parse_monitor_batch(text: &str, format: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    if format == "json" {
        let value: Value = serde_json::from_str(text).map_err(|e| AppError::bad_request(format!("JSON import: {e}")))?;
        let arr = value.as_array().cloned().unwrap_or_else(|| vec![value]);
        for item in arr {
            if item.get("target").and_then(|v| v.as_str()).is_none() { continue; }
            out.push(item);
        }
    } else {
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("name,") { continue; }
            let cols: Vec<&str> = line.split(|c| c == ',' || c == '\t' || c == '|').map(str::trim).collect();
            if cols.len() < 2 { return Err(AppError::bad_request(format!("line {} has too few columns", i + 1))); }
            out.push(json!({
                "name": cols[0], "target": cols[1],
                "monitor_type": cols.get(2).filter(|s| !s.is_empty()).unwrap_or(&"https"),
                "report_types": cols.get(3).map(|s| s.split(';').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default(),
                "cycle": cols.get(4).and_then(|s| s.parse().ok()).unwrap_or(60),
                "repeat_send_gap": cols.get(5).and_then(|s| s.parse().ok()).unwrap_or(10),
                "active": cols.get(6).map(|s| *s != "0").unwrap_or(true),
                "advance_day": cols.get(7).and_then(|s| s.parse().ok()).unwrap_or(30)
            }));
        }
    }
    Ok(out)
}
