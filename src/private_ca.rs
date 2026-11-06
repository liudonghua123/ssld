//! Private CA: root / intermediate certificates, leaf issuance, SM2 dual
//! certificate storage, deletion constraints and workflow issuance.
use crate::crypto::{self, CaMaterial};
use crate::error::{AppError, Result};
use crate::models::{now, CaConfig, CaRecord, Cert, LeafConfig, LeafRecord};
use crate::state::Shared;
use crate::store::next_id;
use serde_json::{json, Value};

pub fn ca_list(core: &Shared) -> Vec<Value> {
    let db = core.store.snapshot();
    db.cas.iter().map(|c| json!({
        "id": c.id, "root_id": c.root_id, "name": c.name, "cn": c.cn, "o": c.o, "c": c.c,
        "algorithm": c.algorithm, "key_length": c.key_length,
        "not_before": c.not_before, "not_after": c.not_after, "created_at": c.created_at,
        "is_root": c.root_id == 0,
        "has_sm2_dual_cert": !c.en_cert.is_empty(),
        "intermediates": db.cas.iter().filter(|x| x.root_id == c.id).count(),
        "leaves": db.leaves.iter().filter(|l| l.ca_id == c.id).count()
    })).collect()
}

pub async fn create_ca(core: &Shared, cfg: CaConfig) -> Result<CaRecord> {
    if cfg.cn.trim().is_empty() { return Err(AppError::bad_request("cn is required")); }
    let db = core.store.snapshot();
    if cfg.root_id > 0 && !db.cas.iter().any(|c| c.id == cfg.root_id) {
        return Err(AppError::not_found("parent root CA not found"));
    }
    let parent = if cfg.root_id > 0 {
        let root = db.cas.iter().find(|c| c.id == cfg.root_id).unwrap();
        Some(CaMaterial { cert_pem: root.cert.clone(), key_pem: root.key.clone() })
    } else { None };
    drop(db);
    let algorithm = if cfg.algorithm.is_empty() { "rsa".into() } else { cfg.algorithm.clone() };
    let days = if cfg.valid_days <= 0 { 3650 } else { cfg.valid_days };
    let (cert_pem, key_pem, en_cert, en_key) = if algorithm == "sm2" {
        sm2_dual(core, &cfg.cn, days)?
    } else {
        let m = crypto::create_ca(&cfg.name, &cfg.cn, &cfg.o, &cfg.c, &algorithm, days, parent.as_ref())?;
        (m.cert_pem, m.key_pem, String::new(), String::new())
    };
    let parsed = crypto::parse_certificate(&cert_pem)?;
    let record = CaRecord {
        id: 0, root_id: cfg.root_id, name: cfg.name, cn: cfg.cn, o: cfg.o, c: cfg.c,
        cert: cert_pem, key: key_pem, en_cert, en_key, algorithm: algorithm.clone(),
        key_length: if cfg.key_length <= 0 { 2048 } else { cfg.key_length },
        not_before: parsed.not_before, not_after: parsed.not_after, created_at: now(),
    };
    let saved = core.store.mutate(|db| { let mut r = record; r.id = next_id(db, "ca"); db.cas.push(r.clone()); r })?;
    let _ = core.emit("ca.created", "private_ca", json!({ "id": saved.id, "cn": saved.cn, "root_id": saved.root_id, "algorithm": algorithm })).await;
    Ok(saved)
}

/// SM2 signing / encryption dual certificates. Uses the openssl binary when
/// available (RustCrypto has no maintained SM2 X.509 signer); the two PEM
/// pairs are stored separately, following the GM/T 0024 layout.
fn sm2_dual(_core: &Shared, cn: &str, days: i64) -> Result<(String, String, String, String)> {
    let openssl = which("openssl").ok_or_else(|| AppError::bad_gateway(
        "SM2 dual certificates require the openssl binary with SM2 support (or use rsa / ecdsa)"))?;
    let dir = std::env::temp_dir().join(format!("ssld-sm2-{}", crypto::random_token(6)));
    std::fs::create_dir_all(&dir)?;
    let gen = |name: &str| -> Result<(String, String)> {
        let key = dir.join(format!("{name}.key"));
        let crt = dir.join(format!("{name}.pem"));
        let status = std::process::Command::new(&openssl)
            .args(["req", "-newkey", "sm2", "-nodes", "-subj", &format!("/CN={cn}"), "-keyout"])
            .arg(&key).arg("-out").arg(dir.join(format!("{name}.csr"))).status();
        if status.map(|s| s.success()).unwrap_or(false) {
            let _ = std::process::Command::new(&openssl)
                .args(["x509", "-req", "-in"]).arg(dir.join(format!("{name}.csr")))
                .arg("-signkey").arg(&key).arg("-out").arg(&crt)
                .args(["-days", &days.to_string(), "-sm3"]).status();
        }
        Ok((std::fs::read_to_string(&key).unwrap_or_default(), std::fs::read_to_string(&crt).unwrap_or_default()))
    };
    let (sign_key, sign_cert) = gen("sign")?;
    let (enc_key, enc_cert) = gen("encrypt")?;
    let _ = std::fs::remove_dir_all(&dir);
    if sign_cert.is_empty() { return Err(AppError::bad_gateway("openssl could not generate SM2 certificates")); }
    Ok((sign_cert, sign_key, enc_cert, enc_key))
}

fn which(program: &str) -> Option<String> {
    let out = std::process::Command::new(if cfg!(windows) { "where" } else { "which" }).arg(program).output().ok()?;
    if !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or(program).to_string())
}

pub async fn delete_ca(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    let db = core.store.snapshot();
    for id in &set {
        if db.cas.iter().any(|c| c.root_id == *id && !set.contains(&c.id)) {
            return Err(AppError::conflict(format!("CA {id} still has intermediate CAs; delete them together")));
        }
    }
    let n = core.store.mutate(|db| {
        let before = db.cas.len();
        db.cas.retain(|c| !set.contains(&c.id));
        db.leaves.retain(|l| !set.contains(&l.ca_id));
        before - db.cas.len()
    })?;
    let _ = core.emit("ca.deleted", "private_ca", json!({ "ids": set, "deleted": n })).await;
    Ok(n)
}

pub fn leaf_list(core: &Shared) -> Vec<Value> {
    core.store.snapshot().leaves.iter().map(|l| json!({
        "id": l.id, "ca_id": l.ca_id, "cn": l.cn, "san": l.san, "usage": l.usage,
        "algorithm": l.algorithm, "key_length": l.key_length,
        "not_before": l.not_before, "not_after": l.not_after,
        "days_left": crypto::days_left(&l.not_after), "created_at": l.created_at,
        "status": if crypto::days_left(&l.not_after) < 0 { "expired" } else { "valid" }
    })).collect()
}

pub async fn issue_leaf(core: &Shared, cfg: LeafConfig) -> Result<LeafRecord> {
    if cfg.cn.trim().is_empty() { return Err(AppError::bad_request("cn is required")); }
    let db = core.store.snapshot();
    let ca = db.cas.iter().find(|c| c.id == cfg.ca_id)
        .ok_or_else(|| AppError::not_found("CA not found"))?;
    if ca.root_id == 0 { return Err(AppError::bad_request("a root CA cannot issue leaf certificates directly; create an intermediate CA first")); }
    if ca.algorithm == "sm2" { return Err(AppError::bad_request("SM2 CAs cannot issue through the workflow engine; use the API with openssl")); }
    if crypto::days_left(&ca.not_after) < cfg.valid_days.max(1) {
        return Err(AppError::bad_request("leaf validity exceeds the intermediate CA's remaining lifetime"));
    }
    let parent = CaMaterial { cert_pem: ca.cert.clone(), key_pem: ca.key.clone() };
    let alg = if cfg.algorithm.is_empty() { ca.algorithm.clone() } else { cfg.algorithm.clone() };
    drop(db);
    let (cert_pem, key_pem) = crypto::issue_leaf(&parent, &cfg.cn, &cfg.san, &alg, cfg.valid_days.max(1))?;
    let parsed = crypto::parse_certificate(&cert_pem)?;
    let record = LeafRecord {
        id: 0, ca_id: cfg.ca_id, cn: cfg.cn, san: cfg.san, usage: cfg.usage,
        cert: cert_pem, key: key_pem, en_cert: String::new(), en_key: String::new(),
        algorithm: alg, key_length: cfg.key_length, not_before: parsed.not_before,
        not_after: parsed.not_after, created_at: now(),
    };
    let saved = core.store.mutate(|db| { let mut r = record; r.id = next_id(db, "leaf"); db.leaves.push(r.clone()); r })?;
    let _ = core.emit("leaf.issued", "private_ca", json!({ "id": saved.id, "cn": saved.cn, "ca_id": saved.ca_id })).await;
    Ok(saved)
}

pub fn delete_leaf(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.leaves.len(); db.leaves.retain(|l| !set.contains(&l.id)); before - db.leaves.len()
    })?)
}

pub fn download(core: &Shared, id: i64, kind: &str) -> Result<(String, String)> {
    let db = core.store.snapshot();
    match kind {
        "leaf" => {
            let l = db.leaves.iter().find(|l| l.id == id).ok_or_else(|| AppError::not_found("leaf not found"))?;
            Ok((format!("{}\n{}\n{}\n{}\n", l.cert, l.key, l.en_cert, l.en_key), format!("leaf-{}.pem", id)))
        }
        _ => {
            let c = db.cas.iter().find(|c| c.id == id).ok_or_else(|| AppError::not_found("CA not found"))?;
            Ok((format!("{}\n{}\n{}\n{}\n", c.cert, c.key, c.en_cert, c.en_key), format!("ca-{}.pem", id)))
        }
    }
}

/// Workflow `private_ca` node. Reuses an identical leaf while it is still
/// outside the renewal window, otherwise issues a new one and stores it.
pub async fn workflow_issue(core: &Shared, config: &Value, workflow_id: i64, history_id: &str) -> Result<Cert> {
    let s = |k: &str, d: &str| config.get(k).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| d.into());
    let i = |k: &str, d: i64| config.get(k).and_then(|v| v.as_i64())
        .or_else(|| config.get(k).and_then(|v| v.as_str()).and_then(|x| x.parse().ok())).unwrap_or(d);
    let ca_id = i("ca_id", 0);
    let cn = s("cn", "");
    let san = config.get("san").cloned().unwrap_or(json!({}));
    let end_day = i("end_day", 30);
    if let Some(existing) = core.store.snapshot().leaves.iter()
        .find(|l| l.ca_id == ca_id && l.cn == cn && l.san == san && crypto::days_left(&l.not_after) > end_day) {
        if let Ok(cert) = crate::certs::save(core, "private_ca", &existing.cert, &existing.key, "", history_id, workflow_id) {
            return Ok(cert);
        }
    }
    let leaf = issue_leaf(core, LeafConfig {
        ca_id, cn, san, usage: i("usage", 0), key_length: i("key_length", 2048),
        valid_days: i("valid_days", 365), algorithm: String::new(),
    }).await?;
    crate::certs::save(core, "private_ca", &leaf.cert, &leaf.key, "", history_id, workflow_id)
}
