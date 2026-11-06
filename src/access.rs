//! Credential management (DNS + host), ACME EAB credentials, ACME accounts,
//! connectivity tests and remote site enumeration.
use crate::error::{AppError, Result};
use crate::models::{now, Access, AccessInput, AcmeAccount, Eab};
use crate::state::Shared;
use crate::store::next_id;
use serde_json::{json, Value};

fn sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["key", "secret", "password", "token", "hmac", "credential", "private"].iter().any(|p| k.contains(p)) && k != "key_path"
}

pub fn mask(config: &Value) -> Value {
    match config.as_object() {
        Some(obj) => Value::Object(obj.iter().map(|(k, v)| {
            (k.clone(), if sensitive(k) && !matches!(v, Value::Bool(_)) {
                Value::String("******".into())
            } else { v.clone() })
        }).collect()),
        None => config.clone(),
    }
}

/// Re-exported for notification channels, which mask secrets the same way.
pub fn merge_secret(old: &Value, incoming: &Value) -> Value { merge_unchanged(old, incoming) }

fn merge_unchanged(old: &Value, incoming: &Value) -> Value {
    let mut merged = incoming.clone();
    if let (Some(dst), Some(src)) = (merged.as_object_mut(), old.as_object()) {
        for (k, v) in dst.clone() {
            if matches!(&v, Value::String(s) if s == "******") {
                if let Some(original) = src.get(&k) { dst.insert(k, original.clone()); }
            }
        }
    }
    merged
}

pub fn list(core: &Shared, kind: &str, search: &str) -> Vec<Value> {
    core.store.snapshot().accesses.into_iter()
        .filter(|a| kind.is_empty() || a.kind == kind)
        .filter(|a| search.is_empty() || a.name.contains(search) || a.provider.contains(search))
        .map(|a| json!({
            "id": a.id, "name": a.name, "kind": a.kind, "provider": a.provider,
            "config": mask(&a.config), "created_at": a.created_at, "updated_at": a.updated_at
        })).collect()
}

pub fn raw(core: &Shared, id: i64) -> Result<Access> {
    core.store.snapshot().accesses.into_iter().find(|a| a.id == id)
        .ok_or_else(|| AppError::not_found("credential not found"))
}

pub async fn create(core: &Shared, input: AccessInput) -> Result<Access> {
    if input.name.trim().is_empty() { return Err(AppError::bad_request("name is required")); }
    if input.provider.trim().is_empty() { return Err(AppError::bad_request("provider is required")); }
    let kind = if input.kind.is_empty() {
        if crate::providers::DNS_PROVIDERS.iter().any(|(id, _, _)| *id == input.provider) { "dns".to_string() } else { "host".to_string() }
    } else { input.kind };
    if !["dns", "host"].contains(&kind.as_str()) { return Err(AppError::bad_request("kind must be dns or host")); }
    let ts = now();
    let item = core.store.mutate(|db| {
        let a = Access { id: next_id(db, "access"), name: input.name, kind: kind.clone(),
            provider: input.provider, config: input.config, created_at: ts.clone(), updated_at: ts };
        db.accesses.push(a.clone()); a
    })?;
    let _ = core.emit("access.created", "access", json!({ "id": item.id, "name": item.name, "provider": item.provider, "kind": kind })).await;
    Ok(item)
}

pub async fn update(core: &Shared, id: i64, input: AccessInput) -> Result<Access> {
    let old = raw(core, id)?;
    let config = merge_unchanged(&old.config, &input.config);
    let item = core.store.mutate(|db| {
        let slot = db.accesses.iter_mut().find(|a| a.id == id)
            .ok_or_else(|| AppError::not_found("credential not found"))?;
        slot.name = input.name; slot.provider = input.provider;
        if !input.kind.is_empty() { slot.kind = input.kind; }
        slot.config = config; slot.updated_at = now();
        Ok::<_, AppError>(slot.clone())
    })??;
    let _ = core.emit("access.updated", "access", json!({ "id": id, "name": item.name })).await;
    Ok(item)
}

pub async fn delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    let n = core.store.mutate(|db| {
        let before = db.accesses.len();
        db.accesses.retain(|a| !set.contains(&a.id));
        before - db.accesses.len()
    })?;
    let _ = core.emit("access.deleted", "access", json!({ "ids": set, "deleted": n })).await;
    Ok(n)
}

pub async fn test(core: &Shared, id: i64) -> Result<Value> {
    let access = raw(core, id)?;
    let result = if access.kind == "dns" { crate::dns::test_access(core, &access).await }
        else { crate::deploy::test_access(core, &access).await };
    match result {
        Ok(v) => Ok(json!({ "id": id, "provider": access.provider, "ok": true, "detail": v })),
        Err(e) => {
            let _ = core.emit("access.test_failed", "access", json!({ "id": id, "provider": access.provider, "error": e.to_string() })).await;
            Err(e)
        }
    }
}

pub async fn get_sites(core: &Shared, id: i64) -> Result<Value> {
    let access = raw(core, id)?;
    let base = access.config.get("url").and_then(|v| v.as_str()).unwrap_or("").trim_end_matches('/');
    if base.is_empty() { return Err(AppError::bad_request("credential requires url")); }
    let token = access.config.get("api_key").and_then(|v| v.as_str())
        .or_else(|| access.config.get("api_token").and_then(|v| v.as_str())).unwrap_or("");
    let path = if access.provider == "1panel" || access.provider == "1panel-site" { "/api/v1/websites" }
        else { "/site?action=GetSiteList" };
    let resp = core.http.get(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {token}")).send().await?;
    let text = resp.text().await?;
    Ok(serde_json::from_str::<Value>(&text).unwrap_or(json!({ "raw": text })))
}

// --- EAB credentials -------------------------------------------------------

pub fn eabs(core: &Shared) -> Vec<Value> {
    core.store.snapshot().eabs.into_iter().map(|e| json!({
        "id": e.id, "name": e.name, "kid": e.kid, "hmac_encoded": "******",
        "ca": e.ca, "mail": e.mail, "created_at": e.created_at, "updated_at": e.updated_at
    })).collect()
}

pub fn eab_create(core: &Shared, mut e: Eab) -> Result<Eab> {
    if e.kid.is_empty() || e.hmac_encoded.is_empty() { return Err(AppError::bad_request("kid and hmac_encoded are required")); }
    let ts = now(); e.created_at = ts.clone(); e.updated_at = ts;
    let out = core.store.mutate(|db| { e.id = next_id(db, "eab"); db.eabs.push(e.clone()); e })?;
    Ok(out)
}

pub fn eab_update(core: &Shared, id: i64, mut e: Eab) -> Result<Eab> {
    let old = core.store.snapshot().eabs.into_iter().find(|x| x.id == id)
        .ok_or_else(|| AppError::not_found("EAB credential not found"))?;
    e.id = id; e.created_at = old.created_at; e.updated_at = now();
    if e.hmac_encoded == "******" { e.hmac_encoded = old.hmac_encoded; }
    let out = e.clone();
    core.store.mutate(|db| { if let Some(s) = db.eabs.iter_mut().find(|x| x.id == id) { *s = e; } })?;
    Ok(out)
}

pub fn eab_delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.eabs.len(); db.eabs.retain(|e| !set.contains(&e.id)); before - db.eabs.len()
    })?)
}

// --- ACME accounts ---------------------------------------------------------

pub fn accounts(core: &Shared) -> Vec<Value> {
    core.store.snapshot().acme_accounts.into_iter().map(|a| json!({
        "id": a.id, "email": a.email, "ca": a.ca, "kid": a.kid,
        "cadirurl": a.cadirurl, "has_eab": !a.hmac_encoded.is_empty(),
        "created_at": a.created_at, "updated_at": a.updated_at
    })).collect()
}

pub fn account_create(core: &Shared, mut a: AcmeAccount) -> Result<AcmeAccount> {
    if a.email.is_empty() || a.ca.is_empty() { return Err(AppError::bad_request("email and ca are required")); }
    if a.private_key.is_empty() {
        a.private_key = crate::crypto::JwsKey::generate()?.pkcs8_pem();
    }
    let ts = now(); a.created_at = ts.clone(); a.updated_at = ts;
    let out = core.store.mutate(|db| { a.id = next_id(db, "acme_account"); db.acme_accounts.push(a.clone()); a })?;
    Ok(out)
}

pub fn account_update(core: &Shared, id: i64, mut a: AcmeAccount) -> Result<AcmeAccount> {
    let old = core.store.snapshot().acme_accounts.into_iter().find(|x| x.id == id)
        .ok_or_else(|| AppError::not_found("ACME account not found"))?;
    a.id = id; a.created_at = old.created_at; a.updated_at = now();
    if a.private_key.is_empty() { a.private_key = old.private_key; }
    let out = a.clone();
    core.store.mutate(|db| { if let Some(s) = db.acme_accounts.iter_mut().find(|x| x.id == id) { *s = a; } })?;
    Ok(out)
}

pub fn account_delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.acme_accounts.len(); db.acme_accounts.retain(|a| !set.contains(&a.id)); before - db.acme_accounts.len()
    })?)
}

pub fn ca_list(core: &Shared) -> Value {
    let mut names: Vec<String> = vec!["letsencrypt".into(), "buypass".into(), "zerossl".into()];
    for a in core.store.snapshot().acme_accounts {
        if !names.contains(&a.ca) { names.push(a.ca); }
    }
    json!({ "cas": names, "directories": crate::providers::CA_PROVIDERS.iter().map(|(id, name, url)|
        json!({"id": id, "name": name, "directory": url})).collect::<Vec<_>>() })
}
