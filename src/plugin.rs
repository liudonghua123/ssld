//! Two plugin systems, matching allinssl: module plugins (protocol 1, manifest
//! with permissions / hooks / frontend injection) and deploy plugins
//! (stdin/stdout executable protocol with dynamic typed parameters).
use crate::error::{AppError, Result};
use crate::models::{now, Access, PluginRecord};
use crate::state::Shared;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn plugin_dir(core: &Shared) -> std::path::PathBuf {
    let configured = core.setting("plugin_dir").unwrap_or_else(|| "plugins".into());
    std::path::PathBuf::from(configured)
}

pub fn plugins(core: &Shared) -> Vec<Value> {
    core.store.snapshot().plugins.iter().map(|p| json!({
        "id": p.id, "name": p.name, "version": p.version, "protocol": p.protocol,
        "backend": p.backend, "permissions": p.permissions, "hooks": p.hooks,
        "frontend": p.frontend, "actions": p.actions, "config_schema": p.config_schema,
        "enabled": p.enabled, "status": p.status, "created_at": p.created_at
    })).collect()
}

pub fn bootstrap(core: &Shared) -> Value {
    let db = core.store.snapshot();
    let modules: Vec<Value> = db.plugins.iter().filter(|p| p.enabled && p.status == "running")
        .map(|p| json!({
            "id": p.id, "name": p.name, "version": p.version,
            "frontend": p.frontend, "permissions": p.permissions
        })).collect();
    json!({ "authentication": "session", "authenticated": true, "modules": modules,
        "protocol": 1, "host": "ssld" })
}

/// Scan the plugin directory for manifests (module plugins and deploy plugins)
/// and merge them into the registry without removing existing entries.
pub fn scan(core: &Shared) -> Result<Value> {
    let dir = plugin_dir(core);
    std::fs::create_dir_all(&dir)?;
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let manifest = path.join("plugin.json");
        let metadata = path.join("metadata.json");
        let file = if manifest.exists() { Some(("module", manifest)) }
            else if metadata.exists() { Some(("deploy", metadata)) } else { None };
        let Some((kind, file)) = file else { continue };
        let raw = std::fs::read_to_string(&file)?;
        let Ok(v) = serde_json::from_str::<Value>(&raw) else { continue };
        let id = v.get("id").and_then(|x| x.as_str())
            .or_else(|| v.get("name").and_then(|x| x.as_str()))
            .unwrap_or("unnamed").to_string();
        let mut record = PluginRecord {
            id: id.clone(), name: v.get("name").and_then(|x| x.as_str()).unwrap_or(&id).into(),
            version: v.get("version").and_then(|x| x.as_str()).unwrap_or("0.0.0").into(),
            protocol: v.get("protocol").and_then(|x| x.as_i64()).unwrap_or(1),
            backend: v.get("backend").and_then(|x| x.as_str()).unwrap_or("").into(),
            permissions: v.get("permissions").and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
            hooks: v.get("hooks").cloned().unwrap_or(json!([])),
            frontend: v.get("frontend").cloned().unwrap_or(json!({})),
            actions: v.get("actions").cloned().unwrap_or(json!([])),
            config_schema: v.get("config").cloned().unwrap_or(json!([])),
            enabled: false, status: if kind == "module" { "disabled" } else { "running" }.into(),
            created_at: now(),
        };
        if kind == "deploy" { record.enabled = true; record.protocol = 0; }
        core.store.mutate(|db| {
            if let Some(slot) = db.plugins.iter_mut().find(|p| p.id == id) {
                slot.name = record.name.clone(); slot.actions = record.actions.clone();
                slot.config_schema = record.config_schema.clone(); slot.version = record.version.clone();
            } else { db.plugins.push(record.clone()); }
        })?;
        found.push(json!({ "id": id, "kind": kind, "path": path.display().to_string() }));
    }
    Ok(json!({ "scanned": found.len(), "found": found }))
}

pub async fn set_enabled(core: &Shared, id: &str, enabled: bool) -> Result<Value> {
    let status = if enabled { "starting" } else { "stopping" };
    core.store.mutate(|db| {
        let p = db.plugins.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| AppError::not_found("plugin not found"))?;
        p.enabled = enabled; p.status = status.into(); Ok::<(), AppError>(())
    })??;
    let final_status = if enabled { "running" } else { "disabled" };
    core.store.mutate(|db| {
        if let Some(p) = db.plugins.iter_mut().find(|p| p.id == id) { p.status = final_status.into(); }
    })?;
    let _ = core.emit(if enabled { "plugin.enabled" } else { "plugin.disabled" }, "plugin", json!({ "id": id })).await;
    Ok(json!({ "id": id, "enabled": enabled, "status": final_status }))
}

pub fn actions(core: &Shared, name: &str) -> Result<Value> {
    let p = core.store.snapshot().plugins.into_iter().find(|p| p.id == name || p.name == name)
        .ok_or_else(|| AppError::not_found("plugin not found"))?;
    Ok(json!({ "name": p.name, "actions": p.actions, "config_schema": p.config_schema,
        "parameter_types": crate::providers::PARAM_TYPES }))
}

pub fn raw_metadata(core: &Shared, name: &str) -> Result<Value> {
    let p = core.store.snapshot().plugins.into_iter().find(|p| p.id == name || p.name == name)
        .ok_or_else(|| AppError::not_found("plugin not found"))?;
    Ok(json!({ "name": p.name, "version": p.version, "protocol": p.protocol,
        "backend": p.backend, "permissions": p.permissions, "hooks": p.hooks,
        "frontend": p.frontend, "actions": p.actions, "config": p.config_schema }))
}

fn executable(dir: &std::path::PathBuf, name: &str) -> Option<std::path::PathBuf> {
    let candidates = if cfg!(windows) {
        vec![format!("{name}.exe"), format!("{name}.bat"), format!("{name}.cmd"), name.to_string()]
    } else { vec![name.to_string(), format!("{name}.sh")] };
    for c in candidates {
        let direct = dir.join(&c);
        if direct.is_file() { return Some(direct); }
        let nested = dir.join(name).join(&c);
        if nested.is_file() { return Some(nested); }
    }
    None
}

/// stdin/stdout plugin protocol: `{action, params}` in, `{status, result}` out.
pub async fn call_plugin(core: &Shared, name: &str, action: &str, params: Value) -> Result<Value> {
    let dir = plugin_dir(core);
    let bin = executable(&dir, name).ok_or_else(|| AppError::bad_request(format!("plugin executable not found: {name}")))?;
    let request = serde_json::to_string(&json!({ "action": action, "params": params }))?;
    let mut child = tokio::process::Command::new(&bin)
        .current_dir(&dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn().map_err(|e| AppError::bad_gateway(format!("plugin spawn: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(request.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.shutdown().await?;
    }
    let stdout = child.stdout.take().ok_or_else(|| AppError::bad_gateway("plugin has no stdout"))?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).await?;
    let _ = child.wait().await;
    if line.trim().is_empty() { return Err(AppError::bad_gateway("plugin returned no response")); }
    let response: Value = serde_json::from_str(line.trim())
        .map_err(|e| AppError::bad_gateway(format!("plugin response: {e}: {line}")))?;
    if response.get("status").and_then(|v| v.as_str()) == Some("error") {
        return Err(AppError::bad_gateway(response.get("message").and_then(|v| v.as_str()).unwrap_or("plugin error").to_string()));
    }
    Ok(response.get("result").cloned().unwrap_or(response))
}

/// Deploy plugin adapter used by `deploy.rs`.
pub async fn invoke_deploy(core: &Shared, access: &Access, params: &Value, payload: &Value) -> Result<Value> {
    let name = access.config.get("name").and_then(|v| v.as_str())
        .or_else(|| params.get("plugin").and_then(|v| v.as_str()))
        .unwrap_or("").to_string();
    if name.is_empty() { return Err(AppError::bad_request("plugin credential requires name")); }
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("deploy").to_string();
    let extra: Value = serde_json::from_str(params.get("params").and_then(|v| v.as_str()).unwrap_or("{}"))
        .unwrap_or_else(|_| params.get("params").cloned().unwrap_or(json!({})));
    let mut merged = serde_json::Map::new();
    for (k, v) in access.config.as_object().cloned().unwrap_or_default() { merged.insert(k, v); }
    for (k, v) in extra.as_object().cloned().unwrap_or_default() { merged.insert(k, v); }
    for (k, v) in payload.as_object().cloned().unwrap_or_default() { merged.insert(k, v); }
    call_plugin(core, &name, &action, Value::Object(merged)).await
}

pub fn register(core: &Shared, mut p: PluginRecord) -> Result<PluginRecord> {
    if p.id.is_empty() { return Err(AppError::bad_request("plugin id is required")); }
    p.created_at = now();
    if p.status.is_empty() { p.status = "disabled".into(); }
    core.store.mutate(|db| {
        db.plugins.retain(|x| x.id != p.id);
        db.plugins.push(p.clone());
    })?;
    Ok(p)
}
