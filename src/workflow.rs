//! Workflow engine: nested node tree, sequential / parallel / result branches,
//! node outputs wired through `inputs`, execution history and per-run logs.
use crate::error::{AppError, Result};
use crate::models::{now, uid, Cert, ExecTime, NodeRun, Workflow, WorkflowHistory, WorkflowInput, WorkflowNode};
use crate::state::Shared;
use crate::store::{next_id, trim};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub fn list(core: &Shared) -> Vec<Value> {
    core.store.snapshot().workflows.into_iter().map(|w| json!({
        "id": w.id, "name": w.name, "active": w.active, "exec_type": w.exec_type,
        "exec_time": w.exec_time, "cron": w.cron, "last_run_status": w.last_run_status,
        "last_run_time": w.last_run_time, "created_at": w.created_at, "updated_at": w.updated_at,
        "node_count": count_nodes(&w.content)
    })).collect()
}

pub fn count_nodes(content: &Value) -> usize {
    fn walk(v: &Value, n: &mut usize) {
        *n += 1;
        if let Some(c) = v.get("child_node") { walk(c, n); }
        if let Some(arr) = v.get("condition_nodes").and_then(|x| x.as_array()) { for c in arr { walk(c, n); } }
    }
    let mut n = 0; walk(content, &mut n); n
}

pub fn get(core: &Shared, id: i64) -> Result<Workflow> {
    core.store.snapshot().workflows.into_iter().find(|w| w.id == id)
        .ok_or_else(|| AppError::not_found("workflow not found"))
}

pub fn create(core: &Shared, input: WorkflowInput) -> Result<Workflow> {
    if input.name.trim().is_empty() { return Err(AppError::bad_request("name is required")); }
    let ts = now();
    let w = Workflow {
        id: 0, name: input.name, content: input.content, cron: input.cron,
        created_at: ts.clone(), updated_at: ts, active: input.active,
        exec_type: if input.exec_type.is_empty() { "manual".into() } else { input.exec_type },
        exec_time: input.exec_time.unwrap_or_default(),
        last_run_status: String::new(), last_run_time: String::new(),
    };
    Ok(core.store.mutate(|db| { let mut x = w; x.id = next_id(db, "workflow"); db.workflows.push(x.clone()); x })?)
}

pub fn update(core: &Shared, id: i64, input: WorkflowInput) -> Result<Workflow> {
    let old = get(core, id)?;
    let w = Workflow {
        id, name: input.name, content: input.content, cron: input.cron,
        created_at: old.created_at, updated_at: now(), active: input.active,
        exec_type: if input.exec_type.is_empty() { old.exec_type } else { input.exec_type },
        exec_time: input.exec_time.unwrap_or(old.exec_time),
        last_run_status: old.last_run_status, last_run_time: old.last_run_time,
    };
    core.store.mutate(|db| { if let Some(s) = db.workflows.iter_mut().find(|x| x.id == id) { *s = w.clone(); } })?;
    Ok(w)
}

pub fn delete(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<i64> = ids.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.workflows.len();
        db.workflows.retain(|w| !set.contains(&w.id));
        db.workflow_deploys.retain(|d| !set.contains(&d.workflow_id));
        before - db.workflows.len()
    })?)
}

pub fn set_active(core: &Shared, id: i64, active: bool) -> Result<()> {
    core.store.mutate(|db| {
        let w = db.workflows.iter_mut().find(|x| x.id == id)
            .ok_or_else(|| AppError::not_found("workflow not found"))?;
        w.active = active; w.updated_at = now(); Ok::<(), AppError>(())
    })?
}

pub fn set_exec_type(core: &Shared, id: i64, exec_type: &str) -> Result<()> {
    core.store.mutate(|db| {
        let w = db.workflows.iter_mut().find(|x| x.id == id)
            .ok_or_else(|| AppError::not_found("workflow not found"))?;
        w.exec_type = exec_type.into(); w.updated_at = now(); Ok::<(), AppError>(())
    })?
}

pub fn history(core: &Shared, workflow_id: Option<i64>, limit: usize) -> Vec<Value> {
    let mut rows: Vec<Value> = core.store.snapshot().histories.into_iter()
        .filter(|h| workflow_id.map(|id| h.workflow_id == id).unwrap_or(true))
        .map(|h| json!({
            "id": h.id, "workflow_id": h.workflow_id, "workflow_name": h.workflow_name,
            "status": h.status, "exec_type": h.exec_type,
            "created_at": h.created_at, "end_time": h.end_time,
            "nodes": h.nodes.len(), "succeeded": h.nodes.iter().filter(|n| n.status == "success").count(),
            "failed": h.nodes.iter().filter(|n| n.status == "fail").count()
        })).collect();
    rows.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
    if limit > 0 { rows.truncate(limit); }
    rows
}

pub fn exec_log(core: &Shared, run_id: &str) -> Result<Value> {
    let db = core.store.snapshot();
    let h = db.histories.iter().find(|h| h.id == run_id)
        .ok_or_else(|| AppError::not_found("run not found"))?;
    let path = std::path::PathBuf::from(&core.config.storage.workflow_log_dir).join(format!("{run_id}.log"));
    let file = std::fs::read_to_string(path).unwrap_or_default();
    Ok(json!({ "run": h, "file_log": file }))
}

pub fn delete_history(core: &Shared, ids: &str) -> Result<usize> {
    let set: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
    Ok(core.store.mutate(|db| {
        let before = db.histories.len(); db.histories.retain(|h| !set.contains(&h.id)); before - db.histories.len()
    })?)
}

pub fn stop(core: &Shared, run_id: &str) -> Result<()> {
    core.store.mutate(|db| {
        let h = db.histories.iter_mut().find(|h| h.id == run_id)
            .ok_or_else(|| AppError::not_found("run not found"))?;
        h.status = "fail".into(); h.end_time = now();
        h.logs.push("stopped by operator".into());
        Ok::<(), AppError>(())
    })?
}

pub struct RunCtx {
    pub history: WorkflowHistory,
    pub data: HashMap<String, Value>,
    pub status: HashMap<String, String>,
    pub cert: Option<Cert>,
}

impl RunCtx {
    fn new(w: &Workflow, exec_type: &str) -> Self {
        Self {
            history: WorkflowHistory {
                id: uid(), workflow_id: w.id, workflow_name: w.name.clone(),
                status: "running".into(), exec_type: exec_type.into(),
                created_at: now(), end_time: String::new(), nodes: Vec::new(), logs: Vec::new(),
            },
            data: HashMap::new(), status: HashMap::new(), cert: None,
        }
    }
    fn fork(&self) -> Self {
        Self {
            history: WorkflowHistory { id: format!("{}-branch-{}", self.history.id, uid()), nodes: Vec::new(), logs: Vec::new(),
                ..self.history.clone() },
            data: self.data.clone(), status: self.status.clone(), cert: self.cert.clone(),
        }
    }
    fn merge(&mut self, other: Self) {
        self.data.extend(other.data);
        self.status.extend(other.status);
        self.history.nodes.extend(other.history.nodes);
        self.history.logs.extend(other.history.logs);
        if other.cert.is_some() { self.cert = other.cert; }
    }
    fn log(&mut self, text: impl Into<String>) {
        let line = format!("[{}] {}", chrono::Utc::now().format("%H:%M:%S"), text.into());
        self.history.logs.push(line);
    }
}

fn cfg<'a>(node: &'a WorkflowNode, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    node.config.get(key).unwrap_or(&NULL)
}
fn cfg_str(node: &WorkflowNode, key: &str, default: &str) -> String {
    cfg(node, key).as_str().map(str::to_string)
        .or_else(|| cfg(node, key).as_i64().map(|n| n.to_string()))
        .unwrap_or_else(|| default.into())
}
fn cfg_i64(node: &WorkflowNode, key: &str, default: i64) -> i64 {
    cfg(node, key).as_i64().or_else(|| cfg(node, key).as_str().and_then(|s| s.parse().ok())).unwrap_or(default)
}
fn cfg_domains(node: &WorkflowNode) -> Vec<String> {
    match cfg(node, "domains") {
        Value::String(s) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

fn resolve_inputs(node: &mut WorkflowNode, ctx: &RunCtx) {
    for input in &node.inputs {
        if let Some(value) = ctx.data.get(&input.from_node_id) {
            if let Some(obj) = node.config.as_object_mut() {
                obj.insert(input.name.clone().replace("certificate", "certificate"), value.clone());
            }
        }
    }
}

fn persist(core: &Shared, ctx: &RunCtx) {
    let h = ctx.history.clone();
    let _ = core.store.mutate(|db| {
        if let Some(slot) = db.histories.iter_mut().find(|x| x.id == h.id) { *slot = h.clone(); }
        else { db.histories.push(h.clone()); trim(&mut db.histories, 500); }
    });
    let dir = std::path::PathBuf::from(&core.config.storage.workflow_log_dir);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(format!("{}.log", h.id)), h.logs.join("\n"));
}

pub async fn execute(core: &Shared, workflow_id: i64, exec_type: &str) -> Result<WorkflowHistory> {
    let w = get(core, id(workflow_id))?;
    let mut ctx = RunCtx::new(&w, exec_type);
    ctx.log(format!("start workflow {} ({})", w.name, w.id));
    let root: WorkflowNode = serde_json::from_value(w.content.clone())
        .map_err(|e| AppError::bad_request(format!("invalid workflow tree: {e}")))?;
    let _ = core.emit("workflow.started", "workflow", json!({
        "workflow_id": w.id, "name": w.name, "run_id": ctx.history.id, "exec_type": exec_type
    })).await;
    persist(core, &ctx);

    let fatal = Box::pin(run_node(core, &root, &mut ctx)).await;
    let failed = ctx.history.nodes.iter().any(|n| n.status == "fail");
    ctx.history.status = if fatal.is_err() { "fail".into() }
        else if failed { "partial".into() } else { "success".into() };
    ctx.history.end_time = now();
    if let Err(e) = &fatal { ctx.log(format!("fatal: {e}")); }
    ctx.log(format!("finished: {}", ctx.history.status));
    persist(core, &ctx);
    let _ = core.store.mutate(|db| {
        if let Some(slot) = db.workflows.iter_mut().find(|x| x.id == w.id) {
            slot.last_run_status = ctx.history.status.clone(); slot.last_run_time = ctx.history.end_time.clone();
        }
    });
    let event = match ctx.history.status.as_str() {
        "success" => "workflow.succeeded", "partial" => "workflow.partial", _ => "workflow.failed",
    };
    let _ = core.emit(event, "workflow", json!({
        "workflow_id": w.id, "name": w.name, "run_id": ctx.history.id,
        "status": ctx.history.status, "nodes": ctx.history.nodes.len()
    })).await;
    Ok(ctx.history.clone())
}

fn id(v: i64) -> i64 { v }

async fn run_node(core: &Shared, node: &WorkflowNode, ctx: &mut RunCtx) -> Result<()> {
    let mut node = node.clone();
    resolve_inputs(&mut node, ctx);
    let started = now();
    let mut message = String::new();
    let result: Result<Value> = match node.node_type.as_str() {
        "start" | "end" | "default" | "branch" | "condition" | "execute_result_branch" | "execute_result_condition" => {
            Ok(json!({ "skipped": true }))
        }
        "apply" => {
            let req = crate::certs::ApplyRequest {
                domains: cfg_domains(&node), ca: cfg_str(&node, "ca", ""),
                cadirurl: cfg_str(&node, "cadirurl", ""), email: cfg_str(&node, "email", ""),
                algorithm: cfg_str(&node, "algorithm", ""),
                dns_access_id: cfg_i64(&node, "provider_id", 0) as i64,
                eab_id: cfg_i64(&node, "eabId", 0),
                account_id: cfg_i64(&node, "account_id", 0),
                end_day: cfg_i64(&node, "end_day", 0),
                max_wait: cfg_i64(&node, "max_wait", 120).max(1) as u64,
                certificate_timeout: cfg_i64(&node, "certificate_timeout", 60) as u64,
                ari_enabled: cfg(&node, "ari_enabled").as_bool().unwrap_or(false),
                skip_check: cfg(&node, "skip_check").as_bool().unwrap_or(false),
                force: cfg(&node, "force").as_bool().unwrap_or(false),
                workflow_id: ctx.history.workflow_id, history_id: ctx.history.id.clone(),
            };
            match crate::certs::apply_certificate(core, req).await {
                Ok(outcome) => {
                    ctx.cert = Some(outcome.cert.clone());
                    message = if outcome.reused { "reused local certificate".into() } else { "issued new certificate".into() };
                    Ok(json!({ "cert": outcome.cert, "reused": outcome.reused, "renewed": outcome.renewed }))
                }
                Err(e) => Err(e),
            }
        }
        "upload" => {
            let cert = if cfg_i64(&node, "cert_id", 0) > 0 {
                crate::certs::get(core, cfg_i64(&node, "cert_id", 0))?
            } else if cfg(&node, "key").as_str().map(|s| !s.is_empty()).unwrap_or(false) {
                crate::certs::save(core, "upload", &cfg_str(&node, "cert", ""), &cfg_str(&node, "key", ""), "", &ctx.history.id, ctx.history.workflow_id)?
            } else {
                let domains = cfg_domains(&node);
                crate::certs::find_matching(core, &domains, cfg_i64(&node, "end_day", 30))
                    .ok_or_else(|| AppError::bad_request("no reusable local certificate for upload node"))?
            };
            ctx.cert = Some(cert.clone());
            message = "loaded certificate".into();
            Ok(json!({ "cert": cert }))
        }
        "deploy" => {
            let cert = ctx.cert.clone().or_else(|| {
                cfg(&node, "certificate").get("cert").and_then(|v| v.as_str()).and_then(|_| None::<Cert>)
            }).ok_or_else(|| AppError::bad_request("deploy node has no upstream certificate"))?;
            let target = cfg_str(&node, "provider", "");
            let access_id = cfg_i64(&node, "provider_id", 0);
            let access = core.store.snapshot().accesses.into_iter().find(|a| a.id == access_id);
            let req = crate::deploy::DeployRequest {
                target, access, cert, params: node.config.clone(),
                workflow_id: ctx.history.workflow_id, node_id: node.id.clone(),
            };
            let (skipped, detail) = crate::deploy::deploy(core, req).await?;
            message = if skipped { "skipped (already deployed)".into() } else { "deployed".into() };
            Ok(json!({ "skipped": skipped, "detail": detail }))
        }
        "notify" => {
            let subject = cfg_str(&node, "subject", "ssld notification");
            let body = cfg_str(&node, "body", "A workflow step completed.");
            let types: Vec<String> = match cfg(&node, "provider") {
                Value::String(s) => vec![s.clone()],
                Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                _ => vec![],
            };
            let id = cfg_i64(&node, "provider_id", 0);
            let mut resolved = types;
            if id > 0 { resolved.push(id.to_string()); }
            let results = crate::notify::notify_many(core, &resolved, &subject, &body,
                &json!({ "workflow_id": ctx.history.workflow_id, "run_id": ctx.history.id })).await;
            message = format!("sent {} notifications", results.len());
            Ok(json!({ "results": results }))
        }
        "private_ca" => {
            match crate::private_ca::workflow_issue(core, &node.config, ctx.history.workflow_id, &ctx.history.id).await {
                Ok(cert) => { ctx.cert = Some(cert.clone()); message = "private CA leaf issued".into(); Ok(json!({ "cert": cert })) }
                Err(e) => Err(e),
            }
        }
        other => Err(AppError::bad_request(format!("unknown node type: {other}"))),
    };

    let status = if result.is_ok() { "success" } else { "fail" };
    ctx.status.insert(node.id.clone(), status.into());
    if let Ok(v) = &result { ctx.data.insert(node.id.clone(), v.clone()); }
    if let Err(e) = &result { message = e.to_string().clone(); }
    let run = NodeRun {
        node_id: node.id.clone(), node_type: node.node_type.clone(), name: node.name.clone(),
        status: status.into(), message: message.clone(), started_at: started, finished_at: now(),
    };
    ctx.history.nodes.push(run);
    ctx.log(format!("{} [{}] {} -> {status}: {message}", node.name, node.node_type, node.id));
    if status == "fail" {
        let _ = core.emit("workflow.node_failed", "workflow", json!({
            "workflow_id": ctx.history.workflow_id, "run_id": ctx.history.id,
            "node_id": node.id, "node_type": node.node_type, "error": message
        })).await;
    }
    persist(core, ctx);

    // Parallel branches. Each branch runs with its own context and merges back.
    if node.node_type == "branch" && !node.condition_nodes.is_empty() {
        let mut branches = Vec::new();
        for child in &node.condition_nodes {
            let c = Arc::clone(core);
            let child = child.clone();
            let mut sub = ctx.fork();
            branches.push(async move {
                let _ = Box::pin(run_node(&c, &child, &mut sub)).await;
                sub
            });
        }
        let results = futures::future::join_all(branches).await;
        for r in results { ctx.merge(r); }
        return Ok(());
    }

    // Result branch: pick the condition whose `type` matches the previous state.
    if node.node_type == "execute_result_branch" {
        let want = ctx.status.values().last().cloned().unwrap_or_else(|| "success".into());
        let chosen = node.condition_nodes.iter().find(|c| cfg_str(c, "type", "success") == want)
            .or_else(|| node.condition_nodes.first()).cloned();
        if let Some(child) = chosen { return Box::pin(run_node(core, &child, ctx)).await; }
    }

    let err = result.err();
    if let Some(child) = &node.child_node {
        if err.is_some() && child.node_type != "execute_result_branch" {
            return Err(err.unwrap());
        }
        Box::pin(run_node(core, child, ctx)).await?;
    }
    match err { Some(e) => Err(e), None => Ok(()) }
}

/// Build a ready-to-run issue → deploy → notify workflow tree.
pub fn build_tree(name: &str, domains: &[String], ca: &str, dns_access_id: i64,
                  deploy_target: &str, deploy_access_id: i64, notify_channel: &str) -> Value {
    let end = json!({ "id": uid(), "type": "end", "name": "End", "config": {}, "inputs": [], "child_node": null, "condition_nodes": [], "validated": true });
    let notify = json!({ "id": uid(), "type": "notify", "name": "Notify result",
        "config": { "subject": "ssld certificate workflow", "body": "Certificate workflow finished.", "provider": notify_channel },
        "inputs": [], "child_node": end, "condition_nodes": [], "validated": true });
    let deploy = json!({ "id": uid(), "type": "deploy", "name": "Deploy certificate",
        "config": { "provider": deploy_target, "provider_id": deploy_access_id, "skip": 1,
            "domain": domains.first().cloned().unwrap_or_default() },
        "inputs": [{ "name": "certificate", "from_node_id": "apply" }],
        "child_node": notify, "condition_nodes": [], "validated": true });
    let apply = json!({ "id": "apply", "type": "apply", "name": "Apply certificate",
        "config": { "domains": domains.join(","), "ca": ca, "provider_id": dns_access_id },
        "inputs": [], "child_node": deploy, "condition_nodes": [], "validated": true });
    let _ = name;
    json!({ "id": uid(), "type": "start", "name": name,
        "config": { "exec_type": "auto", "exec_time": { "type": "day", "hour": 3, "minute": 0 } },
        "inputs": [], "child_node": apply, "condition_nodes": [], "validated": true })
}

pub fn schedule_matches(t: &ExecTime, now: &chrono::DateTime<chrono::Utc>) -> bool {
    use chrono::{Datelike, Timelike, Weekday};
    if t.hour != now.hour() as i64 || t.minute != now.minute() as i64 { return false; }
    match t.period.as_str() {
        "week" => {
            let wd = match now.weekday() { Weekday::Mon => 1, Weekday::Tue => 2, Weekday::Wed => 3,
                Weekday::Thu => 4, Weekday::Fri => 5, Weekday::Sat => 6, Weekday::Sun => 7 };
            wd == t.week.max(1)
        }
        "month" => now.day() as i64 == t.month.max(1),
        _ => true,
    }
}
