//! Deployment adapters for all 32 targets. Common behaviours (idempotent
//! skip, before/after commands, event emission, delivery ledger) live here;
//! vendor specifics are described as endpoint + auth + parameter data.
use crate::cloud::{self, AuthStyle};
use crate::error::{AppError, Result};
use crate::models::{now, Access, Cert, WorkflowDeploy};
use crate::state::Shared;
use serde_json::{json, Value};

pub struct DeployRequest {
    pub target: String,
    pub access: Option<Access>,
    pub cert: Cert,
    pub params: Value,
    pub workflow_id: i64,
    pub node_id: String,
}

fn p(params: &Value, key: &str, default: &str) -> String {
    params.get(key).and_then(|v| v.as_str()).map(str::to_string)
        .unwrap_or_else(|| default.to_string())
}
fn c(access: &Option<Access>, key: &str, default: &str) -> String {
    access.as_ref().and_then(|a| a.config.get(key)).and_then(|v| v.as_str())
        .map(str::to_string).unwrap_or_else(|| default.to_string())
}
fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) { Some(Value::Bool(b)) => *b, Some(Value::String(s)) => s == "1" || s == "true", _ => false }
}

fn shell(cmd: &str) -> Result<String> {
    if cmd.trim().is_empty() { return Ok(String::new()); }
    let (program, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
    let out = std::process::Command::new(program).arg(flag).arg(cmd).output()
        .map_err(|e| AppError::bad_gateway(format!("command {program}: {e}")))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if !out.status.success() { return Err(AppError::bad_gateway(format!("command failed: {text}"))); }
    Ok(text)
}

/// Returns `(skipped, detail)`. A skipped deploy is not an error.
pub async fn deploy(core: &Shared, req: DeployRequest) -> Result<(bool, Value)> {
    let hash = req.cert.sha256.clone();
    let skip = flag(&req.params, "skip") || p(&req.params, "skip", "0") == "1";
    if skip && !req.node_id.is_empty() {
        let already = core.store.snapshot().workflow_deploys.into_iter()
            .any(|d| d.workflow_id == req.workflow_id && d.node_id == req.node_id
                && d.cert_hash == hash && d.status == "success");
        if already {
            return Ok((true, json!({ "reason": "certificate fingerprint already deployed by this node" })));
        }
    }

    let result = execute(core, &req).await;
    let status = if result.is_ok() { "success" } else { "fail" };
    if !req.node_id.is_empty() {
        let entry = WorkflowDeploy {
            workflow_id: req.workflow_id, node_id: req.node_id.clone(),
            cert_hash: hash.clone(), status: status.into(), updated_at: now(),
        };
        let _ = core.store.mutate(|db| {
            db.workflow_deploys.retain(|d| !(d.workflow_id == entry.workflow_id && d.node_id == entry.node_id));
            db.workflow_deploys.push(entry);
        });
    }
    match result {
        Ok(detail) => {
            let _ = core.emit("cert.deployed", "deploy", json!({
                "target": req.target, "cert_id": req.cert.id, "domains": req.cert.domains,
                "sha256": hash, "workflow_id": req.workflow_id, "detail": detail
            })).await;
            Ok((false, detail))
        }
        Err(e) => {
            let _ = core.emit("cert.deploy_failed", "deploy", json!({
                "target": req.target, "cert_id": req.cert.id, "domains": req.cert.domains,
                "sha256": hash, "error": e.to_string()
            })).await;
            Err(e)
        }
    }
}

fn payload_for(cert: &Cert, req: &DeployRequest) -> Value {
    json!({
        "cert": cert.cert, "key": cert.key, "issuer_cert": cert.issuer_cert,
        "chain": crate::crypto::chain_pem(cert),
        "domains": cert.domains, "domain": cert.domains.first().cloned().unwrap_or_default(),
        "sha256": cert.sha256, "target": req.target
    })
}

async fn execute(core: &Shared, req: &DeployRequest) -> Result<Value> {
    let target = req.target.as_str();
    let params = &req.params;
    let payload = payload_for(&req.cert, req);
    let access = req.access.clone().unwrap_or_default();

    if let Some(before) = params.get("beforeCmd").and_then(|v| v.as_str()) { shell(before)?; }

    let result: Value = match target {
        "localhost" => {
            let cert_path = p(params, "certPath", "data/deployed/cert.pem");
            let key_path = p(params, "keyPath", "data/deployed/key.pem");
            for (path, content) in [(&cert_path, crate::crypto::chain_pem(&req.cert)), (&key_path, req.cert.key.clone())] {
                if let Some(parent) = std::path::Path::new(path).parent() { std::fs::create_dir_all(parent)?; }
                std::fs::write(path, content)?;
            }
            json!({ "written": [cert_path, key_path] })
        }
        "ssh" => {
            let host = c(&req.access, "host", "");
            if host.is_empty() { return Err(AppError::bad_request("SSH credential requires host")); }
            let user = c(&req.access, "user", "root");
            let port = c(&req.access, "port", "22");
            let cert_path = p(params, "certPath", "/etc/ssl/ssld/cert.pem");
            let key_path = p(params, "keyPath", "/etc/ssl/ssld/key.pem");
            let dir = std::env::temp_dir().join(format!("ssld-{}", crate::crypto::random_token(6)));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("cert.pem"), crate::crypto::chain_pem(&req.cert))?;
            std::fs::write(dir.join("key.pem"), &req.cert.key)?;
            let mkdir = format!("ssh -p {port} {user}@{host} mkdir -p $(dirname {cert_path}) $(dirname {key_path})");
            let scp_cert = format!("scp -P {port} {} {user}@{host}:{cert_path}", dir.join("cert.pem").display());
            let scp_key = format!("scp -P {port} {} {user}@{host}:{key_path}", dir.join("key.pem").display());
            let mut log = Vec::new();
            for cmd in [mkdir, scp_cert, scp_key] { log.push(shell(&cmd)?); }
            let _ = std::fs::remove_dir_all(&dir);
            json!({ "host": host, "paths": [cert_path, key_path], "log": log })
        }
        "webhook" => {
            let url = p(params, "url", &c(&req.access, "url", ""));
            if url.is_empty() { return Err(AppError::bad_request("webhook deploy requires url")); }
            let method = p(params, "method", "POST").to_uppercase();
            let template = p(params, "data", "{\"cert\":\"__cert__\",\"key\":\"__key__\",\"domain\":\"__domain__\"}");
            let body = template.replace("__cert__", &req.cert.cert.replace('\n', "\\n"))
                .replace("__key__", &req.cert.key.replace('\n', "\\n"))
                .replace("__issuer_cert__", &req.cert.issuer_cert.replace('\n', "\\n"))
                .replace("__domain__", &req.cert.domains.first().cloned().unwrap_or_default())
                .replace("__sha256__", &req.cert.sha256);
            let mut r = core.http.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST), &url)
                .header("Content-Type", "application/json").body(body);
            if let Some(obj) = params.get("headers").and_then(|v| v.as_object()).or_else(|| access.config.get("headers").and_then(|v| v.as_object())) {
                for (k, v) in obj { r = r.header(k, v.as_str().unwrap_or("")); }
            }
            let resp = r.send().await?;
            if !resp.status().is_success() { return Err(AppError::bad_gateway(format!("deploy webhook returned {}", resp.status()))); }
            let _ = core.emit("cert.pushed", "deploy", json!({ "url": url, "cert_id": req.cert.id })).await;
            json!({ "status": resp.status().as_u16(), "url": url })
        }
        "plugin" => crate::plugin::invoke_deploy(core, &access, params, &payload).await?,
        t if t.starts_with("btpanel") || t == "btwaf-site" || t.starts_with("safeline") || t.starts_with("1panel") || t == "lecdn" => {
            panel_deploy(core, &access, target, params, &payload).await?
        }
        t if t.starts_with("aliyun") || t.starts_with("tencentcloud") || t.starts_with("qiniu")
            || t.starts_with("baidu") || t.starts_with("huaweicloud") || t.starts_with("volcengine")
            || t == "doge-cdn" || t == "rainyun-sslcenter" => {
            cloud_deploy(core, &access, target, params, &payload).await?
        }
        _ => return Err(AppError::bad_request(format!("unsupported deploy target: {target}"))),
    };

    if let Some(after) = params.get("afterCmd").and_then(|v| v.as_str()) { shell(after)?; }
    Ok(result)
}

async fn panel_deploy(core: &Shared, access: &Access, target: &str, params: &Value, payload: &Value) -> Result<Value> {
    let base = c(&Some(access.clone()), "url", "").trim_end_matches('/').to_string();
    if base.is_empty() { return Err(AppError::bad_request("panel credential requires url")); }
    let token = c(&Some(access.clone()), "api_key", &c(&Some(access.clone()), "api_token", ""));
    let endpoint = match target {
        "btpanel" | "btpanel-singlesite" => "/ssl?action=SaveCert",
        "btpanel-site" | "btpanel-dockersite" => "/site?action=SetSSL",
        "btwaf-site" => "/site?action=SetSSL",
        "1panel" => "/api/v1/websites/ssl/upload",
        "1panel-site" => "/api/v1/websites/ssl",
        t if t.starts_with("safeline") => "/api/open/ssl",
        "lecdn" => "/api/cert",
        _ => "/api/ssl",
    };
    let mut body = payload.clone();
    let obj = body.as_object_mut().unwrap();
    obj.insert("siteName".into(), json!(p(params, "siteName", &p(params, "site_name", ""))));
    obj.insert("site_id".into(), json!(p(params, "site_id", "")));
    obj.insert("domain".into(), json!(p(params, "domain", "")));
    obj.insert("api_token".into(), json!(token));
    let resp = core.http.post(format!("{base}{endpoint}"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() { return Err(AppError::bad_gateway(format!("{target} returned {status}: {text}"))); }
    Ok(json!({ "endpoint": endpoint, "status": status.as_u16(), "response": serde_json::from_str::<Value>(&text).unwrap_or(json!({"raw": text})) }))
}

fn deploy_api_spec(target: &str) -> (&'static str, &'static str, &'static str) {
    match target {
        "aliyun-cdn" => ("https://cdn.aliyuncs.com/", "hmac_sha1", "SetDomainServerCertificate"),
        "aliyun-oss" => ("https://oss-cn-hangzhou.aliyuncs.com/", "hmac_sha1", "PutBucketCname"),
        "aliyun-waf" => ("https://wafopenapi.cn-hangzhou.aliyuncs.com/", "hmac_sha1", "CreateCertificate"),
        "aliyun-esa" => ("https://esa.cn-hangzhou.aliyuncs.com/", "hmac_sha1", "SetCertificate"),
        "aliyun-dcdn" => ("https://dcdn.aliyuncs.com/", "hmac_sha1", "SetDcdnDomainSSLCertificate"),
        "tencentcloud-cdn" => ("https://cdn.tencentcloudapi.com/", "tc3", "ModifyDomainConfig"),
        "tencentcloud-cos" => ("https://cos.tencentcloudapi.com/", "tc3", "PutDomainCertificate"),
        "tencentcloud-waf" => ("https://waf.tencentcloudapi.com/", "tc3", "CreateHost"),
        "tencentcloud-teo" => ("https://teo.tencentcloudapi.com/", "tc3", "ModifyHostsCertificate"),
        "qiniu-cdn" | "qiniu-oss" => ("https://api.qiniu.com/", "bearer", "cert"),
        "baidu-cdn" => ("https://cdn.baidubce.com/", "hmac_sha1", "setCertificate"),
        "huaweicloud-cdn" => ("https://cdn.myhuaweicloud.com/", "api_key", "UpdateDomainHttpsCert"),
        "volcengine-cdn" | "volcengine-dcdn" => ("https://cdn.volcengineapi.com/", "sigv4", "UpdateDomainHttps"),
        "doge-cdn" => ("https://api.dogecloud.com/", "hmac_sha1", "cdn/cert/upload.json"),
        "rainyun-sslcenter" => ("https://api.rainyun.cc/", "api_key", "sslcenter"),
        _ => ("", "bearer", "DeployCertificate"),
    }
}

async fn cloud_deploy(core: &Shared, access: &Access, target: &str, params: &Value, payload: &Value) -> Result<Value> {
    let (default_endpoint, style, action) = deploy_api_spec(target);
    let override_url = c(&Some(access.clone()), "endpoint", "");
    let endpoint = if override_url.is_empty() { default_endpoint.to_string() } else { override_url };
    if endpoint.is_empty() {
        return Err(AppError::bad_gateway(format!("{target} needs an `endpoint` in its credential config")));
    }
    let mut body = payload.clone();
    let obj = body.as_object_mut().unwrap();
    for key in ["domain", "region", "bucket", "site_id", "cert_id", "resource_type"] {
        obj.insert(key.into(), json!(p(params, key, "")));
    }
    cloud::call(core, &endpoint, match style { "tc3" => AuthStyle::Tc3, "sigv4" => AuthStyle::AwsSigV4, "hmac_sha1" => AuthStyle::HmacSha1Query, "api_key" => AuthStyle::ApiKeyHeader, _ => AuthStyle::Bearer },
        &access.config, "POST", action, body, flag(&access.config, "ignore_ssl")).await
}

pub async fn test_access(core: &Shared, access: &Access) -> Result<Value> {
    let url = c(&Some(access.clone()), "url", "");
    if access.provider == "localhost" { return Ok(json!({ "reachable": true, "mode": "local filesystem" })); }
    if access.provider == "ssh" {
        let host = c(&Some(access.clone()), "host", "");
        let user = c(&Some(access.clone()), "user", "root");
        let port = c(&Some(access.clone()), "port", "22");
        let out = shell(&format!("ssh -o BatchMode=yes -o ConnectTimeout=8 -p {port} {user}@{host} echo ssld-ok"))?;
        return Ok(json!({ "reachable": true, "host": host, "output": out }));
    }
    if url.is_empty() {
        let (endpoint, _, _) = deploy_api_spec(&access.provider);
        return Ok(json!({ "reachable": !endpoint.is_empty(), "configured": !endpoint.is_empty(), "note": "vendor endpoint default" }));
    }
    let resp = core.http.get(&url).send().await?;
    Ok(json!({ "reachable": true, "status": resp.status().as_u16(), "url": url }))
}
