//! Shared signed-HTTP layer for cloud DNS and deployment providers.
//! Instead of vendoring one SDK per vendor, each provider is described by its
//! endpoint, auth style and parameter names, and the signers below implement
//! the four schemes those endpoints actually use.
use crate::error::{AppError, Result};
use crate::state::Shared;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac");
    m.update(data); m.finalize().into_bytes().to_vec()
}
pub fn hmac_sha1(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<sha1::Sha1> as Mac>::new_from_slice(secret).expect("hmac");
    m.update(data); m.finalize().into_bytes().to_vec()
}
pub fn hash_hex(data: &[u8]) -> String { hex::encode(Sha256::digest(data)) }
pub fn base64_std(data: &[u8]) -> String { base64::engine::general_purpose::STANDARD.encode(data) }

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AuthStyle { Bearer, Basic, ApiKeyHeader, HmacSha1Query, Tc3, AwsSigV4 }

pub fn style(name: &str) -> AuthStyle {
    match name {
        "bearer" => AuthStyle::Bearer,
        "basic" => AuthStyle::Basic,
        "api_key" => AuthStyle::ApiKeyHeader,
        "hmac_sha1" => AuthStyle::HmacSha1Query,
        "tc3" => AuthStyle::Tc3,
        "sigv4" => AuthStyle::AwsSigV4,
        _ => AuthStyle::Bearer,
    }
}

fn strings(config: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter().filter_map(|k| config.get(k).and_then(|v| v.as_str()).map(str::to_string)).collect()
}

/// Execute a signed provider call. `params` are merged into query/body as the
/// vendor expects. Returns parsed JSON when possible, otherwise a text wrapper.
pub async fn call(
    core: &Shared,
    endpoint: &str,
    auth: AuthStyle,
    config: &Value,
    method: &str,
    action: &str,
    params: Value,
    skip_tls: bool,
) -> Result<Value> {
    if endpoint.is_empty() {
        return Err(AppError::bad_request("provider endpoint is not configured"));
    }
    let ts = chrono::Utc::now().timestamp();
    let mut url = url::Url::parse(endpoint).map_err(|e| AppError::bad_request(format!("endpoint: {e}")))?;
    let mut headers: Vec<(String, String)> = vec![("Accept".into(), "application/json".into())];
    let mut body = String::new();

    let id_keys = ["access_key_id", "access_key", "secret_id", "client_id", "username", "api_user", "api_key", "auth_id", "account_id"];
    let secret_keys = ["access_key_secret", "secret_key", "client_secret", "password", "api_secret", "api_token", "auth_password", "secret_access_key"];
    let ids = strings(config, &id_keys);
    let secrets = strings(config, &secret_keys);
    let ak = ids.first().cloned().unwrap_or_default();
    let sk = secrets.first().cloned().unwrap_or_default();

    let obj = params.as_object().cloned().unwrap_or_default();
    match auth {
        AuthStyle::Bearer => {
            headers.push(("Authorization".into(), format!("Bearer {}", if sk.is_empty() { &ak } else { &sk })));
        }
        AuthStyle::Basic => {
            let token = base64_std(format!("{ak}:{sk}").as_bytes());
            headers.push(("Authorization".into(), format!("Basic {token}")));
        }
        AuthStyle::ApiKeyHeader => {
            let name = config.get("header_name").and_then(|v| v.as_str()).unwrap_or("X-Api-Key");
            headers.push((name.into(), if sk.is_empty() { ak.clone() } else { sk.clone() }));
        }
        AuthStyle::HmacSha1Query => {
            let mut q: Vec<(String, String)> = vec![
                ("Action".into(), action.into()),
                ("Format".into(), "JSON".into()),
                ("Version".into(), config.get("version").and_then(|v| v.as_str()).unwrap_or("2015-01-09").into()),
                ("AccessKeyId".into(), ak.clone()),
                ("SignatureMethod".into(), "HMAC-SHA1".into()),
                ("SignatureNonce".into(), crate::crypto::random_token(12)),
                ("Timestamp".into(), chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ("SignatureVersion".into(), "1.0".into()),
            ];
            for (k, v) in &obj {
                q.push((k.clone(), match v { Value::String(s) => s.clone(), _ => v.to_string() }));
            }
            q.sort();
            let canonical: String = q.iter().map(|(k, v)| format!("{}={}", pct(k), pct(v))).collect::<Vec<_>>().join("&");
            let to_sign = format!("GET&{}&{}", pct("/"), pct(&canonical));
            let sig = base64_std(&hmac_sha1(format!("{ak}&").as_bytes(), to_sign.as_bytes()));
            q.push(("Signature".into(), sig));
            {
                let mut pairs = url.query_pairs_mut();
                for (k, v) in q { pairs.append_pair(&k, &v); }
            }
        }
        AuthStyle::Tc3 => {
            let host = url.host_str().unwrap_or("").to_string();
            let service = host.split('.').next().unwrap_or("").to_string();
            let payload = serde_json::to_string(&params)?;
            let canonical = format!("POST\n/\n\ncontent-type:application/json\nhost:{host}\n\ncontent-type;host\n{}", hash_hex(payload.as_bytes()));
            let scope = format!("{}/{}/tc3_request", chrono::Utc::now().format("%Y%m%d"), service);
            let to_sign = format!("TC3-HMAC-SHA256\n{ts}\n{scope}\n{}", hash_hex(canonical.as_bytes()));
            let k_date = hmac_sha256(format!("TC3{sk}").as_bytes(), chrono::Utc::now().format("%Y%m%d").to_string().as_bytes());
            let k_service = hmac_sha256(&k_date, service.as_bytes());
            let k_signing = hmac_sha256(&k_service, b"tc3_request");
            let sig = hex::encode(hmac_sha256(&k_signing, to_sign.as_bytes()));
            headers.push(("Content-Type".into(), "application/json".into()));
            headers.push(("X-TC-Action".into(), action.into()));
            headers.push(("X-TC-Timestamp".into(), ts.to_string()));
            headers.push(("X-TC-Version".into(), config.get("version").and_then(|v| v.as_str()).unwrap_or("2021-03-23").into()));
            headers.push(("Authorization".into(), format!(
                "TC3-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=content-type;host, Signature={sig}")));
            body = payload;
        }
        AuthStyle::AwsSigV4 => {
            let host = url.host_str().unwrap_or("").to_string();
            let region = config.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let service = config.get("service").and_then(|v| v.as_str()).unwrap_or("route53");
            let payload = serde_json::to_string(&params)?;
            let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let date = chrono::Utc::now().format("%Y%m%d").to_string();
            let canonical = format!("POST\n/\n\nhost:{host}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n{}", hash_hex(payload.as_bytes()));
            let scope = format!("{date}/{region}/{service}/aws4_request");
            let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hash_hex(canonical.as_bytes()));
            let k_date = hmac_sha256(format!("AWS4{sk}").as_bytes(), date.as_bytes());
            let k_region = hmac_sha256(&k_date, region.as_bytes());
            let k_service = hmac_sha256(&k_region, service.as_bytes());
            let k_signing = hmac_sha256(&k_service, b"aws4_request");
            let sig = hex::encode(hmac_sha256(&k_signing, to_sign.as_bytes()));
            headers.push(("Content-Type".into(), "application/json".into()));
            headers.push(("X-Amz-Date".into(), amz_date));
            headers.push(("X-Amz-Target".into(), action.into()));
            headers.push(("Authorization".into(), format!(
                "AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}")));
            body = payload;
        }
    }

    let client = if skip_tls {
        reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap_or_else(|_| core.http.clone())
    } else { core.http.clone() };
    let verb = reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut req = client.request(verb, url.clone());
    for (k, v) in headers { req = req.header(k, v); }
    if !body.is_empty() { req = req.body(body); }
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    if !status.is_success() {
        return Err(AppError::bad_gateway(format!("provider returned {status}: {}", parsed)));
    }
    Ok(parsed)
}

fn pct(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
        .replace('+', "%20").replace("%7E", "~")
}
