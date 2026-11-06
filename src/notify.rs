//! Notification channels: SMTP mail, generic webhook, DingTalk, Feishu and
//! WeCom. Placeholders are shared with the webhook subsystem.
use crate::error::{AppError, Result};
use crate::models::ReportChannel;
use crate::state::Shared;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

fn field(ch: &ReportChannel, key: &str, default: &str) -> String {
    ch.config.get(key).and_then(|v| v.as_str()).map(str::to_string)
        .unwrap_or_else(|| default.to_string())
}
fn enabled(ch: &ReportChannel) -> bool {
    match ch.config.get("enabled") {
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s != "0" && s != "false",
        Some(Value::Number(n)) => n.as_i64() != Some(0),
        _ => true,
    }
}

fn render(template: &str, subject: &str, body: &str, extra: &Value) -> String {
    let mut out = template.replace("__subject__", subject).replace("__body__", body)
        .replace("__timestamp__", &chrono::Utc::now().timestamp().to_string());
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            let plain = match v { Value::String(s) => s.clone(), _ => v.to_string() };
            out = out.replace(&format!("__{k}__"), &plain);
        }
    }
    out
}

fn dingtalk_sign(secret: &str) -> (String, String) {
    let ts = chrono::Utc::now().timestamp_millis().to_string();
    let data = format!("{ts}\n{secret}");
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac");
    m.update(data.as_bytes());
    let sign = base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes());
    (ts, sign)
}

fn feishu_sign(secret: &str) -> (String, String) {
    let ts = chrono::Utc::now().timestamp().to_string();
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(format!("{ts}\n{secret}").as_bytes()).expect("hmac");
    m.update(b"");
    (ts, base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes()))
}

pub async fn send(core: &Shared, ch: &ReportChannel, subject: &str, body: &str, extra: &Value) -> Result<Value> {
    if !enabled(ch) { return Ok(json!({ "skipped": "channel disabled" })); }
    match ch.kind.as_str() {
        "mail" => send_mail(ch, subject, body),
        "webhook" => {
            let url = field(ch, "url", "");
            if url.is_empty() { return Err(AppError::bad_request("webhook channel requires url")); }
            let method = field(ch, "method", "POST").to_uppercase();
            let template = field(ch, "data", "{\"subject\":\"__subject__\",\"body\":\"__body__\"}");
            let payload = render(&template, subject, body, extra);
            let mut req = core.http.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST), &url)
                .header("Content-Type", "application/json").body(payload);
            if let Some(obj) = ch.config.get("headers").and_then(|v| v.as_object()) {
                for (k, v) in obj { req = req.header(k, render(v.as_str().unwrap_or(""), subject, body, extra)); }
            }
            let r = req.send().await?;
            if !r.status().is_success() { return Err(AppError::bad_gateway(format!("notification webhook returned {}", r.status()))); }
            Ok(json!({ "status": r.status().as_u16(), "channel": ch.name }))
        }
        "dingtalk" => {
            let url = field(ch, "webhook", "");
            let secret = field(ch, "secret", "");
            let mut target = url.clone();
            if !secret.is_empty() {
                let (ts, sign) = dingtalk_sign(&secret);
                target = format!("{url}{}&timestamp={ts}&sign={}", if url.contains('?') { "" } else { "?" }, url::form_urlencoded::byte_serialize(sign.as_bytes()).collect::<String>());
            }
            let r = core.http.post(&target)
                .json(&json!({"msgtype":"text","text":{"content": format!("{subject}\n\n{body}")}}))
                .send().await?;
            let text = r.text().await?;
            if text.contains("\"errcode\":0") || text.contains("success") { Ok(json!({ "channel": ch.name, "response": text })) }
            else { Err(AppError::bad_gateway(format!("DingTalk: {text}"))) }
        }
        "feishu" => {
            let url = field(ch, "webhook", "");
            let (ts, sign) = feishu_sign(&field(ch, "secret", ""));
            let r = core.http.post(&url)
                .json(&json!({"timestamp": ts, "sign": sign, "msg_type":"text",
                    "content":{"text": format!("{subject}\n\n{body}")}})).send().await?;
            Ok(json!({ "status": r.status().as_u16(), "channel": ch.name, "response": r.text().await.unwrap_or_default() }))
        }
        "workwx" => {
            let url = field(ch, "url", "");
            let template = field(ch, "data", "{\"msgtype\":\"news\",\"news\":{\"articles\":[{\"title\":\"__subject__\",\"description\":\"__body__\"}]}}");
            let payload = render(&template, subject, body, extra);
            let r = core.http.post(&url).header("Content-Type", "application/json").body(payload).send().await?;
            Ok(json!({ "status": r.status().as_u16(), "channel": ch.name, "response": r.text().await.unwrap_or_default() }))
        }
        other => Err(AppError::bad_request(format!("unknown notification channel: {other}"))),
    }
}

fn send_mail(ch: &ReportChannel, subject: &str, body: &str) -> Result<Value> {
    use lettre::{Message, SmtpTransport, Transport};
    let host = field(ch, "smtpHost", "");
    if host.is_empty() { return Err(AppError::bad_request("mail channel requires smtpHost")); }
    let port: u16 = field(ch, "smtpPort", "465").parse().unwrap_or(465);
    let sender = field(ch, "sender", "");
    let receiver = field(ch, "receiver", "");
    let user = field(ch, "username", &sender);
    let password = field(ch, "password", "");
    let email = Message::builder()
        .from(sender.parse().map_err(|e| AppError::bad_request(format!("sender: {e}")))?)
        .to(receiver.parse().map_err(|e| AppError::bad_request(format!("receiver: {e}")))?)
        .subject(subject)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(body.to_string()).map_err(|e| AppError::bad_request(format!("mail body: {e}")))?;
    let creds = lettre::transport::smtp::authentication::Credentials::new(user, password);
    let tls = match ch.config.get("smtpTLS") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1" || s == "true",
        _ => port == 465,
    };
    let mailer = if tls {
        SmtpTransport::relay(&host).map_err(|e| AppError::bad_gateway(format!("SMTP relay: {e}")))?
            .port(port).credentials(creds).build()
    } else {
        SmtpTransport::builder_dangerous(&host).port(port).credentials(creds).build()
    };
    let response = mailer.send(&email).map_err(|e| AppError::bad_gateway(format!("SMTP send: {e}")))?;
    Ok(json!({ "channel": ch.name, "smtp": host, "response": response.message().collect::<Vec<_>>().join("") }))
}

/// `report_types` accepts channel ids or channel kinds, matching allinssl's
/// multi-account alarm lists.
pub async fn notify_many(core: &Shared, report_types: &[String], subject: &str, body: &str, extra: &Value) -> Vec<Value> {
    let db = core.store.snapshot();
    let mut chosen: Vec<ReportChannel> = Vec::new();
    for item in report_types {
        for token in item.split(',') {
            let token = token.trim();
            if token.is_empty() { continue; }
            if let Ok(id) = token.parse::<i64>() {
                if let Some(ch) = db.channels.iter().find(|c| c.id == id) { if !chosen.iter().any(|c| c.id == ch.id) { chosen.push(ch.clone()); } }
            } else if let Some(ch) = db.channels.iter().find(|c| c.kind == token) {
                if !chosen.iter().any(|c| c.id == ch.id) { chosen.push(ch.clone()); }
            }
        }
    }
    let mut out = Vec::new();
    for ch in chosen {
        let result = match send(core, &ch, subject, body, extra).await {
            Ok(v) => json!({ "channel": ch.name, "ok": true, "result": v }),
            Err(e) => {
                let _ = core.emit("notify.failed", "notify", json!({"channel": ch.name, "error": e.to_string()})).await;
                json!({ "channel": ch.name, "ok": false, "error": e.to_string() })
            }
        };
        out.push(result);
    }
    out
}

pub async fn test(core: &Shared, id: i64) -> Result<Value> {
    let ch = core.store.snapshot().channels.into_iter().find(|c| c.id == id)
        .ok_or_else(|| AppError::not_found("notification channel not found"))?;
    let result = send(core, &ch, "ssld notification test", "This is a test message from ssld.", &json!({})).await?;
    let _ = core.emit("channel.test", "notify", json!({"channel_id": id, "channel": ch.name})).await;
    Ok(result)
}
