//! Session, API key signature and secure-entry authentication helpers.
use crate::crypto;
use crate::error::{AppError, Result};
use crate::models::{now, Session};
use crate::state::Shared;
use crate::store::next_id;
use serde_json::json;

pub fn hash_password(password: &str, salt: &str) -> String {
    crypto::sha256_hex(format!("{password}{salt}").as_bytes())
}

pub fn login(core: &Shared, username: &str, password: &str, captcha: Option<&str>) -> Result<Session> {
    let db = core.store.snapshot();
    let now_ts = chrono::Utc::now().timestamp();
    let lock_key = format!("login_lock_until:{username}");
    if let Some(until) = db.counters.get(&lock_key) {
        if *until > now_ts {
            return Err(AppError::forbidden(format!("account locked, try again after {} seconds", until - now_ts)));
        }
    }
    let fail_key = format!("login_fail:{username}");
    let fails = db.counters.get(&fail_key).copied().unwrap_or(0);
    if fails >= core.config.auth.login_lock_threshold && captcha.is_none() {
        return Err(AppError::bad_request("captcha required after repeated failures"));
    }
    let user = db.users.iter().find(|u| u.username == username)
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    let ok = crypto::constant_time_eq(&hash_password(password, &user.salt), &user.password_hash);
    if !ok {
        let _ = core.store.mutate(|db| {
            let f = db.counters.entry(fail_key).or_insert(0); *f += 1;
            if *f >= core.config.auth.login_lock_threshold {
                db.counters.insert(lock_key, now_ts + core.config.auth.login_lock_minutes * 60);
            }
        });
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let _ = core.store.mutate(|db| {
        db.counters.remove(&fail_key); db.counters.remove(&lock_key);
    });
    let token = crypto::random_token(24);
    let ts = now();
    let session = Session {
        token: token.clone(), username: username.into(), created_at: ts.clone(),
        last_seen: ts, secure: true,
    };
    core.store.mutate(|db| {
        db.sessions.retain(|s| s.username != username || (chrono::Utc::now().timestamp()
            - chrono::DateTime::parse_from_rfc3339(&s.last_seen).map(|d| d.timestamp()).unwrap_or(0)) < core.config.auth.session_timeout);
        db.sessions.push(session.clone());
        trim_sessions(db, 256);
    })?;
    core.oplog(username, "login", "session", json!({}));
    Ok(session)
}

fn trim_sessions(db: &mut crate::store::Database, cap: usize) {
    if db.sessions.len() > cap { let n = db.sessions.len() - cap; db.sessions.drain(0..n); }
}

pub fn logout(core: &Shared, token: &str) {
    let _ = core.store.mutate(|db| db.sessions.retain(|s| s.token != token));
}

pub fn session(core: &Shared, token: &str) -> Option<Session> {
    let db = core.store.snapshot();
    let found = db.sessions.iter().find(|s| s.token == token)?.clone();
    let last = chrono::DateTime::parse_from_rfc3339(&found.last_seen).map(|d| d.timestamp()).unwrap_or(0);
    if chrono::Utc::now().timestamp() - last > core.config.auth.session_timeout { return None; }
    Some(found)
}

pub fn touch(core: &Shared, token: &str) {
    let _ = core.store.mutate(|db| {
        if let Some(s) = db.sessions.iter_mut().find(|s| s.token == token) { s.last_seen = now(); }
    });
}

/// allinssl-compatible open API signature:
/// `api_token = md5(timestamp + lower(md5(api_key)))`. ssld uses SHA-256 for
/// both steps and also accepts a plain `X-API-Key` header equal to the key.
pub fn check_api_signature(core: &Shared, token: &str, timestamp: &str) -> bool {
    let key = core.setting("api_key").unwrap_or_else(|| core.config.auth.api_key.clone());
    if key.is_empty() { return false; }
    if crypto::constant_time_eq(token, &key) { return true; }
    let ts: i64 = match timestamp.parse() { Ok(v) => v, Err(_) => return false };
    if (chrono::Utc::now().timestamp() - ts).abs() > 300 { return false; }
    let inner = crypto::sha256_hex(key.as_bytes()).to_lowercase();
    let expected = crypto::sha256_hex(format!("{timestamp}{inner}").as_bytes());
    if crypto::constant_time_eq(token, &expected) { return true; }
    // Clients that prefer a keyed signature may send base64(HMAC-SHA256).
    let keyed = crypto::hmac_sha256_b64(&key, format!("{timestamp}.{inner}").as_bytes());
    crypto::constant_time_eq(token, &keyed)
}

pub fn captcha(core: &Shared) -> serde_json::Value {
    let text = {
        let mut buf = [0u8; 3];
        use rand::RngCore; rand::thread_rng().fill_bytes(&mut buf);
        format!("{:x}{:x}{:x}", buf[0] % 16, buf[1] % 16, buf[2] % 16)
    };
    let id = crypto::random_token(8);
    let _ = core.store.mutate(|db| {
        db.settings.insert(format!("captcha:{id}"), text.clone());
        let stale: Vec<String> = db.settings.keys().filter(|k| k.starts_with("captcha:")).cloned().collect();
        if stale.len() > 100 { for k in stale.iter().take(stale.len() - 100) { db.settings.remove(k); } }
    });
    // A tiny inline SVG acts as the visual captcha; the code is kept server side.
    let svg = format!("<svg xmlns='http://www.w3.org/2000/svg' width='120' height='40'><rect width='120' height='40' fill='#f4f6f8'/><text x='60' y='27' font-family='monospace' font-size='20' text-anchor='middle' fill='#1b6c80'>{}</text></svg>", text);
    let encoded = crypto::b64(svg.as_bytes());
    json!({ "id": id, "image": format!("data:image/svg+xml;base64,{encoded}") })
}

pub fn verify_captcha(core: &Shared, id: &str, code: &str) -> bool {
    let key = format!("captcha:{id}");
    let expected = core.setting(&key);
    if let Some(v) = expected {
        let _ = core.store.mutate(|db| { db.settings.remove(&key); });
        return v.eq_ignore_ascii_case(code);
    }
    false
}

pub fn secure_entry(core: &Shared) -> String {
    core.setting("secure").unwrap_or_else(|| "/".into())
}

pub fn is_secure_enabled(core: &Shared) -> bool {
    let s = secure_entry(core);
    !s.is_empty() && s != "/" && s != "/login"
}

pub fn rotate_key(core: &Shared) -> String {
    let key = crypto::random_token(24);
    let _ = core.store.mutate(|db| {
        db.settings.insert("api_key".into(), key.clone());
        db.sessions.clear();
        let _ = next_id(db, "auth_rotation");
    });
    key
}
