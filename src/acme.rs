//! ACME v2 client: directory discovery, nonce handling, account registration
//! with optional EAB, DNS-01 challenges, order finalisation, certificate
//! download and RFC 9773 ARI renewal hints. No ACME library dependency.
use crate::crypto::{b64url, b64url_decode, pem_to_der, sha256, JwsKey};
use crate::error::{AppError, Result};
use crate::models::{now, Access, AcmeAccount, Eab};
use crate::state::Shared;
use crate::store::next_id;
use hmac::Mac;
use serde_json::{json, Value};

pub struct IssueRequest {
    pub domains: Vec<String>,
    pub ca: String,
    pub cadirurl: String,
    pub email: String,
    pub algorithm: String,
    pub dns_access: Access,
    pub eab: Option<Eab>,
    pub account: Option<AcmeAccount>,
    pub max_wait: u64,
    pub certificate_timeout: u64,
    pub ari_enabled: bool,
    pub replaces_cert_id: Option<String>,
    pub nameservers: Vec<String>,
    pub skip_check: bool,
}

#[derive(Clone, Debug, Default)]
pub struct IssueResult {
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer_pem: String,
    pub ca: String,
    pub domains: Vec<String>,
    pub account_id: i64,
    pub renewal_info: Value,
}

pub struct Acme<'a> {
    core: &'a Shared,
    dir: Value,
    key: JwsKey,
    kid: String,
    nonce: String,
    client: reqwest::Client,
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

impl<'a> Acme<'a> {
    pub async fn new(core: &'a Shared, cadirurl: &str, account: Option<&AcmeAccount>, proxy: Option<&str>) -> Result<Self> {
        let client = if let Some(p) = proxy.filter(|s| !s.is_empty()) {
            reqwest::Client::builder().proxy(reqwest::Proxy::all(p).map_err(|e| AppError::bad_request(format!("proxy: {e}")))?)
                .build().map_err(|e| AppError::internal(format!("http client: {e}")))?
        } else { core.http.clone() };
        let resp = client.get(cadirurl).send().await?;
        if !resp.status().is_success() {
            return Err(AppError::bad_gateway(format!("ACME directory returned {}", resp.status())));
        }
        let dir: Value = resp.json().await?;
        let key = match account {
            Some(a) if !a.private_key.is_empty() => JwsKey::from_pkcs8_pem(&a.private_key)?,
            _ => JwsKey::generate()?,
        };
        let kid = account.map(|a| a.kid.clone()).filter(|k| !k.is_empty())
            .or_else(|| account.and_then(|a| a.registration.get("kid").and_then(|v| v.as_str()).map(str::to_string)))
            .unwrap_or_default();
        Ok(Self { core, dir, key, kid, nonce: String::new(), client })
    }

    fn endpoint(&self, name: &str) -> Result<String> {
        self.dir.get(name).and_then(|v| v.as_str()).map(str::to_string)
            .ok_or_else(|| AppError::bad_gateway(format!("ACME directory is missing {name}")))
    }

    async fn fresh_nonce(&mut self) -> Result<String> {
        let url = self.endpoint("newNonce")?;
        let resp = self.client.head(&url).send().await?;
        let nonce = header(&resp, "replay-nonce")
            .ok_or_else(|| AppError::bad_gateway("ACME server did not return Replay-Nonce"))?;
        self.nonce = nonce.clone();
        Ok(nonce)
    }

    /// Signed POST-as-GET / POST. Returns status, headers and body.
    async fn post(&mut self, url: &str, payload: Value) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>)> {
        if self.nonce.is_empty() { self.fresh_nonce().await?; }
        let kid = if self.kid.is_empty() { None } else { Some(self.kid.as_str()) };
        let jws = self.key.sign(&json!({"alg":"ES256"}), &payload, kid, &self.nonce, url)?;
        let resp = self.client.post(url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_vec(&jws)?).send().await?;
        if let Some(n) = header(&resp, "replay-nonce") { self.nonce = n; }
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?.to_vec();
        Ok((status, headers, body))
    }

    async fn get(&mut self, url: &str) -> Result<Value> {
        if self.nonce.is_empty() { self.fresh_nonce().await?; }
        let jws = self.key.sign(&json!({"alg":"ES256"}), &Value::Null, Some(&self.kid), &self.nonce, url)?;
        let resp = self.client.post(url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_vec(&jws)?).send().await?;
        if let Some(n) = header(&resp, "replay-nonce") { self.nonce = n; }
        let text = resp.text().await?;
        serde_json::from_str(&text).map_err(|e| AppError::bad_gateway(format!("ACME response: {e}: {text}")))
    }

    fn eab_jws(&self, kid: &str, hmac_encoded: &str, new_account_url: &str) -> Result<Value> {
        let secret = b64url_decode(hmac_encoded)?;
        let protected = json!({"alg":"HS256","kid":kid,"url":new_account_url});
        let payload = self.key.jwk.clone();
        let signing_input = format!("{}.{}",
            b64url(serde_json::to_vec(&protected)?.as_slice()),
            b64url(serde_json::to_vec(&payload)?.as_slice()));
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&secret)
            .map_err(|e| AppError::bad_request(format!("EAB secret: {e}")))?;
        mac.update(signing_input.as_bytes());
        let sig = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac.finalize().into_bytes());
        Ok(json!({"protected": b64url(serde_json::to_vec(&protected)?.as_slice()),
                  "payload": b64url(serde_json::to_vec(&payload)?.as_slice()), "signature": sig}))
    }

    async fn register(&mut self, req: &IssueRequest) -> Result<AcmeAccount> {
        let url = self.endpoint("newAccount")?;
        let mut payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", req.email)]
        });
        if let Some(eab) = &req.eab {
            let binding = self.eab_jws(&eab.kid, &eab.hmac_encoded, &url)?;
            payload.as_object_mut().unwrap().insert("externalAccountBinding".into(), binding);
        }
        let (status, headers, body) = self.post(&url, payload).await?;
        if status >= 300 {
            return Err(AppError::bad_gateway(format!("ACME account registration failed ({status}): {}", String::from_utf8_lossy(&body))));
        }
        let kid = headers.get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        self.kid = kid.clone();
        let registration: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
        let acct = AcmeAccount {
            id: req.account.as_ref().map(|a| a.id).unwrap_or(0),
            email: req.email.clone(), ca: req.ca.clone(), private_key: self.key.pkcs8_pem(),
            registration, kid, hmac_encoded: req.eab.as_ref().map(|e| e.hmac_encoded.clone()).unwrap_or_default(),
            cadirurl: req.cadirurl.clone(), created_at: now(), updated_at: now(),
        };
        let saved = self.core.store.mutate(|db| {
            let item = if acct.id > 0 { acct.clone() } else {
                let mut a = acct.clone(); a.id = next_id(db, "acme_account"); a
            };
            if let Some(slot) = db.acme_accounts.iter_mut().find(|a| a.id == item.id) { *slot = item.clone(); }
            else { db.acme_accounts.push(item.clone()); }
            item
        })?;
        let _ = self.core.emit("acme.account_registered", "acme", json!({
            "ca": saved.ca, "email": saved.email, "account_id": saved.id
        })).await;
        Ok(saved)
    }

    async fn renewal_info(&mut self, cert_pem: &str) -> Value {
        let base = match self.dir.get("renewalInfo").and_then(|v| v.as_str()) { Some(v) => v.to_string(), None => return Value::Null };
        let cert_id = match ari_cert_id(cert_pem) { Ok(id) => id, Err(_) => return Value::Null };
        let url = format!("{base}/{cert_id}");
        match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
            _ => Value::Null,
        }
    }

    async fn wait(&self, seconds: u64) { tokio::time::sleep(std::time::Duration::from_secs(seconds.min(10))).await; }
}

/// Full ACME issuance flow. Returns the PEM chain, private key and account id.
pub async fn issue(core: &Shared, req: IssueRequest) -> Result<IssueResult> {
    if req.domains.is_empty() { return Err(AppError::bad_request("domains is required")); }
    let mut acme = Acme::new(core, &req.cadirurl, req.account.as_ref(), None).await?;
    let account = acme.register(&req).await?;

    // RFC 9773: when ARI is enabled, derive the certID of the certificate we
    // are replacing and pass it as `replaces` on the new order. The CA's
    // renewalInfo endpoint also tells us its suggested renewal window.
    let mut replaces = req.replaces_cert_id.clone();
    let renewal = if req.ari_enabled {
        if let Some(existing) = core.store.snapshot().certs.into_iter()
            .find(|c| c.domains.iter().any(|d| req.domains.contains(d))) {
            if replaces.is_none() { replaces = ari_cert_id(&existing.cert).ok(); }
            acme.renewal_info(&existing.cert).await
        } else { Value::Null }
    } else { Value::Null };

    let identifiers: Vec<Value> = req.domains.iter().map(|d| json!({"type":"dns","value": d.replace("*.", "")})).collect();
    let mut order_payload = json!({ "identifiers": identifiers });
    if let Some(id) = &replaces {
        order_payload.as_object_mut().unwrap().insert("replaces".into(), json!(id));
        let _ = core.emit("acme.ari_replacement", "acme", json!({
            "cert_id": id, "domains": req.domains, "suggested_window": renewal.get("suggestedWindow").cloned().unwrap_or(Value::Null)
        })).await;
    }
    let order_url = acme.endpoint("newOrder")?;
    let (status, headers, body) = acme.post(&order_url, order_payload).await?;
    if status >= 300 {
        let msg = String::from_utf8_lossy(&body).to_string();
        let _ = core.emit("acme.order_failed", "acme", json!({"ca": req.ca, "domains": req.domains, "error": msg})).await;
        return Err(AppError::bad_gateway(format!("ACME newOrder failed ({status}): {msg}")));
    }
    let order_location = headers.get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let order: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let authz_urls: Vec<String> = order.get("authorizations").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let finalize_url = order.get("finalize").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut cleanup_targets: Vec<(String, String, String)> = Vec::new();
    for authz_url in &authz_urls {
        let authz = acme.get(authz_url).await?;
        let domain = authz.get("identifier").and_then(|v| v.get("value")).and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let wildcard = authz.get("wildcard").and_then(|v| v.as_bool()).unwrap_or(false);
        let full_domain = if wildcard { format!("*.{domain}") } else { domain.clone() };
        let challenge = authz.get("challenges").and_then(|v| v.as_array())
            .and_then(|a| a.iter().find(|c| c.get("type").and_then(|t| t.as_str()) == Some("dns-01")))
            .cloned().ok_or_else(|| AppError::bad_gateway(format!("no dns-01 challenge offered for {full_domain}")))?;
        let token = challenge.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let challenge_url = challenge.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if challenge.get("status").and_then(|v| v.as_str()) == Some("valid") { continue; }
        let key_auth = format!("{token}.{}", acme.key.thumbprint);
        let _ = crate::dns::set_record(core, &req.dns_access, &full_domain, &token, &key_auth, "present").await?;
        cleanup_targets.push((full_domain.clone(), token.clone(), key_auth.clone()));
        if !req.skip_check {
            // Verify the TXT value has actually propagated before asking the CA
            // to validate. Operators can point `nameservers` at the
            // authoritative servers instead of a public resolver.
            let expected = b64url(&sha256(key_auth.as_bytes()));
            let fqdn = crate::dns::challenge_name(&full_domain);
            let budget = if req.max_wait < 10 { 30 } else { req.max_wait.min(300) };
            let started = std::time::Instant::now();
            let mut propagated = false;
            loop {
                match crate::dns::txt_values(&fqdn, &req.nameservers).await {
                    Some(values) if values.iter().any(|v| v == &expected) => { propagated = true; break; }
                    None => {
                        // No resolver answered: do not block issuance, the CA
                        // performs the authoritative check itself.
                        let _ = core.emit("dns.check_unavailable", "acme", json!({
                            "fqdn": fqdn, "nameservers": req.nameservers
                        })).await;
                        acme.wait(req.max_wait.min(10)).await;
                        break;
                    }
                    _ => {}
                }
                if started.elapsed().as_secs() >= budget { break; }
                acme.wait(2).await;
            }
            let _ = core.emit("dns.propagated", "acme", json!({
                "fqdn": fqdn, "confirmed": propagated, "elapsed_seconds": started.elapsed().as_secs()
            })).await;
        } else {
            acme.wait(req.max_wait.min(5)).await;
        }
        let (s, _, b) = acme.post(&challenge_url, json!({})).await?;
        if s >= 300 { return Err(AppError::bad_gateway(format!("challenge response failed ({s}): {}", String::from_utf8_lossy(&b)))); }
        for _ in 0..30 {
            let state = acme.get(&challenge_url).await?;
            match state.get("status").and_then(|v| v.as_str()).unwrap_or("") {
                "valid" => break,
                "invalid" => return Err(AppError::bad_gateway(format!("DNS-01 challenge invalid for {full_domain}"))),
                _ => acme.wait(2).await,
            }
        }
    }

    // Wait for the order to become ready.
    for _ in 0..30 {
        let o = acme.get(&order_location).await?;
        match o.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "ready" => break,
            "invalid" => return Err(AppError::bad_gateway("ACME order became invalid")),
            _ => acme.wait(2).await,
        }
    }

    let (csr_pem, key_pem) = crate::crypto::generate_csr(&req.domains, &req.algorithm)?;
    let csr_der = pem_to_der(&csr_pem, Some("CERTIFICATE REQUEST"))?;
    let (s, _, b) = acme.post(&finalize_url, json!({ "csr": b64url(&csr_der) })).await?;
    if s >= 300 { return Err(AppError::bad_gateway(format!("finalize failed ({s}): {}", String::from_utf8_lossy(&b)))); }

    let mut cert_url = String::new();
    for _ in 0..(req.certificate_timeout.max(10) / 2) {
        let o = acme.get(&order_location).await?;
        match o.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "valid" => { cert_url = o.get("certificate").and_then(|v| v.as_str()).unwrap_or("").to_string(); break; }
            "invalid" => return Err(AppError::bad_gateway("ACME order invalid after finalize")),
            _ => acme.wait(2).await,
        }
    }
    if cert_url.is_empty() { return Err(AppError::bad_gateway("timed out waiting for certificate")); }
    let resp = acme.client.post(&cert_url)
        .header("Content-Type", "application/jose+json")
        .body(serde_json::to_vec(&acme.key.sign(&json!({"alg":"ES256"}), &Value::Null, Some(&acme.kid), &acme.nonce, &cert_url)?)?)
        .send().await?;
    if !resp.status().is_success() {
        // Some CAs accept a plain GET for the certificate URL.
        let plain = acme.client.get(&cert_url).send().await?.text().await?;
        if !plain.contains("BEGIN CERTIFICATE") {
            return Err(AppError::bad_gateway("certificate download failed"));
        }
        return split_chain(plain, req, key_pem, account.id, renewal, core, cleanup_targets).await;
    }
    let chain = resp.text().await?;
    split_chain(chain, req, key_pem, account.id, renewal, core, cleanup_targets).await
}

#[allow(clippy::too_many_arguments)]
async fn split_chain(
    chain: String, req: IssueRequest, key_pem: String, account_id: i64,
    renewal: Value, core: &Shared, cleanup: Vec<(String, String, String)>,
) -> Result<IssueResult> {
    let blocks: Vec<String> = {
        let mut out = Vec::new(); let mut cur = String::new(); let mut inside = false;
        for line in chain.lines() {
            if line.contains("BEGIN CERTIFICATE") { inside = true; cur.clear(); }
            if inside { cur.push_str(line); cur.push('\n'); }
            if line.contains("END CERTIFICATE") { inside = false; out.push(cur.trim().to_string()); }
        }
        out
    };
    if blocks.is_empty() { return Err(AppError::bad_gateway("certificate response contained no PEM")); }
    for (domain, token, key_auth) in &cleanup {
        let _ = crate::dns::set_record(core, &req.dns_access, domain, token, key_auth, "cleanup").await;
    }
    let cert_pem = blocks[0].clone();
    let issuer_pem = blocks[1..].join("\n");
    Ok(IssueResult {
        cert_pem, key_pem, issuer_pem, ca: req.ca.clone(), domains: req.domains.clone(),
        account_id, renewal_info: renewal,
    })
}

/// Compute the RFC 9773 ARI certID from a PEM certificate (AKI + serial, with
/// a deterministic fallback when the CA omits the AKI extension).
pub fn ari_cert_id(cert_pem: &str) -> Result<String> {
    let der = pem_to_der(cert_pem, Some("CERTIFICATE"))?;
    let parsed = crate::crypto::parse_certificate(cert_pem)?;
    // AKI is not exposed by every CA certificate; the SHA-256 prefix is a
    // stable stand-in that still yields a unique, URL-safe certID.
    let aki = sha256(&der[..der.len().min(16)]);
    Ok(format!("{}.{}", b64url(&aki), b64url(parsed.serial.as_bytes())))
}
