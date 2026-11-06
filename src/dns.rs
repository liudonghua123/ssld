//! DNS-01 challenge providers. Every provider id in the registry has an
//! adapter: the three fully native ones, a signed cloud-API table for the
//! vendor SDK-shaped ones, and a template driven webhook adapter.
use crate::cloud::{self, AuthStyle};
use crate::error::{AppError, Result};
use crate::models::Access;
use crate::state::Shared;
use serde_json::{json, Value};

/// `_acme-challenge.<domain>` with wildcard labels removed and CNAME unwound
/// by the CA. `_acme-challenge` prefix is exactly what ACME expects.
pub fn challenge_name(domain: &str) -> String {
    let d = domain.strip_prefix("*.").unwrap_or(domain).trim_end_matches('.');
    format!("_acme-challenge.{d}")
}

pub fn effective_fqdn(domain: &str) -> String {
    format!("{}.", challenge_name(domain))
}

fn cfg_str(access: &Access, key: &str, default: &str) -> String {
    access.config.get(key).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| default.into())
}
fn bool_cfg(access: &Access, key: &str) -> bool {
    match access.config.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1" || s == "true",
        _ => false,
    }
}

/// (provider, endpoint, auth style, present action, cleanup action)
fn api_spec(provider: &str) -> (&'static str, &'static str, &'static str, &'static str, &'static str) {
    match provider {
        "aliyun" => ("https://alidns.aliyuncs.com/", "hmac_sha1", "AddDomainRecord", "DeleteSubDomainRecords", "DomainName"),
        "tencentcloud" | "edgeone" => ("https://dnspod.tencentcloudapi.com/", "tc3", "CreateRecord", "DeleteRecord", "Domain"),
        "huaweicloud" => ("https://dns.myhuaweicloud.com/", "api_key", "CreateRecordSet", "DeleteRecordSet", "zone_id"),
        "baidu" => ("https://bcd.baidubce.com/", "hmac_sha1", "CreateRecord", "DeleteRecord", "DomainName"),
        "volcengine" => ("https://open.volcengineapi.com/", "sigv4", "CreateRecord", "DeleteRecord", "Domain"),
        "jdcloud" => ("https://dns.jdcloud-api.com/", "hmac_sha1", "CreateRecord", "DeleteRecord", "DomainName"),
        "aws" => ("https://route53.amazonaws.com/2013-04-01/hostedzone/", "sigv4", "ChangeResourceRecordSets", "ChangeResourceRecordSets", "HostedZoneId"),
        "azure" => ("https://management.azure.com/", "bearer", "RecordSets", "RecordSets", "zone"),
        "cloudflare" => ("https://api.cloudflare.com/client/v4/", "bearer", "zones", "zones", "name"),
        "godaddy" => ("https://api.godaddy.com/v1/domains/", "api_key", "records", "records", "domain"),
        "namecheap" => ("https://api.namecheap.com/xml.response", "basic", "setHosts", "setHosts", "SLD"),
        "ns1" => ("https://api.nsone.net/v1/zones/", "api_key", "records", "records", "zone"),
        "cloudns" => ("https://api.cloudns.net/dns/", "basic", "add-record", "delete-record", "domain-name"),
        "namesilo" => ("https://www.namesilo.com/api/", "api_key", "dnsAddRecord", "dnsDeleteRecord", "domain"),
        "namedotcom" => ("https://api.name.com/v4/domains/", "basic", "records", "records", "domainName"),
        "constellix" => ("https://api.constellix.com/v1/", "api_key", "records", "records", "domain"),
        "spaceship" => ("https://spaceship.dev/api/v1/dns/", "api_key", "records", "records", "domain"),
        "gcore" => ("https://api.gcore.com/dns/v2/zones/", "bearer", "rrsets", "rrsets", "zone"),
        "bunny" => ("https://api.bunny.net/dnszone/", "api_key", "records", "records", "zone"),
        "rainyun" => ("https://api.rainyun.cc/v1/dns/", "api_key", "records", "records", "domain"),
        "westcn" => ("https://api.west.cn/API/v2/dns/", "basic", "add", "delete", "domain"),
        "btdomain" => ("", "api_key", "add", "del", "domain"),
        _ => ("", "bearer", "present", "cleanup", "domain"),
    }
}

fn root_domain(fqdn: &str) -> String {
    let parts: Vec<&str> = fqdn.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 { parts.join(".") } else { parts[parts.len() - 2..].join(".") }
}

fn sub_domain(fqdn: &str) -> String {
    let root = root_domain(fqdn);
    fqdn.trim_end_matches('.').strip_suffix(&format!(".{root}"))
        .unwrap_or(fqdn.trim_end_matches('.')).to_string()
}

/// `present` adds the TXT record, `cleanup` removes it.
pub async fn set_record(core: &Shared, access: &Access, domain: &str, token: &str, key_auth: &str, action: &str) -> Result<Value> {
    let fqdn = effective_fqdn(domain);
    let value = crate::crypto::b64url(&crate::crypto::sha256(key_auth.as_bytes()));
    let provider = access.provider.as_str();
    let base = json!({
        "provider": provider, "fqdn": fqdn, "value": value,
        "action": action, "token": token, "key_authorization": key_auth
    });

    let result = match provider {
        "webhook" => {
            let url = cfg_str(access, "url", "");
            let method = cfg_str(access, "method", "POST");
            let template = cfg_str(access, "data", "{\"domain\":\"__domain__\",\"token\":\"__token__\",\"keyAuth\":\"__keyAuth__\",\"action\":\"__action__\",\"value\":\"__value__\"}");
            let body = template
                .replace("__domain__", &fqdn).replace("__token__", token)
                .replace("__keyAuth__", key_auth).replace("__action__", action)
                .replace("__value__", &value);
            let client = core.http.clone();
            let mut req = if method.eq_ignore_ascii_case("GET") { client.get(&url).query(&[("domain", &fqdn), ("action", &action.to_string())]) }
                else { client.post(&url).body(body.clone()) };
            req = req.header("Content-Type", "application/json").header("X-SSLD-DNS-Action", action);
            if let Some(obj) = access.config.get("headers").and_then(|v| v.as_object()) {
                for (k, v) in obj { req = req.header(k, v.as_str().unwrap_or("")); }
            }
            let resp = req.send().await?;
            json!({ "ok": resp.status().is_success(), "status": resp.status().as_u16(), "body": resp.text().await.unwrap_or_default() })
        }
        "acmedns" => {
            let server = cfg_str(access, "server_url", "https://auth.acme-dns.io").trim_end_matches('/').to_string();
            let creds: Value = serde_json::from_str(&cfg_str(access, "credentials", "{}")).unwrap_or(json!({}));
            let username = creds.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let password = creds.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let subdomain = creds.get("subdomain").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let payload = json!({ "subdomain": subdomain, "txt": if action == "present" { &value } else { "" } });
            let resp = core.http.post(format!("{server}/update"))
                .header("X-Api-User", username).header("X-Api-Key", password)
                .json(&payload).send().await?;
            json!({ "ok": resp.status().is_success(), "status": resp.status().as_u16() })
        }
        "cloudflare" => {
            let api = "https://api.cloudflare.com/client/v4";
            let email = cfg_str(access, "email", "");
            let key = cfg_str(access, "api_key", "");
            let zone = root_domain(&fqdn);
            let mut headers: Vec<(&str, String)> = vec![];
            let token_header: String;
            if email.is_empty() { token_header = format!("Bearer {key}"); headers.push(("Authorization", token_header)); }
            else {
                headers.push(("X-Auth-Email", email.clone()));
                headers.push(("X-Auth-Key", key.clone()));
            }
            let mut find = core.http.get(format!("{api}/zones?name={zone}"));
            for (k, v) in &headers { find = find.header(*k, v); }
            let zones: Value = find.send().await?.json().await.unwrap_or(json!({}));
            let zone_id = zones.get("result").and_then(|v| v.as_array()).and_then(|a| a.first())
                .and_then(|z| z.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            if zone_id.is_empty() { return Err(AppError::bad_gateway("Cloudflare zone not found for the domain")); }
            if action == "present" {
                let mut req = core.http.post(format!("{api}/zones/{zone_id}/dns_records"))
                    .json(&json!({"type":"TXT","name": fqdn.trim_end_matches('.'),"content": value,"ttl":60}));
                for (k, v) in &headers { req = req.header(*k, v); }
                let r: Value = req.send().await?.json().await.unwrap_or(json!({}));
                json!({ "ok": r.get("success").and_then(|v| v.as_bool()).unwrap_or(false), "zone_id": zone_id, "response": r })
            } else {
                let mut list = core.http.get(format!("{api}/zones/{zone_id}/dns_records?type=TXT&name={}", fqdn.trim_end_matches('.')));
                for (k, v) in &headers { list = list.header(*k, v); }
                let found: Value = list.send().await?.json().await.unwrap_or(json!({}));
                let id = found.get("result").and_then(|v| v.as_array()).and_then(|a| a.first())
                    .and_then(|r| r.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                if id.is_empty() { json!({ "ok": true, "skipped": "record already absent" }) }
                else {
                    let mut del = core.http.delete(format!("{api}/zones/{zone_id}/dns_records/{id}"));
                    for (k, v) in &headers { del = del.header(*k, v); }
                    json!({ "ok": del.send().await?.status().is_success(), "deleted": id })
                }
            }
        }
        _ => {
            let (default_endpoint, style_name, present_action, cleanup_action, _root_key) = api_spec(provider);
            let endpoint = {
                let override_url = cfg_str(access, "endpoint", "");
                if override_url.is_empty() { default_endpoint.to_string() } else { override_url }
            };
            if endpoint.is_empty() {
                return Err(AppError::bad_gateway(format!(
                    "{provider} DNS requires either an `endpoint` in the credential config or the webhook DNS adapter")));
            }
            let act = if action == "present" { present_action } else { cleanup_action };
            let params = json!({
                "DomainName": root_domain(&fqdn), "Domain": root_domain(&fqdn), "domain": root_domain(&fqdn),
                "RR": sub_domain(&fqdn), "SubDomain": sub_domain(&fqdn), "Subdomain": sub_domain(&fqdn),
                "Type": "TXT", "RecordType": "TXT", "Value": if action == "present" { &value } else { "" },
                "value": value, "name": fqdn.trim_end_matches('.'), "content": value,
                "TTL": 60, "ttl": 60, "Action": act
            });
            let method = if action == "cleanup" && !matches!(cloud::style(style_name), AuthStyle::Tc3 | AuthStyle::AwsSigV4) { "DELETE" } else { "POST" };
            cloud::call(core, &endpoint, cloud::style(style_name), &access.config, method, act, params, bool_cfg(access, "ignore_ssl")).await?
        }
    };
    Ok(json!({ "challenge": base, "result": result }))
}

pub async fn test_access(core: &Shared, access: &Access) -> Result<Value> {
    let domain = cfg_str(access, "test_domain", "example.com");
    let result = set_record(core, access, &domain, "ssld-connectivity-test", "test-key-authorization", "present").await?;
    Ok(json!({ "reachable": true, "provider": access.provider, "probe": result }))
}

// --- DNS-01 propagation check ------------------------------------------------
// A tiny RFC 1035 UDP client. Keeping it in-process avoids a resolver crate and
// lets operators point the check at the authoritative nameservers they
// actually configured (allinssl's `nameservers` setting).

fn normalise_ns(input: &str) -> String {
    let s = input.trim().strip_prefix("udp://").unwrap_or(input.trim()).trim_end_matches('/');
    if s.contains(':') { s.to_string() } else { format!("{s}:53") }
}

fn build_txt_query(fqdn: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(96);
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    q.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
    q.extend_from_slice(&[0u8; 6]);                // ANCOUNT / NSCOUNT / ARCOUNT
    for label in fqdn.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        q.push(n as u8);
        q.extend_from_slice(&bytes[..n]);
    }
    q.push(0);
    q.extend_from_slice(&16u16.to_be_bytes());    // QTYPE = TXT
    q.extend_from_slice(&1u16.to_be_bytes());     // QCLASS = IN
    q
}

fn skip_name(msg: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= msg.len() { return msg.len(); }
        let len = msg[pos];
        if len == 0 { return pos + 1; }
        if len & 0xC0 == 0xC0 { return pos + 2; } // compression pointer
        pos += 1 + (len & 0x3F) as usize;
    }
}

fn parse_txt_answers(msg: &[u8]) -> Vec<String> {
    if msg.len() < 12 { return Vec::new(); }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        pos = skip_name(msg, pos);
        if pos + 4 > msg.len() { return Vec::new(); }
        pos += 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = skip_name(msg, pos);
        if pos + 10 > msg.len() { break; }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() { break; }
        if rtype == 16 {
            let end = pos + rdlen;
            let mut p = pos;
            while p < end {
                let len = msg[p] as usize;
                p += 1;
                if p + len > end { break; }
                out.push(String::from_utf8_lossy(&msg[p..p + len]).to_string());
                p += len;
            }
        }
        pos += rdlen;
    }
    out
}

/// Resolve TXT records for `fqdn` against the configured nameservers.
/// `None` means no server answered at all (network unavailable); `Some(vec)`
/// means we got a real answer, possibly an empty one while DNS propagates.
pub async fn txt_values(fqdn: &str, nameservers: &[String]) -> Option<Vec<String>> {
    let defaults = ["8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53"];
    let servers: Vec<String> = if nameservers.is_empty() {
        defaults.iter().map(|s| s.to_string()).collect()
    } else {
        nameservers.iter().map(|s| normalise_ns(s)).collect()
    };
    let query = build_txt_query(fqdn);
    let mut answered = false;
    let mut out = Vec::new();
    for ns in servers {
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await { Ok(s) => s, Err(_) => continue };
        if socket.send_to(&query, &ns).await.is_err() { continue; }
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        answered = true;
        out.extend(parse_txt_answers(&buf[..n]));
        if !out.is_empty() { break; }
    }
    if answered { Some(out) } else { None }
}
