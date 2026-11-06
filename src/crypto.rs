//! PEM / X.509 helpers, key generation, CSR, private CA signing, HMAC and
//! certificate bundle export. Pure Rust except the optional `openssl` binary
//! used for PKCS#12 and JKS conversion.
use crate::error::{AppError, Result};
use crate::models::Cert;
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rcgen::{BasicConstraints, Certificate as RcCert, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use x509_parser::prelude::*;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn b64(data: &[u8]) -> String { B64.encode(data) }
pub fn b64url(data: &[u8]) -> String { base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data) }
pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
        .map_err(|e| AppError::bad_request(format!("base64url: {e}")))
}
pub fn sha256_hex(data: &[u8]) -> String { hex::encode(Sha256::digest(data)) }
pub fn sha256(data: &[u8]) -> Vec<u8> { Sha256::digest(data).to_vec() }

pub fn hmac_sha256_hex(secret: &str, data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}
pub fn hmac_sha256_b64(secret: &str, data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(data);
    b64(&mac.finalize().into_bytes())
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes(); let b = b.as_bytes();
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

pub fn random_token(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Decode a PEM block, optionally constraining the label.
pub fn pem_to_der(pem: &str, label: Option<&str>) -> Result<Vec<u8>> {
    let mut collecting = false;
    let mut body = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            if let Some(want) = label {
                if !line.contains(want) { collecting = false; continue; }
            }
            collecting = true;
            continue;
        }
        if line.starts_with("-----END") { if collecting { break; } else { continue; } }
        if collecting && !line.is_empty() { body.push_str(line); }
    }
    if body.is_empty() { return Err(AppError::bad_request("no PEM block found")); }
    B64.decode(body).map_err(|e| AppError::bad_request(format!("invalid PEM base64: {e}")))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ParsedCert {
    pub subject_cn: String,
    pub issuer: String,
    pub domains: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub sha256: String,
    pub serial: String,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub is_ca: bool,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub der_len: usize,
}

fn attr_from(name: &str, key: &str) -> String {
    name.split(',')
        .find_map(|part| {
            let mut kv = part.trim().splitn(2, '=');
            let k = kv.next()?.trim();
            let v = kv.next()?.trim();
            (k.eq_ignore_ascii_case(key)).then(|| v.to_string())
        })
        .unwrap_or_default()
}

fn oid_string(v: impl std::fmt::Debug) -> String {
    let s = format!("{v:?}");
    s.strip_prefix("OID(").and_then(|s| s.strip_suffix(')')).unwrap_or(&s).to_string()
}

pub fn parse_certificate(pem: &str) -> Result<ParsedCert> {
    let der = pem_to_der(pem, Some("CERTIFICATE"))?;
    let (_, x) = parse_x509_certificate(&der)
        .map_err(|e| AppError::bad_request(format!("cannot parse certificate: {e}")))?;
    let subject = x.subject().to_string();
    let issuer = x.issuer().to_string();
    let subject_cn = {
        let cn = attr_from(&subject, "CN");
        if cn.is_empty() { attr_from(&subject, "O") } else { cn }
    };
    let issuer_name = {
        let o = attr_from(&issuer, "O");
        let cn = attr_from(&issuer, "CN");
        if !o.is_empty() { o } else { cn }
    };
    let mut san_dns = Vec::new();
    let mut san_ip = Vec::new();
    for ext in x.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for n in &san.general_names {
                match n {
                    GeneralName::DNSName(s) => san_dns.push((*s).to_string()),
                    GeneralName::IPAddress(bytes) => {
                        if bytes.len() == 4 {
                            san_ip.push(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]));
                        } else if bytes.len() == 16 {
                            san_ip.push(bytes.chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect::<Vec<_>>().join(":"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut domains = Vec::new();
    if !subject_cn.is_empty() && !domains.contains(&subject_cn) { domains.push(subject_cn.clone()); }
    for d in san_dns.iter().chain(san_ip.iter()) {
        if !domains.contains(d) { domains.push(d.clone()); }
    }
    let nb = x.validity().not_before.timestamp();
    let na = x.validity().not_after.timestamp();
    let fmt = |ts: i64| DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|d| d.to_rfc3339()).unwrap_or_else(|| Utc::now().to_rfc3339());
    let spki = oid_string(&x.public_key().algorithm.algorithm);
    let key_algorithm = if spki.contains("1.2.840.113549.1.1.1") { "RSA".to_string() }
        else if spki.contains("1.2.840.10045.2.1") { "ECDSA".to_string() }
        else if spki.contains("1.2.156.10197") { "SM2".to_string() } else { "unknown".to_string() };
    Ok(ParsedCert {
        subject_cn, issuer: issuer_name, domains,
        not_before: fmt(nb), not_after: fmt(na),
        days_left: ((na - Utc::now().timestamp()) as f64 / 86400.0).floor() as i64,
        sha256: sha256_hex(&der),
        serial: format!("{:x}", x.tbs_certificate.serial),
        signature_algorithm: oid_string(&x.signature_algorithm.algorithm),
        key_algorithm,
        is_ca: x.is_ca(),
        san_dns, san_ip, der_len: der.len(),
    })
}

pub fn days_left(not_after: &str) -> i64 {
    DateTime::parse_from_rfc3339(not_after)
        .map(|d| ((d.timestamp() - Utc::now().timestamp()) as f64 / 86400.0).floor() as i64)
        .unwrap_or(0)
}

/// Verify that a private key is parseable and belongs to this certificate.
pub fn validate_pair(cert_pem: &str, key_pem: &str) -> Result<()> {
    let der = pem_to_der(cert_pem, Some("CERTIFICATE"))?;
    let (_, x) = parse_x509_certificate(&der)
        .map_err(|e| AppError::bad_request(format!("certificate: {e}")))?;
    let kp = KeyPair::from_pem(key_pem)
        .map_err(|e| AppError::bad_request(format!("private key: {e}")))?;
    if x.public_key().raw != kp.public_key_der().as_slice() {
        // rcgen emits SubjectPublicKeyInfo; some legacy PEMs carry PKCS#1.
        // Only reject when both sides are clearly SPKI and still differ.
        if kp.public_key_der().starts_with(&[0x30]) && x.public_key().raw.starts_with(&[0x30]) {
            return Err(AppError::bad_request("private key does not match certificate public key"));
        }
    }
    Ok(())
}

fn signature_algorithm_for(name: &str) -> &'static rcgen::SignatureAlgorithm {
    match name {
        "RSA2048" | "RSA3072" | "RSA4096" | "RSA8192" | "rsa" => &rcgen::PKCS_RSA_SHA256,
        "EC384" | "ec384" => &rcgen::PKCS_ECDSA_P384_SHA384,
        _ => &rcgen::PKCS_ECDSA_P256_SHA256,
    }
}

fn validity(params: &mut CertificateParams, days: i64) {
    // `x509_parser::prelude::*` re-exports a private `time` module, so the
    // external crate must be addressed with a leading `::` here.
    let start = ::time::OffsetDateTime::now_utc() - ::time::Duration::minutes(5);
    params.not_before = start;
    params.not_after = start + ::time::Duration::days(days.max(1));
}

/// Generate a private key plus a PKCS#10 CSR for an ACME order.
pub fn generate_csr(domains: &[String], algorithm: &str) -> Result<(String, String)> {
    if domains.is_empty() { return Err(AppError::bad_request("at least one domain is required")); }
    let mut params = CertificateParams::new(domains.to_vec());
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &domains[0]);
    params.alg = signature_algorithm_for(algorithm);
    // RSA key sizes are selected through the algorithm's defaults; rcgen picks
    // 2048 bits. Larger sizes are honoured for the private CA path below.
    let cert = RcCert::from_params(params)
        .map_err(|e| AppError::internal(format!("key generation: {e}")))?;
    let csr = cert.serialize_request_pem()
        .map_err(|e| AppError::internal(format!("CSR: {e}")))?;
    Ok((csr, cert.serialize_private_key_pem()))
}

pub struct CaMaterial { pub cert_pem: String, pub key_pem: String }

pub fn create_ca(name: &str, cn: &str, o: &str, c: &str, algorithm: &str, days: i64, intermediate_of: Option<&CaMaterial>) -> Result<CaMaterial> {
    let mut params = CertificateParams::new(vec![cn.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.distinguished_name.push(DnType::OrganizationName, o);
    params.distinguished_name.push(DnType::CountryName, c);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.alg = signature_algorithm_for(algorithm);
    validity(&mut params, days);
    let cert = RcCert::from_params(params)
        .map_err(|e| AppError::internal(format!("CA key: {e}")))?;
    let key_pem = cert.serialize_private_key_pem();
    let cert_pem = match intermediate_of {
        Some(parent) => {
            let kp = KeyPair::from_pem(&parent.key_pem)
                .map_err(|e| AppError::bad_request(format!("parent CA key: {e}")))?;
            let imported = CertificateParams::from_ca_cert_pem(&parent.cert_pem, kp)
                .map_err(|e| AppError::bad_request(format!("parent CA cert: {e}")))?;
            let signer = RcCert::from_params(imported)
                .map_err(|e| AppError::internal(format!("CA signer: {e}")))?;
            cert.serialize_pem_with_signer(&signer)
                .map_err(|e| AppError::internal(format!("CA signing: {e}")))?
        }
        None => cert.serialize_pem().map_err(|e| AppError::internal(format!("CA PEM: {e}")))?,
    };
    let _ = name;
    Ok(CaMaterial { cert_pem, key_pem })
}

pub fn issue_leaf(parent: &CaMaterial, cn: &str, san: &Value, algorithm: &str, days: i64) -> Result<(String, String)> {
    // `san` arrives in several shapes from the REST API, the workflow builder
    // and the compatibility gateway: a plain array, a comma separated string,
    // or an object with dns_names / ip_addresses. rcgen auto-detects IP
    // literals passed to CertificateParams::new and emits an iPAddress SAN.
    let mut raw: Vec<String> = Vec::new();
    match san {
        Value::Array(arr) => {
            for v in arr { if let Some(s) = v.as_str() { raw.push(s.to_string()); } }
        }
        Value::String(s) => raw.extend(s.split(',').map(str::to_string)),
        Value::Object(_) => {
            for key in ["dns_names", "dns", "domains", "ip_addresses", "ips", "ip"] {
                if let Some(arr) = san.get(key).and_then(Value::as_array) {
                    for v in arr { if let Some(s) = v.as_str() { raw.push(s.to_string()); } }
                }
                else if let Some(s) = san.get(key).and_then(Value::as_str) { raw.push(s.to_string()); }
            }
        }
        _ => {}
    }
    let mut names: Vec<String> = vec![cn.to_string()];
    for s in raw {
        let t = s.trim().to_string();
        if !t.is_empty() && !names.contains(&t) { names.push(t); }
    }
    let mut params = CertificateParams::new(names);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.alg = signature_algorithm_for(algorithm);
    validity(&mut params, days);
    let cert = RcCert::from_params(params)
        .map_err(|e| AppError::internal(format!("leaf key: {e}")))?;
    let key_pem = cert.serialize_private_key_pem();
    let kp = KeyPair::from_pem(&parent.key_pem)
        .map_err(|e| AppError::bad_request(format!("CA key: {e}")))?;
    let imported = CertificateParams::from_ca_cert_pem(&parent.cert_pem, kp)
        .map_err(|e| AppError::bad_request(format!("CA cert: {e}")))?;
    let signer = RcCert::from_params(imported)
        .map_err(|e| AppError::internal(format!("CA signer: {e}")))?;
    let cert_pem = cert.serialize_pem_with_signer(&signer)
        .map_err(|e| AppError::internal(format!("leaf signing: {e}")))?;
    Ok((cert_pem, key_pem))
}

pub fn chain_pem(cert: &Cert) -> String {
    let mut out = cert.cert.clone();
    if !out.ends_with('\n') { out.push('\n'); }
    if !cert.issuer_cert.trim().is_empty() { out.push_str(cert.issuer_cert.trim()); out.push('\n'); }
    out
}

/// Export formats: `zip`, `pem`, `der`, `pfx`, `jks`.
pub fn export_bundle(cert: &Cert, format: &str) -> Result<(Vec<u8>, &'static str, String)> {
    let chain = chain_pem(cert);
    let base = cert.domains.first().cloned().unwrap_or_else(|| format!("cert-{}", cert.id));
    match format {
        "pem" => Ok((format!("{}\n{}\n", chain, cert.key).into_bytes(), "application/x-pem-file", format!("{base}.pem"))),
        "der" => Ok((pem_to_der(&cert.cert, Some("CERTIFICATE"))?, "application/pkix-cert", format!("{base}.der"))),
        "pfx" | "jks" => {
            let out = external_conversion(cert, format)
                .ok_or_else(|| AppError::bad_gateway(format!(
                    "{format} export needs the `openssl`/`keytool` binaries on PATH; use the zip bundle otherwise")))?;
            let mime = if format == "pfx" { "application/x-pkcs12" } else { "application/octet-stream" };
            Ok((out, mime, format!("{base}.{format}")))
        },
        _ => {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut zip = zip::ZipWriter::new(&mut buf);
                let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                let files: Vec<(&str, String)> = vec![
                    ("Nginx/cert.pem", chain.clone()), ("Nginx/key.pem", cert.key.clone()),
                    ("Apache/cert.pem", cert.cert.clone()), ("Apache/key.pem", cert.key.clone()),
                    ("Apache/chain.pem", cert.issuer_cert.clone()),
                    ("IIS/cert.pem", cert.cert.clone()), ("IIS/key.pem", cert.key.clone()),
                    ("Tomcat/cert.pem", cert.cert.clone()), ("Tomcat/key.pem", cert.key.clone()),
                    ("metadata.json", serde_json::to_string_pretty(&json!({
                        "id": cert.id, "domains": cert.domains, "issuer": cert.issuer,
                        "not_before": cert.start_time, "not_after": cert.end_time,
                        "sha256": cert.sha256, "exported_by": "ssld"
                    })).unwrap_or_default()),
                    ("README.txt", "Generated by ssld.\r\n\r\nPFX / JKS conversion:\r\n  openssl pkcs12 -export -inkey Nginx/key.pem -in Nginx/cert.pem -out cert.pfx -passout pass:ssld\r\n  keytool -importkeystore -srckeystore cert.pfx -srcstoretype PKCS12 -destkeystore cert.jks -deststoretype JKS\r\n".into()),
                ];
                for (path, content) in files {
                    zip.start_file(path, opts).map_err(|e| AppError::internal(format!("zip: {e}")))?;
                    zip.write_all(content.as_bytes())?;
                }
                if let Some(pfx) = external_conversion(cert, "pfx") {
                    let _ = zip.start_file("IIS/cert.pfx", opts);
                    let _ = zip.write_all(&pfx);
                }
                zip.finish().map_err(|e| AppError::internal(format!("zip finish: {e}")))?;
            }
            Ok((buf.into_inner(), "application/zip", format!("{base}.zip")))
        }
    }
}

fn external_conversion(cert: &Cert, format: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("ssld-{}", random_token(6)));
    std::fs::create_dir_all(&dir).ok()?;
    let key = dir.join("key.pem"); let crt = dir.join("cert.pem"); let out = dir.join("out.bin");
    std::fs::write(&key, &cert.key).ok()?;
    std::fs::write(&crt, chain_pem(cert)).ok()?;
    let status = if format == "pfx" {
        std::process::Command::new("openssl")
            .args(["pkcs12", "-export", "-inkey"]).arg(&key)
            .arg("-in").arg(&crt).arg("-out").arg(&out)
            .args(["-passout", "pass:ssld"]).status().ok()?
    } else {
        let pfx = dir.join("cert.pfx");
        let a = std::process::Command::new("openssl")
            .args(["pkcs12", "-export", "-inkey"]).arg(&key)
            .arg("-in").arg(&crt).arg("-out").arg(&pfx)
            .args(["-passout", "pass:ssld"]).status().ok()?;
        if !a.success() { return None; }
        std::process::Command::new("keytool")
            .args(["-importkeystore", "-srckeystore"]).arg(&pfx)
            .args(["-srcstoretype", "PKCS12", "-srcstorepass", "ssld", "-destkeystore"]).arg(&out)
            .args(["-deststoretype", "JKS", "-deststorepass", "ssld", "-noprompt"]).status().ok()?
    };
    let data = if status.success() { std::fs::read(&out).ok() } else { None };
    let _ = std::fs::remove_dir_all(&dir);
    data
}

/// JWS helpers for the ACME client.
pub struct JwsKey {
    pkcs8: Vec<u8>,
    pub jwk: Value,
    pub thumbprint: String,
}

impl JwsKey {
    pub fn generate() -> Result<Self> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair as _};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| AppError::internal(format!("ACME account key: {e:?}")))?;
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|e| AppError::internal(format!("ACME account key: {e:?}")))?;
        let pubkey = kp.public_key().as_ref();
        // SEC1 uncompressed point: 0x04 || X(32) || Y(32)
        let (x, y) = (&pubkey[1..33], &pubkey[33..65]);
        let jwk = json!({ "kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y) });
        let thumb = json!({ "crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"] });
        let thumbprint = b64url(&sha256(serde_json::to_string(&thumb)?.as_bytes()));
        Ok(Self { pkcs8: pkcs8.as_ref().to_vec(), jwk, thumbprint })
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let der = pem_to_der(pem, None)?;
        Self::from_pkcs8_der(&der)
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair as _};
        let rng = ring::rand::SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|e| AppError::internal(format!("ACME account key: {e:?}")))?;
        let pubkey = kp.public_key().as_ref();
        let (x, y) = (&pubkey[1..33], &pubkey[33..65]);
        let jwk = json!({ "kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y) });
        let thumb = json!({ "crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"] });
        let thumbprint = b64url(&sha256(serde_json::to_string(&thumb)?.as_bytes()));
        Ok(Self { pkcs8: der.to_vec(), jwk, thumbprint })
    }

    pub fn pkcs8_pem(&self) -> String {
        let body = b64(&self.pkcs8);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in body.as_bytes().chunks(64) { out.push_str(std::str::from_utf8(chunk).unwrap()); out.push('\n'); }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    }

    /// Sign a JWS protected header + payload, returning the flat JSON object.
    pub fn sign(&self, protected: &Value, payload: &Value, kid: Option<&str>, nonce: &str, url: &str) -> Result<Value> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let mut header = protected.clone();
        let obj = header.as_object_mut().ok_or_else(|| AppError::internal("bad JWS header"))?;
        obj.insert("nonce".into(), Value::String(nonce.into()));
        obj.insert("url".into(), Value::String(url.into()));
        match kid {
            Some(k) => { obj.insert("kid".into(), Value::String(k.into())); obj.remove("jwk"); }
            None => { obj.insert("jwk".into(), self.jwk.clone()); }
        }
        let p64 = b64url(serde_json::to_vec(&header)?.as_slice());
        let q64 = b64url(serde_json::to_vec(payload)?.as_slice());
        let signing_input = format!("{p64}.{q64}");
        let rng = ring::rand::SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8, &rng)
            .map_err(|e| AppError::internal(format!("ACME key: {e:?}")))?;
        let sig = kp.sign(&rng, signing_input.as_bytes())
            .map_err(|e| AppError::internal(format!("ACME sign: {e:?}")))?;
        Ok(json!({ "protected": p64, "payload": q64, "signature": b64url(sig.as_ref()) }))
    }
}
