use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    /// Legacy "secure entry" path. `/` or `/login` disables it.
    pub secure_entry: String,
    pub https: bool,
    pub tls_cert: String,
    pub tls_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    /// Static key for the open API signature scheme. Empty disables it.
    pub api_key: String,
    pub session_timeout: i64,
    pub login_lock_threshold: i64,
    pub login_lock_minutes: i64,
    /// When false (local default) the console works out of the box. Set
    /// `SSLD_AUTH_REQUIRED=1` or configure an api_key to lock it down.
    pub require_auth: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeConfig {
    pub default_ca: String,
    pub default_algorithm: String,
    pub renew_before_days: i64,
    pub dns_propagation_wait: u64,
    pub nameservers: Vec<String>,
    pub ari_enabled: bool,
    pub contact_email: String,
    pub skip_dns_check: bool,
    pub disable_cname: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerConfig {
    pub enabled: bool,
    pub tick_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub timeout_seconds: u64,
    pub max_attempts: u32,
    pub backoff_seconds: u64,
    pub signature_header: String,
    pub user_agent: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    pub enabled: bool,
    pub path: String,
    pub require_auth: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub data_dir: String,
    pub workflow_log_dir: String,
    pub max_event_log: usize,
    pub max_delivery_log: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub acme: AcmeConfig,
    pub scheduler: SchedulerConfig,
    pub webhook: WebhookConfig,
    pub mcp: McpConfig,
    pub storage: StorageConfig,
    pub config_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(), port: 7979, secure_entry: "/".into(),
            https: false, tls_cert: String::new(), tls_key: String::new(),
        }
    }
}
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            username: "admin".into(), password: "ssld".into(), api_key: String::new(),
            session_timeout: 86400, login_lock_threshold: 5, login_lock_minutes: 15,
            require_auth: false,
        }
    }
}
impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            default_ca: "letsencrypt".into(), default_algorithm: "RSA2048".into(),
            renew_before_days: 30, dns_propagation_wait: 120,
            nameservers: vec!["8.8.8.8:53".into(), "1.1.1.1:53".into()],
            ari_enabled: true, contact_email: String::new(),
            skip_dns_check: false, disable_cname: false,
        }
    }
}
impl Default for SchedulerConfig {
    fn default() -> Self { Self { enabled: true, tick_seconds: 10 } }
}
impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true, timeout_seconds: 10, max_attempts: 5, backoff_seconds: 60,
            signature_header: "X-SSLD-Signature".into(), user_agent: "ssld/1.0".into(),
        }
    }
}
impl Default for McpConfig {
    fn default() -> Self { Self { enabled: true, path: "/mcp".into(), require_auth: false } }
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: "data".into(), workflow_log_dir: "data/workflow-logs".into(),
            max_event_log: 1000, max_delivery_log: 1000,
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            server: Default::default(), auth: Default::default(), acme: Default::default(),
            scheduler: Default::default(), webhook: Default::default(), mcp: Default::default(),
            storage: Default::default(), config_path: "config/ssld.json".into(),
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

impl Config {
    /// JSON file config + environment overrides. Every knob is also reachable at
    /// runtime via `PUT /api/v1/settings`, so no CLI control surface is needed.
    pub fn load() -> Result<Self> {
        let path = env("SSLD_CONFIG").unwrap_or_else(|| "config/ssld.json".into());
        let mut cfg: Config = if PathBuf::from(&path).exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw).map_err(|e| AppError::bad_request(format!("config: {e}")))?
        } else {
            Config::default()
        };
        cfg.config_path = path;

        if let Some(v) = env("SSLD_BIND") { cfg.server.bind = v; }
        if let Some(v) = env("SSLD_PORT").and_then(|v| v.parse().ok()) { cfg.server.port = v; }
        if let Some(v) = env("SSLD_SECURE_ENTRY") { cfg.server.secure_entry = v; }
        if let Some(v) = env("SSLD_ADMIN_USER") { cfg.auth.username = v; }
        if let Some(v) = env("SSLD_ADMIN_PASSWORD") { cfg.auth.password = v; }
        if let Some(v) = env("SSLD_API_KEY") { cfg.auth.api_key = v; cfg.auth.require_auth = true; }
        if env("SSLD_AUTH_REQUIRED").is_some() { cfg.auth.require_auth = true; }
        if let Some(v) = env("SSLD_DATA_DIR") { cfg.storage.data_dir = v; }
        if let Some(v) = env("SSLD_WEBHOOK_SECRET") {
            cfg.storage.data_dir = cfg.storage.data_dir.clone();
            // Applied as the default secret for new subscriptions.
            std::env::set_var("SSLD_DEFAULT_WEBHOOK_SECRET", v);
        }
        if let Some(v) = env("SSLD_MCP_PATH") { cfg.mcp.path = v; }
        if let Some(v) = env("SSLD_TICK_SECONDS").and_then(|v| v.parse().ok()) { cfg.scheduler.tick_seconds = v; }
        if env("SSLD_SCHEDULER_OFF").is_some() { cfg.scheduler.enabled = false; }
        if env("SSLD_WEBHOOK_OFF").is_some() { cfg.webhook.enabled = false; }
        if env("SSLD_HTTPS").is_some() { cfg.server.https = true; }
        Ok(cfg)
    }

    pub fn default_webhook_secret(&self) -> String {
        env("SSLD_DEFAULT_WEBHOOK_SECRET").unwrap_or_default()
    }

    pub fn address(&self) -> String { format!("{}:{}", self.server.bind, self.server.port) }

    pub fn data_path(&self, name: &str) -> PathBuf {
        PathBuf::from(&self.storage.data_dir).join(name)
    }
}
