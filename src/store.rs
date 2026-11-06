//! Zero-dependency durable state. A single JSON snapshot is written atomically
//! after every mutation; the working set lives behind one RwLock. No native
//! libraries, no C toolchain, no external database server.
use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    pub version: u32,
    pub settings: BTreeMap<String, String>,
    pub users: Vec<User>,
    pub sessions: Vec<Session>,
    pub access_types: Vec<AccessType>,
    pub accesses: Vec<Access>,
    pub certs: Vec<Cert>,
    pub channels: Vec<ReportChannel>,
    pub workflows: Vec<Workflow>,
    pub histories: Vec<WorkflowHistory>,
    pub workflow_deploys: Vec<WorkflowDeploy>,
    pub acme_accounts: Vec<AcmeAccount>,
    pub eabs: Vec<Eab>,
    pub monitors: Vec<Monitor>,
    pub err_records: Vec<ErrRecord>,
    pub cas: Vec<CaRecord>,
    pub leaves: Vec<LeafRecord>,
    pub webhooks: Vec<WebhookSubscription>,
    pub deliveries: Vec<WebhookDelivery>,
    pub event_log: Vec<EventRecord>,
    pub plugins: Vec<PluginRecord>,
    pub oplogs: Vec<OpLog>,
    pub jobs: Vec<JobStatus>,
    pub counters: BTreeMap<String, i64>,
}

impl Database {
    fn initialise(cfg: &Config) -> Self {
        let mut db = Database { version: 1, ..Default::default() };
        let s = &mut db.settings;
        s.insert("log_path".into(), "data/ssld.log".into());
        s.insert("workflow_log_path".into(), cfg.storage.workflow_log_dir.clone());
        s.insert("timeout".into(), cfg.auth.session_timeout.to_string());
        s.insert("https".into(), if cfg.server.https { "1" } else { "0" }.into());
        s.insert("session_key".into(), uid());
        s.insert("secure".into(), cfg.server.secure_entry.clone());
        s.insert("port".into(), cfg.server.port.to_string());
        s.insert("plugin_dir".into(), "plugins".into());
        s.insert("api_key".into(), cfg.auth.api_key.clone());
        s.insert("renew_before_days".into(), cfg.acme.renew_before_days.to_string());
        s.insert("default_ca".into(), cfg.acme.default_ca.clone());
        s.insert("default_algorithm".into(), cfg.acme.default_algorithm.clone());
        s.insert("ari_enabled".into(), if cfg.acme.ari_enabled { "1" } else { "0" }.into());
        s.insert("webhook_enabled".into(), if cfg.webhook.enabled { "1" } else { "0" }.into());
        s.insert("mcp_enabled".into(), if cfg.mcp.enabled { "1" } else { "0" }.into());
        s.insert("theme".into(), "system".into());
        s.insert("language".into(), "en".into());

        db.users.push(User {
            id: 1, username: cfg.auth.username.clone(),
            password_hash: crate::auth::hash_password(&cfg.auth.password, "ssld-static-salt"),
            salt: "ssld-static-salt".into(),
        });

        for (kind, list) in [
            ("dns", crate::providers::DNS_PROVIDERS),
            ("host", crate::providers::HOST_PROVIDERS),
        ] {
            for (provider, _name, _fields) in list {
                db.access_types.push(AccessType {
                    id: db.access_types.len() as i64 + 1,
                    provider: (*provider).into(), kind: kind.into(),
                });
            }
        }
        db
    }
}

pub struct Store {
    inner: RwLock<Database>,
    path: PathBuf,
}

impl Store {
    pub fn open(cfg: &Config) -> Result<Arc<Store>> {
        let dir = PathBuf::from(&cfg.storage.data_dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::create_dir_all(&cfg.storage.workflow_log_dir)?;
        let path = cfg.data_path("state.json");
        let db = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<Database>(&raw) {
                Ok(db) => db,
                Err(e) => {
                    let backup = dir.join(format!("state.corrupt.{}.json", chrono::Utc::now().timestamp()));
                    let _ = std::fs::copy(&path, &backup);
                    tracing::warn!("state file unreadable ({e}), backed up to {backup:?}, starting fresh");
                    Database::initialise(cfg)
                }
            }
        } else {
            Database::initialise(cfg)
        };
        let store = Arc::new(Store { inner: RwLock::new(db), path });
        store.flush()?;
        Ok(store)
    }

    /// Never hold a guard across an await: callers work on a cloned snapshot.
    pub fn snapshot(&self) -> Database {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn mutate<T>(&self, f: impl FnOnce(&mut Database) -> T) -> Result<T> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let out = f(&mut guard);
        self.write_atomic(&guard)?;
        Ok(out)
    }

    pub fn flush(&self) -> Result<()> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        self.write_atomic(&guard)
    }

    fn write_atomic(&self, db: &Database) -> Result<()> {
        let raw = serde_json::to_string_pretty(db)
            .map_err(|e| AppError::internal(format!("serialize state: {e}")))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn path(&self) -> PathBuf { self.path.clone() }
}

pub fn next_id(db: &mut Database, key: &str) -> i64 {
    let entry = db.counters.entry(key.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

pub fn trim<T>(list: &mut Vec<T>, cap: usize) {
    if list.len() > cap {
        let drain = list.len() - cap;
        list.drain(0..drain);
    }
}
