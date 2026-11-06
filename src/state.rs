use crate::config::Config;
use crate::error::Result;
use crate::events::{record, EventBus};
use crate::models::{now, uid, OpLog};
use crate::store::{trim, Store};
use serde_json::Value;
use std::sync::Arc;

pub type Shared = Arc<Core>;

pub struct Core {
    pub store: Arc<Store>,
    pub config: Config,
    pub bus: EventBus,
    pub http: reqwest::Client,
    pub started_at: String,
}

impl Core {
    pub fn new(config: Config) -> Result<Shared> {
        let store = Store::open(&config)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(&config.webhook.user_agent)
            .build()
            .map_err(|e| crate::error::AppError::internal(format!("http client: {e}")))?;
        Ok(Arc::new(Core {
            store, config, bus: EventBus::new(), http, started_at: now(),
        }))
    }

    /// One method is the single funnel for every event in the system: it writes
    /// the audit log, notifies live SSE subscribers and schedules webhook
    /// deliveries (which are filtered, signed and retried by `webhook.rs`).
    pub async fn emit(self: &Arc<Self>, event: &str, source: &str, payload: Value) -> crate::models::EventRecord {
        let rec = record(event, source, payload);
        let cap = self.config.storage.max_event_log;
        let _ = self.store.mutate(|db| {
            db.event_log.push(rec.clone());
            trim(&mut db.event_log, cap);
        });
        self.bus.publish(&rec);
        crate::webhook::spawn_dispatch(Arc::clone(self), rec.clone());
        rec
    }

    pub fn oplog(&self, actor: &str, action: &str, target: &str, detail: Value) {
        let entry = OpLog {
            id: uid(), actor: actor.into(), action: action.into(),
            target: target.into(), detail, created_at: now(),
        };
        let _ = self.store.mutate(|db| {
            db.oplogs.push(entry);
            trim(&mut db.oplogs, 2000);
        });
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        self.store.snapshot().settings.get(key).cloned()
    }
}
