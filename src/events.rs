use crate::models::{now, uid, EventRecord};
use serde_json::Value;
use tokio::sync::broadcast;

/// In-process fan-out used by the live event stream (`GET /api/v1/events/stream`).
#[derive(Clone)]
pub struct EventBus {
    pub tx: broadcast::Sender<EventRecord>,
}

impl Default for EventBus {
    fn default() -> Self { Self::new() }
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(512);
        Self { tx }
    }
    pub fn subscribe(&self) -> broadcast::Receiver<EventRecord> { self.tx.subscribe() }
    pub fn publish(&self, record: &EventRecord) { let _ = self.tx.send(record.clone()); }
}

pub fn record(event: &str, source: &str, payload: Value) -> EventRecord {
    EventRecord {
        id: uid(), event: event.to_string(), source: source.to_string(),
        payload, created_at: now(),
    }
}
