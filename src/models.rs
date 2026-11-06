//! Data model: the full persistence schema, plus the event / webhook /
//! MCP additions that ssld introduces. Everything is serde-serialisable so the
//! whole state can be snapshotted to disk without an ORM.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn now() -> String { chrono::Utc::now().to_rfc3339() }
pub fn uid() -> String { uuid::Uuid::new_v4().to_string() }

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub salt: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub token: String,
    pub username: String,
    pub created_at: String,
    pub last_seen: String,
    pub secure: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessType {
    pub id: i64,
    pub provider: String,
    pub kind: String, // dns | host
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Access {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub config: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessInput {
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub config: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Cert {
    pub id: i64,
    pub source: String,       // workflow | upload | private_ca | acme
    pub sha256: String,
    pub history_id: String,
    pub key: String,
    pub cert: String,
    pub issuer_cert: String,
    pub domains: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub issuer: String,
    pub start_time: String,
    pub end_time: String,
    pub end_day: i64,
    pub workflow_id: i64,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub serial: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CertInput {
    pub cert: String,
    pub key: String,
    pub issuer_cert: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportChannel {
    pub id: i64,
    pub name: String,
    pub kind: String, // mail | webhook | dingtalk | feishu | workwx
    pub config: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub name: String,
    pub config: Value,
    pub inputs: Vec<NodeInput>,
    pub child_node: Option<Box<WorkflowNode>>,
    pub condition_nodes: Vec<WorkflowNode>,
    pub validated: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeInput {
    pub name: String,
    pub from_node_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecTime {
    #[serde(rename = "type")]
    pub period: String, // day | week | month
    pub month: i64,
    pub week: i64,
    pub hour: i64,
    pub minute: i64,
}
impl Default for ExecTime {
    fn default() -> Self { Self { period: "day".into(), month: 1, week: 1, hour: 3, minute: 0 } }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Workflow {
    pub id: i64,
    pub name: String,
    pub content: Value,
    pub cron: String,
    pub created_at: String,
    pub updated_at: String,
    pub active: bool,
    pub exec_type: String, // auto | manual
    pub exec_time: ExecTime,
    pub last_run_status: String,
    pub last_run_time: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowInput {
    pub name: String,
    pub content: Value,
    pub active: bool,
    pub exec_type: String,
    pub exec_time: Option<ExecTime>,
    pub cron: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowHistory {
    pub id: String,
    pub workflow_id: i64,
    pub workflow_name: String,
    pub status: String, // running | success | fail | partial
    pub exec_type: String,
    pub created_at: String,
    pub end_time: String,
    pub nodes: Vec<NodeRun>,
    pub logs: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeRun {
    pub node_id: String,
    pub node_type: String,
    pub name: String,
    pub status: String,
    pub message: String,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowDeploy {
    pub workflow_id: i64,
    pub node_id: String,
    pub cert_hash: String,
    pub status: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeAccount {
    pub id: i64,
    pub email: String,
    pub ca: String,
    pub private_key: String,
    pub registration: Value,
    pub kid: String,
    pub hmac_encoded: String,
    pub cadirurl: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Eab {
    pub id: i64,
    pub name: String,
    pub kid: String,
    pub hmac_encoded: String,
    pub ca: String,
    pub mail: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Monitor {
    pub id: i64,
    pub name: String,
    pub target: String,
    pub monitor_type: String, // https | smtp
    pub report_types: Vec<String>,
    pub active: bool,
    pub info: Value,
    pub last_time: String,
    pub except_end_time: String,
    pub updated_at: String,
    pub created_at: String,
    pub cycle: i64,
    pub repeat_send_gap: i64,
    pub advance_day: i64,
    pub valid: i64,
    pub error_streak: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorInput {
    pub name: String,
    pub target: String,
    pub monitor_type: String,
    pub report_types: Vec<String>,
    pub active: bool,
    pub cycle: i64,
    pub repeat_send_gap: i64,
    pub advance_day: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrRecord {
    pub id: String,
    pub monitor_id: i64,
    pub created_at: String,
    pub info: Value,
    pub msg: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CaRecord {
    pub id: i64,
    pub root_id: i64,
    pub name: String,
    pub cn: String,
    pub o: String,
    pub c: String,
    pub cert: String,
    pub key: String,
    pub en_cert: String,
    pub en_key: String,
    pub algorithm: String,
    pub key_length: i64,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LeafRecord {
    pub id: i64,
    pub ca_id: i64,
    pub cn: String,
    pub san: Value,
    pub usage: i64,
    pub cert: String,
    pub key: String,
    pub en_cert: String,
    pub en_key: String,
    pub algorithm: String,
    pub key_length: i64,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CaConfig {
    pub name: String,
    pub cn: String,
    pub o: String,
    pub c: String,
    pub algorithm: String,
    pub key_length: i64,
    pub valid_days: i64,
    pub root_id: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LeafConfig {
    pub ca_id: i64,
    pub cn: String,
    pub san: Value,
    pub usage: i64,
    pub key_length: i64,
    pub valid_days: i64,
    pub algorithm: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    /// Empty events means "all events". Prefix wildcards allowed: `cert.*`.
    pub event_mode: String, // include | exclude
    pub secret: String,
    pub method: String,
    pub headers: Value,
    /// Template body. `__event__`, `__payload__`, `__timestamp__` and any
    /// top level payload key are substituted before sending.
    pub body_template: String,
    pub active: bool,
    pub max_attempts: u32,
    pub backoff_seconds: u64,
    pub timeout_seconds: u64,
    pub skip_tls_verify: bool,
    pub content_type: String,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookInput {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub event_mode: String,
    pub secret: String,
    pub method: String,
    pub headers: Value,
    pub body_template: String,
    pub active: bool,
    pub max_attempts: u32,
    pub backoff_seconds: u64,
    pub timeout_seconds: u64,
    pub skip_tls_verify: bool,
    pub content_type: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookDelivery {
    pub id: String,
    pub subscription_id: String,
    pub subscription_name: String,
    pub event: String,
    pub payload: Value,
    pub request_body: String,
    pub status_code: i64,
    pub success: bool,
    pub attempts: u32,
    pub next_retry: String,
    pub error: String,
    pub duration_ms: u64,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventRecord {
    pub id: String,
    pub event: String,
    pub source: String,
    pub payload: Value,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginRecord {
    pub id: String,
    pub name: String,
    pub version: String,
    pub protocol: i64,
    pub backend: String,
    pub permissions: Vec<String>,
    pub hooks: Value,
    pub frontend: Value,
    pub actions: Value,
    pub config_schema: Value,
    pub enabled: bool,
    pub status: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpLog {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: Value,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobStatus {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub message: String,
    pub started_at: String,
    pub finished_at: String,
    pub result: Value,
}
