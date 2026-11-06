//! Capability registry. Every provider, target, event, algorithm and node type
//! that ssld supports is declared here as data, so the API, the UI, the MCP
//! tools and the adapters all read from one source of truth.
use serde_json::{json, Value};

pub type Spec = (&'static str, &'static str, &'static str);

/// (identifier, display name, credential / config fields)
pub const DNS_PROVIDERS: &[Spec] = &[
    ("aliyun", "Alibaba Cloud DNS", "access_key_id,access_key_secret"),
    ("tencentcloud", "Tencent Cloud DNSPod", "secret_id,secret_key"),
    ("rainyun", "RainYun DNS", "api_key"),
    ("cloudflare", "Cloudflare", "email,api_key"),
    ("huaweicloud", "Huawei Cloud DNS", "access_key,secret_key"),
    ("baidu", "Baidu Cloud DNS", "access_key,secret_key"),
    ("westcn", "West.cn", "username,password"),
    ("volcengine", "Volcengine DNS", "access_key,secret_key"),
    ("godaddy", "GoDaddy", "api_key,api_secret"),
    ("namecheap", "Namecheap", "api_user,api_key"),
    ("ns1", "NS1", "api_key"),
    ("cloudns", "ClouDNS", "auth_id,auth_password"),
    ("aws", "AWS Route 53", "access_key_id,secret_access_key,region"),
    ("azure", "Azure DNS", "tenant_id,client_id,client_secret,environment"),
    ("jdcloud", "JD Cloud DNS", "access_key_id,secret_access_key"),
    ("gcore", "Gcore DNS", "api_token"),
    ("bunny", "Bunny DNS", "api_key"),
    ("namedotcom", "Name.com", "username,api_token"),
    ("namesilo", "Namesilo", "api_key"),
    ("constellix", "Constellix", "api_key,secret_key"),
    ("spaceship", "Spaceship", "api_key,api_secret"),
    ("webhook", "Custom webhook DNS", "url,method,headers,data,ignore_ssl"),
    ("btdomain", "BaoTa DNS", "account_id,access_key,secret_key,base_url"),
    ("edgeone", "Tencent EdgeOne DNS", "secret_id,secret_key"),
    ("acmedns", "acme-dns", "server_url,credentials"),
];

/// (identifier, display name, credential fields)
pub const HOST_PROVIDERS: &[Spec] = &[
    ("aliyun", "Alibaba Cloud", "access_key_id,access_key_secret"),
    ("tencentcloud", "Tencent Cloud", "secret_id,secret_key"),
    ("ssh", "SSH / SFTP host", "host,port,user,mode,password,key"),
    ("btpanel", "BaoTa Panel", "url,api_key,ignore_ssl"),
    ("1panel", "1Panel", "url,api_key,version,ignore_ssl"),
    ("cloudflare", "Cloudflare", "email,api_key"),
    ("rainyun", "RainYun", "api_key"),
    ("huaweicloud", "Huawei Cloud", "access_key,secret_key"),
    ("baidu", "Baidu Cloud", "access_key,secret_key"),
    ("btwaf", "BaoTa WAF", "url,api_key,ignore_ssl"),
    ("doge", "Doge Cloud", "access_key,secret_key"),
    ("plugin", "Deploy plugin", "name,mode,config"),
    ("safeline", "SafeLine WAF", "url,api_token,ignore_ssl"),
    ("qiniu", "Qiniu", "access_key,secret_key"),
    ("volcengine", "Volcengine", "access_key,secret_key"),
    ("lecdn", "LeCDN", "url,api_token"),
    ("webhook", "Custom webhook", "url,method,headers,data,ignore_ssl"),
    ("localhost", "Local filesystem", ""),
];

/// (deploy target, display name, credential family)
pub const DEPLOY_TARGETS: &[Spec] = &[
    ("btpanel", "BaoTa panel certificate", "btpanel"),
    ("btpanel-site", "BaoTa site", "btpanel"),
    ("btpanel-dockersite", "BaoTa docker site", "btpanel"),
    ("btpanel-singlesite", "BaoTa single site", "btpanel"),
    ("btwaf-site", "BaoTa WAF site", "btwaf"),
    ("1panel", "1Panel certificate", "1panel"),
    ("1panel-site", "1Panel website", "1panel"),
    ("tencentcloud-cdn", "Tencent Cloud CDN", "tencentcloud"),
    ("tencentcloud-cos", "Tencent Cloud COS", "tencentcloud"),
    ("tencentcloud-waf", "Tencent Cloud WAF", "tencentcloud"),
    ("tencentcloud-teo", "Tencent EdgeOne", "tencentcloud"),
    ("aliyun-cdn", "Alibaba Cloud CDN", "aliyun"),
    ("aliyun-oss", "Alibaba Cloud OSS", "aliyun"),
    ("aliyun-waf", "Alibaba Cloud WAF", "aliyun"),
    ("aliyun-esa", "Alibaba Cloud ESA", "aliyun"),
    ("aliyun-dcdn", "Alibaba Cloud DCDN", "aliyun"),
    ("safeline-site", "SafeLine site", "safeline"),
    ("safeline-panel", "SafeLine panel", "safeline"),
    ("safeline-portal", "SafeLine portal", "safeline"),
    ("qiniu-cdn", "Qiniu CDN", "qiniu"),
    ("qiniu-oss", "Qiniu OSS", "qiniu"),
    ("baidu-cdn", "Baidu Cloud CDN", "baidu"),
    ("huaweicloud-cdn", "Huawei Cloud CDN", "huaweicloud"),
    ("volcengine-cdn", "Volcengine CDN", "volcengine"),
    ("volcengine-dcdn", "Volcengine DCDN", "volcengine"),
    ("doge-cdn", "Doge Cloud CDN", "doge"),
    ("lecdn", "LeCDN", "lecdn"),
    ("rainyun-sslcenter", "RainYun SSL Center", "rainyun"),
    ("ssh", "SSH / SFTP", "ssh"),
    ("localhost", "Local filesystem", "localhost"),
    ("webhook", "Custom webhook", "webhook"),
    ("plugin", "Deploy plugin", "plugin"),
];

/// (CA id, display name, ACME directory URL)
pub const CA_PROVIDERS: &[Spec] = &[
    ("letsencrypt", "Let's Encrypt", "https://acme-v02.api.letsencrypt.org/directory"),
    ("zerossl", "ZeroSSL", "https://acme.zerossl.com/v2/DV90"),
    ("google", "Google Trust Services", "https://dv.acme-v02.api.pki.goog/directory"),
    ("sslcom", "SSL.com RSA", "https://acme.ssl.com/sslcom-dv-rsa"),
    ("sslcom-rsa", "SSL.com RSA", "https://acme.ssl.com/sslcom-dv-rsa"),
    ("sslcom-ecc", "SSL.com ECC", "https://acme.ssl.com/sslcom-dv-ecc"),
    ("buypass", "Buypass Go SSL", "https://api.buypass.com/acme/directory"),
    ("litessl", "LiteSSL", "https://acme.litessl.com/acme/v2/directory"),
    ("custom", "Custom ACME CA", ""),
];

pub const KEY_ALGORITHMS: &[Spec] = &[
    ("RSA2048", "RSA 2048", "rsa"),
    ("RSA3072", "RSA 3072", "rsa"),
    ("RSA4096", "RSA 4096", "rsa"),
    ("RSA8192", "RSA 8192", "rsa"),
    ("EC256", "ECDSA P-256", "ec"),
    ("EC384", "ECDSA P-384", "ec"),
];

/// (channel, display name, config fields)
pub const NOTIFY_CHANNELS: &[Spec] = &[
    ("mail", "SMTP mail", "sender,receiver,password,smtpHost,smtpPort,smtpTLS,enabled"),
    ("webhook", "Generic webhook", "url,data,method,headers,ignore_ssl,enabled"),
    ("dingtalk", "DingTalk", "webhook,secret,enabled"),
    ("feishu", "Feishu / Lark", "webhook,secret,enabled"),
    ("workwx", "WeCom", "url,data,enabled"),
];

/// (node type, category, description)
pub const NODE_TYPES: &[Spec] = &[
    ("start", "structure", "Workflow root, carries schedule"),
    ("end", "structure", "Terminal node"),
    ("default", "structure", "Placeholder node"),
    ("branch", "structure", "Parallel branch container"),
    ("condition", "structure", "Parallel branch child"),
    ("execute_result_branch", "structure", "Success / fail branch"),
    ("execute_result_condition", "structure", "Success / fail condition"),
    ("apply", "business", "ACME certificate application"),
    ("deploy", "business", "Deploy to target platform"),
    ("upload", "business", "Use an imported certificate"),
    ("notify", "business", "Send a notification"),
    ("private_ca", "business", "Issue from a private CA"),
];

pub const WORKFLOW_HOOK_TARGETS: &[&str] = &["apply", "deploy", "upload", "notify", "private_ca"];
pub const SCHEDULER_TASKS: &[&str] = &["monitor", "workflow", "webhook-retry", "ari-renewal", "cleanup"];
pub const MONITOR_TYPES: &[&str] = &["https", "smtp"];
pub const IMPORT_FORMATS: &[&str] = &["csv", "txt", "json", "xlsx"];
pub const EXPORT_FORMATS: &[&str] = &["zip", "pem", "der", "pfx", "jks"];
pub const PLUGIN_STATES: &[&str] = &["disabled", "starting", "running", "stopping", "error", "invalid"];
pub const PARAM_TYPES: &[&str] = &["string", "number", "boolean", "enum"];

/// The event vocabulary. Wildcards such as `cert.*` are accepted by subscriptions.
pub const EVENTS: &[Spec] = &[
    ("cert.issued", "Certificate issued", "ACME order finalised"),
    ("cert.reused", "Existing certificate reused", "Within renew threshold"),
    ("cert.imported", "Certificate imported", "PEM upload"),
    ("cert.deleted", "Certificate deleted", "Bulk delete"),
    ("cert.renewal.started", "Renewal started", "ARI or threshold triggered"),
    ("cert.renewal.succeeded", "Renewal succeeded", "New certificate stored"),
    ("cert.renewal.failed", "Renewal failed", "ACME error"),
    ("cert.deployed", "Certificate deployed", "Target accepted the certificate"),
    ("cert.deploy_failed", "Deployment failed", "Target rejected the certificate"),
    ("cert.expiring", "Certificate expiring", "Days left <= threshold"),
    ("cert.expired", "Certificate expired", "NotAfter in the past"),
    ("cert.invalid", "Certificate invalid", "Chain or hostname verification failed"),
    ("cert.recovered", "Certificate recovered", "Monitor returned to healthy"),
    ("cert.pushed", "Certificate pushed", "Webhook deploy target"),
    ("workflow.started", "Workflow started", "Manual or scheduled"),
    ("workflow.succeeded", "Workflow succeeded", "All nodes succeeded"),
    ("workflow.failed", "Workflow failed", "Fatal node error"),
    ("workflow.partial", "Workflow partial", "Some nodes failed"),
    ("workflow.node_failed", "Workflow node failed", "Node level failure"),
    ("workflow.stopped", "Workflow stopped", "Explicit stop"),
    ("monitor.alert", "Monitor alert", "Anomaly notification"),
    ("monitor.recovered", "Monitor recovered", "Anomaly cleared"),
    ("monitor.check_failed", "Monitor check failed", "Probe error"),
    ("access.created", "Credential created", ""),
    ("access.updated", "Credential updated", ""),
    ("access.deleted", "Credential deleted", ""),
    ("access.test_failed", "Credential test failed", ""),
    ("acme.account_registered", "ACME account registered", ""),
    ("acme.order_failed", "ACME order failed", ""),
    ("acme.ari_replacement", "ARI replacement order", "RFC 9773 replaces field"),
    ("dns.propagated", "DNS-01 propagation checked", "TXT confirmed against nameservers"),
    ("dns.check_unavailable", "DNS resolver unavailable", "Falling back to CA-side validation"),
    ("ca.created", "Private CA created", ""),
    ("ca.deleted", "Private CA deleted", ""),
    ("leaf.issued", "Private leaf issued", ""),
    ("channel.test", "Notification test", ""),
    ("notify.failed", "Notification failed", ""),
    ("webhook.delivery_failed", "Webhook delivery failed", "Exhausted retries"),
    ("webhook.test", "Webhook test", ""),
    ("plugin.enabled", "Plugin enabled", ""),
    ("plugin.disabled", "Plugin disabled", ""),
    ("settings.updated", "Settings updated", ""),
    ("system.started", "ssld started", ""),
    ("system.audit", "Security audit completed", ""),
];

pub fn ca_directory(ca: &str) -> Option<String> {
    CA_PROVIDERS.iter().find(|(id, _, _)| *id == ca).map(|(_, _, url)| url.to_string()).filter(|u| !u.is_empty())
}

pub fn event_exists(name: &str) -> bool { EVENTS.iter().any(|(id, _, _)| *id == name) }

pub fn matches_event(patterns: &[String], event: &str, mode: &str) -> bool {
    if patterns.is_empty() { return mode != "exclude"; }
    let matched = patterns.iter().any(|p| {
        if p == event || p == "*" { return true; }
        if let Some(prefix) = p.strip_suffix(".*") { return event.starts_with(&format!("{prefix}.")); }
        false
    });
    if mode == "exclude" { !matched } else { matched }
}

/// Fields a deploy node needs, derived from the target family.
pub fn deploy_fields(target: &str) -> Vec<&'static str> {
    let mut fields = vec!["provider_id", "skip"];
    let extra: &[&str] = match target {
        "ssh" | "localhost" => &["keyPath", "certPath", "beforeCmd", "afterCmd"],
        "btpanel" | "btpanel-site" | "btpanel-dockersite" | "btpanel-singlesite" | "btwaf-site" => &["siteName"],
        "1panel" | "1panel-site" | "aliyun-esa" => &["site_id"],
        "lecdn" => &["site_id", "domain"],
        "webhook" => &["url", "method", "headers", "data", "ignore_ssl"],
        "plugin" => &["action", "params"],
        "rainyun-sslcenter" => &["cert_id"],
        t if t.contains("-cos") || t.contains("-oss") => &["domain", "region", "bucket"],
        t if t.contains("-waf") => &["domain", "region"],
        _ => &["domain"],
    };
    fields.extend_from_slice(extra);
    fields
}

pub fn catalog() -> Value {
    let list = |items: &[Spec]| -> Value {
        Value::Array(items.iter().map(|(id, name, third)| json!({
            "id": id, "name": name, "detail": third
        })).collect())
    };
    json!({
        "dns_providers": list(DNS_PROVIDERS),
        "host_providers": list(HOST_PROVIDERS),
        "deploy_targets": Value::Array(DEPLOY_TARGETS.iter().map(|(id, name, family)| json!({
            "id": id, "name": name, "credential_family": family,
            "fields": deploy_fields(id)
        })).collect()),
        "certificate_authorities": list(CA_PROVIDERS),
        "key_algorithms": list(KEY_ALGORITHMS),
        "notification_channels": list(NOTIFY_CHANNELS),
        "workflow_node_types": list(NODE_TYPES),
        "events": list(EVENTS),
        "monitor_types": MONITOR_TYPES,
        "import_formats": IMPORT_FORMATS,
        "export_formats": EXPORT_FORMATS,
        "plugin_states": PLUGIN_STATES,
        "plugin_param_types": PARAM_TYPES,
        "scheduler_tasks": SCHEDULER_TASKS,
        "workflow_hook_targets": WORKFLOW_HOOK_TARGETS,
        "counts": {
            "dns_providers": DNS_PROVIDERS.len(),
            "host_providers": HOST_PROVIDERS.len(),
            "deploy_targets": DEPLOY_TARGETS.len(),
            "certificate_authorities": CA_PROVIDERS.len(),
            "events": EVENTS.len(),
            "rest_endpoints": crate::api::ENDPOINT_COUNT,
            "mcp_tools": crate::mcp::TOOL_COUNT
        }
    })
}
