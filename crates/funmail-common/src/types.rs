use serde::{Deserialize, Serialize};

/// 邮件队列状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueueStatus {
    Pending,
    Delivering,
    Deferred,
    Bounced,
    Delivered,
}

impl std::fmt::Display for QueueStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueStatus::Pending => write!(f, "pending"),
            QueueStatus::Delivering => write!(f, "delivering"),
            QueueStatus::Deferred => write!(f, "deferred"),
            QueueStatus::Bounced => write!(f, "bounced"),
            QueueStatus::Delivered => write!(f, "delivered"),
        }
    }
}

/// 邮件方向
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MailDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for MailDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailDirection::Inbound => write!(f, "inbound"),
            MailDirection::Outbound => write!(f, "outbound"),
        }
    }
}

/// 域名记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: i32,
    pub name: String,
    pub enabled: bool,
    pub dkim_selector: String,
    pub dkim_private_key: Option<String>,
    pub dkim_public_key: Option<String>,
    pub mx_verified: bool,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub cert_id: Option<i32>,
    pub default_quota_mb: i32,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 邮箱账号
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: i32,
    pub domain_id: i32,
    pub username: String,
    pub password_hash: String,
    pub quota_mb: i32,
    pub used_bytes: i64,
    pub enabled: bool,
    pub aliases: serde_json::Value,
    pub forward_to: serde_json::Value,
    pub keep_copy: bool,
    pub is_admin: bool,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_ip: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Mailbox {
    /// 获取完整邮箱地址
    pub fn full_address(&self, domain_name: &str) -> String {
        format!("{}@{}", self.username, domain_name)
    }
}

/// 邮件队列条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailQueueEntry {
    pub id: i64,
    pub from_addr: String,
    pub to_addr: String,
    pub data_path: String,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub status: String,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    pub direction: String,
    pub priority: i32,
    pub size_bytes: i64,
    pub spam_score: f32,
    pub virus_scanned: bool,
    pub dkim_valid: Option<bool>,
    pub spf_valid: Option<bool>,
    pub dmarc_valid: Option<bool>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 证书记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cert {
    pub id: i32,
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub auto_renew: bool,
    pub acme_order_url: Option<String>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 邮件日志
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailLog {
    pub id: i64,
    pub domain_id: Option<i32>,
    pub from_addr: String,
    pub to_addr: String,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub direction: String,
    pub status: String,
    pub size_bytes: i64,
    pub latency_ms: i32,
    pub spam_score: f32,
    pub dkim_valid: Option<bool>,
    pub spf_valid: Option<bool>,
    pub dmarc_valid: Option<bool>,
    pub client_ip: Option<String>,
    pub client_hostname: Option<String>,
    pub reject_reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 仪表盘统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardStats {
    pub total_inbound: i64,
    pub total_outbound: i64,
    pub total_blocked: i64,
    pub total_spam: i64,
    pub total_bounced: i64,
    pub active_domains: i32,
    pub active_mailboxes: i32,
    pub queue_pending: i64,
    pub queue_deferred: i64,
    pub avg_latency_ms: f64,
}

/// SMTP 认证结果
#[derive(Debug, Clone)]
pub struct SmtpAuthResult {
    pub mailbox_id: i32,
    pub username: String,
    pub domain: String,
}
