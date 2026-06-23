use serde::{Deserialize, Serialize};

/// 全局服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// SMTP 配置
    pub smtp: SmtpConfig,
    /// POP3 配置
    pub pop3: Pop3Config,
    /// IMAP 配置
    pub imap: ImapConfig,
    /// 投递引擎配置
    pub delivery: DeliveryConfig,
    /// 管理后台配置
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    /// SMTPS 端口 (465)
    pub smtps_port: u16,
    /// Submission 端口 (587)
    pub submission_port: u16,
    /// 最大邮件大小 (字节)
    pub max_message_size: u64,
    /// 最大收件人数
    pub max_recipients: usize,
    /// 是否要求认证才能发信
    pub require_auth_for_outbound: bool,
    /// 是否启用 STARTTLS
    pub starttls_enabled: bool,
    /// SMTP 问候语
    pub hostname: String,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 25,
            smtps_port: 465,
            submission_port: 587,
            max_message_size: 50 * 1024 * 1024, // 50MB
            max_recipients: 100,
            require_auth_for_outbound: true,
            starttls_enabled: true,
            hostname: "mail.example.com".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop3Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub pop3s_port: u16,
    pub starttls_enabled: bool,
}

impl Default for Pop3Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 110,
            pop3s_port: 995,
            starttls_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub imaps_port: u16,
    pub starttls_enabled: bool,
    pub max_connections: usize,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 143,
            imaps_port: 993,
            starttls_enabled: true,
            max_connections: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryConfig {
    /// 最大重试次数
    pub max_retries: u32,
    /// 重试间隔（秒）：指数退避基础值
    pub retry_base_interval_secs: u64,
    /// 最大重试间隔（秒）
    pub retry_max_interval_secs: u64,
    /// 邮件存储目录
    pub maildir_base: String,
    /// 投递工作线程数
    pub worker_count: usize,
    /// 扫描队列间隔（毫秒）
    pub queue_scan_interval_ms: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            retry_base_interval_secs: 300,   // 5分钟
            retry_max_interval_secs: 86400,  // 24小时
            maildir_base: "/var/lib/funmail/maildir".to_string(),
            worker_count: 4,
            queue_scan_interval_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub static_dir: String,
    pub admin_user: String,
    pub admin_password: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 10002,
            static_dir: "../frontend/dist".to_string(),
            admin_user: "admin".to_string(),
            admin_password: "funmail2026".to_string(),
        }
    }
}
