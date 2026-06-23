use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;

/// 证书申请进度
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertProgress {
    pub domain: String,
    pub status: String,    // "pending" | "requesting" | "challenge" | "verifying" | "done" | "failed"
    pub message: String,
    pub success: bool,
    pub done: bool,        // 是否已完成
    pub step: u8,          // 当前步骤
    pub total_steps: u8,   // 总步骤数
    pub step_name: String, // 步骤名称
    pub detail: String,    // 详细信息
    pub error: Option<String>, // 错误信息
}

/// CAPTCHA 题目条目（自注册时下发）
#[derive(Debug, Clone)]
pub struct CaptchaEntry {
    pub answer: u32,
    pub expires_at: Instant,
}

/// 注册/登录失败计数（基于 IP 滑动窗口，内存存储）
#[derive(Debug, Clone, Default)]
pub struct AttemptCounter {
    pub register_attempts: Vec<Instant>,
    pub register_successes: Vec<Instant>,
    pub login_attempts: Vec<Instant>,
    pub last_block_until: Option<Instant>,
}

pub struct AppState {
    pub pool: PgPool,
    pub logs_pool: PgPool,
    pub jwt_secret: String,
    pub system_log_min_level: Arc<RwLock<String>>,
    pub cert_progress: Arc<RwLock<HashMap<String, CertProgress>>>,
    /// CAPTCHA 临时存储：captcha_id -> 答案 + 过期时间
    pub captcha_store: Arc<RwLock<HashMap<String, CaptchaEntry>>>,
    /// 注册/登录暴力破解防护：IP -> 滑动窗口
    pub attempt_counter: Arc<RwLock<HashMap<IpAddr, AttemptCounter>>>,
}

impl AppState {
    pub async fn new(pool: PgPool, logs_pool: PgPool, jwt_secret: String) -> Self {
        Self {
            pool,
            logs_pool,
            jwt_secret,
            system_log_min_level: Arc::new(RwLock::new("INFO".to_string())),
            cert_progress: Arc::new(RwLock::new(HashMap::new())),
            captcha_store: Arc::new(RwLock::new(HashMap::new())),
            attempt_counter: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
