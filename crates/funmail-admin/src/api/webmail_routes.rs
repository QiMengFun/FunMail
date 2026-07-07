use crate::auth;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    middleware::Next,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 32;
const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 128;
const CAPTCHA_TTL: Duration = Duration::from_secs(5 * 60);
const CAPTCHA_MAX_STORED: usize = 50_000;

/// 限流配置：从数据库 settings.webmail_rate_limit 动态读取，失败时使用默认值
#[derive(Debug, Clone)]
struct RateLimitConfig {
    attempt_window: Duration,
    login_max: usize,
    register_max: usize,
    register_success_max: usize,
    block_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            attempt_window: Duration::from_secs(60),
            login_max: 5,
            register_max: 5,
            register_success_max: 1,
            block_duration: Duration::from_secs(30),
        }
    }
}

/// 从数据库读取限流配置
async fn load_rate_limit_config(pool: &sqlx::PgPool) -> RateLimitConfig {
    let row: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'webmail_rate_limit'"
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let cfg = RateLimitConfig::default();
    if let Some(v) = row.as_ref().and_then(|v| v.as_object()) {
        return RateLimitConfig {
            attempt_window: Duration::from_secs(v.get("attempt_window_secs").and_then(|v| v.as_u64()).unwrap_or(cfg.attempt_window.as_secs())),
            login_max: v.get("login_max_per_window").and_then(|v| v.as_u64()).unwrap_or(cfg.login_max as u64) as usize,
            register_max: v.get("register_max_per_window").and_then(|v| v.as_u64()).unwrap_or(cfg.register_max as u64) as usize,
            register_success_max: v.get("register_success_max_per_window").and_then(|v| v.as_u64()).unwrap_or(cfg.register_success_max as u64) as usize,
            block_duration: Duration::from_secs(v.get("block_duration_secs").and_then(|v| v.as_u64()).unwrap_or(cfg.block_duration.as_secs())),
        };
    }
    cfg
}

#[derive(Deserialize)]
pub struct WebmailLoginRequest {
    /// 邮箱地址（如 user@u3u.fun），不区分大小写
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WebmailClaims {
    /// 邮箱地址
    pub sub: String,
    /// 邮箱主键 id
    pub mailbox_id: i32,
    /// 域名主键 id
    pub domain_id: i32,
    /// 是否管理员
    pub is_admin: bool,
    /// token 类型
    pub kind: String,
    /// token 版本号（与数据库 token_version 比较，不匹配则失效）
    pub tv: i32,
    /// 颁发时间
    pub iat: usize,
    /// 过期时间
    pub exp: usize,
}

#[derive(Serialize)]
pub struct WebmailLoginResponse {
    pub token: String,
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
    pub expires_at: i64,
    pub error: Option<String>,
}

impl WebmailLoginResponse {
    fn error(email: &str, display_name: &str, msg: &str) -> Self {
        Self {
            token: String::new(),
            email: email.to_string(),
            display_name: display_name.to_string(),
            is_admin: false,
            expires_at: 0,
            error: Some(msg.to_string()),
        }
    }
}

#[derive(Serialize)]
pub struct WebmailMeResponse {
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
    pub quota_mb: i32,
    pub used_bytes: i64,
    pub aliases: Vec<String>,
    /// 是否自助注册产生（true 则受 register_config 限制）
    pub is_self_registered: bool,
    /// 所属域名的注册策略
    pub register_config: serde_json::Value,
    /// 单个附件最大大小（MB），从 smtp_config.max_attachment_size_mb 读取
    pub max_attachment_size_mb: i64,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/webmail/login", axum::routing::post(login_with_rate_limit))
        .route("/webmail/logout", axum::routing::post(logout))
        .route("/webmail/me", axum::routing::get(me))
        // 自助注册
        .route("/webmail/register-info", axum::routing::get(register_info))
        .route("/webmail/register", axum::routing::post(register))
        .route("/webmail/captcha", axum::routing::get(get_captcha))
        .route("/webmail/captcha/verify", axum::routing::post(verify_captcha))
        .route("/webmail/footer", axum::routing::get(get_footer))
        .route("/webmail/site-name", axum::routing::get(get_site_name))
}

/// 从 Authorization: Bearer <token> 头里解析 Claims
pub fn extract_claims(headers: &HeaderMap, jwt_secret: &str) -> Result<WebmailClaims, StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    let data = jsonwebtoken::decode::<WebmailClaims>(token, &key, &validation)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(data.claims)
}

/// 解析 JWT 并校验 token_version（异步，需查数据库）
/// 用于 mail_routes 等不经过中间件的路由
pub async fn verify_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<WebmailClaims, (StatusCode, String)> {
    let claims = extract_claims(headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    if claims.kind != "webmail" {
        return Err((StatusCode::FORBIDDEN, "非 webmail token".to_string()));
    }
    // 校验 token_version
    let db_tv: Option<i32> = sqlx::query_scalar(
        "SELECT token_version FROM mailboxes WHERE id = $1 AND enabled = true"
    )
    .bind(claims.mailbox_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    match db_tv {
        Some(tv) if tv == claims.tv => Ok(claims),
        _ => Err((StatusCode::UNAUTHORIZED, "登录已失效，请重新登录".to_string())),
    }
}

/// Webmail 鉴权中间件：要求 token 是 webmail 类型，否则 401
/// 同时校验 token_version，确保密码修改/禁用/删除后旧 token 立即失效
pub async fn require_webmail(
    State(state): State<Arc<AppState>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let headers = req.headers().clone();
    match extract_claims(&headers, &state.jwt_secret) {
        Ok(claims) => {
            if claims.kind != "webmail" {
                return (StatusCode::FORBIDDEN, "非 webmail token").into_response();
            }
            // 校验 token_version：与数据库当前值比较
            let db_tv: Option<i32> = sqlx::query_scalar(
                "SELECT token_version FROM mailboxes WHERE id = $1 AND enabled = true"
            )
            .bind(claims.mailbox_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

            match db_tv {
                Some(tv) if tv == claims.tv => {
                    req.extensions_mut().insert(claims);
                    next.run(req).await
                }
                _ => {
                    // 邮箱不存在、已禁用、或 token_version 不匹配
                    (StatusCode::UNAUTHORIZED, "登录已失效，请重新登录").into_response()
                }
            }
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "未登录").into_response(),
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebmailLoginRequest>,
) -> Json<WebmailLoginResponse> {
    let email = req.email.trim().to_lowercase();
    let (local, domain) = match email.split_once('@') {
        Some((l, d)) => (l, d),
        None => return Json(WebmailLoginResponse::error(&email, "", "邮箱格式错误")),
    };

    // 查 mailbox
    let row: Option<(i32, i32, String, bool, bool, i32, i32)> = match sqlx::query_as(
        "SELECT m.id, m.domain_id, m.password_hash, m.enabled, d.enabled, m.quota_mb, m.token_version
         FROM mailboxes m
         JOIN domains d ON d.id = m.domain_id
         WHERE LOWER(m.username) = $1 AND LOWER(d.name) = $2"
    )
    .bind(local)
    .bind(domain)
    .fetch_optional(&state.pool)
    .await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("登录查询失败: {}", e);
            return Json(WebmailLoginResponse::error(&email, "", "操作失败"));
        }
    };

    let (mailbox_id, domain_id, password_hash, m_enabled, d_enabled, _quota_mb, token_version) =
        match row {
            Some(r) => r,
            None => return Json(WebmailLoginResponse::error(&email, local, "邮箱或密码错误")),
        };

    if !m_enabled || !d_enabled {
        return Json(WebmailLoginResponse::error(&email, local, "邮箱已停用"));
    }
    if !auth::verify_password(&req.password, &password_hash).unwrap_or(false) {
        return Json(WebmailLoginResponse::error(&email, local, "邮箱或密码错误"));
    }

    // 更新最后登录
    let _ = sqlx::query(
        "UPDATE mailboxes SET last_login_at = NOW(), last_login_ip = 'webmail' WHERE id = $1"
    )
    .bind(mailbox_id)
    .execute(&state.pool)
    .await;

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(12);
    let claims = WebmailClaims {
        sub: email.clone(),
        mailbox_id,
        domain_id,
        is_admin: false,
        kind: "webmail".to_string(),
        tv: token_version,
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };

    let token = match jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("JWT 编码失败: {}", e);
            return Json(WebmailLoginResponse::error(&email, local, "操作失败"));
        }
    };

    Json(WebmailLoginResponse {
        token,
        email: email.clone(),
        display_name: local.to_string(),
        is_admin: false,
        expires_at: exp.timestamp(),
        error: None,
    })
}

async fn logout() -> impl IntoResponse {
    // JWT 无状态，客户端丢弃 token 即视为登出
    (StatusCode::OK, Json(serde_json::json!({"success": true})))
}

async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<WebmailMeResponse>, (StatusCode, String)> {
    let claims = verify_claims(&headers, &state).await?;

    let row: Option<(i32, i64, serde_json::Value, bool, serde_json::Value, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT m.quota_mb, m.used_bytes, m.aliases, m.is_self_registered, d.register_config, m.protocols
         FROM mailboxes m
         JOIN domains d ON d.id = m.domain_id
         WHERE m.id = $1"
    )
    .bind(claims.mailbox_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| { tracing::error!("me 查询失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    let (quota_mb, used_bytes, aliases_json, is_self_registered, register_config, mailbox_protocols) = row
        .ok_or((StatusCode::NOT_FOUND, "邮箱不存在".to_string()))?;

    let aliases: Vec<String> = serde_json::from_value(aliases_json).unwrap_or_default();

    let display_name = claims
        .sub
        .split_once('@')
        .map(|(l, _)| l.to_string())
        .unwrap_or_else(|| claims.sub.clone());

    // 合并协议权限：mailbox.protocols 非空时覆盖域名 register_config
    let effective_register_config: serde_json::Value = match mailbox_protocols {
        Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
        _ => register_config,
    };

    // 读取附件大小限制
    let max_attachment_size_mb: i64 = sqlx::query_scalar(
        "SELECT (value->>'max_attachment_size_mb')::int FROM settings WHERE key = 'smtp_config'"
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(25);

    Ok(Json(WebmailMeResponse {
        email: claims.sub,
        display_name,
        is_admin: claims.is_admin,
        quota_mb,
        used_bytes,
        aliases,
        is_self_registered,
        register_config: effective_register_config,
        max_attachment_size_mb,
    }))
}

// ============================================================
// 自助注册 + 安全相关接口
// ============================================================

/// 提取客户端 IP（优先取 X-Forwarded-For / X-Real-IP，回落到连接 IP）
fn extract_client_ip(headers: &HeaderMap, default: IpAddr) -> IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    default
}

/// 检查 + 记录一次 IP 行为；返回 Ok(()) 或 Err(剩余封禁秒数)
async fn check_and_record(
    state: &AppState,
    ip: IpAddr,
    is_register: bool,
) -> Result<(), u64> {
    let cfg = load_rate_limit_config(&state.pool).await;
    let now = Instant::now();
    let mut map = state.attempt_counter.write().await;
    let entry = map.entry(ip).or_default();
    let attempts = if is_register { &mut entry.register_attempts } else { &mut entry.login_attempts };
    let max = if is_register { cfg.register_max } else { cfg.login_max };

    // 清理过期记录
    attempts.retain(|t| now.duration_since(*t) < cfg.attempt_window);
    if let Some(block_until) = entry.last_block_until {
        if now < block_until {
            let left = (block_until - now).as_secs().max(1);
            return Err(left);
        }
    }
    if attempts.len() >= max {
        entry.last_block_until = Some(now + cfg.block_duration);
        attempts.clear();
        return Err(cfg.block_duration.as_secs());
    }
    attempts.push(now);
    Ok(())
}

/// 记录一次成功（清空计数器）
#[allow(dead_code)]
async fn record_success(state: &AppState, ip: IpAddr, is_register: bool) {
    let cfg = load_rate_limit_config(&state.pool).await;
    let mut map = state.attempt_counter.write().await;
    let entry = map.entry(ip).or_default();
    if is_register {
        entry.register_attempts.clear();
        // 记录注册成功次数（用于限制成功注册频率）
        entry.register_successes.push(Instant::now());
        entry.register_successes.retain(|t| t.elapsed() < cfg.attempt_window);
    } else {
        entry.login_attempts.clear();
    }
    entry.last_block_until = None;
}

/// 记录一次失败（累加）
#[allow(dead_code)]
async fn record_failure(state: &AppState, ip: IpAddr, is_register: bool) {
    let cfg = load_rate_limit_config(&state.pool).await;
    let now = Instant::now();
    let mut map = state.attempt_counter.write().await;
    let entry = map.entry(ip).or_default();
    let attempts = if is_register { &mut entry.register_attempts } else { &mut entry.login_attempts };
    let max = if is_register { cfg.register_max } else { cfg.login_max };
    attempts.retain(|t| now.duration_since(*t) < cfg.attempt_window);
    attempts.push(now);
    if attempts.len() >= max {
        entry.last_block_until = Some(now + cfg.block_duration);
        attempts.clear();
    }
}

// ---------- 注册前置信息 ----------

#[derive(Serialize)]
struct RegisterInfoResponse {
    domain: String,
    enabled: bool,
    default_quota_mb: i32,
    captcha_required: bool,
    username_min: usize,
    username_max: usize,
    password_min: usize,
    password_max: usize,
    allow_smtp: bool,
    allow_pop3: bool,
    allow_imap: bool,
    allow_forward: bool,
}

/// GET /api/webmail/register-info?domain=xxx
async fn register_info(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<RegisterInfoResponse>, (StatusCode, String)> {
    let domain_name = params
        .get("domain")
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "缺少 domain 参数".to_string()))?;

    // 防止泄漏：domain 必须存在 + setup_completed
    let row: Option<(bool, i32, serde_json::Value)> = sqlx::query_as(
        "SELECT enabled, default_quota_mb, register_config FROM domains
         WHERE LOWER(name) = $1 AND setup_completed = TRUE"
    )
    .bind(&domain_name)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| { tracing::error!("register_info 查询失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    let (domain_enabled, default_quota_mb, cfg) = match row {
        Some(r) => r,
        None => {
            // 域名不存在或未启用：返回 enabled=false，但不泄漏存在性
            return Ok(Json(RegisterInfoResponse {
                domain: domain_name,
                enabled: false,
                default_quota_mb: 0,
                captcha_required: true,
                username_min: USERNAME_MIN,
                username_max: USERNAME_MAX,
                password_min: PASSWORD_MIN,
                password_max: PASSWORD_MAX,
                allow_smtp: false, allow_pop3: false, allow_imap: false, allow_forward: false,
            }));
        }
    };

    if !domain_enabled {
        return Ok(Json(RegisterInfoResponse {
            domain: domain_name,
            enabled: false,
            default_quota_mb,
            captcha_required: true,
            username_min: USERNAME_MIN,
            username_max: USERNAME_MAX,
            password_min: PASSWORD_MIN,
            password_max: PASSWORD_MAX,
            allow_smtp: false, allow_pop3: false, allow_imap: false, allow_forward: false,
        }));
    }

    let enabled = cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let _captcha_required = cfg.get("captcha_required").and_then(|v| v.as_bool()).unwrap_or(true);
    let allow_smtp = cfg.get("allow_smtp").and_then(|v| v.as_bool()).unwrap_or(true);
    let allow_pop3 = cfg.get("allow_pop3").and_then(|v| v.as_bool()).unwrap_or(true);
    let allow_imap = cfg.get("allow_imap").and_then(|v| v.as_bool()).unwrap_or(true);
    let allow_forward = cfg.get("allow_forward").and_then(|v| v.as_bool()).unwrap_or(false);

    // 总是强制要求 captcha（自注册场景一律开）
    Ok(Json(RegisterInfoResponse {
        domain: domain_name,
        enabled,
        default_quota_mb,
        captcha_required: true,
        username_min: USERNAME_MIN,
        username_max: USERNAME_MAX,
        password_min: PASSWORD_MIN,
        password_max: PASSWORD_MAX,
        allow_smtp,
        allow_pop3,
        allow_imap,
        allow_forward,
    }))
}

// ---------- CAPTCHA ----------

#[derive(Serialize)]
struct CaptchaResponse {
    captcha_id: String,
    /// 形如 "3 + 5 = ?"
    question: String,
    /// 过期时间（unix 秒），前端可选展示
    expires_in: u64,
}

#[derive(Deserialize)]
struct CaptchaVerifyRequest {
    captcha_id: String,
    answer: u32,
}

/// 使用 OsRng 生成密码学安全的随机 u32
fn rand_u32() -> u32 {
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::rand_core::RngCore;
    OsRng.next_u32()
}

/// 清理过期 CAPTCHA
async fn cleanup_captcha(state: &AppState) {
    let mut store = state.captcha_store.write().await;
    if store.len() > CAPTCHA_MAX_STORED {
        store.clear();
        return;
    }
    let now = Instant::now();
    store.retain(|_, v| now < v.expires_at);
}

/// GET /api/webmail/captcha
async fn get_captcha(
    State(state): State<Arc<AppState>>,
) -> Json<CaptchaResponse> {
    // 出题：a + b，a,b in 0..=20
    let a = rand_u32() % 21;
    let b = rand_u32() % 21;
    let answer = a.wrapping_add(b);
    let id = uuid::Uuid::new_v4().to_string();
    let entry = crate::state::CaptchaEntry {
        answer,
        expires_at: Instant::now() + CAPTCHA_TTL,
    };
    state.captcha_store.write().await.insert(id.clone(), entry);
    cleanup_captcha(&state).await;
    Json(CaptchaResponse {
        captcha_id: id,
        question: format!("{} + {} = ?", a, b),
        expires_in: CAPTCHA_TTL.as_secs(),
    })
}

/// POST /api/webmail/captcha/verify
async fn verify_captcha(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CaptchaVerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut store = state.captcha_store.write().await;
    let entry = store
        .remove(&req.captcha_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "验证码无效或已过期".to_string()))?;
    if Instant::now() > entry.expires_at {
        return Err((StatusCode::BAD_REQUEST, "验证码已过期".to_string()));
    }
    if entry.answer != req.answer {
        return Err((StatusCode::BAD_REQUEST, "验证码错误".to_string()));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------- 自助注册 ----------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub domain: String,
    pub username: String,
    pub password: String,
    /// 必填（哪怕 captcha_required=false 也强制要求通过一道 CAPTCHA）
    pub captcha_id: String,
    pub captcha_answer: u32,
}

fn validate_username(u: &str) -> Result<(), String> {
    if u.len() < USERNAME_MIN {
        return Err(format!("用户名至少 {} 个字符", USERNAME_MIN));
    }
    if u.len() > USERNAME_MAX {
        return Err(format!("用户名最多 {} 个字符", USERNAME_MAX));
    }
    if !u.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err("用户名仅允许字母/数字/./_/-".to_string());
    }
    if u.starts_with('.') || u.starts_with('_') || u.starts_with('-') {
        return Err("用户名不能以 . _ - 开头".to_string());
    }
    // 防止路径穿越：拒绝 .. 和连续 .
    if u.contains("..") {
        return Err("用户名不能包含连续点号".to_string());
    }
    Ok(())
}

/// 校验域名格式，防止路径穿越
fn validate_domain(d: &str) -> Result<(), String> {
    // 必须匹配标准域名格式：label.label...，每个 label 为 [a-z0-9]([a-z0-9-]*[a-z0-9])?
    let re = regex::Regex::new(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$").unwrap();
    if !re.is_match(d) {
        return Err("域名格式无效".to_string());
    }
    Ok(())
}

fn validate_password(p: &str) -> Result<(), String> {
    if p.len() < PASSWORD_MIN {
        return Err(format!("密码至少 {} 个字符", PASSWORD_MIN));
    }
    if p.len() > PASSWORD_MAX {
        return Err(format!("密码最多 {} 个字符", PASSWORD_MAX));
    }
    let has_letter = p.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = p.chars().any(|c| c.is_ascii_digit());
    if !has_letter || !has_digit {
        return Err("密码必须同时包含字母和数字".to_string());
    }
    Ok(())
}

/// POST /api/webmail/register
async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<WebmailLoginResponse>, (StatusCode, String)> {
    let ip = extract_client_ip(&headers, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    // 1) 限流检查
    if let Err(left) = check_and_record(&state, ip, true).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!("注册过于频繁，请在 {} 秒后重试", left),
        ));
    }

    // 1.5) 注册成功次数限制：从数据库读取配置
    {
        let cfg = load_rate_limit_config(&state.pool).await;
        let map = state.attempt_counter.read().await;
        if let Some(entry) = map.get(&ip) {
            let now = Instant::now();
            let recent: Vec<_> = entry.register_successes.iter().filter(|t| now.duration_since(**t) < cfg.attempt_window).collect();
            if recent.len() >= cfg.register_success_max {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("注册过于频繁，请在 {} 秒后重试", cfg.attempt_window.as_secs()),
                ));
            }
        }
    }

    // 2) 入参基础校验
    let domain = req.domain.trim().to_lowercase();
    let username = req.username.trim().to_lowercase();
    let password = req.password;
    if domain.is_empty() || username.is_empty() || password.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "参数不能为空".to_string()));
    }
    validate_domain(&domain).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_username(&username).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_password(&password).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // 3) CAPTCHA 校验
    let mut store = state.captcha_store.write().await;
    let entry = store
        .remove(&req.captcha_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "验证码无效或已过期".to_string()))?;
    drop(store);
    if Instant::now() > entry.expires_at {
        return Err((StatusCode::BAD_REQUEST, "验证码已过期".to_string()));
    }
    if entry.answer != req.captcha_answer {
        return Err((StatusCode::BAD_REQUEST, "验证码错误".to_string()));
    }

    // 4) 查域名 + 策略
    let row: Option<(i32, bool, i32, serde_json::Value)> = sqlx::query_as(
        "SELECT id, enabled, default_quota_mb, register_config FROM domains
         WHERE LOWER(name) = $1 AND setup_completed = TRUE"
    )
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| { tracing::error!("register 域名查询失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    let (domain_id, domain_enabled, default_quota_mb, cfg) =
        row.ok_or_else(|| (StatusCode::FORBIDDEN, "该域名未开放注册或不存在".to_string()))?;

    if !domain_enabled {
        return Err((StatusCode::FORBIDDEN, "该域名已停用".to_string()));
    }
    let enabled = cfg.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    if !enabled {
        return Err((StatusCode::FORBIDDEN, "该域名未开放自助注册".to_string()));
    }

    // 5) 查重
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM mailboxes WHERE domain_id = $1 AND LOWER(username) = $2"
    )
    .bind(domain_id)
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| { tracing::error!("register 查重失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;
    if exists.is_some() {
        return Err((StatusCode::CONFLICT, "该用户名已被占用".to_string()));
    }

    // 6) 创建 Maildir
    let maildir = std::path::Path::new("/var/lib/funmail/maildir")
        .join(&domain)
        .join(&username);
    for subdir in &["new", "cur", "tmp",
        "Sent/new", "Sent/cur", "Sent/tmp",
        "Drafts/new", "Drafts/cur", "Drafts/tmp",
        "Trash/new", "Trash/cur", "Trash/tmp",
        "Spam/new", "Spam/cur", "Spam/tmp"] {
        if let Err(e) = std::fs::create_dir_all(maildir.join(subdir)) {
            tracing::error!("创建 Maildir 失败: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()));
        }
    }

    // 7) 哈希密码
    let password_hash = auth::hash_password(&password)
        .map_err(|e| { tracing::error!("密码哈希失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    // 8) 插入数据库（is_self_registered = TRUE，quota = 域名默认）
    let insert_res = sqlx::query_as::<_, (i32,)>(
        "INSERT INTO mailboxes (domain_id, username, password_hash, quota_mb,
            aliases, forward_to, keep_copy, is_admin, is_self_registered, protocols, enabled)
         VALUES ($1, $2, $3, $4, '[]'::jsonb, '[]'::jsonb, TRUE, FALSE, TRUE, NULL, TRUE)
         RETURNING id"
    )
    .bind(domain_id)
    .bind(&username)
    .bind(&password_hash)
    .bind(default_quota_mb)
    .fetch_one(&state.pool)
    .await;

    let mailbox_id = match insert_res {
        Ok((id,)) => id,
        Err(e) => {
            tracing::error!("创建邮箱失败: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()));
        }
    };

    // 9) 颁发 JWT（同 login）
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(12);
    let full_email = format!("{}@{}", username, domain);
    let claims = WebmailClaims {
        sub: full_email.clone(),
        mailbox_id,
        domain_id,
        is_admin: false,
        kind: "webmail".to_string(),
        tv: 0, // 新注册用户 token_version 为 0
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| { tracing::error!("register JWT 编码失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    // 10) 更新最后登录
    let _ = sqlx::query(
        "UPDATE mailboxes SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2"
    )
    .bind(ip.to_string())
    .bind(mailbox_id)
    .execute(&state.pool)
    .await;

    // 11) 清空失败计数
    record_success(&state, ip, true).await;

    tracing::info!(
        "[register] 自助注册成功: {}@{} (id={}, ip={})",
        username, domain, mailbox_id, ip
    );

    Ok(Json(WebmailLoginResponse {
        token,
        email: full_email,
        display_name: username,
        is_admin: false,
        expires_at: exp.timestamp(),
        error: None,
    }))
}

// 在 login 上加 IP 限流包装
async fn login_with_rate_limit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WebmailLoginRequest>,
) -> Json<WebmailLoginResponse> {
    let ip = extract_client_ip(&headers, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if let Err(left) = check_and_record(&state, ip, false).await {
        return Json(WebmailLoginResponse::error("", "", &format!("登录尝试过多，请在 {} 秒后重试", left)));
    }
    let result = login(State(state.clone()), Json(req)).await;
    if result.error.is_some() {
        record_failure(&state, ip, false).await;
    } else {
        record_success(&state, ip, false).await;
    }
    result
}

/// GET /api/webmail/footer — 公开接口，无需登录，返回自定义页脚 HTML
async fn get_footer(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let footer: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'webmail_footer'"
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let html = footer
        .and_then(|v| v.get("html").and_then(|h| h.as_str()).map(String::from))
        .unwrap_or_default();

    Json(serde_json::json!({ "html": html }))
}

/// GET /api/webmail/site-name — 公开接口，无需登录，返回自定义网站名称
async fn get_site_name(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let val: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'site_name'"
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let name = val
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();

    Json(serde_json::json!({ "name": name }))
}
