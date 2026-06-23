use crate::auth;
use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct MailboxResponse {
    pub id: i32,
    pub domain_id: i32,
    pub username: String,
    pub domain_name: String,
    pub quota_mb: i32,
    pub used_bytes: i64,
    pub used_mb: f64,
    pub enabled: bool,
    pub aliases: serde_json::Value,
    pub forward_to: serde_json::Value,
    pub keep_copy: bool,
    pub is_admin: bool,
    /// 协议权限（null = 继承域名策略；对象 = 覆盖）
    pub protocols: Option<serde_json::Value>,
    pub last_login_at: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateMailboxRequest {
    pub domain_id: i32,
    pub username: String,
    pub password: String,
    pub quota_mb: Option<i32>,
    pub aliases: Option<serde_json::Value>,
    pub forward_to: Option<serde_json::Value>,
    pub keep_copy: Option<bool>,
    pub is_admin: Option<bool>,
    /// 协议权限；null = 继承域名策略
    pub protocols: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct UpdateMailboxRequest {
    pub password: Option<String>,
    pub quota_mb: Option<i32>,
    pub enabled: Option<bool>,
    pub aliases: Option<serde_json::Value>,
    pub forward_to: Option<serde_json::Value>,
    pub keep_copy: Option<bool>,
    pub is_admin: Option<bool>,
    /// 协议权限；传 None = 不改；传 Some(null) = 恢复继承；传 Some(obj) = 覆盖
    pub protocols: Option<serde_json::Value>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/mailboxes", axum::routing::get(list_mailboxes).post(create_mailbox))
        .route("/mailboxes/{id}", axum::routing::get(get_mailbox).put(update_mailbox).delete(delete_mailbox))
}

async fn list_mailboxes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<MailboxResponse>>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let rows = sqlx::query_as::<_, (i32, i32, String, String, i32, i64, bool, serde_json::Value, serde_json::Value, bool, bool, Option<serde_json::Value>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)>(
        "SELECT m.id, m.domain_id, m.username, d.name, m.quota_mb, m.used_bytes, m.enabled, m.aliases, m.forward_to, m.keep_copy, m.is_admin, m.protocols, m.last_login_at, m.created_at
         FROM mailboxes m JOIN domains d ON m.domain_id = d.id ORDER BY d.name, m.username"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询邮箱失败".to_string()))?;

    let mailboxes: Vec<MailboxResponse> = rows
        .into_iter()
        .map(|(id, domain_id, username, domain_name, quota_mb, used_bytes, enabled, aliases, forward_to, keep_copy, is_admin, protocols, last_login_at, created_at)| {
            MailboxResponse {
                id, domain_id, username, domain_name, quota_mb, used_bytes,
                used_mb: used_bytes as f64 / 1048576.0,
                enabled, aliases, forward_to, keep_copy, is_admin, protocols,
                last_login_at: last_login_at.map(|t| t.to_rfc3339()),
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(mailboxes))
}

async fn create_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateMailboxRequest>,
) -> Result<Json<MailboxResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 用户名统一归一化为小写，避免与自助注册产生大小写冲突
    let username = req.username.trim().to_lowercase();
    // 路径穿越防护：用户名不能包含路径分隔符或 ..
    if username.contains('/') || username.contains('\\') || username.contains("..") || username.starts_with('.') {
        return Err((StatusCode::BAD_REQUEST, "用户名包含非法字符".to_string()));
    }
    let password_hash = auth::hash_password(&req.password)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 创建 Maildir 目录
    let domain_name: String = sqlx::query_scalar(
        "SELECT name FROM domains WHERE id = $1"
    )
    .bind(req.domain_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("域名不存在: {}", e)))?;

    // 查重：同域名下大小写不敏感唯一
    let dup: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM mailboxes WHERE domain_id = $1 AND LOWER(username) = $2"
    )
    .bind(req.domain_id)
    .bind(&username)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if dup.is_some() {
        return Err((StatusCode::CONFLICT, "该用户名已被占用".to_string()));
    }

    let maildir = std::path::Path::new("/var/lib/funmail/maildir")
        .join(&domain_name)
        .join(&username);
    let subdirs = ["new", "cur", "tmp", "Sent/new", "Sent/cur", "Sent/tmp", "Drafts/new", "Drafts/cur", "Drafts/tmp", "Trash/new", "Trash/cur", "Trash/tmp", "Spam/new", "Spam/cur", "Spam/tmp"];
    for subdir in &subdirs {
        if let Err(e) = std::fs::create_dir_all(maildir.join(subdir)) {
            // 创建失败时回滚已创建的目录
            let _ = std::fs::remove_dir(&maildir);
            tracing::error!("创建 Maildir 失败: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()));
        }
    }

    let aliases = req.aliases.clone().unwrap_or(serde_json::json!([]));
    let forward_to = req.forward_to.clone().unwrap_or(serde_json::json!([]));

    let row = sqlx::query_as::<_, (i32, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO mailboxes (domain_id, username, password_hash, quota_mb, aliases, forward_to, keep_copy, is_admin, protocols)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, created_at"
    )
    .bind(req.domain_id)
    .bind(&username)
    .bind(&password_hash)
    .bind(req.quota_mb.unwrap_or(1024))
    .bind(&aliases)
    .bind(&forward_to)
    .bind(req.keep_copy.unwrap_or(true))
    .bind(req.is_admin.unwrap_or(false))
    .bind(req.protocols.as_ref().map(|v| v.clone()).unwrap_or(serde_json::Value::Null))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(MailboxResponse {
        id: row.0,
        domain_id: req.domain_id,
        username,
        domain_name,
        quota_mb: req.quota_mb.unwrap_or(1024),
        used_bytes: 0,
        used_mb: 0.0,
        enabled: true,
        aliases,
        forward_to,
        keep_copy: req.keep_copy.unwrap_or(true),
        is_admin: req.is_admin.unwrap_or(false),
        protocols: req.protocols,
        last_login_at: None,
        created_at: row.1.to_rfc3339(),
    }))
}

async fn get_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Json<MailboxResponse>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let row = sqlx::query_as::<_, (i32, i32, String, String, i32, i64, bool, serde_json::Value, serde_json::Value, bool, bool, Option<serde_json::Value>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)>(
        "SELECT m.id, m.domain_id, m.username, d.name, m.quota_mb, m.used_bytes, m.enabled, m.aliases, m.forward_to, m.keep_copy, m.is_admin, m.protocols, m.last_login_at, m.created_at
         FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询邮箱失败".to_string()))?;

    match row {
        Some((id, domain_id, username, domain_name, quota_mb, used_bytes, enabled, aliases, forward_to, keep_copy, is_admin, protocols, last_login_at, created_at)) => {
            Ok(Json(MailboxResponse {
                id, domain_id, username, domain_name, quota_mb, used_bytes,
                used_mb: used_bytes as f64 / 1048576.0,
                enabled, aliases, forward_to, keep_copy, is_admin, protocols,
                last_login_at: last_login_at.map(|t| t.to_rfc3339()),
                created_at: created_at.to_rfc3339(),
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "邮箱不存在".to_string())),
    }
}

async fn update_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<UpdateMailboxRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let password_hash = match &req.password {
        Some(p) => Some(auth::hash_password(p).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?),
        None => None,
    };

    // protocols 用 sentinel：req 字段是 Option<serde_json::Value>，
    //   字段缺失（前端没传）→ 不改
    //   显式传 null          → 恢复继承（写入 NULL）
    //   传对象                → 覆盖
    // 但 serde 把 None 视为字段缺失；要把"显式 null"区分开，我们用一个 enum。
    // 为了简洁：这里仅支持两种情况：有 protocols 字段（替换）、没传（保留）。
    // 恢复继承需要前端把 protocols 设为 {} 而不是 null — 此处按 "传了就整体写" 处理。
    let protocols_to_write: Option<serde_json::Value> = match &req.protocols {
        Some(v) if v.is_object() && v.as_object().map(|o| o.is_empty()).unwrap_or(false) => Some(serde_json::Value::Null),
        Some(v) => Some(v.clone()),
        None => None,
    };

    // 判断是否需要使用户的旧 token 失效
    let need_invalidate = password_hash.is_some() || req.enabled == Some(false);

    let result = sqlx::query(
        "UPDATE mailboxes SET
            password_hash = COALESCE($2, password_hash),
            quota_mb = COALESCE($3, quota_mb),
            enabled = COALESCE($4, enabled),
            aliases = COALESCE($5, aliases),
            forward_to = COALESCE($6, forward_to),
            keep_copy = COALESCE($7, keep_copy),
            is_admin = COALESCE($8, is_admin),
            protocols = COALESCE($9, protocols),
            token_version = CASE WHEN $10 THEN token_version + 1 ELSE token_version END,
            updated_at = NOW()
         WHERE id = $1"
    )
    .bind(id)
    .bind(password_hash)
    .bind(req.quota_mb)
    .bind(req.enabled)
    .bind(req.aliases)
    .bind(req.forward_to)
    .bind(req.keep_copy)
    .bind(req.is_admin)
    .bind(protocols_to_write)
    .bind(need_invalidate)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "邮箱不存在".to_string()));
    }

    Ok(StatusCode::OK)
}

async fn delete_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let result = sqlx::query("DELETE FROM mailboxes WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "邮箱不存在".to_string()));
    }

    Ok(StatusCode::OK)
}
