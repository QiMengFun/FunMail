use crate::auth;
use crate::state::AppState;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// 管理员角色：admin 或 viewer
    #[serde(default = "default_role")]
    pub role: String,
    /// token 版本号（与数据库 token_version 比较，不匹配则失效）
    #[serde(default)]
    pub tv: i32,
}

fn default_role() -> String {
    "admin".to_string()
}

/// 从 Authorization: Bearer <token> 解析 admin Claims
/// 旧版同步接口：仅解码 JWT，不校验 token_version（兼容未改造完的路由）
pub fn extract_admin_claims(headers: &axum::http::HeaderMap, jwt_secret: &str) -> Result<Claims, StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // kind == "admin" 或旧 token 无 kind 字段也视为 admin（兼容）
    if let Some(ref kind) = data.claims.kind {
        if kind != "admin" {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(data.claims)
}

/// 异步校验 admin Claims + token_version（推荐使用）
/// 改密码/禁用后旧 token 立即失效
pub async fn verify_admin_claims(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<Claims, (StatusCode, String)> {
    let claims = extract_admin_claims(headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    // 校验 token_version：与数据库当前值比较
    let db_tv: Option<i32> = sqlx::query_scalar(
        "SELECT token_version FROM admin_users WHERE username = $1 AND enabled = true"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| { tracing::error!("admin token_version 查询失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    match db_tv {
        Some(db_tv) if db_tv == claims.tv => Ok(claims),
        _ => Err((StatusCode::UNAUTHORIZED, "登录已失效，请重新登录".to_string())),
    }
}

/// Admin 鉴权 axum middleware layer（所有已认证管理员，包括 viewer）
/// 校验 token_version，改密码/禁用后旧 token 立即失效
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let headers = req.headers().clone();
    match verify_admin_claims(&headers, &state).await {
        Ok(_) => next.run(req).await,
        Err((status, msg)) => {
            let body = if status == StatusCode::FORBIDDEN {
                "非管理员 token".to_string()
            } else {
                msg
            };
            (status, body).into_response()
        }
    }
}

/// 检查 claims 是否为 admin 角色（非 viewer）
/// 用于写操作的权限校验
pub fn require_admin_role(claims: &Claims) -> Result<(), (StatusCode, String)> {
    if claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "只读用户无权执行此操作".to_string()));
    }
    Ok(())
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/auth/login", axum::routing::post(login))
}

const ADMIN_LOGIN_MAX_PER_WINDOW: usize = 10;
const ADMIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(10 * 60);
const ADMIN_BLOCK_DURATION: Duration = Duration::from_secs(15 * 60);

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 限流检查（复用 attempt_counter）
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            headers.get("x-real-ip")
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    {
        let now = Instant::now();
        let mut map = state.attempt_counter.write().await;
        let entry = map.entry(client_ip).or_default();
        let attempts = &mut entry.login_attempts;
        attempts.retain(|t| now.duration_since(*t) < ADMIN_ATTEMPT_WINDOW);
        if let Some(block_until) = entry.last_block_until {
            if now < block_until {
                let left = (block_until - now).as_secs().max(1);
                return Err((StatusCode::TOO_MANY_REQUESTS, format!("登录过于频繁，请在 {} 秒后重试", left)));
            }
        }
        if attempts.len() >= ADMIN_LOGIN_MAX_PER_WINDOW {
            entry.last_block_until = Some(now + ADMIN_BLOCK_DURATION);
            attempts.clear();
            return Err((StatusCode::TOO_MANY_REQUESTS, format!("登录失败次数过多，已封禁 {} 秒", ADMIN_BLOCK_DURATION.as_secs())));
        }
        attempts.push(now);
    }

    let row = sqlx::query_as::<_, (String, bool, String, i32)>(
        "SELECT password_hash, enabled, role, token_version FROM admin_users WHERE username = $1"
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()))?;

    match row {
        Some((hash, enabled, role, token_version)) => {
            if !enabled {
                return Err((StatusCode::UNAUTHORIZED, "用户名或密码错误".to_string()));
            }
            if !auth::verify_password(&req.password, &hash).unwrap_or(false) {
                return Err((StatusCode::UNAUTHORIZED, "用户名或密码错误".to_string()));
            }

            // 登录成功，清空计数器
            {
                let mut map = state.attempt_counter.write().await;
                if let Some(entry) = map.get_mut(&client_ip) {
                    entry.login_attempts.clear();
                    entry.last_block_until = None;
                }
            }

            let now = chrono::Utc::now();
            let claims = Claims {
                sub: req.username.clone(),
                iat: now.timestamp() as usize,
                exp: (now + chrono::Duration::hours(24)).timestamp() as usize,
                kind: Some("admin".to_string()),
                role: role.clone(),
                tv: token_version,
            };

            let header = jsonwebtoken::Header::default();
            let token = jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_secret(state.jwt_secret.as_bytes()))
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()))?;

            Ok(Json(LoginResponse {
                token,
                username: req.username,
                role,
            }))
        }
        None => Err((StatusCode::UNAUTHORIZED, "用户名或密码错误".to_string())),
    }
}
