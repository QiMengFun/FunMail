use crate::auth;
use crate::state::AppState;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::auth_routes;

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
    pub role: Option<String>,
    pub enabled: Option<bool>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/users", axum::routing::get(list_users).post(create_user))
        .route("/users/{id}", axum::routing::put(update_user).delete(delete_user))
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, String)> {
    let _claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    // viewer 只能查看用户列表，但不能操作（写操作由 require_admin_role 拦截）
    let rows = sqlx::query_as::<_, (i32, String, String, bool, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, username, role, enabled, created_at FROM admin_users ORDER BY username"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询用户失败".to_string()))?;

    let users: Vec<UserResponse> = rows
        .into_iter()
        .map(|(id, username, role, enabled, created_at)| {
            UserResponse {
                id, username, role, enabled,
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(users))
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let password_hash = auth::hash_password(&req.password)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let role = req.role.unwrap_or_else(|| "admin".to_string());

    let row = sqlx::query_as::<_, (i32, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, created_at"
    )
    .bind(&req.username)
    .bind(&password_hash)
    .bind(&role)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UserResponse {
        id: row.0,
        username: req.username,
        role,
        enabled: true,
        created_at: row.1.to_rfc3339(),
    }))
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;

    let current_user_id: i32 = sqlx::query_scalar(
        "SELECT id FROM admin_users WHERE username = $1"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "当前用户不存在".to_string()))?;

    // 查询目标用户当前的角色和启用状态
    let target_row: Option<(String, bool)> = sqlx::query_as(
        "SELECT role, enabled FROM admin_users WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (target_role, target_enabled) = match target_row {
        Some(r) => r,
        None => return Err((StatusCode::NOT_FOUND, "用户不存在".to_string())),
    };

    // 计算操作后的最终角色和启用状态
    let final_role = req.role.clone().unwrap_or_else(|| target_role.clone());
    let final_enabled = req.enabled.unwrap_or(target_enabled);

    // 如果要禁用用户，检查不能禁用自己
    if req.enabled == Some(false) && id == current_user_id {
        return Err((StatusCode::BAD_REQUEST, "不能禁用自己".to_string()));
    }

    // 如果目标用户当前是 admin，且操作后会失去 admin 权限（降级或禁用），检查是否最后一个管理员
    let will_lose_admin = target_role == "admin" && (final_role != "admin" || !final_enabled);
    if will_lose_admin {
        let admin_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_users WHERE enabled = true AND role = 'admin'"
        )
        .fetch_one(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if admin_count <= 1 {
            return Err((StatusCode::BAD_REQUEST, "不能降级或禁用最后一个管理员".to_string()));
        }
    }

    let password_hash = match &req.password {
        Some(p) => Some(auth::hash_password(p).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?),
        None => None,
    };

    // 改密码或禁用时递增 token_version，使旧 JWT 立即失效
    let need_invalidate = password_hash.is_some() || req.enabled == Some(false);

    let result = sqlx::query(
        "UPDATE admin_users SET
            password_hash = COALESCE($2, password_hash),
            role = COALESCE($3, role),
            enabled = COALESCE($4, enabled),
            token_version = CASE WHEN $5 THEN token_version + 1 ELSE token_version END,
            updated_at = NOW()
         WHERE id = $1"
    )
    .bind(id)
    .bind(password_hash)
    .bind(req.role)
    .bind(req.enabled)
    .bind(need_invalidate)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "用户不存在".to_string()));
    }
    Ok(StatusCode::OK)
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 角色权限检查
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 不能删除自己
    let current_user_id: i32 = sqlx::query_scalar(
        "SELECT id FROM admin_users WHERE username = $1"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "当前用户不存在".to_string()))?;

    if id == current_user_id {
        return Err((StatusCode::BAD_REQUEST, "禁止删除当前登录账号".to_string()));
    }

    // 不能删除最后一个管理员
    let admin_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM admin_users WHERE enabled = true"
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if admin_count <= 1 {
        return Err((StatusCode::BAD_REQUEST, "禁止删除最后一个管理员".to_string()));
    }

    // 不能删除 admin 默认账号
    let target_username: String = sqlx::query_scalar(
        "SELECT username FROM admin_users WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "用户不存在".to_string()))?;

    if target_username == "admin" {
        return Err((StatusCode::BAD_REQUEST, "admin 账号禁止删除".to_string()));
    }

    let result = sqlx::query("DELETE FROM admin_users WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "用户不存在".to_string()));
    }
    Ok(StatusCode::OK)
}
