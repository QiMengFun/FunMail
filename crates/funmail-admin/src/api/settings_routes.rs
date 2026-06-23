use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct SettingsResponse {
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub key: String,
    pub value: serde_json::Value,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/settings", axum::routing::get(list_settings))
        .route("/settings/{key}", axum::routing::get(get_setting).put(update_setting))
}

async fn list_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SettingsResponse>>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let is_admin = claims.role == "admin";
    let rows = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT key, value FROM settings ORDER BY key"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询设置失败".to_string()))?;

    // viewer 不能查看 jwt_secret
    let settings: Vec<SettingsResponse> = rows
        .into_iter()
        .filter(|(key, _)| is_admin || key != "jwt_secret")
        .map(|(key, value)| SettingsResponse { key, value })
        .collect();

    Ok(Json(settings))
}

async fn get_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> Result<Json<SettingsResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    // viewer 不能查看 jwt_secret
    if key == "jwt_secret" && claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "无权查看此设置".to_string()));
    }
    let row = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT key, value FROM settings WHERE key = $1"
    )
    .bind(&key)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询设置失败".to_string()))?;

    match row {
        Some((key, value)) => Ok(Json(SettingsResponse { key, value })),
        None => Err((StatusCode::NOT_FOUND, "设置不存在".to_string())),
    }
}

async fn update_setting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(key): axum::extract::Path<String>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()"
    )
    .bind(&key)
    .bind(&req.value)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}
