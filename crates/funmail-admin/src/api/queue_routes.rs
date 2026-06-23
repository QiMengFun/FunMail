use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct QueueEntryResponse {
    pub id: i64,
    pub from_addr: String,
    pub to_addr: String,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub status: String,
    pub retry_count: i32,
    pub direction: String,
    pub size_bytes: i64,
    pub last_error: Option<String>,
    pub next_retry_at: Option<String>,
    pub created_at: String,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/queue", axum::routing::get(list_queue))
        .route("/queue/stats", axum::routing::get(queue_stats))
        .route("/queue/{id}", axum::routing::delete(delete_queue_entry))
        .route("/queue/{id}/retry", axum::routing::post(retry_queue_entry))
}

async fn list_queue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let page = params.get("page").and_then(|s| s.parse::<i64>().ok()).unwrap_or(1).max(1);
    let page_size = params.get("page_size").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_queue WHERE status NOT IN ('delivered', 'bounced')"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let rows = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<String>, String, i32, String, i64, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, from_addr, to_addr, message_id, subject, status, retry_count, direction, size_bytes, last_error, next_retry_at, created_at
         FROM mail_queue WHERE status NOT IN ('delivered', 'bounced') ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询队列失败".to_string()))?;

    let entries: Vec<QueueEntryResponse> = rows
        .into_iter()
        .map(|(id, from_addr, to_addr, message_id, subject, status, retry_count, direction, size_bytes, last_error, next_retry_at, created_at)| {
            QueueEntryResponse {
                id, from_addr, to_addr, message_id, subject, status, retry_count, direction, size_bytes, last_error,
                next_retry_at: next_retry_at.map(|t| t.to_rfc3339()),
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": entries,
    })))
}

#[derive(Serialize)]
pub struct QueueStats {
    pub pending: i64,
    pub delivering: i64,
    pub deferred: i64,
    pub total: i64,
}

async fn queue_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<QueueStats>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let pending = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'pending'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let delivering = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'delivering'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let deferred = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'deferred'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    Ok(Json(QueueStats {
        pending,
        delivering,
        deferred,
        total: pending + delivering + deferred,
    }))
}

async fn delete_queue_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let result = sqlx::query("DELETE FROM mail_queue WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "队列条目不存在".to_string()));
    }
    Ok(StatusCode::OK)
}

async fn retry_queue_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let result = sqlx::query(
        "UPDATE mail_queue SET status = 'pending', retry_count = 0, next_retry_at = NULL, updated_at = NOW() WHERE id = $1"
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "队列条目不存在".to_string()));
    }
    Ok(StatusCode::OK)
}
