use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct MailLogResponse {
    pub id: i64,
    pub from_addr: String,
    pub to_addr: String,
    pub subject: Option<String>,
    pub direction: String,
    pub status: String,
    pub size_bytes: i64,
    pub spam_score: f32,
    pub client_ip: Option<String>,
    pub reject_reason: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct LogQuery {
    pub direction: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub hours: Option<f64>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/logs", axum::routing::get(list_logs))
}

async fn list_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<LogQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let hours = query.hours.unwrap_or(24.0);
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    // 参数化查询，防止 SQL 注入
    let mut conditions: Vec<String> = vec![
        "created_at > NOW() - ($1::float8 * INTERVAL '1 hour')".to_string(),
    ];
    let mut param_idx = 2u32;

    let direction_filter;
    if let Some(ref direction) = query.direction {
        direction_filter = direction.clone();
        conditions.push(format!("direction = ${}", param_idx));
        param_idx += 1;
    } else {
        direction_filter = String::new();
    }

    let status_filter;
    if let Some(ref status) = query.status {
        status_filter = status.clone();
        conditions.push(format!("status = ${}", param_idx));
        param_idx += 1;
    } else {
        status_filter = String::new();
    }

    let search_filter;
    if let Some(ref search) = query.search {
        search_filter = format!("%{}%", search);
        conditions.push(format!(
            "(from_addr ILIKE ${} OR to_addr ILIKE ${} OR subject ILIKE ${})",
            param_idx, param_idx, param_idx
        ));
        param_idx += 1;
    } else {
        search_filter = String::new();
    }

    let where_clause = conditions.join(" AND ");

    // 计数
    let count_sql = format!("SELECT COUNT(*) FROM mail_logs WHERE {}", where_clause);
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(hours);
    if !direction_filter.is_empty() { count_q = count_q.bind(&direction_filter); }
    if !status_filter.is_empty() { count_q = count_q.bind(&status_filter); }
    if !search_filter.is_empty() { count_q = count_q.bind(&search_filter); }
    let total: i64 = count_q.fetch_one(&state.pool).await.unwrap_or(0);

    // 查询
    let data_sql = format!(
        "SELECT id, from_addr, to_addr, subject, direction, status, size_bytes, \
         COALESCE(spam_score, 0::real), client_ip, reject_reason, created_at \
         FROM mail_logs WHERE {} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
        where_clause, param_idx, param_idx + 1
    );
    let mut data_q = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String, i64, f32, Option<String>, Option<String>, chrono::DateTime<chrono::Utc>)>(
        &data_sql
    )
    .bind(hours);
    if !direction_filter.is_empty() { data_q = data_q.bind(&direction_filter); }
    if !status_filter.is_empty() { data_q = data_q.bind(&status_filter); }
    if !search_filter.is_empty() { data_q = data_q.bind(&search_filter); }
    data_q = data_q.bind(page_size).bind(offset);

    let rows = data_q.fetch_all(&state.pool).await.map_err(|e| {
        tracing::error!("查询日志失败: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "查询日志失败".to_string())
    })?;

    let logs: Vec<MailLogResponse> = rows
        .into_iter()
        .map(|(id, from_addr, to_addr, subject, direction, status, size_bytes, spam_score, client_ip, reject_reason, created_at)| {
            MailLogResponse {
                id, from_addr, to_addr, subject, direction, status, size_bytes, spam_score, client_ip, reject_reason,
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": logs,
    })))
}
