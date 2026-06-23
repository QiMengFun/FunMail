use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
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

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/stats/dashboard", axum::routing::get(dashboard))
        .route("/stats/traffic", axum::routing::get(traffic))
        .route("/stats/traffic7d", axum::routing::get(traffic_30d))
}

async fn dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DashboardStats>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let total_inbound = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_logs WHERE direction = 'inbound' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let total_outbound = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_logs WHERE direction = 'outbound' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let total_blocked = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_logs WHERE status = 'blocked' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let total_spam = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_logs WHERE spam_score > 5.0 AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let total_bounced = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_logs WHERE status = 'bounced' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let active_domains = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM domains WHERE enabled = true"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0) as i32;

    let active_mailboxes = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mailboxes WHERE enabled = true"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0) as i32;

    let queue_pending = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'pending'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let queue_deferred = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'deferred'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let avg_latency: f64 = sqlx::query_scalar(
        "SELECT COALESCE(AVG(latency_ms), 0) FROM mail_logs WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0.0);

    Ok(Json(DashboardStats {
        total_inbound,
        total_outbound,
        total_blocked,
        total_spam,
        total_bounced,
        active_domains,
        active_mailboxes,
        queue_pending,
        queue_deferred,
        avg_latency_ms: avg_latency,
    }))
}

/// 24小时收发趋势
#[derive(Serialize)]
pub struct TrafficData {
    pub hours: Vec<String>,
    pub inbound: Vec<i64>,
    pub outbound: Vec<i64>,
}

async fn traffic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TrafficData>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    // 优先从 hourly_stats 读取，回退到 mail_logs 实时聚合
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT \
            to_char(h, 'HH24') AS hour, \
            COALESCE(SUM(total_inbound), 0), \
            COALESCE(SUM(total_outbound), 0) \
         FROM generate_series(NOW() - INTERVAL '23 hours', NOW(), INTERVAL '1 hour') AS h \
         LEFT JOIN hourly_stats ON hourly_stats.stat_time >= h AND hourly_stats.stat_time < h + INTERVAL '1 hour' \
         GROUP BY h ORDER BY h"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // 如果 hourly_stats 无数据，回退到 mail_logs 实时聚合
    let rows = if rows.iter().all(|(_, i, o)| *i == 0 && *o == 0) {
        sqlx::query_as(
            "SELECT \
                to_char(h, 'HH24') AS hour, \
                COUNT(*) FILTER (WHERE direction = 'inbound'), \
                COUNT(*) FILTER (WHERE direction = 'outbound') \
             FROM generate_series(NOW() - INTERVAL '23 hours', NOW(), INTERVAL '1 hour') AS h \
             LEFT JOIN mail_logs ON mail_logs.created_at >= h AND mail_logs.created_at < h + INTERVAL '1 hour' \
             GROUP BY h ORDER BY h"
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    } else {
        rows
    };

    let hours = rows.iter().map(|(h, _, _)| h.clone()).collect();
    let inbound = rows.iter().map(|(_, i, _)| *i).collect();
    let outbound = rows.iter().map(|(_, _, o)| *o).collect();

    Ok(Json(TrafficData { hours, inbound, outbound }))
}

/// 近30天收发退趋势
#[derive(Serialize)]
pub struct Traffic30dData {
    pub days: Vec<String>,
    pub inbound: Vec<i64>,
    pub outbound: Vec<i64>,
    pub bounced: Vec<i64>,
}

async fn traffic_30d(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Traffic30dData>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT \
            to_char(d, 'MM-DD') AS day, \
            COALESCE(SUM(total_inbound), 0), \
            COALESCE(SUM(total_outbound), 0), \
            0::bigint \
         FROM generate_series(DATE(NOW()) - INTERVAL '29 days', DATE(NOW()), INTERVAL '1 day') AS d \
         LEFT JOIN hourly_stats ON hourly_stats.stat_time >= d AND hourly_stats.stat_time < d + INTERVAL '1 day' \
         GROUP BY d ORDER BY d"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // 如果 hourly_stats 无数据，回退到 mail_logs 实时聚合
    let rows = if rows.iter().all(|(_, i, o, _)| *i == 0 && *o == 0) {
        sqlx::query_as(
            "SELECT \
                to_char(d, 'MM-DD') AS day, \
                COUNT(*) FILTER (WHERE direction = 'inbound'), \
                COUNT(*) FILTER (WHERE direction = 'outbound'), \
                COUNT(*) FILTER (WHERE status = 'bounced') \
             FROM generate_series(DATE(NOW()) - INTERVAL '29 days', DATE(NOW()), INTERVAL '1 day') AS d \
             LEFT JOIN mail_logs ON mail_logs.created_at >= d AND mail_logs.created_at < d + INTERVAL '1 day' \
             GROUP BY d ORDER BY d"
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
    } else {
        // hourly_stats 有数据时，从 mail_logs 补充 bounced
        let bounced_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT \
                to_char(d, 'MM-DD') AS day, \
                COUNT(*) FILTER (WHERE status = 'bounced') \
             FROM generate_series(DATE(NOW()) - INTERVAL '29 days', DATE(NOW()), INTERVAL '1 day') AS d \
             LEFT JOIN mail_logs ON mail_logs.created_at >= d AND mail_logs.created_at < d + INTERVAL '1 day' \
             GROUP BY d ORDER BY d"
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

        let bounced_map: std::collections::HashMap<String, i64> = bounced_rows.into_iter().collect();
        rows.into_iter().map(|(d, i, o, _)| {
            let b = bounced_map.get(&d).copied().unwrap_or(0);
            (d, i, o, b)
        }).collect()
    };

    let days = rows.iter().map(|(d, _, _, _)| d.clone()).collect();
    let inbound = rows.iter().map(|(_, i, _, _)| *i).collect();
    let outbound = rows.iter().map(|(_, _, o, _)| *o).collect();
    let bounced = rows.iter().map(|(_, _, _, b)| *b).collect();

    Ok(Json(Traffic30dData { days, inbound, outbound, bounced }))
}
