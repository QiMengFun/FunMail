use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub os: String,
    pub cpu_usage: f32,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
    pub uptime_secs: u64,
    pub smtp_running: bool,
    pub pop3_running: bool,
    pub imap_running: bool,
    pub delivery_running: bool,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/system/info", axum::routing::get(system_info))
        .route("/system/metrics", axum::routing::get(system_metrics))
}

async fn system_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SystemInfo>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let cpu_usage = sys.global_cpu_usage();
    let mem = sys.used_memory();
    let mem_total = sys.total_memory();
    let uptime = sysinfo::System::uptime();

    // 检查服务状态（通过查询数据库中的心跳或进程检测）
    let smtp_running = check_service_running(&state.pool, "smtp").await;
    let pop3_running = check_service_running(&state.pool, "pop3").await;
    let imap_running = check_service_running(&state.pool, "imap").await;
    let delivery_running = check_service_running(&state.pool, "delivery").await;

    Ok(Json(SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        cpu_usage,
        memory_used_gb: mem as f64 / 1073741824.0,
        memory_total_gb: mem_total as f64 / 1073741824.0,
        uptime_secs: uptime,
        smtp_running,
        pop3_running,
        imap_running,
        delivery_running,
    }))
}

#[derive(Serialize)]
pub struct MetricPoint {
    pub time: String,
    pub cpu_usage: f32,
    pub memory_used_gb: f64,
    pub queue_pending: i32,
    pub queue_deferred: i32,
}

async fn system_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<MetricPoint>>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let rows = sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>, f32, f64, i32, i32)>(
        "SELECT created_at, cpu_usage, memory_used_gb, queue_pending, queue_deferred
         FROM system_metrics ORDER BY created_at DESC LIMIT 60"
    )
    .fetch_all(&state.logs_pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询指标失败".to_string()))?;

    let metrics: Vec<MetricPoint> = rows
        .into_iter()
        .map(|(time, cpu_usage, memory_used_gb, queue_pending, queue_deferred)| {
            MetricPoint {
                time: time.to_rfc3339(),
                cpu_usage,
                memory_used_gb,
                queue_pending,
                queue_deferred,
            }
        })
        .collect();

    Ok(Json(metrics))
}

async fn check_service_running(pool: &sqlx::PgPool, service: &str) -> bool {
    // 简化：通过检查最近的系统日志判断服务是否运行
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM system_logs WHERE message ILIKE $1 AND created_at > NOW() - INTERVAL '5 minutes'"
    )
    .bind(format!("%{}%", service))
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    result > 0
}
