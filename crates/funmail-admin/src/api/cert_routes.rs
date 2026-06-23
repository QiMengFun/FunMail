use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct CertResponse {
    pub id: i32,
    pub domain: String,
    pub issuer: Option<String>,
    pub expires_at: String,
    pub auto_renew: bool,
    pub notes: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateCertRequest {
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub auto_renew: Option<bool>,
    pub notes: Option<String>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/certs", axum::routing::get(list_certs).post(create_cert))
        .route("/certs/{id}", axum::routing::get(get_cert).delete(delete_cert).patch(update_cert))
        .route("/certs/{id}/renew", axum::routing::post(renew_cert))
}

async fn list_certs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<CertResponse>>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let rows = sqlx::query_as::<_, (i32, String, Option<String>, chrono::DateTime<chrono::Utc>, bool, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, domain, issuer, expires_at, auto_renew, notes, created_at FROM certs ORDER BY domain"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询证书失败".to_string()))?;

    let certs: Vec<CertResponse> = rows
        .into_iter()
        .map(|(id, domain, issuer, expires_at, auto_renew, notes, created_at)| {
            CertResponse {
                id, domain, issuer,
                expires_at: expires_at.to_rfc3339(),
                auto_renew, notes,
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(certs))
}

async fn create_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateCertRequest>,
) -> Result<Json<CertResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let (cert_pem, key_pem) = match (req.cert_pem, req.key_pem) {
        (Some(c), Some(k)) => (c, k),
        _ => {
            // ACME 自动申请，后台执行并返回进度
            let domain = req.domain.clone();
            let auto_renew = req.auto_renew.unwrap_or(true);

            // 去重检查：如果该域名已有正在进行的申请，拒绝重复提交
            {
                let progress = state.cert_progress.read().await;
                if let Some(p) = progress.get(&domain) {
                    if !p.done {
                        return Err((StatusCode::CONFLICT, format!("域名 {} 的证书申请正在进行中", domain)));
                    }
                }
            }

            // 初始化进度
            {
                let mut progress = state.cert_progress.write().await;
                progress.insert(domain.clone(), crate::state::CertProgress {
                    domain: domain.clone(),
                    status: "requesting".to_string(),
                    message: "正在申请证书...".to_string(),
                    success: false,
                    done: false,
                    step: 0,
                    total_steps: 9,
                    step_name: "初始化".to_string(),
                    detail: "正在准备申请证书...".to_string(),
                    error: None,
                });
            }

            // 后台异步申请
            let pool = state.pool.clone();
            let progress_map = state.cert_progress.clone();
            tokio::spawn(async move {
                match crate::acme::request_certificate(&pool, &domain, auto_renew, Some(progress_map.clone())).await {
                    Ok(_cert_id) => {
                        let mut p = progress_map.write().await;
                        p.insert(domain.clone(), crate::state::CertProgress {
                            domain: domain.clone(),
                            status: "done".to_string(),
                            message: "证书申请成功".to_string(),
                            success: true,
                            done: true,
                            step: 9,
                            total_steps: 9,
                            step_name: "完成".to_string(),
                            detail: "证书已成功签发并保存".to_string(),
                            error: None,
                        });
                    }
                    Err(e) => {
                        let error_detail = format!(
                            "证书申请失败: {}。请检查：1) 80端口是否对外开放 2) 域名是否已备案 3) DNS是否已正确解析到本服务器",
                            e
                        );
                        let mut p = progress_map.write().await;
                        p.insert(domain.clone(), crate::state::CertProgress {
                            domain: domain.clone(),
                            status: "failed".to_string(),
                            message: error_detail.clone(),
                            success: false,
                            done: true,
                            step: 0,
                            total_steps: 9,
                            step_name: "失败".to_string(),
                            detail: error_detail.clone(),
                            error: Some(error_detail),
                        });
                    }
                }
            });

            // 立即返回，前端通过进度接口查询
            return Ok(Json(CertResponse {
                id: 0,
                domain: req.domain,
                issuer: Some("ACME".to_string()),
                expires_at: String::new(),
                auto_renew: req.auto_renew.unwrap_or(true),
                notes: req.notes,
                created_at: chrono::Utc::now().to_rfc3339(),
            }));
        }
    };

    let expires_at = chrono::Utc::now() + chrono::Duration::days(90);

    let row = sqlx::query_as::<_, (i32, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO certs (domain, cert_pem, key_pem, issuer, expires_at, auto_renew, notes)
         VALUES ($1, $2, $3, 'Manual', $4, $5, $6) RETURNING id, created_at"
    )
    .bind(&req.domain)
    .bind(&cert_pem)
    .bind(&key_pem)
    .bind(expires_at)
    .bind(req.auto_renew.unwrap_or(true))
    .bind(&req.notes)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CertResponse {
        id: row.0,
        domain: req.domain,
        issuer: Some("Manual".to_string()),
        expires_at: expires_at.to_rfc3339(),
        auto_renew: req.auto_renew.unwrap_or(true),
        notes: req.notes,
        created_at: row.1.to_rfc3339(),
    }))
}

async fn get_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Json<CertResponse>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    get_cert_inner(&state, id).await
}

async fn get_cert_inner(state: &Arc<AppState>, id: i32) -> Result<Json<CertResponse>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, (String, Option<String>, chrono::DateTime<chrono::Utc>, bool, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT domain, issuer, expires_at, auto_renew, notes, created_at FROM certs WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some((domain, issuer, expires_at, auto_renew, notes, created_at)) => {
            Ok(Json(CertResponse {
                id, domain, issuer,
                expires_at: expires_at.to_rfc3339(),
                auto_renew, notes,
                created_at: created_at.to_rfc3339(),
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "证书不存在".to_string())),
    }
}

async fn delete_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 先获取被删除证书的域名，用于后续检查
    let domain: Option<String> = sqlx::query_scalar("SELECT domain FROM certs WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result = sqlx::query("DELETE FROM certs WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "证书不存在".to_string()));
    }

    // 如果删除的证书域名是子域名（如 mail.xxx.com），检查该域名下是否还有其他证书
    // 如果没有了，重置 setup_completed 以便用户可以重新申请
    if let Some(ref cert_domain) = domain {
        // 只有子域名（含至少一个点）才做此检查，顶级域名 example.com 不需要
        if cert_domain.contains('.') {
            let base_domain = cert_domain.split_once('.').map(|(_, rest)| rest).unwrap_or(cert_domain);
            let remaining: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM certs WHERE domain LIKE '%' || $1"
            )
            .bind(format!(".{}", base_domain))
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

            if remaining == 0 {
                let _ = sqlx::query("UPDATE domains SET setup_completed = false, updated_at = NOW() WHERE name = $1")
                    .bind(base_domain)
                    .execute(&state.pool)
                    .await;
            }
        }
    }

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct UpdateCertRequest {
    auto_renew: Option<bool>,
    notes: Option<String>,
}

async fn update_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<UpdateCertRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 检查证书是否存在
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM certs WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !exists {
        return Err((StatusCode::NOT_FOUND, "证书不存在".to_string()));
    }

    sqlx::query("UPDATE certs SET auto_renew = COALESCE($2, auto_renew), notes = COALESCE($3, notes), updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(req.auto_renew)
        .bind(&req.notes)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}

async fn renew_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let (domain, issuer): (String, Option<String>) = sqlx::query_as(
        "SELECT domain, issuer FROM certs WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    // 自签名/手动导入的证书不能通过 ACME 续签
    if issuer.as_deref() != Some("ACME") {
        return Err((StatusCode::BAD_REQUEST, "仅 ACME 证书支持在线续签，自签名或手动导入的证书请手动替换".to_string()));
    }

    // 设置初始进度
    {
        let mut progress = state.cert_progress.write().await;
        progress.insert(domain.clone(), crate::state::CertProgress {
            domain: domain.clone(),
            status: "pending".to_string(),
            message: "正在提交续签申请...".to_string(),
            success: false,
            step: 0,
            total_steps: 9,
            step_name: "初始化".to_string(),
            detail: "正在提交续签申请...".to_string(),
            done: false,
            error: None,
        });
    }

    let progress_map = state.cert_progress.clone();
    crate::acme::renew_certificate(&state.pool, &domain, id, false, Some(progress_map))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}
