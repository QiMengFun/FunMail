use crate::state::AppState;
use crate::api::auth_routes;
use axum::{Json, extract::State, http::{HeaderMap, StatusCode}};
use base64::Engine;
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct DomainResponse {
    pub id: i32,
    pub name: String,
    pub enabled: bool,
    pub dkim_selector: String,
    pub dkim_public_key: Option<String>,
    pub mx_verified: bool,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub default_quota_mb: i32,
    /// 注册策略（JSONB，最大限度自定义）
    /// 推荐键：enabled, default_quota_mb, allow_smtp, allow_pop3, allow_imap, allow_forward, max_aliases, ...
    pub register_config: serde_json::Value,
    pub notes: Option<String>,
    pub setup_completed: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    pub default_quota_mb: Option<i32>,
    pub register_config: Option<serde_json::Value>,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateDomainRequest {
    pub enabled: Option<bool>,
    pub dkim_selector: Option<String>,
    pub default_quota_mb: Option<i32>,
    /// 整体替换 register_config。传 null 保持不变。
    pub register_config: Option<serde_json::Value>,
    pub notes: Option<String>,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/domains", axum::routing::get(list_domains).post(create_domain))
        .route("/domains/{id}", axum::routing::get(get_domain).put(update_domain).delete(delete_domain))
        .route("/domains/{id}/dns-guide", axum::routing::get(dns_guide))
        .route("/domains/{id}/verify-dns", axum::routing::post(verify_dns))
        .route("/domains/{id}/setup-cert", axum::routing::post(setup_cert))
        .route("/cert-progress", axum::routing::get(cert_progress))
}

async fn list_domains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<DomainResponse>>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let rows = sqlx::query_as::<_, (i32, String, bool, String, Option<String>, bool, bool, bool, bool, i32, serde_json::Value, Option<String>, bool, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed, created_at FROM domains ORDER BY name"
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询域名失败".to_string()))?;

    let domains: Vec<DomainResponse> = rows
        .into_iter()
        .map(|(id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed, created_at)| {
            DomainResponse {
                id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed,
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(domains))
}

async fn create_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<DomainResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 生成 DKIM 密钥对（RSA 2048）
    let dkim_selector = "funmail".to_string();
    // 使用 OsRng（Send）而非 thread_rng（非 Send），兼容 axum 的 async handler
    let mut rng = rand::rngs::OsRng;
    let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 导出 PKCS#8 PEM 私钥（用于投递时签名）
    let private_key = rsa_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    // 导出 SPKI DER 公钥，base64 编码（用于 DKIM DNS TXT 记录的 p= 字段）
    let public_key_der = rsa_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let public_key = base64::engine::general_purpose::STANDARD.encode(public_key_der.as_bytes());

    let default_config = serde_json::json!({
        "enabled": false,
        "default_quota_mb": req.default_quota_mb.unwrap_or(1024),
        "allow_smtp": true,
        "allow_pop3": true,
        "allow_imap": true,
        "allow_forward": false,
        "max_aliases": 1,
        "max_forwarders": 1,
        "max_mail_per_day": 100,
        "captcha_required": true,
    });
    let register_config = req.register_config.unwrap_or(default_config.clone());

    // 检查域名是否已存在
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM domains WHERE LOWER(name) = LOWER($1))")
        .bind(&req.name)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| { tracing::error!("查询域名失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;
    if exists {
        return Err((StatusCode::CONFLICT, "域名已存在".to_string()));
    }

    let row = sqlx::query_as::<_, (i32, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO domains (name, dkim_selector, dkim_private_key, dkim_public_key, default_quota_mb, register_config, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at"
    )
    .bind(&req.name)
    .bind(&dkim_selector)
    .bind(&private_key)
    .bind(&public_key)
    .bind(req.default_quota_mb.unwrap_or(1024))
    .bind(&register_config)
    .bind(&req.notes)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DomainResponse {
        id: row.0,
        name: req.name,
        enabled: true,
        dkim_selector,
        dkim_public_key: Some(public_key),
        mx_verified: false,
        spf_verified: false,
        dkim_verified: false,
        dmarc_verified: false,
        default_quota_mb: req.default_quota_mb.unwrap_or(1024),
        register_config,
        notes: req.notes,
        setup_completed: false,
        created_at: row.1.to_rfc3339(),
    }))
}

async fn get_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Json<DomainResponse>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let row = sqlx::query_as::<_, (i32, String, bool, String, Option<String>, bool, bool, bool, bool, i32, serde_json::Value, Option<String>, bool, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed, created_at FROM domains WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "查询域名失败".to_string()))?;

    match row {
        Some((id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed, created_at)) => {
            Ok(Json(DomainResponse {
                id, name, enabled, dkim_selector, dkim_public_key, mx_verified, spf_verified, dkim_verified, dmarc_verified, default_quota_mb, register_config, notes, setup_completed,
                created_at: created_at.to_rfc3339(),
            }))
        }
        None => Err((StatusCode::NOT_FOUND, "域名不存在".to_string())),
    }
}

async fn update_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // register_config 整体替换：传了就整体写，不传则保持原值
    let result = if let Some(cfg) = req.register_config.as_ref() {
        sqlx::query(
            "UPDATE domains SET
                enabled = COALESCE($2, enabled),
                dkim_selector = COALESCE($3, dkim_selector),
                default_quota_mb = COALESCE($4, default_quota_mb),
                register_config = $5,
                notes = COALESCE($6, notes),
                updated_at = NOW()
             WHERE id = $1"
        )
        .bind(id)
        .bind(req.enabled)
        .bind(req.dkim_selector)
        .bind(req.default_quota_mb)
        .bind(cfg)
        .bind(req.notes)
        .execute(&state.pool)
        .await
    } else {
        sqlx::query(
            "UPDATE domains SET
                enabled = COALESCE($2, enabled),
                dkim_selector = COALESCE($3, dkim_selector),
                default_quota_mb = COALESCE($4, default_quota_mb),
                notes = COALESCE($5, notes),
                updated_at = NOW()
             WHERE id = $1"
        )
        .bind(id)
        .bind(req.enabled)
        .bind(req.dkim_selector)
        .bind(req.default_quota_mb)
        .bind(req.notes)
        .execute(&state.pool)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "域名不存在".to_string()));
    }

    Ok(StatusCode::OK)
}

async fn delete_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    // 先获取域名信息（用于清理磁盘文件）
    let domain_name: String = sqlx::query_scalar("SELECT name FROM domains WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "域名不存在".to_string()))?;

    // 删除关联的邮箱（数据库）
    // 使用事务确保删除操作的原子性
    let mut tx = state.pool.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query("DELETE FROM mailboxes WHERE domain_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 删除关联的证书：精确匹配域名或子域名（%.domain_name）
    // 不用 domain_name%（前缀匹配）避免误删：删除 u3u.fun 会误删 u3u.funnel.com
    sqlx::query("DELETE FROM certs WHERE domain = $1 OR domain LIKE $2")
        .bind(&domain_name)
        .bind(format!("%.{}", domain_name))
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 删除域名记录
    let result = sqlx::query("DELETE FROM domains WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "域名不存在".to_string()));
    }

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 清理磁盘上的 Maildir（异步，失败不阻塞）
    let maildir_path = std::path::Path::new("/var/lib/funmail/maildir").join(&domain_name);
    if maildir_path.exists() {
        if let Err(e) = std::fs::remove_dir_all(&maildir_path) {
            tracing::warn!("清理域名 {} 的 Maildir 失败: {}", domain_name, e);
        }
    }

    tracing::info!("域名已删除: {} (已清理邮箱和证书)", domain_name);
    Ok(StatusCode::OK)
}

// ============ DNS 向导相关 API ============

/// DNS 记录引导信息
#[derive(Serialize, Clone)]
pub struct DnsRecordGuide {
    pub record_type: String,   // A, MX, TXT, CNAME, SRV
    pub host: String,          // 记录主机名
    pub value: String,         // 记录值
    pub priority: Option<i32>, // MX/SRV 优先级
    pub port: Option<i32>,     // SRV 端口
    pub description: String,   // 说明
    pub verified: bool,        // 是否已验证通过
    pub required: bool,        // 是否必须
}

/// DNS 引导响应
#[derive(Serialize)]
pub struct DnsGuideResponse {
    pub domain: String,
    pub server_ip: String,
    pub records: Vec<DnsRecordGuide>,
    pub all_verified: bool,
}

/// 获取域名需要的 DNS 记录列表（自动验证）
async fn dns_guide(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Json<DnsGuideResponse>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    // 复用验证逻辑
    let (records, server_ip, domain_name) = verify_domain_dns(&state.pool, id).await?;
    
    let all_verified = records.iter().filter(|r| r.required).all(|r| r.verified);

    Ok(Json(DnsGuideResponse {
        domain: domain_name,
        server_ip,
        records,
        all_verified,
    }))
}

/// DNS 验证结果
#[derive(Serialize)]
pub struct DnsVerifyResponse {
    pub records: Vec<DnsRecordGuide>,
    pub all_verified: bool,
}

/// 共享的 DNS 验证逻辑，返回 (records, server_ip, domain_name)
async fn verify_domain_dns(
    pool: &sqlx::PgPool,
    domain_id: i32,
) -> Result<(Vec<DnsRecordGuide>, String, String), (StatusCode, String)> {
    let domain: (String, String, Option<String>) = sqlx::query_as(
        "SELECT name, dkim_selector, dkim_public_key FROM domains WHERE id = $1"
    )
    .bind(domain_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "域名不存在".to_string()))?;

    let (domain_name, dkim_selector, dkim_public_key) = domain;
    let server_ip = get_server_ip().await;
    let dkim_txt_value = build_dkim_txt(&dkim_selector, dkim_public_key.as_deref());

    let mut records = Vec::new();

    // === 必须记录 ===
    // 验证 A 记录
    for (host, desc) in [
        (format!("mail.{}", domain_name), "邮件服务器地址"),
        (format!("smtp.{}", domain_name), "SMTP 发信服务器地址"),
        (format!("pop.{}", domain_name), "POP3 收信服务器地址"),
        (format!("imap.{}", domain_name), "IMAP 收信服务器地址"),
    ] {
        let verified = verify_a_record(&host, &server_ip).await;
        records.push(DnsRecordGuide {
            record_type: "A".to_string(),
            host,
            value: server_ip.clone(),
            priority: None,
            port: None,
            description: desc.to_string(),
            verified,
            required: true,
        });
    }

    // 验证 MX 记录
    let mx_verified = verify_mx_record(&domain_name, &format!("mail.{}", domain_name)).await;
    records.push(DnsRecordGuide {
        record_type: "MX".to_string(),
        host: domain_name.clone(),
        value: format!("mail.{}", domain_name),
        priority: Some(10),
        port: None,
        description: "邮件交换记录，指定收信服务器。主机记录填 @".to_string(),
        verified: mx_verified,
        required: true,
    });

    // 验证 SPF
    let spf_verified = verify_spf_record(&domain_name, &server_ip).await;
    records.push(DnsRecordGuide {
        record_type: "TXT".to_string(),
        host: domain_name.clone(),
        value: format!("v=spf1 mx a ip4:{} -all", server_ip),
        priority: None,
        port: None,
        description: "SPF 发件人策略，防止邮件被拒收。主机记录填 @".to_string(),
        verified: spf_verified,
        required: true,
    });

    // 验证 DKIM（检查 DNS 记录中的公钥与数据库一致）
    let expected_pubkey = dkim_public_key.clone().unwrap_or_default();
    let dkim_verified = verify_dkim_record(&domain_name, &dkim_selector, &expected_pubkey).await;
    records.push(DnsRecordGuide {
        record_type: "TXT".to_string(),
        host: format!("{}._domainkey.{}", dkim_selector, domain_name),
        value: dkim_txt_value,
        priority: None,
        port: None,
        description: "DKIM 签名验证，防止邮件被篡改。主机记录格式：selector._domainkey".to_string(),
        verified: dkim_verified,
        required: true,
    });

    // 验证 DMARC
    let dmarc_verified = verify_dmarc_record(&domain_name).await;
    records.push(DnsRecordGuide {
        record_type: "TXT".to_string(),
        host: format!("_dmarc.{}", domain_name),
        value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@".to_string() + &domain_name,
        priority: None,
        port: None,
        description: "DMARC 邮件认证策略。主机记录填 _dmarc".to_string(),
        verified: dmarc_verified,
        required: true,
    });

    // === 推荐记录（可选） ===
    let autodiscover_verified = verify_cname_record(&format!("autodiscover.{}", domain_name), &format!("mail.{}", domain_name)).await;
    records.push(DnsRecordGuide {
        record_type: "CNAME".to_string(),
        host: format!("autodiscover.{}", domain_name),
        value: format!("mail.{}", domain_name),
        priority: None,
        port: None,
        description: "Outlook/Apple Mail 自动发现配置。主机记录填 autodiscover".to_string(),
        verified: autodiscover_verified,
        required: false,
    });

    let autoconfig_verified = verify_cname_record(&format!("autoconfig.{}", domain_name), &format!("mail.{}", domain_name)).await;
    records.push(DnsRecordGuide {
        record_type: "CNAME".to_string(),
        host: format!("autoconfig.{}", domain_name),
        value: format!("mail.{}", domain_name),
        priority: None,
        port: None,
        description: "Thunderbird 自动配置。主机记录填 autoconfig".to_string(),
        verified: autoconfig_verified,
        required: false,
    });

    let srv_verified = verify_srv_record(&domain_name, &format!("mail.{}", domain_name)).await;
    records.push(DnsRecordGuide {
        record_type: "SRV".to_string(),
        host: format!("_autodiscover._tcp.{}", domain_name),
        value: format!("mail.{}", domain_name),
        priority: Some(0),
        port: Some(443),
        description: "SRV 自动发现服务。主机记录格式：_autodiscover._tcp".to_string(),
        verified: srv_verified,
        required: false,
    });

    // 更新数据库验证状态
    let _ = sqlx::query(
        "UPDATE domains SET mx_verified = $2, spf_verified = $3, dkim_verified = $4, dmarc_verified = $5, updated_at = NOW() WHERE id = $1"
    )
    .bind(domain_id)
    .bind(mx_verified)
    .bind(spf_verified)
    .bind(dkim_verified)
    .bind(dmarc_verified)
    .execute(pool)
    .await;

    Ok((records, server_ip, domain_name))
}

/// 验证域名 DNS 记录
async fn verify_dns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Json<DnsVerifyResponse>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let (records, _, _) = verify_domain_dns(&state.pool, id).await?;
    let all_verified = records.iter().filter(|r| r.required).all(|r| r.verified);

    Ok(Json(DnsVerifyResponse {
        records,
        all_verified,
    }))
}

/// 生成自签名证书（内网测试用）
async fn generate_self_signed_certs(
    state: Arc<AppState>,
    domain_id: i32,
    base_domain: &str,
    need_cert: &[String],
    existing_certs: &[String],
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut results = Vec::new();

    for domain in need_cert {
        let sans = if domain != base_domain {
            vec![domain.clone(), base_domain.to_string()]
        } else {
            vec![domain.clone()]
        };

        let cert = rcgen::generate_simple_self_signed(sans).map_err(|e| {
            tracing::error!("自签名证书生成失败: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "证书生成失败".to_string())
        })?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(365);

        sqlx::query(
            "INSERT INTO certs (domain, cert_pem, key_pem, issuer, expires_at, auto_renew, notes)
             VALUES ($1, $2, $3, 'Self-Signed', $4, FALSE, '自签名证书（内网测试用）')"
        )
        .bind(domain)
        .bind(&cert_pem)
        .bind(&key_pem)
        .bind(expires_at)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("自签名证书保存失败: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "证书保存失败".to_string())
        })?;

        results.push(domain.clone());
    }

    // 标记域名设置完成
    sqlx::query("UPDATE domains SET setup_completed = true, updated_at = NOW() WHERE id = $1")
        .bind(domain_id)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("更新域名状态失败: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string())
        })?;

    let mut all = existing_certs.to_vec();
    all.extend(results.clone());

    Ok(Json(serde_json::json!({
        "message": format!("已生成 {} 个自签名证书", results.len()),
        "domains": all,
        "method": "self-signed",
    })))
}

/// 全部 DNS 验证通过后，申请证书
#[derive(Deserialize)]
struct SetupCertRequest {
    /// "acme" (default) or "self-signed"
    #[serde(default)]
    method: Option<String>,
}

async fn setup_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i32>,
    Json(req): Json<SetupCertRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let claims = auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    auth_routes::require_admin_role(&claims)?;
    let method = req.method.unwrap_or_else(|| "acme".to_string());

    // 检查 DNS 是否全部验证通过
    let verified: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT mx_verified, spf_verified, dkim_verified, dmarc_verified FROM domains WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "域名不存在".to_string()))?;

    if !verified.0 || !verified.1 || !verified.2 || !verified.3 {
        return Err((StatusCode::BAD_REQUEST, "DNS 记录尚未全部验证通过".to_string()));
    }

    // 获取域名
    let domain_name: String = sqlx::query_scalar(
        "SELECT name FROM domains WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 初始化进度（MX记录域名不申请SSL证书）
    let all_domains = vec![
        format!("mail.{}", domain_name),
        format!("smtp.{}", domain_name),
        format!("pop.{}", domain_name),
        format!("imap.{}", domain_name),
    ];

    // 查询已有证书的域名，重新申请时跳过
    let existing_certs: Vec<String> = sqlx::query_scalar(
        "SELECT domain FROM certs WHERE domain = ANY($1)"
    )
    .bind(&all_domains)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // 需要申请的域名（排除已有证书的）
    let need_cert: Vec<String> = all_domains.iter()
        .filter(|d| !existing_certs.contains(d))
        .cloned()
        .collect();

    if need_cert.is_empty() {
        return Ok(Json(serde_json::json!({
            "message": "所有域名证书已存在，无需重新申请",
            "existing": existing_certs,
        })));
    }

    // ========== 自签名证书（内网测试用）==========
    if method == "self-signed" {
        return generate_self_signed_certs(state, id, &domain_name, &need_cert, &existing_certs).await;
    }

    // ========== ACME 证书（默认）==========
    {
        let mut progress = state.cert_progress.write().await;
        // 已有证书的域名标记为成功
        for d in &existing_certs {
            progress.insert(d.clone(), crate::state::CertProgress {
                domain: d.clone(),
                status: "done".to_string(),
                message: "证书已存在，跳过".to_string(),
                success: true,
                done: true,
                step: 9,
                total_steps: 9,
                step_name: "完成".to_string(),
                detail: "证书已存在，跳过申请".to_string(),
                error: None,
            });
        }
        // 需要申请的域名标记为等待
        for d in &need_cert {
            progress.insert(d.clone(), crate::state::CertProgress {
                domain: d.clone(),
                status: "pending".to_string(),
                message: "等待申请...".to_string(),
                success: false,
                done: false,
                step: 0,
                total_steps: 9,
                step_name: "等待".to_string(),
                detail: "等待申请...".to_string(),
                error: None,
            });
        }
    }

    // 在后台任务中顺序申请证书，某个失败则终止后续申请
    let pool = state.pool.clone();
    let progress_map = state.cert_progress.clone();
    let domain_id = id;
    let spawn_domains = need_cert.clone();
    tokio::spawn(async move {
        let mut aborted = false;
        for (i, d) in spawn_domains.iter().enumerate() {
            // 如果已经中止，将剩余域名标记为失败
            if aborted {
                let mut p = progress_map.write().await;
                p.insert(d.clone(), crate::state::CertProgress {
                    domain: d.clone(),
                    status: "failed".to_string(),
                    message: "因前序域名验证失败而中止".to_string(),
                    success: false,
                    done: true,
                    step: 0,
                    total_steps: 9,
                    step_name: "已中止".to_string(),
                    detail: "因前序域名验证失败而中止，请检查：1) 80端口是否对外开放 2) 域名是否已备案 3) DNS是否已正确解析到本服务器".to_string(),
                    error: Some("因前序域名验证失败而中止，请检查：1) 80端口是否对外开放 2) 域名是否已备案 3) DNS是否已正确解析到本服务器".to_string()),
                });
                continue;
            }

            // 更新进度：正在申请
            {
                let mut p = progress_map.write().await;
                p.insert(d.clone(), crate::state::CertProgress {
                    domain: d.clone(),
                    status: "requesting".to_string(),
                    message: format!("正在申请证书 ({}/{})...", i + 1, spawn_domains.len()),
                    success: false,
                    done: false,
                    step: 0,
                    total_steps: 9,
                    step_name: "初始化".to_string(),
                    detail: "正在准备申请证书...".to_string(),
                    error: None,
                });
            }

            match crate::acme::request_certificate(&pool, d, true, Some(progress_map.clone())).await {
                Ok(cert_id) => {
                    let mut p = progress_map.write().await;
                    p.insert(d.clone(), crate::state::CertProgress {
                        domain: d.clone(),
                        status: "done".to_string(),
                        message: format!("证书申请成功 (id={})", cert_id),
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
                    p.insert(d.clone(), crate::state::CertProgress {
                        domain: d.clone(),
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
                    // 中止后续域名的申请
                    aborted = true;
                }
            }
        }

        // 检查是否所有证书都申请成功，只有全部成功才标记域名设置完成
        {
            let progress = progress_map.read().await;
            let all_success = progress.values().all(|p| p.done && p.success);
            if all_success {
                let _ = sqlx::query("UPDATE domains SET setup_completed = true, updated_at = NOW() WHERE id = $1")
                    .bind(domain_id)
                    .execute(&pool)
                    .await;
            }
        }
    });

    Ok(Json(serde_json::json!({
        "message": "证书申请已开始",
        "domains": all_domains,
    })))
}

/// 查询证书申请进度
async fn cert_progress(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    auth_routes::extract_admin_claims(&headers, &state.jwt_secret)
        .map_err(|s| (s, "未登录".to_string()))?;
    let progress = state.cert_progress.read().await;
    let items: Vec<&crate::state::CertProgress> = progress.values().collect();
    Ok(Json(serde_json::json!({
        "progress": items,
        "all_done": items.iter().all(|p| p.status == "done" || p.status == "failed"),
        "all_success": items.iter().all(|p| p.success),
    })))
}

// ============ DNS 验证工具函数 ============

/// 获取服务器公网 IP
async fn get_server_ip() -> String {
    // 优先从环境变量读取（安装脚本写入 .env）
    if let Ok(ip) = std::env::var("SERVER_IP") {
        if !ip.is_empty() && ip != "YOUR_SERVER_IP" {
            return ip;
        }
    }
    // 从本地网卡获取（排除私有/回环地址）
    if let Ok(output) = tokio::process::Command::new("hostname")
        .arg("-I")
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(ip) = stdout.split_whitespace().find(|s| !is_private_ip(s)) {
            return ip.to_string();
        }
    }
    // 通过外部 API 获取公网 IP（容器内 hostname -I 返回内部 IP 时的备选方案）
    for url in &[
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://ip.sb",
    ] {
        if let Ok(resp) = reqwest::get(*url).await {
            if let Ok(ip) = resp.text().await {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && !is_private_ip(&ip) {
                    return ip;
                }
            }
        }
    }
    "YOUR_SERVER_IP".to_string()
}

/// 判断是否为私有/回环 IP 地址（RFC 1918 + 回环 + 链路本地）
fn is_private_ip(s: &str) -> bool {
    let ip: std::net::Ipv4Addr = match s.parse() {
        Ok(ip) => ip,
        Err(_) => return true, // 无法解析的视为无效
    };
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

/// 构建 DKIM TXT 记录值
fn build_dkim_txt(_selector: &str, public_key_b64: Option<&str>) -> String {
    // public_key_b64 已是 base64 编码的 SPKI DER，直接拼入 DKIM TXT 记录
    if let Some(b64) = public_key_b64 {
        if !b64.is_empty() {
            format!("v=DKIM1; k=rsa; p={}", b64)
        } else {
            format!("v=DKIM1; k=rsa; p=<public_key>")
        }
    } else {
        format!("v=DKIM1; k=rsa; p=<public_key>")
    }
}

/// 创建 DNS resolver（禁用缓存，确保验证时读取最新记录）
fn make_resolver() -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::config::{ResolverOpts, NameServerConfigGroup};
    use std::time::Duration;

    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.positive_min_ttl = Some(Duration::ZERO);
    opts.positive_max_ttl = Some(Duration::ZERO);
    opts.negative_min_ttl = Some(Duration::ZERO);
    opts.negative_max_ttl = Some(Duration::ZERO);
    opts.attempts = 1;
    opts.timeout = Duration::from_secs(3);

    // 直接使用公共 DNS 服务器，绕过本地系统缓存
    let nameservers = NameServerConfigGroup::from_ips_clear(
        &[
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 4, 4)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(114, 114, 114, 114)),
        ],
        53,
        false,
    );

    let config = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], nameservers);

    Some(
        hickory_resolver::Resolver::builder_with_config(config, hickory_resolver::name_server::TokioConnectionProvider::default())
            .with_options(opts)
            .build()
    )
}

/// 验证 A 记录
async fn verify_a_record(hostname: &str, expected_ip: &str) -> bool {
    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.ipv4_lookup(hostname).await {
        Ok(ips) => {
            for ip in ips.iter() {
                if ip.to_string() == expected_ip {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 验证 MX 记录
async fn verify_mx_record(domain: &str, expected_mail_host: &str) -> bool {
    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.mx_lookup(domain).await {
        Ok(mx_records) => {
            for mx in mx_records.iter() {
                if mx.exchange().to_string().trim_end_matches('.') == expected_mail_host.trim_end_matches('.') {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 验证 SPF 记录
async fn verify_spf_record(domain: &str, server_ip: &str) -> bool {
    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.txt_lookup(domain).await {
        Ok(txt_records) => {
            for txt in txt_records.iter() {
                let txt_str = txt.to_string();
                if txt_str.starts_with("v=spf1") && txt_str.contains(server_ip) {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 验证 DKIM 记录：检查 DNS 中存在 DKIM 记录且 p= 公钥值与数据库一致
async fn verify_dkim_record(domain: &str, selector: &str, expected_public_key_b64: &str) -> bool {
    let dkim_host = format!("{}._domainkey.{}", selector, domain);

    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.txt_lookup(&dkim_host).await {
        Ok(txt_records) => {
            for txt in txt_records.iter() {
                let txt_str = txt.to_string();
                if txt_str.starts_with("v=DKIM1") {
                    // 如果数据库没有公钥（旧数据），只检查记录存在
                    if expected_public_key_b64.is_empty() {
                        return true;
                    }
                    // 从 DNS 记录中提取 p= 值，与数据库中的公钥对比
                    let dns_pubkey = extract_dkim_tag(&txt_str, "p");
                    if !dns_pubkey.is_empty() && dns_pubkey == expected_public_key_b64 {
                        return true;
                    }
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 从 DKIM TXT 记录中提取指定标签的值（如 p=, k=）
fn extract_dkim_tag(record: &str, tag: &str) -> String {
    let prefix = format!("{}=", tag);
    for part in record.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&prefix) {
            return value.trim().to_string();
        }
    }
    String::new()
}

/// 验证 DMARC 记录
async fn verify_dmarc_record(domain: &str) -> bool {
    let dmarc_host = format!("_dmarc.{}", domain);

    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.txt_lookup(&dmarc_host).await {
        Ok(txt_records) => {
            for txt in txt_records.iter() {
                let txt_str = txt.to_string();
                if txt_str.starts_with("v=DMARC1") {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 验证 CNAME 记录
async fn verify_cname_record(hostname: &str, expected_target: &str) -> bool {
    use hickory_proto::rr::RecordType;

    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.lookup(hostname, RecordType::CNAME).await {
        Ok(lookup) => {
            let expected = expected_target.trim_end_matches('.');
            for record in lookup.record_iter() {
                let rdata = record.data();
                let rdata_str = rdata.to_string();
                // CNAME rdata 格式为 "CNAME(target.example.com.)"
                if rdata_str.contains(expected) {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// 验证 SRV 记录
async fn verify_srv_record(domain: &str, expected_target: &str) -> bool {
    let srv_host = format!("_autodiscover._tcp.{}", domain);

    let resolver = match make_resolver() {
        Some(r) => r,
        None => return false,
    };

    match resolver.srv_lookup(&srv_host).await {
        Ok(srv_records) => {
            let expected = expected_target.trim_end_matches('.');
            for srv in srv_records.iter() {
                if srv.target().to_string().trim_end_matches('.') == expected {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}
