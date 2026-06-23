/// ACME 证书自动申请与续签 (Let's Encrypt)
/// 使用 instant-acme 0.7 实现 HTTP-01 验证

use instant_acme::{Account, BytesResponse, HttpClient};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use http_body_util::BodyExt;

/// Let's Encrypt 目录 URL
const LE_PROD: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// 带超时的 reqwest HTTP 客户端适配器
#[derive(Clone)]
struct ReqwestClient {
    client: reqwest::Client,
}

impl ReqwestClient {
    fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client })
    }
}

/// 简单的 body 实现
struct SimpleBody(bytes::Bytes);

#[async_trait::async_trait]
impl instant_acme::BytesBody for SimpleBody {
    async fn into_bytes(&mut self) -> Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.clone())
    }
}

impl HttpClient for ReqwestClient {
    fn request(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let url: reqwest::Url = parts.uri.to_string().parse()
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            let mut req_builder = client.request(parts.method, url);
            for (key, value) in parts.headers.iter() {
                req_builder = req_builder.header(key, value);
            }

            let collected = body.collect().await
                .map_err(|e| instant_acme::Error::Other(e.into()))?;
            let body_bytes = collected.to_bytes();

            let resp = req_builder
                .body(body_bytes.to_vec())
                .send()
                .await
                .map_err(|e| instant_acme::Error::Other(e.into()))?;

            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let body = resp.bytes().await
                .map_err(|e| instant_acme::Error::Other(e.into()))?;

            let mut resp_builder = http::Response::builder()
                .status(status);

            for (key, value) in resp_headers.iter() {
                resp_builder = resp_builder.header(key, value);
            }

            let response = resp_builder.body(())
                .map_err(|e| instant_acme::Error::Other(e.into()))?;

            let (parts, _) = response.into_parts();

            Ok(BytesResponse {
                parts,
                body: Box::new(SimpleBody(body)),
            })
        })
    }
}

/// 证书申请进度类型
type CertProgressMap = Arc<RwLock<HashMap<String, crate::state::CertProgress>>>;

/// 更新进度信息
fn update_progress(progress: Option<&CertProgressMap>, domain: &str, step: u8, step_name: &str, detail: &str) {
    if let Some(progress_map) = progress {
        if let Ok(mut map) = progress_map.try_write() {
            if let Some(p) = map.get_mut(domain) {
                p.step = step;
                p.step_name = step_name.to_string();
                p.detail = detail.to_string();
                p.message = format!("{}: {}", step_name, detail);
            }
        }
    }
}

/// 完成进度（成功或失败）
fn finish_progress(progress: Option<&CertProgressMap>, domain: &str, error: Option<&str>) {
    if let Some(progress_map) = progress {
        if let Ok(mut map) = progress_map.try_write() {
            if let Some(p) = map.get_mut(domain) {
                p.done = true;
                p.step = p.total_steps;
                p.step_name = if error.is_some() { "申请失败".to_string() } else { "申请完成".to_string() };
                p.detail = error.unwrap_or("证书已成功签发并保存").to_string();
                p.error = error.map(|s| s.to_string());
                p.message = if error.is_some() {
                    format!("申请失败: {}", error.unwrap())
                } else {
                    "证书申请成功".to_string()
                };
            }
        }
    }
}

pub async fn check_renewals(pool: &PgPool, staging: bool) -> anyhow::Result<()> {
    let certs = sqlx::query_as::<_, (i32, String)>(
        "SELECT id, domain FROM certs
         WHERE auto_renew = true AND issuer = 'ACME' AND expires_at < NOW() + INTERVAL '30 days'"
    )
    .fetch_all(pool)
    .await?;

    for (cert_id, domain) in &certs {
        tracing::info!("证书即将过期，尝试续签: {} (id={})", domain, cert_id);
        match renew_certificate(pool, domain, *cert_id, staging, None).await {
            Ok(()) => tracing::info!("证书续签成功: {}", domain),
            Err(e) => tracing::warn!("证书续签失败 {}: {}", domain, e),
        }
    }

    Ok(())
}

pub async fn renew_certificate(
    pool: &PgPool,
    domain: &str,
    cert_id: i32,
    staging: bool,
    progress: Option<CertProgressMap>,
) -> anyhow::Result<()> {
    let dir_url = if staging { LE_STAGING } else { LE_PROD };
    let (cert_pem, key_pem) = request_acme_cert(pool, domain, dir_url, progress.as_ref()).await?;

    let expires_at = chrono::Utc::now() + chrono::Duration::days(90);

    sqlx::query(
        "UPDATE certs SET cert_pem = $1, key_pem = $2, expires_at = $3, issuer = 'ACME', updated_at = NOW() WHERE id = $4"
    )
    .bind(&cert_pem)
    .bind(&key_pem)
    .bind(expires_at)
    .bind(cert_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 为新域名申请证书（必须使用ACME，不回退到自签名证书）
pub async fn request_certificate(
    pool: &PgPool,
    domain: &str,
    auto_renew: bool,
    progress: Option<CertProgressMap>,
) -> anyhow::Result<i32> {
    // 尝试 ACME 申请，最多 180 秒超时
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(180),
        request_acme_cert(pool, domain, LE_PROD, progress.as_ref())
    ).await;

    let (cert_pem, key_pem) = match result {
        Ok(Ok((cert, key))) => {
            (cert, key)
        }
        Ok(Err(e)) => {
            let error_msg = e.to_string();
            finish_progress(progress.as_ref(), domain, Some(&error_msg));
            return Err(e);
        }
        Err(_) => {
            let error_msg = "ACME证书申请超时（180秒）".to_string();
            finish_progress(progress.as_ref(), domain, Some(&error_msg));
            return Err(anyhow::anyhow!(error_msg));
        }
    };

    let expires_at = chrono::Utc::now() + chrono::Duration::days(90);

    let id: i32 = sqlx::query_scalar(
        "INSERT INTO certs (domain, cert_pem, key_pem, issuer, expires_at, auto_renew)
         VALUES ($1, $2, $3, 'ACME', $4, $5)
         ON CONFLICT (domain) DO UPDATE SET cert_pem = $2, key_pem = $3, issuer = 'ACME', expires_at = $4, auto_renew = $5, updated_at = NOW()
         RETURNING id"
    )
    .bind(domain)
    .bind(&cert_pem)
    .bind(&key_pem)
    .bind(expires_at)
    .bind(auto_renew)
    .fetch_one(pool)
    .await?;

    // 证书已写入数据库后再标记完成，确保前端刷新列表时能查到
    finish_progress(progress.as_ref(), domain, None);

    Ok(id)
}

/// 使用 ACME 协议申请 Let's Encrypt 证书 (HTTP-01 验证)
async fn request_acme_cert(
    pool: &PgPool,
    domain: &str,
    dir_url: &str,
    progress: Option<&CertProgressMap>,
) -> anyhow::Result<(String, String)> {
    use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder};

    tracing::info!("ACME: 开始为域名 {} 申请证书", domain);
    update_progress(progress, domain, 1, "预检测试", "正在验证域名解析和 80 端口可达性...");

    // 0. 预检：验证域名 → 80 端口完整链路
    let test_url = format!("http://{}/.well-known/acme-challenge/test", domain);
    let resolved_ip = tokio::net::lookup_host(format!("{}:80", domain))
        .await
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "未知".to_string());

    match reqwest::get(&test_url).await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // 只要 HTTP 200 且有响应内容即视为预检通过
            if status.is_success() && !body.trim().is_empty() {
                tracing::info!("ACME: 预检通过，域名 {} 的 80 端口可达（解析到 {}）", domain, resolved_ip);
            } else {
                tracing::error!("ACME: 预检失败！访问 {} 返回状态 {}，内容: {}", test_url, status, body);
                return Err(anyhow::anyhow!(
                    "ACME 预检失败：访问 {} 返回状态 {}（内容: {}）。\n\
                     域名解析到: {}\n\
                     请检查：\n\
                     1. 域名 DNS 是否正确解析到本服务器\n\
                     2. 80 端口是否对外开放\n\
                     3. 云服务商安全组是否允许所有来源 IP 访问 80 端口\n\
                     4. 是否有 CDN/WAF/防火墙拦截了部分请求\n\
                     5. funmail-admin 是否正常监听 80 端口",
                    test_url, status, body, resolved_ip
                ));
            }
        }
        Err(e) => {
            tracing::error!("ACME: 预检失败！无法访问 {}: {}", test_url, e);
            return Err(anyhow::anyhow!(
                "ACME 预检失败：无法连接 {}（{}）。\n\
                 域名解析到: {}\n\
                 请检查：\n\
                 1. 域名 DNS 是否正确解析\n\
                 2. 80 端口是否对外开放\n\
                 3. 云服务商安全组设置",
                test_url, e, resolved_ip
            ));
        }
    }

    // 1. 创建或加载 ACME 账号
    tracing::info!("ACME: 正在获取/创建账号...");
    update_progress(progress, domain, 2, "创建账号", "正在向 Let's Encrypt 注册/获取账号...");
    let account = get_or_create_account(pool, dir_url).await?;
    tracing::info!("ACME: 账号准备完成");

    // 2. 创建订单
    tracing::info!("ACME: 正在创建订单...");
    update_progress(progress, domain, 3, "创建订单", "正在向 Let's Encrypt 提交证书申请订单...");
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder {
        identifiers: &identifiers,
    }).await?;
    tracing::info!("ACME: 订单创建成功");
    update_progress(progress, domain, 4, "获取验证挑战", "订单已创建，正在获取域名验证信息...");

    // 3. 获取验证挑战
    tracing::info!("ACME: 正在获取验证挑战...");
    let authorizations = order.authorizations().await?;
    tracing::info!("ACME: 获取到 {} 个授权", authorizations.len());
    for authz in &authorizations {
        if authz.status == AuthorizationStatus::Valid {
            tracing::info!("ACME: 域名 {} 已验证，跳过", domain);
            continue;
        }

        // 找到 HTTP-01 挑战
        let challenge = authz.challenges.iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("没有 HTTP-01 挑战可用"))?;

        let key_auth = order.key_authorization(challenge);

        // 4. 将挑战写入数据库，供 .well-known/acme-challenge/ 路由返回
        tracing::info!("ACME: 保存验证令牌到数据库...");
        tracing::info!("ACME: 验证 URL: http://{}/.well-known/acme-challenge/{}", domain, challenge.token);
        tracing::info!("ACME: Key Auth: {}", key_auth.as_str());
        update_progress(progress, domain, 5, "配置域名验证", "已保存验证令牌，准备响应验证请求...");
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(30);
        sqlx::query(
            "INSERT INTO acme_challenges (domain, token, key_auth, challenge_type, validated, expires_at)
             VALUES ($1, $2, $3, 'http-01', false, $4)
             ON CONFLICT (domain) DO UPDATE SET token = $2, key_auth = $3, validated = false, expires_at = $4"
        )
        .bind(domain)
        .bind(&challenge.token)
        .bind(key_auth.as_str())
        .bind(expires_at)
        .execute(pool)
        .await?;

        // 自检：验证 token 是否可通过外网访问（模拟 CA 的实际验证方式）
        let self_check_url = format!("http://{}/.well-known/acme-challenge/{}", domain, challenge.token);
        match reqwest::get(&self_check_url).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::info!("ACME: 自检通过，token 可访问");
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::error!("ACME: 自检失败！访问 {} 返回状态 {}", self_check_url, status);
                    tracing::error!("ACME: 自检响应内容: {}", body);
                    return Err(anyhow::anyhow!(
                        "ACME 自检失败：访问 {} 返回状态 {}。请检查：\n\
                         1. 域名 DNS 是否正确解析到本服务器\n\
                         2. 80 端口是否对外开放\n\
                         3. funmail-admin 是否正常监听 80 端口\n\
                         4. 查看日志 journalctl -u funmail-admin -n 50",
                        self_check_url, status
                    ));
                }
            }
            Err(e) => {
                tracing::error!("ACME: 自检失败！无法访问 {}: {}", self_check_url, e);
                return Err(anyhow::anyhow!(
                    "ACME 自检失败：无法连接本地 80 端口（{}）。\n\
                     请检查 funmail-admin 服务是否正常运行：systemctl status funmail-admin",
                    e
                ));
            }
        }

        // 5. 通知 ACME 服务器开始验证
        tracing::info!("ACME: 通知服务器开始验证...");
        update_progress(progress, domain, 6, "提交域名验证", "已向 Let's Encrypt 提交 HTTP-01 域名所有权验证...");
        order.set_challenge_ready(&challenge.url).await?;
        tracing::info!("ACME: 等待验证完成...");

        // 6. 等待验证完成（轮询最多 120 秒，检查 order 状态是否变为 Ready）
        let mut validated = false;
        let mut retry_count = 0;
        for i in 0..60 {
            update_progress(progress, domain, 7, "等待验证通过", &format!("CA 正在验证域名所有权... ({}/60)", i + 1));
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let state = match order.refresh().await {
                Ok(s) => s,
                Err(e) => {
                    retry_count += 1;
                    tracing::warn!("ACME: 刷新订单状态失败 ({}), 重试 {}/5", e, retry_count);
                    if retry_count >= 5 {
                        return Err(anyhow::anyhow!("ACME验证失败: 订单状态刷新连续失败 - {}", e));
                    }
                    continue;
                }
            };

            match state.status {
                instant_acme::OrderStatus::Ready => {
                    tracing::info!("ACME: 域名 {} 验证通过", domain);
                    validated = true;
                    break;
                }
                instant_acme::OrderStatus::Invalid => {
                    // 尝试获取授权的详细错误信息
                    let mut error_detail = String::new();
                    if let Ok(auths) = order.authorizations().await {
                        for auth in &auths {
                            for ch in &auth.challenges {
                                if let Some(err) = &ch.error {
                                    error_detail = format!("{:?} - {:?}", err.r#type, err.detail);
                                }
                            }
                        }
                    }
                    if error_detail.is_empty() {
                        error_detail = "域名验证失败，CA无法访问验证URL".to_string();
                    }
                    tracing::error!("ACME: 域名 {} 验证失败: {}", domain, error_detail);
                    // 清理挑战记录
                    sqlx::query("DELETE FROM acme_challenges WHERE domain = $1")
                        .bind(domain)
                        .execute(pool)
                        .await?;
                    return Err(anyhow::anyhow!("ACME 验证失败: {} - {}", domain, error_detail));
                }
                _ => {
                    tracing::debug!("ACME: 订单状态: {:?}", state.status);
                    continue;
                }
            }
        }

        if !validated {
            // 清理挑战记录
            sqlx::query("DELETE FROM acme_challenges WHERE domain = $1")
                .bind(domain)
                .execute(pool)
                .await?;
            return Err(anyhow::anyhow!("ACME 验证超时: {}（CA 未能在120秒内完成验证，请检查80端口是否开放）", domain));
        }
    }

    // 7. 生成 CSR 并完成订单
    tracing::info!("ACME: 生成 CSR...");
    update_progress(progress, domain, 8, "签发证书", "域名验证通过，正在生成 CSR 并提交签发请求...");
    let mut cert_params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    cert_params.distinguished_name.push(rcgen::DnType::CommonName, domain);
    let private_key = rcgen::KeyPair::generate()?;
    let csr = cert_params.serialize_request(&private_key)?;
    let csr_der = csr.der().to_vec();

    order.finalize(&csr_der).await?;
    tracing::info!("ACME: CSR 已提交，等待证书签发...");

    // 8. 等待证书签发
    let mut cert_pem = None;
    for i in 0..30 {
        update_progress(progress, domain, 9, "等待证书下载", &format!("证书正在签发中，即将完成... ({}/30)", i + 1));
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match order.certificate().await {
            Ok(Some(pem)) => {
                tracing::info!("ACME: 证书签发成功: {}", domain);
                cert_pem = Some(pem);
                break;
            }
            Ok(None) => {
                tracing::debug!("ACME: 证书尚未就绪，继续等待...");
                continue;
            }
            Err(e) => {
                tracing::error!("ACME: 获取证书失败: {}", e);
                // 清理挑战记录
                sqlx::query("DELETE FROM acme_challenges WHERE domain = $1")
                    .bind(domain)
                    .execute(pool)
                    .await?;
                return Err(anyhow::anyhow!("获取证书失败: {}", e));
            }
        }
    }

    let cert_pem = cert_pem.ok_or_else(|| anyhow::anyhow!("证书签发超时"))?;
    let key_pem = private_key.serialize_pem();

    // 清理挑战记录
    sqlx::query("DELETE FROM acme_challenges WHERE domain = $1")
        .bind(domain)
        .execute(pool)
        .await?;

    Ok((cert_pem, key_pem))
}

/// 获取或创建 ACME 账号（持久化到数据库）
async fn get_or_create_account(
    pool: &PgPool,
    dir_url: &str,
) -> anyhow::Result<Account> {
    use instant_acme::{AccountCredentials, NewAccount};

    let http = Box::new(ReqwestClient::new()?);

    // 尝试从数据库加载已保存的账号凭证
    let saved: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = 'acme_account'"
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some(creds_json) = saved {
        // 用保存的凭证恢复账号
        if let Ok(creds) = serde_json::from_value::<AccountCredentials>(creds_json) {
            if let Ok(account) = Account::from_credentials_and_http(creds, http.clone()).await {
                return Ok(account);
            }
        }
    }

    // 创建新账号
    let (account, creds) = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        dir_url,
        None,
        http,
    ).await?;

    // 保存账号凭证到数据库
    let creds_json = serde_json::to_value(&creds)?;
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('acme_account', $1)
         ON CONFLICT (key) DO UPDATE SET value = $1"
    )
    .bind(creds_json)
    .execute(pool)
    .await?;

    Ok(account)
}

/// 获取 ACME 挑战响应（供 .well-known/acme-challenge/ 路由使用）
pub async fn get_challenge_response(pool: &PgPool, token: &str) -> Option<String> {
    match sqlx::query_as::<_, (String,)>(
        "SELECT key_auth FROM acme_challenges WHERE token = $1 AND expires_at > NOW()"
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    {
        Ok(Some((key_auth,))) => Some(key_auth),
        Ok(None) => {
            tracing::warn!("ACME: 数据库中未找到 token={}", token);
            None
        }
        Err(e) => {
            tracing::error!("ACME: 查询 token={} 失败: {}", token, e);
            None
        }
    }
}
