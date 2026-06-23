use crate::api::webmail_routes;
use crate::state::AppState;
use axum::body::Body;
use axum::response::Response;
use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use mail_parser::MimeHeaders;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub struct MailLogItem {
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
    pub is_read: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct MailListQuery {
    pub mailbox: Option<String>,   // 过滤特定邮箱地址
    pub domain: Option<String>,    // 过滤特定域名
    pub search: Option<String>,    // 搜索发件人/收件人/主题
    pub status: Option<String>,    // 状态过滤
    pub hours: Option<f64>,        // 时间范围（小时）
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Deserialize)]
pub struct SendMailRequest {
    pub from_addr: String,         // 发件人地址 (必须是本地邮箱)
    pub to_addrs: Vec<String>,     // 收件人列表
    pub cc_addrs: Option<Vec<String>>,  // 抄送列表
    pub subject: String,
    pub body_text: Option<String>,      // 纯文本正文
    pub body_html: Option<String>,      // HTML 正文
    pub attachments: Option<Vec<AttachmentData>>,  // 附件列表
}

#[derive(Deserialize)]
pub struct AttachmentData {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,  // base64 编码的文件内容
}

#[derive(Serialize)]
pub struct SendMailResponse {
    pub success: bool,
    pub message: String,
    pub queued_count: usize,
}

pub fn routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .route("/mail/inbox", axum::routing::get(list_inbox))
        .route("/mail/sent", axum::routing::get(list_sent))
        .route("/mail/send", axum::routing::post(send_mail))
        .route("/mail/detail/{id}", axum::routing::get(mail_detail))
        .route("/mail/attachment/{id}/{index}", axum::routing::get(download_attachment))
}

/// 检查请求是否携带有效 token（admin 或 webmail 均可）
fn check_any_auth(headers: &axum::http::HeaderMap, jwt_secret: &str) -> Result<(), StatusCode> {
    // 先尝试 admin token
    if crate::api::auth_routes::extract_admin_claims(headers, jwt_secret).is_ok() {
        return Ok(());
    }
    // 再尝试 webmail token（仅解析，token_version 由 verify_webmail_claims 异步校验）
    if webmail_routes::extract_claims(headers, jwt_secret).is_ok() {
        return Ok(());
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// 对 webmail token 异步校验 token_version；admin token 直接放行
/// 返回 Some(claims) 表示是 webmail 用户，None 表示是 admin
async fn verify_webmail_if_present(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<Option<webmail_routes::WebmailClaims>, StatusCode> {
    // admin token 直接放行
    if crate::api::auth_routes::extract_admin_claims(headers, &state.jwt_secret).is_ok() {
        return Ok(None);
    }
    // webmail token 需校验 token_version
    webmail_routes::verify_claims(headers, state)
        .await
        .map(Some)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

/// 收件列表：direction = inbound，支持按邮箱/域名过滤
async fn list_inbox(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(mut query): axum::extract::Query<MailListQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let webmail_claims = verify_webmail_if_present(&headers, &state).await?;
    if let Some(claims) = webmail_claims {
        query.mailbox = Some(claims.sub);
        query.domain = None;
    }
    list_mail_logs(&state, query, "inbound").await
}

/// 发件列表：from_addr = 当前用户，支持按邮箱/域名过滤
async fn list_sent(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(mut query): axum::extract::Query<MailListQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let webmail_claims = verify_webmail_if_present(&headers, &state).await?;
    if let Some(claims) = webmail_claims {
        query.mailbox = Some(claims.sub);
        query.domain = None;
    }
    list_mail_logs(&state, query, "sent").await
}

async fn list_mail_logs(
    state: &Arc<AppState>,
    query: MailListQuery,
    direction: &str,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // 搜索时扩大时间范围到 365 天，非搜索默认 7 天
    let hours = query.hours.unwrap_or(if query.search.is_some() { 365.0 * 24.0 } else { 168.0 });
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    // 使用动态 SQL 构建器，参数按顺序绑定
    let mut conditions: Vec<String> = Vec::new();
    let mut param_values: Vec<String> = Vec::new(); // 绑定值（全部用 text 类型）
    let mut param_idx = 1u32;

    // 时间范围（始终为第一个条件）
    conditions.push(format!("created_at > NOW() - (${}::float8 * INTERVAL '1 hour')", param_idx));
    param_values.push(hours.to_string());
    param_idx += 1;

    // direction 或 sent 过滤
    let mailbox_filter = query.mailbox.as_ref().map(|m| m.to_lowercase()).unwrap_or_default();
    if direction == "sent" && !mailbox_filter.is_empty() {
        // 发件箱：按 from_addr 匹配（本地互发邮件也能出现）
        conditions.push(format!("LOWER(from_addr) = ${}", param_idx));
        param_values.push(mailbox_filter.clone());
        param_idx += 1;
    } else if direction == "sent" {
        // 后台管理无 mailbox 时退回 outbound
        conditions.push(format!("direction = ${}", param_idx));
        param_values.push("outbound".to_string());
        param_idx += 1;
    } else {
        conditions.push(format!("direction = ${}", param_idx));
        param_values.push(direction.to_string());
        param_idx += 1;
        // 按邮箱过滤
        if !mailbox_filter.is_empty() {
            if direction == "inbound" {
                conditions.push(format!("LOWER(to_addr) = ${}", param_idx));
            } else {
                conditions.push(format!("LOWER(from_addr) = ${}", param_idx));
            }
            param_values.push(mailbox_filter.clone());
            param_idx += 1;
        }
    }

    // 按域名过滤
    if let Some(ref domain) = query.domain {
        let domain_filter = format!("%@{}%", domain);
        if direction == "inbound" {
            conditions.push(format!("to_addr ILIKE ${}", param_idx));
        } else {
            conditions.push(format!("from_addr ILIKE ${}", param_idx));
        }
        param_values.push(domain_filter);
        param_idx += 1;
    }

    // 状态过滤
    if let Some(ref status) = query.status {
        conditions.push(format!("status = ${}", param_idx));
        param_values.push(status.clone());
        param_idx += 1;
    }

    // 搜索
    if let Some(ref search) = query.search {
        let search_filter = format!("%{}%", search);
        conditions.push(format!(
            "(from_addr ILIKE ${} OR to_addr ILIKE ${} OR subject ILIKE ${})",
            param_idx, param_idx, param_idx
        ));
        param_values.push(search_filter);
        param_idx += 1;
    }

    let where_clause = conditions.join(" AND ");

    // 计数
    let count_sql = format!("SELECT COUNT(*) FROM mail_logs WHERE {}", where_clause);
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for v in &param_values {
        count_q = count_q.bind(v);
    }
    let total: i64 = count_q.fetch_one(&state.pool).await.unwrap_or(0);

    // 查询
    let data_sql = format!(
        "SELECT id, from_addr, to_addr, subject, direction, status, size_bytes, \
         COALESCE(spam_score, 0::real), client_ip, reject_reason, is_read, created_at \
         FROM mail_logs WHERE {} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
        where_clause, param_idx, param_idx + 1
    );
    let mut data_q = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String, i64, f32, Option<String>, Option<String>, bool, chrono::DateTime<chrono::Utc>)>(
        &data_sql
    );
    for v in &param_values {
        data_q = data_q.bind(v);
    }
    data_q = data_q.bind(page_size as i64).bind(offset as i64);

    let rows = data_q.fetch_all(&state.pool).await.map_err(|e| {
        tracing::error!("查询邮件日志失败: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let logs: Vec<MailLogItem> = rows
        .into_iter()
        .map(|(id, from_addr, to_addr, subject, direction, status, size_bytes, spam_score, client_ip, reject_reason, is_read, created_at)| {
            MailLogItem {
                id, from_addr, to_addr, subject, direction, status, size_bytes, spam_score, client_ip, reject_reason, is_read,
                created_at: created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": logs,
        "mails": logs,   // 兼容旧版前端
        "items": logs,   // 兼容旧版前端
    })))
}

/// 发送邮件：构造邮件内容，写入队列
async fn send_mail(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<SendMailRequest>,
) -> Result<Json<SendMailResponse>, (StatusCode, String)> {
    let webmail_claims = verify_webmail_if_present(&headers, &state).await
        .map_err(|s| (s, "未登录".to_string()))?;
    // Webmail 用户只能以自己的邮箱发件（强制 from_addr = JWT.sub）
    if let Some(claims) = &webmail_claims {
        req.from_addr = claims.sub.clone();
    }
    // 验证发件人是本地邮箱
    let from_parts: Vec<&str> = req.from_addr.rsplitn(2, '@').collect();
    if from_parts.len() != 2 {
        return Err((StatusCode::BAD_REQUEST, "发件人地址格式无效".to_string()));
    }
    // 防止邮件头注入：发件人地址不允许包含 CRLF
    if req.from_addr.contains('\r') || req.from_addr.contains('\n') {
        return Err((StatusCode::BAD_REQUEST, "发件人地址包含非法字符".to_string()));
    }
    let from_user = from_parts[1];
    let from_domain = from_parts[0];

    // 验证邮箱存在且启用，同时取出协议权限配置
    let mailbox_row: Option<(bool, Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
        "SELECT m.enabled, m.protocols, d.register_config
         FROM mailboxes m JOIN domains d ON m.domain_id = d.id
         WHERE m.username = $1 AND d.name = $2 AND m.enabled = true AND d.enabled = true"
    )
    .bind(from_user)
    .bind(from_domain)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (mailbox_exists, mailbox_protocols, register_config) = match mailbox_row {
        Some(r) => r,
        None => (false, None, serde_json::json!({})),
    };

    if !mailbox_exists {
        return Err((StatusCode::BAD_REQUEST, format!("发件邮箱 {} 不存在或已禁用", req.from_addr)));
    }

    // Webmail 用户检查 Webmail 发信权限（不受 SMTP 协议开关影响）
    if let Some(_claims) = &webmail_claims {
        let effective_config = match &mailbox_protocols {
            Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v.clone(),
            _ => register_config,
        };
        let allow_webmail = effective_config.get("allow_webmail").and_then(|v| v.as_bool()).unwrap_or(true);
        if !allow_webmail {
            return Err((StatusCode::FORBIDDEN, "Webmail 发信权限已被禁用".to_string()));
        }
    }

    if req.to_addrs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "至少需要一个收件人".to_string()));
    }

    let mut all_recipients = req.to_addrs.clone();
    if let Some(ref cc) = req.cc_addrs {
        all_recipients.extend(cc.iter().cloned());
    }

    // 防止邮件头注入：收件人/抄送地址不允许包含 CRLF
    for addr in &all_recipients {
        if addr.contains('\r') || addr.contains('\n') {
            return Err((StatusCode::BAD_REQUEST, "收件人地址包含非法字符".to_string()));
        }
    }
    // Subject 也要防止头注入（虽然非 ASCII 已编码，但 ASCII subject 可能含 CRLF）
    if req.subject.contains('\r') || req.subject.contains('\n') {
        return Err((StatusCode::BAD_REQUEST, "邮件主题包含非法字符".to_string()));
    }

    // 收件人数量上限：从 smtp_config.max_recipients 读取，默认 100
    let max_recipients: i64 = sqlx::query_scalar(
        "SELECT (value->>'max_recipients')::int FROM settings WHERE key = 'smtp_config'"
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(100);
    if all_recipients.len() as i64 > max_recipients {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("收件人数量超出限制（{} > {}）", all_recipients.len(), max_recipients),
        ));
    }

    // 构造邮件内容
    let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), from_domain);
    let now = chrono::Utc::now();
    let date = now.to_rfc2822();

    let to_header = req.to_addrs.join(", ");
    let cc_header = req.cc_addrs.as_ref().map(|cc| format!("Cc: {}\r\n", cc.join(", "))).unwrap_or_default();

    // 对 Subject 做 RFC 2047 编码（非 ASCII 字符必须编码，否则收件方显示乱码）
    let subject_encoded = if req.subject.is_ascii() {
        req.subject.clone()
    } else {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(req.subject.as_bytes());
        format!("=?utf-8?B?{}?=", encoded)
    };

    let header_block = format!(
        "From: {}\r\nTo: {}\r\n{}Subject: {}\r\nDate: {}\r\nMessage-ID: {}\r\nMIME-Version: 1.0\r\n",
        req.from_addr, to_header, cc_header, subject_encoded, date, message_id
    );

    // 构造邮件正文部分（可能为 multipart/alternative 或单一 text/plain / text/html）
    let body_text = req.body_text.as_deref().unwrap_or("");
    let body_html = req.body_html.as_deref().unwrap_or("");
    let attachments = req.attachments.as_deref().unwrap_or(&[]);

    // 校验单个附件大小
    if !attachments.is_empty() {
        let max_att_mb: i64 = sqlx::query_scalar(
            "SELECT (value->>'max_attachment_size_mb')::int FROM settings WHERE key = 'smtp_config'"
        )
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(25);
        let max_att_bytes = (max_att_mb as usize) * 1024 * 1024;
        for att in attachments {
            let content_len = base64::engine::general_purpose::STANDARD
                .decode(&att.content_base64)
                .map(|d| d.len())
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("附件 {} base64 解码失败: {}", att.filename, e)))?;
            if content_len > max_att_bytes {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("附件 {} 超出大小限制（{} MB > {} MB）", att.filename, (content_len / 1048576), max_att_mb),
                ));
            }
        }
    }

    let email = if attachments.is_empty() {
        // 无附件：保持原来的简单格式
        let mut email = header_block;
        match (&req.body_text, &req.body_html) {
            (Some(text), Some(html)) => {
                let boundary = format!("----=_Part_{}", uuid::Uuid::new_v4());
                email.push_str(&format!("Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n", boundary));
                email.push_str(&format!("--{}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", boundary, text));
                email.push_str(&format!("--{}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", boundary, html));
                email.push_str(&format!("--{}--\r\n", boundary));
            }
            (None, Some(html)) => {
                email.push_str("Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
                email.push_str(html);
            }
            (Some(_), None) | (None, None) => {
                email.push_str("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
                email.push_str(body_text);
            }
        }
        email
    } else {
        // 有附件：构造 multipart/mixed
        let mixed_boundary = format!("----=_Part_{}", uuid::Uuid::new_v4());
        let mut email = header_block;
        email.push_str(&format!("Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n", mixed_boundary));

        // 正文部分
        if !body_html.is_empty() && !body_text.is_empty() {
            // multipart/alternative 包裹正文
            let alt_boundary = format!("----=_Part_{}", uuid::Uuid::new_v4());
            email.push_str(&format!("--{}\r\n", mixed_boundary));
            email.push_str(&format!("Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n", alt_boundary));
            email.push_str(&format!("--{}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", alt_boundary, body_text));
            email.push_str(&format!("--{}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", alt_boundary, body_html));
            email.push_str(&format!("--{}--\r\n\r\n", alt_boundary));
        } else if !body_html.is_empty() {
            email.push_str(&format!("--{}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", mixed_boundary, body_html));
        } else {
            email.push_str(&format!("--{}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n\r\n", mixed_boundary, body_text));
        }

        // 附件部分
        for att in attachments {
            let content = base64::engine::general_purpose::STANDARD
                .decode(&att.content_base64)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("附件 {} base64 解码失败: {}", att.filename, e)))?;
            let content_b64 = base64::engine::general_purpose::STANDARD.encode(&content);
            email.push_str(&format!("--{}\r\n", mixed_boundary));
            email.push_str(&format!("Content-Type: {}\r\n", att.content_type));
            email.push_str(&format!("Content-Transfer-Encoding: base64\r\n"));
            email.push_str(&format!("Content-Disposition: attachment; filename=\"{}\"\r\n\r\n", att.filename));
            // base64 内容每 76 字符换行（RFC 2045）
            for chunk in content_b64.as_bytes().chunks(76) {
                email.push_str(std::str::from_utf8(chunk).unwrap_or(""));
                email.push_str("\r\n");
            }
            email.push_str("\r\n");
        }

        email.push_str(&format!("--{}--\r\n", mixed_boundary));
        email
    };

    let data = email.as_bytes();
    let size = data.len() as i64;

    // 检查邮件大小限制（结合全局 settings 与发件域名 / 收件域名 register_config 覆盖）
    let from_domain_owned: Option<String> = req.from_addr.rsplitn(2, '@').next().map(|s| s.to_string()).filter(|s| !s.is_empty());
    {
        // 发件人 send 上限
        let send_limit = funmail_common::db::resolve_size_limits(
            &state.pool, from_domain_owned.as_deref(), None
        ).await.max_send_bytes;
        if (size as u64) > send_limit {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("邮件超出发送大小限制（{} 字节 > {} 字节）", size, send_limit),
            ));
        }
        // 收件人 receive 上限（取最严格）
        for rcpt in &all_recipients {
            let to_domain = rcpt.rsplitn(2, '@').next().map(|s| s.to_string()).filter(|s| !s.is_empty());
            let recv_limit = funmail_common::db::resolve_size_limits(
                &state.pool, from_domain_owned.as_deref(), to_domain.as_deref()
            ).await.max_receive_bytes;
            if (size as u64) > recv_limit {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("邮件超出收件人 {} 的接收大小限制（{} 字节 > {} 字节）", rcpt, size, recv_limit),
                ));
            }
        }
    }

    // 写入邮件文件
    let mail_id = uuid::Uuid::new_v4().to_string();
    let data_dir = std::path::Path::new("/var/lib/funmail/maildir/queue");
    std::fs::create_dir_all(data_dir)
        .map_err(|e| { tracing::error!("创建队列目录失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;
    let data_path = data_dir.join(&mail_id);
    std::fs::write(&data_path, data)
        .map_err(|e| { tracing::error!("写入邮件文件失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    let data_path_str = data_path.to_string_lossy().to_string();

    // subject 直接使用用户输入（我们自己构造的邮件，不需要再解析）
    let subject_decoded = req.subject.clone();

    // 预查询所有收件域名信息，避免在循环中重复查询
    let mut domain_cache: std::collections::HashMap<String, Option<(i32, bool)>> = std::collections::HashMap::new();
    for rcpt in &all_recipients {
        let domain = rcpt.split('@').last().unwrap_or("").to_string();
        if domain_cache.contains_key(&domain) {
            continue;
        }
        let row: Option<(i32, bool)> = sqlx::query_as(
            "SELECT id, enabled FROM domains WHERE LOWER(name) = LOWER($1)"
        )
        .bind(&domain)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        domain_cache.insert(domain, row);
    }

    // 为每个收件人创建队列条目
    let mut queued_count = 0;
    for rcpt in &all_recipients {
        let domain = rcpt.split('@').last().unwrap_or("");
        let (domain_id, is_local) = match domain_cache.get(domain) {
            Some(Some((id, enabled))) => (*id, *enabled),
            _ => (0, false),
        };

        let direction = if is_local { "inbound" } else { "outbound" };

        sqlx::query(
            "INSERT INTO mail_queue (from_addr, to_addr, data_path, message_id, subject, status, direction, size_bytes)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)"
        )
        .bind(&req.from_addr)
        .bind(rcpt)
        .bind(&data_path_str)
        .bind(&message_id)
        .bind(&subject_decoded)
        .bind(direction)
        .bind(size)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        queued_count += 1;
    }

    // 通知投递引擎有新邮件入队，触发实时投递
    let _ = sqlx::query("SELECT pg_notify('mail_new', '1')")
        .execute(&state.pool)
        .await;

    // 写入邮件日志
    for rcpt in &all_recipients {
        let domain = rcpt.split('@').last().unwrap_or("");
        let (domain_id_opt, is_local) = match domain_cache.get(domain) {
            Some(Some((id, enabled))) => (Some(*id), *enabled),
            _ => (None, false),
        };

        let log_direction = if is_local { "inbound" } else { "outbound" };

        sqlx::query(
            "INSERT INTO mail_logs (domain_id, from_addr, to_addr, message_id, subject, direction, status, size_bytes, data_path)
             VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8)"
        )
        .bind(domain_id_opt)
        .bind(&req.from_addr)
        .bind(rcpt)
        .bind(&message_id)
        .bind(&subject_decoded)
        .bind(log_direction)
        .bind(size)
        .bind(&data_path_str)
        .execute(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // 复制到发件人的 IMAP Sent 目录
    {
        let from_parts: Vec<&str> = req.from_addr.rsplitn(2, '@').collect();
        if from_parts.len() == 2 {
            let from_user = from_parts[1]; // rsplitn 反转
            let from_domain = from_parts[0];
            let sent_dir = std::path::Path::new("/var/lib/funmail/maildir")
                .join(from_domain).join(from_user).join("Sent").join("new");
            if let Ok(()) = std::fs::create_dir_all(&sent_dir) {
                let sent_filename = format!(
                    "{}.{}.{}",
                    chrono::Utc::now().timestamp(),
                    std::process::id(),
                    uuid::Uuid::new_v4().as_simple()
                );
                if std::fs::copy(&data_path, sent_dir.join(&sent_filename)).is_ok() {
                    // 更新发件人 used_bytes
                    let _ = funmail_common::db::add_mailbox_used_bytes(
                        &state.pool, from_user, from_domain, size
                    ).await;
                }
            }
        }
    }

    tracing::info!(
        "管理后台发送邮件: from={} to={:?} subject={} size={}",
        req.from_addr, all_recipients, req.subject, size
    );

    Ok(Json(SendMailResponse {
        success: true,
        message: format!("邮件已入队，共 {} 个收件人", queued_count),
        queued_count,
    }))
}

/// 附件元信息
#[derive(Serialize)]
struct AttachmentInfo {
    index: usize,       // 附件序号（用于下载）
    filename: String,
    content_type: String,
    size: usize,        // 字节数
}

/// 邮件详情响应
#[derive(Serialize)]
struct MailDetailResponse {
    id: i64,
    from_addr: String,
    to_addr: String,
    cc_addrs: Option<String>,
    subject: String,
    date: Option<String>,
    message_id: Option<String>,
    direction: String,
    status: String,
    size_bytes: i64,
    spam_score: f32,
    reject_reason: Option<String>,
    data_path: Option<String>,
    body_text: Option<String>,
    body_html: Option<String>,
    attachments: Vec<AttachmentInfo>,
}

/// 邮件详情：根据 mail_logs.id 查找并读取邮件文件
async fn mail_detail(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<MailDetailResponse>, (StatusCode, String)> {
    let webmail_claims = verify_webmail_if_present(&headers, &state).await
        .map_err(|s| (s, "未登录".to_string()))?;
    // 1. 查 mail_logs 拿到方向、from/to、data_path
    let row: Option<(String, String, Option<String>, String, String, i64, f32, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT from_addr, to_addr, subject, direction, status, size_bytes, COALESCE(spam_score, 0::real), message_id, data_path, reject_reason
         FROM mail_logs WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (from_addr, to_addr, subject, direction, status, size_bytes, spam_score, message_id, data_path_from_logs, reject_reason) =
        row.ok_or((StatusCode::NOT_FOUND, "邮件不存在".to_string()))?;

    // Webmail 用户只能查看与自己邮箱相关的邮件（精确匹配）
    if let Some(claims) = &webmail_claims {
        let me = claims.sub.to_lowercase();
        let from_match = from_addr.to_lowercase() == me;
        let to_match = to_addr.to_lowercase().split(',')
            .any(|addr| addr.trim() == me);
        if !from_match && !to_match {
            return Err((StatusCode::FORBIDDEN, "无权查看此邮件".to_string()));
        }
    }

    // 2. 获取 data_path：优先从 mail_logs 直接读取，回退查 mail_queue
    let data_path: Option<String> = if let Some(ref dp) = data_path_from_logs {
        Some(dp.clone())
    } else if let Some(ref msg_id) = message_id {
        sqlx::query_scalar(
            "SELECT data_path FROM mail_queue WHERE message_id = $1 ORDER BY id DESC LIMIT 1"
        )
        .bind(msg_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        None
    };

    let data_path = data_path.ok_or((StatusCode::NOT_FOUND, "邮件文件不存在".to_string()))?;

    // 3. 读取并解析邮件文件
    let raw = std::fs::read(&data_path)
        .map_err(|e| { tracing::error!("读取邮件文件失败: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, "操作失败".to_string()) })?;

    let parsed = parse_mail_message(&raw);

    // 标记为已读：仅 webmail 用户打开才标记，避免管理员在后台查看污染用户已读状态
    if let Some(_claims) = &webmail_claims {
        let _ = sqlx::query("UPDATE mail_logs SET is_read = TRUE WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await;
    }

    // 4. 取抄送头（如果有）
    let cc_addrs: Option<String> = parsed.headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cc"))
        .map(|(_, v)| v.clone())
        .filter(|s| !s.is_empty());

    // 5. 用 mail-parser 提取附件列表
    let attachments = extract_attachments(&raw);

    Ok(Json(MailDetailResponse {
        id,
        from_addr,
        to_addr,
        cc_addrs,
        subject: subject.unwrap_or_default(),
        date: parsed.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("date")).map(|(_, v)| v.clone()),
        message_id,
        direction,
        status,
        size_bytes,
        spam_score,
        reject_reason,
        data_path: Some(data_path),
        body_text: parsed.body_text,
        body_html: parsed.body_html,
        attachments,
    }))
}

/// 下载附件：根据 mail_logs.id + 附件序号返回原始二进制内容
async fn download_attachment(
    State(state): State<Arc<AppState>>,
    mut headers: axum::http::HeaderMap,
    axum::extract::Path((id, index)): axum::extract::Path<(i64, usize)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    // 支持 query token（用于 <a> 标签直接下载）
    if let Some(token) = params.get("token") {
        if let Some(v) = axum::http::HeaderValue::from_str(&format!("Bearer {}", token)).ok() {
            headers.insert("authorization", v);
        }
    }
    let webmail_claims = verify_webmail_if_present(&headers, &state).await
        .map_err(|s| (s, "未登录".to_string()))?;

    // 1. 查 mail_logs 获取 data_path 和 from/to（权限校验）
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT from_addr, to_addr, data_path FROM mail_logs WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (from_addr, to_addr, data_path_from_logs) =
        row.ok_or((StatusCode::NOT_FOUND, "邮件不存在".to_string()))?;

    // Webmail 用户权限检查
    if let Some(claims) = &webmail_claims {
        let me = claims.sub.to_lowercase();
        let from_match = from_addr.to_lowercase() == me;
        let to_match = to_addr.to_lowercase().split(',')
            .any(|addr| addr.trim() == me);
        if !from_match && !to_match {
            return Err((StatusCode::FORBIDDEN, "无权访问此附件".to_string()));
        }
    }

    let data_path = data_path_from_logs
        .ok_or((StatusCode::NOT_FOUND, "邮件文件不存在".to_string()))?;

    // 2. 读取并解析邮件
    let raw = std::fs::read(&data_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("读取邮件文件失败: {}", e)))?;

    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "邮件解析失败".to_string()))?;

    // 3. 取出指定序号的附件
    let attachment = parsed.attachments()
        .nth(index)
        .ok_or((StatusCode::NOT_FOUND, format!("附件 {} 不存在", index)))?;

    let filename = attachment.attachment_name().unwrap_or("attachment").to_string();
    let content_type = attachment.content_type()
        .map(|ct| {
            let mut s = ct.ctype().to_string();
            if let Some(sub) = ct.subtype() {
                s.push('/');
                s.push_str(sub);
            }
            s
        })
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let contents = attachment.contents().to_vec();

    // 4. 构造 HTTP 响应
    let encoded_filename = urlencode(&filename);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Content-Disposition", format!("attachment; filename*=UTF-8''{}", encoded_filename))
        .header("Content-Length", contents.len())
        .body(Body::from(contents))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(response)
}

/// URL 编码（RFC 3986），用于 Content-Disposition 文件名
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

struct ParsedMail {
    headers: Vec<(String, String)>,
    body_text: Option<String>,
    body_html: Option<String>,
}

/// 用 mail-parser 提取附件列表（仅元信息，不含内容）
fn extract_attachments(raw: &[u8]) -> Vec<AttachmentInfo> {
    let parsed = match mail_parser::MessageParser::default().parse(raw) {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut attachments = Vec::new();
    for (idx, attachment) in parsed.attachments().enumerate() {
        let filename = attachment.attachment_name().unwrap_or("unknown").to_string();
        let content_type = attachment.content_type()
            .map(|ct| {
                let mut s = ct.ctype().to_string();
                if let Some(sub) = ct.subtype() {
                    s.push('/');
                    s.push_str(sub);
                }
                s
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let size = attachment.contents().len();
        attachments.push(AttachmentInfo {
            index: idx,
            filename,
            content_type,
            size,
        });
    }
    attachments
}

/// 简单邮件解析：解析 headers + multipart/alternative
fn parse_mail_message(raw: &[u8]) -> ParsedMail {
    // 0. 统一换行符为 CRLF：兼容仅用 \n（LF）的邮件，否则 header/body 分界与正文解析会失败
    let raw_owned = String::from_utf8_lossy(raw);
    let normalized = raw_owned.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n");
    let raw_str = normalized.as_str();
    // 1. 找到 header/body 分界（第一个空行）
    let mut parts = raw_str.splitn(2, "\r\n\r\n");
    let header_block = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");

    // 2. 解析 headers
    let mut headers = Vec::new();
    // 处理多行续行（以空白开头的行属于前一个 header）
    let mut current: Option<(String, String)> = None;
    for line in header_block.split("\r\n") {
        if line.is_empty() { continue; }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, ref mut v)) = current {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some(pos) = line.find(':') {
            if let Some(prev) = current.take() {
                headers.push(prev);
            }
            let k = line[..pos].trim().to_string();
            let v = line[pos+1..].trim().to_string();
            current = Some((k, v));
        }
    }
    if let Some(prev) = current.take() {
        headers.push(prev);
    }

    // 3. 找到 Content-Type，区分单段 / multipart
    let content_type = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    let (mut body_text, body_html) = if content_type.to_lowercase().contains("multipart/") {
        // 解析 multipart，取 text/plain 和 text/html
        parse_multipart(body, content_type, &headers)
    } else if content_type.to_lowercase().contains("text/html") {
        let charset = extract_charset(content_type);
        (None, Some(decode_body(body, headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-transfer-encoding")).map(|(_, v)| v.as_str()), charset.as_deref())))
    } else {
        let charset = extract_charset(content_type);
        (Some(decode_body(body, headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-transfer-encoding")).map(|(_, v)| v.as_str()), charset.as_deref())), None)
    };

    // 如果没有纯文本但有 HTML，从 HTML 中剥离标签生成纯文本
    if body_text.is_none() {
        if let Some(ref html) = body_html {
            body_text = Some(strip_html_tags(html));
        }
    }

    ParsedMail { headers, body_text, body_html }
}

/// 解析 multipart body
fn parse_multipart(body: &str, content_type: &str, headers: &[(String, String)]) -> (Option<String>, Option<String>) {
    // 取 boundary
    let boundary = content_type.split(';')
        .find_map(|s| s.trim().strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string()));
    let boundary = match boundary {
        Some(b) => b,
        None => return (Some(body.to_string()), None),
    };

    let mut text: Option<String> = None;
    let mut html: Option<String> = None;

    // 用 boundary 分割
    let delim = format!("--{}", boundary);
    for part in body.split(&delim) {
        if part.is_empty() || part == "--" || part == "--\r\n" || part.starts_with("--") {
            continue;
        }
        // 去掉前导 \r\n
        let part = part.trim_start_matches("\r\n").trim_start_matches('\n');
        // 切分 part header / body
        let mut pb = part.splitn(2, "\r\n\r\n");
        let part_header = pb.next().unwrap_or("");
        let part_body = pb.next().unwrap_or("").trim_end_matches("\r\n").trim_end_matches("--");
        let part_body = part_body.trim();

        let ct_lower = part_header.to_lowercase();
        let cte = part_header.lines()
            .find(|l| l.to_lowercase().starts_with("content-transfer-encoding:"))
            .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
        
        // 从 part 的 Content-Type 提取 charset
        let part_ct = part_header.lines()
            .find(|l| l.to_lowercase().starts_with("content-type:"))
            .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
            .unwrap_or_default();
        let part_charset = extract_charset(&part_ct);

        if ct_lower.contains("text/html") {
            if html.is_none() { html = Some(decode_body(part_body, cte.as_deref(), part_charset.as_deref())); }
        } else if ct_lower.contains("text/plain") {
            if text.is_none() { text = Some(decode_body(part_body, cte.as_deref(), part_charset.as_deref())); }
        }
    }
    (text, html)
}

/// 从 HTML 中剥离标签，生成纯文本
fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_buf = String::new();
    let mut skip = false; // inside <style> or <script>

    for ch in html.chars() {
        if in_tag {
            tag_buf.push(ch);
            if ch == '>' {
                in_tag = false;
                let tag = tag_buf.trim_end_matches('>');
                let tag_lower = tag.trim().to_lowercase();
                if tag_lower.starts_with("<style") || tag_lower.starts_with("<script") {
                    skip = true;
                }
                if tag_lower.starts_with("</style") || tag_lower.starts_with("</script") {
                    skip = false;
                }
                tag_buf.clear();
            }
            continue;
        }
        if ch == '<' {
            in_tag = true;
            tag_buf.push(ch);
            continue;
        }
        if skip {
            continue;
        }
        result.push(ch);
    }
    // 处理常见 HTML 实体
    result = result.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    // 压缩连续空白
    let mut compressed = String::with_capacity(result.len());
    let mut last_was_space = false;
    for ch in result.chars() {
        if ch == ' ' || ch == '\t' {
            if !last_was_space { compressed.push(' '); last_was_space = true; }
        } else {
            compressed.push(ch);
            last_was_space = false;
        }
    }
    compressed.trim().to_string()
}

/// 从 Content-Type 头提取 charset 参数
/// 例如: "text/plain; charset=gbk" -> Some("gbk")
fn extract_charset(content_type: &str) -> Option<String> {
    content_type.split(';')
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix("charset=")
                .map(|s| s.trim_matches('"').trim().to_lowercase())
        })
}

/// 解码邮件正文（支持 quoted-printable / base64 / 7bit / 8bit + charset 转换）
fn decode_body(body: &str, encoding: Option<&str>, charset: Option<&str>) -> String {
    let enc = encoding.unwrap_or("7bit").to_lowercase();
    let raw_bytes: Vec<u8> = match enc.as_str() {
        "base64" => {
            // 去掉换行后 base64 解码
            let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            base64_decode_bytes(&cleaned)
        }
        "quoted-printable" => quoted_printable_decode_bytes(body),
        _ => body.as_bytes().to_vec(),
    };

    // 根据 charset 解码字节
    decode_charset(&raw_bytes, charset.unwrap_or("utf-8"))
}

/// 根据 charset 将字节解码为 UTF-8 字符串
fn decode_charset(bytes: &[u8], charset: &str) -> String {
    let charset_lower = charset.to_lowercase();
    match charset_lower.as_str() {
        "utf-8" | "utf8" => String::from_utf8_lossy(bytes).into_owned(),
        "gbk" | "gb2312" | "gb18030" => {
            // 使用 encoding_rs 解码 GBK/GB2312
            let (decoded, _, _) = encoding_rs::GBK.decode(bytes);
            decoded.into_owned()
        }
        "big5" => {
            let (decoded, _, _) = encoding_rs::BIG5.decode(bytes);
            decoded.into_owned()
        }
        "shift_jis" | "shift-jis" => {
            let (decoded, _, _) = encoding_rs::SHIFT_JIS.decode(bytes);
            decoded.into_owned()
        }
        "euc-kr" | "euc_kr" => {
            let (decoded, _, _) = encoding_rs::EUC_KR.decode(bytes);
            decoded.into_owned()
        }
        "iso-8859-1" | "latin1" | "windows-1252" => {
            let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
            decoded.into_owned()
        }
        _ => {
            // 未知编码，尝试 UTF-8，失败则用 latin1
            String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| {
                    let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
                    decoded.into_owned()
                })
        }
    }
}

fn base64_decode_bytes(s: &str) -> Vec<u8> {
    // 简单的 base64 解码
    use std::collections::HashMap;
    let table: HashMap<char, u8> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .chars().enumerate().map(|(i, c)| (c, i as u8)).collect();
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().collect();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b0 = table.get(&(bytes[i] as char)).copied().unwrap_or(0);
        let b1 = table.get(&(bytes[i+1] as char)).copied().unwrap_or(0);
        let b2 = table.get(&(bytes[i+2] as char)).copied().unwrap_or(0);
        let b3 = table.get(&(bytes[i+3] as char)).copied().unwrap_or(0);
        out.push((b0 << 2) | (b1 >> 4));
        if bytes[i+2] != b'=' { out.push((b1 << 4) | (b2 >> 2)); }
        if bytes[i+3] != b'=' { out.push((b2 << 6) | b3); }
        i += 4;
    }
    out
}

fn quoted_printable_decode_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len()
                && bytes[i+1].is_ascii_hexdigit()
                && bytes[i+2].is_ascii_hexdigit() {
                let h = ((bytes[i+1] as char).to_digit(16).unwrap_or(0) << 4)
                      | (bytes[i+2] as char).to_digit(16).unwrap_or(0);
                out.push(h as u8);
                i += 3;
            } else if i + 1 < bytes.len() && bytes[i+1] == b'\n' {
                i += 2; // 软换行
            } else if i + 1 < bytes.len() && bytes[i+1] == b'\r' && i + 2 < bytes.len() && bytes[i+2] == b'\n' {
                i += 3;
            } else {
                out.push(b'=');
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}
