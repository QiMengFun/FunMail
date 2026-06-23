mod local;
mod remote;
mod dkim;
mod dns;

use clap::Parser;
use funmail_common::db;
use sqlx::PgPool;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "funmail-delivery", about = "FunMail 邮件投递引擎")]
struct Args {
    #[arg(long)]
    database_url: Option<String>,

    #[arg(long, default_value = "/var/lib/funmail/maildir")]
    maildir_base: String,

    #[arg(long, default_value = "4")]
    worker_count: usize,

    #[arg(long, default_value = "1000")]
    queue_scan_interval_ms: u64,

    #[arg(long, default_value = "3")]
    max_retries: u32,

    #[arg(long, default_value = "30")]
    retry_interval_sec: u64,

    #[arg(long, default_value = "mail.example.com")]
    hostname: String,
}

struct AppState {
    pool: PgPool,
    database_url: String,
    maildir_base: String,
    max_retries: u32,
    retry_interval_sec: u64,
    skip_bounce_retry: bool,
    hostname: String,
    worker_count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 安装 rustls crypto provider（rustls 0.23+ 要求）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    tracing::info!("FunMail Delivery 正在启动...");

    let args = Args::parse();
    let database_url = args.database_url.unwrap_or_else(|| {
        "postgres://funmail:funmail@127.0.0.1:5432/funmail".to_string()
    });

    let pool = db::create_pool(&database_url).await?;
    tracing::info!("数据库连接成功");

    // 从数据库读取投递配置覆盖命令行默认值
    let mut max_retries = args.max_retries;
    let mut retry_interval_sec = args.retry_interval_sec;
    let mut skip_bounce_retry = true;
    if let Ok(row) = sqlx::query_as::<_, (sqlx::types::JsonValue,)>(
        "SELECT value FROM settings WHERE key = 'delivery_config'"
    )
    .fetch_one(&pool)
    .await
    {
        if let Some(cfg) = row.0.as_object() {
            if let Some(v) = cfg.get("max_retries").and_then(|v| v.as_u64()) {
                max_retries = v as u32;
            }
            if let Some(v) = cfg.get("retry_interval_sec").and_then(|v| v.as_u64()) {
                retry_interval_sec = v;
            }
            if let Some(v) = cfg.get("skip_bounce_retry").and_then(|v| v.as_bool()) {
                skip_bounce_retry = v;
            }
        }
    }
    tracing::info!("投递配置: 最大重试={}, 重试间隔={}s, 退信不重试={}", max_retries, retry_interval_sec, skip_bounce_retry);

    // 自动确定 EHLO 主机名：优先使用数据库中第一个域名的 FQDN
    let hostname = if args.hostname == "mail.example.com" || args.hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
        // 默认值或纯 IP 地址，尝试从数据库获取
        match sqlx::query_scalar::<_, String>("SELECT name FROM domains WHERE enabled = true ORDER BY id LIMIT 1")
            .fetch_optional(&pool)
            .await
        {
            Ok(Some(domain)) => {
                let h = format!("mail.{}", domain);
                tracing::info!("EHLO 主机名（自动）: {}", h);
                h
            }
            _ => {
                tracing::warn!("无法自动确定 EHLO 主机名，使用: {}", args.hostname);
                args.hostname.clone()
            }
        }
    } else {
        tracing::info!("EHLO 主机名: {}", args.hostname);
        args.hostname.clone()
    };

    let state = Arc::new(AppState {
        pool: pool.clone(),
        database_url: database_url.clone(),
        maildir_base: args.maildir_base.clone(),
        max_retries,
        retry_interval_sec,
        skip_bounce_retry,
        hostname,
        worker_count: args.worker_count,
    });

    // 确保 Maildir 目录存在
    std::fs::create_dir_all(&args.maildir_base)?;

    // 恢复上次崩溃时卡在 delivering 状态的邮件
    let recovering = sqlx::query(
        "UPDATE mail_queue SET status = 'pending', updated_at = NOW() WHERE status = 'delivering'"
    )
    .execute(&pool)
    .await
    .unwrap_or_default();
    if recovering.rows_affected() > 0 {
        tracing::info!("恢复 {} 封卡在 delivering 状态的邮件", recovering.rows_affected());
    }

    // 启动 PostgreSQL LISTEN 监听新邮件
    let listen_pool = pool.clone();
    let listen_state = state.clone();
    tokio::spawn(async move {
        listen_for_new_mail(&listen_pool, &listen_state).await;
    });

    // 启动工作线程处理队列
    let interval = tokio::time::Duration::from_millis(args.queue_scan_interval_ms);
    let worker_state = state.clone();
    tokio::spawn(async move {
        process_queue_loop(&worker_state, interval).await;
    });

    // 启动延迟重试扫描
    let retry_state = state.clone();
    tokio::spawn(async move {
        retry_loop(&retry_state).await;
    });

    // 主线程等待
    tokio::signal::ctrl_c().await?;
    tracing::info!("FunMail Delivery 正在关闭...");

    Ok(())
}

/// 监听 PostgreSQL 通知，有新邮件时立即处理
async fn listen_for_new_mail(pool: &PgPool, state: &Arc<AppState>) {
    let mut listener = match sqlx::postgres::PgListener::connect(&state.database_url).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("PG LISTEN 连接失败: {}，退回轮询模式", e);
            return;
        }
    };

    if let Err(e) = listener.listen("mail_new").await {
        tracing::warn!("PG LISTEN mail_new 失败: {}", e);
        return;
    }

    tracing::info!("PostgreSQL LISTEN mail_new 已连接");

    loop {
        match listener.recv().await {
            Ok(notification) => {
                tracing::debug!("收到新邮件通知: {}", notification.payload());
                process_pending_mail(state).await;
            }
            Err(e) => {
                tracing::warn!("PG LISTEN 错误: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}

/// 定期扫描队列
async fn process_queue_loop(state: &Arc<AppState>, interval: tokio::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        process_pending_mail(state).await;
    }
}

/// 延迟重试循环
async fn retry_loop(state: &Arc<AppState>) {
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
    loop {
        ticker.tick().await;
        process_retry_mail(state).await;
    }
}

/// 处理待投递邮件
async fn process_pending_mail(state: &Arc<AppState>) {
    // 使用 FOR UPDATE SKIP LOCKED 原子获取并锁定待投递邮件，
    // 避免 LISTEN 通知和轮询同时触发导致重复投递
    let entries: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT id, from_addr, to_addr, data_path, direction
         FROM mail_queue
         WHERE status = 'pending'
         ORDER BY priority DESC, created_at ASC
         LIMIT 100
         FOR UPDATE SKIP LOCKED"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    if entries.is_empty() {
        return;
    }
    tracing::info!("扫描到 {} 封待投递邮件", entries.len());

    // 立即将这些邮件标记为 delivering，释放行锁
    let ids: Vec<i64> = entries.iter().map(|(id, _, _, _, _)| *id).collect();
    let _ = sqlx::query("UPDATE mail_queue SET status = 'delivering', updated_at = NOW() WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&state.pool)
        .await;

    // 并发投递：用信号量限制最大并发数（worker_count），避免一封慢邮件阻塞其余邮件
    let sem = Arc::new(tokio::sync::Semaphore::new(state.worker_count.max(1)));
    let mut handles = Vec::with_capacity(entries.len());
    for entry in entries {
        let state = state.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            deliver_one(&state, entry).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// 投递单封邮件并更新其队列/日志状态
async fn deliver_one(state: &Arc<AppState>, entry: (i64, String, String, String, String)) {
    let (id, from_addr, to_addr, data_path, direction) = entry;
    let id = &id;
    let from_addr = &from_addr;
    let to_addr = &to_addr;
    let data_path = &data_path;
    let direction = &direction;
    {
        // NOTE: status 已在 process_pending_mail 中标记为 delivering，此处无需重复

        let result = if direction == "inbound" {
            // 本地投递
            local::deliver_local(&state.pool, &state.maildir_base, from_addr, to_addr, data_path).await
        } else {
            // 远程投递
            // EHLO 主机名自适应：从发件人地址提取域名作为 EHLO 标识
            // 例如 user@example.com 投递时使用 mail.example.com
            let ehlo_hostname = from_addr
                .rsplitn(2, '@')
                .next()
                .filter(|d| !d.is_empty())
                .map(|d| format!("mail.{}", d))
                .unwrap_or_else(|| state.hostname.clone());
            remote::deliver_remote(&state.pool, from_addr, to_addr, data_path, &ehlo_hostname).await
        };

        match result {
            Ok(()) => {
                let _ = sqlx::query(
                    "UPDATE mail_queue SET status = 'delivered', updated_at = NOW() WHERE id = $1"
                )
                .bind(id)
                .execute(&state.pool)
                .await;

                // 更新邮件日志（用 data_path 精确匹配，避免同发件人+收件人多封邮件误更新）
                let _ = sqlx::query(
                    "UPDATE mail_logs SET status = 'delivered' WHERE data_path = $1 AND to_addr = $2 AND status = 'queued'"
                )
                .bind(data_path)
                .bind(to_addr)
                .execute(&state.pool)
                .await;

                tracing::info!("邮件投递成功: {} -> {} ({})", from_addr, to_addr, direction);
            }
            Err(e) => {
                let error_msg = e.to_string();
                tracing::warn!("投递失败: {} -> {} (原因: {})", from_addr, to_addr, error_msg);
                // 检测永久性错误（用户不存在、域名无效等），这类错误重试无意义
                let is_permanent_error = is_permanent_smtp_error(&error_msg);

                let retry_count: i32 = sqlx::query_scalar(
                    "SELECT retry_count FROM mail_queue WHERE id = $1"
                )
                .bind(id)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);

                if is_permanent_error && state.skip_bounce_retry {
                    // 永久性错误且开启了退信不重试，直接标记退信
                    let bounce_reason = format!("[永久性错误] {}", error_msg);
                    let _ = sqlx::query(
                        "UPDATE mail_queue SET status = 'bounced', last_error = $2, updated_at = NOW() WHERE id = $1"
                    )
                    .bind(id)
                    .bind(&bounce_reason)
                    .execute(&state.pool)
                    .await;

                    let _ = sqlx::query(
                        "UPDATE mail_logs SET status = 'bounced', reject_reason = $3 WHERE data_path = $1 AND to_addr = $2 AND status = 'queued'"
                    )
                    .bind(data_path)
                    .bind(to_addr)
                    .bind(&bounce_reason)
                    .execute(&state.pool)
                    .await;

                    tracing::warn!("邮件永久退信(不重试): {} -> {} ({})", from_addr, to_addr, error_msg);
                } else if retry_count >= state.max_retries as i32 {
                    // 超过最大重试次数，标记为退信
                    let bounce_reason = e.to_string();
                    let _ = sqlx::query(
                        "UPDATE mail_queue SET status = 'bounced', last_error = $2, updated_at = NOW() WHERE id = $1"
                    )
                    .bind(id)
                    .bind(&bounce_reason)
                    .execute(&state.pool)
                    .await;

                    let _ = sqlx::query(
                        "UPDATE mail_logs SET status = 'bounced', reject_reason = $3 WHERE data_path = $1 AND to_addr = $2 AND status = 'queued'"
                    )
                    .bind(data_path)
                    .bind(to_addr)
                    .bind(&bounce_reason)
                    .execute(&state.pool)
                    .await;

                    tracing::warn!("邮件退信: {} -> {} (重试{}次后失败: {})", from_addr, to_addr, retry_count, e);
                } else {
                    // 固定间隔重试
                    let next_retry = chrono::Utc::now() + chrono::Duration::seconds(state.retry_interval_sec as i64);
                    let res = sqlx::query(
                        "UPDATE mail_queue SET status = 'deferred', retry_count = $2, next_retry_at = $3, last_error = $4, updated_at = NOW() WHERE id = $1"
                    )
                    .bind(id)
                    .bind(retry_count + 1)
                    .bind(next_retry)
                    .bind(e.to_string())
                    .execute(&state.pool)
                    .await;

                    if let Err(db_err) = res {
                        tracing::error!("更新邮件队列为 deferred 失败: {}", db_err);
                    }

                    tracing::info!("邮件延迟重试: {} -> {} (第{}次, {}s后重试, 原因: {})", from_addr, to_addr, retry_count + 1, state.retry_interval_sec, e);
                }
            }
        }
    }
}

/// 判断是否为永久性 SMTP 错误（重试无意义的错误）
/// 550: 邮箱不存在 / 拒绝访问
/// 551: 用户不在本地
/// 552: 邮箱已满
/// 553: 邮箱名无效
/// 511: 收件人不存在（Bad destination mailbox address）
/// 521: 域名不接受邮件
fn is_permanent_smtp_error(error_msg: &str) -> bool {
    let msg = error_msg.to_lowercase();

    // SMTP 5xx 永久性错误码
    let permanent_codes = ["550", "551", "552", "553", "511", "521"];
    for code in &permanent_codes {
        // 匹配 "550 " 或 "550." 等模式
        if msg.contains(&format!("{} ", code)) || msg.contains(&format!("{}-", code)) {
            return true;
        }
    }

    // 常见错误关键词
    let keywords = [
        "user unknown",
        "mailbox not found",
        "no such user",
        "recipient invalid",
        "invalid recipient",
        "recipient not found",
        "address rejected",
        "mailbox unavailable",
        "no such recipient",
        "domain not found",
        "no mx records",
        "host not found",
        "name or service not known",
    ];
    for kw in &keywords {
        if msg.contains(kw) {
            return true;
        }
    }

    false
}

/// 处理延迟重试邮件
async fn process_retry_mail(state: &Arc<AppState>) {
    let entries = sqlx::query_as::<_, (i64, String, String, String, String)>(
        "SELECT id, from_addr, to_addr, data_path, direction
         FROM mail_queue
         WHERE status = 'deferred' AND next_retry_at <= NOW()
         ORDER BY next_retry_at ASC
         LIMIT 50"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    for (id, _from_addr, _to_addr, _data_path, _direction) in &entries {
        // 标记回 pending
        let _ = sqlx::query("UPDATE mail_queue SET status = 'pending', updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await;
    }

    if !entries.is_empty() {
        tracing::info!("重新入队 {} 封延迟邮件", entries.len());
        process_pending_mail(state).await;
    }
}
