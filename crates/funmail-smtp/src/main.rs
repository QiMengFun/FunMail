mod session;
mod store;

use chrono::Datelike;
use clap::Parser;
use funmail_common::db;
use funmail_common::TlsCertStore;
use session::SmtpSession;
use sqlx::PgPool;
use std::sync::Arc;
use store::DomainStore;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "funmail-smtp", about = "FunMail SMTP 服务器")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:25")]
    listen: String,

    #[arg(long, default_value = "0.0.0.0:587")]
    submission_listen: String,

    /// 隐式 TLS 监听地址（如 0.0.0.0:465），连接后立即 TLS 握手
    #[arg(long)]
    tls_listen: Option<String>,

    #[arg(long)]
    database_url: Option<String>,

    #[arg(long, default_value = "mail.example.com")]
    hostname: String,

    #[arg(long, default_value = "/var/lib/funmail/maildir")]
    maildir_base: String,

    #[arg(long, default_value = "52428800")]
    max_message_size: u64,
}

struct AppState {
    pool: PgPool,
    domain_store: DomainStore,
    tls_cert_store: TlsCertStore,
    hostname: String,
    maildir_base: String,
    /// 全局最大邮件字节数（取 send/receive 较大值用于 EHLO SIZE 广播）
    /// 实际收发限制按发件人/收件人域名动态解析，详见 funmail_common::db::resolve_size_limits
    max_message_size: std::sync::atomic::AtomicU64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 安装 rustls crypto provider（rustls 0.23+ 要求）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    tracing::info!("FunMail SMTP 正在启动...");

    let args = Args::parse();

    let database_url = args.database_url.unwrap_or_else(|| {
        "postgres://funmail:funmail@127.0.0.1:5432/funmail".to_string()
    });

    let pool = db::init_pool(&database_url).await?;
    ensure_partitions(&pool).await;
    tracing::info!("数据库连接成功");

    // 定期检查并创建 mail_logs 分区（每6小时）
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 3600));
        loop {
            interval.tick().await;
            ensure_partitions(&pool_clone).await;
        }
    });

    let domain_store = DomainStore::new(pool.clone());
    domain_store.reload().await?;
    tracing::info!("域名配置已加载");

    // 自动确定主机名：优先使用数据库中第一个域名
    let hostname = if args.hostname == "mail.example.com" || args.hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
        match sqlx::query_scalar::<_, String>("SELECT name FROM domains WHERE enabled = true ORDER BY id LIMIT 1")
            .fetch_optional(&pool)
            .await
        {
            Ok(Some(domain)) => {
                let h = format!("mail.{}", domain);
                tracing::info!("SMTP 主机名（自动）: {}", h);
                h
            }
            _ => {
                tracing::warn!("无法自动确定主机名，使用: {}", args.hostname);
                args.hostname.clone()
            }
        }
    } else {
        args.hostname.clone()
    };

    let tls_cert_store = TlsCertStore::new(pool.clone(), hostname.clone());
    if let Err(e) = tls_cert_store.reload().await {
        tracing::warn!("TLS 证书加载失败（TLS 暂不可用）: {}", e);
    }

    let state = Arc::new(AppState {
        pool: pool.clone(),
        domain_store,
        tls_cert_store,
        hostname,
        maildir_base: args.maildir_base.clone(),
        max_message_size: std::sync::atomic::AtomicU64::new(args.max_message_size),
    });

    // 启动时立即从 settings 加载一次全局上限
    {
        let limits = funmail_common::db::load_global_size_limits(&state.pool).await;
        let v = limits.max_send_bytes.max(limits.max_receive_bytes);
        state.max_message_size.store(v, std::sync::atomic::Ordering::Relaxed);
        tracing::info!("SMTP 全局邮件大小上限: send={}MB, receive={}MB",
            limits.max_send_bytes / 1024 / 1024, limits.max_receive_bytes / 1024 / 1024);
    }

    // 启动 SMTP 端口 25（接收邮件）
    let state_smtp = state.clone();
    let smtp_listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("SMTP 监听地址: {}", args.listen);

    // 启动 Submission 端口 587（用户发信）
    let state_sub = state.clone();
    let sub_listener = tokio::net::TcpListener::bind(&args.submission_listen).await?;
    tracing::info!("Submission 监听地址: {}", args.submission_listen);

    // 定期刷新域名配置和 TLS 证书
    let reload_store = state.domain_store.clone();
    let reload_tls = state.tls_cert_store.clone();
    let reload_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if let Err(e) = reload_store.reload().await {
                tracing::warn!("域名配置刷新失败: {}", e);
            }
            if let Err(e) = reload_tls.reload().await {
                tracing::warn!("TLS 证书刷新失败: {}", e);
            }
            // 刷新全局邮件大小上限
            let limits = funmail_common::db::load_global_size_limits(&reload_state.pool).await;
            let v = limits.max_send_bytes.max(limits.max_receive_bytes);
            reload_state.max_message_size.store(v, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // SMTP 服务循环
    tokio::spawn(async move {
        loop {
            match smtp_listener.accept().await {
                Ok((stream, addr)) => {
                    let state = state_smtp.clone();
                    tokio::spawn(async move {
                        if let Err(e) = SmtpSession::handle(stream, addr, state, false).await {
                            tracing::debug!("SMTP 会话错误 {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("SMTP 接受连接失败: {}", e);
                }
            }
        }
    });

    // Submission 服务循环 + 隐式 TLS（端口 465）
    // 隐式 TLS 监听
    if let Some(ref tls_addr) = args.tls_listen {
        let tls_listener = tokio::net::TcpListener::bind(tls_addr).await?;
        tracing::info!("SMTP 隐式 TLS 监听地址: {}", tls_addr);
        let state_tls = state.clone();
        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((stream, addr)) => {
                        let state = state_tls.clone();
                        tokio::spawn(async move {
                            let acceptor = state.tls_cert_store.acceptor().await;
                            match acceptor {
                                Some(acceptor) => {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            if let Err(e) = SmtpSession::handle_tls(tls_stream, addr, state, true).await {
                                                tracing::debug!("SMTP TLS 会话错误 {}: {}", addr, e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("SMTP TLS 握手失败 {}: {}", addr, e);
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!("SMTP TLS 连接但无证书: {}", addr);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("SMTP TLS accept 错误: {}", e);
                    }
                }
            }
        });
    }

    // Submission 服务循环（端口 587 STARTTLS）
    loop {
        match sub_listener.accept().await {
            Ok((stream, addr)) => {
                let state = state_sub.clone();
                tokio::spawn(async move {
                    if let Err(e) = SmtpSession::handle(stream, addr, state, true).await {
                        tracing::debug!("Submission 会话错误 {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Submission 接受连接失败: {}", e);
            }
        }
    }
}

/// 确保当月和未来月份的 mail_logs 分区存在
async fn ensure_partitions(pool: &PgPool) {
    let now = chrono::Utc::now();
    // 为过去1个月、当月和未来3个月创建分区
    for offset in -1i32..4 {
        let month_val = now.month() as i32 + offset;
        let year = now.year() + (month_val - 1) / 12;
        let month = ((month_val - 1) % 12 + 12) % 12 + 1;
        let next_month_val = month + 1;
        let next_month_year = year + (next_month_val - 1) / 12;
        let next_month = ((next_month_val - 1) % 12 + 12) % 12 + 1;

        let partition_name = format!("mail_logs_y{}m{:02}", year, month);
        let start = format!("{}-{:02}-01", year, month);
        let end = format!("{}-{:02}-01", next_month_year, next_month);

        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} PARTITION OF mail_logs FOR VALUES FROM ('{}') TO ('{}')",
            partition_name, start, end
        );

        match sqlx::query(&sql).execute(pool).await {
            Ok(_) => {
                tracing::info!("分区 {} 已就绪 ({} ~ {})", partition_name, start, end);
            }
            Err(e) => {
                if e.to_string().contains("already exists") {
                    tracing::debug!("分区 {} 已存在", partition_name);
                } else {
                    tracing::warn!("创建分区 {} 失败: {}", partition_name, e);
                }
            }
        }
    }
}
