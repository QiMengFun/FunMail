mod api;
mod auth;
mod db;
mod state;
mod tasks;
mod acme;

use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "funmail-admin", about = "FunMail 管理后台服务")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:10002")]
    listen: String,

    #[arg(long)]
    database_url: Option<String>,

    #[arg(long, default_value = "../frontend/dist")]
    static_dir: String,

    #[arg(long, default_value = "admin")]
    admin_user: String,

    #[arg(long, env = "ADMIN_PASSWORD", default_value = "funmail2026")]
    admin_password: String,

    #[arg(long, default_value = "false")]
    acme_staging: bool,

    #[arg(long, env = "ACME_PORT", default_value = "80")]
    acme_port: u16,

    #[arg(long, env = "HTTPS_PORT")]
    https_port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 安装 rustls crypto provider（rustls 0.23+ 要求）
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    tracing::info!("FunMail Admin 正在启动...");

    let database_url = args.database_url.unwrap_or_else(|| {
        "postgres://funmail:funmail@127.0.0.1:5432/funmail".to_string()
    });

    let pool = db::init_pool(&database_url).await?;
    db::run_migrations(&pool).await?;
    db::seed_defaults(&pool).await?;
    db::ensure_partitions(&pool).await?;
    tracing::info!("数据库连接成功");

    let logs_db_url = if let Some(pos) = database_url.rfind('/') {
        format!("{}/logs_db", &database_url[..pos])
    } else {
        database_url.clone()
    };
    let logs_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&logs_db_url)
        .await?;

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    tracing::info!("日志数据库连接成功");

    // 创建管理员账号
    let password_hash = auth::hash_password(&args.admin_password)?;
    sqlx::query(
        "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
    )
    .bind(&args.admin_user)
    .bind(&password_hash)
    .execute(&pool)
    .await?;
    tracing::info!("管理员账号已就绪: {}", args.admin_user);

    // 清理过期的 ACME 挑战记录
    let cleaned = sqlx::query("DELETE FROM acme_challenges WHERE expires_at < NOW()")
        .execute(&pool)
        .await?;
    if cleaned.rows_affected() > 0 {
        tracing::info!("已清理 {} 条过期 ACME 挑战记录", cleaned.rows_affected());
    }

    // 加载 JWT 密钥
    let jwt_secret: String = {
        let row: (serde_json::Value,) = sqlx::query_as(
            "SELECT value FROM settings WHERE key = 'jwt_secret'"
        )
        .fetch_one(&pool)
        .await?;
        let secret = row.0.as_str().unwrap_or("").to_string();
        if secret.is_empty() {
            // 生成新的 JWT 密钥
            let new_secret = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().to_string();
            sqlx::query("UPDATE settings SET value = $1 WHERE key = 'jwt_secret'")
                .bind(serde_json::json!(new_secret))
                .execute(&pool)
                .await?;
            new_secret
        } else {
            secret
        }
    };
    tracing::info!("JWT 密钥已加载");

    let state = Arc::new(state::AppState::new(pool.clone(), logs_pool, jwt_secret).await);

    // 启动后台任务
    tasks::start_all(state.pool.clone(), args.acme_staging);

    // 启动时重算一次所有邮箱的 used_bytes，修复历史不一致
    {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            match funmail_common::db::recalc_all_used_bytes(&pool, "/var/lib/funmail/maildir").await {
                Ok(n) => tracing::info!("邮箱用量重算完成，已更新 {} 个邮箱", n),
                Err(e) => tracing::warn!("邮箱用量重算失败: {}", e),
            }
        });
    }

    let app = api::create_router(state.clone(), &args.static_dir)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("FunMail Admin 监听地址: {}", args.listen);

    let acme_addr = format!("0.0.0.0:{}", args.acme_port);
    match tokio::net::TcpListener::bind(&acme_addr).await {
        Ok(acme_listener) => {
            tracing::info!("ACME 挑战监听地址: {}", acme_addr);
            let acme_app = api::create_router(state.clone(), &args.static_dir);

            // HTTPS 服务（如果指定了端口且有证书）
            if let Some(https_port) = args.https_port {
                let https_addr = format!("0.0.0.0:{}", https_port);
                match tokio::net::TcpListener::bind(&https_addr).await {
                    Ok(https_listener) => {
                        tracing::info!("HTTPS 监听地址: {}", https_addr);
                        let tls_store = funmail_common::TlsCertStore::new(state.pool.clone(), String::new());
                        // 先尝试加载已有证书（没有也不报错，serve_tls 会等待证书就绪）
                        let _ = tls_store.reload_with_alpn(vec![b"http/1.1".to_vec()]).await;
                        tokio::select! {
                            result = axum::serve(listener, app) => { result?; }
                            result = axum::serve(acme_listener, acme_app) => { result?; }
                            result = serve_tls(https_listener, tls_store, state.clone(), &args.static_dir) => { result?; }
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!("无法绑定 HTTPS 端口 {}: {}，跳过 HTTPS", https_addr, e);
                    }
                }
            }

            // 无 HTTPS
            tokio::select! {
                result = axum::serve(listener, app) => { result?; }
                result = axum::serve(acme_listener, acme_app) => { result?; }
            }
        }
        Err(e) => {
            tracing::warn!("无法绑定 ACME 挑战端口 {}: {} (ACME HTTP-01 验证将不可用)", acme_addr, e);
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

/// 使用 TLS 证书服务 HTTPS（等待证书就绪后再接受连接）
async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls_store: funmail_common::TlsCertStore,
    state: Arc<state::AppState>,
    static_dir: &str,
) -> anyhow::Result<()> {
    // 定期刷新证书（使用 HTTPS ALPN）
    let tls_refresh = tls_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            let _ = tls_refresh.reload_with_alpn(vec![b"http/1.1".to_vec()]).await;
        }
    });

    loop {
        let (stream, _addr) = listener.accept().await?;
        let tls_store = tls_store.clone();
        let state = state.clone();
        let static_dir = static_dir.to_string();
        tokio::spawn(async move {
            // 等待证书就绪（最多等 30 秒）
            let acceptor = {
                let mut waited = 0u64;
                loop {
                    if let Some(acc) = tls_store.acceptor().await {
                        break acc;
                    }
                    if waited >= 30 {
                        tracing::debug!("TLS 等待超时，关闭连接");
                        return;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    waited += 1;
                }
            };
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let app = api::create_router(state, &static_dir);
                    let svc = hyper_util::service::TowerToHyperService::new(app);
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                }
                Err(e) => {
                    tracing::debug!("TLS 握手失败: {}", e);
                }
            }
        });
    }
}
