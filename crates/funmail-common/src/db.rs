use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// 创建数据库连接池
pub async fn create_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// 初始化数据库连接池并运行迁移
pub async fn init_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = create_pool(database_url).await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

/// 运行数据库迁移（使用 CREATE IF NOT EXISTS 保证幂等）
/// 单条语句失败不会中断整体迁移（例如已有数据冲突导致 UNIQUE INDEX 创建失败）
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let schema = include_str!("../../../sql/schema.sql");
    
    // 按分号分割，逐条执行（sqlx 一次只能执行一条语句）
    for statement in schema.split(';') {
        let stmt = statement.trim();
        if stmt.is_empty() || stmt.starts_with("--") {
            continue;
        }
        // 单条失败记录日志但不中断（避免已有数据导致索引创建失败时阻塞后续建表）
        if let Err(e) = sqlx::query(stmt).execute(pool).await {
            tracing::warn!("迁移语句执行失败（已跳过，不阻塞）: {}", e);
        }
    }
    
    Ok(())
}

/// 初始化默认数据
pub async fn seed_defaults(pool: &PgPool) -> anyhow::Result<()> {
    // 初始化默认设置
    let defaults = [
        ("smtp_config", serde_json::json!({
            "max_message_size_mb": 50,
            "max_send_size_mb": 50,
            "max_receive_size_mb": 50,
            "max_recipients": 100,
            "require_auth_for_outbound": true,
            "starttls_enabled": true,
        })),
        ("pop3_config", serde_json::json!({
            "starttls_enabled": true,
        })),
        ("imap_config", serde_json::json!({
            "starttls_enabled": true,
            "max_connections": 1000,
        })),
        ("delivery_config", serde_json::json!({
            "max_retries": 3,
            "retry_interval_sec": 30,
            "skip_bounce_retry": true,
            "worker_count": 4,
        })),
        ("security_config", serde_json::json!({
            "spam_filter_enabled": true,
            "spam_threshold": 5.0,
            "virus_scan_enabled": false,
            "rbl_enabled": true,
            "rbl_servers": ["zen.spamhaus.org", "bl.spamcop.net"],
            "rate_limit_per_ip": 100,
            "rate_limit_window_secs": 60,
        })),
        ("jwt_secret", serde_json::json!("")),
        ("captcha_hmac_key", serde_json::json!("")),
        ("timezone", serde_json::json!({
            "name": "Asia/Shanghai",
            "offset": "+08:00",
        })),
        ("language", serde_json::json!("zh")),
    ];

    for (key, value) in &defaults {
        // delivery_config 始终更新以同步配置键名变更
        // smtp_config 使用 JSONB merge：保留用户已配置的字段，只补齐新增字段
        if key == &"delivery_config" {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?;
        } else if key == &"smtp_config" {
            // 默认值在底，用户值在顶，缺失字段会被补齐，已有字段不变
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = $2 || settings.value"
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING"
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// 验证邮箱账号密码
pub async fn authenticate_mailbox(
    pool: &PgPool,
    username: &str,
    domain: &str,
    password: &str,
) -> anyhow::Result<Option<i32>> {
    let row = sqlx::query_as::<_, (i32, String, bool)>(
        "SELECT m.id, m.password_hash, m.enabled
         FROM mailboxes m
         JOIN domains d ON m.domain_id = d.id
         WHERE m.username = $1 AND d.name = $2 AND m.enabled = true AND d.enabled = true"
    )
    .bind(username)
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((id, hash, enabled)) => {
            if !enabled {
                return Ok(None);
            }
            if verify_password(password, &hash)? {
                Ok(Some(id))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

/// 哈希密码
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password failed: {e}"))?
        .to_string();
    Ok(hash)
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> anyhow::Result<bool> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("parse hash failed: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// 更新邮箱最后登录信息
pub async fn update_last_login(
    pool: &PgPool,
    mailbox_id: i32,
    client_ip: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE mailboxes SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2"
    )
    .bind(client_ip)
    .bind(mailbox_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// 检查域名是否为本服务器管理的域名
pub async fn is_local_domain(pool: &PgPool, domain: &str) -> anyhow::Result<bool> {
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM domains WHERE name = $1 AND enabled = true"
    )
    .bind(domain)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

/// 获取邮箱的 Maildir 路径
pub fn mailbox_maildir_path(base: &str, domain: &str, username: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(base).join(domain).join(username)
}

/// 邮件大小限制（字节）
#[derive(Debug, Clone, Copy)]
pub struct MailSizeLimits {
    pub max_send_bytes: u64,
    pub max_receive_bytes: u64,
}

impl Default for MailSizeLimits {
    fn default() -> Self {
        // 默认 50MB
        let v = 50u64 * 1024 * 1024;
        Self { max_send_bytes: v, max_receive_bytes: v }
    }
}

/// 读取全局 smtp_config 中的发送/接收上限（MB），未配置时回退默认 50MB
pub async fn load_global_size_limits(pool: &PgPool) -> MailSizeLimits {
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT value FROM settings WHERE key = 'smtp_config'"
    )
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let mut limits = MailSizeLimits::default();
    if let Some((v,)) = row {
        // 兼容旧字段 max_message_size_mb
        let fallback_mb = v.get("max_message_size_mb").and_then(|x| x.as_u64()).unwrap_or(50);
        let send_mb = v.get("max_send_size_mb").and_then(|x| x.as_u64()).unwrap_or(fallback_mb);
        let recv_mb = v.get("max_receive_size_mb").and_then(|x| x.as_u64()).unwrap_or(fallback_mb);
        limits.max_send_bytes = send_mb * 1024 * 1024;
        limits.max_receive_bytes = recv_mb * 1024 * 1024;
    }
    limits
}

/// 解析域名级 register_config 中的发送/接收覆盖（MB），无覆盖时返回 None
pub fn parse_domain_size_overrides(register_config: &serde_json::Value) -> (Option<u64>, Option<u64>) {
    let send = register_config.get("max_send_size_mb").and_then(|x| x.as_u64()).map(|m| m * 1024 * 1024);
    let recv = register_config.get("max_receive_size_mb").and_then(|x| x.as_u64()).map(|m| m * 1024 * 1024);
    (send, recv)
}

/// 给定发件域名/收件域名，结合全局 settings 与各自 register_config 覆盖，得到生效的 send/receive 字节上限
/// from_domain / to_domain 可为 None（外部域名），此时只用全局上限
pub async fn resolve_size_limits(
    pool: &PgPool,
    from_domain: Option<&str>,
    to_domain: Option<&str>,
) -> MailSizeLimits {
    let mut limits = load_global_size_limits(pool).await;

    // 发件人域名：覆盖 max_send_bytes
    if let Some(d) = from_domain {
        if let Ok(Some((cfg,))) = sqlx::query_as::<_, (serde_json::Value,)>(
            "SELECT register_config FROM domains WHERE LOWER(name) = LOWER($1)"
        )
        .bind(d)
        .fetch_optional(pool)
        .await
        {
            let (send_override, _) = parse_domain_size_overrides(&cfg);
            if let Some(v) = send_override { limits.max_send_bytes = v; }
        }
    }

    // 收件人域名：覆盖 max_receive_bytes
    if let Some(d) = to_domain {
        if let Ok(Some((cfg,))) = sqlx::query_as::<_, (serde_json::Value,)>(
            "SELECT register_config FROM domains WHERE LOWER(name) = LOWER($1)"
        )
        .bind(d)
        .fetch_optional(pool)
        .await
        {
            let (_, recv_override) = parse_domain_size_overrides(&cfg);
            if let Some(v) = recv_override { limits.max_receive_bytes = v; }
        }
    }

    limits
}

/// 增加邮箱已用空间（大小写不敏感匹配 username/domain）
/// size_delta 可为正（投递/写入）或负（删除邮件）
pub async fn add_mailbox_used_bytes(
    pool: &PgPool,
    username: &str,
    domain: &str,
    size_delta: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE mailboxes SET used_bytes = GREATEST(used_bytes + $1, 0)
         WHERE LOWER(username) = LOWER($2)
           AND domain_id = (SELECT id FROM domains WHERE LOWER(name) = LOWER($3))"
    )
    .bind(size_delta)
    .bind(username)
    .bind(domain)
    .execute(pool)
    .await?;
    Ok(())
}

/// 通过扫描 maildir 文件系统重算所有邮箱的 used_bytes（修复历史不一致）
pub async fn recalc_all_used_bytes(pool: &PgPool, maildir_base: &str) -> anyhow::Result<usize> {
    // 获取所有邮箱 (id, username, domain_name)
    let rows: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT m.id, m.username, d.name FROM mailboxes m JOIN domains d ON m.domain_id = d.id"
    )
    .fetch_all(pool)
    .await?;

    let mut updated = 0usize;
    for (id, username, domain_name) in rows {
        let dir = std::path::PathBuf::from(maildir_base).join(&domain_name).join(&username);
        let total = dir_size(&dir);
        let res = sqlx::query("UPDATE mailboxes SET used_bytes = $1 WHERE id = $2")
            .bind(total as i64)
            .bind(id)
            .execute(pool)
            .await;
        if res.is_ok() { updated += 1; }
    }
    Ok(updated)
}

/// 递归计算目录总字节数（忽略错误的条目）
fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                total += meta.len();
            } else if meta.is_dir() {
                total += dir_size(&p);
            }
        }
    }
    total
}
