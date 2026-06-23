use chrono::Datelike;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn create_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn init_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = create_pool(database_url).await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let schema = include_str!("../../../sql/schema.sql");
    
    // 按分号分割，逐条执行（sqlx 一次只能执行一条语句）
    for statement in schema.split(';') {
        // 移除注释行，只保留有效 SQL
        let sql: String = statement
            .lines()
            .filter(|line| !line.trim().starts_with("--"))
            .collect::<Vec<&str>>()
            .join(" ");
        let sql = sql.trim();
        if sql.is_empty() {
            continue;
        }
        sqlx::query(sql).execute(pool).await?;
    }
    
    Ok(())
}

pub async fn seed_defaults(pool: &PgPool) -> anyhow::Result<()> {
    let defaults = [
        ("smtp_config", serde_json::json!({
            "max_message_size_mb": 50,
            "max_recipients": 100,
            "require_auth_for_outbound": true,
            "starttls_enabled": true,
            "max_attachment_size_mb": 25,
        })),
        ("pop3_config", serde_json::json!({
            "starttls_enabled": true,
        })),
        ("imap_config", serde_json::json!({
            "starttls_enabled": true,
            "max_connections": 1000,
        })),
        ("delivery_config", serde_json::json!({
            "max_retries": 5,
            "retry_base_interval_secs": 300,
            "retry_max_interval_secs": 86400,
            "worker_count": 4,
        })),
        ("security_config", serde_json::json!({
            "spam_filter_enabled": true,
            "spam_threshold": 5.0,
            "spam_action": "mark",
            "rbl_enabled": true,
            "rbl_servers": ["zen.spamhaus.org", "bl.spamcop.net"],
            "virus_scan_enabled": false,
            "virus_scan_mode": "clamd_tcp",
            "clamd_tcp_host": "127.0.0.1",
            "clamd_tcp_port": 3310,
            "clamd_unix_path": "/var/run/clamav/clamd.ctl",
            "virus_scan_command": "clamdscan",
            "virus_action": "reject",
        })),
        ("jwt_secret", serde_json::json!("")),
        ("webmail_rate_limit", serde_json::json!({
            "attempt_window_secs": 60,
            "login_max_per_window": 5,
            "register_max_per_window": 5,
            "register_success_max_per_window": 1,
            "block_duration_secs": 30,
        })),
        ("notification_config", serde_json::json!({
            "enabled": false,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_password": "",
            "notify_to": [],
        })),
        ("timezone", serde_json::json!({
            "name": "Asia/Shanghai",
            "offset": "+08:00",
        })),
        ("language", serde_json::json!("zh")),
    ];

    for (key, value) in &defaults {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING"
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// 确保当月和未来月份的 mail_logs 分区存在
pub async fn ensure_partitions(pool: &PgPool) -> anyhow::Result<()> {
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

    Ok(())
}
