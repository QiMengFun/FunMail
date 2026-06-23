pub fn start_all(pool: sqlx::PgPool, acme_staging: bool) {
    // 定期刷新 ACME 证书
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = crate::acme::check_renewals(&pool_clone, acme_staging).await {
                tracing::warn!("ACME 证书续签检查失败: {}", e);
            }
        }
    });

    // 定期清理过期邮件日志
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
        loop {
            interval.tick().await;
            // 清理 90 天前的邮件日志
            let _ = sqlx::query(
                "DELETE FROM mail_logs WHERE created_at < NOW() - INTERVAL '90 days'"
            )
            .execute(&pool_clone)
            .await;
            tracing::debug!("过期邮件日志已清理");
        }
    });

    // 定期清理已投递的队列条目
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let _ = sqlx::query(
                "DELETE FROM mail_queue WHERE status IN ('delivered', 'bounced') AND updated_at < NOW() - INTERVAL '7 days'"
            )
            .execute(&pool_clone)
            .await;
            tracing::debug!("过期队列条目已清理");
        }
    });

    // 定期更新系统指标
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = crate::tasks::collect_metrics(&pool_clone).await;
        }
    });

    // 定期检查并创建 mail_logs 分区（每6小时）
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(6 * 3600));
        loop {
            interval.tick().await;
            if let Err(e) = crate::db::ensure_partitions(&pool_clone).await {
                tracing::warn!("定时分区检查失败: {}", e);
            }
        }
    });
}

pub async fn collect_metrics(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let cpu_usage = sys.global_cpu_usage();
    let mem = sys.used_memory();
    let mem_total = sys.total_memory();

    let queue_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'pending'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let queue_deferred: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_queue WHERE status = 'deferred'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    sqlx::query(
        "INSERT INTO system_metrics (cpu_usage, memory_used_gb, memory_total_gb, queue_pending, queue_deferred)
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(cpu_usage as f32)
    .bind(mem as f64 / 1073741824.0)
    .bind(mem_total as f64 / 1073741824.0)
    .bind(queue_pending as i32)
    .bind(queue_deferred as i32)
    .execute(pool)
    .await?;

    Ok(())
}
