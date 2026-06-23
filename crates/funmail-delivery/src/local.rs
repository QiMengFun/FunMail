use sqlx::PgPool;
use std::path::Path;

/// 本地投递：将邮件写入收件人的 Maildir
pub async fn deliver_local(
    pool: &PgPool,
    maildir_base: &str,
    from_addr: &str,
    to_addr: &str,
    data_path: &str,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = to_addr.rsplitn(2, '@').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid recipient address: {}", to_addr);
    }
    let username = parts[1]; // rsplitn 所以顺序反转
    let domain = parts[0];

    // 路径穿越防护：username 和 domain 不允许包含路径分隔符或 ..
    if username.contains('/') || username.contains('\\') || username.contains("..") {
        anyhow::bail!("Invalid username (path traversal): {}", username);
    }
    if domain.contains('/') || domain.contains('\\') || domain.contains("..") {
        anyhow::bail!("Invalid domain (path traversal): {}", domain);
    }

    // 验证邮箱存在
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mailboxes m JOIN domains d ON m.domain_id = d.id
         WHERE m.username = $1 AND d.name = $2 AND m.enabled = true AND d.enabled = true"
    )
    .bind(username)
    .bind(domain)
    .fetch_one(pool)
    .await?;

    if exists == 0 {
        anyhow::bail!("Mailbox not found: {}", to_addr);
    }

    // 检查配额
    let quota: Option<(i64, i32)> = sqlx::query_as(
        "SELECT used_bytes, quota_mb FROM mailboxes m
         JOIN domains d ON m.domain_id = d.id
         WHERE m.username = $1 AND d.name = $2"
    )
    .bind(username)
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    if let Some((used_bytes, quota_mb)) = quota {
        // quota_mb = 0 表示禁止接收新邮件
        if quota_mb == 0 {
            anyhow::bail!("Mailbox blocked (quota=0): {}", to_addr);
        }
        let quota_bytes = quota_mb as i64 * 1024 * 1024;
        if used_bytes >= quota_bytes {
            anyhow::bail!("Mailbox quota exceeded: {}", to_addr);
        }
    }

    // 读取邮件数据
    let data = std::fs::read(data_path)?;
    let size = data.len() as i64;

    // 写入 Maildir/new
    let maildir = Path::new(maildir_base)
        .join(domain)
        .join(username);

    let new_dir = maildir.join("new");
    let cur_dir = maildir.join("cur");
    std::fs::create_dir_all(&new_dir)?;
    std::fs::create_dir_all(&cur_dir)?;

    // Maildir 文件名: time.pid.count
    let filename = format!(
        "{}.{}.{}",
        chrono::Utc::now().timestamp(),
        std::process::id(),
        uuid::Uuid::new_v4().as_simple()
    );

    let dest_path = new_dir.join(&filename);
    std::fs::write(&dest_path, &data)?;

    // 更新邮箱已用空间（大小写不敏感）
    funmail_common::db::add_mailbox_used_bytes(pool, username, domain, size).await?;

    // 检查转发规则
    let forward_to: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT forward_to FROM mailboxes WHERE LOWER(username) = LOWER($1) AND domain_id = (SELECT id FROM domains WHERE LOWER(name) = LOWER($2))"
    )
    .bind(username)
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    if let Some(fwd) = forward_to {
        // 转发邮件的 from_addr 使用当前邮箱地址（而非原始发件人），
        // 这样 DKIM 签名时用的是本域名私钥，收件方能正确验证
        let forward_from = format!("{}@{}", username, domain);
        if let Some(addrs) = fwd.as_array() {
            for addr in addrs {
                if let Some(addr_str) = addr.as_str() {
                    // 创建转发队列条目
                    let data_path_str = data_path.to_string();
                    sqlx::query(
                        "INSERT INTO mail_queue (from_addr, to_addr, data_path, status, direction, size_bytes)
                         VALUES ($1, $2, $3, 'pending', 'outbound', $4)"
                    )
                    .bind(&forward_from)
                    .bind(addr_str)
                    .bind(&data_path_str)
                    .bind(size)
                    .execute(pool)
                    .await?;
                }
            }
        }
    }

    tracing::debug!("本地投递成功: {} -> {} ({} bytes)", from_addr, to_addr, size);
    Ok(())
}
