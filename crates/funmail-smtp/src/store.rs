use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 域名存储：缓存本服务器管理的域名列表
#[derive(Clone)]
pub struct DomainStore {
    pool: PgPool,
    domains: Arc<RwLock<HashSet<String>>>,
}

impl DomainStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            domains: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// 从数据库重新加载域名列表
    pub async fn reload(&self) -> anyhow::Result<()> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT name FROM domains WHERE enabled = true"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut domains = self.domains.write().await;
        // 统一转小写，确保域名大小写不敏感匹配（RFC 5321）
        *domains = rows.into_iter().map(|d| d.to_lowercase()).collect();
        Ok(())
    }

    /// 检查域名是否为本服务器管理（大小写不敏感）
    pub async fn is_local(&self, domain: &str) -> bool {
        let domains = self.domains.read().await;
        domains.contains(&domain.to_lowercase())
    }

    /// 获取所有本地域名
    pub async fn all_domains(&self) -> HashSet<String> {
        let domains = self.domains.read().await;
        domains.clone()
    }
}
