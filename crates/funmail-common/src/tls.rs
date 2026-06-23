use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// TLS 证书存储：从数据库加载证书，定期刷新，提供 TlsAcceptor
#[derive(Clone)]
pub struct TlsCertStore {
    pool: PgPool,
    acceptor: Arc<RwLock<Option<tokio_rustls::TlsAcceptor>>>,
    hostname: String,
}

impl TlsCertStore {
    pub fn new(pool: PgPool, hostname: String) -> Self {
        Self {
            pool,
            acceptor: Arc::new(RwLock::new(None)),
            hostname,
        }
    }

    /// 从数据库重新加载证书
    pub async fn reload(&self) -> anyhow::Result<()> {
        self.reload_with_alpn(vec![b"smtp".to_vec(), b"imap".to_vec(), b"pop3".to_vec()]).await
    }

    /// 从数据库重新加载证书（自定义 ALPN）
    pub async fn reload_with_alpn(&self, alpn_protocols: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let certs = self.load_certs_from_db().await?;
        if certs.is_empty() {
            let mut acc = self.acceptor.write().await;
            if acc.is_some() {
                tracing::warn!("TLS: 数据库中没有证书，TLS 暂不可用");
                *acc = None;
            }
            return Ok(());
        }

        // 在拿锁之前完成所有耗时操作（数据库查询、PEM解析、ServerConfig构建）
        let server_config = Self::build_server_config(certs, alpn_protocols)?;
        let new_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        // 只在替换时短暂持写锁
        let mut acc = self.acceptor.write().await;
        let changed = acc.is_none();
        *acc = Some(new_acceptor);
        drop(acc); // 显式释放写锁，避免后续操作意外持锁
        if changed {
            tracing::info!("TLS: 证书已加载，TLS 可用");
        }
        Ok(())
    }

    /// 获取当前 TlsAcceptor（可能为 None 如果没有证书）
    pub async fn acceptor(&self) -> Option<tokio_rustls::TlsAcceptor> {
        self.acceptor.read().await.clone()
    }

    /// 是否有可用的 TLS 配置
    pub async fn is_available(&self) -> bool {
        self.acceptor.read().await.is_some()
    }

    /// 从数据库加载所有证书
    async fn load_certs_from_db(&self) -> anyhow::Result<Vec<(String, String, String)>> {
        // (domain, cert_pem, key_pem)
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT domain, cert_pem, key_pem FROM certs WHERE cert_pem IS NOT NULL AND key_pem IS NOT NULL ORDER BY domain"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// 构建 rustls ServerConfig
    fn build_server_config(
        certs: Vec<(String, String, String)>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> anyhow::Result<rustls::ServerConfig> {
        let mut cert_resolver = CertResolver::new();

        for (domain, cert_pem, key_pem) in &certs {
            let cert_chain = Self::parse_certs(cert_pem)?;
            let key = Self::parse_key(key_pem)?;

            cert_resolver.add(domain.clone(), cert_chain, key);
        }

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver));

        config.alpn_protocols = alpn_protocols;

        Ok(config)
    }

    /// 解析 PEM 格式证书链
    fn parse_certs(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            anyhow::bail!("没有找到有效的证书");
        }
        Ok(certs)
    }

    /// 解析 PEM 格式私钥
    fn parse_key(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());

        // 先尝试 PKCS8
        if let Ok(Some(key)) = rustls_pemfile::private_key(&mut reader) {
            return Ok(key);
        }

        // 再尝试 RSA
        reader = std::io::BufReader::new(pem.as_bytes());
        if let Ok(Some(key)) = rustls_pemfile::rsa_private_keys(&mut reader)
            .next()
            .transpose()
        {
            return Ok(PrivateKeyDer::from(key));
        }

        anyhow::bail!("没有找到有效的私钥")
    }
}

/// 基于 SNI 的证书解析器
#[derive(Debug)]
struct CertResolver {
    entries: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    default: Option<Arc<rustls::sign::CertifiedKey>>,
}

impl CertResolver {
    fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            default: None,
        }
    }

    fn add(&mut self, domain: String, cert_chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) {
        let signing_key = match rustls::crypto::ring::sign::any_supported_type(&key) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("TLS: 域名 {} 的私钥不受支持: {:?}，跳过此证书", domain, e);
                return;
            }
        };

        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(cert_chain, signing_key));

        // 存储域名映射
        self.entries.insert(domain.clone(), certified_key.clone());

        // 第一个证书作为默认证书
        if self.default.is_none() {
            self.default = Some(certified_key);
        }
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // 优先按 SNI 匹配
        if let Some(sni) = client_hello.server_name() {
            if let Some(key) = self.entries.get(sni) {
                return Some(key.clone());
            }
        }

        // 回退到默认证书
        self.default.clone()
    }
}
