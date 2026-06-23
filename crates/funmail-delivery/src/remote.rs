use std::sync::Arc;

use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// 远程投递：通过 SMTP 发送到目标邮件服务器
pub async fn deliver_remote(
    pool: &PgPool,
    from_addr: &str,
    to_addr: &str,
    data_path: &str,
    hostname: &str,
) -> anyhow::Result<()> {
    let domain = to_addr
        .rsplitn(2, '@')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid address: {}", to_addr))?;

    // DNS MX 查询
    let mx_hosts = crate::dns::lookup_mx(domain).await?;

    if mx_hosts.is_empty() {
        anyhow::bail!("No MX records found for domain: {}", domain);
    }

    // 读取邮件数据
    let mut data = std::fs::read(data_path)?;

    // DKIM 签名：查询发件域名的私钥并签名
    let from_domain = from_addr.rsplitn(2, '@').next().unwrap_or("");
    if !from_domain.is_empty() {
        match fetch_dkim_key(pool, from_domain).await {
            Ok(Some((selector, private_key_pem))) => {
                match crate::dkim::sign_dkim(&private_key_pem, &selector, from_domain, &data) {
                    Ok(signature_value) => {
                        // 在邮件头部的第一个空行（\r\n\r\n）前插入 DKIM-Signature 头
                        // pos 指向 \r\n\r\n 的第一个 \r，插入 "\r\nDKIM-Signature: ..." 使前一个头正确换行
                        let dkim_header = format!("\r\nDKIM-Signature: {}", signature_value);
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header_bytes = dkim_header.into_bytes();
                            data.splice(pos..pos, header_bytes);
                        }
                        tracing::debug!("DKIM 签名已添加: from_domain={}", from_domain);
                    }
                    Err(e) => {
                        tracing::warn!("DKIM 签名失败（继续投递）: {}", e);
                    }
                }
            }
            Ok(None) => {
                // 域名未配置 DKIM 私钥，跳过签名
            }
            Err(e) => {
                tracing::warn!("查询 DKIM 私钥失败: {}", e);
            }
        }
    }

    // 依次尝试 MX 主机
    let mut last_error = String::new();
    for mx in &mx_hosts {
        // 先解析 IPv4 地址
        let ipv4_addrs = match crate::dns::lookup_a(mx).await {
            Ok(addrs) => addrs,
            Err(e) => {
                last_error = format!("DNS A 记录查询失败: {} (MX: {})", e, mx);
                tracing::warn!("DNS A 记录查询失败 {}: {}", mx, e);
                continue;
            }
        };

        if ipv4_addrs.is_empty() {
            last_error = format!("MX 主机无 IPv4 地址: {}", mx);
            tracing::warn!("MX 主机 {} 无 IPv4 地址（可能只有 IPv6，容器不支持）", mx);
            continue;
        }

        // 尝试每个 IPv4 地址
        for addr in &ipv4_addrs {
            let target = std::net::SocketAddr::new(addr.ip(), 25);
            match try_smtp_delivery(from_addr, to_addr, &data, &target, hostname, mx).await {
                Ok(()) => {
                    tracing::info!(
                        "远程投递成功: {} -> {} via {} ({})",
                        from_addr, to_addr, mx, target.ip()
                    );
                    return Ok(());
                }
                Err(e) => {
                    last_error = format!("{} (MX: {} IP: {})", e, mx, target.ip());
                    tracing::warn!(
                        "远程投递失败 {} -> {} via {} ({}): {}",
                        from_addr, to_addr, mx, target.ip(), e
                    );
                }
            }
        }
    }

    anyhow::bail!("All MX hosts failed: {}", last_error)
}

/// SMTP 流：可以是明文、TLS 或已关闭
enum SmtpStream {
    Plain(BufReader<TcpStream>),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    Closed,
}

impl SmtpStream {
    async fn read_line(&mut self, buf: &mut String) -> anyhow::Result<usize> {
        buf.clear();
        match self {
            SmtpStream::Plain(reader) => reader.read_line(buf).await.map_err(Into::into),
            SmtpStream::Tls(stream) => {
                let mut byte = [0u8; 1];
                let mut total = 0usize;
                loop {
                    let n = stream.read(&mut byte).await?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                    buf.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Ok(total)
            }
            SmtpStream::Closed => anyhow::bail!("连接已关闭"),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        match self {
            SmtpStream::Plain(reader) => reader.get_mut().write_all(data).await?,
            SmtpStream::Tls(stream) => stream.write_all(data).await?,
            SmtpStream::Closed => anyhow::bail!("连接已关闭"),
        }
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        match self {
            SmtpStream::Plain(reader) => reader.get_mut().flush().await?,
            SmtpStream::Tls(stream) => stream.flush().await?,
            SmtpStream::Closed => anyhow::bail!("连接已关闭"),
        }
        Ok(())
    }

    /// 将明文流升级为 TLS 流（STARTTLS）
    async fn upgrade_to_tls(&mut self, domain: &str) -> anyhow::Result<()> {
        // 从 SmtpStream 中取出底层 TcpStream
        let plain_stream = match std::mem::replace(self, SmtpStream::Closed) {
            SmtpStream::Plain(reader) => reader.into_inner(),
            SmtpStream::Tls(_) => anyhow::bail!("已经是 TLS 连接"),
            SmtpStream::Closed => anyhow::bail!("连接已关闭"),
        };

        // 构建 rustls 客户端配置
        let mut root_certs = rustls::RootCertStore::empty();
        // 加载系统原生证书
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_certs.add(cert)?;
        }
        if root_certs.is_empty() {
            tracing::warn!("未找到系统根证书，TLS 验证可能失败");
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
            .map_err(|e| anyhow::anyhow!("无效的服务器名: {:?}", e))?;

        let tls_stream = connector.connect(server_name, plain_stream).await?;
        *self = SmtpStream::Tls(tls_stream);
        Ok(())
    }
}

/// 尝试通过 SMTP 投递到目标服务器
/// 支持 STARTTLS：如果对方 EHLO 响应包含 STARTTLS，则自动升级加密
async fn try_smtp_delivery(
    from_addr: &str,
    to_addr: &str,
    data: &[u8],
    target: &std::net::SocketAddr,
    hostname: &str,
    mx_host: &str,
) -> anyhow::Result<()> {
    // 连接到目标 MX 服务器
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(target),
    )
    .await??;

    let mut smtp = SmtpStream::Plain(BufReader::new(stream));

    // 读取欢迎信息
    let mut greeting = String::new();
    smtp.read_line(&mut greeting).await?;
    if !greeting.starts_with("220") {
        anyhow::bail!("SMTP 连接被拒绝: {}", greeting.trim());
    }

    // EHLO
    smtp.write_all(format!("EHLO {}\r\n", hostname).as_bytes()).await?;
    smtp.flush().await?;
    let ehlo_response = read_smtp_response_collect(&mut smtp, "250").await?;

    // 检查是否支持 STARTTLS
    let supports_starttls = ehlo_response
        .lines()
        .any(|l| l.trim().to_uppercase().contains("STARTTLS"));

    // 如果支持 STARTTLS，升级加密
    if supports_starttls {
        smtp.write_all(b"STARTTLS\r\n").await?;
        smtp.flush().await?;
        read_smtp_response(&mut smtp, "220").await?;

        // 使用 rustls 进行 TLS 升级（用目标 MX 主机名验证证书）
        smtp.upgrade_to_tls(mx_host).await?;

        // TLS 升级后需要重新 EHLO（RFC 3207）
        smtp.write_all(format!("EHLO {}\r\n", hostname).as_bytes()).await?;
        smtp.flush().await?;
        read_smtp_response(&mut smtp, "250").await?;

        tracing::debug!("远程投递 STARTTLS 升级成功: {}", target.ip());
    } else {
        tracing::debug!("远程 MX 不支持 STARTTLS，使用明文投递: {}", target.ip());
    }

    // MAIL FROM
    smtp.write_all(format!("MAIL FROM:<{}>\r\n", from_addr).as_bytes()).await?;
    smtp.flush().await?;
    read_smtp_response(&mut smtp, "250").await?;

    // RCPT TO
    smtp.write_all(format!("RCPT TO:<{}>\r\n", to_addr).as_bytes()).await?;
    smtp.flush().await?;
    read_smtp_response(&mut smtp, "250").await?;

    // DATA
    smtp.write_all(b"DATA\r\n").await?;
    smtp.flush().await?;
    read_smtp_response(&mut smtp, "354").await?;

    // 发送邮件内容（点号转义）
    let content = String::from_utf8_lossy(data);
    for line in content.lines() {
        if line.starts_with('.') {
            smtp.write_all(b".").await?;
        }
        smtp.write_all(line.as_bytes()).await?;
        smtp.write_all(b"\r\n").await?;
    }
    smtp.write_all(b".\r\n").await?;
    smtp.flush().await?;
    read_smtp_response(&mut smtp, "250").await?;

    // QUIT
    smtp.write_all(b"QUIT\r\n").await?;
    smtp.flush().await?;

    Ok(())
}

/// 读取 SMTP 多行响应，检查是否以指定代码开头
async fn read_smtp_response(smtp: &mut SmtpStream, expected_code: &str) -> anyhow::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = smtp.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("SMTP 连接意外关闭");
        }
        let trimmed = line.trim();
        if trimmed.starts_with(expected_code) {
            if trimmed.len() > 3 && trimmed.as_bytes()[3] == b' ' {
                return Ok(());
            }
        } else {
            anyhow::bail!("SMTP 错误响应: {}", trimmed);
        }
    }
}

/// 读取 SMTP 多行响应并收集全部内容（用于 EHLO 解析扩展）
async fn read_smtp_response_collect(
    smtp: &mut SmtpStream,
    expected_code: &str,
) -> anyhow::Result<String> {
    let mut full_response = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = smtp.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("SMTP 连接意外关闭");
        }
        full_response.push_str(&line);
        let trimmed = line.trim();
        if trimmed.starts_with(expected_code) {
            if trimmed.len() > 3 && trimmed.as_bytes()[3] == b' ' {
                return Ok(full_response);
            }
        } else {
            anyhow::bail!("SMTP 错误响应: {}", trimmed);
        }
    }
}

/// 从数据库查询域名的 DKIM 私钥和选择器
/// 返回 None 表示域名未配置 DKIM（跳过签名）
async fn fetch_dkim_key(pool: &PgPool, domain: &str) -> anyhow::Result<Option<(String, String)>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT dkim_selector, dkim_private_key FROM domains WHERE LOWER(name) = LOWER($1) AND enabled = true"
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((selector, Some(key))) if !key.is_empty() => Ok(Some((selector, key))),
        _ => Ok(None),
    }
}
