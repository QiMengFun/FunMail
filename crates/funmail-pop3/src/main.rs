use clap::Parser;
use funmail_common::db;
use funmail_common::TlsCertStore;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "funmail-pop3", about = "FunMail POP3 服务器")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:110")]
    listen: String,

    /// 隐式 TLS 监听地址（如 0.0.0.0:995），连接后立即 TLS 握手
    #[arg(long)]
    tls_listen: Option<String>,

    #[arg(long)]
    database_url: Option<String>,

    #[arg(long, default_value = "/var/lib/funmail/maildir")]
    maildir_base: String,

    #[arg(long, default_value = "mail.example.com")]
    hostname: String,
}

struct AppState {
    pool: PgPool,
    maildir_base: String,
    tls_cert_store: TlsCertStore,
}

/// POP3 邮件信息
struct Pop3Message {
    id: String,
    size: usize,
    data: Vec<u8>,
    deleted: bool,
}

/// 可升级的流：先以 Plain TCP 运行，STLS 后升级为 TLS
enum UpgradableStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    Closed,
}

impl UpgradableStream {
    async fn read_line(&mut self, buf: &mut String) -> anyhow::Result<usize> {
        match self {
            UpgradableStream::Plain(stream) => {
                buf.clear();
                let mut byte = [0u8; 1];
                let mut total = 0usize;
                loop {
                    stream.readable().await?;
                    let n = match stream.try_read(&mut byte) {
                        Ok(n) => n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e.into()),
                    };
                    if n == 0 { break; } // EOF：客户端关闭连接
                    total += n;
                    buf.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Ok(total)
            }
            UpgradableStream::Tls(stream) => {
                buf.clear();
                let mut byte = [0u8; 1];
                let mut total = 0usize;
                loop {
                    let n = AsyncReadExt::read(stream, &mut byte).await?;
                    if n == 0 { break; }
                    total += n;
                    buf.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Ok(total)
            }
            UpgradableStream::Closed => anyhow::bail!("连接已关闭"),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        match self {
            UpgradableStream::Plain(stream) => {
                let mut written = 0usize;
                while written < data.len() {
                    stream.writable().await?;
                    match stream.try_write(&data[written..]) {
                        Ok(n) => written += n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(())
            }
            UpgradableStream::Tls(stream) => {
                AsyncWriteExt::write_all(stream, data).await?;
                Ok(())
            }
            UpgradableStream::Closed => anyhow::bail!("连接已关闭"),
        }
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        match self {
            UpgradableStream::Plain(_) => Ok(()),
            UpgradableStream::Tls(stream) => {
                AsyncWriteExt::flush(stream).await?;
                Ok(())
            }
            UpgradableStream::Closed => Ok(()),
        }
    }

    fn take_plain_stream(&mut self) -> anyhow::Result<TcpStream> {
        let this = std::mem::replace(self, UpgradableStream::Closed);
        match this {
            UpgradableStream::Plain(stream) => Ok(stream),
            UpgradableStream::Tls(stream) => {
                *self = UpgradableStream::Tls(stream);
                anyhow::bail!("连接已经是 TLS");
            }
            UpgradableStream::Closed => anyhow::bail!("连接已关闭"),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 安装 rustls crypto provider（rustls 0.23+ 要求）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    tracing::info!("FunMail POP3 正在启动...");

    let args = Args::parse();
    let database_url = args.database_url.unwrap_or_else(|| {
        "postgres://funmail:funmail@127.0.0.1:5432/funmail".to_string()
    });

    let pool = db::create_pool(&database_url).await?;
    tracing::info!("数据库连接成功");

    let tls_cert_store = TlsCertStore::new(pool.clone(), args.hostname.clone());
    if let Err(e) = tls_cert_store.reload().await {
        tracing::warn!("TLS 证书加载失败（TLS 暂不可用）: {}", e);
    }

    let state = Arc::new(AppState {
        pool,
        maildir_base: args.maildir_base.clone(),
        tls_cert_store,
    });

    // 定期刷新 TLS 证书
    let reload_tls = state.tls_cert_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if let Err(e) = reload_tls.reload().await {
                tracing::warn!("TLS 证书刷新失败: {}", e);
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("POP3 监听地址: {} (STARTTLS)", args.listen);

    // 隐式 TLS 监听（端口 995）
    if let Some(ref tls_addr) = args.tls_listen {
        let tls_listener = tokio::net::TcpListener::bind(tls_addr).await?;
        tracing::info!("POP3 隐式 TLS 监听地址: {}", tls_addr);
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
                                            let mut wrapped = UpgradableStream::Tls(tls_stream);
                                            if let Err(e) = run_pop3_session(&mut wrapped, addr, &state, true).await {
                                                tracing::debug!("POP3 TLS 会话错误 {}: {}", addr, e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("POP3 TLS 握手失败 {}: {}", addr, e);
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!("POP3 TLS 连接但无证书: {}", addr);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("POP3 TLS accept 错误: {}", e);
                    }
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_pop3_session(stream, addr, &state).await {
                tracing::debug!("POP3 会话错误 {}: {}", addr, e);
            }
        });
    }
}

async fn handle_pop3_session(
    stream: TcpStream,
    addr: std::net::SocketAddr,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    let mut wrapped = UpgradableStream::Plain(stream);
    run_pop3_session(&mut wrapped, addr, state, false).await
}

async fn run_pop3_session(
    stream: &mut UpgradableStream,
    addr: std::net::SocketAddr,
    state: &Arc<AppState>,
    implicit_tls: bool,
) -> anyhow::Result<()> {
    let client_ip = addr.ip().to_string();
    let mut tls_upgraded = implicit_tls;

    // 问候
    stream.write_all(b"+OK FunMail POP3 Server ready\r\n").await?;

    let mut authenticated = false;
    let mut auth_username = String::new();
    let mut auth_domain = String::new();
    let mut mailbox_id: i32 = 0;
    let mut messages: Vec<Pop3Message> = Vec::new();

    let mut line = String::new();
    loop {
        line.clear();
        let n = stream.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let line = line.trim_end_matches("\r\n").trim_end_matches('\n');
        let (cmd, args) = if let Some(pos) = line.find(' ') {
            (&line[..pos], &line[pos + 1..])
        } else {
            (line.trim_end(), "")
        };

        match cmd.to_uppercase().as_str() {
            "STLS" => {
                if tls_upgraded {
                    stream.write_all(b"-ERR TLS already active\r\n").await?;
                    continue;
                }
                if authenticated {
                    stream.write_all(b"-ERR STLS not allowed after authentication\r\n").await?;
                    continue;
                }

                let acceptor = state.tls_cert_store.acceptor().await;
                match acceptor {
                    Some(acceptor) => {
                        stream.write_all(b"+OK Begin TLS negotiation\r\n").await?;
                        stream.flush().await?;

                        let tcp_stream = stream.take_plain_stream()?;
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                *stream = UpgradableStream::Tls(tls_stream);
                                tls_upgraded = true;
                                // RFC 2595: STLS 后必须重置状态
                                authenticated = false;
                                auth_username.clear();
                                auth_domain.clear();
                                tracing::info!("POP3: TLS 升级成功 ({})", client_ip);
                            }
                            Err(e) => {
                                tracing::warn!("POP3: TLS 握手失败: {}", e);
                                break;
                            }
                        }
                    }
                    None => {
                        stream.write_all(b"-ERR TLS not available\r\n").await?;
                    }
                }
            }
            "USER" => {
                // 明文连接禁止 USER（防止密码被嗅探），必须先 STLS
                if !tls_upgraded {
                    stream.write_all(b"-ERR Use STLS to upgrade to TLS first\r\n").await?;
                    continue;
                }
                // USER username@domain 或 USER username
                if let Some((user, domain)) = args.split_once('@') {
                    auth_username = user.to_string();
                    auth_domain = domain.to_string();
                } else {
                    auth_username = args.to_string();
                    auth_domain.clear();
                }
                stream.write_all(b"+OK User name accepted\r\n").await?;
            }
            "PASS" => {
                // 明文连接禁止 PASS（防止密码被嗅探），必须先 STLS
                if !tls_upgraded {
                    stream.write_all(b"-ERR Use STLS to upgrade to TLS first\r\n").await?;
                    continue;
                }
                if auth_username.is_empty() {
                    stream.write_all(b"-ERR Need USER before PASS\r\n").await?;
                    continue;
                }
                let password = args;

                // 如果没有指定域名，尝试查找
                if auth_domain.is_empty() {
                    let domain = sqlx::query_scalar::<_, String>(
                        "SELECT d.name FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND m.enabled = true AND d.enabled = true LIMIT 1"
                    )
                    .bind(&auth_username)
                    .fetch_optional(&state.pool)
                    .await?;

                    match domain {
                        Some(d) => auth_domain = d,
                        None => {
                            stream.write_all(b"-ERR Authentication failed\r\n").await?;
                            continue;
                        }
                    }
                }

                match db::authenticate_mailbox(&state.pool, &auth_username, &auth_domain, password).await {
                    Ok(Some(id)) => {
                        // 检查协议权限：mailbox.protocols 非空时覆盖域名 register_config
                        let proto_row: Option<(Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
                            "SELECT m.protocols, d.register_config
                             FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                             WHERE m.username = $1 AND d.name = $2"
                        )
                        .bind(&auth_username)
                        .bind(&auth_domain)
                        .fetch_optional(&state.pool)
                        .await
                        .unwrap_or(None);

                        let allow_pop3 = proto_row
                            .map(|(mp, rc)| {
                                let cfg = match mp {
                                    Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
                                    _ => rc,
                                };
                                cfg.get("allow_pop3").and_then(|v| v.as_bool()).unwrap_or(true)
                            })
                            .unwrap_or(true);

                        if !allow_pop3 {
                            tracing::warn!("POP3 认证被拒（协议权限禁止 POP3）: {}@{}", auth_username, auth_domain);
                            stream.write_all(b"-ERR POP3 access denied for this account\r\n").await?;
                            continue;
                        }

                        authenticated = true;
                        mailbox_id = id;
                        db::update_last_login(&state.pool, mailbox_id, &client_ip).await?;
                        // 加载邮件列表
                        messages = load_messages(&state.maildir_base, &auth_domain, &auth_username)?;
                        stream.write_all(b"+OK Authentication successful\r\n").await?;
                        tracing::info!("POP3 登录成功: {}@{}", auth_username, auth_domain);
                    }
                    Ok(None) => {
                        stream.write_all(b"-ERR Authentication failed\r\n").await?;
                    }
                    Err(e) => {
                        tracing::warn!("POP3 认证错误: {}", e);
                        stream.write_all(b"-ERR Temporary authentication failure\r\n").await?;
                    }
                }
            }
            "STAT" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                let count = messages.iter().filter(|m| !m.deleted).count();
                let total_size: usize = messages.iter().filter(|m| !m.deleted).map(|m| m.size).sum();
                stream
                    .write_all(format!("+OK {} {}\r\n", count, total_size).as_bytes())
                    .await?;
            }
            "LIST" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                let active: Vec<(usize, &Pop3Message)> = messages
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| !m.deleted)
                    .collect();
                stream
                    .write_all(format!("+OK {} messages\r\n", active.len()).as_bytes())
                    .await?;
                for (idx, msg) in &active {
                    stream
                        .write_all(format!("{} {}\r\n", idx + 1, msg.size).as_bytes())
                        .await?;
                }
                stream.write_all(b".\r\n").await?;
            }
            "RETR" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                let msg_num: usize = match args.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        stream.write_all(b"-ERR Invalid message number\r\n").await?;
                        continue;
                    }
                };
                if msg_num == 0 || msg_num > messages.len() {
                    stream.write_all(b"-ERR No such message\r\n").await?;
                    continue;
                }
                let msg = &messages[msg_num - 1];
                if msg.deleted {
                    stream.write_all(b"-ERR Message deleted\r\n").await?;
                    continue;
                }
                stream
                    .write_all(format!("+OK {} octets\r\n", msg.size).as_bytes())
                    .await?;
                // 发送邮件内容，点填充
                let content = String::from_utf8_lossy(&msg.data);
                for line in content.lines() {
                    if line.starts_with('.') {
                        stream.write_all(b".").await?;
                    }
                    stream.write_all(line.as_bytes()).await?;
                    stream.write_all(b"\r\n").await?;
                }
                stream.write_all(b".\r\n").await?;
            }
            "DELE" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                let msg_num: usize = match args.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        stream.write_all(b"-ERR Invalid message number\r\n").await?;
                        continue;
                    }
                };
                if msg_num == 0 || msg_num > messages.len() {
                    stream.write_all(b"-ERR No such message\r\n").await?;
                    continue;
                }
                messages[msg_num - 1].deleted = true;
                stream.write_all(b"+OK Message deleted\r\n").await?;
            }
            "RSET" => {
                for msg in &mut messages {
                    msg.deleted = false;
                }
                stream.write_all(b"+OK\r\n").await?;
            }
            "NOOP" => {
                stream.write_all(b"+OK\r\n").await?;
            }
            "QUIT" => {
                // 删除标记为删除的邮件文件
                if authenticated {
                    for msg in &messages {
                        if msg.deleted {
                            let path = std::path::Path::new(&msg.id);
                            if path.exists() {
                                let _ = std::fs::remove_file(path);
                            }
                        }
                    }
                }
                stream.write_all(b"+OK FunMail POP3 Server signing off\r\n").await?;
                break;
            }
            "CAPA" => {
                stream.write_all(b"+OK Capability list follows\r\n").await?;
                stream.write_all(b"USER\r\n").await?;
                stream.write_all(b"PIPELINING\r\n").await?;
                stream.write_all(b"UIDL\r\n").await?;
                stream.write_all(b"TOP\r\n").await?;
                if !tls_upgraded {
                    stream.write_all(b"STLS\r\n").await?;
                }
                stream.write_all(b".\r\n").await?;
            }
            "UIDL" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                stream.write_all(b"+OK\r\n").await?;
                for (idx, msg) in messages.iter().enumerate() {
                    if !msg.deleted {
                        // 使用文件名哈希作为 UIDL
                        let uidl = format!("{:x}", md5_hash(&msg.id));
                        stream
                            .write_all(format!("{} {}\r\n", idx + 1, uidl).as_bytes())
                            .await?;
                    }
                }
                stream.write_all(b".\r\n").await?;
            }
            "TOP" => {
                if !authenticated {
                    stream.write_all(b"-ERR Not authenticated\r\n").await?;
                    continue;
                }
                let parts: Vec<&str> = args.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    stream.write_all(b"-ERR Syntax: TOP msg n\r\n").await?;
                    continue;
                }
                let msg_num: usize = match parts[0].parse() {
                    Ok(n) => n,
                    Err(_) => {
                        stream.write_all(b"-ERR Invalid message number\r\n").await?;
                        continue;
                    }
                };
                let line_count: usize = match parts[1].parse() {
                    Ok(n) => n,
                    Err(_) => {
                        stream.write_all(b"-ERR Invalid line count\r\n").await?;
                        continue;
                    }
                };
                if msg_num == 0 || msg_num > messages.len() {
                    stream.write_all(b"-ERR No such message\r\n").await?;
                    continue;
                }
                let msg = &messages[msg_num - 1];
                if msg.deleted {
                    stream.write_all(b"-ERR Message deleted\r\n").await?;
                    continue;
                }
                stream.write_all(b"+OK\r\n").await?;
                let content = String::from_utf8_lossy(&msg.data);
                let mut in_header = true;
                let mut body_lines = 0;
                for line in content.lines() {
                    if line.starts_with('.') {
                        stream.write_all(b".").await?;
                    }
                    stream.write_all(line.as_bytes()).await?;
                    stream.write_all(b"\r\n").await?;
                    if in_header {
                        if line.is_empty() {
                            in_header = false;
                        }
                    } else {
                        body_lines += 1;
                        if body_lines >= line_count {
                            break;
                        }
                    }
                }
                stream.write_all(b".\r\n").await?;
            }
            _ => {
                stream.write_all(b"-ERR Unknown command\r\n").await?;
            }
        }
    }

    Ok(())
}

/// 从 Maildir 加载邮件
fn load_messages(maildir_base: &str, domain: &str, username: &str) -> anyhow::Result<Vec<Pop3Message>> {
    let maildir = std::path::Path::new(maildir_base)
        .join(domain)
        .join(username)
        .join("new");

    let mut messages = Vec::new();
    if !maildir.exists() {
        return Ok(messages);
    }

    for entry in std::fs::read_dir(&maildir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let data = std::fs::read(&path)?;
        let size = data.len();
        let id = path.to_string_lossy().to_string();
        messages.push(Pop3Message {
            id,
            size,
            data,
            deleted: false,
        });
    }

    Ok(messages)
}

/// 简单 MD5 哈希（用于 UIDL）
fn md5_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
