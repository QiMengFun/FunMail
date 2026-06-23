use chrono::{Datelike, Timelike};
use clap::Parser;
use funmail_common::db;
use funmail_common::TlsCertStore;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing_subscriber::EnvFilter;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Parser, Debug)]
#[command(name = "funmail-imap", about = "FunMail IMAP4 服务器")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:143")]
    listen: String,

    /// 隐式 TLS 监听地址（如 0.0.0.0:993），连接后立即 TLS 握手
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
    /// 服务器时区偏移（秒），从 settings 表 timezone 读取，默认 UTC+8 (28800)
    tz_offset_secs: i32,
}

/// IMAP 邮件信息
#[derive(Clone)]
struct ImapMessage {
    uid: u32,
    id: String,
    flags: Vec<String>,
    size: usize,
    data: Vec<u8>,
    internal_date: String, // IMAP INTERNALDATE 格式: "DD-Mon-YYYY HH:MM:SS +ZZZZ"
    sort_key: i64,         // 用于排序的 Unix 时间戳（秒），保证按时间先后排列
}

/// IMAP 文件夹
#[derive(Clone)]
struct ImapFolder {
    name: String,
    messages: Vec<ImapMessage>,
    uid_validity: u32,
    uid_next: u32,
}

/// IMAP 会话状态
#[derive(PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
}

/// 可升级的流：先以 Plain TCP 运行，STARTTLS 后升级为 TLS
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
            UpgradableStream::Plain(stream) => {
                use tokio::io::AsyncWriteExt;
                stream.flush().await?;
                Ok(())
            }
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

    tracing::info!("FunMail IMAP 正在启动...");

    let args = Args::parse();
    let database_url = args.database_url.unwrap_or_else(|| {
        "postgres://funmail:funmail@127.0.0.1:5432/funmail".to_string()
    });

    let pool = db::create_pool(&database_url).await?;
    tracing::info!("数据库连接成功");

    // 从数据库读取时区设置
    let tz_offset_secs = load_timezone_offset(&pool).await;

    let tls_cert_store = TlsCertStore::new(pool.clone(), args.hostname.clone());
    if let Err(e) = tls_cert_store.reload().await {
        tracing::warn!("TLS 证书加载失败（TLS 暂不可用）: {}", e);
    }

    let state = Arc::new(AppState {
        pool,
        maildir_base: args.maildir_base.clone(),
        tls_cert_store,
        tz_offset_secs,
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
    tracing::info!("IMAP 监听地址: {} (STARTTLS)", args.listen);

    // 隐式 TLS 监听（端口 993）
    if let Some(ref tls_addr) = args.tls_listen {
        let tls_listener = tokio::net::TcpListener::bind(tls_addr).await?;
        tracing::info!("IMAP 隐式 TLS 监听地址: {}", tls_addr);
        let state_tls = state.clone();
        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((stream, addr)) => {
                        let state = state_tls.clone();
                        tokio::spawn(async move {
                            // 立即 TLS 握手
                            let acceptor = state.tls_cert_store.acceptor().await;
                            match acceptor {
                                Some(acceptor) => {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            let mut wrapped = UpgradableStream::Tls(tls_stream);
                                            if let Err(e) = handle_imap_session_tls(&mut wrapped, addr, &state).await {
                                                tracing::debug!("IMAP TLS 会话错误 {}: {}", addr, e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("IMAP TLS 握手失败 {}: {}", addr, e);
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!("IMAP TLS 连接但无证书: {}", addr);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("IMAP TLS accept 错误: {}", e);
                    }
                }
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_imap_session(stream, addr, &state).await {
                tracing::debug!("IMAP 会话错误 {}: {}", addr, e);
            }
        });
    }
}

async fn handle_imap_session(
    stream: TcpStream,
    addr: std::net::SocketAddr,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    let mut wrapped = UpgradableStream::Plain(stream);
    run_imap_session(&mut wrapped, addr, state, false).await
}

/// 隐式 TLS 入口（连接后已经是 TLS 流）
async fn handle_imap_session_tls(
    stream: &mut UpgradableStream,
    addr: std::net::SocketAddr,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    run_imap_session(stream, addr, state, true).await
}

async fn run_imap_session(
    stream: &mut UpgradableStream,
    addr: std::net::SocketAddr,
    state: &Arc<AppState>,
    implicit_tls: bool,
) -> anyhow::Result<()> {
    let client_ip = addr.ip().to_string();

    // 问候
    // RFC 3501: 隐式 TLS 连接上不应通告 AUTH 机制（连接已加密，LOGIN 命令即可安全使用）
    // 否则 Outlook 等客户端会认为需要 AUTHENTICATE 而非 LOGIN，导致认证流程异常
    if implicit_tls {
        stream
            .write_all(b"* OK [CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED] FunMail IMAP4 Server ready\r\n")
            .await?;
    } else {
        stream
            .write_all(b"* OK [CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED STARTTLS AUTH=PLAIN AUTH=LOGIN] FunMail IMAP4 Server ready\r\n")
            .await?;
    }

    let mut session_state = ImapState::NotAuthenticated;
    let mut auth_username = String::new();
    let mut auth_domain = String::new();
    let mut mailbox_id: i32 = 0;
    let mut folders: Vec<ImapFolder> = Vec::new();
    let mut selected_folder: Option<String> = None;
    let mut tls_upgraded = implicit_tls;

    let mut line = String::new();
    loop {
        line.clear();
        let n = stream.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let raw_line = line.trim_end_matches("\r\n").trim_end_matches('\n').to_string();
        tracing::info!("IMAP 收到: {}", sanitize_log_line(&raw_line));
        let line = &raw_line;
        let line = line.trim_end_matches("\r\n").trim_end_matches('\n');

        // IMAP 命令格式: tag COMMAND [args]
        let (tag, command) = if let Some(pos) = line.find(' ') {
            (&line[..pos], &line[pos + 1..])
        } else {
            ("*", line.trim_end())
        };

        let (cmd, args) = if let Some(pos) = command.find(' ') {
            (&command[..pos], &command[pos + 1..])
        } else {
            (command, "")
        };

        match cmd.to_uppercase().as_str() {
            "CAPABILITY" => {
                // RFC 3501: 登录后不应再通告 AUTH 机制，否则部分客户端（如新版 Outlook）会认为认证未完成
                // 隐式 TLS 连接上也不通告 AUTH 机制（连接已加密，LOGIN 命令即可安全使用）
                if tls_upgraded {
                    if session_state == ImapState::NotAuthenticated {
                        stream.write_all(b"* CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED\r\n").await?;
                    } else {
                        stream.write_all(b"* CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED\r\n").await?;
                    }
                } else {
                    if session_state == ImapState::NotAuthenticated {
                        stream.write_all(b"* CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED STARTTLS AUTH=PLAIN AUTH=LOGIN\r\n").await?;
                    } else {
                        stream.write_all(b"* CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED\r\n").await?;
                    }
                }
                stream
                    .write_all(format!("{} OK CAPABILITY completed\r\n", tag).as_bytes())
                    .await?;
            }
            "STARTTLS" => {
                if tls_upgraded {
                    stream
                        .write_all(format!("{} BAD TLS already active\r\n", tag).as_bytes())
                        .await?;
                    continue;
                }

                let acceptor = state.tls_cert_store.acceptor().await;
                match acceptor {
                    Some(acceptor) => {
                        stream
                            .write_all(format!("{} OK Begin TLS negotiation\r\n", tag).as_bytes())
                            .await?;
                        stream.flush().await?;

                        let tcp_stream = stream.take_plain_stream()?;
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                *stream = UpgradableStream::Tls(tls_stream);
                                tls_upgraded = true;
                                // RFC 2595: STARTTLS 后必须重置状态
                                session_state = ImapState::NotAuthenticated;
                                auth_username.clear();
                                auth_domain.clear();
                                tracing::info!("IMAP: TLS 升级成功 ({})", client_ip);
                            }
                            Err(e) => {
                                tracing::warn!("IMAP: TLS 握手失败: {}", e);
                                break;
                            }
                        }
                    }
                    None => {
                        stream
                            .write_all(format!("{} NO TLS not available\r\n", tag).as_bytes())
                            .await?;
                    }
                }
            }
            "LOGIN" => {
                if session_state != ImapState::NotAuthenticated {
                    stream
                        .write_all(format!("{} BAD Already authenticated\r\n", tag).as_bytes())
                        .await?;
                    continue;
                }
                // 明文连接禁止 LOGIN（防止密码被嗅探），必须先 STARTTLS
                if !tls_upgraded {
                    stream
                        .write_all(format!("{} NO LOGIN requires STARTTLS encryption first\r\n", tag).as_bytes())
                        .await?;
                    continue;
                }
                // 解析 LOGIN <user> <pass> —— user/pass 可为带引号字符串或裸 atom
                let (user_part, pass_part) = match parse_astring_pair(args) {
                    Some(v) => v,
                    None => {
                        stream
                            .write_all(format!("{} BAD Invalid LOGIN arguments\r\n", tag).as_bytes())
                            .await?;
                        continue;
                    }
                };

                let (user, domain) = if let Some((u, d)) = user_part.split_once('@') {
                    (u.to_string(), d.to_string())
                } else {
                    match sqlx::query_scalar::<_, String>(
                        "SELECT d.name FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND m.enabled = true AND d.enabled = true LIMIT 1"
                    )
                    .bind(&user_part)
                    .fetch_optional(&state.pool)
                    .await
                    {
                        Ok(Some(d)) => (user_part, d),
                        _ => {
                            stream
                                .write_all(format!("{} NO LOGIN failed\r\n", tag).as_bytes())
                                .await?;
                            continue;
                        }
                    }
                };

                match db::authenticate_mailbox(&state.pool, &user, &domain, &pass_part).await {
                    Ok(Some(id)) => {
                        // 检查协议权限：mailbox.protocols 非空时覆盖域名 register_config
                        let proto_row: Option<(Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
                            "SELECT m.protocols, d.register_config
                             FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                             WHERE m.username = $1 AND d.name = $2"
                        )
                        .bind(&user)
                        .bind(&domain)
                        .fetch_optional(&state.pool)
                        .await
                        .unwrap_or(None);

                        let allow_imap = proto_row
                            .map(|(mp, rc)| {
                                let cfg = match mp {
                                    Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
                                    _ => rc,
                                };
                                cfg.get("allow_imap").and_then(|v| v.as_bool()).unwrap_or(true)
                            })
                            .unwrap_or(true);

                        if !allow_imap {
                            tracing::warn!("IMAP LOGIN 被拒（协议权限禁止 IMAP）: {}@{}", user, domain);
                            stream.write_all(format!("{} NO IMAP access denied for this account\r\n", tag).as_bytes()).await?;
                            continue;
                        }

                        mailbox_id = id;
                        auth_username = user.clone();
                        auth_domain = domain.clone();
                        session_state = ImapState::Authenticated;
                        let _ = db::update_last_login(&state.pool, mailbox_id, &client_ip).await;
                        tracing::info!("IMAP LOGIN 成功: {}@{}, mailbox_id={}, 开始加载文件夹", auth_username, auth_domain, mailbox_id);
                        folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);
                        stream
                            .write_all(format!("{} OK [CAPABILITY IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED] LOGIN completed\r\n", tag).as_bytes())
                            .await?;
                    }
                    Ok(None) | Err(_) => {
                        stream
                            .write_all(format!("{} NO LOGIN failed\r\n", tag).as_bytes())
                            .await?;
                    }
                }
            }
            "AUTHENTICATE" => {
                // AUTHENTICATE <mechanism> [initial-response]
                // 解析：args 第一段是机制名，剩下（可选）是 SASL-IR base64
                let mut sp = args.splitn(2, ' ');
                let mech = sp.next().unwrap_or("").to_uppercase();
                let ir_b64 = sp.next().unwrap_or("").trim().to_string();
                let initial_response = if ir_b64.is_empty() { None } else { Some(ir_b64.as_str()) };
                handle_authenticate(
                    stream, tag, &mech, initial_response,
                    &state, &mut session_state, &mut mailbox_id,
                    &mut auth_username, &mut auth_domain, &mut folders,
                    &client_ip, tls_upgraded,
                ).await;
            }
            "LIST" => {
                // LIST reference mailbox-pattern
                let _pattern = if args.contains(' ') {
                    args.splitn(2, ' ').last().unwrap_or("*").trim_matches('"')
                } else {
                    args.trim_matches('"')
                };

                stream
                    .write_all(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LIST (\\HasNoChildren \\Drafts) \"/\" \"Drafts\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LIST (\\HasNoChildren \\Trash) \"/\" \"Trash\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LIST (\\HasNoChildren \\Junk) \"/\" \"Spam\"\r\n")
                    .await?;
                stream
                    .write_all(format!("{} OK LIST completed\r\n", tag).as_bytes())
                    .await?;
            }
            "SELECT" => {
                let folder_name = normalize_folder(args.trim_matches('"'));
                selected_folder = Some(folder_name.clone());
                session_state = ImapState::Selected;

                // 每次 SELECT 时重新加载文件夹，确保新邮件可见
                tracing::info!("SELECT {} - 重新加载文件夹（base={}, domain={}, user={}）", folder_name, state.maildir_base, auth_domain, auth_username);
                folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);

                let folder = folders.iter().find(|f| f.name == folder_name);
                let (exists, recent, uidnext, uidvalidity, first_unseen) = if let Some(f) = folder {
                    tracing::info!("SELECT {} - 找到文件夹，包含 {} 封邮件", folder_name, f.messages.len());
                    let unseen_pos = f.messages.iter().position(|m| !m.flags.contains(&"\\Seen".to_string())).map(|p| p + 1);
                    (
                        f.messages.len(),
                        f.messages.iter().filter(|m| !m.flags.contains(&"\\Seen".to_string())).count(),
                        f.uid_next,
                        f.uid_validity,
                        unseen_pos,
                    )
                } else {
                    tracing::warn!("SELECT {} - 文件夹未找到！现有文件夹: {:?}", folder_name, folders.iter().map(|f| &f.name).collect::<Vec<_>>());
                    (0, 0, 1, 1, None)
                };

                stream
                    .write_all(format!("* {} EXISTS\r\n", exists).as_bytes())
                    .await?;
                stream
                    .write_all(format!("* {} RECENT\r\n", recent).as_bytes())
                    .await?;
                stream
                    .write_all(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").await?;
                stream
                    .write_all(b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited\r\n").await?;
                if let Some(unseen) = first_unseen {
                    stream
                        .write_all(format!("* OK [UNSEEN {}] First unseen\r\n", unseen).as_bytes())
                        .await?;
                }
                stream
                    .write_all(format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity).as_bytes())
                    .await?;
                stream
                    .write_all(format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext).as_bytes())
                    .await?;
                stream
                    .write_all(format!("{} OK [READ-WRITE] SELECT completed\r\n", tag).as_bytes())
                    .await?;
            }
            "FETCH" => {
                // FETCH sequence-set data-items
                let folder_name = selected_folder.clone().unwrap_or_default();
                let parts: Vec<&str> = args.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    stream
                        .write_all(format!("{} BAD FETCH requires sequence and items\r\n", tag).as_bytes())
                        .await?;
                    continue;
                }
                let seq_spec = parts[0];
                let items_upper = parts[1].to_uppercase();
                let items_original = parts[1].to_string();

                if let Some(folder) = folders.iter().find(|f| f.name == folder_name) {
                    for seqno in parse_seq_set(seq_spec, &folder.messages, false) {
                        let msg = &folder.messages[seqno - 1];
                        let resp = build_fetch_response(seqno, msg, &items_upper, &items_original, false);
                        tracing::info!("FETCH resp[{}]: {:?}...", seqno, String::from_utf8_lossy(&resp[..resp.len().min(200)]));
                        stream.write_all(&resp).await?;
                    }
                }
                stream
                    .write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
                    .await?;
                stream.flush().await?;
            }
            "LOGOUT" => {
                stream.write_all(b"* BYE FunMail IMAP4 Server logging out\r\n").await?;
                stream
                    .write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes())
                    .await?;
                break;
            }
            "NOOP" => {
                // 刷新文件夹以检测新邮件
                folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);
                if let Some(ref f) = folders.iter().find(|f| f.name == selected_folder.clone().unwrap_or_default()) {
                    stream.write_all(format!("* {} EXISTS\r\n", f.messages.len()).as_bytes()).await?;
                    let recent = f.messages.iter().filter(|m| !m.flags.contains(&"\\Seen".to_string())).count();
                    if recent > 0 {
                        stream.write_all(format!("* {} RECENT\r\n", recent).as_bytes()).await?;
                    }
                }
                stream
                    .write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
                    .await?;
            }
            "CHECK" => {
                // 刷新文件夹以检测新邮件
                folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);
                stream
                    .write_all(format!("{} OK CHECK completed\r\n", tag).as_bytes())
                    .await?;
            }
            "CLOSE" => {
                selected_folder = None;
                session_state = ImapState::Authenticated;
                stream
                    .write_all(format!("{} OK CLOSE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "EXAMINE" => {
                let folder_name = normalize_folder(args.trim_matches('"'));
                selected_folder = Some(folder_name.clone());
                // 重新加载文件夹，确保新邮件可见
                folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);
                let folder = folders.iter().find(|f| f.name == folder_name);
                let exists = folder.map(|f| f.messages.len()).unwrap_or(0);
                let uidnext = folder.map(|f| f.uid_next).unwrap_or(1);
                let uidvalidity = folder.map(|f| f.uid_validity).unwrap_or(1);
                stream
                    .write_all(format!("* {} EXISTS\r\n", exists).as_bytes())
                    .await?;
                stream.write_all(b"* 0 RECENT\r\n").await?;
                stream
                    .write_all(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").await?;
                stream
                    .write_all(format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity).as_bytes())
                    .await?;
                stream
                    .write_all(format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext).as_bytes())
                    .await?;
                stream
                    .write_all(format!("{} OK [READ-ONLY] EXAMINE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "STATUS" => {
                // STATUS "mailbox" (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)
                let (folder_part, items_part) = if let Some(pos) = args.find('(') {
                    (args[..pos].trim().trim_matches('"'), &args[pos..])
                } else {
                    (args.trim().trim_matches('"'), "")
                };
                let folder_name = normalize_folder(folder_part);
                let items_upper = items_part.to_uppercase();

                let folder = folders.iter().find(|f| f.name == folder_name);
                let (messages, recent, uidnext, uidvalidity, unseen) = if let Some(f) = folder {
                    (
                        f.messages.len(),
                        f.messages.iter().filter(|m| !m.flags.contains(&"\\Seen".to_string())).count(),
                        f.uid_next,
                        f.uid_validity,
                        f.messages.iter().filter(|m| !m.flags.contains(&"\\Seen".to_string())).count(),
                    )
                } else {
                    (0, 0, 1, 1, 0)
                };

                let mut parts: Vec<String> = Vec::new();
                if items_upper.contains("MESSAGES") { parts.push(format!("MESSAGES {}", messages)); }
                if items_upper.contains("RECENT") { parts.push(format!("RECENT {}", recent)); }
                if items_upper.contains("UIDNEXT") { parts.push(format!("UIDNEXT {}", uidnext)); }
                if items_upper.contains("UIDVALIDITY") { parts.push(format!("UIDVALIDITY {}", uidvalidity)); }
                if items_upper.contains("UNSEEN") { parts.push(format!("UNSEEN {}", unseen)); }
                if parts.is_empty() {
                    parts.push(format!("MESSAGES {}", messages));
                    parts.push(format!("UIDNEXT {}", uidnext));
                    parts.push(format!("UIDVALIDITY {}", uidvalidity));
                    parts.push(format!("UNSEEN {}", unseen));
                }

                stream
                    .write_all(format!("* STATUS \"{}\" ({})\r\n", folder_name, parts.join(" ")).as_bytes())
                    .await?;
                stream
                    .write_all(format!("{} OK STATUS completed\r\n", tag).as_bytes())
                    .await?;
            }
            "CREATE" | "DELETE" | "RENAME" | "SUBSCRIBE" | "UNSUBSCRIBE" => {
                stream
                    .write_all(format!("{} OK {} completed\r\n", tag, cmd.to_uppercase()).as_bytes())
                    .await?;
            }
            "STORE" => {
                stream
                    .write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "EXPUNGE" => {
                stream
                    .write_all(format!("{} OK EXPUNGE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "IDLE" => {
                stream.write_all(b"+ idling\r\n").await?;
                // 记录进入 IDLE 时的邮件数量
                let mut last_exists: usize = if let Some(ref f) = folders.iter().find(|f| f.name == selected_folder.clone().unwrap_or_default()) {
                    f.messages.len()
                } else {
                    0
                };
                // 30 分钟总超时（RFC 2177 建议 29 分钟）
                let idle_start = std::time::Instant::now();
                let max_idle = tokio::time::Duration::from_secs(29 * 60);
                // 等待 DONE
                let mut idle_line = String::new();
                loop {
                    idle_line.clear();
                    let read_result = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        stream.read_line(&mut idle_line),
                    ).await;
                    // 检查总超时
                    if idle_start.elapsed() >= max_idle {
                        // 超时，发送重新 IDLE 提示
                        stream.write_all(b"* OK IDLE will terminate after 29 minutes\r\n").await?;
                        break;
                    }
                    match read_result {
                        Ok(Ok(n)) => {
                            if n == 0 { break; }
                            if idle_line.trim().to_uppercase() == "DONE" {
                                break;
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            // 每 5 秒超时一次，检查是否有新邮件
                            folders = load_folders(&state.maildir_base, &auth_domain, &auth_username, state.tz_offset_secs);
                            if let Some(ref f) = folders.iter().find(|f| f.name == selected_folder.clone().unwrap_or_default()) {
                                let new_exists = f.messages.len();
                                if new_exists > last_exists {
                                    stream.write_all(format!("* {} EXISTS\r\n", new_exists).as_bytes()).await?;
                                    let recent = f.messages.iter().filter(|m| !m.flags.contains(&"\\Seen".to_string())).count();
                                    if recent > 0 {
                                        stream.write_all(format!("* {} RECENT\r\n", recent).as_bytes()).await?;
                                    }
                                    last_exists = new_exists;
                                }
                            }
                            continue;
                        }
                    }
                }
                stream
                    .write_all(format!("{} OK IDLE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "NAMESPACE" => {
                // 个人/其他用户/共享命名空间
                stream
                    .write_all(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n")
                    .await?;
                stream
                    .write_all(format!("{} OK NAMESPACE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "ID" => {
                // RFC 2971: ID 命令，返回服务器信息
                stream
                    .write_all(b"* ID (\"name\" \"FunMail\" \"version\" \"0.1.0\")\r\n")
                    .await?;
                stream
                    .write_all(format!("{} OK ID completed\r\n", tag).as_bytes())
                    .await?;
            }
            "ENABLE" => {
                // RFC 5161: ENABLE 扩展
                stream
                    .write_all(format!("{} OK ENABLE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "LSUB" => {
                // 订阅的文件夹列表
                stream
                    .write_all(b"* LSUB () \"/\" \"INBOX\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LSUB () \"/\" \"Sent\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LSUB () \"/\" \"Drafts\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LSUB () \"/\" \"Trash\"\r\n")
                    .await?;
                stream
                    .write_all(b"* LSUB () \"/\" \"Spam\"\r\n")
                    .await?;
                stream
                    .write_all(format!("{} OK LSUB completed\r\n", tag).as_bytes())
                    .await?;
            }
            "UID" => {
                // UID FETCH / UID SEARCH / UID STORE / UID COPY
                let folder_name = selected_folder.clone().unwrap_or_default();
                let uid_parts: Vec<&str> = args.splitn(2, ' ').collect();
                let sub = uid_parts.first().map(|s| s.to_uppercase()).unwrap_or_default();
                let rest = uid_parts.get(1).copied().unwrap_or("");

                match sub.as_str() {
                    "FETCH" => {
                        let p: Vec<&str> = rest.splitn(2, ' ').collect();
                        let seq_spec = p.first().copied().unwrap_or("");
                        let mut items_upper = p.get(1).copied().unwrap_or("").to_uppercase();
                        let mut items_original = p.get(1).copied().unwrap_or("").to_string();
                        // UID FETCH 必须在响应中包含 UID 项
                        if !items_upper.contains("UID") {
                            items_upper = format!("UID {}", items_upper);
                            items_original = format!("UID {}", items_original);
                        }
                        if let Some(folder) = folders.iter().find(|f| f.name == folder_name) {
                            for seqno in parse_seq_set(seq_spec, &folder.messages, true) {
                                let msg = &folder.messages[seqno - 1];
                                let resp = build_fetch_response(seqno, msg, &items_upper, &items_original, true);
                                stream.write_all(&resp).await?;
                            }
                        }
                        stream
                            .write_all(format!("{} OK UID FETCH completed\r\n", tag).as_bytes())
                            .await?;
                    }
                    "SEARCH" => {
                        // 简化：返回该文件夹所有 UID（ALL / 未识别条件都按全部处理）
                        let uids: Vec<String> = folders
                            .iter()
                            .find(|f| f.name == folder_name)
                            .map(|f| f.messages.iter().map(|m| m.uid.to_string()).collect())
                            .unwrap_or_default();
                        if uids.is_empty() {
                            stream.write_all(b"* SEARCH\r\n").await?;
                        } else {
                            stream
                                .write_all(format!("* SEARCH {}\r\n", uids.join(" ")).as_bytes())
                                .await?;
                        }
                        stream
                            .write_all(format!("{} OK UID SEARCH completed\r\n", tag).as_bytes())
                            .await?;
                    }
                    "STORE" => {
                        // 简化：回显 FETCH 结果但不持久化标志
                        let p: Vec<&str> = rest.splitn(2, ' ').collect();
                        let seq_spec = p.first().copied().unwrap_or("");
                        if let Some(folder) = folders.iter().find(|f| f.name == folder_name) {
                            for seqno in parse_seq_set(seq_spec, &folder.messages, true) {
                                let msg = &folder.messages[seqno - 1];
                                let flags_str = msg.flags.join(" ");
                                stream
                                    .write_all(format!("* {} FETCH (UID {} FLAGS ({}))\r\n", seqno, msg.uid, flags_str).as_bytes())
                                    .await?;
                            }
                        }
                        stream
                            .write_all(format!("{} OK UID STORE completed\r\n", tag).as_bytes())
                            .await?;
                    }
                    _ => {
                        stream
                            .write_all(format!("{} OK UID completed\r\n", tag).as_bytes())
                            .await?;
                    }
                }
            }
            "SEARCH" => {
                // 搜索命令：简化为返回所有序号
                let folder_name = selected_folder.clone().unwrap_or_default();
                let seqs: Vec<String> = folders
                    .iter()
                    .find(|f| f.name == folder_name)
                    .map(|f| (1..=f.messages.len()).map(|i| i.to_string()).collect())
                    .unwrap_or_default();
                if seqs.is_empty() {
                    stream.write_all(b"* SEARCH\r\n").await?;
                } else {
                    stream
                        .write_all(format!("* SEARCH {}\r\n", seqs.join(" ")).as_bytes())
                        .await?;
                }
                stream
                    .write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
                    .await?;
            }
            "COPY" => {
                stream
                    .write_all(format!("{} OK COPY completed\r\n", tag).as_bytes())
                    .await?;
            }
            "MOVE" => {
                stream
                    .write_all(format!("{} OK MOVE completed\r\n", tag).as_bytes())
                    .await?;
            }
            "APPEND" => {
                // APPEND <mailbox> [<flag-list>] [<date-time>] <literal-or-astring>
                // 简化解析：APPEND <mailbox> [{size}]
                let mut parts = args.splitn(2, ' ');
                let mailbox_part = parts.next().unwrap_or("").trim().trim_matches('"').to_string();
                let rest = parts.next().unwrap_or("");
                // 字面量大小：从 {N} 中提取
                let literal_size = extract_literal_size(rest);
                handle_append(
                    stream, tag, &mailbox_part, literal_size,
                    &state, &mut folders, &auth_domain, &auth_username,
                    session_state == ImapState::Selected || session_state == ImapState::Authenticated,
                ).await;
            }
            _ => {
                stream
                    .write_all(format!("{} BAD Unknown command\r\n", tag).as_bytes())
                    .await?;
            }
        }
    }

    Ok(())
}

/// 用文件名生成稳定的 UID（FNV-1a 哈希，确保同一文件始终映射到同一 UID）
fn stable_uid(filename: &str) -> u32 {
    let mut hash: u32 = 2166136261; // FNV offset basis
    for byte in filename.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619); // FNV prime
    }
    // 确保不为 0（UID 必须非零）
    if hash == 0 { 1 } else { hash }
}

/// 从邮件原始数据中解析 Date 头，返回 (IMAP INTERNALDATE 格式字符串, Unix 时间戳秒)
fn extract_email_date_with_ts(data: &[u8]) -> Option<(String, i64)> {
    // 只搜索前 8KB（邮件头通常在开头）
    let header_end = find_header_end(data);
    let header_bytes = &data[..header_end];
    let header_text = String::from_utf8_lossy(header_bytes);

    // 找 Date: 头（大小写不敏感）
    let date_val = header_text.lines()
        .find(|line| line.to_lowercase().starts_with("date:"))
        .and_then(|line| {
            let colon = line.find(':')?;
            Some(line[colon + 1..].trim().to_string())
        })?;

    // 用 chrono 解析 RFC 2822 日期
    let datetime = chrono::DateTime::parse_from_rfc2822(&date_val).ok()?;

    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let tz_secs = datetime.offset().local_minus_utc();
    let tz_h = tz_secs / 3600;
    let tz_m = (tz_secs.abs() % 3600) / 60;
    let tz = format!("{:+03}{:02}", tz_h, tz_m);

    let date_str = format!(
        "{:02}-{}-{} {:02}:{:02}:{:02} {}",
        datetime.day(),
        months[datetime.month() as usize - 1],
        datetime.year(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
        tz
    );
    Some((date_str, datetime.timestamp()))
}

/// 从数据库 settings 表读取时区偏移（秒），默认 UTC+8 (28800)
async fn load_timezone_offset(pool: &PgPool) -> i32 {
    match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM settings WHERE key = 'timezone'"
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(v)) => {
            // 优先解析 offset 字段（如 "+08:00"）
            if let Some(offset_str) = v.get("offset").and_then(|o| o.as_str()) {
                if let Some(secs) = parse_tz_offset(offset_str) {
                    tracing::info!("时区设置: offset={}, 秒={}", offset_str, secs);
                    return secs;
                }
            }
            // 回退：按 IANA 名称解析
            if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                if let Some(secs) = tz_name_to_offset(name) {
                    tracing::info!("时区设置: name={}, 秒={}", name, secs);
                    return secs;
                }
            }
            tracing::warn!("时区设置格式无效，使用默认 UTC+8");
            28800
        }
        _ => {
            tracing::info!("未找到时区设置，使用默认 UTC+8");
            28800
        }
    }
}

/// 解析时区偏移字符串，如 "+08:00" → 28800, "-05:00" → -18000
fn parse_tz_offset(s: &str) -> Option<i32> {
    let s = s.trim();
    if s.len() < 5 { return None; }
    let sign = if s.starts_with('+') { 1 } else if s.starts_with('-') { -1 } else { return None };
    let rest = &s[1..];
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 2 { return None; }
    let h: i32 = parts[0].parse().ok()?;
    let m: i32 = parts[1].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

/// 常用时区名称到偏移秒数的映射
fn tz_name_to_offset(name: &str) -> Option<i32> {
    let map = [
        ("Asia/Shanghai", 28800),
        ("Asia/Tokyo", 32400),
        ("Asia/Seoul", 32400),
        ("Asia/Singapore", 28800),
        ("Asia/Hong_Kong", 28800),
        ("Asia/Taipei", 28800),
        ("Asia/Kolkata", 19800),
        ("Asia/Dubai", 14400),
        ("Europe/London", 0),
        ("Europe/Paris", 3600),
        ("Europe/Berlin", 3600),
        ("Europe/Moscow", 10800),
        ("America/New_York", -18000),
        ("America/Chicago", -21600),
        ("America/Denver", -25200),
        ("America/Los_Angeles", -28800),
        ("Australia/Sydney", 36000),
        ("Pacific/Auckland", 43200),
        ("UTC", 0),
    ];
    map.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, s)| *s)
}

/// 将 SystemTime 格式化为 IMAP INTERNALDATE 格式: "DD-Mon-YYYY HH:MM:SS +ZZZZ"
/// tz_offset_secs: 时区偏移秒数（如 UTC+8 = 28800）
fn format_internal_date_with_tz(t: std::time::SystemTime, tz_offset_secs: i32) -> String {
    use std::time::UNIX_EPOCH;
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    // 使用配置的时区偏移，将 UTC 时间转换为本地时间
    let local_secs = secs + tz_offset_secs as i64;
    let datetime = chrono::DateTime::from_timestamp(local_secs, 0).unwrap_or_default();
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let tz_h = tz_offset_secs / 3600;
    let tz_m = (tz_offset_secs.abs() % 3600) / 60;
    let tz = format!("{:+03}{:02}", tz_h, tz_m);
    format!(
        "{:02}-{}-{} {:02}:{:02}:{:02} {}",
        datetime.day(),
        months[datetime.month() as usize - 1],
        datetime.year(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
        tz
    )
}

/// 规范化文件夹名：INBOX 大小写不敏感（RFC 3501），其余原样
fn normalize_folder(name: &str) -> String {
    // 安全检查：禁止路径遍历字符
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return name.to_string(); // 原样返回，后续逻辑会因为找不到匹配的文件夹而失败
    }
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".to_string()
    } else {
        name.to_string()
    }
}

/// 处理 AUTHENTICATE 命令（手写解析后调用）
#[allow(clippy::too_many_arguments)]
async fn handle_authenticate(
    stream: &mut UpgradableStream,
    tag: &str,
    mechanism: &str,
    // SASL-IR：客户端 inline 发送的 **base64 字符串**（未解码）
    initial_response: Option<&str>,
    state: &Arc<AppState>,
    session_state: &mut ImapState,
    mailbox_id: &mut i32,
    auth_username: &mut String,
    auth_domain: &mut String,
    folders: &mut Vec<ImapFolder>,
    client_ip: &str,
    tls_upgraded: bool,
) {
    // 明文连接禁止 AUTHENTICATE（防止密码被嗅探），必须先 STARTTLS
    if !tls_upgraded {
        let _ = stream.write_all(format!("{} NO AUTHENTICATE requires STARTTLS encryption first\r\n", tag).as_bytes()).await;
        return;
    }

    let caps_str = "IMAP4rev1 ID IDLE NAMESPACE UIDPLUS ENABLE SPECIAL-USE LIST-EXTENDED";

    match mechanism {
        "PLAIN" => {
            // 获取 PLAIN 机制的解码后字节：\0username\0password
            let decoded: Vec<u8> = if let Some(ir_b64) = initial_response {
                // SASL-IR：客户端 inline 提供了 base64
                match STANDARD.decode(ir_b64.trim()) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = stream.write_all(format!("{} BAD Invalid base64 in AUTHENTICATE\r\n", tag).as_bytes()).await;
                        return;
                    }
                }
            } else {
                // 标准两步：发送 continuation，等待 base64
                let _ = stream.write_all(b"+ \r\n").await;
                let mut auth_line = String::new();
                let n = match stream.read_line(&mut auth_line).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if n == 0 { return; }
                let input = auth_line
                    .trim_end_matches("\r\n")
                    .trim_end_matches('\n');
                if input == "*" {
                    let _ = stream.write_all(format!("{} NO AUTHENTICATE cancelled\r\n", tag).as_bytes()).await;
                    return;
                }
                match STANDARD.decode(input) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = stream.write_all(format!("{} BAD Invalid base64 in AUTHENTICATE\r\n", tag).as_bytes()).await;
                        return;
                    }
                }
            };

            let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
            if parts.len() >= 3 {
                let username = String::from_utf8_lossy(parts[1]).to_string();
                let password = String::from_utf8_lossy(parts[2]).to_string();

                let (user, domain) = if let Some((u, d)) = username.split_once('@') {
                    (u.to_string(), d.to_string())
                } else {
                    match sqlx::query_scalar::<_, String>(
                        "SELECT d.name FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND m.enabled = true AND d.enabled = true LIMIT 1"
                    )
                    .bind(&username)
                    .fetch_optional(&state.pool)
                    .await
                    {
                        Ok(Some(d)) => (username, d),
                        _ => {
                            let _ = stream.write_all(format!("{} NO AUTHENTICATE failed\r\n", tag).as_bytes()).await;
                            return;
                        }
                    }
                };

                match db::authenticate_mailbox(&state.pool, &user, &domain, &password).await {
                    Ok(Some(id)) => {
                        // 检查协议权限
                        let proto_row: Option<(Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
                            "SELECT m.protocols, d.register_config
                             FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                             WHERE m.username = $1 AND d.name = $2"
                        )
                        .bind(&user)
                        .bind(&domain)
                        .fetch_optional(&state.pool)
                        .await
                        .unwrap_or(None);

                        let allow_imap = proto_row
                            .map(|(mp, rc)| {
                                let cfg = match mp {
                                    Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
                                    _ => rc,
                                };
                                cfg.get("allow_imap").and_then(|v| v.as_bool()).unwrap_or(true)
                            })
                            .unwrap_or(true);

                        if !allow_imap {
                            tracing::warn!("IMAP AUTHENTICATE 被拒（协议权限禁止 IMAP）: {}@{}", user, domain);
                            let _ = stream.write_all(format!("{} NO IMAP access denied for this account\r\n", tag).as_bytes()).await;
                            return;
                        }

                        *mailbox_id = id;
                        *auth_username = user;
                        *auth_domain = domain;
                        *session_state = ImapState::Authenticated;
                        let _ = db::update_last_login(&state.pool, *mailbox_id, client_ip).await;
                        *folders = load_folders(&state.maildir_base, auth_domain, auth_username, state.tz_offset_secs);
                        let _ = stream.write_all(format!("{} OK [CAPABILITY {}] AUTHENTICATE completed\r\n", tag, caps_str).as_bytes()).await;
                        tracing::info!("IMAP AUTHENTICATE PLAIN 登录成功: {}@{}", auth_username, auth_domain);
                    }
                    Ok(None) | Err(_) => {
                        let _ = stream.write_all(format!("{} NO AUTHENTICATE failed\r\n", tag).as_bytes()).await;
                    }
                }
            } else {
                let _ = stream.write_all(format!("{} BAD Malformed AUTHENTICATE PLAIN\r\n", tag).as_bytes()).await;
            }
        }
        "LOGIN" => {
            // LOGIN 机制：先 base64(username)，再 base64(password)
            let _ = stream.write_all(b"+ VXNlcm5hbWU6\r\n").await;
            let mut user_line = String::new();
            let n = match stream.read_line(&mut user_line).await {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 { return; }
            let user_input = user_line.trim_end_matches("\r\n").trim_end_matches('\n');
            if user_input == "*" {
                let _ = stream.write_all(format!("{} NO AUTHENTICATE cancelled\r\n", tag).as_bytes()).await;
                return;
            }
            let username = match STANDARD.decode(user_input) {
                Ok(b) => String::from_utf8_lossy(&b).to_string(),
                Err(_) => {
                    let _ = stream.write_all(format!("{} BAD Invalid base64 in AUTHENTICATE\r\n", tag).as_bytes()).await;
                    return;
                }
            };

            let _ = stream.write_all(b"+ UGFzc3dvcmQ6\r\n").await;
            let mut pass_line = String::new();
            let n = match stream.read_line(&mut pass_line).await {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 { return; }
            let pass_input = pass_line.trim_end_matches("\r\n").trim_end_matches('\n');
            if pass_input == "*" {
                let _ = stream.write_all(format!("{} NO AUTHENTICATE cancelled\r\n", tag).as_bytes()).await;
                return;
            }
            let password = match STANDARD.decode(pass_input) {
                Ok(b) => String::from_utf8_lossy(&b).to_string(),
                Err(_) => {
                    let _ = stream.write_all(format!("{} BAD Invalid base64 in AUTHENTICATE\r\n", tag).as_bytes()).await;
                    return;
                }
            };

            let (user, domain) = if let Some((u, d)) = username.split_once('@') {
                (u.to_string(), d.to_string())
            } else {
                match sqlx::query_scalar::<_, String>(
                    "SELECT d.name FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                     WHERE m.username = $1 AND m.enabled = true AND d.enabled = true LIMIT 1"
                )
                .bind(&username)
                .fetch_optional(&state.pool)
                .await
                {
                    Ok(Some(d)) => (username, d),
                    _ => {
                        let _ = stream.write_all(format!("{} NO AUTHENTICATE failed\r\n", tag).as_bytes()).await;
                        return;
                    }
                }
            };

            match db::authenticate_mailbox(&state.pool, &user, &domain, &password).await {
                Ok(Some(id)) => {
                    // 检查协议权限
                    let proto_row: Option<(Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
                        "SELECT m.protocols, d.register_config
                         FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND d.name = $2"
                    )
                    .bind(&user)
                    .bind(&domain)
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);

                    let allow_imap = proto_row
                        .map(|(mp, rc)| {
                            let cfg = match mp {
                                Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
                                _ => rc,
                            };
                            cfg.get("allow_imap").and_then(|v| v.as_bool()).unwrap_or(true)
                        })
                        .unwrap_or(true);

                    if !allow_imap {
                        tracing::warn!("IMAP AUTHENTICATE LOGIN 被拒（协议权限禁止 IMAP）: {}@{}", user, domain);
                        let _ = stream.write_all(format!("{} NO IMAP access denied for this account\r\n", tag).as_bytes()).await;
                        return;
                    }

                    *mailbox_id = id;
                    *auth_username = user;
                    *auth_domain = domain;
                    *session_state = ImapState::Authenticated;
                    let _ = db::update_last_login(&state.pool, *mailbox_id, client_ip).await;
                    *folders = load_folders(&state.maildir_base, auth_domain, auth_username, state.tz_offset_secs);
                    let _ = stream.write_all(format!("{} OK [CAPABILITY {}] AUTHENTICATE completed\r\n", tag, caps_str).as_bytes()).await;
                    tracing::info!("IMAP AUTHENTICATE LOGIN 登录成功: {}@{}", auth_username, auth_domain);
                }
                Ok(None) | Err(_) => {
                    let _ = stream.write_all(format!("{} NO AUTHENTICATE failed\r\n", tag).as_bytes()).await;
                }
            }
        }
        _ => {
            let _ = stream.write_all(format!("{} NO Unsupported authentication mechanism\r\n", tag).as_bytes()).await;
        }
    }
}

/// 处理 APPEND 命令（手写解析后调用）
#[allow(clippy::too_many_arguments)]
async fn handle_append(
    stream: &mut UpgradableStream,
    tag: &str,
    mailbox: &str,
    literal_size: Option<usize>,
    state: &Arc<AppState>,
    folders: &mut Vec<ImapFolder>,
    auth_domain: &str,
    auth_username: &str,
    is_authed: bool,
) {
    if !is_authed {
        let _ = stream.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await;
        return;
    }
    let folder_name = normalize_folder(mailbox);
    let literal_size = match literal_size {
        Some(s) => s,
        None => {
            let _ = stream.write_all(format!("{} BAD APPEND requires literal data\r\n", tag).as_bytes()).await;
            return;
        }
    };

    // 防止内存耗尽：限制 APPEND 邮件大小（50MB）
    const MAX_APPEND_SIZE: usize = 50 * 1024 * 1024;
    if literal_size > MAX_APPEND_SIZE {
        let _ = stream.write_all(format!("{} NO Message too large (max {}MB)\r\n", tag, MAX_APPEND_SIZE / 1024 / 1024).as_bytes()).await;
        return;
    }

    // 发送 continuation，等待 literal 数据
    let _ = stream.write_all(b"+ Ready for literal data\r\n").await;
    let _ = stream.flush().await;

    // 读取 exactly literal_size 字节
    let mut msg_data = vec![0u8; literal_size];
    let mut total_read = 0;
    while total_read < literal_size {
        let read_result = match stream {
            UpgradableStream::Plain(s) => {
                let _ = s.readable().await;
                match s.try_read(&mut msg_data[total_read..]) {
                    Ok(n) => Ok(n),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                    Err(e) => Err(e),
                }
            }
            UpgradableStream::Tls(s) => match AsyncReadExt::read(s, &mut msg_data[total_read..]).await {
                Ok(n) => Ok(n),
                Err(e) => Err(std::io::Error::other(e)),
            },
            UpgradableStream::Closed => return,
        };
        match read_result {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => break,
        }
    }

    // 读取 literal 后的 \r\n
    let mut trailing = String::new();
    let _ = stream.read_line(&mut trailing).await;

    // 安全检查：文件夹名不能包含路径遍历字符
    if folder_name.contains("..") || folder_name.contains('/') || folder_name.contains('\\') || folder_name.contains('\0') {
        let _ = stream.write_all(format!("{} NO Invalid mailbox name\r\n", tag).as_bytes()).await;
        return;
    }

    // 保存到 maildir
    let base = std::path::Path::new(&state.maildir_base)
        .join(auth_domain)
        .join(auth_username);
    let mail_dir = if folder_name == "INBOX" {
        base.join("new")
    } else {
        base.join(&folder_name).join("new")
    };
    let _ = std::fs::create_dir_all(&mail_dir);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let hostname = &state.maildir_base;
    let filename = format!("{}.{}.M{}P{}Q{}.{}", ts, pid, ts, pid, ts, hostname);
    let filepath = mail_dir.join(&filename);

    match std::fs::write(&filepath, &msg_data[..total_read]) {
        Ok(()) => {
            // 更新邮箱 used_bytes
            let _ = funmail_common::db::add_mailbox_used_bytes(
                &state.pool, auth_username, auth_domain, total_read as i64
            ).await;
            *folders = load_folders(&state.maildir_base, auth_domain, auth_username, state.tz_offset_secs);
            let _ = stream.write_all(format!("{} OK APPEND completed\r\n", tag).as_bytes()).await;
            tracing::info!("IMAP APPEND 成功: {}@{}/{} ({} bytes)", auth_username, auth_domain, folder_name, total_read);
        }
        Err(e) => {
            let _ = stream.write_all(format!("{} NO APPEND failed: {}\r\n", tag, e).as_bytes()).await;
        }
    }
}

/// 解析 APPEND 命令参数：返回 (mailbox_name, literal_size)
/// APPEND "mailbox" [flags] [date-time] {size}
fn parse_append_args(args: &str) -> (String, Option<usize>) {
    let mut remaining = args.trim();
    // 提取 mailbox name（带引号或不带）
    let mailbox = if remaining.starts_with('"') {
        remaining = &remaining[1..];
        let end = remaining.find('"').unwrap_or(remaining.len());
        let name = remaining[..end].to_string();
        remaining = if end + 1 < remaining.len() { &remaining[end + 1..] } else { "" };
        name
    } else {
        let end = remaining.find(' ').unwrap_or(remaining.len());
        let name = remaining[..end].to_string();
        remaining = if end < remaining.len() { &remaining[end..] } else { "" };
        name
    };
    // 查找 literal size {n}
    let literal_size = if let Some(pos) = remaining.rfind('{') {
        let end = remaining[pos..].find('}').unwrap_or(0);
        remaining[pos + 1..pos + end].parse::<usize>().ok()
    } else {
        None
    };
    (mailbox, literal_size)
}

/// 脱敏日志行：隐藏 LOGIN 命令的密码、AUTHENTICATE 的 base64 凭据，避免明文写入日志。
/// 返回脱敏后的字符串（超过 200 字符会截断）。
fn sanitize_log_line(raw: &str) -> String {
    // 解析 tag 与命令名
    let trimmed = raw.trim_end();
    let (tag, rest) = match trimmed.find(' ') {
        Some(pos) => (&trimmed[..pos], &trimmed[pos + 1..]),
        None => (trimmed, ""),
    };
    let (cmd, args) = match rest.find(' ') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    let sanitized = match cmd.to_uppercase().as_str() {
        // LOGIN <user> <password> —— 保留用户名，隐藏密码
        "LOGIN" => {
            if let Some((user, _rest)) = read_astring(args) {
                format!("{} LOGIN {} <hidden>", tag, user)
            } else {
                format!("{} LOGIN <hidden>", tag)
            }
        }
        // AUTHENTICATE <mechanism> [base64-ir] —— 隐藏内联凭据
        "AUTHENTICATE" => {
            let mech = args.split_whitespace().next().unwrap_or("");
            format!("{} AUTHENTICATE {} <hidden>", tag, mech)
        }
        _ => trimmed.to_string(),
    };

    if sanitized.len() > 200 {
        sanitized[..200].to_string()
    } else {
        sanitized
    }
}

/// 解析 LOGIN 命令的两个 astring 参数（user 和 password）。
/// 支持带引号字符串（"..."）和裸 atom。支持反斜杠转义。
/// 返回 None 表示参数不足。
fn parse_astring_pair(args: &str) -> Option<(String, String)> {
    let (a, rest) = read_astring(args)?;
    let (b, _rest) = read_astring(rest)?;
    Some((a, b))
}

/// 从字符串开头读一个 astring。引号支持反斜杠转义。返回 (值, 剩余)。
fn read_astring(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_prefix('"') {
        // quoted-string
        let mut out = String::new();
        let bytes = stripped.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '"' {
                // 结束
                let rest = &stripped[i + 1..];
                return Some((out, rest));
            } else if c == '\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
            } else {
                out.push(c);
                i += 1;
            }
        }
        // 没有找到闭合引号
        Some((out, ""))
    } else {
        // atom（非空白直到下一个空格）
        let end = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
        Some((s[..end].to_string(), &s[end..]))
    }
}

/// 从 APPEND 命令后续参数中提取字面量大小 {N}
fn extract_literal_size(s: &str) -> Option<usize> {
    if let Some(start) = s.find('{') {
        let rest = &s[start + 1..];
        if let Some(end) = rest.find('}') {
            return rest[..end].parse::<usize>().ok();
        }
    }
    None
}

/// 解析 IMAP 序列集（如 "1", "1:5", "1,3,5", "1:*", "*"）。
/// by_uid 为 true 时 spec 中的数字是 UID，返回的仍是 1-based 序号（用于 messages 索引）。
fn parse_seq_set(spec: &str, messages: &[ImapMessage], by_uid: bool) -> Vec<usize> {
    let count = messages.len();
    if count == 0 {
        return Vec::new();
    }
    // 把 UID 映射回序号
    let resolve = |val: u32| -> Option<usize> {
        if by_uid {
            messages.iter().position(|m| m.uid == val).map(|p| p + 1)
        } else {
            let v = val as usize;
            if v >= 1 && v <= count { Some(v) } else { None }
        }
    };
    // 序列集里 '*' 代表最大值
    let max_val: u32 = if by_uid {
        messages.iter().map(|m| m.uid).max().unwrap_or(0)
    } else {
        count as u32
    };

    let mut result: Vec<usize> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once(':') {
            let lo_v = if lo == "*" { max_val } else { lo.parse().unwrap_or(0) };
            let hi_v = if hi == "*" { max_val } else { hi.parse().unwrap_or(0) };
            let (start, end) = if lo_v <= hi_v { (lo_v, hi_v) } else { (hi_v, lo_v) };
            if by_uid {
                for m in messages {
                    if m.uid >= start && m.uid <= end {
                        if let Some(seqno) = resolve(m.uid) {
                            result.push(seqno);
                        }
                    }
                }
            } else {
                for v in start..=end {
                    if let Some(seqno) = resolve(v) {
                        result.push(seqno);
                    }
                }
            }
        } else if part == "*" {
            if let Some(seqno) = resolve(max_val) {
                result.push(seqno);
            }
        } else if let Ok(v) = part.parse::<u32>() {
            if let Some(seqno) = resolve(v) {
                result.push(seqno);
            }
        }
    }
    result.sort_unstable();
    result.dedup();
    result
}

/// 根据请求的数据项构造单条 FETCH 响应。
/// is_uid 为 true 时强制在括号内包含 UID 项。
/// items_original 保留原始大小写的请求项（用于响应标签匹配），items_upper 为大写版本（用于匹配判断）
fn build_fetch_response(seqno: usize, msg: &ImapMessage, items_upper: &str, items_original: &str, _is_uid: bool) -> Vec<u8> {
    // 收集非字面量的属性（FLAGS/UID/RFC822.SIZE/INTERNALDATE/ENVELOPE 等），
    // BODY[]/RFC822 这类带 {n} 字面量的单独追加在末尾。
    let mut atoms: Vec<String> = Vec::new();
    let mut want_body = false;
    let mut want_headers_only = false;
    let mut body_label = "BODY[]".to_string();

    let want_all = items_upper.contains("ALL") || items_upper.contains("FAST") || items_upper.contains("FULL");

    if items_upper.contains("UID") {
        atoms.push(format!("UID {}", msg.uid));
    }
    if items_upper.contains("FLAGS") || want_all {
        atoms.push(format!("FLAGS ({})", msg.flags.join(" ")));
    }
    if items_upper.contains("RFC822.SIZE") || want_all {
        atoms.push(format!("RFC822.SIZE {}", msg.size));
    }
    if items_upper.contains("INTERNALDATE") || want_all {
        atoms.push(format!("INTERNALDATE \"{}\"", msg.internal_date));
    }

    // 是否请求正文
    // BODY.PEEK[HEADER.FIELDS (xxx)] 或 BODY[HEADER.FIELDS (xxx)] → 只返回头部指定字段
    // BODY.PEEK[HEADER] 或 BODY[HEADER] → 返回完整头部
    // BODY.PEEK[] 或 BODY[] → 返回完整邮件
    // RFC822 → 等同于 BODY[]
    if items_upper.contains("BODY.PEEK[HEADER") || items_upper.contains("BODY[HEADER") {
        want_body = true;
        want_headers_only = true;
        // 从原始请求中提取标签，保持大小写匹配
        body_label = extract_body_label(items_original);
    } else if items_upper.contains("BODY[]") || items_upper.contains("BODY.PEEK[]")
        || items_upper.contains("RFC822") && !items_upper.contains("RFC822.SIZE")
    {
        want_body = true;
        body_label = extract_body_label(items_original);
        if body_label.is_empty() {
            // RFC822 的情况
            if items_upper.contains("RFC822") && !items_upper.contains("RFC822.SIZE") {
                body_label = "RFC822".to_string();
            } else {
                body_label = "BODY[]".to_string();
            }
        }
    }

    let mut out: Vec<u8> = Vec::new();
    if want_body {
        let payload: Vec<u8> = if want_headers_only {
            // 检查是否是 HEADER.FIELDS 请求
            let upper_label = body_label.to_uppercase();
            if upper_label.contains("HEADER.FIELDS") {
                // 提取请求的字段名列表
                let fields = extract_header_fields(&body_label);
                // 从邮件头部中提取指定字段
                let header_end = find_header_end(&msg.data);
                let header_str = String::from_utf8_lossy(&msg.data[..header_end]);
                let mut result = String::new();
                for line in header_str.lines() {
                    if line.is_empty() { continue; }
                    if line.starts_with(' ') || line.starts_with('\t') {
                        // 续行，属于前一个头部字段
                        if !result.is_empty() {
                            result.push_str(line);
                            result.push_str("\r\n");
                        }
                    } else if let Some(colon_pos) = line.find(':') {
                        let field_name = line[..colon_pos].trim();
                        if fields.iter().any(|f| f.eq_ignore_ascii_case(field_name)) {
                            result.push_str(line);
                            result.push_str("\r\n");
                        }
                    }
                }
                result.push_str("\r\n");
                result.into_bytes()
            } else {
                // 完整头部
                let idx = find_header_end(&msg.data);
                msg.data[..idx].to_vec()
            }
        } else {
            msg.data.clone()
        };
        let prefix = if atoms.is_empty() {
            format!("* {} FETCH ({} {{{}}}\r\n", seqno, body_label, payload.len())
        } else {
            format!("* {} FETCH ({} {} {{{}}}\r\n", seqno, atoms.join(" "), body_label, payload.len())
        };
        out.extend_from_slice(prefix.as_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(b")\r\n");
    } else {
        let line = format!("* {} FETCH ({})\r\n", seqno, atoms.join(" "));
        out.extend_from_slice(line.as_bytes());
    }
    out
}

/// 从 FETCH 请求项中提取 BODY 标签，响应时必须去掉 PEEK（RFC 3501 要求）
/// 例如 "BODY.PEEK[HEADER.FIELDS (Message-ID)]" → "BODY[HEADER.FIELDS (Message-ID)]"
fn extract_body_label(items: &str) -> String {
    // 查找 BODY 或 BODY.PEEK 开头的标签
    let upper = items.to_uppercase();
    if let Some(pos) = upper.find("BODY.PEEK[") {
        let start = pos;
        let rest = &items[start + "BODY.PEEK[".len()..];
        if let Some(end) = rest.find(']') {
            // 响应中去掉 PEEK，只返回 BODY[...]
            return format!("BODY[{}]", &rest[..end]);
        }
    }
    if let Some(pos) = upper.find("BODY[") {
        let start = pos;
        let rest = &items[start + "BODY[".len()..];
        if let Some(end) = rest.find(']') {
            return format!("BODY[{}]", &rest[..end]);
        }
    }
    String::new()
}

/// 从 BODY.PEEK[HEADER.FIELDS (field1 field2 ...)] 中提取字段名列表
fn extract_header_fields(label: &str) -> Vec<String> {
    // 找到括号内的字段名列表
    if let Some(start) = label.find('(') {
        if let Some(end) = label[start + 1..].find(')') {
            let inner = &label[start + 1..start + 1 + end];
            return inner.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    Vec::new()
}

/// 找到邮件头部结束位置（首个 \r\n\r\n 或 \n\n 之后），返回包含分隔空行在内的偏移
fn find_header_end(data: &[u8]) -> usize {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return pos + 4;
    }
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        return pos + 2;
    }
    data.len()
}

/// 加载用户的 IMAP 文件夹
fn load_folders(maildir_base: &str, domain: &str, username: &str, tz_offset_secs: i32) -> Vec<ImapFolder> {
    let base = std::path::Path::new(maildir_base).join(domain).join(username);
    let mut folders = Vec::new();

    let folder_names = ["INBOX", "Sent", "Drafts", "Trash", "Spam"];
    let subdirs = ["new", "cur", "Sent/new", "Sent/cur", "Drafts/new", "Drafts/cur", "Trash/new", "Trash/cur", "Spam/new", "Spam/cur"];

    // 确保目录存在
    for dir in &subdirs {
        let _ = std::fs::create_dir_all(base.join(dir));
    }

    for name in &folder_names {
        let mut messages = Vec::new();
        let mail_dirs = if name == &"INBOX" {
            vec![base.join("new"), base.join("cur")]
        } else {
            vec![base.join(name).join("new"), base.join(name).join("cur")]
        };

        tracing::debug!("加载文件夹 {} 从目录: {:?}", name, mail_dirs);
        for mail_dir in &mail_dirs {
            match std::fs::read_dir(mail_dir) {
                Ok(entries) => {
                    let mut file_count = 0;
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            file_count += 1;
                        }
                    }
                    tracing::debug!("  目录 {:?} 包含 {} 个文件", mail_dir, file_count);
                }
                Err(e) => {
                    tracing::warn!("  无法读取目录 {:?}: {}", mail_dir, e);
                }
            }
            if let Ok(entries) = std::fs::read_dir(mail_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(data) = std::fs::read(&path) {
                            let size = data.len();
                            // 用文件名生成稳定哈希，仅作为时间相同时的排序次序（最终 UID 在排序后统一重新分配）
                            let filename = path.file_name().unwrap_or_default().to_string_lossy();
                            let uid = stable_uid(&filename);
                            let id = path.to_string_lossy().to_string();
                            // 从文件名解析 flags
                            let flags = if filename.contains(":2,") {
                                let flag_part = filename.split(":2,").last().unwrap_or("");
                                let mut f = Vec::new();
                                if flag_part.contains('S') { f.push("\\Seen".to_string()); }
                                if flag_part.contains('R') { f.push("\\Answered".to_string()); }
                                if flag_part.contains('F') { f.push("\\Flagged".to_string()); }
                                if flag_part.contains('D') { f.push("\\Draft".to_string()); }
                                if flag_part.contains('T') { f.push("\\Deleted".to_string()); }
                                f
                            } else {
                                // new 目录中的邮件默认未读
                                Vec::new()
                            };
                            // 从邮件 Date 头解析真实发送时间
                            let (internal_date, sort_key) = extract_email_date_with_ts(&data)
                                .unwrap_or_else(|| {
                                    let mtime = std::fs::metadata(&path)
                                        .ok()
                                        .and_then(|m| m.modified().ok());
                                    let ts = mtime
                                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs() as i64)
                                        .unwrap_or(0);
                                    let date_str = mtime
                                        .map(|t| format_internal_date_with_tz(t, tz_offset_secs))
                                        .unwrap_or_else(|| "01-Jan-1970 00:00:00 +0000".to_string());
                                    (date_str, ts)
                                });
                            messages.push(ImapMessage {
                                uid,
                                id,
                                flags,
                                size,
                                data,
                                internal_date,
                                sort_key,
                            });
                        }
                    }
                }
            }
        }

        // 按邮件真实时间排序（时间戳升序），时间相同时用稳定哈希作为次序，确保顺序稳定。
        // 注意：IMAP 要求 UID 必须随序号严格递增（RFC 3501 §2.3.1.1），
        // 否则 Outlook 等客户端的增量同步（UID FETCH n:*）会失效，导致收件箱无法同步新邮件。
        messages.sort_by(|a, b| {
            a.sort_key.cmp(&b.sort_key).then_with(|| a.uid.cmp(&b.uid))
        });
        // 排序后重新分配单调递增的 UID（从 1 开始），保证 UID 顺序与序号顺序一致。
        for (i, m) in messages.iter_mut().enumerate() {
            m.uid = (i + 1) as u32;
        }

        let uid_next = messages.len() as u32 + 1;
        // UIDVALIDITY 改为 2，强制所有客户端丢弃旧 UID 缓存并重新同步
        let uid_validity = 2;

        tracing::info!("文件夹 {} 加载完成: {} 封邮件, UID范围 1-{}", name, messages.len(), uid_next - 1);

        folders.push(ImapFolder {
            name: name.to_string(),
            messages,
            uid_validity,
            uid_next,
        });
    }

    tracing::debug!("load_folders 完成，共 {} 个文件夹", folders.len());
    folders
}
