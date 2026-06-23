use crate::AppState;
use base64::{engine::general_purpose::STANDARD, Engine};
use funmail_common::db;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SMTP 会话状态
enum SmtpState {
    Greeting,
    Helo,
    MailFrom,
    RcptTo,
    Data,
    Quit,
}

/// SMTP 会话
pub struct SmtpSession {
    state: SmtpState,
    hostname: String,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    is_submission: bool,
    authenticated: bool,
    auth_username: Option<String>,
    auth_domain: Option<String>,
    client_ip: String,
    tls_upgraded: bool,
}

/// 可升级的流：先以 Plain TCP 运行，STARTTLS 后升级为 TLS
pub enum UpgradableStream {
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

    /// 取出底层 TCP 流用于 TLS 升级
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

impl SmtpSession {
    /// 处理一个 SMTP 连接（明文，支持 STARTTLS）
    pub async fn handle(
        stream: TcpStream,
        addr: std::net::SocketAddr,
        app_state: Arc<AppState>,
        is_submission: bool,
    ) -> anyhow::Result<()> {
        let mut wrapped = UpgradableStream::Plain(stream);
        Self::run_session(&mut wrapped, addr, app_state, is_submission, false).await
    }

    /// 处理一个 SMTP 连接（隐式 TLS，连接后已经是 TLS）
    pub async fn handle_tls(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        addr: std::net::SocketAddr,
        app_state: Arc<AppState>,
        is_submission: bool,
    ) -> anyhow::Result<()> {
        let mut wrapped = UpgradableStream::Tls(stream);
        Self::run_session(&mut wrapped, addr, app_state, is_submission, true).await
    }

    async fn run_session(
        stream: &mut UpgradableStream,
        addr: std::net::SocketAddr,
        app_state: Arc<AppState>,
        is_submission: bool,
        implicit_tls: bool,
    ) -> anyhow::Result<()> {
        let client_ip = addr.ip().to_string();

        // 问候
        let hostname = &app_state.hostname;
        stream
            .write_all(format!("220 {} ESMTP FunMail\r\n", hostname).as_bytes())
            .await?;

        let mut session = SmtpSession {
            state: SmtpState::Greeting,
            hostname: hostname.clone(),
            mail_from: None,
            rcpt_to: Vec::new(),
            is_submission,
            authenticated: false,
            auth_username: None,
            auth_domain: None,
            client_ip: client_ip.clone(),
            tls_upgraded: implicit_tls,
        };

        let mut line = String::new();
        loop {
            line.clear();
            let n = stream.read_line(&mut line).await?;
            if n == 0 {
                break; // 连接关闭
            }

            let line = line.trim_end_matches("\r\n").trim_end_matches('\n');
            let response = session.process_command(line, &app_state).await;

            match response {
                Response::Continue(msg) => {
                    stream.write_all(msg.as_bytes()).await?;
                }
                Response::Data => {
                    stream.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").await?;
                    // 读取邮件数据
                    let mut data = Vec::new();
                    let mut data_line = String::new();
                    loop {
                        data_line.clear();
                        let n = stream.read_line(&mut data_line).await?;
                        if n == 0 {
                            break;
                        }
                        let trimmed = data_line.trim_end_matches("\r\n").trim_end_matches('\n');
                        if trimmed == "." {
                            break;
                        }
                        // 透明化处理：移除点 stuffing
                        if trimmed.starts_with('.') {
                            data.extend_from_slice(&trimmed.as_bytes()[1..]);
                        } else {
                            data.extend_from_slice(trimmed.as_bytes());
                        }
                        data.extend_from_slice(b"\r\n");
                    }

                    // 处理邮件数据
                    let result = session.handle_data(&data, &app_state).await;
                    match result {
                        Ok(()) => {
                            stream.write_all(b"250 2.0.0 OK: Message queued\r\n").await?;
                        }
                        Err(e) => {
                            tracing::warn!("邮件处理失败: {}", e);
                            stream
                                .write_all(format!("451 4.3.0 Error: {}\r\n", e).as_bytes())
                                .await?;
                        }
                    }
                    session.reset();
                }
                Response::Quit(msg) => {
                    stream.write_all(msg.as_bytes()).await?;
                    break;
                }
                Response::StartTls => {
                    stream.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                    stream.flush().await?;

                    // 执行 TLS 升级
                    let tcp_stream = stream.take_plain_stream()?;
                    let acceptor = app_state.tls_cert_store.acceptor().await;

                    match acceptor {
                        Some(acceptor) => {
                            match acceptor.accept(tcp_stream).await {
                                Ok(tls_stream) => {
                                    *stream = UpgradableStream::Tls(tls_stream);
                                    session.tls_upgraded = true;
                                    // RFC 3207: TLS 升级后必须重置会话状态
                                    session.state = SmtpState::Greeting;
                                    session.authenticated = false;
                                    session.auth_username = None;
                                    session.auth_domain = None;
                                    session.mail_from = None;
                                    session.rcpt_to.clear();
                                    tracing::info!("SMTP: TLS 升级成功 ({})", client_ip);
                                }
                                Err(e) => {
                                    tracing::warn!("SMTP: TLS 握手失败: {}", e);
                                    break;
                                }
                            }
                        }
                        None => {
                            tracing::warn!("SMTP: STARTTLS 请求但无可用证书");
                            break;
                        }
                    }
                }
                Response::AuthLoginStep(prompt, pending_username) => {
                    tracing::info!("SMTP AUTH LOGIN 步骤: pending_username={}", if pending_username.is_empty() { "(空,等用户名)" } else { &pending_username });
                    stream.write_all(prompt.as_bytes()).await?;
                    if !pending_username.is_empty() {
                        // 用户名已在 AUTH LOGIN <b64user> 中提供，只等密码
                        let mut pwd_line = String::new();
                        let n = stream.read_line(&mut pwd_line).await?;
                        if n == 0 { break; }
                        let pwd_input = pwd_line.trim_end_matches("\r\n").trim_end_matches('\n');
                        if pwd_input == "*" {
                            stream.write_all(b"501 5.7.0 Authentication cancelled\r\n").await?;
                            continue;
                        }
                        let password = STANDARD.decode(pwd_input)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .unwrap_or_default();
                        let resp = session.do_auth_login(&pending_username, &password, &app_state).await;
                        stream.write_all(resp.as_bytes()).await?;
                    } else {
                        // 两步：先读用户名，再读密码
                        let mut auth_line = String::new();
                        let n = stream.read_line(&mut auth_line).await?;
                        if n == 0 { break; }
                        let auth_input = auth_line.trim_end_matches("\r\n").trim_end_matches('\n');
                        if auth_input == "*" {
                            stream.write_all(b"501 5.7.0 Authentication cancelled\r\n").await?;
                            continue;
                        }
                        let username = STANDARD.decode(auth_input)
                            .ok()
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_default();

                        // 发送密码提示
                        stream.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                        stream.flush().await?;

                        // 等待密码
                        let mut pwd_line = String::new();
                        let n = stream.read_line(&mut pwd_line).await?;
                        if n == 0 { break; }
                        let pwd_input = pwd_line.trim_end_matches("\r\n").trim_end_matches('\n');
                        if pwd_input == "*" {
                            stream.write_all(b"501 5.7.0 Authentication cancelled\r\n").await?;
                            continue;
                        }
                        let password = STANDARD.decode(pwd_input)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .unwrap_or_default();

                        // 验证
                        let resp = session.do_auth_login(&username, &password, &app_state).await;
                        stream.write_all(resp.as_bytes()).await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// 处理 SMTP 命令
    async fn process_command(&mut self, line: &str, app_state: &Arc<AppState>) -> Response {
        let (cmd, args) = if let Some(pos) = line.find(' ') {
            (&line[..pos], line[pos + 1..].trim())
        } else {
            (line, "")
        };

        match cmd.to_uppercase().as_str() {
            "HELO" | "EHLO" => {
                self.state = SmtpState::Helo;
                let mut caps = vec![
                    format!("250-{} Hello", self.hostname),
                    format!("250-SIZE {}", app_state.max_message_size.load(std::sync::atomic::Ordering::Relaxed)),
                    "250-8BITMIME".to_string(),
                    "250-PIPELINING".to_string(),
                    "250-ENHANCEDSTATUSCODES".to_string(),
                ];
                // AUTH 能力广播：
                // - Submission 端口：始终广播
                // - SMTP 端口(25)：仅在 STARTTLS 后广播（防止明文传输密码）
                if self.is_submission || self.tls_upgraded {
                    caps.push("250-AUTH LOGIN PLAIN".to_string());
                }
                // STARTTLS 只在未升级时 advertised
                if !self.tls_upgraded {
                    caps.push("250-STARTTLS".to_string());
                }
                caps.push("250 HELP".to_string());
                Response::Continue(caps.join("\r\n") + "\r\n")
            }
            "AUTH" => {
                // 端口 25：仅允许在 STARTTLS 后认证（防止明文传输密码）
                // Submission 端口：始终允许认证
                if !self.is_submission && !self.tls_upgraded {
                    return Response::Continue("538 5.7.11 AUTH requires TLS encryption first\r\n".to_string());
                }
                self.handle_auth(args, app_state).await
            }
            "MAIL" => {
                // MAIL FROM:<sender@example.com>
                if self.is_submission && !self.authenticated {
                    return Response::Continue("530 5.7.0 Authentication required\r\n".to_string());
                }
                let addr = Self::extract_address(args);
                if addr.is_none() {
                    return Response::Continue("501 5.5.4 Syntax error in MAIL FROM\r\n".to_string());
                }
                let addr = addr.unwrap();

                // 认证用户的 MAIL FROM 必须是自己（防止冒充其他用户）
                // 仅对 submission 端口和已认证的中继用户强制
                if self.authenticated {
                    if let (Some(u), Some(d)) = (&self.auth_username, &self.auth_domain) {
                        let auth_addr = format!("{}@{}", u, d);
                        // 允许使用已认证别名（查询 aliases）
                        let is_alias = self.check_alias(u, d, &addr, app_state).await;
                        if addr.to_lowercase() != auth_addr.to_lowercase() && !is_alias {
                            tracing::warn!(
                                "MAIL FROM 地址不匹配认证用户: auth={}@{}, mail_from={}",
                                u, d, addr
                            );
                            return Response::Continue(
                                "550 5.7.1 Sender address does not match authenticated user\r\n".to_string(),
                            );
                        }
                    }
                }

                self.mail_from = Some(addr);
                self.state = SmtpState::MailFrom;
                Response::Continue("250 2.1.0 OK\r\n".to_string())
            }
            "RCPT" => {
                // RCPT TO:<recipient@example.com>
                if self.mail_from.is_none() {
                    return Response::Continue("503 5.5.1 Need MAIL before RCPT\r\n".to_string());
                }
                let addr = Self::extract_address(args);
                if addr.is_none() {
                    return Response::Continue("501 5.5.4 Syntax error in RCPT TO\r\n".to_string());
                }
                let addr = addr.unwrap();

                // 检查收件人域名
                let domain = addr.split('@').last().unwrap_or("");
                let is_local = app_state.domain_store.is_local(domain).await;

                if is_local {
                    // 本地域名：检查邮箱是否存在
                    let username = addr.split('@').next().unwrap_or("");
                    let exists = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND d.name = $2 AND m.enabled = true AND d.enabled = true"
                    )
                    .bind(username)
                    .bind(domain)
                    .fetch_one(&app_state.pool)
                    .await
                    .unwrap_or(0);

                    if exists == 0 {
                        return Response::Continue(
                            format!("550 5.1.1 <{}>: Recipient address rejected: User unknown\r\n", addr),
                        );
                    }
                }

                // 对于出站邮件（非本地域名），必须认证才能中继
                // 无论 SMTP(25) 还是 Submission(587) 端口，都禁止未认证的中继
                if !is_local && !self.authenticated {
                    return Response::Continue("550 5.7.1 Relaying denied\r\n".to_string());
                }

                // 收件人数量上限：从 smtp_config.max_recipients 读取，默认 100
                let max_recipients: i64 = sqlx::query_scalar(
                    "SELECT (value->>'max_recipients')::int FROM settings WHERE key = 'smtp_config'"
                )
                .fetch_optional(&app_state.pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(100);
                if self.rcpt_to.len() as i64 >= max_recipients {
                    return Response::Continue(
                        format!("452 4.5.3 Too many recipients (max {})\r\n", max_recipients),
                    );
                }

                self.rcpt_to.push(addr);
                self.state = SmtpState::RcptTo;
                Response::Continue("250 2.1.5 OK\r\n".to_string())
            }
            "DATA" => {
                if self.mail_from.is_none() || self.rcpt_to.is_empty() {
                    return Response::Continue("503 5.5.1 Need MAIL and RCPT before DATA\r\n".to_string());
                }
                self.state = SmtpState::Data;
                Response::Data
            }
            "RSET" => {
                self.reset();
                Response::Continue("250 2.0.0 OK\r\n".to_string())
            }
            "NOOP" => Response::Continue("250 2.0.0 OK\r\n".to_string()),
            "QUIT" => {
                self.state = SmtpState::Quit;
                Response::Quit(format!("221 2.0.0 {} closing connection\r\n", self.hostname))
            }
            "STARTTLS" => {
                if self.tls_upgraded {
                    return Response::Continue("503 5.5.1 TLS already active\r\n".to_string());
                }
                Response::StartTls
            }
            "VRFY" => Response::Continue("252 2.5.0 Cannot VRFY user\r\n".to_string()),
            "HELP" => Response::Continue("214 2.0.0 FunMail SMTP Server\r\n".to_string()),
            _ => Response::Continue("500 5.5.1 Command unrecognized\r\n".to_string()),
        }
    }

    /// 处理 AUTH 命令
    async fn handle_auth(&mut self, args: &str, app_state: &Arc<AppState>) -> Response {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        tracing::info!("SMTP AUTH 请求: mechanism={}, parts={}", parts.first().unwrap_or(&""), parts.len());
        if parts.is_empty() {
            return Response::Continue("501 5.5.4 Syntax error in AUTH\r\n".to_string());
        }

        let mechanism = parts[0].to_uppercase();
        match mechanism.as_str() {
            "LOGIN" => {
                // AUTH LOGIN 两步交互
                // 客户端可能在 AUTH LOGIN 后面直接带上 base64(username)
                if parts.len() >= 2 && !parts[1].is_empty() {
                    // 客户端一次性发送: AUTH LOGIN <base64(username)>
                    let username = STANDARD.decode(parts[1])
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_default();
                    // 进入等待密码步骤，把 username 暂存
                    Response::AuthLoginStep("334 UGFzc3dvcmQ6\r\n".to_string(), username)
                } else {
                    // 标准两步: AUTH LOGIN → 等待用户名 → 等待密码
                    Response::AuthLoginStep("334 VXNlcm5hbWU6\r\n".to_string(), String::new())
                }
            }
            "PLAIN" => {
                if parts.len() < 2 {
                    return Response::Continue("501 5.5.4 Syntax error in AUTH PLAIN\r\n".to_string());
                }
                // PLAIN 格式: \0username\0password 或 base64 编码
                match STANDARD.decode(parts[1]) {
                    Ok(decoded) => {
                        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                        if parts.len() >= 3 {
                            let username = String::from_utf8(parts[1].to_vec()).unwrap_or_default();
                            let password = String::from_utf8(parts[2].to_vec()).unwrap_or_default();
                            let result = self.do_auth_login(&username, &password, app_state).await;
                            Response::Continue(result)
                        } else {
                            Response::Continue("501 5.5.4 Malformed AUTH PLAIN\r\n".to_string())
                        }
                    }
                    Err(_) => Response::Continue("501 5.5.4 Invalid base64 in AUTH PLAIN\r\n".to_string()),
                }
            }
            _ => Response::Continue("504 5.5.4 Unrecognized authentication type\r\n".to_string()),
        }
    }

    /// 处理邮件数据
    async fn handle_data(&mut self, data: &[u8], app_state: &Arc<AppState>) -> anyhow::Result<()> {
        let from = self.mail_from.clone().unwrap_or_default();
        let size = data.len() as i64;

        // 解析发件人/收件人域名以应用 register_config 覆盖
        let from_domain_owned = from.rsplitn(2, '@').next().map(|s| s.to_string()).filter(|s| !s.is_empty());

        // 一次性加载全局 + 发件人域名的 send 上限
        let limits_with_from = funmail_common::db::resolve_size_limits(
            &app_state.pool,
            from_domain_owned.as_deref(),
            None,
        ).await;
        let send_limit = limits_with_from.max_send_bytes;
        let global_recv = limits_with_from.max_receive_bytes;

        // 收件人侧逐个域名找最严格 receive 上限（复用全局值，仅查域名覆盖）
        let mut min_recv_bytes: u64 = global_recv;
        for rcpt in &self.rcpt_to {
            let to_domain = rcpt.rsplitn(2, '@').next().map(|s| s.to_string()).filter(|s| !s.is_empty());
            if let Some(d) = to_domain {
                if let Ok(Some((cfg,))) = sqlx::query_as::<_, (serde_json::Value,)>(
                    "SELECT register_config FROM domains WHERE LOWER(name) = LOWER($1)"
                )
                .bind(&d)
                .fetch_optional(&app_state.pool)
                .await
                {
                    let (_, recv_override) = funmail_common::db::parse_domain_size_overrides(&cfg);
                    if let Some(v) = recv_override {
                        min_recv_bytes = min_recv_bytes.min(v);
                    }
                }
            }
        }

        // 检查邮件大小：发件人不得超出 send 上限，收件人不得超出 receive 上限
        if (size as u64) > send_limit {
            anyhow::bail!("Message exceeds send size limit ({} > {} bytes)", size, send_limit);
        }
        if (size as u64) > min_recv_bytes {
            anyhow::bail!("Message exceeds recipient receive size limit ({} > {} bytes)", size, min_recv_bytes);
        }

        // 解析邮件获取 Message-ID、Subject（已解码）
        let (message_id, subject) = Self::parse_headers(data);

        // 读取安全配置
        let sec_config = Self::get_security_config(&app_state.pool).await;
        let spam_filter_enabled = sec_config.get("spam_filter_enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let _spam_threshold = sec_config.get("spam_threshold").and_then(|v| v.as_f64()).unwrap_or(5.0) as f32;
        let spam_action = sec_config.get("spam_action").and_then(|v| v.as_str()).unwrap_or("mark").to_string();
        let rbl_enabled = sec_config.get("rbl_enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let rbl_servers: Vec<String> = sec_config.get("rbl_servers")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["zen.spamhaus.org".into(), "bl.spamcop.net".into()]);
        let virus_scan_enabled = sec_config.get("virus_scan_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        let virus_scan_mode = sec_config.get("virus_scan_mode").and_then(|v| v.as_str()).unwrap_or("clamd_tcp").to_string();
        let clamd_tcp_host = sec_config.get("clamd_tcp_host").and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| std::env::var("CLAMD_TCP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()));
        let clamd_tcp_port = sec_config.get("clamd_tcp_port").and_then(|v| v.as_u64()).unwrap_or(3310) as u16;
        let clamd_unix_path = sec_config.get("clamd_unix_path").and_then(|v| v.as_str()).unwrap_or("/var/run/clamav/clamd.ctl").to_string();
        let virus_scan_command = sec_config.get("virus_scan_command").and_then(|v| v.as_str()).unwrap_or("clamdscan").to_string();
        let virus_action = sec_config.get("virus_action").and_then(|v| v.as_str()).unwrap_or("reject").to_string();

        let mut spam_score: f32 = 0.0;
        let mut is_spam = false;
        let mut spam_details = String::new();
        let mut is_infected = false;
        let mut virus_name: Option<String> = None;

        // 反垃圾邮件检查（仅对未认证的入站邮件执行，已认证发信用户跳过）
        if spam_filter_enabled && !self.authenticated {
            let result = funmail_common::security::check_spam(
                &from, &self.client_ip, data, rbl_enabled, &rbl_servers,
            ).await;
            spam_score = result.score;
            is_spam = result.is_spam;
            spam_details = result.details.join("; ");

            if is_spam && spam_action == "reject" {
                tracing::warn!("垃圾邮件已拒绝: from={} score={:.1} details={}", from, spam_score, spam_details);
                anyhow::bail!("Message rejected as spam (score: {:.1})", spam_score);
            }

            if is_spam {
                tracing::warn!("检测到垃圾邮件: from={} score={:.1} action={} details={}", from, spam_score, spam_action, spam_details);
            }
        }

        // 防病毒扫描（仅对未认证的入站邮件执行）
        if virus_scan_enabled && !self.authenticated {
            let scan_mode = match virus_scan_mode.as_str() {
                "clamd_tcp" => funmail_common::security::VirusScanMode::ClamdTcp {
                    host: clamd_tcp_host,
                    port: clamd_tcp_port,
                },
                "clamd_unix" => funmail_common::security::VirusScanMode::ClamdUnix {
                    path: clamd_unix_path,
                },
                _ => funmail_common::security::VirusScanMode::Command {
                    command: virus_scan_command,
                },
            };
            let result = funmail_common::security::scan_virus(data, &scan_mode).await;
            is_infected = result.infected;
            virus_name = result.virus_name;

            if is_infected && virus_action == "reject" {
                tracing::warn!("病毒邮件已拒绝: from={} virus={:?}", from, virus_name);
                anyhow::bail!("Message rejected: virus detected ({})", virus_name.unwrap_or_default());
            }

            if is_infected {
                tracing::warn!("检测到病毒邮件: from={} virus={:?} action={}", from, virus_name, virus_action);
            }
        }

        // 写入邮件文件
        let mail_id = uuid::Uuid::new_v4().to_string();
        let data_dir = std::path::Path::new(&app_state.maildir_base).join("queue");
        std::fs::create_dir_all(&data_dir)?;
        let data_path = data_dir.join(&mail_id);
        std::fs::write(&data_path, data)?;

        let data_path_str = data_path.to_string_lossy().to_string();

        // 确定邮件状态
        let queue_status = if is_infected && virus_action == "quarantine" {
            "quarantined"
        } else if is_spam && spam_action == "quarantine" {
            "quarantined"
        } else {
            "pending"
        };

        // 为每个收件人创建队列条目
        for rcpt in &self.rcpt_to {
            let domain = rcpt.split('@').last().unwrap_or("");
            let is_local = app_state.domain_store.is_local(domain).await;
            let direction = if is_local { "inbound" } else { "outbound" };

            sqlx::query(
                "INSERT INTO mail_queue (from_addr, to_addr, data_path, message_id, subject, status, direction, size_bytes, spam_score)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            )
            .bind(&from)
            .bind(rcpt)
            .bind(&data_path_str)
            .bind(&message_id)
            .bind(&subject)
            .bind(queue_status)
            .bind(direction)
            .bind(size)
            .bind(spam_score)
            .execute(&app_state.pool)
            .await?;
        }

        // 通知投递引擎有新邮件入队，触发实时投递（无需等待轮询）
        if queue_status == "pending" {
            let _ = sqlx::query("SELECT pg_notify('mail_new', '1')")
                .execute(&app_state.pool)
                .await;
        }

        // 写入邮件日志
        let log_status = if is_infected {
            if virus_action == "reject" { "rejected" } else { "quarantined" }
        } else if is_spam {
            if spam_action == "reject" { "rejected" } else { "spam" }
        } else {
            "queued"
        };

        let reject_reason = if is_infected {
            Some(format!("病毒: {}", virus_name.unwrap_or_default()))
        } else if is_spam {
            Some(format!("垃圾邮件 (score={:.1}): {}", spam_score, spam_details))
        } else {
            None
        };

        for rcpt in &self.rcpt_to {
            let domain = rcpt.split('@').last().unwrap_or("");
            let domain_id = Self::get_domain_id(&app_state.pool, domain).await;
            let is_local = app_state.domain_store.is_local(domain).await;
            let log_direction = if is_local { "inbound" } else { "outbound" };

            sqlx::query(
                "INSERT INTO mail_logs (domain_id, from_addr, to_addr, message_id, subject, direction, status, size_bytes, client_ip, spam_score, reject_reason, data_path)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
            )
            .bind(domain_id)
            .bind(&from)
            .bind(rcpt)
            .bind(&message_id)
            .bind(&subject)
            .bind(log_direction)
            .bind(log_status)
            .bind(size)
            .bind(&self.client_ip)
            .bind(spam_score)
            .bind(&reject_reason)
            .bind(&data_path_str)
            .execute(&app_state.pool)
            .await?;
        }

        // 复制到发件人的 IMAP Sent 目录（仅限已认证用户发送的邮件）
        if self.authenticated {
            let from_parts: Vec<&str> = from.rsplitn(2, '@').collect();
            if from_parts.len() == 2 {
                let from_user = from_parts[1];
                let from_domain = from_parts[0];
                let sent_dir = std::path::Path::new(&app_state.maildir_base)
                    .join(from_domain).join(from_user).join("Sent").join("new");
                if let Ok(()) = std::fs::create_dir_all(&sent_dir) {
                    let sent_filename = format!(
                        "{}.{}.{}",
                        chrono::Utc::now().timestamp(),
                        std::process::id(),
                        uuid::Uuid::new_v4().as_simple()
                    );
                    if std::fs::copy(&data_path, sent_dir.join(&sent_filename)).is_ok() {
                        // 更新发件人 used_bytes
                        let _ = funmail_common::db::add_mailbox_used_bytes(
                            &app_state.pool, from_user, from_domain, size
                        ).await;
                    }
                }
            }
        }

        tracing::info!(
            "邮件已入队: from={} to={:?} size={} status={} spam_score={:.1}",
            from,
            self.rcpt_to,
            size,
            log_status,
            spam_score
        );

        Ok(())
    }

    /// AUTH LOGIN / AUTH PLAIN 的实际验证逻辑
    async fn do_auth_login(&mut self, username: &str, password: &str, app_state: &Arc<AppState>) -> String {
        tracing::info!("SMTP 认证尝试: username={}", username);
        if let Some((user, domain)) = username.split_once('@') {
            match db::authenticate_mailbox(&app_state.pool, user, domain, password).await {
                Ok(Some(_id)) => {
                    // 检查协议权限：mailbox.protocols 非空时覆盖域名 register_config
                    let proto_row: Option<(Option<serde_json::Value>, serde_json::Value)> = sqlx::query_as(
                        "SELECT m.protocols, d.register_config
                         FROM mailboxes m JOIN domains d ON m.domain_id = d.id
                         WHERE m.username = $1 AND d.name = $2"
                    )
                    .bind(user)
                    .bind(domain)
                    .fetch_optional(&app_state.pool)
                    .await
                    .unwrap_or(None);

                    let allow_smtp = proto_row
                        .map(|(mp, rc)| {
                            let cfg = match mp {
                                Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v,
                                _ => rc,
                            };
                            // 统一使用 allow_* 字段名
                            cfg.get("allow_smtp").and_then(|v| v.as_bool()).unwrap_or(true)
                        })
                        .unwrap_or(true);

                    if !allow_smtp {
                        tracing::warn!("SMTP 认证被拒（协议权限禁止 SMTP）: {}@{}", user, domain);
                        return "535 5.7.8 SMTP access denied for this account\r\n".to_string();
                    }

                    self.authenticated = true;
                    self.auth_username = Some(user.to_string());
                    self.auth_domain = Some(domain.to_string());
                    tracing::info!("SMTP 认证成功: {}@{}", user, domain);
                    "235 2.7.0 Authentication successful\r\n".to_string()
                }
                Ok(None) => {
                    tracing::warn!("SMTP 认证失败（密码错误或用户不存在）: {}@{}", user, domain);
                    "535 5.7.8 Authentication failed\r\n".to_string()
                }
                Err(e) => {
                    tracing::warn!("SMTP 认证错误: {}", e);
                    "451 4.3.0 Temporary authentication failure\r\n".to_string()
                }
            }
        } else {
            tracing::warn!("SMTP 认证失败：用户名格式错误（需要 user@domain）: {}", username);
            "535 5.7.8 Invalid username format (need user@domain)\r\n".to_string()
        }
    }

    /// 检查 mail_from 地址是否是认证用户的别名
    async fn check_alias(&self, user: &str, domain: &str, mail_from: &str, app_state: &Arc<AppState>) -> bool {
        // mail_from 的 domain 必须和认证用户的 domain 相同
        let (_, mf_domain) = match mail_from.split_once('@') {
            Some(p) => p,
            None => return false,
        };
        if !mf_domain.eq_ignore_ascii_case(domain) {
            return false;
        }
        // 查询用户的 aliases 数组
        let aliases_json: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT aliases FROM mailboxes m JOIN domains d ON m.domain_id = d.id
             WHERE m.username = $1 AND d.name = $2"
        )
        .bind(user)
        .bind(domain)
        .fetch_optional(&app_state.pool)
        .await
        .unwrap_or(None);

        match aliases_json {
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().any(|v| v.as_str().map(|s| s.eq_ignore_ascii_case(mail_from)).unwrap_or(false))
            }
            _ => false,
        }
    }

    /// 从 MAIL FROM / RCPT TO 参数中提取地址
    fn extract_address(args: &str) -> Option<String> {
        // MAIL FROM:<user@domain> 或 RCPT TO:<user@domain>
        let args_upper = args.to_uppercase();
        let prefix = if args_upper.starts_with("FROM:") {
            "FROM:"
        } else if args_upper.starts_with("TO:") {
            "TO:"
        } else {
            return None;
        };

        let addr_part = &args[prefix.len()..].trim();
        let addr = addr_part.trim_start_matches('<').trim_end_matches('>');
        if addr.is_empty() {
            return None;
        }
        Some(addr.to_string())
    }

    /// 解析邮件头部：返回 (message_id, subject_decoded)
    /// subject_decoded 已按 RFC 2047 / charset 解码，可直接存储为可读中文
    fn parse_headers(data: &[u8]) -> (Option<String>, Option<String>) {
        // 优先用 mail-parser 解码（支持 RFC 2047、charset 等）
        let (decoded, msg_id) = if let Some(parsed) = mail_parser::MessageParser::default().parse(data) {
            let s_decoded = parsed.subject().map(|s| s.to_string());
            let m_id = parsed.message_id().map(|s| s.to_string());
            (s_decoded, m_id)
        } else {
            (None, None)
        };

        // 兜底：用简单字符串解析
        let (msg_id_fb, subject_fb) = {
            let content = String::from_utf8_lossy(data);
            let mut message_id = None;
            let mut subject = None;
            for line in content.lines() {
                if line.is_empty() { break; }
                if let Some(v) = line.strip_prefix("Message-ID:") {
                    message_id = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("Subject:") {
                    subject = Some(v.trim().to_string());
                }
            }
            (message_id, subject)
        };

        (
            msg_id.or(msg_id_fb),
            decoded.or(subject_fb),
        )
    }

    /// 获取域名 ID
    async fn get_domain_id(pool: &sqlx::PgPool, domain: &str) -> Option<i32> {
        sqlx::query_scalar::<_, i32>(
            "SELECT id FROM domains WHERE name = $1"
        )
        .bind(domain)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
    }

    /// 获取安全配置
    async fn get_security_config(pool: &sqlx::PgPool) -> serde_json::Value {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM system_settings WHERE key = 'security_config'"
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(serde_json::json!({}))
    }

    /// 重置会话状态（准备下一封邮件）
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.state = SmtpState::Helo;
    }
}

/// SMTP 响应类型
enum Response {
    Continue(String),
    Data,
    Quit(String),
    StartTls,
    /// AUTH LOGIN 多步交互：发送 prompt 后等待客户端回复
    AuthLoginStep(String, String), // (prompt, pending_username)
}
