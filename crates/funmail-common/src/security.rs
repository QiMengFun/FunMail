use std::net::IpAddr;

/// 垃圾邮件检查结果
#[derive(Debug, Clone)]
pub struct SpamCheckResult {
    pub score: f32,
    pub is_spam: bool,
    pub details: Vec<String>,
}

/// 病毒扫描结果
#[derive(Debug, Clone)]
pub struct VirusScanResult {
    pub infected: bool,
    pub virus_name: Option<String>,
}

/// 病毒扫描模式
#[derive(Debug, Clone)]
pub enum VirusScanMode {
    /// 通过 ClamAV 守护进程（TCP socket）扫描
    ClamdTcp { host: String, port: u16 },
    /// 通过 ClamAV 守护进程（Unix socket）扫描
    ClamdUnix { path: String },
    /// 通过外部命令扫描
    Command { command: String },
}

/// RBL（实时黑名单）检查
pub async fn check_rbl(ip: &str, servers: &[String]) -> Vec<String> {
    let mut hits = Vec::new();

    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return hits,
    };

    // 构造反向查询域名
    let reversed = match ip_addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(_) => return hits,
    };

    for server in servers {
        let query = format!("{}.{}", reversed, server);
        // 每个 RBL 查询最多等待 5 秒，防止 DNS 超时阻塞 SMTP 会话
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host(&format!("{}:0", query)),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                if addrs.count() > 0 {
                    hits.push(server.clone());
                }
            }
            Ok(Err(_)) => {}
            Err(_elapsed) => {
                tracing::warn!("RBL 查询超时: {}", server);
            }
        }
    }

    hits
}

/// 垃圾邮件评分
pub async fn check_spam(
    from_addr: &str,
    client_ip: &str,
    data: &[u8],
    rbl_enabled: bool,
    rbl_servers: &[String],
) -> SpamCheckResult {
    let mut score: f32 = 0.0;
    let mut details = Vec::new();

    // 1. RBL 检查（每命中一个 +3.0）
    if rbl_enabled && !rbl_servers.is_empty() && !client_ip.is_empty() {
        let rbl_hits = check_rbl(client_ip, rbl_servers).await;
        let hit_count = rbl_hits.len() as f32;
        score += hit_count * 3.0;
        for server in &rbl_hits {
            details.push(format!("RBL 命中: {}", server));
        }
    }

    // 2. 发件人地址检查
    if from_addr.is_empty() {
        score += 2.0;
        details.push("缺少发件人地址".to_string());
    } else if !from_addr.contains('@') {
        score += 2.0;
        details.push("发件人地址格式异常".to_string());
    }

    // 3. 内容特征检查
    let content = String::from_utf8_lossy(data);

    let checks: [(&str, fn(&str) -> bool); 5] = [
        ("大量大写字母", |c: &str| {
            let total = c.chars().count();
            if total == 0 { return false; }
            let upper = c.chars().filter(|ch| ch.is_uppercase()).count();
            upper as f32 > total as f32 * 0.5
        }),
        ("可疑 URL 短链接", |c: &str| c.contains("bit.ly") || c.contains("tinyurl.com") || c.contains("t.co")),
        ("HTML 表单", |c: &str| c.contains("<form") && c.contains("password")),
        ("JavaScript 内容", |c: &str| c.contains("<script") || c.contains("javascript:")),
        ("可疑附件扩展名", |c: &str| c.contains(".exe") || c.contains(".scr") || c.contains(".bat") || c.contains(".cmd")),
    ];

    for (name, check_fn) in &checks {
        if check_fn(&content) {
            score += 1.5;
            details.push(format!("内容特征: {}", name));
        }
    }

    // 4. 邮件大小异常
    if data.len() < 50 {
        score += 1.0;
        details.push("邮件内容过短".to_string());
    }

    SpamCheckResult {
        score,
        is_spam: score >= 5.0,
        details,
    }
}

/// 病毒扫描（支持 ClamAV 守护进程和外部命令）
pub async fn scan_virus(data: &[u8], mode: &VirusScanMode) -> VirusScanResult {
    match mode {
        VirusScanMode::ClamdTcp { host, port } => scan_clamd_tcp(data, host, *port).await,
        VirusScanMode::ClamdUnix { path } => scan_clamd_unix(data, path).await,
        VirusScanMode::Command { command } => scan_command(data, command).await,
    }
}

/// 通过 ClamAV 守护进程 TCP socket 扫描
async fn scan_clamd_tcp(data: &[u8], host: &str, port: u16) -> VirusScanResult {
    let addr = format!("{}:{}", host, port);
    let config = clamav_client::tokio::Tcp {
        host_address: addr.clone(),
    };

    match clamav_client::tokio::scan_buffer(data, config, None).await {
        Ok(response) => {
            let result = String::from_utf8_lossy(&response);
            parse_clamd_response(&result)
        }
        Err(e) => {
            tracing::warn!("ClamAV TCP 扫描失败 ({}): {}", addr, e);
            VirusScanResult {
                infected: false,
                virus_name: None,
            }
        }
    }
}

/// 通过 ClamAV 守护进程 Unix socket 扫描
async fn scan_clamd_unix(data: &[u8], path: &str) -> VirusScanResult {
    let config = clamav_client::tokio::Socket {
        socket_path: path.to_string(),
    };

    match clamav_client::tokio::scan_buffer(data, config, None).await {
        Ok(response) => {
            let result = String::from_utf8_lossy(&response);
            parse_clamd_response(&result)
        }
        Err(e) => {
            tracing::warn!("ClamAV Unix socket 扫描失败 ({}): {}", path, e);
            VirusScanResult {
                infected: false,
                virus_name: None,
            }
        }
    }
}

/// 解析 clamd 响应
/// 格式: "stream: Virus.Name FOUND\n" 或 "stream: OK\n"
fn parse_clamd_response(response: &str) -> VirusScanResult {
    let response = response.trim();

    if response.ends_with("OK") {
        VirusScanResult {
            infected: false,
            virus_name: None,
        }
    } else if response.ends_with("FOUND") {
        // 提取病毒名: "stream: Virus.Name FOUND" → "Virus.Name"
        let virus_name = response
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
            .map(|s| s.trim().to_string())
            .or_else(|| Some("unknown".to_string()));

        tracing::warn!("ClamAV 检测到病毒: {:?}", virus_name);
        VirusScanResult {
            infected: true,
            virus_name,
        }
    } else if response.contains("ERROR") {
        tracing::warn!("ClamAV 返回错误: {}", response);
        VirusScanResult {
            infected: false,
            virus_name: None,
        }
    } else {
        VirusScanResult {
            infected: false,
            virus_name: None,
        }
    }
}

/// 通过外部命令扫描（兼容模式）
async fn scan_command(data: &[u8], command: &str) -> VirusScanResult {
    let temp_dir = std::path::Path::new("/tmp/funmail_scan");
    let _ = std::fs::create_dir_all(temp_dir);

    let temp_file = temp_dir.join(format!("scan_{}", uuid::Uuid::new_v4()));
    if let Err(e) = std::fs::write(&temp_file, data) {
        tracing::warn!("病毒扫描: 写入临时文件失败: {}", e);
        return VirusScanResult {
            infected: false,
            virus_name: None,
        };
    }

    let output = tokio::process::Command::new(command)
        .arg(&temp_file)
        .output()
        .await;

    let _ = std::fs::remove_file(&temp_file);

    match output {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(0);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            match exit_code {
                0 => VirusScanResult {
                    infected: false,
                    virus_name: None,
                },
                1 => {
                    let virus_name = extract_virus_name(&stdout, &stderr);
                    tracing::warn!("病毒扫描: 发现病毒: {:?}", virus_name);
                    VirusScanResult {
                        infected: true,
                        virus_name,
                    }
                }
                _ => {
                    tracing::warn!("病毒扫描: 扫描程序返回错误 (code={}): {}", exit_code, stderr);
                    VirusScanResult {
                        infected: false,
                        virus_name: None,
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("病毒扫描: 执行扫描程序失败: {}", e);
            VirusScanResult {
                infected: false,
                virus_name: None,
            }
        }
    }
}

/// 从外部命令输出中提取病毒名
fn extract_virus_name(stdout: &str, stderr: &str) -> Option<String> {
    for line in stdout.lines().chain(stderr.lines()) {
        if line.contains("FOUND") {
            if let Some(pos) = line.find(": ") {
                let rest = &line[pos + 2..];
                if let Some(end) = rest.find(" FOUND") {
                    return Some(rest[..end].to_string());
                }
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}
