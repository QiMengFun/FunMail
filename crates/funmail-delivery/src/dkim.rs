use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{Signer, SignatureEncoding};

/// DKIM 签名（RSA-SHA256，RFC 6376 relaxed 规范化）
///
/// 对邮件头部和正文进行签名，生成可插入邮件的 DKIM-Signature 头值
///
/// 参数：
/// - `private_key_pem`：PKCS#8 或 PKCS#1 格式的 RSA 私钥 PEM
/// - `selector`：DKIM 选择器（如 "funmail"）
/// - `domain`：签名域名（发件人域 d=）
/// - `data`：完整的 RFC 5322 邮件内容（headers + body）
///
/// 返回：DKIM-Signature 头的值部分（调用方需自行加 "DKIM-Signature:" 前缀和 CRLF）
pub fn sign_dkim(
    private_key_pem: &str,
    selector: &str,
    domain: &str,
    data: &[u8],
) -> anyhow::Result<String> {
    let private_key = parse_rsa_private_key(private_key_pem)?;

    // 1. 分离 headers 和 body（第一个空行分隔）
    let raw = std::str::from_utf8(data)
        .map_err(|_| anyhow::anyhow!("邮件包含非 UTF-8 字节"))?;
    // 统一换行符为 \r\n
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let normalized = normalized.replace('\n', "\r\n");
    let (header_block, body) = normalized
        .split_once("\r\n\r\n")
        .unwrap_or((&normalized, ""));

    // 2. relaxed 规范化 body：去除尾部空行，确保以单个 CRLF 结尾
    let body_normalized = relax_body(body);

    // 3. 计算 body hash（bh=）：SHA256 后 base64
    let body_hash = base64::engine::general_purpose::STANDARD
        .encode(Sha256::digest(body_normalized.as_bytes()));

    // 4. 解析 headers，收集需要签名的头部
    let header_map = parse_headers(header_block);
    // RFC 6376 建议签 From/To/Subject/Date/Message-ID
    let headers_to_sign = ["From", "To", "Subject", "Date", "Message-ID"];
    let h_field: Vec<&str> = headers_to_sign
        .iter()
        .filter(|name| header_map.contains_key(&name.to_lowercase()))
        .map(|s| s.as_ref())
        .collect();

    // relaxed 规范化各头部
    let mut signing_headers = String::new();
    for name in &h_field {
        let lower = name.to_lowercase();
        if let Some(value) = header_map.get(&lower) {
            // relaxed: 头部名小写 + 值内空白折叠
            signing_headers.push_str(&format!("{}:{}\r\n", lower, relax_header_value(value)));
        }
    }

    // 5. 构造 DKIM-Signature 头（b= 为空，用于参与签名计算）
    let now = chrono::Utc::now().timestamp();
    let h_list = h_field.join(":");
    // 注意：i=@domain 表示签名身份
    let dkim_hdr_value = format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; i=@{}; bh={}; b=",
        domain, selector, now, h_list, domain, body_hash
    );

    // 6. 拼接待签名数据：规范化的头部们 + DKIM-Signature 头本身（不含 CRLF 尾部）
    let signing_data = format!("{}dkim-signature:{}", signing_headers, dkim_hdr_value);

    // 7. RSA-SHA256 签名
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_data.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    // 8. 替换 b= 空值为实际签名
    let final_value = format!("{}{}", dkim_hdr_value, signature_b64);
    Ok(final_value)
}

/// RFC 6376 relaxed body 规范化：
/// - 去除行尾空白
/// - 不以 CRLF 结尾的加上
/// - 多个连续空行压缩为一个
/// - 最终结果以单个 CRLF 结尾
fn relax_body(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let trimmed = line.trim_end_matches([' ', '\t']);
        out.push_str(trimmed);
        out.push_str("\r\n");
    }
    // 压缩尾部空行：RFC 6376 要求忽略 body 末尾的空行
    while out.ends_with("\r\n\r\n") {
        out.truncate(out.len() - 2);
    }
    out
}

/// RFC 6376 relaxed header value 规范化：
/// - 多个连续空白（含内部）折叠为单个空格
/// - 去除首尾空白
fn relax_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_ws = false;
    for ch in value.chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_ws {
                out.push(' ');
            }
            prev_ws = true;
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

/// 简单解析 headers（支持多行续行），返回 lower_name -> value
fn parse_headers(header_block: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();

    for line in header_block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        // 续行：以空格或 tab 开头
        if line.starts_with(' ') || line.starts_with('\t') {
            current_value.push(' ');
            current_value.push_str(line.trim());
        } else {
            // 新 header：保存上一个
            if let Some(name) = current_name.take() {
                map.entry(name).or_insert(current_value.clone());
                current_value.clear();
            }
            if let Some(pos) = line.find(':') {
                current_name = Some(line[..pos].to_lowercase());
                current_value = line[pos + 1..].trim().to_string();
            }
        }
    }
    // 最后一个
    if let Some(name) = current_name {
        map.entry(name).or_insert(current_value);
    }
    map
}

/// 解析 PEM 格式的 RSA 私钥（PKCS#8 优先，回退 PKCS#1）
fn parse_rsa_private_key(pem: &str) -> anyhow::Result<rsa::RsaPrivateKey> {
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
        return Ok(key);
    }
    anyhow::bail!("无法解析 RSA 私钥 PEM（不支持此格式）")
}
