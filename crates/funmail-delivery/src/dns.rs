use std::net::SocketAddr;

/// 创建系统配置的 DNS resolver（hickory-resolver 0.25 API）
fn make_resolver() -> anyhow::Result<hickory_resolver::TokioResolver> {
    Ok(hickory_resolver::Resolver::builder_tokio()?.build())
}

/// DNS MX 记录查询
pub async fn lookup_mx(domain: &str) -> anyhow::Result<Vec<String>> {
    let resolver = make_resolver()?;

    let mx_records = resolver.mx_lookup(domain).await?;

    let mut hosts: Vec<(u16, String)> = mx_records
        .iter()
        .map(|mx| (mx.preference(), mx.exchange().to_string().trim_end_matches('.').to_string()))
        .collect();

    // 按优先级排序
    hosts.sort_by_key(|(pref, _)| *pref);

    Ok(hosts.into_iter().map(|(_, host)| host).collect())
}

/// DNS TXT 记录查询（用于 SPF/DKIM/DMARC）
pub async fn lookup_txt(domain: &str) -> anyhow::Result<Vec<String>> {
    let resolver = make_resolver()?;
    let txt_records = resolver.txt_lookup(domain).await?;

    Ok(txt_records
        .iter()
        .map(|txt| txt.to_string())
        .collect())
}

/// DNS A 记录查询
pub async fn lookup_a(domain: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let resolver = make_resolver()?;
    let ips = resolver.ipv4_lookup(domain).await?;

    Ok(ips
        .iter()
        .map(|ip| SocketAddr::new(std::net::IpAddr::V4(**ip), 0))
        .collect())
}

/// SPF 验证
pub async fn verify_spf(domain: &str, ip: &str) -> anyhow::Result<SpfResult> {
    let txt_records = lookup_txt(domain).await?;

    for txt in &txt_records {
        if txt.starts_with("v=spf1") {
            // 简化 SPF 验证
            if txt.contains("+all") {
                return Ok(SpfResult::Pass);
            }
            if txt.contains("~all") {
                return Ok(SpfResult::SoftFail);
            }
            if txt.contains("-all") {
                return Ok(SpfResult::Fail);
            }
            if txt.contains("?all") {
                return Ok(SpfResult::Neutral);
            }
            // 包含 ip4/ip6 指令时检查
            if txt.contains(&format!("ip4:{}", ip)) || txt.contains(&format!("ip6:{}", ip)) {
                return Ok(SpfResult::Pass);
            }
        }
    }

    Ok(SpfResult::None)
}

/// DMARC 验证
pub async fn verify_dmarc(domain: &str) -> anyhow::Result<DmarcPolicy> {
    let dmarc_domain = format!("_dmarc.{}", domain);
    let txt_records = lookup_txt(&dmarc_domain).await?;

    for txt in &txt_records {
        if txt.starts_with("v=DMARC1") {
            if txt.contains("p=reject") {
                return Ok(DmarcPolicy::Reject);
            }
            if txt.contains("p=quarantine") {
                return Ok(DmarcPolicy::Quarantine);
            }
            return Ok(DmarcPolicy::None);
        }
    }

    Ok(DmarcPolicy::None)
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}
