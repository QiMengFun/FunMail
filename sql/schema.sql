-- FunMail 数据库 Schema
-- 邮件服务器核心表结构

-- 管理员用户
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin',
    enabled BOOLEAN DEFAULT TRUE,
    permissions JSONB NOT NULL DEFAULT '{
        "domains": true,
        "mailboxes": true,
        "certs": true,
        "logs": true,
        "queue": true,
        "settings": true,
        "security": true
    }',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 邮件域名
CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT TRUE,
    -- DKIM 配置
    dkim_selector VARCHAR(100) DEFAULT 'funmail',
    dkim_private_key TEXT,
    dkim_public_key TEXT,
    -- DNS 验证状态
    mx_verified BOOLEAN DEFAULT FALSE,
    spf_verified BOOLEAN DEFAULT FALSE,
    dkim_verified BOOLEAN DEFAULT FALSE,
    dmarc_verified BOOLEAN DEFAULT FALSE,
    -- 证书
    cert_id INTEGER,
    -- 默认配额
    default_quota_mb INTEGER DEFAULT 1024,
    -- 注册策略（JSONB，最大限度自定义）
    -- 推荐键：enabled, default_quota_mb, allow_smtp, allow_pop3, allow_imap, allow_imap_idle, ...
    register_config JSONB DEFAULT '{"enabled": false, "default_quota_mb": 1024, "allow_smtp": true, "allow_pop3": true, "allow_imap": true, "allow_forward": false, "max_aliases": 1, "max_forwarders": 1, "max_mail_per_day": 100, "captcha_required": true}'::jsonb,
    -- 备注
    notes TEXT,
    -- 设置是否完成（DNS验证+证书申请）
    setup_completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 邮箱账号
CREATE TABLE IF NOT EXISTS mailboxes (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    username VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- 存储
    quota_mb INTEGER DEFAULT 1024,
    used_bytes BIGINT DEFAULT 0,
    -- 状态
    enabled BOOLEAN DEFAULT TRUE,
    -- 别名（逗号分隔）
    aliases JSONB DEFAULT '[]',
    -- 转发地址（逗号分隔）
    forward_to JSONB DEFAULT '[]',
    -- 是否保留转发副本
    keep_copy BOOLEAN DEFAULT TRUE,
    -- 是否是管理员
    is_admin BOOLEAN DEFAULT FALSE,
    -- 是否自助注册（true 则受 domain.register_config 限制）
    is_self_registered BOOLEAN DEFAULT FALSE,
    -- 协议权限（管理员可单独覆盖此邮箱的协议开关）
    -- 键：smtp, pop3, imap, forward, allow_webmail
    -- 留空 JSON null 表示 "继承域名策略"；存对象表示 "覆盖"
    protocols JSONB DEFAULT NULL,
    -- token 版本号：每次修改密码/禁用/删除时递增，使旧 JWT 失效
    token_version INTEGER DEFAULT 0,
    -- 每日发件数限制（0 = 继承域名默认值）
    max_mail_per_day INTEGER DEFAULT 0,
    -- 单封发送邮件大小上限 MB（0 = 继承全局配置）
    max_send_size_mb INTEGER DEFAULT 0,
    -- 单封接收邮件大小上限 MB（0 = 继承全局配置）
    max_receive_size_mb INTEGER DEFAULT 0,
    -- 最大别名数（0 = 继承域名默认值）
    max_aliases INTEGER DEFAULT 0,
    -- 最大转发数（0 = 继承域名默认值）
    max_forwarders INTEGER DEFAULT 0,
    -- 最后登录
    last_login_at TIMESTAMPTZ,
    last_login_ip VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(domain_id, username)
);

-- 邮件投递队列表
CREATE TABLE IF NOT EXISTS mail_queue (
    id BIGSERIAL PRIMARY KEY,
    -- 发件人/收件人
    from_addr VARCHAR(320) NOT NULL,
    to_addr VARCHAR(320) NOT NULL,
    -- 邮件内容
    data_path TEXT NOT NULL,
    message_id VARCHAR(512),
    subject TEXT,
    -- 队列状态
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- pending: 待投递
    -- delivering: 投递中
    -- deferred: 延迟重试
    -- bounced: 投递失败
    -- delivered: 已投递
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    last_error TEXT,
    -- 方向
    direction VARCHAR(10) NOT NULL DEFAULT 'inbound',
    -- inbound: 入站  outbound: 出站
    -- 优先级
    priority INTEGER DEFAULT 0,
    -- 大小
    size_bytes BIGINT DEFAULT 0,
    -- 安全
    spam_score REAL DEFAULT 0,
    virus_scanned BOOLEAN DEFAULT FALSE,
    dkim_valid BOOLEAN,
    spf_valid BOOLEAN,
    dmarc_valid BOOLEAN,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_queue_status ON mail_queue(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_mail_queue_to ON mail_queue(to_addr);
CREATE INDEX IF NOT EXISTS idx_mail_queue_from ON mail_queue(from_addr);
CREATE INDEX IF NOT EXISTS idx_mail_queue_created ON mail_queue(created_at);

-- 邮件日志
CREATE TABLE IF NOT EXISTS mail_logs (
    id BIGSERIAL,
    domain_id INTEGER,
    -- 地址
    from_addr VARCHAR(320) NOT NULL,
    to_addr VARCHAR(320) NOT NULL,
    -- 邮件信息
    message_id VARCHAR(512),
    subject TEXT,
    -- 投递信息
    direction VARCHAR(10) NOT NULL DEFAULT 'inbound',
    status VARCHAR(20) NOT NULL DEFAULT 'delivered',
    size_bytes BIGINT DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    -- 安全
    spam_score REAL DEFAULT 0,
    dkim_valid BOOLEAN,
    spf_valid BOOLEAN,
    dmarc_valid BOOLEAN,
    -- 客户端信息
    client_ip VARCHAR(45),
    client_hostname VARCHAR(255),
    -- 拒绝原因
    reject_reason VARCHAR(255),
    -- 已读标记（webmail 收件箱用）
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- 邮件日志按月分区（由应用自动创建）
CREATE TABLE IF NOT EXISTS mail_logs_y2026m06 PARTITION OF mail_logs FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS mail_logs_y2026m07 PARTITION OF mail_logs FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS mail_logs_y2026m08 PARTITION OF mail_logs FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE INDEX IF NOT EXISTS idx_mail_logs_domain ON mail_logs(domain_id);
CREATE INDEX IF NOT EXISTS idx_mail_logs_from ON mail_logs(from_addr);
CREATE INDEX IF NOT EXISTS idx_mail_logs_to ON mail_logs(to_addr);
CREATE INDEX IF NOT EXISTS idx_mail_logs_status ON mail_logs(status);
CREATE INDEX IF NOT EXISTS idx_mail_logs_created ON mail_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_mail_logs_direction ON mail_logs(direction);

-- 兼容旧库：补充 is_read 字段
ALTER TABLE mail_logs ADD COLUMN IF NOT EXISTS is_read BOOLEAN NOT NULL DEFAULT FALSE;
-- 补充 data_path 字段（用于查看邮件原文）
ALTER TABLE mail_logs ADD COLUMN IF NOT EXISTS data_path TEXT;

-- 补充 token_version 字段（用于使旧 JWT 失效）
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0;

-- 补充 admin_users.token_version 字段（管理员改密码/禁用后旧 JWT 立即失效）
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0;

-- 补充 mailboxes 限制字段（升级兼容）
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS max_mail_per_day INTEGER DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS max_send_size_mb INTEGER DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS max_receive_size_mb INTEGER DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS max_aliases INTEGER DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS max_forwarders INTEGER DEFAULT 0;

-- 每小时统计
CREATE TABLE IF NOT EXISTS hourly_stats (
    domain_id INTEGER NOT NULL,
    stat_time TIMESTAMPTZ NOT NULL,
    total_inbound BIGINT DEFAULT 0,
    total_outbound BIGINT DEFAULT 0,
    total_blocked BIGINT DEFAULT 0,
    total_spam BIGINT DEFAULT 0,
    total_bounced BIGINT DEFAULT 0,
    avg_latency REAL DEFAULT 0,
    top_senders JSONB,
    top_recipients JSONB,
    PRIMARY KEY (domain_id, stat_time)
);

CREATE INDEX IF NOT EXISTS idx_hourly_stats_time ON hourly_stats(stat_time);

-- 证书
CREATE TABLE IF NOT EXISTS certs (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    issuer VARCHAR(100),
    expires_at TIMESTAMPTZ NOT NULL,
    auto_renew BOOLEAN DEFAULT TRUE,
    acme_order_url TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certs_domain ON certs(domain);
CREATE INDEX IF NOT EXISTS idx_certs_expires ON certs(expires_at);

-- ACME 验证
CREATE TABLE IF NOT EXISTS acme_challenges (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    token TEXT NOT NULL,
    key_auth TEXT NOT NULL,
    challenge_type VARCHAR(20) DEFAULT 'http-01',
    validated BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 黑白名单
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(255),
    expire_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_blacklist_ip ON ip_blacklist(ip_address);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(255),
    expire_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_whitelist_ip ON ip_whitelist(ip_address);

-- 发件人黑白名单
CREATE TABLE IF NOT EXISTS sender_blacklist (
    id SERIAL PRIMARY KEY,
    address VARCHAR(320) NOT NULL,
    reason VARCHAR(255),
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    expire_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sender_blacklist_address ON sender_blacklist(address);

CREATE TABLE IF NOT EXISTS sender_whitelist (
    id SERIAL PRIMARY KEY,
    address VARCHAR(320) NOT NULL,
    reason VARCHAR(255),
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    expire_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sender_whitelist_address ON sender_whitelist(address);

-- 全局设置
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 操作审计日志
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL DEFAULT 'admin',
    action VARCHAR(50) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id INTEGER,
    detail TEXT NOT NULL,
    client_ip VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- 域名索引
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name);
CREATE INDEX IF NOT EXISTS idx_domains_enabled ON domains(enabled);
CREATE INDEX IF NOT EXISTS idx_mailboxes_domain ON mailboxes(domain_id);
CREATE INDEX IF NOT EXISTS idx_mailboxes_username ON mailboxes(username);

-- 大小写不敏感的唯一约束：防止 Tsa123 和 tsa123 同时注册
CREATE UNIQUE INDEX IF NOT EXISTS idx_mailboxes_domain_username_ci
    ON mailboxes (domain_id, LOWER(username));

-- JSONB 字段 GIN 索引（用于按 register_config / protocols 内部键值查询 / 表达式索引兼容 pg 12+）
-- 使用默认 ops 类（jsonb_ops）兼容所有 PG 9.4+
CREATE INDEX IF NOT EXISTS idx_domains_register_config_gin
    ON domains USING GIN (register_config);
CREATE INDEX IF NOT EXISTS idx_mailboxes_protocols_gin
    ON mailboxes USING GIN (protocols);
-- 表达式索引：让"按协议策略查询"也能用上索引（如查找所有 allow_smtp=false 的域名）
CREATE INDEX IF NOT EXISTS idx_domains_register_smtp_off
    ON domains ((register_config->>'allow_smtp'))
    WHERE register_config->>'allow_smtp' = 'false';

-- ============ 联系人表 ============
CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name VARCHAR(128),
    email VARCHAR(255) NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(mailbox_id, email)
);
CREATE INDEX IF NOT EXISTS idx_contacts_mailbox ON contacts(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email_lower ON contacts(LOWER(email));

-- 全文搜索：为 mail_logs 添加 GIN 索引（subject + from_addr + to_addr）
CREATE INDEX IF NOT EXISTS idx_mail_logs_search_fts
    ON mail_logs USING GIN (to_tsvector('simple', coalesce(subject, '') || ' ' || from_addr || ' ' || to_addr));
