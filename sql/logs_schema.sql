-- FunMail 日志数据库 Schema
-- 独立数据库存储邮件日志和系统指标

-- 系统指标
CREATE TABLE IF NOT EXISTS system_metrics (
    id BIGSERIAL PRIMARY KEY,
    cpu_usage REAL NOT NULL,
    memory_used_gb DOUBLE PRECISION NOT NULL,
    memory_total_gb DOUBLE PRECISION NOT NULL,
    net_rx_mbps DOUBLE PRECISION NOT NULL DEFAULT 0,
    net_tx_mbps DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- 邮件指标
    queue_pending INTEGER NOT NULL DEFAULT 0,
    queue_deferred INTEGER NOT NULL DEFAULT 0,
    smtp_connections INTEGER NOT NULL DEFAULT 0,
    pop3_connections INTEGER NOT NULL DEFAULT 0,
    imap_connections INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_metrics_created ON system_metrics(created_at);

-- 系统日志
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGSERIAL PRIMARY KEY,
    level VARCHAR(10) NOT NULL,
    message TEXT NOT NULL,
    module VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
