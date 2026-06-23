<p align="center">
  <img src="frontend/src/static/images/logo.png" alt="FunMail Logo" width="120">
  <br>
  <img src="frontend/src/static/images/logo2.png" alt="FunMail" width="220">
</p>

<h1 align="center">FunMail</h1>

<p align="center">
  <strong>高性能自托管邮件服务器</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2026-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/SMTP-587%2F465-blue" alt="SMTP">
  <img src="https://img.shields.io/badge/IMAP-143%2F993-green" alt="IMAP">
  <img src="https://img.shields.io/badge/POP3-110%2F995-yellow" alt="POP3">
  <img src="https://img.shields.io/badge/DB-PostgreSQL-336791?logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

---

## FunMail 是什么？

FunMail 是一款基于 Rust 构建的全功能自托管邮件服务器，涵盖 SMTP 发信、IMAP/POP3 收信、DKIM 签名、SPF 验证、垃圾邮件过滤、病毒扫描、Let's Encrypt 证书自动申请等核心功能，并提供现代化的可视化管理控制台和 Webmail 邮件客户端，同时支持多域名多邮箱管理以及语言切换（中文、English）。

---

## 界面展示

### 仪表盘

24 小时收发信趋势、7 天流量统计、队列状态饼图，邮件数据一目了然。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail1.jpg" alt="仪表盘" width="800">

### 域名管理

多域名独立配置，DKIM 密钥自动生成，DNS 设置向导（MX / SPF / DKIM / DMARC）一键验证与证书申请。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail2.jpg" alt="域名管理" width="800">

### 邮箱管理

创建邮箱、设置配额、别名、转发、协议权限（SMTP / POP3 / IMAP / Webmail 独立开关），灵活管控。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail3.jpg" alt="邮箱管理" width="800">

### 邮件队列

查看待投递、延迟投递邮件，支持手动重试与删除。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail4.jpg" alt="邮件队列" width="800">

### 邮件日志

收发信日志实时查看，支持按方向、状态、时间范围过滤与全文检索。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail5.jpg" alt="邮件日志" width="800">

### 证书管理

自动申请 Let's Encrypt 证书（ACME HTTP-01），支持手动上传，一键续签。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail6.jpg" alt="证书管理" width="800">

### 系统设置

安全配置（垃圾邮件过滤、RBL 黑名单、病毒扫描）、投递配置、SMTP 大小限制、Webmail 限流、时区与语言，一站式管理。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail7.jpg" alt="系统设置" width="800">

### 账号管理

管理员 / 只读用户，细粒度权限控制。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail8.jpg" alt="账号管理" width="800">

### Webmail 邮件客户端

内置 Webmail，用户可直接通过浏览器收发邮件，支持自助注册与验证码。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail9.jpg" alt="Webmail" width="800">

### 深色模式

管理控制台与 Webmail 均完整支持深色主题。

<img src="https://cdn.quqimeng.com/static/images/screenshot/FunMail10.jpg" alt="深色模式" width="800">

---

## 核心特性

### 邮件协议

| 能力 | 说明 |
|------|------|
| **SMTP** | 完整 SMTP 服务，支持端口 25/587/465，STARTTLS 与 SMTPS |
| **IMAP** | IMAP4rev1 服务，支持端口 143/993 |
| **POP3** | POP3 服务，支持端口 110/995 |
| **Submission** | 587 端口认证发信，SASL PLAIN/LOGIN 认证 |
| **TLS** | 全链路 TLS 加密，STARTTLS 自动升级 |

### 安全与反垃圾

| 能力 | 说明 |
|------|------|
| **DKIM 签名** | RSA-SHA256 签名（RFC 6376 relaxed 规范化），自动生成密钥对 |
| **SPF 验证** | 发件人 SPF 记录验证 |
| **DMARC** | DMARC 策略检查 |
| **垃圾邮件过滤** | SpamAssassin 兼容评分，可调阈值，支持标记/拒绝 |
| **RBL 黑名单** | 多源实时黑名单查询（Spamhaus、SpamCop 等，可自定义添加） |
| **病毒扫描** | ClamAV 集成，支持 TCP/Unix Socket 模式，可配置拒绝/标记 |
| **Webmail 限流** | 登录与注册频率限制，防止暴力破解 |

### 证书与域名

- **Let's Encrypt 自动申请**：ACME HTTP-01 验证，一键申请 SSL 证书
- **自动续签**：证书到期前自动续签
- **DNS 设置向导**：MX / SPF / DKIM / DMARC 记录自动生成，分步验证
- **多域名支持**：独立域名配置，独立 DKIM 密钥与配额

### 管理与运维

- **可视化管理控制台**：现代化 Web UI，深色/浅色主题
- **邮件统计仪表盘**：24 小时收发趋势、7 天流量统计、队列状态、收发信计数
- **系统信息**：CPU / 内存使用率、服务运行状态、系统运行时间
- **邮件日志**：收发信日志 + 系统日志，支持全文检索与多维度过滤
- **邮箱管理**：配额、别名、转发、协议权限精细控制
- **账号管理**：管理员 / 只读用户，细粒度权限
- **自助注册**：可按域名开启用户自助注册，支持验证码
- **Webmail**：内置邮件客户端，用户可直接浏览器收发邮件
- **国际化**：中文 / 英文双语支持
- **时区配置**：支持全球常用时区

---

## 组件说明

| 组件 | 说明 |
|------|------|
| `funmail-smtp` | SMTP 服务，处理邮件接收与认证发信，支持 STARTTLS 升级 |
| `funmail-imap` | IMAP 服务，提供邮件读取与文件夹管理 |
| `funmail-pop3` | POP3 服务，提供邮件下载 |
| `funmail-delivery` | 投递引擎，本地投递 + 远程 SMTP 投递，DKIM 签名，DNS 解析 |
| `funmail-admin` | 管理后台，提供 RESTful API、Web UI、ACME 证书管理、系统指标采集 |
| `funmail-common` | 公共类型、配置、数据库、安全与 TLS 工具 |

---

## 系统架构

```
                    ┌─────────────────────────────────────────┐
                    │              FunMail 架构                 │
                    └─────────────────────────────────────────┘

  发件人 ──────▶ ┌──────────┐    ┌──────────────┐    ┌──────────────┐
                │  SMTP     │───▶│  Delivery    │───▶│  远程 MX      │
                │  :25/587  │    │  投递引擎     │    │  (外部邮件)   │
                └──────────┘    └──────────────┘    └──────────────┘
                     │                │
                     │                ▼
                     │         ┌──────────────┐
                     │         │  本地投递     │
                     │         │  Maildir 存储  │
                     │         └──────────────┘
                     │                │
                     ▼                ▼
                ┌──────────┐    ┌──────────────┐
                │  IMAP     │    │  POP3        │
                │  :143/993 │    │  :110/995    │
                └──────────┘    └──────────────┘
                     │                │
                     ▼                ▼
                ┌──────────────────────────────┐
                │         邮件客户端             │
                │   (Webmail / 第三方客户端)     │
                └──────────────────────────────┘

                ┌──────────┐    ┌──────────────┐
                │  Admin   │───▶│  PostgreSQL   │
                │  管理后台  │    │  (配置+日志)  │
                └──────────┘    └──────────────┘
                     │
                ┌──────────┐    ┌──────────────┐
                │  Web UI  │    │  ClamAV      │
                │  管理控制台│    │  病毒扫描     │
                └──────────┘    └──────────────┘
```

---

## 快速部署（Docker Compose）


方法1:
```bash
# 一键安装最新版
bash <(curl -sSL https://fun.quqimeng.com/mail/static/funmail.sh)
```


方法2:
```bash
# 克隆仓库
git clone https://github.com/QiMengFun/FunMail.git
cd FunMail

# 配置环境变量
cp docker/.env.example docker/.env
# 编辑 .env 设置密码、主机名等

# 启动所有服务
cd docker
docker compose up -d
```

Docker Compose 会自动启动以下服务：

| 服务 | 端口 | 说明 |
|------|------|------|
| `funmail-smtp` | 25, 587 | SMTP 邮件接收与发信 |
| `funmail-imap` | 143, 993 | IMAP 邮件读取 |
| `funmail-pop3` | 110, 995 | POP3 邮件下载 |
| `funmail-admin` | 80, 10002 | 管理后台 + Web UI |
| `funmail-delivery` | - | 邮件投递引擎 |
| `postgres` | 5432 | PostgreSQL 数据库 |
| `clamav` | - | ClamAV 病毒扫描 |

---

## 从源码构建

```bash
# 构建
cargo build --release

# 二进制文件位于 target/release/
# - funmail-smtp
# - funmail-imap
# - funmail-pop3
# - funmail-delivery
# - funmail-admin
```

---

## 技术栈

| 层级 | 技术 |
|------|------|
| 邮件协议 | SMTP / IMAP / POP3（纯 Rust 实现） |
| 后端框架 | Axum (Rust) |
| 数据库 | PostgreSQL 14+ |
| 前端 | Alpine.js + Tailwind CSS + ECharts |
| 证书 | Let's Encrypt (instant-acme) + rcgen |
| 病毒扫描 | ClamAV |
| 容器化 | Docker + Docker Compose |

---

## 目录结构

```
FunMail/
├── crates/
│   ├── funmail-smtp/       # SMTP 服务
│   ├── funmail-imap/       # IMAP 服务
│   ├── funmail-pop3/       # POP3 服务
│   ├── funmail-delivery/   # 投递引擎（DKIM 签名、DNS 解析）
│   ├── funmail-admin/      # 管理后台（API、Web UI、ACME、指标采集）
│   └── funmail-common/     # 公共库（配置、数据库、安全、TLS）
├── frontend/
│   ├── src/                # 管理控制台前端
│   │   ├── pages/          # 页面组件（dashboard、domains、mailboxes 等）
│   │   ├── static/images/  # Logo 等静态资源
│   │   └── vendor/         # Alpine.js、ECharts、i18n、Tailwind
│   └── webmail/            # Webmail 前端（登录、邮件列表、阅读）
├── docker/
│   ├── Dockerfile          # 多阶段构建镜像
│   └── docker-compose.yml  # 编排配置
├── sql/
│   ├── schema.sql          # 主数据库 Schema
│   └── logs_schema.sql     # 日志数据库 Schema
└── Cargo.toml              # Workspace 配置
```

---

## License

MIT
