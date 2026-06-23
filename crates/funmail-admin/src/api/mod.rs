pub mod auth_routes;
pub mod domain_routes;
pub mod mailbox_routes;
pub mod cert_routes;
pub mod queue_routes;
pub mod log_routes;
pub mod stats_routes;
pub mod settings_routes;
pub mod user_routes;
pub mod system_routes;
pub mod mail_routes;
pub mod webmail_routes;
pub mod contacts_routes;

use crate::state::AppState;
use axum::Router;
use axum::body::Body;
use axum::extract::{State, Path};
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

/// ACME HTTP-01 挑战验证处理
/// Let's Encrypt 会访问 http://domain/.well-known/acme-challenge/{token}
async fn acme_challenge_handler(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    req: axum::http::Request<Body>,
) -> impl IntoResponse {
    let client_ip = req.headers().get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    tracing::info!("ACME 挑战请求: token={}, 客户端IP近似={}", token, client_ip);
    match crate::acme::get_challenge_response(&state.pool, &token).await {
        Some(key_auth) => {
            tracing::info!("ACME 挑战响应成功: token={}, key_auth长度={}", token, key_auth.len());
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], key_auth)
        }
        None => {
            tracing::warn!("ACME 挑战未找到: token={}", token);
            (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain")], String::new())
        }
    }
}

/// 80 端口连通性测试
async fn test_handler() -> impl IntoResponse {
    tracing::info!("ACME: 80端口连通性测试请求");
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "您通过80端口成功访问FunMail")
}

/// 创建 ACME 挑战路由（无 fallback，用于 merge 到主 router，不能带 fallback 否则会吃掉静态文件请求）
fn acme_challenge_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", axum::routing::get(acme_challenge_handler))
        .route("/.well-known/acme-challenge/test", axum::routing::get(test_handler))
        .with_state(state)
}

/// 80 端口 HTTP → HTTPS / mail.* 跳转
///   - 命中 `/.well-known/acme-challenge/*` → ACME handler（不动）
///   - `mail.*` 主机名 → 不跳转，继续走 webmail
///   - 其他主机名 → 301 跳到 https://mail.{host}{path}
async fn port80_redirect(
    headers: axum::http::HeaderMap,
    uri: Uri,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let hostname = host.split(':').next().unwrap_or(host);
    let path_q = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // ACME 路径一定不会到这里（被 .route() 优先匹配）
    // mail.* 主机名直通：80 端口虽没 webmail 内容，但保持 404 而非重定向死循环
    if hostname.starts_with("mail.") {
        return (StatusCode::NOT_FOUND, "use https").into_response();
    }

    // IP 地址直接访问：拼出 mail.<ip> 不是合法域名，Chrome 会报 ERR_INVALID_REDIRECT。
    // 这里返回 404 避免循环重定向，用户应通过域名 + 443 访问。
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        tracing::info!("80 端口 IP 直接访问: {}，返回 404", host);
        return (StatusCode::NOT_FOUND, "use https via domain").into_response();
    }

    let target = format!("https://mail.{}{}", hostname, path_q);
    tracing::info!("HTTP→HTTPS 跳转: {} → {}", host, target);
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, target)
        .body(Body::empty())
        .unwrap()
        .into_response()
}

/// 创建 80 端口专用路由器（包含 ACME 测试端点 + 非 ACME 路径跳转）
pub fn acme_80_port_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", axum::routing::get(acme_challenge_handler))
        .route("/.well-known/acme-challenge/test", axum::routing::get(test_handler))
        // 其余所有路径（含 /）→ port80_redirect 处理
        .fallback(port80_redirect)
        .with_state(state)
}

static MIME_TYPES: &[(&str, &str)] = &[
    (".html", "text/html"),
    (".js", "application/javascript"),
    (".css", "text/css"),
    (".json", "application/json"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".svg", "image/svg+xml"),
    (".ico", "image/x-icon"),
    (".woff", "font/woff"),
    (".woff2", "font/woff2"),
    (".ttf", "font/ttf"),
];

/// 从内存缓存提供静态文件，未命中则读磁盘并缓存
async fn serve_cached_file(
    cache: &Arc<RwLock<HashMap<String, (&'static str, Vec<u8>)>>>,
    base_dir: &str,
    path: &str,
) -> Option<Response> {
    // 先查缓存
    {
        let cache_read = cache.read().await;
        if let Some((ct, data)) = cache_read.get(path) {
            return Some(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", *ct)
                .header("cache-control", "public, max-age=86400")
                .header("content-length", data.len())
                .body(Body::from(data.clone()))
                .unwrap()
                .into_response());
        }
    }

    // 缓存未命中，读磁盘
    let file_path = std::path::Path::new(base_dir).join(path.trim_start_matches('/'));
    if let Ok(canonical) = file_path.canonicalize() {
        // 安全检查：确保解析后的路径仍在基础目录下
        let base_canonical = std::path::Path::new(base_dir).canonicalize().unwrap_or_else(|_| std::path::PathBuf::from(base_dir));
        if canonical.starts_with(&base_canonical) {
            if let Ok(data) = tokio::fs::read(&canonical).await {
                let ct = guess_content_type(path);
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", ct)
                    .header("cache-control", "public, max-age=86400")
                    .header("content-length", data.len())
                    .body(Body::from(data.clone()))
                    .unwrap()
                    .into_response();
                // 写入缓存
                cache.write().await.insert(path.to_string(), (ct, data));
                return Some(resp);
            }
        }
    }
    None
}

fn guess_content_type(path: &str) -> &'static str {
    for (ext, ct) in MIME_TYPES {
        if path.ends_with(ext) {
            return ct;
        }
    }
    "application/octet-stream"
}

pub fn create_router(state: Arc<AppState>, static_dir: &str) -> Router {

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);

    // 管理后台 API（需要 admin 认证）
    let admin_routes = Router::new()
        .merge(domain_routes::routes())
        .merge(mailbox_routes::routes())
        .merge(cert_routes::routes())
        .merge(queue_routes::routes())
        .merge(log_routes::routes())
        .merge(stats_routes::routes())
        .merge(settings_routes::routes())
        .merge(user_routes::routes())
        .merge(system_routes::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_routes::require_admin));

    // 公开 API（无需认证或自行验证 token）
    let public_routes = Router::new()
        .merge(auth_routes::routes())
        .merge(webmail_routes::routes())
        .merge(mail_routes::routes())
        .merge(contacts_routes::routes());

    let api_routes = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .layer(cors)
        .with_state(state.clone());

    let mut router = Router::new()
        .nest("/api", api_routes)
        // ACME HTTP-01 验证路由（必须在 /.well-known/acme-challenge/ 下）
        .merge(acme_challenge_routes(state.clone()));

    if std::path::Path::new(static_dir).exists() {
        let dir = static_dir.to_string();
        let index_html = match std::fs::read_to_string(
            std::path::Path::new(static_dir).join("index.html")
        ) {
            Ok(html) => html,
            Err(e) => {
                tracing::error!("读取 index.html 失败: {} (路径: {}/index.html)", e, static_dir);
                String::new()
            }
        };

        // webmail 入口（用户邮箱登录界面）
        let webmail_dir = format!("{}/webmail", static_dir);
        let webmail_dir_for_closure = webmail_dir.clone();
        let webmail_index = std::fs::read_to_string(
            std::path::Path::new(&webmail_dir).join("index.html")
        ).unwrap_or_default();

        // 静态文件内存缓存：path -> (content_type, bytes)
        let file_cache: Arc<RwLock<HashMap<String, (&'static str, Vec<u8>)>>> =
            Arc::new(RwLock::new(HashMap::new()));

        router = router
            .fallback(move |uri: Uri, host: axum::http::HeaderMap| {
                let dir = dir.clone();
                let index_html = index_html.clone();
                let webmail_dir = webmail_dir_for_closure.clone();
                let webmail_index = webmail_index.clone();
                let file_cache = file_cache.clone();
                async move {
                    let host_str = host.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
                    let is_webmail_host = host_str
                        .split(':')
                        .next()
                        .map(|h| h.starts_with("mail."))
                        .unwrap_or(false);
                    let path = uri.path();

                    // mail.* 子域名 → 提供 webmail 静态资源
                    if is_webmail_host {
                        if path.contains(".") && !path.ends_with("/") {
                            if let Some(resp) = serve_cached_file(&file_cache, &webmail_dir, path).await {
                                return resp;
                            }
                            // 有扩展名但文件不存在，返回 404（不要 fallback 到 index.html）
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        if !path.starts_with("/api/") && !webmail_index.is_empty() {
                            return Html(webmail_index).into_response();
                        }
                        return StatusCode::NOT_FOUND.into_response();
                    }

                    // 其他子域名/主域名 → admin 静态资源
                    if path.contains(".") && !path.ends_with("/") {
                        if let Some(resp) = serve_cached_file(&file_cache, &dir, path).await {
                            return resp;
                        }
                        // 有扩展名但文件不存在，返回 404（不要 fallback 到 index.html）
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    if !path.starts_with("/api/") && !index_html.is_empty() {
                        return Html(index_html).into_response();
                    }
                    StatusCode::NOT_FOUND.into_response()
                }
            });
        tracing::info!("前端静态文件目录: {}", static_dir);
    } else {
        tracing::warn!("前端静态文件目录不存在: {}，仅 API 模式运行", static_dir);
    }

    router
}
