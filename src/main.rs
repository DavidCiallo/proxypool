use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::RwLock;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use ip_proxy_pool::http::HttpProxyServer;
use ip_proxy_pool::pool::IpPool;
use ip_proxy_pool::socks5::Socks5Server;
use ip_proxy_pool::{AuthConfig, BypassList};

#[derive(Parser, Debug)]
#[command(name = "ip-proxy-pool", about = "SOCKS5/HTTP proxy pool with auto IP rotation")]
struct Args {
    /// 起始端口
    #[arg(long, default_value = "10000")]
    port_start: u16,

    /// 结束端口
    #[arg(long, default_value = "10029")]
    port_end: u16,

    /// IP 获取 API URL（或设置 FETCH_URL 环境变量）
    #[arg(long)]
    fetch_url: Option<String>,

    /// 上游代理用户名（或设置 PROXY_USERNAME 环境变量）
    #[arg(long)]
    proxy_username: Option<String>,

    /// 上游代理密码（或设置 PROXY_PASSWORD 环境变量）
    #[arg(long)]
    proxy_password: Option<String>,

    /// 管理接口端口（HTTP，用于添加/删除白名单）
    #[arg(long, default_value = "9999")]
    admin_port: u16,

    /// 初始白名单域名，逗号分隔
    #[arg(long, value_delimiter = ',')]
    bypass: Vec<String>,

    /// 本地代理用户名（或设置 LOCAL_USERNAME 环境变量）
    #[arg(long)]
    local_username: Option<String>,

    /// 本地代理密码（或设置 LOCAL_PASSWORD 环境变量）
    #[arg(long)]
    local_password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // 从 CLI 参数或环境变量读取敏感配置
    let fetch_url = args.fetch_url
        .or_else(|| std::env::var("FETCH_URL").ok())
        .expect("FETCH_URL is required (set env var or use --fetch-url)");

    let proxy_username = args.proxy_username
        .or_else(|| std::env::var("PROXY_USERNAME").ok())
        .expect("PROXY_USERNAME is required (set env var or use --proxy-username)");

    let proxy_password = args.proxy_password
        .or_else(|| std::env::var("PROXY_PASSWORD").ok())
        .expect("PROXY_PASSWORD is required (set env var or use --proxy-password)");

    let local_username = args.local_username
        .or_else(|| std::env::var("LOCAL_USERNAME").ok())
        .unwrap_or_default();

    let local_password = args.local_password
        .or_else(|| std::env::var("LOCAL_PASSWORD").ok())
        .unwrap_or_default();

    let auth = AuthConfig {
        username: local_username,
        password: local_password,
    };

    if auth.is_required() {
        info!("Local proxy auth enabled: username={}", auth.username);
    } else {
        info!("Local proxy auth disabled (no LOCAL_USERNAME set)");
    }

    info!("Starting IP Proxy Pool");

    // 创建白名单
    let bypass: BypassList = Arc::new(RwLock::new(HashSet::new()));
    {
        let mut bp = bypass.write().await;
        for domain in &args.bypass {
            info!("Initial bypass domain: {}", domain);
            bp.insert(domain.clone());
        }
    }

    let pool = Arc::new(IpPool::new(
        (args.port_start, args.port_end),
        fetch_url,
        0,
        0,
        proxy_username,
        proxy_password,
    ));

    pool.start().await?;

    let mut handles = Vec::new();

    // 启动管理接口
    let admin_bypass = bypass.clone();
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = start_admin_server(args.admin_port, admin_bypass).await {
            error!("Admin server failed: {}", e);
        }
    });
    handles.push(admin_handle);

    for port in args.port_start..=args.port_end {
        // SOCKS5 on each port
        let socks_server = Socks5Server::new(pool.clone(), bypass.clone(), auth.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = socks_server.start(port).await {
                error!("SOCKS5 server on port {} failed: {}", port, e);
            }
        });
        handles.push(handle);

        // HTTP on each port + 1000
        let http_port = port + 1000;
        let http_server = HttpProxyServer::new(pool.clone(), bypass.clone(), auth.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = http_server.start(http_port, port).await {
                error!("HTTP server on port {} failed: {}", http_port, e);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}

/// 管理接口：HTTP 服务，提供白名单增删查
///
/// GET  /bypass          — 查看当前白名单
/// POST /bypass/{domain} — 添加白名单域名
/// DELETE /bypass/{domain} — 删除白名单域名
async fn start_admin_server(port: u16, bypass: BypassList) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Admin API listening on port {}", port);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let bypass = bypass.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return;
            }

            let method = parts[0];
            let path = parts[1];

            let response = if path == "/bypass" && method == "GET" {
                // 查看白名单
                let bp = bypass.read().await;
                let list: Vec<&str> = bp.iter().map(|s| s.as_str()).collect();
                let body = serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string());
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
            } else if path.starts_with("/bypass/") && method == "POST" {
                // 添加白名单
                let domain = &path[7..]; // skip "/bypass/"
                if domain.is_empty() {
                    "HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"empty domain\"}".to_string()
                } else {
                    let mut bp = bypass.write().await;
                    bp.insert(domain.to_string());
                    info!("Bypass added: {}", domain);
                    let body = format!("{{\"added\":\"{}\"}}", domain);
                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
                }
            } else if path.starts_with("/bypass/") && method == "DELETE" {
                // 删除白名单
                let domain = &path[7..];
                let mut bp = bypass.write().await;
                let removed = bp.remove(domain);
                if removed {
                    info!("Bypass removed: {}", domain);
                }
                let body = format!("{{\"removed\":{}}}", removed);
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
            } else {
                "HTTP/1.1 404 Not Found\r\n\r\n".to_string()
            };

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}
