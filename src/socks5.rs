use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn, debug};

use crate::pool::IpPool;
use crate::{AuthConfig, BypassList};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERPASS_AUTH: u8 = 0x02;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_FAILURE: u8 = 0x01;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;

pub struct Socks5Server {
    pool: Arc<IpPool>,
    bypass: BypassList,
    auth: AuthConfig,
}

impl Socks5Server {
    pub fn new(pool: Arc<IpPool>, bypass: BypassList, auth: AuthConfig) -> Self {
        Self { pool, bypass, auth }
    }

    pub async fn start(&self, port: u16) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            let pool = self.pool.clone();
            let bypass = self.bypass.clone();
            let auth = self.auth.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, addr, pool, bypass, auth, port).await {
                    debug!("Client {} disconnected: {}", addr, e);
                }
            });
        }
    }

    /// 判断目标是否在白名单中（精确匹配域名）
    fn is_bypass(dest_addr: &str, bypass: &std::collections::HashSet<String>) -> bool {
        // 域名精确匹配
        if bypass.contains(dest_addr) {
            return true;
        }
        // 如果目标是 IP，也检查是否在白名单中
        false
    }

    async fn handle_client(
        mut stream: TcpStream,
        addr: SocketAddr,
        pool: Arc<IpPool>,
        bypass: BypassList,
        auth: AuthConfig,
        local_port: u16,
    ) -> anyhow::Result<()> {
        debug!("New connection from {}", addr);

        // Read SOCKS5 greeting
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            anyhow::bail!("Unsupported SOCKS version: {}", buf[0]);
        }

        // Read client methods
        let nmethods = buf[1];
        let mut methods = vec![0u8; nmethods as usize];
        stream.read_exact(&mut methods).await?;

        if auth.is_required() {
            // 要求认证：客户端必须支持 USERPASS
            if !methods.contains(&SOCKS5_USERPASS_AUTH) {
                // 客户端不支持用户名密码认证，回复 0xFF（无可接受方法）
                stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
                anyhow::bail!("Client does not support username/password auth");
            }
            // 选择 USERPASS
            stream.write_all(&[SOCKS5_VERSION, SOCKS5_USERPASS_AUTH]).await?;

            // 读取认证请求: VER ULEN USER PLEN PASS
            let mut auth_ver = [0u8; 1];
            stream.read_exact(&mut auth_ver).await?;
            if auth_ver[0] != 0x01 {
                anyhow::bail!("Unsupported auth version: {}", auth_ver[0]);
            }

            let mut ulen = [0u8; 1];
            stream.read_exact(&mut ulen).await?;
            let mut username = vec![0u8; ulen[0] as usize];
            stream.read_exact(&mut username).await?;

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut password = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut password).await?;

            let username = String::from_utf8(username).unwrap_or_default();
            let password = String::from_utf8(password).unwrap_or_default();

            if username != auth.username || password != auth.password {
                // 认证失败
                stream.write_all(&[0x01, 0x01]).await?;
                anyhow::bail!("Auth failed for user: {}", username);
            }

            // 认证成功
            stream.write_all(&[0x01, 0x00]).await?;
            debug!("Auth success for user: {}", username);
        } else {
            // 不需要认证
            stream.write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH]).await?;
        }

        // Read request
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;

        if header[0] != SOCKS5_VERSION {
            anyhow::bail!("Invalid SOCKS5 request version");
        }

        if header[1] != SOCKS5_CMD_CONNECT {
            Self::send_reply(&mut stream, SOCKS5_REP_FAILURE).await?;
            anyhow::bail!("Unsupported command: {}", header[1]);
        }

        // Parse address
        let (dest_addr, dest_port) = match header[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf).await?;
                let ip = std::net::Ipv4Addr::from(addr_buf);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain)?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                (domain, port)
            }
            _ => {
                Self::send_reply(&mut stream, SOCKS5_REP_FAILURE).await?;
                anyhow::bail!("Unsupported address type: {}", header[3]);
            }
        };

        debug!("SOCKS5 request to {}:{}", dest_addr, dest_port);

        // 检查是否在白名单中，是则直连
        let bp = bypass.read().await;
        let should_bypass = Self::is_bypass(&dest_addr, &bp);
        drop(bp);

        if should_bypass {
            debug!("Bypass: {}:{} — connecting directly", dest_addr, dest_port);
            let target = format!("{}:{}", dest_addr, dest_port);
            let mut direct = match TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    Self::send_reply(&mut stream, SOCKS5_REP_HOST_UNREACHABLE).await?;
                    anyhow::bail!("Direct connect to {} failed: {}", target, e);
                }
            };
            Self::send_reply(&mut stream, SOCKS5_REP_SUCCESS).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut direct).await?;
            return Ok(());
        }

        // 走上游代理
        let upstream_addr = match pool.get_proxy_address(local_port).await {
            Some(addr) => addr,
            None => {
                Self::send_reply(&mut stream, SOCKS5_REP_HOST_UNREACHABLE).await?;
                anyhow::bail!("No proxy available for port {}", local_port);
            }
        };

        // Mark port as used
        pool.mark_used(local_port).await;

        // Connect to upstream proxy
        let mut upstream = match TcpStream::connect(&upstream_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                Self::send_reply(&mut stream, SOCKS5_REP_HOST_UNREACHABLE).await?;
                anyhow::bail!("Upstream connection failed: {}", e);
            }
        };

        // Perform SOCKS5 handshake with upstream
        if let Err(e) = Self::upstream_handshake(
            &mut upstream,
            &dest_addr,
            dest_port,
            pool.proxy_username(),
            pool.proxy_password(),
        ).await {
            warn!("Upstream handshake failed for {}:{}: {}", dest_addr, dest_port, e);
            Self::send_reply(&mut stream, SOCKS5_REP_HOST_UNREACHABLE).await?;
            anyhow::bail!("Upstream handshake failed: {}", e);
        }

        // Send success reply to client
        Self::send_reply(&mut stream, SOCKS5_REP_SUCCESS).await?;

        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
        Ok(())
    }

    async fn upstream_handshake(
        upstream: &mut TcpStream,
        dest_addr: &str,
        dest_port: u16,
        username: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        upstream.write_all(&[SOCKS5_VERSION, 0x02, SOCKS5_NO_AUTH, SOCKS5_USERPASS_AUTH]).await?;

        // Read response
        let mut buf = [0u8; 2];
        upstream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            anyhow::bail!("Upstream proxy version mismatch");
        }

        // If upstream requires username/password auth (RFC 1929)
        if buf[1] == SOCKS5_USERPASS_AUTH {
            if username.is_empty() {
                anyhow::bail!("Upstream requires auth but no credentials provided");
            }
            // Build username/password auth request: VER ULEN USER PLEN PASS
            let mut auth_req = vec![0x01]; // Auth version
            auth_req.push(username.len() as u8);
            auth_req.extend_from_slice(username.as_bytes());
            auth_req.push(password.len() as u8);
            auth_req.extend_from_slice(password.as_bytes());
            upstream.write_all(&auth_req).await?;

            // Read auth response: VER STATUS
            let mut auth_resp = [0u8; 2];
            upstream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                anyhow::bail!("Upstream proxy auth rejected: status={}", auth_resp[1]);
            }
            debug!("Upstream proxy auth success");
        } else if buf[1] != SOCKS5_NO_AUTH {
            anyhow::bail!("Upstream proxy unsupported auth method: {}", buf[1]);
        }

        // Build connect request
        let mut request = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00];

        // Parse address
        if let Ok(ip) = dest_addr.parse::<std::net::Ipv4Addr>() {
            request.push(SOCKS5_ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        } else {
            request.push(SOCKS5_ATYP_DOMAIN);
            let domain_bytes = dest_addr.as_bytes();
            request.push(domain_bytes.len() as u8);
            request.extend_from_slice(domain_bytes);
        }

        request.extend_from_slice(&dest_port.to_be_bytes());

        upstream.write_all(&request).await?;

        // Read response
        let mut response = [0u8; 4];
        upstream.read_exact(&mut response).await?;

        if response[1] != SOCKS5_REP_SUCCESS {
            anyhow::bail!("Upstream proxy connect failed: {}", response[1]);
        }

        // Skip bound address
        match response[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut skip = [0u8; 4 + 2]; // IPv4 + port
                upstream.read_exact(&mut skip).await?;
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                upstream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut skip = vec![0u8; len + 2]; // domain + port
                upstream.read_exact(&mut skip).await?;
            }
            _ => anyhow::bail!("Unsupported upstream bound address type"),
        }

        Ok(())
    }

    async fn send_reply(stream: &mut TcpStream, reply: u8) -> anyhow::Result<()> {
        let response = [
            SOCKS5_VERSION,
            reply,
            0x00, // RSV
            SOCKS5_ATYP_IPV4,
            0x00, 0x00, 0x00, 0x00, // BND.ADDR
            0x00, 0x00, // BND.PORT
        ];
        stream.write_all(&response).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;

    use crate::pool::IpPool;

    /// 启动一个 mock 上游 SOCKS5 echo 服务器（循环 accept）
    async fn start_mock_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    // greeting
                    let mut ver = [0u8; 2];
                    if stream.read_exact(&mut ver).await.is_err() { return; }
                    let mut methods = vec![0u8; ver[1] as usize];
                    let _ = stream.read_exact(&mut methods).await;
                    let _ = stream.write_all(&[0x05, 0x00]).await;
                    // CONNECT header
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() { return; }
                    match header[3] {
                        0x01 => { let mut skip = [0u8; 6]; let _ = stream.read_exact(&mut skip).await; }
                        0x03 => {
                            let mut len = [0u8; 1];
                            if stream.read_exact(&mut len).await.is_err() { return; }
                            let mut skip = vec![0u8; len[0] as usize + 2];
                            let _ = stream.read_exact(&mut skip).await;
                        }
                        _ => return,
                    }
                    let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await;
                    // echo
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { let _ = stream.write_all(&buf[..n]).await; }
                        }
                    }
                });
            }
        });

        (addr, handle)
    }

    /// 客户端完成 SOCKS5 握手 + CONNECT
    async fn socks5_connect(
        proxy_addr: std::net::SocketAddr,
        atyp: u8,
        addr_bytes: &[u8],
        port: u16,
    ) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        stream.write_all(&[SOCKS5_VERSION, 0x01, SOCKS5_NO_AUTH]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[0] != SOCKS5_VERSION || reply[1] != SOCKS5_NO_AUTH {
            anyhow::bail!("greeting failed: {:?}", reply);
        }
        let mut req = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, atyp];
        req.extend_from_slice(addr_bytes);
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await?;
        let mut connect_reply = [0u8; 10];
        stream.read_exact(&mut connect_reply).await?;
        if connect_reply[1] != SOCKS5_REP_SUCCESS {
            anyhow::bail!("connect failed: rep={}", connect_reply[1]);
        }
        Ok(stream)
    }

    // ===== Socks5Server 测试 =====

    #[tokio::test]
    async fn test_socks5_server_connect_ipv4_and_echo() {
        let (upstream_addr, _uh) = start_mock_upstream().await;

        let pool = Arc::new(IpPool::new(
            (20001, 20001), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        pool.set_proxy_address(20001, upstream_addr.to_string()).await;

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20001).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = socks5_connect(
            "127.0.0.1:20001".parse().unwrap(),
            SOCKS5_ATYP_IPV4, &[10, 0, 0, 1], 80,
        ).await.expect("IPv4 connect should succeed");

        stream.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        sh.abort();
    }

    #[tokio::test]
    async fn test_socks5_server_connect_domain_and_echo() {
        let (upstream_addr, _uh) = start_mock_upstream().await;

        let pool = Arc::new(IpPool::new(
            (20002, 20002), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        pool.set_proxy_address(20002, upstream_addr.to_string()).await;

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20002).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let domain = b"example.com";
        let mut addr_bytes = vec![domain.len() as u8];
        addr_bytes.extend_from_slice(domain);

        let mut stream = socks5_connect(
            "127.0.0.1:20002".parse().unwrap(),
            SOCKS5_ATYP_DOMAIN, &addr_bytes, 443,
        ).await.expect("domain connect should succeed");

        stream.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");

        sh.abort();
    }

    #[tokio::test]
    async fn test_socks5_server_no_upstream_returns_host_unreachable() {
        let pool = Arc::new(IpPool::new(
            (20003, 20003), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        // 不注入上游地址

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20003).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = TcpStream::connect("127.0.0.1:20003").await.unwrap();
        stream.write_all(&[SOCKS5_VERSION, 0x01, SOCKS5_NO_AUTH]).await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, SOCKS5_NO_AUTH]);

        let req = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4, 10,0,0,1, 0x00, 0x50];
        stream.write_all(&req).await.unwrap();

        let mut connect_reply = [0u8; 10];
        stream.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(connect_reply[1], SOCKS5_REP_HOST_UNREACHABLE);

        sh.abort();
    }

    #[tokio::test]
    async fn test_socks5_server_unsupported_version() {
        let pool = Arc::new(IpPool::new(
            (20004, 20004), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        pool.set_proxy_address(20004, "127.0.0.1:19998".to_string()).await;

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20004).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = TcpStream::connect("127.0.0.1:20004").await.unwrap();
        stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

        let mut buf = [0u8; 2];
        let result = stream.read_exact(&mut buf).await;
        assert!(result.is_err(), "服务器应关闭不支持版本的连接");

        sh.abort();
    }

    #[tokio::test]
    async fn test_socks5_server_unsupported_command_returns_failure() {
        let (upstream_addr, _uh) = start_mock_upstream().await;

        let pool = Arc::new(IpPool::new(
            (20005, 20005), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        pool.set_proxy_address(20005, upstream_addr.to_string()).await;

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20005).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = TcpStream::connect("127.0.0.1:20005").await.unwrap();
        stream.write_all(&[SOCKS5_VERSION, 0x01, SOCKS5_NO_AUTH]).await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();

        // BIND command (0x02)
        let req = vec![SOCKS5_VERSION, 0x02, 0x00, SOCKS5_ATYP_IPV4, 10,0,0,1, 0x00, 0x50];
        stream.write_all(&req).await.unwrap();

        let mut connect_reply = [0u8; 10];
        let result = stream.read_exact(&mut connect_reply).await;
        // 服务器发 FAILURE reply 后 bail 关闭连接
        // 可能读到 reply（10 字节），也可能连接直接关闭
        if result.is_ok() {
            assert_eq!(connect_reply[1], SOCKS5_REP_FAILURE);
        }
        // 如果连接直接关闭了也是正确行为（bail 导致 drop）

        sh.abort();
    }

    #[tokio::test]
    async fn test_socks5_server_unsupported_atyp_returns_failure() {
        let (upstream_addr, _uh) = start_mock_upstream().await;

        let pool = Arc::new(IpPool::new(
            (20006, 20006), "http://127.0.0.1:1/x".to_string(), 60, 60,
            String::new(), String::new(),
        ));
        pool.set_proxy_address(20006, upstream_addr.to_string()).await;

        let sp = pool.clone();
        let sh = tokio::spawn(async move {
            Socks5Server::new(sp, Arc::new(RwLock::new(std::collections::HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(20006).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = TcpStream::connect("127.0.0.1:20006").await.unwrap();
        stream.write_all(&[SOCKS5_VERSION, 0x01, SOCKS5_NO_AUTH]).await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();

        // IPv6 (0x04) 不支持
        let req = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, 0x04];
        stream.write_all(&req).await.unwrap();

        let mut connect_reply = [0u8; 10];
        let result = stream.read_exact(&mut connect_reply).await;
        if result.is_ok() {
            assert_eq!(connect_reply[1], SOCKS5_REP_FAILURE);
        }

        sh.abort();
    }

    // ===== Constants 测试 =====

    #[test]
    fn test_protocol_constants() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(SOCKS5_NO_AUTH, 0x00);
        assert_eq!(SOCKS5_CMD_CONNECT, 0x01);
        assert_eq!(SOCKS5_ATYP_IPV4, 0x01);
        assert_eq!(SOCKS5_ATYP_DOMAIN, 0x03);
        assert_eq!(SOCKS5_REP_SUCCESS, 0x00);
        assert_eq!(SOCKS5_REP_FAILURE, 0x01);
        assert_eq!(SOCKS5_REP_HOST_UNREACHABLE, 0x04);
    }
}