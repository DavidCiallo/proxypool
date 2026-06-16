use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn, debug};

use crate::pool::IpPool;
use crate::BypassList;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERPASS_AUTH: u8 = 0x02;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_FAILURE: u8 = 0x01;

pub struct HttpProxyServer {
    pool: Arc<IpPool>,
    bypass: BypassList,
}

impl HttpProxyServer {
    pub fn new(pool: Arc<IpPool>, bypass: BypassList) -> Self {
        Self { pool, bypass }
    }

    pub async fn start(&self, port: u16, socks_port: u16) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            let pool = self.pool.clone();
            let bypass = self.bypass.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, addr, pool, bypass, port, socks_port).await {
                    debug!("HTTP client {} disconnected: {}", addr, e);
                }
            });
        }
    }

    fn is_bypass(host: &str, bypass: &std::collections::HashSet<String>) -> bool {
        bypass.contains(host)
    }

    async fn handle_client(
        mut stream: TcpStream,
        _addr: SocketAddr,
        pool: Arc<IpPool>,
        bypass: BypassList,
        _local_port: u16,
        socks_port: u16,
    ) -> anyhow::Result<()> {
        let mut buf_reader = BufReader::new(&mut stream);

        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await?;
        let request_line = request_line.trim_end_matches("\r\n").to_string();

        if request_line.is_empty() {
            anyhow::bail!("Empty request line");
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            anyhow::bail!("Malformed request line: {}", request_line);
        }

        let method = parts[0].to_string();
        let target = parts[1].to_string();

        if method.eq_ignore_ascii_case("CONNECT") {
            loop {
                let mut line = String::new();
                buf_reader.read_line(&mut line).await?;
                if line.trim_end_matches("\r\n").is_empty() {
                    break;
                }
            }
            drop(buf_reader);
            Self::handle_connect(stream, &target, pool, bypass, socks_port).await
        } else {
            let mut headers = Vec::new();
            let mut content_length: usize = 0;
            loop {
                let mut line = String::new();
                buf_reader.read_line(&mut line).await?;
                let trimmed = line.trim_end_matches("\r\n");
                if trimmed.is_empty() {
                    break;
                }
                if let Some(val) = trimmed.strip_prefix("Content-Length:") {
                    content_length = val.trim().parse().unwrap_or(0);
                }
                headers.push(line);
            }

            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                buf_reader.read_exact(&mut body).await?;
            }
            drop(buf_reader);

            let (reader, mut writer) = stream.into_split();
            Self::handle_http(reader, &mut writer, &method, &target, &headers, &body, pool, bypass, socks_port).await
        }
    }

    async fn handle_connect(
        mut stream: TcpStream,
        target: &str,
        pool: Arc<IpPool>,
        bypass: BypassList,
        socks_port: u16,
    ) -> anyhow::Result<()> {
        let (host, port) = parse_host_port(target, 443)?;

        // 检查白名单，直连
        let bp = bypass.read().await;
        let should_bypass = Self::is_bypass(&host, &bp);
        drop(bp);

        if should_bypass {
            debug!("HTTP CONNECT bypass: {}:{} — connecting directly", host, port);
            let target_addr = format!("{}:{}", host, port);
            let mut direct = match TcpStream::connect(&target_addr).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    anyhow::bail!("Direct connect to {} failed: {}", target_addr, e);
                }
            };
            let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
            tokio::io::copy_bidirectional(&mut stream, &mut direct).await?;
            return Ok(());
        }

        // 走上游代理
        let upstream_addr = match pool.get_proxy_address(socks_port).await {
            Some(addr) => addr,
            None => {
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                pool.mark_unavailable(socks_port).await;
                anyhow::bail!("No proxy available for port {}", socks_port);
            }
        };

        pool.mark_used(socks_port).await;

        let mut upstream = match TcpStream::connect(&upstream_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to upstream {}: {}", upstream_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                pool.mark_unavailable(socks_port).await;
                anyhow::bail!("Upstream connection failed: {}", e);
            }
        };

        Self::socks5_handshake(&mut upstream, &host, port, pool.proxy_username(), pool.proxy_password()).await?;

        let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;

        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
        Ok(())
    }

    async fn handle_http(
        _reader: OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        method: &str,
        target: &str,
        headers: &[String],
        body: &[u8],
        pool: Arc<IpPool>,
        bypass: BypassList,
        socks_port: u16,
    ) -> anyhow::Result<()> {
        let (host, port) = if let Some(rest) = target.strip_prefix("http://") {
            parse_host_port(rest, 80)?
        } else {
            parse_host_port(target, 80)?
        };

        // 检查白名单，直连
        let bp = bypass.read().await;
        let should_bypass = Self::is_bypass(&host, &bp);
        drop(bp);

        if should_bypass {
            debug!("HTTP bypass: {}:{} — connecting directly", host, port);
            let target_addr = format!("{}:{}", host, port);
            let mut direct = match TcpStream::connect(&target_addr).await {
                Ok(s) => s,
                Err(e) => {
                    writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                    anyhow::bail!("Direct connect to {} failed: {}", target_addr, e);
                }
            };
            // 转发原始请求
            let path = if let Some(idx) = target.find("//") {
                let rest = &target[idx + 2..];
                if let Some(slash) = rest.find('/') {
                    &rest[slash..]
                } else {
                    "/"
                }
            } else {
                target
            };
            let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
            for h in headers {
                request.push_str(h);
            }
            request.push_str("\r\n");
            direct.write_all(request.as_bytes()).await?;
            if !body.is_empty() {
                direct.write_all(body).await?;
            }
            direct.flush().await?;
            tokio::io::copy(&mut direct, writer).await?;
            return Ok(());
        }

        // 走上游代理
        let upstream_addr = match pool.get_proxy_address(socks_port).await {
            Some(addr) => addr,
            None => {
                writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                pool.mark_unavailable(socks_port).await;
                anyhow::bail!("No proxy available for port {}", socks_port);
            }
        };

        pool.mark_used(socks_port).await;

        let mut upstream = match TcpStream::connect(&upstream_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to upstream {}: {}", upstream_addr, e);
                writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                pool.mark_unavailable(socks_port).await;
                anyhow::bail!("Upstream connection failed: {}", e);
            }
        };

        Self::socks5_handshake(&mut upstream, &host, port, pool.proxy_username(), pool.proxy_password()).await?;
        debug!("SOCKS5 handshake OK for {}:{}", host, port);

        let path = if let Some(idx) = target.find("//") {
            let rest = &target[idx + 2..];
            if let Some(slash) = rest.find('/') {
                &rest[slash..]
            } else {
                "/"
            }
        } else {
            target
        };

        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
        for h in headers {
            request.push_str(h);
        }
        request.push_str("\r\n");

        upstream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            upstream.write_all(&body).await?;
        }
        upstream.flush().await?;

        tokio::io::copy(&mut upstream, writer).await?;

        Ok(())
    }

    async fn socks5_handshake(
        upstream: &mut TcpStream,
        dest_addr: &str,
        dest_port: u16,
        username: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        upstream.write_all(&[SOCKS5_VERSION, 0x02, SOCKS5_NO_AUTH, SOCKS5_USERPASS_AUTH]).await?;

        let mut buf = [0u8; 2];
        upstream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            anyhow::bail!("Upstream proxy version mismatch");
        }

        if buf[1] == SOCKS5_USERPASS_AUTH {
            if username.is_empty() {
                anyhow::bail!("Upstream requires auth but no credentials provided");
            }
            let mut auth_req = vec![0x01];
            auth_req.push(username.len() as u8);
            auth_req.extend_from_slice(username.as_bytes());
            auth_req.push(password.len() as u8);
            auth_req.extend_from_slice(password.as_bytes());
            upstream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            upstream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                anyhow::bail!("Upstream proxy auth rejected: status={}", auth_resp[1]);
            }
        } else if buf[1] != SOCKS5_NO_AUTH {
            anyhow::bail!("Upstream proxy unsupported auth method: {}", buf[1]);
        }

        let mut request = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00];

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

        let mut response = [0u8; 4];
        upstream.read_exact(&mut response).await?;

        if response[1] != SOCKS5_REP_SUCCESS {
            anyhow::bail!("Upstream proxy connect failed: {}", response[1]);
        }

        match response[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                upstream.read_exact(&mut skip).await?;
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                upstream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut skip = vec![0u8; len + 2];
                upstream.read_exact(&mut skip).await?;
            }
            _ => anyhow::bail!("Unsupported upstream bound address type"),
        }

        Ok(())
    }
}

fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    let s = s.trim_start_matches("http://").trim_start_matches("https://");
    let s = s.split('/').next().unwrap_or(s);
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port: u16 = s[idx + 1..].parse().unwrap_or(default_port);
        Ok((host.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("example.com:8080", 80).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_without_port() {
        let (host, port) = parse_host_port("example.com", 443).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_with_scheme() {
        let (host, port) = parse_host_port("http://example.com:8080/path", 80).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }
}
