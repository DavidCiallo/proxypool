use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use ip_proxy_pool::AuthConfig;

/// 启动一个 mock 上游 SOCKS5 服务器（循环 accept）
async fn start_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut ver_buf = [0u8; 2];
                if stream.read_exact(&mut ver_buf).await.is_err() { return; }
                let mut methods = vec![0u8; ver_buf[1] as usize];
                let _ = stream.read_exact(&mut methods).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() { return; }
                match header[3] {
                    0x01 => { let mut skip = [0u8; 6]; let _ = stream.read_exact(&mut skip).await; }
                    0x03 => {
                        let mut len_buf = [0u8; 1];
                        if stream.read_exact(&mut len_buf).await.is_err() { return; }
                        let mut skip = vec![0u8; len_buf[0] as usize + 2];
                        let _ = stream.read_exact(&mut skip).await;
                    }
                    _ => return,
                }

                let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await;

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

/// 通过 SOCKS5 代理发送请求
async fn socks5_request(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        return Err(format!("SOCKS5 greeting failed: {:?}", reply).into());
    }

    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(target_host.len() as u8);
    req.extend_from_slice(target_host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await?;
    if connect_reply[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed: rep={}", connect_reply[1]).into());
    }

    stream.write_all(payload).await?;

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await?;
    response.truncate(n);

    Ok(response)
}

/// 绑定一个随机端口，返回 listener 和端口号
async fn bind_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

// ===== Mock 上游服务器基础测试 =====

#[tokio::test]
async fn test_mock_upstream_ipv4_handshake() {
    let (upstream_addr, _handle) = start_mock_upstream().await;
    let mut stream = TcpStream::connect(upstream_addr).await.unwrap();

    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1];
    req.extend_from_slice(&80u16.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await.unwrap();
    assert_eq!(connect_reply[1], 0x00);

    stream.write_all(b"hello").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
}

#[tokio::test]
async fn test_mock_upstream_domain_handshake() {
    let (upstream_addr, _handle) = start_mock_upstream().await;
    let mut stream = TcpStream::connect(upstream_addr).await.unwrap();

    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00]);

    let domain = b"example.com";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await.unwrap();
    assert_eq!(connect_reply[1], 0x00);
}

// ===== 端到端 SOCKS5 代理测试 =====

#[tokio::test]
async fn test_socks5_end_to_end_with_mock_upstream() {
    use ip_proxy_pool::pool::IpPool;

    let (upstream_addr, _uh) = start_mock_upstream().await;

    // 绑定随机端口给 SOCKS5 server
    let (listener, port) = bind_port().await;
    drop(listener); // 释放端口给 Socks5Server 用

    let pool = Arc::new(IpPool::new(
        (port, port), "http://127.0.0.1:1/x".to_string(), 60, 60,
        String::new(), String::new(),
    ));
    pool.set_proxy_address(port, upstream_addr.to_string()).await;

    let sp = pool.clone();
    let sh = tokio::spawn(async move {
        ip_proxy_pool::socks5::Socks5Server::new(sp, Arc::new(RwLock::new(HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(port).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let response = socks5_request(
        format!("127.0.0.1:{}", port).parse().unwrap(),
        "test.example.com", 80, b"ping",
    ).await;

    match response {
        Ok(data) => assert_eq!(data, b"ping"),
        Err(e) => panic!("SOCKS5 端到端请求失败: {}", e),
    }

    sh.abort();
}

#[tokio::test]
async fn test_socks5_end_to_end_unavailable_upstream() {
    use ip_proxy_pool::pool::IpPool;

    let (listener, port) = bind_port().await;
    drop(listener);

    let pool = Arc::new(IpPool::new(
        (port, port), "http://127.0.0.1:1/x".to_string(), 60, 60,
        String::new(), String::new(),
    ));
    // 注入一个不存在的上游
    pool.set_proxy_address(port, "127.0.0.1:19998".to_string()).await;

    let sp = pool.clone();
    let sh = tokio::spawn(async move {
        ip_proxy_pool::socks5::Socks5Server::new(sp, Arc::new(RwLock::new(HashSet::new())), AuthConfig { username: String::new(), password: String::new() }).start(port).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let result = socks5_request(
        format!("127.0.0.1:{}", port).parse().unwrap(),
        "test.example.com", 80, b"test",
    ).await;

    assert!(result.is_err(), "上游不可达时应返回错误");

    // 单次失败不再标记不可用，由健康检查统一管理
    let addr = pool.get_proxy_address(port).await;
    assert!(addr.is_some(), "单次失败不应标记不可用，应由健康检查处理");

    sh.abort();
}

// ===== Pool 操作测试 =====

#[tokio::test]
async fn test_pool_mark_used_and_unavailable() {
    use ip_proxy_pool::pool::IpPool;

    let pool = Arc::new(IpPool::new(
        (30001, 30001), "http://127.0.0.1:1/x".to_string(), 60, 60,
        String::new(), String::new(),
    ));

    pool.set_proxy_address(30001, "1.2.3.4:30001".to_string()).await;

    pool.mark_used(30001).await;
    let addr = pool.get_proxy_address(30001).await;
    assert_eq!(addr, Some("1.2.3.4:30001".to_string()));

    pool.mark_unavailable(30001).await;
    let addr = pool.get_proxy_address(30001).await;
    assert!(addr.is_none());
}
