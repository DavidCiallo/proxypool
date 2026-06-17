use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub address: String,
    pub port: u16,
    pub created_at: Instant,
    pub last_used: Instant,
    pub is_available: bool,
}

impl ProxyEntry {
    pub fn new(address: String, port: u16) -> Self {
        let now = Instant::now();
        Self {
            address,
            port,
            created_at: now,
            last_used: now,
            is_available: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(600)
    }

    pub fn is_soon_expiring(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(540)
    }

    pub fn is_idle(&self) -> bool {
        self.last_used.elapsed() > Duration::from_secs(303)
    }

    pub fn rotation_priority(&self) -> u32 {
        if !self.is_available || self.address.is_empty() {
            return 1000;
        }
        if self.is_expired() {
            return 800;
        }
        if self.is_soon_expiring() && self.is_idle() {
            return 600;
        }
        if self.is_soon_expiring() {
            return 400;
        }
        if self.is_idle() {
            return 200;
        }
        0
    }

    pub fn needs_rotation(&self) -> bool {
        self.rotation_priority() > 0
    }
}

#[derive(Debug, Clone)]
struct ReserveEntry {
    address: String,
    created_at: Instant,
    latency_ms: u64,
}

impl ReserveEntry {
    fn new(address: String, latency_ms: u64) -> Self {
        Self {
            address,
            created_at: Instant::now(),
            latency_ms,
        }
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(600)
    }
}

pub struct IpPool {
    pool: Arc<RwLock<HashMap<u16, ProxyEntry>>>,
    reserve: Arc<RwLock<VecDeque<ReserveEntry>>>,
    port_range: (u16, u16),
    fetch_url: String,
    proxy_username: String,
    proxy_password: String,
}

impl IpPool {
    pub fn new(
        port_range: (u16, u16),
        fetch_url: String,
        _fetch_interval_secs: u64,
        _check_interval_secs: u64,
        proxy_username: String,
        proxy_password: String,
    ) -> Self {
        Self {
            pool: Arc::new(RwLock::new(HashMap::new())),
            reserve: Arc::new(RwLock::new(VecDeque::new())),
            port_range,
            fetch_url,
            proxy_username,
            proxy_password,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        {
            let mut pool = self.pool.write().await;
            for port in self.port_range.0..=self.port_range.1 {
                pool.insert(port, ProxyEntry::new(String::new(), port));
            }
        }

        self.fetch_and_assign().await;

        let pool_clone = self.clone();
        tokio::spawn(async move {
            pool_clone.fetch_loop().await;
        });

        Ok(())
    }

    async fn fetch_loop(&self) {
        let fetch_interval = Duration::from_secs(11);
        loop {
            tokio::time::sleep(fetch_interval).await;
            self.clean_expired_reserve().await;
            self.health_check().await;
            self.fetch_and_assign().await;
        }
    }

    /// 清理累积池中过期的 IP
    async fn clean_expired_reserve(&self) {
        let mut reserve = self.reserve.write().await;
        reserve.retain(|e| !e.is_expired());
    }

    /// 健康检查：逐个 TCP 连通性测试（避免同时并发太多连接）
    async fn health_check(&self) {
        let entries: Vec<(u16, String, Instant)> = {
            let pool = self.pool.read().await;
            pool.iter()
                .filter(|(_, e)| e.is_available && !e.address.is_empty())
                .map(|(port, e)| (*port, e.address.clone(), e.created_at))
                .collect()
        };

        if entries.is_empty() {
            return;
        }

        for (port, addr, created_at) in entries {
            let ok = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);

            if !ok {
                let age = created_at.elapsed().as_secs();
                if age < 300 {
                    warn!("Health check failed for port {} (upstream {}, age={}s)", port, addr, age);
                }
                {
                    let mut pool = self.pool.write().await;
                    if let Some(entry) = pool.get_mut(&port) {
                        entry.is_available = false;
                    }
                }
                // 立即从累积池补充
                self.try_replenish_from_reserve(port).await;
            }

            // 每个检查间隔 500ms，避免瞬时连接风暴
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// 尝试从累积池取一个可用 IP 补充到指定端口（逐个验证，失败则丢弃继续下一个）
    async fn try_replenish_from_reserve(&self, port: u16) -> bool {
        loop {
            let entry = {
                let mut reserve = self.reserve.write().await;
                reserve.pop_front()
            };

            let entry = match entry {
                Some(e) => e,
                None => return false, // 累积池空了
            };

            // 验证 IP 是否仍然可用
            match Self::validate_upstream(&entry.address).await {
                Some(latency) => {
                    let mut pool = self.pool.write().await;
                    if let Some(pool_entry) = pool.get_mut(&port) {
                        *pool_entry = ProxyEntry::new(entry.address, port);
                        return true;
                    }
                    return false;
                }
                None => {
                    warn!("Reserve IP {} expired/unreachable, discarding", entry.address);
                    continue; // 丢弃，尝试下一个
                }
            }
        }
    }

    async fn fetch_one_ip(&self) -> Option<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let response = match client.get(&self.fetch_url).send().await {
            Ok(r) => r,
            Err(e) => {
                return None;
            }
        };
        let ip_text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to read response body: {}", e);
                return None;
            }
        };
        let ip = ip_text.trim().to_string();
        debug!("API response: {:?}", ip);

        if ip.is_empty() {
            warn!("Empty IP response");
            return None;
        }

        if ip.starts_with('{') {
            warn!("API returned error: {}", ip);
            return None;
        }

        Some(ip)
    }

    fn parse_upstream_addr(raw: &str) -> String {
        if raw.contains(':') {
            raw.to_string()
        } else {
            format!("{}:1080", raw)
        }
    }

    /// 验证上游代理是否可用，返回延迟(ms)，不可用返回 None
    async fn validate_upstream(addr: &str) -> Option<u64> {
        let start = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await;

        match result {
            Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
            _ => None,
        }
    }

    /// 1. 有端口需要轮换 → 先从累积池取，累积池空则请求 API
    /// 2. 没有端口需要轮换 → 请求 API 存入累积池
    async fn fetch_and_assign(&self) {
        let mut candidates: Vec<(u16, u32)> = {
            let pool = self.pool.read().await;
            pool.iter()
                .filter(|(_, entry)| entry.needs_rotation())
                .map(|(port, entry)| (*port, entry.rotation_priority()))
                .collect()
        };

        if !candidates.is_empty() {
            // 有端口需要轮换
            candidates.sort_by(|a, b| b.1.cmp(&a.1));

            for (target_port, priority) in &candidates {
                // 先从累积池取（逐个验证）
                loop {
                    let entry = {
                        let mut reserve = self.reserve.write().await;
                        reserve.pop_front()
                    };

                    match entry {
                        Some(e) => {
                            match Self::validate_upstream(&e.address).await {
                                Some(latency) => {
                                    let mut pool = self.pool.write().await;
                                    if let Some(pool_entry) = pool.get_mut(target_port) {
                                        *pool_entry = ProxyEntry::new(e.address, *target_port);
                                    }
                                    break; // 成功，跳出内层循环
                                }
                                None => {
                                    continue; // 丢弃，尝试下一个
                                }
                            }
                        }
                        None => {
                            // 累积池空了，请求 API
                            let ip = match self.fetch_one_ip().await {
                                Some(ip) => ip,
                                None => return,
                            };
                            let upstream_addr = Self::parse_upstream_addr(&ip);

                            // 验证 API 返回的 IP
                            match Self::validate_upstream(&upstream_addr).await {
                                Some(latency) => {
                                    let mut pool = self.pool.write().await;
                                    if let Some(entry) = pool.get_mut(target_port) {
                                        *entry = ProxyEntry::new(upstream_addr, *target_port);
                                    }
                                }
                                None => {
                                }
                            }
                            return; // 每次循环只请求一次 API
                        }
                    }
                }
                return; // 每次循环只请求一次 API
            }
        } else {
            // 所有端口健康，请求 API 存入累积池
            let reserve_len = self.reserve.read().await.len();
            if reserve_len >= 50 {
                debug!("Reserve pool full ({}), skipping fetch", reserve_len);
                return;
            }

            let ip = match self.fetch_one_ip().await {
                Some(ip) => ip,
                None => return,
            };
            let upstream_addr = Self::parse_upstream_addr(&ip);


            // 入池前验证：TCP 连通
            match Self::validate_upstream(&upstream_addr).await {
                Some(latency) => {
                    let mut reserve = self.reserve.write().await;
                    reserve.push_back(ReserveEntry::new(upstream_addr.clone(), latency));
                }
                None => {
                    warn!("Upstream {} failed validation, discarded", upstream_addr);
                }
            }
        }
    }

    pub async fn mark_used(&self, port: u16) {
        let mut pool = self.pool.write().await;
        if let Some(entry) = pool.get_mut(&port) {
            entry.last_used = Instant::now();
        }
    }

    pub async fn mark_unavailable(&self, port: u16) {
        {
            let mut pool = self.pool.write().await;
            if let Some(entry) = pool.get_mut(&port) {
                entry.is_available = false;
            }
        }
        // 立即尝试从累积池补充
        self.try_replenish_from_reserve(port).await;
    }

    pub async fn get_proxy_address(&self, port: u16) -> Option<String> {
        let pool = self.pool.read().await;
        pool.get(&port).and_then(|entry| {
            if entry.is_available && !entry.address.is_empty() {
                Some(entry.address.clone())
            } else {
                None
            }
        })
    }

    pub async fn get_all_ports(&self) -> Vec<u16> {
        let pool = self.pool.read().await;
        pool.keys().cloned().collect()
    }

    pub async fn set_proxy_address(&self, port: u16, address: String) {
        let mut pool = self.pool.write().await;
        pool.insert(port, ProxyEntry::new(address, port));
    }

    pub fn proxy_username(&self) -> &str {
        &self.proxy_username
    }

    pub fn proxy_password(&self) -> &str {
        &self.proxy_password
    }

    pub async fn reserve_size(&self) -> usize {
        self.reserve.read().await.len()
    }
}

impl Clone for IpPool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            reserve: self.reserve.clone(),
            port_range: self.port_range,
            fetch_url: self.fetch_url.clone(),
            proxy_username: self.proxy_username.clone(),
            proxy_password: self.proxy_password.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_entry_new() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert_eq!(entry.address, "1.2.3.4:10000");
        assert_eq!(entry.port, 10000);
        assert!(entry.is_available);
    }

    #[test]
    fn test_proxy_entry_not_expired_fresh() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_proxy_entry_not_idle_fresh() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert!(!entry.is_idle());
    }

    #[test]
    fn test_proxy_entry_needs_rotation_when_unavailable() {
        let mut entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        entry.is_available = false;
        assert!(entry.needs_rotation());
    }

    #[test]
    fn test_proxy_entry_no_rotation_when_available_and_fresh() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert!(!entry.needs_rotation());
    }

    #[test]
    fn test_proxy_entry_empty_address_needs_rotation() {
        let mut entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        entry.address = String::new();
        assert!(entry.needs_rotation());
    }

    #[tokio::test]
    async fn test_pool_initialization() {
        let pool = IpPool::new(
            (10000, 10002),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60, 60, String::new(), String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            for port in 10000..=10002 {
                p.insert(port, ProxyEntry::new(String::new(), port));
            }
        }
        let ports = pool.get_all_ports().await;
        assert_eq!(ports.len(), 3);
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_empty() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60, 60, String::new(), String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new(String::new(), 10000));
        }
        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_none());
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_available() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60, 60, String::new(), String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }
        let addr = pool.get_proxy_address(10000).await;
        assert_eq!(addr, Some("1.2.3.4:10000".to_string()));
    }

    #[tokio::test]
    async fn test_pool_mark_used() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60, 60, String::new(), String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }
        pool.mark_used(10000).await;
        let addr = pool.get_proxy_address(10000).await;
        assert_eq!(addr, Some("1.2.3.4:10000".to_string()));
    }

    #[tokio::test]
    async fn test_pool_mark_unavailable() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60, 60, String::new(), String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }
        pool.mark_unavailable(10000).await;
        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_none());
    }

    #[tokio::test]
    async fn test_reserve_stores_excess_ips() {
        // 启动一个真实的 TCP "上游代理"（只 accept 不做任何事）
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_str = upstream_addr.to_string();
        tokio::spawn(async move {
            loop {
                if upstream.accept().await.is_err() { break; }
            }
        });

        // 启动 mock HTTP API，返回这个真实地址
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let fetch_url = format!("http://{}", http_addr);
        let resp_body = upstream_str.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match http_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let body = resp_body.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let pool = IpPool::new((10000, 10000), fetch_url, 60, 60, String::new(), String::new());
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }

        pool.fetch_and_assign().await;
        let reserve_size = pool.reserve_size().await;
        assert!(reserve_size >= 1, "Reserve should have at least 1 IP, got {}", reserve_size);
    }

    #[tokio::test]
    async fn test_reserve_replenishes_dead_port() {
        // 启动一个真实的 TCP "上游代理"
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_str = upstream_addr.to_string();
        tokio::spawn(async move {
            loop {
                if upstream.accept().await.is_err() { break; }
            }
        });

        // 启动 mock HTTP API
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let fetch_url = format!("http://{}", http_addr);
        let resp_body = upstream_str.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match http_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let body = resp_body.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let pool = IpPool::new((10000, 10000), fetch_url, 60, 60, String::new(), String::new());
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }

        // 先存一个 IP 到累积池
        pool.fetch_and_assign().await;
        assert!(pool.reserve_size().await >= 1);

        // 标记端口不可用，应该从累积池补充
        pool.mark_unavailable(10000).await;
        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_some(), "Port should be replenished from reserve");
    }
}