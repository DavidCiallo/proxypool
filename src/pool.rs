use std::collections::HashMap;
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
        // IP 有效期 5-10 分钟，超过 10 分钟视为已过期
        self.created_at.elapsed() > Duration::from_secs(600)
    }

    pub fn is_soon_expiring(&self) -> bool {
        // 接近 10 分钟（9 分钟+）视为即将过期，优先替换
        self.created_at.elapsed() > Duration::from_secs(540)
    }

    pub fn is_idle(&self) -> bool {
        // 5 分钟 + 3 秒无连接视为空闲
        self.last_used.elapsed() > Duration::from_secs(303)
    }

    /// 计算优先级分数，分数越高越需要更新
    /// 优先级：不可用/空地址 > 已过期 > 即将过期 > 空闲
    pub fn rotation_priority(&self) -> u32 {
        if !self.is_available || self.address.is_empty() {
            return 1000; // 最高优先级：坏了或没 IP
        }
        if self.is_expired() {
            return 800; // 已过期
        }
        if self.is_soon_expiring() && self.is_idle() {
            return 600; // 即将过期 + 空闲
        }
        if self.is_soon_expiring() {
            return 400; // 即将过期（可能还在用）
        }
        if self.is_idle() {
            return 200; // 空闲但还没过期
        }
        0 // 正常，不需要更新
    }

    pub fn needs_rotation(&self) -> bool {
        self.rotation_priority() > 0
    }
}

pub struct IpPool {
    pool: Arc<RwLock<HashMap<u16, ProxyEntry>>>,
    port_range: (u16, u16),
    fetch_url: String,
    proxy_username: String,
    proxy_password: String,
}

impl IpPool {
    pub fn new(
        port_range: (u16, u16),
        fetch_url: String,
        _fetch_interval_secs: u64,   // 保留兼容，不再使用
        _check_interval_secs: u64,   // 保留兼容，不再使用
        proxy_username: String,
        proxy_password: String,
    ) -> Self {
        Self {
            pool: Arc::new(RwLock::new(HashMap::new())),
            port_range,
            fetch_url,
            proxy_username,
            proxy_password,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        // Initialize pool with empty entries
        {
            let mut pool = self.pool.write().await;
            for port in self.port_range.0..=self.port_range.1 {
                pool.insert(port, ProxyEntry::new(String::new(), port));
            }
        }

        // Fetch initial IPs
        self.fetch_and_assign().await;

        // 唯一的后台循环：11 秒固定节奏，控制反转
        let pool_clone = self.clone();
        tokio::spawn(async move {
            pool_clone.fetch_loop().await;
        });

        Ok(())
    }

    /// 核心循环：每 11 秒做一次健康检查 + 按需获取新 IP
    async fn fetch_loop(&self) {
        let fetch_interval = Duration::from_secs(11);
        loop {
            tokio::time::sleep(fetch_interval).await;
            // 先健康检查：TCP 连接测试所有有 IP 的端口
            self.health_check().await;
            // 再按优先级替换需要更新的端口
            self.fetch_and_assign().await;
        }
    }

    /// 健康检查：对所有有地址的端口做 TCP 连通性测试，连不通的标记为不可用
    async fn health_check(&self) {
        let entries: Vec<(u16, String)> = {
            let pool = self.pool.read().await;
            pool.iter()
                .filter(|(_, e)| e.is_available && !e.address.is_empty())
                .map(|(port, e)| (*port, e.address.clone()))
                .collect()
        };

        if entries.is_empty() {
            return;
        }

        // 并发测试所有端口，3 秒超时
        let mut handles = Vec::new();
        for (port, addr) in entries {
            handles.push(tokio::spawn(async move {
                let ok = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                (port, addr, ok)
            }));
        }

        for handle in handles {
            if let Ok((port, addr, ok)) = handle.await {
                if !ok {
                    warn!("Health check failed for port {} (upstream {}), marking unavailable", port, addr);
                    let mut pool = self.pool.write().await;
                    if let Some(entry) = pool.get_mut(&port) {
                        entry.is_available = false;
                    }
                }
            }
        }
    }

    /// 请求 API 获取一个 IP，失败返回 None
    async fn fetch_one_ip(&self) -> Option<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let response = match client.get(&self.fetch_url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("HTTP request failed: {}", e);
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

    /// 解析 "ip:port" 格式的地址
    fn parse_upstream_addr(raw: &str) -> String {
        if raw.contains(':') {
            raw.to_string()
        } else {
            format!("{}:1080", raw)
        }
    }

    /// 核心：请求 API → 按优先级找最需要更新的端口 → 分配
    /// 由于 API 每次只返回一个 IP（limit=1），每次循环只更新一个端口
    /// 但高优先级（不可用/已过期）会优先被更新
    async fn fetch_and_assign(&self) {
        let mut candidates: Vec<(u16, u32)> = {
            let pool = self.pool.read().await;
            pool.iter()
                .filter(|(_, entry)| entry.needs_rotation())
                .map(|(port, entry)| (*port, entry.rotation_priority()))
                .collect()
        };

        if candidates.is_empty() {
            debug!("All ports healthy, skipping fetch");
            return;
        }

        // 按优先级降序排列，最高优先级的端口先更新
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        let target_port = candidates[0].0;
        let priority = candidates[0].1;
        let total_candidates = candidates.len();
        info!(
            "Port {} needs update (priority={}, {}/{} candidates), fetching...",
            target_port, priority, total_candidates,
            self.pool.read().await.len()
        );

        let ip = match self.fetch_one_ip().await {
            Some(ip) => ip,
            None => return,
        };

        let upstream_addr = Self::parse_upstream_addr(&ip);
        info!("Fetched upstream proxy: {}", upstream_addr);

        let mut pool = self.pool.write().await;
        if let Some(entry) = pool.get_mut(&target_port) {
            info!("Assigned {} → local port {} (was: {})", upstream_addr, target_port, entry.address);
            *entry = ProxyEntry::new(upstream_addr.clone(), target_port);
        }
    }

    pub async fn mark_used(&self, port: u16) {
        let mut pool = self.pool.write().await;
        if let Some(entry) = pool.get_mut(&port) {
            entry.last_used = Instant::now();
        }
    }

    pub async fn mark_unavailable(&self, port: u16) {
        let mut pool = self.pool.write().await;
        if let Some(entry) = pool.get_mut(&port) {
            entry.is_available = false;
        }
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

    /// 直接设置指定端口的代理地址（用于测试或手动注入）
    pub async fn set_proxy_address(&self, port: u16, address: String) {
        let mut pool = self.pool.write().await;
        pool.insert(port, ProxyEntry::new(address, port));
    }

    /// 获取上游代理认证用户名
    pub fn proxy_username(&self) -> &str {
        &self.proxy_username
    }

    /// 获取上游代理认证密码
    pub fn proxy_password(&self) -> &str {
        &self.proxy_password
    }
}

impl Clone for IpPool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
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

    // ===== ProxyEntry 单元测试 =====

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
        assert!(!entry.is_expired(), "刚创建的 entry 不应过期");
    }

    #[test]
    fn test_proxy_entry_not_idle_fresh() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert!(!entry.is_idle(), "刚创建的 entry 不应空闲");
    }

    #[test]
    fn test_proxy_entry_needs_rotation_when_unavailable() {
        let mut entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        entry.is_available = false;
        assert!(entry.needs_rotation(), "不可用时应需要轮换");
    }

    #[test]
    fn test_proxy_entry_no_rotation_when_available_and_fresh() {
        let entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        assert!(!entry.needs_rotation(), "可用且新鲜时不应轮换");
    }

    #[test]
    fn test_proxy_entry_empty_address_needs_rotation() {
        let mut entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
        entry.address = String::new();
        // 空地址 → rotation_priority() = 1000（最高优先级），需要立即轮换
        assert!(entry.needs_rotation(), "空地址应需要轮换（priority=1000）");
    }

    // ===== IpPool 集成测试 =====

    #[tokio::test]
    async fn test_pool_initialization() {
        let pool = IpPool::new(
            (10000, 10002),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );

        // 手动初始化（不调用 start，避免网络请求和后台任务）
        {
            let mut p = pool.pool.write().await;
            for port in 10000..=10002 {
                p.insert(port, ProxyEntry::new(String::new(), port));
            }
        }

        let ports = pool.get_all_ports().await;
        assert_eq!(ports.len(), 3);
        assert!(ports.contains(&10000));
        assert!(ports.contains(&10001));
        assert!(ports.contains(&10002));
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_empty() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new(String::new(), 10000));
        }

        // address 为空，应该返回 None
        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_none(), "空地址应返回 None");
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_available() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }

        let addr = pool.get_proxy_address(10000).await;
        assert_eq!(addr, Some("1.2.3.4:10000".to_string()));
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_unavailable() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            let mut entry = ProxyEntry::new("1.2.3.4:10000".to_string(), 10000);
            entry.is_available = false;
            p.insert(10000, entry);
        }

        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_none(), "不可用时应返回 None");
    }

    #[tokio::test]
    async fn test_pool_mark_used() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }

        // mark_used 应该更新 last_used 时间
        pool.mark_used(10000).await;

        let addr = pool.get_proxy_address(10000).await;
        assert_eq!(addr, Some("1.2.3.4:10000".to_string()));
    }

    #[tokio::test]
    async fn test_pool_mark_unavailable() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );
        {
            let mut p = pool.pool.write().await;
            p.insert(10000, ProxyEntry::new("1.2.3.4:10000".to_string(), 10000));
        }

        pool.mark_unavailable(10000).await;

        let addr = pool.get_proxy_address(10000).await;
        assert!(addr.is_none(), "mark_unavailable 后应返回 None");
    }

    #[tokio::test]
    async fn test_pool_get_proxy_address_nonexistent_port() {
        let pool = IpPool::new(
            (10000, 10000),
            "http://127.0.0.1:19999/nonexistent".to_string(),
            60,
            60,
            String::new(),
            String::new(),
        );

        let addr = pool.get_proxy_address(9999).await;
        assert!(addr.is_none(), "不存在的端口应返回 None");
    }

    #[tokio::test]
    async fn test_pool_fetch_and_assign_with_mock_server() {
        // 启动一个 mock HTTP 服务器返回固定 IP（循环 accept）
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fetch_url = format!("http://{}", addr);

        let server_handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0, "应收到 HTTP 请求");
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n10.0.0.1:22868";
                    let _ = stream.write_all(response).await;
                });
            }
        });

        let pool = IpPool::new((10000, 10002), fetch_url, 60, 60, String::new(), String::new());

        // 手动初始化空 entries
        {
            let mut p = pool.pool.write().await;
            for port in 10000..=10002 {
                p.insert(port, ProxyEntry::new(String::new(), port));
            }
        }

        // 调用 fetch_and_assign（每次只分配一个端口）
        // 第一次调用分配优先级最高的端口（空地址，优先级 1000）
        pool.fetch_and_assign().await;

        // 第一次 fetch 只分配一个端口（优先级最高的）
        let mut assigned_count = 0;
        for port in 10000..=10002 {
            let addr = pool.get_proxy_address(port).await;
            if addr == Some("10.0.0.1:22868".to_string()) {
                assigned_count += 1;
            }
        }
        assert!(assigned_count >= 1, "至少一个端口应被分配地址");

        // 关闭 mock server（drop listener 触发 accept 失败退出循环）
        drop(pool);
        server_handle.abort();
    }
}