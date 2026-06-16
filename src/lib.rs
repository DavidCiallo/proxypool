use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod http;
pub mod pool;
pub mod socks5;

/// 共享白名单类型
pub type BypassList = Arc<RwLock<HashSet<String>>>;