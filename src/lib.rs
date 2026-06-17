use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod http;
pub mod pool;
pub mod socks5;

pub type BypassList = Arc<RwLock<HashSet<String>>>;

#[derive(Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

impl AuthConfig {
    pub fn is_required(&self) -> bool {
        !self.username.is_empty()
    }
}