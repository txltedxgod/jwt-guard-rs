use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    conn: Arc<Mutex<Option<redis::aio::ConnectionManager>>>,
}

impl RedisStore {
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            conn: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn blacklist_token(&self, jti: &str, ttl_seconds: u64) -> Result<(), redis::RedisError> {
        let mut conn = self.client.get_connection_manager().await?;
        let key = format!("blacklist:{}", jti);
        let _: () = conn.set_ex(key, "revoked", ttl_seconds).await?;
        Ok(())
    }

    pub async fn is_blacklisted(&self, jti: &str) -> Result<bool, redis::RedisError> {
        let mut conn = self.client.get_connection_manager().await?;
        let key = format!("blacklist:{}", jti);
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
}
