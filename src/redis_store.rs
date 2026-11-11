use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    conn: Arc<Mutex<Option<ConnectionManager>>>,
}

impl RedisStore {
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            conn: Arc::new(Mutex::new(None)),
        })
    }

    async fn get_connection(&self) -> Result<ConnectionManager, redis::RedisError> {
        let mut guard = self.conn.lock().await;
        if let Some(manager) = guard.as_ref() {
            return Ok(manager.clone());
        }
        let manager = ConnectionManager::new(self.client.clone()).await?;
        *guard = Some(manager.clone());
        Ok(manager)
    }

    pub async fn blacklist_token(
        &self,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.get_connection().await?;
        let key = format!("blacklist:{jti}");
        let _: () = conn.set_ex(key, "revoked", ttl_seconds).await?;
        Ok(())
    }

    pub async fn is_blacklisted(&self, jti: &str) -> Result<bool, redis::RedisError> {
        let mut conn = self.get_connection().await?;
        let key = format!("blacklist:{jti}");
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
}
