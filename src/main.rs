use jwt_guard_rs::{
    auth::hash_password, build_router, handlers::AppState, redis_store::RedisStore,
};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let jwt_secret = match std::env::var("JWT_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => {
            tracing::warn!("JWT_SECRET not set; using ephemeral development fallback secret");
            b"dev-only-change-jwt-secret".to_vec()
        }
    };

    let admin_username = std::env::var("AUTH_USERNAME").unwrap_or_else(|_| "admin".into());
    let admin_password_hash = match std::env::var("AUTH_PASSWORD_HASH") {
        Ok(hash) => hash,
        Err(_) => {
            let plain = std::env::var("AUTH_PASSWORD").unwrap_or_else(|_| {
                tracing::warn!("AUTH_PASSWORD_HASH not set; using development credentials");
                "secret".into()
            });
            hash_password(&plain).map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?
        }
    };

    let redis_store = RedisStore::new(&redis_url)?;

    let app_state = Arc::new(AppState {
        jwt_secret,
        redis: redis_store,
        admin_username,
        admin_password_hash,
    });

    let app = build_router(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("[jwt-guard-rs] Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
