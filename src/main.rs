mod auth;
mod handlers;
mod redis_store;

use axum::{routing::{get, post}, Router};
use handlers::{health_handler, login_handler, AppState};
use redis_store::RedisStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-jwt-signing-key".into()).into_bytes();

    let redis_store = RedisStore::new(&redis_url)?;

    let app_state = Arc::new(AppState {
        jwt_secret,
        redis: redis_store,
    });

    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/auth/login", post(login_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("[jwt-guard-rs] Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
