pub mod auth;
pub mod handlers;
pub mod redis_store;

use axum::{
    routing::{get, post},
    Router,
};
use handlers::{health_handler, login_handler, revoke_handler, verify_handler, AppState};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(health_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/verify", post(verify_handler))
        .route("/auth/revoke", post(revoke_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
