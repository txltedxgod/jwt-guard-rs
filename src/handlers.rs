use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use crate::auth::create_jwt;
use crate::redis_store::RedisStore;
use std::sync::Arc;

pub struct AppState {
    pub jwt_secret: Vec<u8>,
    pub redis: RedisStore,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub token_id: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginPayload>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    if payload.username == "admin" && payload.password == "secret" {
        let (token, jti) = create_jwt(&payload.username, "admin", &state.jwt_secret, 3600)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT Error"))?;

        Ok(Json(TokenResponse {
            token,
            token_id: jti,
            token_type: "Bearer".into(),
            expires_in: 3600,
        }))
    } else {
        Err((StatusCode::UNAUTHORIZED, "Invalid credentials"))
    }
}

pub async fn health_handler() -> &'static str {
    "OK"
}
