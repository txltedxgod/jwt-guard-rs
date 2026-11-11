use crate::auth::{create_jwt, verify_jwt, verify_password, Claims};
use crate::redis_store::RedisStore;
use axum::{
    extract::{Json, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub jwt_secret: Vec<u8>,
    pub redis: RedisStore,
    pub admin_username: String,
    pub admin_password_hash: String,
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
    if payload.username == state.admin_username
        && verify_password(&payload.password, &state.admin_password_hash)
    {
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

pub async fn verify_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Claims>, (StatusCode, &'static str)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(token, &state.jwt_secret)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    let revoked = state.redis.is_blacklisted(&claims.jti).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Revocation store unavailable",
        )
    })?;

    if revoked {
        return Err((StatusCode::UNAUTHORIZED, "Token has been revoked"));
    }

    Ok(Json(claims))
}

pub async fn revoke_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let token = extract_bearer_token(&headers)?;
    let claims = verify_jwt(token, &state.jwt_secret)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let ttl = (claims.exp as u64).saturating_sub(now).max(1);

    state
        .redis
        .blacklist_token(&claims.jti, ttl)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Revocation store unavailable",
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn health_handler() -> &'static str {
    "OK"
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, (StatusCode, &'static str)> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;
    value
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization scheme"))
}
