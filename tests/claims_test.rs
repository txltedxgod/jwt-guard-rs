use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request, StatusCode},
};
use jwt_guard_rs::{
    auth::{create_jwt, hash_password, verify_jwt, verify_password},
    build_router,
    handlers::AppState,
    redis_store::RedisStore,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

#[test]
fn test_jwt_create_and_verify_roundtrip() {
    let secret = b"integration-test-secret-key";
    let (token1, jti1) = create_jwt("user_123", "admin", secret, 3600).expect("token created");
    let (token2, jti2) = create_jwt("user_123", "admin", secret, 3600).expect("token created");

    assert_ne!(jti1, jti2);
    assert_ne!(token1, token2);

    let claims = verify_jwt(&token1, secret).expect("valid token should verify");
    assert_eq!(claims.sub, "user_123");
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.jti, jti1);

    assert!(verify_jwt(&token1, b"wrong-secret").is_err());

    let (expired_token, _) =
        create_jwt("user_123", "admin", secret, -120).expect("expired token created");
    assert!(verify_jwt(&expired_token, secret).is_err());
}

#[test]
fn test_argon2_password_hashing_and_verification() {
    let hash = hash_password("strong-passphrase").expect("hashing succeeds");
    assert!(hash.starts_with("$argon2"));
    assert!(verify_password("strong-passphrase", &hash));
    assert!(!verify_password("wrong-passphrase", &hash));
    assert!(!verify_password("strong-passphrase", "invalid-hash"));
}

#[tokio::test]
async fn test_http_health_and_login_flow() {
    let secret = b"http-flow-test-secret".to_vec();
    let password_hash = hash_password("correct-horse-battery").expect("hashing succeeds");
    let redis = RedisStore::new("redis://127.0.0.1:6379").expect("valid redis URL");

    let state = Arc::new(AppState {
        jwt_secret: secret.clone(),
        redis,
        admin_username: "admin".into(),
        admin_password_hash: password_hash,
    });
    let app = build_router(state);

    let health_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    let body = to_bytes(health_resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"OK");

    let bad_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_login.status(), StatusCode::UNAUTHORIZED);

    let ok_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"correct-horse-battery"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_login.status(), StatusCode::OK);
    let login_bytes = to_bytes(ok_login.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&login_bytes).unwrap();
    let token = payload["token"].as_str().expect("token string present");
    let claims = verify_jwt(token, &secret).expect("issued token must verify");
    assert_eq!(claims.sub, "admin");
    assert_eq!(claims.role, "admin");

    let unauth_verify = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_verify.status(), StatusCode::UNAUTHORIZED);
}
