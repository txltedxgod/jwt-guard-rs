use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub jti: String,
    pub exp: usize,
}

pub fn create_jwt(user_id: &str, role: &str, secret: &[u8], duration_seconds: i64) -> Result<(String, String), jsonwebtoken::errors::Error> {
    let jti = uuid_simple();
    let exp = chrono::Utc::now().timestamp() + duration_seconds;

    let claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        jti: jti.clone(),
        exp: exp as usize,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))?;
    Ok((token, jti))
}

pub fn verify_jwt(token: &str, secret: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &Validation::default())?;
    Ok(token_data.claims)
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}{:x}", d.as_secs(), d.subsec_nanos())
}
