// JWT Guard - Claims Validation Tests

#[cfg(test)]
mod tests {
    #[derive(Debug, PartialEq)]
    pub struct Claims {
        pub sub: String,
        pub exp: u64,
    }

    impl Claims {
        pub fn is_expired(&self, current_timestamp: u64) -> bool {
            self.exp < current_timestamp
        }
    }

    #[test]
    fn test_token_expiration_logic() {
        let claims = Claims { sub: "user_123".into(), exp: 1000 };
        assert!(claims.is_expired(1001));
        assert!(!claims.is_expired(999));
    }
}
