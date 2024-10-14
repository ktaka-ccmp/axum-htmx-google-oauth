use once_cell::sync::Lazy;

pub(crate) static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(crate) static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub(crate) static GOOGLE_OAUTH2_CLIENT_ID: Lazy<String> = Lazy::new(|| {
    std::env::var("GOOGLE_OAUTH2_CLIENT_ID").expect("GOOGLE_OAUTH2_CLIENT_ID must be set")
});
pub(crate) static GOOGLE_OAUTH2_CLIENT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("GOOGLE_OAUTH2_CLIENT_SECRET").expect("GOOGLE_OAUTH2_CLIENT_SECRET must be set")
});

pub(crate) static OAUTH2_SCOPE: Lazy<String> =
    Lazy::new(|| std::env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string()));
pub(crate) static OAUTH2_RESPONSE_MODE: Lazy<String> =
    Lazy::new(|| std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("query".to_string()));

// "__Host-" prefix are added to make cookies "host-only".
pub(crate) static SESSION_COOKIE_NAME: &str = "__Host-SessionId";
pub(crate) static SESSION_COOKIE_MAX_AGE: Lazy<i64> = Lazy::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1800) // Default to 0.5 hour if not set or invalid
});

pub(crate) static CSRF_TOKEN_NAME: &str = "__Host-CrfToken";
pub(crate) static USER_TOKEN_NAME: &str = "__Host-UserToken";

pub(crate) static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
pub(crate) static CSRF_COOKIE_MAX_AGE: Lazy<i64> = Lazy::new(|| {
    std::env::var("CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 1 minutes if not set or invalid
});

pub(crate) static NONCE_COOKIE_NAME: &str = "__Host-Nonce";
pub(crate) static NONCE_COOKIE_MAX_AGE: Lazy<i64> = Lazy::new(|| {
    std::env::var("NONCE_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 1 minutes if not set or invalid
});
