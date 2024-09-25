pub(crate) static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(crate) static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) static OAUTH2_SCOPE: &str = "openid+email+profile";
pub(crate) static OAUTH2_RESPONSE_MODE: &str = "form_post";
// pub(crate) static OAUTH2_RESPONSE_MODE: &str = "query";

// "__Host-" prefix are added to make cookies "host-only".
pub(crate) static COOKIE_NAME: &str = "__Host-SessionId";
pub(crate) static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
pub(crate) static COOKIE_MAX_AGE: i64 = 600; // 10 minutes
pub(crate) static CSRF_COOKIE_MAX_AGE: i64 = 20; // 20 seconds

pub(crate) static NONCE_COOKIE_NAME: &str = "__Host-Nonce";
pub(crate) static NONCE_COOKIE_MAX_AGE: i64 = 20; // 10 minutes
                                                  // pub(super) static NONCE_COOKIE_MAX_AGE: i64 = 20; // 10 minutes
