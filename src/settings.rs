pub(crate) static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(crate) static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) static OAUTH2_SCOPE: &str = "openid+email+profile";
pub(crate) static OAUTH2_RESPONSE_MODE: &str = "form_post";
// pub(crate) static OAUTH2_RESPONSE_MODE: &str = "query";

// "__Host-" prefix are added to make cookies "host-only".
pub(crate) static SESSION_COOKIE_NAME: &str = "__Host-SessionId";
pub(crate) static SESSION_COOKIE_MAX_AGE: i64 = 180; // 3 minutes

pub(crate) static CSRF_TOKEN_NAME: &str = "__Host-CrfToken";
pub(crate) static USER_TOKEN_NAME: &str = "__Host-UserToken";

// pub(crate) static SESSION_COOKIE_NAME: &str = "SessionId";
// pub(crate) static CSRF_TOKEN_NAME: &str = "csrf_token";
// pub(crate) static USER_TOKEN_NAME: &str = "user_token";

pub(crate) static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
pub(crate) static CSRF_COOKIE_MAX_AGE: i64 = 20; // 20 seconds

pub(crate) static NONCE_COOKIE_NAME: &str = "__Host-Nonce";
pub(crate) static NONCE_COOKIE_MAX_AGE: i64 = 20; // 10 minutes
                                                  // pub(super) static NONCE_COOKIE_MAX_AGE: i64 = 20; // 10 minutes
