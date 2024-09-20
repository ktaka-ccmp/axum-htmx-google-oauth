use aide::{axum::{
    routing::{get_with, post_with},
    ApiRouter, IntoApiResponse,
}, OperationOutput};

use anyhow::{Context, Result};
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    RequestPartsExt, Router,
};
use axum_extra::{headers, typed_header::TypedHeaderRejectionReason, TypedHeader};
use http::{header, request::Parts, StatusCode};

use serde::{Deserialize, Serialize};
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// use tower_http::cors::CorsLayer;
// use http::HeaderValue;

use url::Url;

use chrono::{DateTime, Duration, Utc};
use rand::{thread_rng, Rng};
use urlencoding::encode;

// use askama::Template;
use askama_axum::Template;
use axum::response::Html;

// use axum_server::tls_rustls::RustlsConfig;
use std::{net::SocketAddr, path::PathBuf};
use tokio::task::JoinHandle;

static AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
static TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
static SCOPE: &str = "openid+email+profile";

// "__Host-" prefix are added to make cookies "host-only".
static COOKIE_NAME: &str = "__Host-SessionId";
static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
static COOKIE_MAX_AGE: i64 = 600; // 10 minutes
static CSRF_COOKIE_MAX_AGE: i64 = 20; // 20 seconds

// pub fn create_router(state: Arc<AppState>) -> ApiRouter {
pub fn create_router() -> ApiRouter {
    let app_state = app_state_init();

    ApiRouter::new()
        .api_route("/", get_with(google_auth, |op| op.tag("auth")))
        .api_route(
            "/authorized",
            get_with(login_authorized, |op| op.tag("auth")),
        )
        .api_route("/protected", get_with(protected, |op| op.tag("auth")))
        .api_route("/logout", get_with(logout, |op| op.tag("auth")))
        .api_route("/popup_close", get_with(popup_close, |op| op.tag("auth")))
        .with_state(app_state);
}

fn app_state_init() -> AppState {
    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let oauth2_params = OAuth2Params {
        client_id: env::var("CLIENT_ID").expect("Missing CLIENT_ID!"),
        client_secret: env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!"),
        redirect_uri: format!(
            "{}/auth/authorized",
            env::var("ORIGIN").expect("Missing ORIGIN!")
        ),
        auth_url: AUTH_URL.to_string(),
        token_url: TOKEN_URL.to_string(),
        response_type: ResponseType::Code.as_str().to_string(),
        scope: SCOPE.to_string(),
        nonce: None,
        state: None,
        csrf_token: None,
        response_mode: Some(ResponseMode::Query), // "query",
        prompt: Some(Prompt::Consent),            // "consent",
        access_type: Some(AccessType::Online),    // "online",
    };

    AppState {
        store,
        oauth2_params,
    }
}

#[derive(Debug, Clone)]
enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

impl ResponseMode {
    fn as_str(&self) -> &str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }
}

#[derive(Debug, Clone)]
enum Prompt {
    None,
    Consent,
    SelectAccount,
    Login,
    ConsentSelectAccount,
    ConsentLogin,
    SelectAccountLogin,
    ConsentSelectAccountLogin,
}

impl Prompt {
    fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
            Self::Login => "login",
            Self::ConsentSelectAccount => "consent select_account",
            Self::ConsentLogin => "consent login",
            Self::SelectAccountLogin => "select_account login",
            Self::ConsentSelectAccountLogin => "consent select_account login",
        }
    }
}

#[derive(Debug, Clone)]
enum AccessType {
    Online,
    Offline,
}

impl AccessType {
    fn as_str(&self) -> &str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }
}

enum ResponseType {
    None = 0b000,
    Code = 0b001,
    Token = 0b010,
    IdToken = 0b100,
    CodeToken = 0b011,
    CodeIdToken = 0b101,
    TokenIdToken = 0b110,
    CodeTokenIdToken = 0b111,
}

impl ResponseType {
    fn as_str(&self) -> &str {
        match self {
            Self::None => "",
            Self::Code => "code",
            Self::Token => "token",
            Self::IdToken => "id_token",
            Self::CodeToken => "code token",
            Self::CodeIdToken => "code id_token",
            Self::TokenIdToken => "token id_token",
            Self::CodeTokenIdToken => "code token id_token",
        }
    }
}

#[derive(Clone, Debug)]
struct OAuth2Params {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth_url: String,
    token_url: String,
    response_type: String,
    scope: String,
    nonce: Option<String>,
    state: Option<String>,
    csrf_token: Option<String>,
    response_mode: Option<ResponseMode>,
    prompt: Option<Prompt>,
    access_type: Option<AccessType>,
}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    oauth2_params: OAuth2Params,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for OAuth2Params {
    fn from_ref(state: &AppState) -> Self {
        state.oauth2_params.clone()
    }
}

// The user data we'll get back from Google
#[derive(Debug, Serialize, Deserialize)]
struct User {
    family_name: String,
    name: String,
    picture: String,
    email: String,
    given_name: String,
    id: String,
    hd: String,
    verified_email: bool,
}

async fn popup_close() -> impl IntoApiResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Self-closing Page</title>
    <script>
        window.onload = function() {
            localStorage.setItem('popup_status', 'closed');
            window.close();
        }
    </script>
</head>
<body>
    <h1>This window will close automatically...</h1>
</body>
</html>
"#
    .to_string();

    Response::builder()
        .header("Content-Type", "text/html")
        .body(html)
        .unwrap()
}

#[derive(Serialize, Deserialize)]
struct CsrfData {
    csrf_token: String,
    expires_at: DateTime<Utc>,
    user_agent: String,
}

async fn google_auth(
    State(mut params): State<OAuth2Params>,
    State(store): State<MemoryStore>,
    headers: HeaderMap,
) -> Result<impl IntoApiResponse, AppError> {
    let csrf_token = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();

    let expires_at = Utc::now() + Duration::seconds(CSRF_COOKIE_MAX_AGE);

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let csrf_data = CsrfData {
        csrf_token: csrf_token.clone(),
        expires_at,
        user_agent,
    };

    let mut session = Session::new();
    session.insert("csrf_data", csrf_data)?;
    session.set_expiry(expires_at);

    let cloned_session = session.clone();

    let csrf_id = store
        .store_session(session)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to store session"))?;

    params.nonce = Some("some_nonce".to_string());
    params.csrf_token = Some(csrf_token.clone());
    params.state = Some(csrf_token);

    println!("session: {:#?}", cloned_session);
    println!("csrf_id: {:#?}", csrf_id);

    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&nonce={}&prompt={}&access_type={}&response_mode={}",
        params.auth_url,
        params.client_id,
        encode(params.redirect_uri.as_str()),
        encode(params.response_type.as_str()),
        params.scope,
        params.state.as_ref().unwrap(),
        params.nonce.as_ref().unwrap(),
        params.prompt.as_ref().unwrap().as_str(),
        params.access_type.as_ref().unwrap().as_str(),
        params.response_mode.as_ref().unwrap().as_str(),
    );
    // Need to investigate how to use nonce, state, csrf_token.
    println!("Auth URL: {:#?}", auth_url);

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        CSRF_COOKIE_NAME.to_string(),
        csrf_id,
        expires_at,
        CSRF_COOKIE_MAX_AGE,
    )?;

    Ok((headers, Redirect::to(&auth_url)))
    // Ok(Redirect::to(auth_url.as_str()))
}

// Valid user session required. If there is none, redirect to the auth page
async fn protected(user: User) -> impl IntoApiResponse {
    format!("Welcome to the protected area :)\nHere's your info:\n{user:?}")
}

async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoApiResponse, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    delete_session_from_store(cookies, COOKIE_NAME.to_string(), &store).await?;

    Ok((headers, Redirect::to("/")))
}

async fn delete_session_from_store(
    cookies: headers::Cookie,
    cookie_name: String,
    store: &MemoryStore,
) -> Result<(), AppError> {
    let cookie = cookies
        .get(&cookie_name)
        .context("unexpected error getting cookie name")?;

    match store
        .load_session(cookie.to_string())
        .await
        .context("failed to load session")?
    {
        Some(session) => {
            store
                .destroy_session(session)
                .await
                .context("failed to destroy session")?;
        }
        // No session active
        None => (),
    };
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
    _id_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    id_token: Option<String>,
}

async fn login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(params): State<OAuth2Params>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<impl IntoApiResponse, AppError> {
    println!("Query: {:#?}", query);
    println!("code: {:#?}", query.code);
    println!("Params: {:#?}", params);

    validate_origin(&headers, &params.auth_url).await?;
    csrf_checks(cookies.clone(), &store, &query, headers).await?;

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    delete_session_from_store(cookies, CSRF_COOKIE_NAME.to_string(), &store).await?;

    let (access_token, id_token) = exchange_code_for_token(params, query.code).await?;
    println!("Access Token: {:#?}", access_token);
    println!("ID Token: {:#?}", id_token);

    let user_data = fetch_user_data_from_google(access_token).await?;

    let max_age = COOKIE_MAX_AGE;
    let expires_at = Utc::now() + Duration::seconds(max_age);
    let session_id = create_and_store_session(user_data, &store, expires_at).await?;
    header_set_cookie(
        &mut headers,
        COOKIE_NAME.to_string(),
        session_id,
        expires_at,
        max_age,
    )?;
    // println!("Headers: {:#?}", headers);

    Ok((headers, Redirect::to("/popup_close")))
}

async fn validate_origin(headers: &HeaderMap, auth_url: &str) -> Result<(), AppError> {
    let parsed_url = Url::parse(&auth_url).expect("Invalid URL");
    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or_default();
    let port = parsed_url
        .port()
        .map_or("".to_string(), |p| format!(":{}", p));
    let expected_origin = format!("{}://{}{}", scheme, host, port);

    let origin = headers
        .get("Origin")
        .or_else(|| headers.get("Referer"))
        .and_then(|h| h.to_str().ok());

    match origin {
        Some(origin) if origin.starts_with(&expected_origin) => Ok(()),
        _ => Err(anyhow::anyhow!("Invalid origin").into()),
    }
}

async fn csrf_checks(
    cookies: headers::Cookie,
    store: &MemoryStore,
    query: &AuthRequest,
    headers: HeaderMap,
) -> Result<(), AppError> {
    let csrf_id = cookies
        .get(CSRF_COOKIE_NAME)
        .ok_or_else(|| anyhow::anyhow!("No session cookie found"))?;
    let session = store
        .load_session(csrf_id.to_string())
        .await?
        .ok_or_else(|| anyhow::anyhow!("CSRF Session not found"))?;
    println!("CSRF ID: {:#?}", csrf_id);
    println!("Session: {:#?}", session);
    let csrf_data: CsrfData = session
        .get("csrf_data")
        .ok_or_else(|| anyhow::anyhow!("No CSRF data in session"))?;
    if query.state != csrf_data.csrf_token {
        return Err(anyhow::anyhow!("CSRF token mismatch").into());
    }
    println!("CSRF token: {:#?}", csrf_data.csrf_token);
    println!("State: {:#?}", query.state);
    if Utc::now() > csrf_data.expires_at {
        return Err(anyhow::anyhow!("CSRF token expired").into());
    }
    println!("Now: {:#?}", Utc::now());
    println!("CSRF token expires at: {:#?}", csrf_data.expires_at);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    if user_agent != csrf_data.user_agent {
        // return Err(anyhow::anyhow!("User agent mismatch").into());
        return Err(anyhow::anyhow!("Funny thing happend").into());
    }
    println!("User agent: {:#?}", user_agent);
    println!("CSRF user agent: {:#?}", csrf_data.user_agent);
    Ok(())
}

fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, AppError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );
    Ok(headers)
}

async fn create_and_store_session(
    user_data: User,
    store: &MemoryStore,
    expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed in inserting serialized value into session")?;
    session.set_expiry(expires_at);
    println!("Session: {:#?}", session);
    let session_id = store
        .store_session(session)
        .await
        .context("failed to store session")?
        .context("unexpected error retrieving cookie value")?;
    Ok(session_id)
}

async fn fetch_user_data_from_google(access_token: String) -> Result<User, AppError> {
    let response = reqwest::Client::new()
        .get("https://www.googleapis.com/userinfo/v2/me")
        .bearer_auth(access_token)
        .send()
        .await
        .context("failed in sending request to target Url")?;
    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    let user_data: User =
        serde_json::from_str(&response_body).context("failed to deserialize response body")?;
    println!("User data: {:#?}", user_data);
    Ok(user_data)
}

async fn exchange_code_for_token(
    params: OAuth2Params,
    code: String,
) -> Result<(String, String), AppError> {
    let response = reqwest::Client::new()
        .post(params.token_url)
        .form(&[
            ("code", code),
            ("client_id", params.client_id.clone()),
            ("client_secret", params.client_secret.clone()),
            ("redirect_uri", params.redirect_uri.clone()),
            ("grant_type", "authorization_code".to_string()),
        ])
        .send()
        .await
        .context("failed in sending request request to authorization server")?;
    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    let response_json: OidcTokenResponse =
        serde_json::from_str(&response_body).context("failed to deserialize response body")?;
    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();
    println!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        // Redirect::temporary("/auth/google").into_response()
        Redirect::temporary("/").into_response()
    }
}

impl IntoApiResponse for AuthRedirect {
    fn into_api_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        println!("Retrieving cookies");
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {e}"),
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;
        // println!("Cookies: {:#?}", cookies);
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        // Retrieve session from store
        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        // println!("Loaded Session: {:#?}", session);
        // Retrieve user data from session
        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);

        // (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
        let message = self.0.to_string();
        (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
    }
}

impl OperationOutput for AppError {
    type Inner = Self;

    fn operation_response(
        &mut self,
        _gen: &mut aide::gen::GenContext,
        _op: &mut aide::openapi::Operation,
    ) -> Option<aide::openapi::Response> {
        tracing::error!("Application error: {:#}", self.0);

        // (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
        let message = self.0.to_string();
        Some((StatusCode::INTERNAL_SERVER_ERROR, message).into_response())
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}