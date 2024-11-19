/// This module handles Google OAuth2 authentication for an Axum web application.
/// It provides routes for initiating the OAuth2 flow, handling the authorization response,
/// and closing the authentication popup window.
///
/// The main components of this module are:
/// - `create_router`: Sets up the API routes for the OAuth2 flow.
/// - `app_state_init`: Initializes the application state with OAuth2 parameters and session store.
/// - `google_auth`: Initiates the OAuth2 flow by redirecting the user to Google's authorization endpoint.
/// - `get_authorized` and `post_authorized`: Handle the authorization response from Google.
/// - `authorized`: Exchanges the authorization code for tokens and verifies the ID token.
/// - `popup_close`: Closes the authentication popup window.
///
/// The module also defines several enums and structs to represent OAuth2 parameters and responses:
/// - `OAuth2ResponseMode`: Enum representing the response mode for OAuth2.
/// - `Prompt`: Enum representing the prompt parameter for OAuth2.
/// - `AccessType`: Enum representing the access type for OAuth2.
/// - `ResponseType`: Enum representing the response type for OAuth2.
/// - `OAuth2Params`: Struct representing the OAuth2 parameters.
/// - `AppState`: Struct representing the application state.
/// - `User`: Struct representing the user data returned by Google.
/// - `CsrfData`: Struct representing CSRF token data.
/// - `AuthRequest`: Struct representing the authorization request.
/// - `OidcTokenResponse`: Struct representing the token response from Google.
///
/// The module also defines several helper functions:
/// - `validate_origin`: Validates the origin of the request.
/// - `csrf_checks`: Performs CSRF checks.
/// - `header_set_cookie`: Sets a cookie in the response headers.
/// - `fetch_user_data_from_google`: Fetches user data from Google using the access token.
/// - `exchange_code_for_token`: Exchanges the authorization code for tokens.
///
/// Error handling is done using the `AppError` enum, which defines various error types:
/// - `SessionError`: Error related to session handling.
/// - `AuthError`: Error related to authentication.
/// - `NetworkError`: Error related to network requests.
/// - `SerializationError`: Error related to serialization.
/// - `UnexpectedError`: Catch-all for unexpected errors.
///
/// The module uses the `aide` crate for API documentation and the `axum` crate for web framework functionality.
use aide::{
    axum::{routing::get_with, ApiRouter, IntoApiResponse},
    OperationOutput,
};

use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    extract::{Form, FromRef, Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{headers, TypedHeader};
use http::StatusCode;

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use url::Url;

use chrono::{DateTime, Duration, Utc};
use rand::{thread_rng, Rng};
use urlencoding::encode;

use super::{
    auth::hash_nonce,
    auth::new_session,
    idtoken::verify_idtoken,
    models::Error,
    settings::{
        CSRF_COOKIE_MAX_AGE, CSRF_COOKIE_NAME, GOOGLE_OAUTH2_CLIENT_ID,
        GOOGLE_OAUTH2_CLIENT_SECRET, NONCE_COOKIE_MAX_AGE, NONCE_COOKIE_NAME, OAUTH2_AUTH_URL,
        OAUTH2_RESPONSE_MODE, OAUTH2_RESPONSE_TYPE, OAUTH2_SCOPE, OAUTH2_TOKEN_URL, ORIGIN_SERVER,
    },
    user::get_or_create_user,
    AppState as CrateAppState,
};

pub fn create_router(crate_app_state: Arc<CrateAppState>) -> ApiRouter {
    let app_state = app_state_init(crate_app_state);

    ApiRouter::new()
        .api_route("/", get_with(google_auth, |op| op.tag("auth")))
        .api_route(
            "/authorized",
            get_with(get_authorized, |op| op.tag("auth"))
                .post_with(post_authorized, |op| op.tag("auth")),
        )
        .api_route("/popup_close", get_with(popup_close, |op| op.tag("auth")))
        .with_state(app_state)
}

fn app_state_init(crate_app_state: Arc<CrateAppState>) -> AppState {
    let store = MemoryStore::new();

    let oauth2_params = OAuth2Params {
        client_id: GOOGLE_OAUTH2_CLIENT_ID.to_string(),
        client_secret: GOOGLE_OAUTH2_CLIENT_SECRET.to_string(),
        redirect_uri: format!("{}/oauth2/google/authorized", *ORIGIN_SERVER),
        auth_url: OAUTH2_AUTH_URL.to_string(),
        token_url: OAUTH2_TOKEN_URL.to_string(),
        response_type: OAUTH2_RESPONSE_TYPE.parse().unwrap_or(ResponseType::Code),
        scope: OAUTH2_SCOPE.to_string(),
        nonce: None,
        state: None,
        csrf_token: None,
        response_mode: Some(
            OAUTH2_RESPONSE_MODE
                .parse()
                .unwrap_or(OAuth2ResponseMode::Query),
        ),
        prompt: Some(Prompt::Consent),         // "consent",
        access_type: Some(AccessType::Online), // "online",
    };

    AppState {
        store,
        oauth2_params,
        crate_app_state,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum OAuth2ResponseMode {
    Query,
    Fragment,
    FormPost,
}

impl OAuth2ResponseMode {
    fn as_str(&self) -> &str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }
}

impl std::str::FromStr for OAuth2ResponseMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(OAuth2ResponseMode::Query),
            "form_post" => Ok(OAuth2ResponseMode::FormPost),
            "fragment" => Ok(OAuth2ResponseMode::Fragment),
            _ => Err(format!("Invalid value for OAuth2ResponseMode: {}", s)),
        }
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Clone)]
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

impl std::str::FromStr for ResponseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(ResponseType::None),
            "code" => Ok(ResponseType::Code),
            "token" => Ok(ResponseType::Token),
            "id_token" => Ok(ResponseType::IdToken),
            "code token" => Ok(ResponseType::CodeToken),
            "token code" => Ok(ResponseType::CodeToken),
            "code id_token" => Ok(ResponseType::CodeIdToken),
            "id_token code" => Ok(ResponseType::CodeIdToken),
            "token id_token" => Ok(ResponseType::TokenIdToken),
            "id_token token" => Ok(ResponseType::TokenIdToken),
            "code token id_token" => Ok(ResponseType::CodeTokenIdToken),
            "code id_token token" => Ok(ResponseType::CodeTokenIdToken),
            "token code id_token" => Ok(ResponseType::CodeTokenIdToken),
            "token id_token code" => Ok(ResponseType::CodeTokenIdToken),
            "id_token token code" => Ok(ResponseType::CodeTokenIdToken),
            "id_token code token" => Ok(ResponseType::CodeTokenIdToken),
            _ => Err(format!("Invalid value for ResponseType: {}", s)),
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
    response_type: ResponseType,
    scope: String,
    nonce: Option<String>,
    state: Option<String>,
    csrf_token: Option<String>,
    response_mode: Option<OAuth2ResponseMode>,
    // response_mode: Option<String>,
    prompt: Option<Prompt>,
    access_type: Option<AccessType>,
}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    oauth2_params: OAuth2Params,
    crate_app_state: Arc<CrateAppState>,
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
    hd: Option<String>,
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

    let expires_at = Utc::now() + Duration::seconds(*CSRF_COOKIE_MAX_AGE);

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
    let _ = session.insert("csrf_data", csrf_data);

    session.set_expiry(expires_at);

    let cloned_session = session.clone();

    let csrf_id = match store.store_session(session).await {
        Ok(id) => id,
        Err(e) => {
            return Err(AppError::SessionError(format!(
                "Failed to store session: {:#?}",
                e
            )));
        }
    };

    let nonce = thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();

    params.nonce = Some(nonce.clone());
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
        csrf_id.unwrap_or_default(),
        expires_at,
        *CSRF_COOKIE_MAX_AGE,
    )?;

    let hashed_nonce = hash_nonce(nonce.as_str());
    let expires_at = Utc::now() + Duration::seconds(*NONCE_COOKIE_MAX_AGE);

    header_set_cookie(
        &mut headers,
        NONCE_COOKIE_NAME.to_string(),
        hashed_nonce,
        expires_at,
        *NONCE_COOKIE_MAX_AGE,
    )?;

    Ok((headers, Redirect::to(&auth_url)))
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Serialize)]
struct AuthRequest {
    code: String,
    state: String,
    // id_token: Option<String>,
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

async fn post_authorized(
    State(params): State<OAuth2Params>,
    State(state): State<AppState>,
    // State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthRequest>,
) -> Result<impl IntoApiResponse, AppError> {
    // println!("Form: {:#?}", form);
    // println!("code: {:#?}", form.code);
    // println!("Params: {:#?}", params);
    println!("Cookies: {:#?}", cookies.get(CSRF_COOKIE_NAME));

    validate_origin(&headers, &params.auth_url).await?;
    // csrf_checks(cookies.clone(), &store, &query, headers).await?;

    authorized(form.code.clone(), params, state).await
}

async fn get_authorized(
    Query(query): Query<AuthRequest>,
    State(params): State<OAuth2Params>,
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<impl IntoApiResponse, AppError> {
    // println!("Query: {:#?}", query);
    // println!("code: {:#?}", query.code);
    // println!("Params: {:#?}", params);
    // println!("Cookies: {:#?}", cookies.get(CSRF_COOKIE_NAME));

    validate_origin(&headers, &params.auth_url).await?;
    csrf_checks(cookies.clone(), &state.store, &query, headers).await?;

    authorized(query.code.clone(), params, state).await
}

async fn authorized(
    code: String,
    params: OAuth2Params,
    state: AppState,
) -> Result<impl IntoApiResponse, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    let client_id = params.client_id.clone();
    let (access_token, id_token) = exchange_code_for_token(params, code).await?;
    println!("Access Token: {:#?}", access_token);
    println!("ID Token: {:#?}", id_token);

    let idinfo = match verify_idtoken(id_token, client_id).await {
        Ok(idinfo) => {
            // let _ = verify_nonce(&header, &idinfo);
            // let _ = verify_nonce(jar.clone(), &idinfo);

            println!("idinfo: {:?}", idinfo);
            idinfo
        }
        Err(e) => {
            let message = Error {
                error: format!("Error verifying token: {:?}", e),
            };
            println!("{}", message.error);
            return Err(AppError::AuthError(message.error));
        }
    };

    let user_info = fetch_user_data_from_google(access_token).await?;
    println!("User Info: {:#?}", user_info);

    if idinfo.sub != user_info.id
        || idinfo.email != user_info.email
        || idinfo.name != user_info.name
        || idinfo.picture != Some(user_info.picture.clone())
    {
        let message = Error {
            error: format!("IdToken/UserInfo mismatch: {:?}", idinfo),
        };
        println!("{}", message.error);
        return Err(AppError::AuthError(message.error));
    }

    let user_data = crate::models::User {
        id: None,
        sub: user_info.id.clone(),
        email: user_info.email.clone(),
        name: user_info.name.clone(),
        picture: Some(user_info.picture.clone()),
        enabled: Some(true),
        admin: Some(false),
    };

    let user = match get_or_create_user(state.crate_app_state.pool.clone(), user_data.clone()).await
    {
        Ok(user) => user,
        Err(e) => {
            let message = Error {
                error: format!("Error getting/creating user: {:?}", e),
            };
            println!("{}", message.error);
            return Err(AppError::AuthError(message.error));
        }
    };

    let jar = match new_session(user, state.crate_app_state).await {
        Ok(jar) => jar,
        Err(e) => {
            let message = Error {
                error: format!("Error creating session: {:?}", e),
            };
            println!("{}", message.error);
            return Err(AppError::AuthError(message.error));
        }
    };

    Ok((jar, Redirect::to("/oauth2/google/popup_close")))
}

async fn validate_origin(headers: &HeaderMap, auth_url: &str) -> Result<(), AppError> {
    let parsed_url = Url::parse(auth_url).expect("Invalid URL");
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
        _ => Err(AppError::AuthError("Invalid origin".to_string())),
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
        .ok_or_else(|| AppError::AuthError("No CSRF cookie found".to_string()))?;

    let session = match store
        .load_session(csrf_id.to_string())
        .await
        .map_err(|e| AppError::SessionError(format!("Failed to load session: {:#?}", e)))?
    {
        Some(session) => {
            // Taken from delete_session_from_store
            // if session relaed to csrf_id is found, destroy it immediately, since it's a one-time use.
            store.destroy_session(session.clone()).await.map_err(|e| {
                AppError::SessionError(format!("Failed to destroy session: {:#?}", e))
            })?;

            session
        }
        None => {
            return Err(AppError::AuthError("No CSRF session found".to_string()));
        }
    };

    println!("CSRF ID: {:#?}", csrf_id);
    println!("Session: {:#?}", session);

    let csrf_data: CsrfData = session
        .get("csrf_data")
        .ok_or_else(|| AppError::AuthError("No CSRF data found".to_string()))?;

    if query.state != csrf_data.csrf_token {
        return Err(AppError::AuthError(("CSRF token mismatch").to_string()));
    }
    println!("CSRF token: {:#?}", csrf_data.csrf_token);
    println!("State: {:#?}", query.state);

    if Utc::now() > csrf_data.expires_at {
        return Err(AppError::AuthError(("CSRF token expired").to_string()));
    }
    println!("Now: {:#?}", Utc::now());
    println!("CSRF token expires at: {:#?}", csrf_data.expires_at);

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    if user_agent != csrf_data.user_agent {
        return Err(AppError::AuthError(("User agent mismatch").to_string()));
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
        cookie
            .parse()
            .map_err(|e| AppError::UnexpectedError(format!("{:#?}", e)))?,
    );
    Ok(headers)
}

async fn fetch_user_data_from_google(access_token: String) -> Result<User, AppError> {
    let response = reqwest::Client::new()
        .get("https://www.googleapis.com/userinfo/v2/me")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| AppError::NetworkError(e.to_string()))?;

    let response_body = response
        .text()
        .await
        .map_err(|e| AppError::NetworkError(e.to_string()))?;

    let user_data: User = serde_json::from_str(&response_body)
        .map_err(|e| AppError::SerializationError(e.to_string()))?;

    // println!("User data: {:#?}", user_data);

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
        .map_err(|e| AppError::NetworkError(e.to_string()))?;

    let response_body = response
        .text()
        .await
        .map_err(|e| AppError::NetworkError(e.to_string()))?;

    let response_json: OidcTokenResponse = serde_json::from_str(&response_body)
        .map_err(|e| AppError::SerializationError(e.to_string()))?;

    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();

    println!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

impl OperationOutput for AuthRedirect {
    type Inner = Self;
    fn operation_response(
        _gen: &mut aide::gen::GenContext,
        _operation: &mut aide::openapi::Operation,
    ) -> Option<aide::openapi::Response> {
        Some(aide::openapi::Response::default())
    }
}

use thiserror::Error;

#[derive(Error, Debug, Serialize)]
pub enum AppError {
    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Network error: {0}")]
    // NetworkError(#[from] reqwest::Error),
    NetworkError(String),

    #[error("Serialization error: {0}")]
    // SerializationError(#[from] serde_json::Error),
    SerializationError(String),

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
    // Add other error variants as needed
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {}", self);
        let message = self.to_string();
        (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
    }
}

impl OperationOutput for AppError {
    type Inner = Self;
    fn operation_response(
        _gen: &mut aide::gen::GenContext,
        _operation: &mut aide::openapi::Operation,
    ) -> Option<aide::openapi::Response> {
        Some(aide::openapi::Response::default())
    }
}
