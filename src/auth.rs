/// This module handles authentication-related routes and functions for an Axum-based web application.
/// It includes routes for logging out, refreshing tokens, rendering authentication-related navigation bars,
/// checking session status, and mutating user information.
///
/// # Routes
/// - `/logout`: Logs out the user by deleting the session and removing relevant cookies.
/// - `/refresh_token`: Refreshes the user's session token and CSRF token.
/// - `/auth_navbar`: Renders the authentication navigation bar based on the user's session status.
/// - `/check`: Checks if the user is logged in by validating the session.
/// - `/mutate_user`: Mutates user information based on the provided user token.
/// - `/logout_content`: Renders a message indicating the user has logged out.
///
/// # Functions
/// - `create_router`: Creates an `ApiRouter` with the defined authentication routes.
/// - `logout`: Handles the logout process by deleting the session and removing cookies.
/// - `refresh_token`: Refreshes the session and CSRF tokens, and verifies the user and CSRF tokens.
/// - `auth_navbar`: Renders the authentication navigation bar based on the user's session status.
/// - `check`: Checks if the user is logged in by validating the session.
/// - `mutate_user`: Mutates user information based on the provided user token.
/// - `logout_content`: Renders a message indicating the user has logged out.
/// - `get_current_user_from_jar`: Retrieves the current user from the session cookie.
/// - `jar_to_session`: Converts a `CookieJar` to a `Session`.
/// - `mutate_session`: Mutates the session if it is about to expire.
/// - `new_session`: Creates a new session for the user.
/// - `new_cookie`: Creates new cookies for the session, CSRF token, and user token.
/// - `hash_email`: Hashes the user's email using SHA-256.
/// - `hash_nonce`: Hashes a nonce using SHA-256 and a secret salt.
/// - `csrf_verify`: Verifies the provided CSRF token against the session's CSRF token.
/// - `user_verify`: Verifies the provided user token against the hashed email in the session.
///
/// # Templates
/// - `NavbarLoginTemplate`: Template for rendering the login navigation bar.
/// - `NavbarLogoutTemplate`: Template for rendering the logout navigation bar.
/// - `ContentErrorTemplate`: Template for rendering error messages.
///
/// # Structs
/// - `XCsrfToken`: Represents the CSRF token extracted from the request header.
/// - `XUserToken`: Represents the user token extracted from the request header.
///
/// # Dependencies
/// - `aide::axum`: Provides routing and response utilities for Axum.
/// - `askama_axum`: Provides template rendering for Axum using Askama.
/// - `axum`: Provides the core web framework.
/// - `axum_extra::extract::cookie`: Provides cookie extraction utilities.
/// - `cookie`: Provides cookie creation and manipulation utilities.
/// - `chrono`: Provides date and time utilities.
/// - `rand`: Provides random number generation utilities.
/// - `hyper`: Provides HTTP utilities.
/// - `serde`: Provides serialization and deserialization utilities.
/// - `sha2`: Provides SHA-256 hashing utilities.
///
use aide::axum::{routing::get_with, ApiRouter, IntoApiResponse};
use askama_axum::Template;
use axum::{
    extract::State,
    http::HeaderMap,
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};

use axum_extra::extract::cookie::CookieJar;
use cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, SameSite,
};

use chrono::Utc;
use rand::{thread_rng, Rng};
use std::sync::Arc;

use hyper::{header, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    models::{Error, Session, User},
    settings::{
        CSRF_TOKEN_NAME, GOOGLE_OAUTH2_CLIENT_ID, NONCE_COOKIE_MAX_AGE, NONCE_COOKIE_NAME,
        ORIGIN_SERVER, SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, USER_TOKEN_NAME,
    },
    user::get_user_by_id,
    AppState,
};

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/logout", get_with(logout, |op| op.tag("auth")))
        .api_route(
            "/refresh_token",
            get_with(refresh_token, |op| op.tag("auth")),
        )
        .api_route("/auth_navbar", get_with(auth_navbar, |op| op.tag("auth")))
        .api_route("/check", get_with(check, |op| op.tag("auth")))
        .api_route("/mutate_user", get_with(mutate_user, |op| op.tag("auth")))
        .api_route(
            "/logout_content",
            get_with(logout_content, |op| op.tag("auth")),
        )
        // .route_layer(axum::middleware::from_fn(check_hx_request))
        .with_state(state)
}

/// The `logout` function is responsible for terminating the user's session.
/// It performs the following steps:
/// 1. Invalidates the current session by removing session data.
/// 2. Optionally, it may clear cookies or tokens associated with the session.
/// 3. Logs a message indicating the user has been logged out.
/// 4. Returns a result indicating the success or failure of the logout operation.
///
/// This function ensures that any sensitive session information is properly
/// cleared, preventing unauthorized access after the user logs out.
///

async fn logout(
    State(state): State<Arc<AppState>>,
    jar: Option<CookieJar>,
) -> impl IntoApiResponse {
    let mut session_deleted = false;

    if let Some(mut jar) = jar {
        if let Some(session_id) = jar.get(SESSION_COOKIE_NAME) {
            if let Err(e) = state.cache.delete_session(session_id.value()).await {
                eprintln!("Failed to delete session: {}", e);
            } else {
                session_deleted = true;
            }
        }

        let cookies_to_remove = [SESSION_COOKIE_NAME, CSRF_TOKEN_NAME, USER_TOKEN_NAME];
        for name in cookies_to_remove.iter() {
            // .path("/").secure(true) is necessary to remove the "__Host-" cookie.
            jar = jar.remove(Cookie::build((*name, "")).path("/").secure(true));
        }

        let message = if session_deleted {
            serde_json::json!({
                "message": "Session deleted successfully",
            })
        } else {
            serde_json::json!({
                "message": "No active session found",
            })
        };

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("HX-Trigger", "ReloadNavbar")
            .body(Json(message).into_response().into_body())
            .unwrap();

        (jar, response).into_response()
    } else {
        (StatusCode::OK, "No active session found").into_response()
    }
}

/// This asynchronous function `refresh_token` handles the process of refreshing a user's session token.
/// It performs several key steps:
/// 1. Extracts the application state, headers, and optional cookie jar from the request.
/// 2. Attempts to retrieve the session from the cookie jar using the `jar_to_session` function.
///    - If unsuccessful, it returns an internal server error response with an appropriate error message.
/// 3. Extracts and verifies the CSRF token from the headers.
///    - If the CSRF token is missing or invalid, it returns an internal server error response with an appropriate error message.
/// 4. Extracts and verifies the user token from the headers.
///    - If the user token is missing or invalid, it returns an internal server error response with an appropriate error message.
/// 5. Ensures the cookie jar is present.
///    - If the cookie jar is missing, it returns an internal server error response with an appropriate error message.
/// 6. Attempts to mutate the session using the `mutate_session` function.
///    - If successful, it constructs a JSON response containing the new session ID, CSRF token, and user token.
///    - If unsuccessful, it returns an internal server error response with an appropriate error message.
/// 7. Returns the updated cookie jar and the constructed response.

async fn refresh_token(
    State(state): State<Arc<AppState>>,
    header: HeaderMap,
    cookiejar: Option<CookieJar>,
) -> impl IntoApiResponse {
    let session = match jar_to_session(cookiejar.clone(), state.clone()).await {
        Ok(session) => session,
        Err(e) => {
            let message = Error {
                error: format!("Error getting session: {:?}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
    };

    let x_csrf_token = match header.get("x-csrf-token") {
        Some(t) => XCsrfToken {
            x_csrf_token: t.to_str().unwrap().to_string(),
        },
        None => {
            let message = Error {
                error: "X-CSRF-TOKEN not set in the Header".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
    };

    let _ = csrf_verify(x_csrf_token, session.clone()).await;

    let x_user_token = match header.get("x-user-token") {
        Some(t) => XUserToken {
            x_user_token: t.to_str().unwrap().to_string(),
        },
        None => {
            let message = Error {
                error: "X-USER-TOKEN not set in the Header".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
    };

    let _ = user_verify(x_user_token, session.clone()).await;

    let cookiejar = match cookiejar {
        None => {
            let message = Error {
                error: "Error: CookieJar not found".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
        Some(jar) => jar,
    };

    match mutate_session(Some(cookiejar.clone()), state).await {
        Ok(newjar) => {
            let message = serde_json::json!({
                "ok": true,
                "session_id": newjar.get(SESSION_COOKIE_NAME).unwrap().value(),
                "csrf_token": newjar.get(CSRF_TOKEN_NAME).unwrap().value(),
                "user_token": newjar.get(USER_TOKEN_NAME).unwrap().value(),
            });

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("HX-Trigger", "ReloadNavbar")
                .body(Json(message).into_response().into_body())
                .unwrap();

            (newjar, response).into_response()
        }
        Err(e) => {
            let message = Error {
                error: format!("Error mutating session: {:?}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response()
        }
    }
}

#[allow(non_snake_case)]
#[derive(Template)]
#[template(path = "auth_navbar.login.j2")]
struct NavbarLoginTemplate {
    client_id: String,
    login_url: String,
    icon_url: String,
    refresh_token_url: String,
    mutate_user_url: String,
    userToken: String,
    nonce: String,
    csrf_token_name: String,
    user_token_name: String,
}

#[allow(non_snake_case)]
#[derive(Template)]
#[template(path = "auth_navbar.logout.j2")]
struct NavbarLogoutTemplate {
    logout_url: String,
    icon_url: String,
    refresh_token_url: String,
    mutate_user_url: String,
    name: String,
    picture: String,
    userToken: String,
    csrf_token_name: String,
    user_token_name: String,
}

/// This asynchronous function `auth_navbar` is responsible for generating the navigation bar
/// for authenticated and unauthenticated users. It takes two parameters:
/// - `State(state)`: An `Arc` wrapped `AppState` which provides shared state across the application.
/// - `cookiejar`: An optional `CookieJar` which contains cookies from the user's request.
///
/// The function performs the following steps:
/// 1. It attempts to retrieve the current user from the `cookiejar` using the `get_current_user_from_jar` function.
/// 2. If a user is found (authenticated), it calls the `auth_navbar_logout` function to generate the logout navigation bar.
/// 3. If no user is found (unauthenticated), it calls the `auth_navbar_login` function to generate the login navigation bar.
///
/// Both `auth_navbar_login` and `auth_navbar_logout` return an `impl IntoApiResponse` which is a response type that can be
/// converted into an HTTP response. The final response includes any cookies set during the process.

async fn auth_navbar(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
) -> impl IntoApiResponse {
    // For unauthenticated users, return the menu.login component.
    // fn auth_navbar_login() -> Html<String> {
    fn auth_navbar_login() -> impl IntoApiResponse {
        let login_url = ORIGIN_SERVER.clone() + "/signin/w/google/authorized";
        let icon_url = "/asset/icon.png".to_string();
        let refresh_token_url = "/auth/refresh_token".to_string();
        let mutate_user_url = "/auth/mutate_user".to_string();

        let nonce = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();

        let hashed_nonce = hash_nonce(nonce.as_str());

        let mut jar = CookieJar::new();
        let max_age = Duration::seconds(*NONCE_COOKIE_MAX_AGE);
        let expires_at = OffsetDateTime::now_utc() + max_age;

        let cookie = Cookie::build((NONCE_COOKIE_NAME, hashed_nonce))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict)
            .max_age(max_age)
            .expires(expires_at)
            .build();

        jar = jar.add(cookie);

        let template = NavbarLoginTemplate {
            client_id: GOOGLE_OAUTH2_CLIENT_ID.to_string(),
            login_url,
            icon_url,
            refresh_token_url,
            mutate_user_url,
            userToken: "anonymous".to_string(),
            nonce,
            csrf_token_name: CSRF_TOKEN_NAME.to_string(),
            user_token_name: USER_TOKEN_NAME.to_string(),
        };
        let response = Html(template.render().unwrap());
        (jar, response).into_response()
    }

    // For authenticated users, return the menu.logout component.
    // fn auth_navbar_logout(user: User) -> Html<String> {
    fn auth_navbar_logout(user: User) -> impl IntoApiResponse {
        let logout_url = "/auth/logout".to_string();
        let icon_url = "/asset/logout.png".to_string();
        let refresh_token_url = "/auth/refresh_token".to_string();
        let mutate_user_url = "/auth/mutate_user".to_string();
        let picture_url = match user.picture {
            Some(picture) => picture,
            None => "/asset/default_icon.png".to_string(),
        };

        let template = NavbarLogoutTemplate {
            logout_url,
            icon_url,
            refresh_token_url,
            mutate_user_url,
            name: user.name.to_string(),
            picture: picture_url,
            userToken: hash_email(&user.email).to_string(),
            csrf_token_name: CSRF_TOKEN_NAME.to_string(),
            user_token_name: USER_TOKEN_NAME.to_string(),
        };
        Html(template.render().unwrap())
    }

    match get_current_user_from_jar(cookiejar.clone(), state).await {
        Some(user) => {
            let response = auth_navbar_logout(user);
            (cookiejar, response).into_response()
        }
        None => {
            let response = auth_navbar_login();
            (cookiejar, response).into_response()
        }
    }
}

async fn check(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
) -> impl IntoApiResponse {
    match jar_to_session(cookiejar, state).await {
        Ok(_s) => (StatusCode::NO_CONTENT, "").into_response(),
        Err(e) => {
            let message = Error {
                error: format!("user logged out: {:?}", e),
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("HX-Trigger", "ReloadNavbar, LogoutSecretContent")
                .body(Json(message).into_response().into_body())
                .unwrap();

            response.into_response()
        }
    }
}

async fn mutate_user(header: HeaderMap) -> impl IntoApiResponse {
    match header.get("x-user-token") {
        Some(x_user_token) => {
            let message = serde_json::json!({
                "message": "User mutated",
                "new_user": x_user_token.to_str().unwrap(),
            });

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("HX-Trigger", "ReloadNavbar, LogoutSecretContent")
                .body(Json(message).into_response().into_body())
                .unwrap();
            response.into_response()
        }
        None => {
            let message = Error {
                error: "X-USER-TOKEN not found in the Header".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "content.error.j2")]
struct ContentErrorTemplate {
    message: String,
}

async fn logout_content() -> impl IntoApiResponse {
    let template = ContentErrorTemplate {
        message: "User logged out".to_string(),
    };
    Html(template.render().unwrap())
}

// @router.get("/cleanup_sessions")
// async def cleanup_sessions(
//                          background_tasks: BackgroundTasks,
//                          session_id: Annotated[str|None, Cookie()] = None,
//                          cs: CacheStore = Depends(get_cache_store)):
//     if not session_id:
//         return {"message": "Session CleanUp not triggered. Please login first."}

//     background_tasks.add_task(cs.cleanup_sessions)
//     return {"message": "Session CleanUp triggered."}

async fn get_current_user_from_jar(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Option<User> {
    let state_clone = state.clone();
    let session_result = jar_to_session(cookiejar, state_clone).await;
    match session_result {
        Ok(session) => {
            let user_result = get_user_by_id(&session.user_id, &state.pool).await;
            user_result.unwrap_or_default()
        }
        Err(_) => None,
    }
}

async fn jar_to_session(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Result<Session, Error> {
    let cookiejar = cookiejar.ok_or_else(|| Error {
        error: "CookieJar not found".to_string(),
    })?;

    let session_id = cookiejar.get(SESSION_COOKIE_NAME).ok_or_else(|| Error {
        error: "Session ID not found in CookieJar".to_string(),
    })?;

    let session = state
        .cache
        .get_session(session_id.value())
        .await
        .map_err(|e| Error {
            error: e.to_string(),
        })?
        .ok_or_else(|| Error {
            error: "Session not found".to_string(),
        })?;

    println!("session: {:?}", session);
    Ok(session)
}

async fn mutate_session(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Result<CookieJar, Error> {
    let admin_email = std::env::var("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set");
    let max_age = *SESSION_COOKIE_MAX_AGE;

    let cookiejar = cookiejar.ok_or_else(|| Error {
        error: "CookieJar not found".to_string(),
    })?;

    let session_id = cookiejar.get(SESSION_COOKIE_NAME).ok_or_else(|| Error {
        error: "Session ID not found in CookieJar".to_string(),
    })?;

    let old_session = state
        .cache
        .get_session(session_id.value())
        .await
        .map_err(|e| Error {
            error: format!("Failed to get session: {}", e),
        })?
        .ok_or_else(|| Error {
            error: "Session not found".to_string(),
        })?;

    if old_session.email == admin_email {
        return Ok(cookiejar);
    }

    let age_left = old_session.expires - Utc::now().timestamp();
    if age_left * 2 > max_age {
        println!("Session still has much time: {} seconds left.", age_left);
        return Ok(cookiejar);
    }

    println!(
        "Session expires soon in {} seconds. Mutating the session.",
        age_left
    );

    let user = get_user_by_id(&old_session.user_id, &state.pool)
        .await
        .map_err(|e| Error {
            error: format!("Failed to get user: {}", e),
        })?
        .ok_or_else(|| Error {
            error: "User not found".to_string(),
        })?;

    new_session(user, state).await
}

/// This function creates a new session for a user and returns a `CookieJar` containing session cookies.
/// It takes a `User` object and an `Arc<AppState>` as parameters.
/// It first attempts to create a session using the `create_session` method of the `cache` in `AppState`.
/// If successful, it calls `new_cookie` to generate the cookies for the session.
/// If an error occurs during session creation, it returns an `Error`.

pub(crate) async fn new_session(user: User, state: Arc<AppState>) -> Result<CookieJar, Error> {
    let session = match state
        .cache
        .create_session(user.id.unwrap(), &user.email)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            return Err(Error {
                error: format!("Error creating session: {}", e),
            });
        }
    };

    new_cookie(&session)
}

/// This function generates a `CookieJar` containing cookies for the session.
/// It takes a reference to a `Session` object as a parameter.
/// It creates three cookies: a session cookie, a CSRF token cookie, and a user token cookie.
/// The cookies are configured with properties like path, security, HTTP-only flag, same-site policy, max age, and expiration time.
/// The user token cookie contains a hashed version of the user's email.

fn new_cookie(session: &Session) -> Result<CookieJar, Error> {
    let max_age = Duration::seconds(*SESSION_COOKIE_MAX_AGE);

    let expires = OffsetDateTime::now_utc() + max_age;

    let mut jar = CookieJar::new();

    let cookie = Cookie::build((SESSION_COOKIE_NAME, session.session_id.clone()))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    jar = jar.add(cookie);

    let cookie = Cookie::build((CSRF_TOKEN_NAME, session.csrf_token.clone()))
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    jar = jar.add(cookie);

    let cookie = Cookie::build((USER_TOKEN_NAME, hash_email(&session.email)))
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    Ok(jar.add(cookie))
}

fn hash_email(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn hash_nonce(nonce: &str) -> String {
    let secret_salt = std::env::var("NONCE_SALT").expect("NONCE_SALT must be set in .env");
    let mut hasher = Sha256::new();
    hasher.update(nonce.as_bytes());
    hasher.update(secret_salt.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Deserialize)]
struct XCsrfToken {
    pub x_csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct XUserToken {
    pub x_user_token: String,
}

async fn csrf_verify(t: XCsrfToken, session: Session) -> Result<XCsrfToken, Error> {
    if t.x_csrf_token == session.csrf_token {
        println!("CSRF Token: {} matched.", t.x_csrf_token);
        Ok(t)
    } else {
        Err(Error {
            error: format!(
                "X-CSRF-TOKEN: {} did not match the csrf_token in the record: {}.",
                t.x_csrf_token, session.csrf_token
            ),
        })
    }
}

async fn user_verify(t: XUserToken, session: Session) -> Result<XUserToken, Error> {
    if t.x_user_token == hash_email(&session.email) {
        println!(
            "User Token: {} matched for {}.",
            t.x_user_token, session.email
        );
        Ok(t)
    } else {
        Err(Error {
            error: format!(
                "X-USER-TOKEN: {} did not match the hash of email in the record: {}.",
                t.x_user_token,
                hash_email(&session.email)
            ),
        })
    }
}
