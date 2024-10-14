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

use crate::models::{Error, Session, User};
use crate::user::get_user_by_id;
use crate::AppState;

use super::settings::{
    CSRF_TOKEN_NAME, GOOGLE_OAUTH2_CLIENT_ID, NONCE_COOKIE_MAX_AGE, NONCE_COOKIE_NAME,
    SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, USER_TOKEN_NAME,
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

async fn refresh_token(
    State(state): State<Arc<AppState>>,
    header: HeaderMap,
    mut cookiejar: Option<CookieJar>,
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

    match cookiejar {
        None => {
            let message = Error {
                error: "Error: CookieJar not found".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response()
        }
        Some(ref mut cookiejar) => {
            let newjar = mutate_session(Some(cookiejar.clone()), state).await;
            match newjar {
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

                    (cookiejar.clone(), response).into_response()
                }
                Err(e) => {
                    let message = Error {
                        error: format!("Error mutating session: {:?}", e),
                    };
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response()
                }
            }
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

async fn auth_navbar(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
) -> impl IntoApiResponse {
    // For unauthenticated users, return the menu.login component.
    // fn auth_navbar_login() -> Html<String> {
    fn auth_navbar_login() -> impl IntoApiResponse {
        let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");

        let login_url = origin_server + "/signin/w/google/authorized";
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
    match cookiejar {
        None => Err(Error {
            error: "CookieJar not found".to_string(),
        }),
        Some(cookiejar) => match cookiejar.get(SESSION_COOKIE_NAME) {
            None => Err(Error {
                error: "Session ID not found in CookieJar".to_string(),
            }),
            Some(session_id) => {
                let session = match state.cache.get_session(session_id.value()).await {
                    Ok(session) => session,
                    Err(e) => {
                        return Err(Error {
                            error: e.to_string(),
                        })
                    }
                };
                println!("session: {:?}", session);
                match session {
                    None => Err(Error {
                        error: "Session not found".to_string(),
                    }),
                    Some(session) => {
                        println!("session: {:?}", session);
                        Ok(session)
                    }
                }
                // Ok(session.unwrap())
            }
        },
    }
}

async fn mutate_session(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Result<CookieJar, Error> {
    let admin_email = std::env::var("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set");
    let max_age = *SESSION_COOKIE_MAX_AGE;

    match cookiejar {
        None => Err(Error {
            error: "CookieJar not found".to_string(),
        }),
        Some(cookiejar) => match cookiejar.get(SESSION_COOKIE_NAME) {
            None => Err(Error {
                error: "Session ID not found in CookieJar".to_string(),
            }),
            Some(session_id) => {
                let old_session = state.cache.get_session(session_id.value()).await.unwrap();

                if old_session.clone().unwrap().email == admin_email {
                    return Ok(cookiejar);
                }

                let age_left = old_session.clone().unwrap().expires - (Utc::now().timestamp());
                if age_left * 2 > max_age {
                    println!("Session still has much time: {} seconds left.", age_left);
                    return Ok(cookiejar);
                }

                println!(
                    "Session expires soon in {}. Mutating the session.",
                    age_left
                );

                match get_user_by_id(&old_session.unwrap().user_id, &state.pool).await {
                    Ok(Some(user)) => match new_session(user, state).await {
                        Ok(new_jar) => Ok(new_jar),
                        Err(e) => Err(e),
                    },
                    Ok(None) => Err(Error {
                        error: "User not found".to_string(),
                    }),
                    Err(e) => {
                        eprintln!("Error getting user: {}", e);
                        Err(Error {
                            error: format!("Error getting user: {}", e),
                        })
                    }
                }
            }
        },
    }
}

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
