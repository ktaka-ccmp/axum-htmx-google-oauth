use std::sync::Arc;

use aide::{
    axum::{
        routing::{get_with, post_with},
        ApiRouter, IntoApiResponse,
    },
    NoApi,
};
use askama_axum::Template;
use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, SameSite,
};

use bytes::Bytes;
use hyper::{header, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Pool;

use crate::idtoken::verify_idtoken;
use crate::idtoken::TokenVerificationError;
use crate::models::{Error, IdInfo, Session, User, XCsrfToken, XUserToken};
use crate::user::{create_user, get_user_by_id, get_user_by_sub};
use crate::{AppState, DB};

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/login", post_with(login, |op| op.tag("auth")))
        .api_route("/logout", get_with(logout, |op| op.tag("auth")))
        .api_route(
            "/refresh_token",
            get_with(refresh_token, |op| op.tag("auth")),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct FormData {
    credential: Option<String>,
}

async fn login(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoApiResponse {
    let form_data: FormData = serde_urlencoded::from_bytes(&body).unwrap();
    // println!("form_data: {:?}", form_data);
    let jwt = form_data.credential.unwrap();
    println!("jwt: {:?}", jwt);

    if let Ok(idinfo) = verify_token(jwt).await {
        // match header::HeaderValue
        //     Some(expected_nonce) => {
        //         if idinfo.nonce == expected_nonce.to_str().unwrap() {
        //             (StatusCode::OK, "OK".to_string()).into_response()
        //         } else {
        //             (StatusCode::BAD_REQUEST, "Invalid nonce".to_string()).into_response()
        //         }
        //     }
        //     None => (StatusCode::BAD_REQUEST, "Invalid nonce".to_string()).into_response(),
        // }

        println!("idinfo: {:?}", idinfo);

        match get_or_create_user(&idinfo, state.pool.clone()).await {
            Ok(user) => {
                let message = serde_json::json!({
                    "message": "Created user",
                    "user": user.email,
                });

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("HX-Trigger", "ReloadNavbar")
                    .body(Json(message).into_response().into_body())
                    .unwrap();

                let jar = new_session(user, state).await;
                (jar, response).into_response()
            }
            Err(e) => {
                let message = Error {
                    error: format!("Error creating user: {:?}", e),
                };
                (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response()
            }
        }
    } else {
        let message = Error {
            error: "Error verifying token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(message)).into_response()
    }
}

async fn logout(
    State(state): State<Arc<AppState>>,
    jar: Option<CookieJar>,
) -> impl IntoApiResponse {
    let mut session_deleted = false;

    if let Some(mut jar) = jar {
        if let Some(session_id) = jar.get("session_id") {
            if let Err(e) = state.cache.delete_session(session_id.value()).await {
                eprintln!("Failed to delete session: {}", e);
            } else {
                session_deleted = true;
            }
        }

        let cookies_to_remove = ["session_id", "csrf_token", "user_token"];
        for name in cookies_to_remove.iter() {
            jar = jar.remove(Cookie::build((*name, "")).path("/"));
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
            .body(Json(message).into_response().into_body())
            .unwrap();

        // (jar, Redirect::to("/auth/me")).into_response()
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
                        "session_id": newjar.get("session_id").unwrap().value(),
                        "csrf_token": newjar.get("csrf_token").unwrap().value(),
                        "user_token": newjar.get("user_token").unwrap().value(),
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

async fn jar_to_session(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Result<Session, Error> {
    match cookiejar {
        None => Err(Error {
            error: "CookieJar not found".to_string(),
        }),
        Some(cookiejar) => match cookiejar.get("session_id") {
            None => Err(Error {
                error: "Session ID not found in CookieJar".to_string(),
            }),
            Some(session_id) => {
                let session = state.cache.get_session(session_id.value()).await.unwrap();
                Ok(session.unwrap())
            }
        },
    }
}

async fn mutate_session(
    cookiejar: Option<CookieJar>,
    state: Arc<AppState>,
) -> Result<CookieJar, Error> {
    let admin_email = std::env::var("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set");
    let max_age = std::env::var("SESSION_MAX_AGE")
        .expect("SESSION_MAX_AGE must be set")
        .parse::<i64>()
        .expect("SESSION_MAX_AGE must be an integer");

    match cookiejar {
        None => Err(Error {
            error: "CookieJar not found".to_string(),
        }),
        Some(cookiejar) => match cookiejar.get("session_id") {
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
                    Ok(Some(user)) => Ok(new_session(user, state).await),
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

async fn new_session(user: User, state: Arc<AppState>) -> CookieJar {
    let session = state
        .cache
        .create_session(user.id.unwrap(), &user.email)
        .await
        .unwrap();

    new_cookie(&session)
}

fn new_cookie(session: &Session) -> CookieJar {
    let max_age_sec = std::env::var("SESSION_MAX_AGE")
        .expect("SESSION_MAX_AGE must be set")
        .parse::<i64>()
        .expect("SESSION_MAX_AGE must be an integer");
    let max_age = Duration::seconds(max_age_sec);

    let expires = OffsetDateTime::now_utc() + max_age;

    let mut jar = CookieJar::new();

    let cookie = Cookie::build(("session_id", session.session_id.clone()))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    jar = jar.add(cookie);

    let cookie = Cookie::build(("csrf_token", session.csrf_token.clone()))
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    jar = jar.add(cookie);

    let cookie = Cookie::build(("user_token", hash_email(&session.email)))
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .expires(expires)
        .build();

    jar.add(cookie)
}

fn hash_email(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    format!("{:x}", hasher.finalize())
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

async fn get_or_create_user(idinfo: &IdInfo, pool: Pool<DB>) -> Result<User, sqlx::Error> {
    match get_user_by_sub(&idinfo.sub, &pool).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => {
            let user_data = User {
                id: None,
                sub: idinfo.sub.clone(),
                email: idinfo.email.clone(),
                name: idinfo.name.clone(),
                picture: idinfo.picture.clone(),
                enabled: Some(true),
                admin: Some(false),
            };
            match create_user(user_data, &pool).await {
                Ok(user) => Ok(user),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

async fn verify_token(jwt: String) -> Result<IdInfo, TokenVerificationError> {
    let client_id =
        std::env::var("GOOGLE_OAUTH2_CLIENT_ID").expect("GOOGLE_OAUTH2_CLIENT_ID must be set");

    let idinfo = match verify_idtoken(jwt, client_id).await {
        Ok(idinfo) => idinfo,
        Err(err) => {
            println!("Error: {:?}", err);
            return Err(err);
        }
    };
    println!("idinfo: {:?}", idinfo);
    Ok(idinfo)
}
