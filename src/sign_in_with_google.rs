use aide::axum::{routing::post_with, ApiRouter, IntoApiResponse};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use axum_extra::extract::cookie::CookieJar;
use cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, SameSite,
};

use std::sync::Arc;

use bytes::Bytes;
use hyper::{header, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Pool;

use crate::idtoken::verify_idtoken;
use crate::idtoken::TokenVerificationError;
use crate::models::{Error, IdInfo, Session, User};
use crate::user::{create_user, get_user_by_sub};
use crate::{AppState, DB};

use super::settings::SESSION_COOKIE_MAX_AGE;
use super::settings::SESSION_COOKIE_NAME;

use super::settings::CSRF_TOKEN_NAME;
use super::settings::USER_TOKEN_NAME;

use crate::settings::NONCE_COOKIE_NAME;

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/authorized", post_with(authorized, |op| op.tag("auth")))
        // .route_layer(axum::middleware::from_fn(check_hx_request))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct FormData {
    credential: Option<String>,
    state: Option<String>,
}

async fn authorized(
    State(state): State<Arc<AppState>>,
    jar: Option<CookieJar>,
    body: Bytes,
) -> impl IntoApiResponse {
    let form_data: FormData = serde_urlencoded::from_bytes(&body).unwrap();
    println!("form_data: {:?}", form_data);
    let jwt = form_data.credential.unwrap();
    println!("jwt: {:?}", jwt);

    if let Ok(idinfo) = verify_token(jwt).await {
        // let _ = verify_nonce(&header, &idinfo);
        let _ = verify_nonce(jar.clone(), &idinfo);
        // println!("idinfo: {:?}", idinfo);

        let user_data = crate::models::User {
            id: None,
            sub: idinfo.sub.clone(),
            email: idinfo.email.clone(),
            name: idinfo.name.clone(),
            picture: idinfo.picture.clone(),
            enabled: Some(true),
            admin: Some(false),
        };

        match get_or_create_user(state.pool.clone(), user_data).await {
            Ok(user) => {
                let message = serde_json::json!({
                    "message": "Created user",
                    "user": user.email,
                });

                let jar = new_session(user, state).await;

                // Redirect to the original page if state is set in the form data.
                // Otherwise, return the message in JSON format.
                if let Some(href) = form_data.state {
                    println!("state: {:?}", href);
                    let response = Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, href)
                        .body(Json(message).into_response().into_body())
                        .unwrap();
                    (jar, response).into_response()
                } else {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("HX-Trigger", "ReloadNavbar")
                        .body(Json(message).into_response().into_body())
                        .unwrap();
                    (jar, response).into_response()
                }
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

pub(crate) async fn new_session(user: User, state: Arc<AppState>) -> CookieJar {
    let session = state
        .cache
        .create_session(user.id.unwrap(), &user.email)
        .await
        .unwrap();

    new_cookie(&session)
}

fn new_cookie(session: &Session) -> CookieJar {
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

    jar.add(cookie)
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


async fn get_or_create_user(
    pool: Pool<DB>,
    user_data: crate::models::User,
) -> Result<crate::models::User, sqlx::Error> {
    match get_user_by_sub(&user_data.sub, &pool.clone()).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => match create_user(user_data, &pool.clone()).await {
            Ok(user) => Ok(user),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

async fn _get_or_create_user(
    idinfo: &IdInfo,
    pool: Pool<DB>,
) -> Result<crate::models::User, sqlx::Error> {
    match get_user_by_sub(&idinfo.sub, &pool).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => {
            let user_data = crate::models::User {
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

fn verify_nonce(jar: Option<CookieJar>, idinfo: &IdInfo) -> Result<(), (StatusCode, Json<Error>)> {
    let hashed_nonce_idinfo = hash_nonce(idinfo.nonce.as_ref().unwrap_or(&"".to_string()));

    println!("idinfo_nonce: {:?}", hashed_nonce_idinfo);

    if let Some(jar) = jar {
        if let Some(hashed_nonce_cookie) = jar.get(NONCE_COOKIE_NAME) {
            println!(
                "hashed_nonce from header: {:?}, hashed idinfo.nonce: {:?}",
                hashed_nonce_cookie.to_string(),
                hashed_nonce_idinfo
            );
            if hashed_nonce_cookie.to_string() != hashed_nonce_idinfo {
                let message = Error {
                    error: "Invalid nonce".to_string(),
                };
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(message)));
            }
        } else {
            println!("hashed_nonce not found in header");

            let message = Error {
                error: "hashed_nonce not found".to_string(),
            };
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(message)));
        }
    }

    let message = Error {
        error: "hashed_nonce not found".to_string(),
    };
    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(message)))

    // Ok(())
}
