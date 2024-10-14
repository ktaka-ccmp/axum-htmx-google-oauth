use aide::axum::{routing::post_with, ApiRouter, IntoApiResponse};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use axum_extra::extract::cookie::CookieJar;

use std::sync::Arc;

use bytes::Bytes;
use hyper::{header, Response};
use serde::Deserialize;

use super::auth::hash_nonce;
use super::auth::new_session;
use super::idtoken::verify_idtoken;
use super::idtoken::TokenVerificationError;

use crate::models::{Error, IdInfo};
use crate::user::get_or_create_user;
use crate::AppState;

use super::settings::NONCE_COOKIE_NAME;
use super::settings::GOOGLE_OAUTH2_CLIENT_ID;

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

async fn verify_token(jwt: String) -> Result<IdInfo, TokenVerificationError> {
    let idinfo = match verify_idtoken(jwt, GOOGLE_OAUTH2_CLIENT_ID.to_string()).await {
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
