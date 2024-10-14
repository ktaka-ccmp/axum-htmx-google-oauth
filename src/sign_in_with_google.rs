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

use crate::models::{Error, IdInfo};
use crate::user::get_or_create_user;
use crate::AppState;

use super::settings::GOOGLE_OAUTH2_CLIENT_ID;
use super::settings::NONCE_COOKIE_NAME;

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

    let idinfo = match verify_idtoken(jwt, GOOGLE_OAUTH2_CLIENT_ID.to_string()).await {
        Ok(idinfo) => idinfo,
        Err(err) => {
            println!("Error: {:?}", err);
            let message = Error {
                error: "Error verifying token".to_string(),
            };
            return (StatusCode::UNAUTHORIZED, Json(message)).into_response();
        }
    };

    match verify_nonce(jar.clone(), &idinfo) {
        Ok(_) => (),
        Err((status, message)) => {
            println!("Error: {:?}", message);
            return (status, message).into_response();
        }
    };

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

    let user = match get_or_create_user(state.pool.clone(), user_data).await {
        Ok(user) => user,
        Err(e) => {
            let message = Error {
                error: format!("Error creating user: {:?}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
    };

    let user_email = user.email.clone();
    let jar = match new_session(user, state).await {
        Ok(jar) => jar,
        Err(e) => {
            let message = Error {
                error: format!("Error creating session: {:?}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(message)).into_response();
        }
    };

    let message = serde_json::json!({
        "message": "Created user",
        "user": user_email,
    });

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

fn verify_nonce(jar: Option<CookieJar>, idinfo: &IdInfo) -> Result<(), (StatusCode, Json<Error>)> {
    let hashed_nonce_idinfo = hash_nonce(idinfo.nonce.as_ref().unwrap_or(&"".to_string()));
    println!("idinfo_nonce: {:?}", hashed_nonce_idinfo);

    let jar = jar.ok_or_else(|| {
        println!("CookieJar not found");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Error {
                error: "CookieJar not found".to_string(),
            }),
        )
    })?;

    let hashed_nonce_cookie = jar
        .get(NONCE_COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(|| {
            println!("hashed_nonce not found in header");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Error {
                    error: "hashed_nonce not found".to_string(),
                }),
            )
        })?;

    if hashed_nonce_cookie == hashed_nonce_idinfo {
        Ok(())
    } else {
        println!("Invalid nonce");
        println!(
            "hashed_nonce from header: {:?}, hashed idinfo.nonce: {:?}",
            hashed_nonce_cookie, hashed_nonce_idinfo
        );
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Error {
                error: "Invalid nonce".to_string(),
            }),
        ))
    }
}
