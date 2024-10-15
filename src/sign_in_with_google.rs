/// This module handles the sign-in process with Google OAuth2.
///
/// It provides the following functionalities:
/// - Creating an API router with the necessary routes.
/// - Handling the authorization process by verifying the ID token and nonce, creating a user session, and responding accordingly.
///
/// # Functions
///
/// - `create_router`: Creates an `ApiRouter` with the `/authorized` route for handling Google OAuth2 authorization.
/// - `authorized`: Handles the authorization process, including verifying the ID token, checking the nonce, creating a user, and starting a session.
/// - `verify_nonce`: Verifies the nonce from the ID token against the nonce stored in the cookies.
///
/// # Structs
///
/// - `FormData`: Represents the form data received in the authorization request, containing the credential (JWT) and state.
///
/// # Dependencies
///
/// This module depends on several external crates and internal modules:
/// - External crates: `aide`, `axum`, `axum_extra`, `bytes`, `hyper`, `serde`
/// - Internal modules: `auth`, `idtoken`, `models`, `settings`, `user`
///
/// # Example
///
/// ```rust
/// let state = Arc::new(AppState::new());
/// let router = create_router(state);
/// ```
use aide::axum::{routing::post_with, ApiRouter, IntoApiResponse};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use axum_extra::extract::cookie::CookieJar;

use std::sync::Arc;

use bytes::Bytes;
use hyper::{header, Response};
use serde::Deserialize;

use super::{
    auth::{hash_nonce, new_session},
    idtoken::verify_idtoken,
    models::{Error, IdInfo},
    settings::{GOOGLE_OAUTH2_CLIENT_ID, NONCE_COOKIE_NAME},
    user::get_or_create_user,
    AppState,
};

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

/// Handles the authorization process for Google OAuth2.
///
/// This function performs the following steps:
/// 1. Extracts the application state, cookies, and request body.
/// 2. Parses the form data from the request body to extract the JWT (credential).
/// 3. Verifies the JWT using Google's OAuth2 client ID.
/// 4. If the JWT verification fails, responds with an unauthorized status.
/// 5. Verifies the nonce from the ID token against the nonce stored in the cookies.
/// 6. If the nonce verification fails, responds with the appropriate error status.
/// 7. Creates or retrieves a user based on the ID token information.
/// 8. If user creation fails, responds with an internal server error status.
/// 9. Creates a new session for the user.
/// 10. If session creation fails, responds with an internal server error status.
/// 11. Constructs a success message with the user's email.
/// 12. If the form data contains a state (original page URL), redirects to that URL.
/// 13. Otherwise, responds with the success message in JSON format.
///
/// # Parameters
/// - `State(state)`: The application state wrapped in an `Arc`.
/// - `jar`: An optional `CookieJar` containing the cookies from the request.
/// - `body`: The request body as `Bytes`.
///
/// # Returns
/// An implementation of `IntoApiResponse` which can be a redirect response or a JSON response.

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

/// Verifies the nonce from the `IdInfo` against the nonce stored in the `CookieJar`.
///
/// # Arguments
///
/// * `jar` - An optional `CookieJar` that may contain the nonce cookie.
/// * `idinfo` - A reference to `IdInfo` which contains the nonce to be verified.
///
/// # Returns
///
/// * `Ok(())` if the nonce in `idinfo` matches the nonce in the `CookieJar`.
/// * `Err((StatusCode, Json<Error>))` if the `CookieJar` is not found, the nonce is not found in the `CookieJar`,
///   or the nonces do not match.
///
/// # Steps
///
/// 1. Hash the nonce from `idinfo` using the `hash_nonce` function.
/// 2. Attempt to retrieve the `CookieJar`. If not found, log an error and return an `INTERNAL_SERVER_ERROR`.
/// 3. Retrieve the hashed nonce from the `CookieJar`. If not found, log an error and return an `INTERNAL_SERVER_ERROR`.
/// 4. Compare the hashed nonce from `idinfo` with the hashed nonce from the `CookieJar`.
///    - If they match, return `Ok(())`.
///    - If they do not match, log an error and return an `INTERNAL_SERVER_ERROR`.

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
