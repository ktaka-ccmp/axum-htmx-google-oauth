use std::sync::Arc;

use aide::axum::{
    routing::{get, post}, ApiRouter, AxumOperationHandler, IntoApiResponse
};
use askama_axum::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, SameSite,
};

use bytes::Bytes;
use hyper::{header, Response};
use serde::Deserialize;
use sqlx::Pool;
use tracing_subscriber::field::display::Messages;

use crate::cachestore::Session;
use crate::idtoken::verify_idtoken;
use crate::idtoken::TokenVerificationError;
use crate::models::User;
use crate::models::{Error, IdInfo};
use crate::user::{create_user, get_user_by_sub};
use crate::{AppState, DB};

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/signin", get(signinpage))
        .api_route("/login", post(login))
        .api_route("/logout", get(logout))
        .api_route("/me", get(me))
        .api_route("/createsession", get(create_session))
        // .api_route(
        //     "/",
        //     get(create_session).layer(axum::middleware::from_fn(delete_session)),
        // )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct FormData {
    credential: Option<String>,
}

async fn me(jar: CookieJar) -> impl IntoApiResponse {
    if let Some(session_id) = jar.get("session_id") {
        println!("session_id: {}", session_id.value());
        let messages = format!("session_id: {}", session_id.value());
        (StatusCode::OK, messages).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "session_id not found in Cookie").into_response()
    }
}

// impl AxumOperationHandler<axum_extra::extract::CookieJar, Result<impl IntoApiResponse, StatusCode>> for fn(axum_extra::extract::CookieJar) -> impl Future<Output = impl IntoApiResponse> {
//     fn call(&self, jar: axum_extra::extract::CookieJar) -> Result<impl IntoApiResponse, StatusCode> {
//         (*self)(jar)
//     }
// }

async fn logout(
    State(state): State<Arc<AppState>>,
) -> impl IntoApiResponse {

    // let jar: CookieJar = 
    // let mut session_deleted = false;

    // if let Some(jar) = jar {
    //     if let Some(session_id) = jar.get("session_id") {
    //         if let Err(e) = state.cache.delete_session(session_id.value()).await {
    //             eprintln!("Failed to delete session: {}", e);
    //         } else {
    //             session_deleted = true;
    //         }
    //     }

    //     // Remove cookies
    //     let cookies_to_remove = ["session_id", "csrf_token", "user_token"];
    //     let mut new_jar = jar.clone();
    //     for name in cookies_to_remove.iter() {
    //         new_jar = new_jar.remove(Cookie::new(*name, ""));
    //     }

    //     let message = if session_deleted {
    //         "Session deleted successfully"
    //     } else {
    //         "No active session found"
    //     };

    //     // (jar, StatusCode::OK, message)
    //     (StatusCode::OK, message).into_response()
    //     // (StatusCode::OK, jar, message).into_response()
    // } else {
    //     (StatusCode::OK, "No active session found").into_response()
    // }
    (StatusCode::OK, "No yet implemented").into_response()
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
                    "user": user
                });

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Json(message).into_response().into_body())
                    .unwrap();

                let session = state
                    .cache
                    .create_session(user.id.unwrap(), &user.email)
                    .await
                    .unwrap();

                let jar = new_cookie(&session);
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

use sha2::{Digest, Sha256};

fn new_cookie(session: &Session) -> CookieJar {
    let max_age = Duration::seconds(3600); // Replace with your actual session_max_age value
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

#[derive(Template)]
#[template(path = "signin.j2")]
struct SigninTemplate {
    title: String,
    client_id: String,
    nonce: String,
    login_url: String,
}

async fn signinpage() -> Html<String> {
    let client_id =
        std::env::var("GOOGLE_OAUTH2_CLIENT_ID").expect("GOOGLE_OAUTH2_CLIENT_ID must be set");
    let signin_template = SigninTemplate {
        title: "Signin".to_string(),
        client_id,
        nonce: "n-0S6_WzA2Mj".to_string(),
        login_url: "/auth/login".to_string(),
    };
    let template = signin_template;
    Html(template.render().unwrap())
}

// pub struct User;

// #[async_trait]
// impl<S> FromRequestParts<S> for User {
//     type Rejection = Infallible;

//     async fn from_request_parts(_parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
//         Ok(User)
//     }
// }

async fn _delete_session(
    cookiejar: Option<CookieJar>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoApiResponse {
    if let Some(cookiejar) = cookiejar {
        if let Some(_session_id) = cookiejar.get("session_id") {
            let _ = cookiejar.remove(Cookie::from("session_id"));
        }
    }
    next.run(req).await.into_response()
}

async fn create_session() -> Result<(CookieJar, Redirect), StatusCode> {
    if let Some(session_id) = authorize_and_create_session().await {
        let jar = CookieJar::new();
        let cookie = Cookie::build(("session_id", session_id))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict)
            .max_age(Duration::seconds(60 * 5))
            .expires(OffsetDateTime::now_utc() + Duration::seconds(60 * 5));

        Ok((jar.add(cookie), Redirect::to("/spa/content.secret2")))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn authorize_and_create_session() -> Option<String> {
    // Check if the token is valid
    // If valid, create a session and return the session ID
    // If invalid, return None
    // None
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos();
    Some(format!("ssid_{}", now))
}
