use aide::axum::IntoApiResponse;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use askama_axum::Template;
use axum::http::{request, StatusCode};
use axum::response::Html;
use axum::response::IntoResponse;
use axum::Error;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts, response::Redirect};
use axum_extra::extract::cookie::CookieJar;
use cookie::time::{Duration, OffsetDateTime};
use cookie::{Cookie, SameSite};
use hyper::header;
use std::convert::Infallible;

use bytes::Bytes;
use serde::Deserialize;

use crate::idtoken::verify_idtoken;
use crate::idtoken::TokenVerificationError;
use crate::models::IdInfo;

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/signin", get(signinpage))
        .api_route("/login", post(login))
        .api_route("/createsession", get(create_session))
    // .api_route(
    //     "/",
    //     get(create_session).layer(axum::middleware::from_fn(delete_session)))
}

#[derive(Debug, Deserialize)]
struct FormData {
    credential: Option<String>,
}

async fn login(body: Bytes) -> impl IntoApiResponse {
    let form_data: FormData = serde_urlencoded::from_bytes(&body).unwrap();
    // println!("form_data: {:?}", form_data);
    let jwt = form_data.credential.unwrap();
    println!("jwt: {:?}", jwt);

    if let Ok(_idinfo) = verify_token(jwt).await {
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

        // let user = get_create_user(&idinfo).await;
        // if user.is_some() {
        //     (StatusCode::OK, "OK".to_string()).into_response()
        // } else {
        //     (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
        // }
        (StatusCode::OK, "OK".to_string()).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
    }
}

use crate::models::User;

async fn get_create_user(idinfo: &IdInfo) -> Result<User, Error> {
    // Check if the user exists
    // If exists, return the user ID
    // If not, create the user and return the user ID
    // None
    // Some("user_id".to_string())
    let user_id: i64 = 1;
    Ok(User {
        id: Some(user_id),
        sub: idinfo.sub.clone(),
        email: idinfo.email.clone(),
        name: idinfo.name.clone(),
        picture: idinfo.picture.clone(),
        enabled: Some(true),
        admin: Some(false),
    })
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

async fn delete_session(
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
