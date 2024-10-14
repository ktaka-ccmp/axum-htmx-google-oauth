use std::sync::Arc;

use crate::AppState;
use aide::{
    axum::{routing::get_with, ApiRouter, IntoApiResponse},
    NoApi,
};
use axum::http::header::HeaderMap;
use axum::{http::StatusCode, response::Html, Json};
use axum_extra::extract::cookie::CookieJar;

use askama_axum::Template;

use super::settings::GOOGLE_OAUTH2_CLIENT_ID;
use super::settings::SESSION_COOKIE_NAME;

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/signin", get_with(signinpage, |op| op.tag("debug")))
        .api_route("/me", get_with(me, |op| op.tag("debug")))
        .api_route("/me2", get_with(me2, |op| op.tag("debug")))
        .api_route("/headers", get_with(show_headers, |op| op.tag("debug")))
        .api_route(
            "/headers2",
            get_with(show_headers_all, |op| op.tag("debug")),
        )
        .with_state(state)
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
    let signin_template = SigninTemplate {
        title: "Signin".to_string(),
        client_id: GOOGLE_OAUTH2_CLIENT_ID.to_string(),
        nonce: "n-0S6_WzA2Mj".to_string(),
        login_url: "/auth/login".to_string(),
    };
    let template = signin_template;
    Html(template.render().unwrap())
}

async fn me(NoApi(jar): NoApi<CookieJar>) -> impl IntoApiResponse {
    if let Some(session_id) = jar.get(SESSION_COOKIE_NAME) {
        println!("{}: {}", SESSION_COOKIE_NAME, session_id.value());
        (
            StatusCode::OK,
            Json(serde_json::json!({
                SESSION_COOKIE_NAME: session_id.value(),
            })),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
            "message": format!("{} not found in Cookie", SESSION_COOKIE_NAME)})),
        )
    }
}

async fn me2(jar: Option<CookieJar>) -> impl IntoApiResponse {
    if let Some(jar) = jar {
        if let Some(session_id) = jar.get(SESSION_COOKIE_NAME) {
            println!("{}: {}", SESSION_COOKIE_NAME, session_id.value());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    SESSION_COOKIE_NAME: session_id.value(),
                })),
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "message": format!("{} not found in Cookie", SESSION_COOKIE_NAME)})),
            )
        }
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
            "message": "CookieJar not found"})),
        )
    }
}

async fn show_headers(headers: HeaderMap) -> impl IntoApiResponse {
    let mut headers_map = serde_json::Map::new();

    let heade_of_interests = vec!["host", "accept", "x-csrf-token", "x-user-token"];

    for header in heade_of_interests {
        if headers.get(header).is_some() {
            headers_map.insert(
                header.to_string(),
                serde_json::Value::String(
                    headers.get(header).unwrap().to_str().unwrap().to_string(),
                ),
            );
        }
    }

    // println!("{:?}", headers_map);

    (StatusCode::OK, Json(headers_map))
}

async fn show_headers_all(headers: HeaderMap) -> impl IntoApiResponse {
    let mut headers_map = serde_json::Map::new();

    for (header_name, header_value) in headers.iter() {
        headers_map.insert(
            header_name.as_str().to_string(),
            serde_json::Value::String(header_value.to_str().unwrap().to_string()),
        );
    }

    // println!("{:?}", headers_map);

    (StatusCode::OK, Json(headers_map))
}
