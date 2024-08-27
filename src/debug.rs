use std::sync::Arc;

use crate::AppState;
use aide::{
    axum::{routing::get_with, ApiRouter, IntoApiResponse},
    NoApi,
};
use axum::{
    http::StatusCode,
    response::Html,
    Json,
};
use axum_extra::extract::cookie::CookieJar;

use askama_axum::Template;

pub fn create_router(state: Arc<AppState>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/signin", get_with(signinpage, |op| op.tag("debug")))
        .api_route("/me", get_with(me, |op| op.tag("debug")))
        .api_route("/me2", get_with(me2, |op| op.tag("debug")))
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

async fn me(NoApi(jar): NoApi<CookieJar>) -> impl IntoApiResponse {
    if let Some(session_id) = jar.get("session_id") {
        println!("session_id: {}", session_id.value());
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "session_id": session_id.value(),
            })),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
            "message": "session_id not found in Cookie"})),
        )
    }
}

async fn me2(jar: Option<CookieJar>) -> impl IntoApiResponse {
    if let Some(jar) = jar {
        if let Some(session_id) = jar.get("session_id") {
            println!("session_id: {}", session_id.value());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "session_id": session_id.value(),
                })),
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                "message": "session_id not found in Cookie"})),
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
