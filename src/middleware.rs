use aide::axum::IntoApiResponse;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

use crate::auth::get_current_user;
use crate::AppState;
use std::sync::Arc;

/// Represents an error response.
#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

pub async fn check_hx_request(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoApiResponse {
    // Check if the HX-Request header is present
    if req.headers().get("HX-Request").is_none() {
        // Create an error response if the header is missing
        let error_response = ErrorResponse {
            detail: "Only HX request is allowed to this endpoint.".to_string(),
        };
        return (StatusCode::BAD_REQUEST, axum::Json(error_response)).into_response();
    }
    next.run(req).await.into_response()
}

pub async fn check_auth(
    State(_state): State<Arc<AppState>>,
    cookie: Option<CookieJar>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoApiResponse {
    println!("Checking authorization...");

    let error_response = ErrorResponse {
        detail: "Authoriztion required.".to_string(),
    };

    if let Some(cookie) = cookie {
        println!("Cookie found.{:?}", cookie);
        if let Some(session_id) = cookie.get("session_id") {
            println!("Session ID: {:?}", session_id);
        } else {
            println!("Session ID not found in cookie.");
            (StatusCode::UNAUTHORIZED, axum::Json(error_response)).into_response();
        }
    } else {
        println!("Cookie not found.");
        return (StatusCode::UNAUTHORIZED, axum::Json(error_response)).into_response();
    }

    next.run(req).await.into_response()
}

pub async fn is_authenticated(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoApiResponse {
    let error_response = serde_json::json!({
        "message": "Authoriztion required.",
    });

    if let Some(cookiejar) = cookiejar {
        if let Some(session_id) = cookiejar.get("session_id") {
            println!("Session ID: {:?}", session_id.value());
            let user = get_current_user(session_id.value(), State(state)).await;
            if let Some(user) = user {
                if user.enabled.unwrap() {
                    println!("Authenticated as: {}", user.email);
                    next.run(req).await.into_response()
                } else {
                    println!("Disabled user.");
                    (StatusCode::FORBIDDEN, Json(error_response)).into_response()
                }
            } else {
                println!("NotAuthenticated");
                (StatusCode::UNAUTHORIZED, Json(error_response)).into_response()
            }
        } else {
            println!("Session ID not found in cookie.");
            (StatusCode::UNAUTHORIZED, Json(error_response)).into_response()
        }
    } else {
        println!("Cookie not found.");
        (StatusCode::UNAUTHORIZED, Json(error_response)).into_response()
    }
}
