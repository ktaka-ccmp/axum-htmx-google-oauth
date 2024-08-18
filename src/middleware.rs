use aide::axum::IntoApiResponse;
use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

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
            return (StatusCode::UNAUTHORIZED, axum::Json(error_response)).into_response();
        }
    } else {
        println!("Cookie not found.");
        return (StatusCode::UNAUTHORIZED, axum::Json(error_response)).into_response();
    }

    next.run(req).await.into_response()
}
