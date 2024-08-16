use aide::axum::IntoApiResponse;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Represents an error response.
#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

/// Checks if the request is an HX request.
/// Returns an error response if the request is not an HX request.
pub fn check_hx_request(headers: &HeaderMap) -> Result<(), Response> {
    if headers.get("HX-Request").is_none() {
        let error_response = ErrorResponse {
            detail: "Only HX request is allowed to this endpoint.".to_string(),
        };
        Err((StatusCode::BAD_REQUEST, axum::Json(error_response)).into_response())
    } else {
        Ok(())
    }
}

pub async fn hx_request_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoApiResponse {
    if let Err(err) = check_hx_request(req.headers()) {
        return err.into_response();
    }
    next.run(req).await.into_response()
}
