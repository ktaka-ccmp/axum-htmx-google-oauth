use aide::axum::IntoApiResponse;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

use crate::models::User;
use crate::user::get_user_by_id;
use crate::AppState;

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

pub async fn authenticate(
    is_admin_required: bool,
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
    req: Request<Body>,
    next: Next,
) -> impl IntoApiResponse {
    let error_response = json!({"message": "Authorization required(authenticate())"});

    async fn process_authentication(
        is_admin_required: bool,
        state: Arc<AppState>,
        session_id: &str,
    ) -> Result<(), StatusCode> {
        let user = get_current_user(session_id, State(state)).await;
        if let Some(user) = user {
            if !user.enabled.unwrap_or(false) {
                println!("Disabled user.");
                return Err(StatusCode::FORBIDDEN);
            }
            if is_admin_required {
                let admin_email = std::env::var("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set");
                if user.email != admin_email {
                    println!("Not an admin user.");
                    return Err(StatusCode::FORBIDDEN);
                }
                println!("Authenticated as admin: {}", user.email);
            } else {
                println!("Authenticated as: {}", user.email);
            }
            Ok(())
        } else {
            println!("NotAuthenticated");
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    match cookiejar.and_then(|jar| {
        jar.get("session_id")
            .map(|cookie| cookie.value().to_string())
    }) {
        Some(session_id) => {
            println!("Session ID: {:?}", session_id);
            match process_authentication(is_admin_required, state, &session_id).await {
                Ok(_) => next.run(req).await.into_response(),
                Err(status) => (status, Json(error_response)).into_response(),
            }
        }
        None => {
            println!("Session ID not found in cookie.");
            (StatusCode::UNAUTHORIZED, Json(error_response)).into_response()
        }
    }
}

pub async fn is_authenticated_admin(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
    req: Request<Body>,
    next: Next,
) -> impl IntoApiResponse {
    authenticate(true, State(state), cookiejar, req, next).await
}

pub async fn is_authenticated(
    State(state): State<Arc<AppState>>,
    cookiejar: Option<CookieJar>,
    req: Request<Body>,
    next: Next,
) -> impl IntoApiResponse {
    authenticate(false, State(state), cookiejar, req, next).await
}

async fn get_current_user(session_id: &str, State(state): State<Arc<AppState>>) -> Option<User> {
    let session = state.cache.get_session(session_id).await.unwrap();
    if let Some(session) = session {
        println!(
            "get_current_user: Session found for the session_id: {}",
            session_id
        );
        match get_user_by_id(&session.user_id, &state.pool).await {
            Ok(user) => user,
            Err(e) => {
                eprintln!("Error getting user: {}", e);
                None
            }
        }
    } else {
        println!(
            "get_current_user: No session found for the session_id: {}",
            session_id
        );
        None
    }
}
