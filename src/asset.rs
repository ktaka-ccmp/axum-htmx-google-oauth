use aide::axum::routing::get_with;
use aide::axum::{ApiRouter, IntoApiResponse};
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use std::io::{Error, ErrorKind};
use std::path::Path;
use tracing::error;

fn get_routes() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    // vec of file paths, routes, tags, and descriptions
    vec![
        (
            "assets/web_dark_rd_na@1x.png",
            "/google_oauth2.png",
            "image",
            "Google OAuth icon",
        ),
        (
            "assets/dog_meme.png",
            "/secret1.png",
            "image",
            "Secret file",
        ),
        (
            "assets/cat_meme.png",
            "/secret2.png",
            "image",
            "Secret file",
        ),
        (
            "assets/unknown-person-icon.png",
            "/icon.png",
            "image",
            "Icon for anonymous user",
        ),
        (
            "assets/door-check-out-icon.png",
            "/logout.png",
            "image",
            "Logout icon",
        ),
        (
            "assets/admin_icon.webp",
            "/admin_icon.webp",
            "image",
            "Admin icon",
        ),
        ("assets/index.html", "/index.html", "html", ""),
    ]
}

pub fn create_router() -> ApiRouter {
    let routes = get_routes();
    let mut router = ApiRouter::new();

    for (file_path, route, tag, description) in routes {
        let desc = if description.is_empty() {
            file_path
        } else {
            description
        };
        router = router.api_route(
            route,
            get_with(
                move || get_handler(file_path),
                move |op| op.tag(tag).description(desc),
            ),
        );
    }

    router
}

async fn get_handler(file_path: &str) -> impl IntoApiResponse {
    match read_file_and_detect_mime(file_path).await {
        Ok((contents, mime_type)) => build_response(contents, mime_type),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => build_error_response(StatusCode::NOT_FOUND, "File not found"),
            _ => build_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        },
    }
}

async fn read_file_and_detect_mime(file_path: &str) -> Result<(Vec<u8>, String), Error> {
    if !is_safe_path(file_path) {
        return Err(Error::new(ErrorKind::PermissionDenied, "Unsafe path"));
    }

    let contents = tokio::fs::read(file_path).await?;
    let mime_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();
    Ok((contents, mime_type))
}

fn is_safe_path(file_path: &str) -> bool {
    let path = Path::new(file_path);
    path.is_relative() && !path.starts_with("..") && !path.to_string_lossy().contains("..")
}

fn build_response(contents: Vec<u8>, mime_type: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            "Content-Type",
            HeaderValue::from_str(&mime_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        )
        .body(Body::from(contents))
        .unwrap_or_else(|e| {
            error!("Failed to build response: {:?}", e);
            build_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })
}

fn build_error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", HeaderValue::from_static("text/plain"))
        .body(Body::from(message.to_string()))
        .unwrap_or_else(|e| {
            error!("Failed to build error response: {:?}", e);
            Response::new(Body::from("Internal server error"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::io::ErrorKind;

    #[tokio::test]
    async fn test_get_routes() {
        let routes = get_routes();
        assert_eq!(routes.len(), 7);
        assert_eq!(
            routes[1],
            (
                "assets/dog_meme.png",
                "/secret1.png",
                "image",
                "Secret file"
            )
        );
    }

    #[tokio::test]
    async fn test_build_response() {
        let contents = vec![1, 2, 3];
        let response = build_response(contents.clone(), "application/octet-stream".to_string());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );

        // Check response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body, contents);
    }

    #[tokio::test]
    async fn test_build_error_response() {
        let response = build_error_response(StatusCode::NOT_FOUND, "File not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["content-type"], "text/plain");

        // Check response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body, "File not found".as_bytes());
    }

    #[tokio::test]
    async fn test_unsafe_path() {
        let result = read_file_and_detect_mime("../secret1.png").await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_internal_server_error_response() {
        let contents = vec![1, 2, 3];
        let response = build_response(contents.clone(), "\0".to_string()); // Invalid MIME type
        assert_eq!(response.status(), StatusCode::OK); // Should produce 200 OK
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );

        // Check response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body, contents);
    }

    #[tokio::test]
    async fn test_get_handler() {
        let response = get_handler("assets/dog_meme.png").await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/png");

        let response = get_handler("assets/nonexistent.png").await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_mime_type_handling() {
        let response = get_handler("assets/index.html").await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/html");

        let response = get_handler("assets/admin_icon.webp").await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/webp");
    }
}
