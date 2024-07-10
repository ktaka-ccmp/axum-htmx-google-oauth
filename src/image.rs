use aide::axum::routing::get_with;
use aide::axum::{ApiRouter, IntoApiResponse};
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use std::fs::read;

pub fn get_routes() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    // vec of file paths, routes, tags, and descriptions
    vec![
        (
            "images/dog_meme.png",
            "/secret1.png",
            "image",
            "Secret file",
        ),
        (
            "images/cat_meme.png",
            "/secret2.png",
            "image",
            "Secret file",
        ),
        (
            "images/unknown-person-icon.png",
            "/icon.png",
            "image",
            "Icon for anonymous user",
        ),
        (
            "images/door-check-out-icon.png",
            "/logout.png",
            "image",
            "Logout icon",
        ),
        (
            "images/admin_icon.webp",
            "/admin_icon.webp",
            "image",
            "Admin icon",
        ),
    ]
}

pub fn create_router() -> ApiRouter {
    let routes = get_routes();

    let mut router = ApiRouter::new();
    for (file_path, route, tag, description) in routes {
        router = router.api_route(
            route,
            get_with(
                move || get_handler(file_path),
                move |op| op.tag(tag).description(description),
            ),
        );
    }

    router
}

async fn get_handler(file_path: &str) -> impl IntoApiResponse {
    match read(file_path) {
        Ok(contents) => {
            let mime_type = infer::get(&contents)
                .map_or("application/octet-stream".to_string(), |typ| {
                    typ.mime_type().to_string()
                });
            build_response(contents, mime_type)
        }
        Err(_) => build_error_response(StatusCode::NOT_FOUND, "File not found"),
    }
}

fn build_response(contents: Vec<u8>, mime_type: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", HeaderValue::from_str(&mime_type).unwrap())
        .body(Body::from(contents))
        .unwrap()
}

fn build_error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", HeaderValue::from_static("text/plain"))
        .body(Body::from(message.to_string()))
        .unwrap()
}
