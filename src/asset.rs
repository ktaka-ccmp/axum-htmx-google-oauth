use aide::axum::routing::get_with;
use aide::axum::{ApiRouter, IntoApiResponse};
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use tracing::error;

pub fn get_routes() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    // vec of file paths, routes, tags, and descriptions
    vec![
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

pub async fn get_handler(file_path: &str) -> impl IntoApiResponse {
    match read_file_and_detect_mime(file_path).await {
        Ok((contents, mime_type)) => build_response(contents, mime_type),
        Err(err) => {
            error!("Error handling file {}: {:?}", file_path, err);
            build_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        }
    }
}

async fn read_file_and_detect_mime(file_path: &str) -> Result<(Vec<u8>, String), std::io::Error> {
    let contents = tokio::fs::read(file_path).await?;
    let mime_type = mime_guess::from_path(file_path).first_or_octet_stream().to_string();
    Ok((contents, mime_type))
}

pub fn build_response(contents: Vec<u8>, mime_type: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", HeaderValue::from_str(&mime_type).unwrap())
        .body(Body::from(contents))
        .unwrap()
}

pub fn build_error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", HeaderValue::from_static("text/plain"))
        .body(Body::from(message.to_string()))
        .unwrap()
}
