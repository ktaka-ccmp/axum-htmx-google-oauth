use aide::axum::routing::{get_with, ApiMethodRouter};
use aide::axum::ApiRouter;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use mime_guess::from_path;
use log;

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/secret1.png", get_image_route("images/dog_meme.png", "image", "Secret file"))
        .api_route("/secret2.png", get_image_route("images/cat_meme.png", "image", "Secret file"))
        .api_route("/icon.png", get_image_route("images/unknown-person-icon.png", "image", "Icon for anonymous user"))
        .api_route("/logout.png", get_image_route("images/door-check-out-icon.png", "image", "Logout icon"))
        .api_route("/admin_icon.webp", get_image_route("images/admin_icon.webp", "image", "Admin icon"))
}

fn get_image_route(path: &'static str, tag: &'static str, description: &'static str) -> ApiMethodRouter {
    get_with(
        move || async move { serve_file(path).await },
        move |op| op.tag(tag).description(description),
    )
}

async fn serve_file(path: &str) -> Result<Response<Body>, Response<Body>> {
    match read_file(path).await {
        Ok((contents, mime_type)) => Ok(build_response(contents, mime_type)),
        Err(response) => Err(response),
    }
}

async fn read_file(path: &str) -> Result<(Vec<u8>, String), Response<Body>> {
    let mut file = File::open(path).await.map_err(|_| {
        log::error!("Failed to open file: {}", path);
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(format!("File not found: {}", path)))
            .unwrap()
    })?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.map_err(|_| {
        log::error!("Error reading file: {}", path);
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("Error reading file: {}", path)))
            .unwrap()
    })?;

    let mime_type = from_path(path).first_or_octet_stream().as_ref().to_string();
    Ok((contents, mime_type))
}

fn build_response(contents: Vec<u8>, mime_type: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", HeaderValue::from_str(&mime_type).unwrap())
        .body(Body::from(contents))
        .unwrap()
}

