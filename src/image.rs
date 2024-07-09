use aide::axum::routing::{get_with, ApiMethodRouter};
use aide::axum::ApiRouter;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get_service;
use axum::Router;
use log;
use mime_guess::from_path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tower_http::services::ServeFile;

// vec of file paths, routes, tags, and descriptions
fn get_routes() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        ("images/dog_meme.png", "/secret1.png", "image", "Secret file"),
        ("images/cat_meme.png", "/secret2.png", "image", "Secret file"),
        ("images/unknown-person-icon.png", "/icon.png", "image", "Icon for anonymous user"),
        ("images/door-check-out-icon.png", "/logout.png", "image", "Logout icon"),
        ("images/admin_icon.webp", "/admin_icon.webp", "image", "Admin icon"),
    ]
}

pub fn create_router() -> ApiRouter {
    let routes = get_routes();

    let mut router = ApiRouter::new();
    for (file_path, route, tag, description) in &routes {
        router = router.api_route(route, get_image_route(file_path, tag, description));
    }

    router
}

// Unused old create_router function using axum::Router
pub fn _create_router() -> Router {
    let routes = get_routes();

    let mut router = Router::new();
    for (file_path, route, _, _) in &routes {
        router = router.route(route, get_service(ServeFile::new(file_path)));
    }

    router
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
