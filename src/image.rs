use aide::axum::routing::get_with;
use aide::axum::ApiRouter;
use aide::axum::IntoApiResponse;

use axum::body::Body;
use axum::response::Response;

use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route(
            "/secret1.png",
            get_with(
                || async { serve_file("images/dog_meme.png").await },
                |op| op.tag("image"),
            ),
        )
        .api_route(
            "/secret2.png",
            get_with(
                || async { serve_file("images/cat_meme.png").await },
                |op| op.tag("image"),
            ),
        )
        .api_route(
            "/icon.png",
            get_with(
                || async { serve_file("images/unknown-person-icon.png").await },
                |op| op.tag("image"),
            ),
        )
        .api_route(
            "/logout.png",
            get_with(
                || async { serve_file("images/door-check-out-icon.png").await },
                |op| op.tag("image"),
            ),
        )
        .api_route(
            "/admin_icon.webp",
            get_with(
                || async { serve_file("images/admin_icon.webp").await },
                |op| op.tag("image"),
            ),
        )
}

async fn serve_file(path: &str) -> impl IntoApiResponse {
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => {
            return Response::builder()
                .status(404)
                .body("File not found".into())
                .unwrap()
        }
    };

    let mut contents: Vec<u8> = vec![];
    if let Err(_) = file.read_to_end(&mut contents).await {
        return Response::builder()
            .status(500)
            .body("Error reading file".into())
            .unwrap();
    }

    Response::builder()
        .status(200)
        .header("Content-Type", "image/png")
        .body(Body::from(contents))
        .unwrap()
}

use axum::routing::get_service;
use axum::Router;
use tower_http::services::ServeFile;

pub fn _create_router() -> Router {
    Router::new()
        .route(
            "/secret1.png",
            get_service(ServeFile::new("images/dog_meme.png")),
        )
        .route(
            "/secret2.png",
            get_service(ServeFile::new("images/cat_meme.png")),
        )
        .route(
            "/icon.png",
            get_service(ServeFile::new("images/unknown-person-icon.png")),
        )
        .route(
            "/logout.png",
            get_service(ServeFile::new("images/door-check-out-icon.png")),
        )
        .route(
            "/admin_icon.webp",
            get_service(ServeFile::new("images/admin_icon.webp")),
        )
}
