use aide::{
    axum::{routing::get, ApiRouter, IntoApiResponse},
    openapi::{Info, OpenApi},
    scalar::Scalar,
};

use axum::{
    response::Redirect,
    Extension, Json,
};

use dotenv::dotenv;
use sqlx::sqlite::SqlitePool as Pool;
use std::net::SocketAddr;

use tower_http::trace::TraceLayer;

mod api;
mod api2;
mod htmx;
mod htmx_secret;
mod spa;
mod models;
mod image;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv().ok();
    let db_connection_str = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = Pool::connect(&db_connection_str).await?;

    let docs_router = ApiRouter::new()
        .route("/", Scalar::new("/docs/api.json").axum_route())
        .route("/api.json", get(serve_api));
    
    let app = ApiRouter::new()
        .api_route("/", get(|| async { Redirect::permanent("/spa")}))
        .api_route("/docs/", get(|| async { Redirect::permanent("/docs") }))
        .api_route("/spa/", get(|| async { Redirect::permanent("/spa") }))
        .api_route("/htmx/", get(|| async { Redirect::permanent("/htmx") }))
        .nest("/docs", docs_router)
        .nest("/api", api::create_router(pool.clone()))
        .nest("/api2", api2::create_router(pool.clone()))
        .nest("/spa", spa::create_router())
        .nest("/htmx", htmx::create_router(pool.clone()))
        .nest("/htmx", htmx_secret::create_router())
        .nest("/img", image::create_router())
        // .nest_service("/img", image::create_router())
        .layer(TraceLayer::new_for_http())
        .with_state(());

    let mut api = OpenApi {
        info: Info {
            description: Some("an example API".to_string()),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);
    axum::serve(
        listener,
        app.finish_api(&mut api)
            .layer(Extension(api))
            .into_make_service(),
    )
    .await?;
    Ok(())
}

async fn serve_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}
