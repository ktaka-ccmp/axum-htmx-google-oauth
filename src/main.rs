use aide::{
    axum::{routing::get, ApiRouter, IntoApiResponse},
    openapi::{Info, OpenApi},
    scalar::Scalar,
};

use axum::{response::Redirect, Extension, Json};

use dotenv::dotenv;
use sqlx::Pool;
use std::{net::SocketAddr, sync::Arc};

use tower_http::trace::TraceLayer;

use api_server_htmx::api;
use api_server_htmx::api2;
use api_server_htmx::asset;
use api_server_htmx::auth;
use api_server_htmx::htmx;
use api_server_htmx::htmx_secret;
use api_server_htmx::spa;
use api_server_htmx::user;
use api_server_htmx::cachestore;

use api_server_htmx::AppState;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv().ok();
    let db_connection_str = std::env::var("DATABASE_URL")
        .expect("Check your .env file.\nDATABASE_URL environment variable must be set.");
    let pool = Pool::connect(&db_connection_str).await?;
    let cache: Arc<dyn cachestore::CacheStore + Send + Sync> = cachestore::get_cache_store().await?;

    let state = Arc::new(AppState {
        pool: pool.clone(),
        cache,
    });

    let docs_router = ApiRouter::new()
        .route("/", Scalar::new("/docs/api.json").axum_route())
        .route("/api.json", get(serve_api));

    let app = ApiRouter::new()
        .route("/", get(|| async { Redirect::permanent("/spa") }))
        .route("/docs/", get(|| async { Redirect::permanent("/docs") }))
        .route("/spa/", get(|| async { Redirect::permanent("/spa") }))
        .route("/htmx/", get(|| async { Redirect::permanent("/htmx") }))
        .route("/auth/", get(|| async { Redirect::permanent("/auth") }))
        .nest("/docs", docs_router)
        .nest("/api", api::create_router(pool.clone()))
        .nest("/api2", api2::create_router(pool.clone()))
        .nest("/spa", spa::create_router())
        .nest("/htmx", htmx::create_router(pool.clone()))
        .nest("/htmx", htmx_secret::create_router())
        .nest("/asset", asset::create_router())
        .nest("/auth", auth::create_router(state.clone()))
        .nest("/crud", user::create_router(pool.clone()))
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
