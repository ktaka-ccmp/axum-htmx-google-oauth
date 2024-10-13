pub mod api;
pub mod api2;
pub mod asset;
pub mod auth;
pub mod cachestore;
pub mod debug;
pub mod htmx;
pub mod htmx_secret;
pub mod idtoken;
pub mod middleware;
pub mod models; // Ensure this is also included if models are in a separate file
pub mod oauth2;
pub mod spa;
pub mod user;

use sqlx::{Pool, Sqlite};
use std::sync::Arc;
pub type DB = Sqlite;

pub struct AppState {
    pub pool: Pool<DB>,
    pub cache: Arc<dyn cachestore::CacheStore + Send + Sync>,
}
