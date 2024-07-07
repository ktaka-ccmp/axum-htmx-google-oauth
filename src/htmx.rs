use aide::axum::{routing::get, ApiRouter};
use askama_axum::Template;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use serde::Serialize;
use sqlx::SqlitePool;
use tracing::error;

use crate::models::{Customer, Params};

/// Creates the API router with the given SQLite pool.
pub fn create_router(pool: SqlitePool) -> ApiRouter {
    ApiRouter::new()
        .api_route("/content.top", get(content_top))
        .api_route("/content.list", get(content_list))
        .api_route("/content.list.tbody", get(content_list_tbody))
        .with_state(pool)
        .fallback(page_not_found)
}

/// Represents a template for rendering the content list.
#[derive(Template)]
#[template(path = "content.top.j2")]
struct ContentTopTemplate {
    title: String,
}

/// Handles the content list request.
async fn content_top(headers: HeaderMap) -> Result<Html<String>, Response> {
    check_hx_request(&headers)?;

    let template = ContentTopTemplate {
        title: "Htmx Spa Top".to_string(),
    };
    Ok(Html(template.render().unwrap()))
}

async fn page_not_found(uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    check_hx_request(&headers).unwrap();
    let title = format!("Page not found: {}", uri);
    println!("Page not found: {:?}", uri);
    let template = ContentTopTemplate {
        title: title,
    };
    let html = Html(template.render().unwrap());
    (StatusCode::NOT_FOUND, html).into_response()
}

/// Represents a template for rendering the content list.
#[derive(Template)]
#[template(path = "content.list.j2")]
struct ContentListTemplate {
    title: String,
    skip_next: i32,
    limit: i32,
}

/// Handles the content list request.
async fn content_list(headers: HeaderMap) -> Result<Html<String>, Response> {
    check_hx_request(&headers)?;

    let template = ContentListTemplate {
        title: "Incremental hx-get demo".to_string(),
        skip_next: 0,
        limit: 2,
    };
    Ok(Html(template.render().unwrap()))
}

/// Represents a template for rendering the content list table body.
#[derive(Template)]
#[template(path = "content.list.tbody.j2")]
struct ContentListTbodyTemplate {
    skip_next: i32,
    limit: i32,
    customers: Vec<Customer>,
}

/// Handles the content list table body request.
async fn content_list_tbody(
    Query(params): Query<Params>,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Html<String>, Response> {
    check_hx_request(&headers)?;

    let skip = params.skip.unwrap_or(0);
    let limit = params.limit.unwrap_or(1);

    let customers = sqlx::query_as::<_, Customer>("SELECT * FROM customer LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(skip)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        })?;

    let template = ContentListTbodyTemplate {
        skip_next: skip + limit,
        limit,
        customers,
    };

    Ok(Html(template.render().unwrap()))
}

/// Represents an error response.
#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, axum::Json(self)).into_response()
    }
}

/// Checks if the request is an HX request.
/// Returns an error response if the request is not an HX request.
fn check_hx_request(headers: &HeaderMap) -> Result<(), Response> {
    if headers.get("HX-Request").is_none() {
        Err(ErrorResponse {
            detail: "Only HX request is allowed to this endpoint.".to_string(),
        }
        .into_response())
    } else {
        Ok(())
    }
}
