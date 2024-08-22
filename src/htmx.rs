use aide::axum::{routing::get_with, ApiRouter, IntoApiResponse};
use askama_axum::Template;
use axum::{
    extract::{Query, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse},
};
use sqlx::Pool;
use tracing::error;

use crate::models::{Customer, Params};
use crate::middleware::check_hx_request;
use crate::DB;

/// Creates the API router with the given SQLite pool.
pub fn create_router(pool: Pool<DB>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/content.top", get_with(content_top, |op| op.tag("htmx")))
        .api_route("/content.list", get_with(content_list, |op| op.tag("htmx")))
        .api_route(
            "/content.list.tbody",
            get_with(content_list_tbody, |op| op.tag("htmx")),
        )
        .with_state(pool)
        .route_layer(axum::middleware::from_fn(check_hx_request))
        .fallback(page_not_found)
}

/// Represents a template for rendering the content.
#[derive(Template)]
#[template(path = "content.top.j2")]
struct ContentTopTemplate {
    title: String,
}

/// Handles the content list request.
async fn content_top() -> impl IntoApiResponse {
    let template = ContentTopTemplate {
        title: "Htmx Spa Top".to_string(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
    // The following line also works:
    // Html(template.render().unwrap()).into_response()
}

/// Fallback route for handling 404 - Page Not Found.
async fn page_not_found(uri: Uri) -> impl IntoApiResponse {
    let title = format!("Page not found: {}", uri);
    println!("Page not found: {:?}", uri);
    let template = ContentTopTemplate { title };
    (StatusCode::NOT_FOUND, Html(template.render().unwrap())).into_response()
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
async fn content_list() -> impl IntoApiResponse {
    let template = ContentListTemplate {
        title: "Incremental hx-get demo".to_string(),
        skip_next: 0,
        limit: 2,
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
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
    State(pool): State<Pool<DB>>,
) -> impl IntoApiResponse {
    let skip = params.skip.unwrap_or(0);
    let limit = params.limit.unwrap_or(1);

    let customers = match sqlx::query_as::<_, Customer>("SELECT * FROM customer LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(skip)
        .fetch_all(&pool)
        .await
    {
        Ok(customers) => customers,
        Err(e) => {
            error!("Database error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
        }
    };

    let template = ContentListTbodyTemplate {
        skip_next: skip + limit,
        limit,
        customers,
    };

    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}
