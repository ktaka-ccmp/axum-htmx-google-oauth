use aide::axum::{routing::get_with, ApiRouter, IntoApiResponse};
use askama_axum::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
};

use crate::middleware::check_hx_request;

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route(
            "/content.secret1",
            get_with(content_secret1, |op| op.tag("htmx_secret")),
        )
        .api_route(
            "/content.secret2",
            get_with(content_secret2, |op| op.tag("htmx_secret")),
        )
        .route_layer(axum::middleware::from_fn(check_hx_request))
    // .fallback(page_not_found)
}

#[derive(Template)]
#[template(path = "content.secret.j2")]
struct ContentSecretTemplate {
    title: String,
    img_url: String,
}

async fn content_secret1() -> impl IntoApiResponse {
    let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");

    let template = ContentSecretTemplate {
        title: "Oops, my secret's been revealed!".to_string(),
        img_url: format!("{}/asset/secret1.png", origin_server),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

async fn content_secret2() -> impl IntoApiResponse {
    let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");

    let template = ContentSecretTemplate {
        title: "Believe it or not, it's absolutely not me!".to_string(),
        img_url: format!("{}/asset/secret2.png", origin_server),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}
