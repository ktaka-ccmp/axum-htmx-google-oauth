use aide::axum::{routing::get, ApiRouter, IntoApiResponse};
use askama_axum::Template;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
};

use crate::htmx::check_hx_request;

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/content.secret1", get(content_secret1))
        .api_route("/content.secret2", get(content_secret2))
        // .fallback(page_not_found)
}

#[derive(Template)]
#[template(path = "content.secret.j2")]
struct ContentSecretTemplate {
    title: String,
    img_url: String,
}

async fn content_secret1(headers: HeaderMap) -> impl IntoApiResponse {
    if let Err(err) = check_hx_request(&headers) {
        return err;
    }

    let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");

    let template = ContentSecretTemplate {
        title: "Oops, my secret's been revealed!".to_string(),
        img_url: format!("{}/img/secret1.png", origin_server),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

async fn content_secret2(headers: HeaderMap) -> impl IntoApiResponse {
    if let Err(err) = check_hx_request(&headers) {
        return err;
    }

    let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");

    let template = ContentSecretTemplate {
        title: "Believe it or not, it's absolutely not me!".to_string(),
        img_url: format!("{}/img/secret2.png", origin_server),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}
