use aide::axum::routing::get_with;
use aide::axum::ApiRouter;
use askama_axum::Template;
use axum::extract::Path;
use axum::response::Html;

#[derive(Template)]
#[template(path = "spa.j2")]
struct SpaTemplate {
    title: String,
    page: String,
}

async fn get_top_page() -> Html<String> {
    let page = "content.top".to_string();
    println!("page: {:?}", page);

    let template = SpaTemplate {
        title: "Htmx Spa".to_string(),
        page,
    };
    Html(template.render().unwrap())
}

async fn get_spa(Path(page): Path<String>) -> Html<String> {
    println!("page: {:?}", page);

    let template = SpaTemplate {
        title: "Htmx Spa".to_string(),
        page,
    };
    Html(template.render().unwrap())
}

pub fn create_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/", get_with(get_top_page, |op| op.tag("spa")))
        .api_route("/:page", get_with(get_spa, |op| op.tag("spa")))
}
