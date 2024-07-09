#[cfg(test)]
mod tests {
    
    // use api_server_htmx::image::create_router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `app.oneshot()`
    use std::sync::Once;
    use aide::axum::ApiRouter;
    
    // Initialize logging for tests
    static INIT: Once = Once::new();
    fn init_logging() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    // Create the test router
    async fn test_router() -> ApiRouter {
        init_logging();
        api_server_htmx::image::create_router().into()
    }

    #[tokio::test]
    async fn test_image_routes() {
        let router = test_router().await;

        let routes = api_server_htmx::image::get_routes();

        for (_, route, _, _) in &routes {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri::<String>(route.to_string().parse().unwrap())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "Failed route: {}", route);
        }
    }

    #[tokio::test]
    async fn test_nonexistent_route() {
        let router = test_router().await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/nonexistent.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
