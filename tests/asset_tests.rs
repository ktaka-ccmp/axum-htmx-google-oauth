#[cfg(test)]
mod tests {

    // use api_server_htmx::image::create_router;
    use aide::axum::ApiRouter;
    use api_server_htmx::asset::{
        build_error_response, build_response, create_router, get_handler, get_routes,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Once;
    use tower::ServiceExt; // for `app.oneshot()`

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
        api_server_htmx::asset::create_router().into()
    }

    #[tokio::test]
    async fn test_image_routes() {
        let router = test_router().await;

        let routes = api_server_htmx::asset::get_routes();

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

    #[tokio::test]
    async fn test_get_routes() {
        let routes = get_routes();
        assert_eq!(routes.len(), 6);
        assert_eq!(
            routes[0],
            (
                "assets/dog_meme.png",
                "/secret1.png",
                "image",
                "Secret file"
            )
        );
    }

    #[tokio::test]
    async fn test_create_router() {
        let app = create_router();

        // Test a valid route
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/secret1.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/png");

        // Test an invalid route
        let response = app
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

    #[tokio::test]
    async fn test_get_handler() {
        let response =
            askama_axum::IntoResponse::into_response(get_handler("assets/dog_meme.png").await);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/png");

        let response =
            askama_axum::IntoResponse::into_response(get_handler("assets/nonexistent.png").await);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_build_response() {
        let contents = vec![1, 2, 3];
        let response = build_response(contents.clone(), "application/octet-stream".to_string());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );

        // Check response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body, contents);
    }

    #[tokio::test]
    async fn test_build_error_response() {
        let response = build_error_response(StatusCode::NOT_FOUND, "File not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["content-type"], "text/plain");

        // Check response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body, "File not found".as_bytes());
    }
}
