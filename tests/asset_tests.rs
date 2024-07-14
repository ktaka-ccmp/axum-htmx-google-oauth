#[cfg(test)]
mod tests {
    use aide::axum::ApiRouter;
    use api_server_htmx::asset::create_router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hyper::Uri;
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
        create_router().into()
    }

    #[tokio::test]
    async fn test_image_routes() {
        let router = test_router().await;

        let routes = vec![
            "/secret1.png",
            "/secret2.png",
            "/icon.png",
            "/logout.png",
            "/admin_icon.webp",
            "/index.html",
        ];

        for route in &routes {
            let uri: Uri = route.parse().unwrap();
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
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
}
