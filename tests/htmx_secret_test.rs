#[cfg(test)]
mod tests {
    use aide::axum::ApiRouter;
    use api_server_htmx::htmx_secret::create_router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot` method // for `collect`

    async fn send_request(router: &ApiRouter, uri: &str) -> Response {
        let request = Request::builder()
            .uri(uri)
            .header("HX-Request", "true") // Simulating an HX request
            .body(Body::empty())
            .unwrap();

        router.clone().oneshot(request).await.unwrap()
    }

    async fn assert_response_contains(router: &ApiRouter, uri: &str, expected: &str) {
        let response = send_request(router, uri).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_byte = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_byte.to_vec()).unwrap();

        println!("{:?}", body_str);
        assert!(body_str.contains(expected));
    }

    async fn assert_response_not_ok(router: &ApiRouter, uri: &str) {
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_content_secret1() {
        let router = create_router();
        dotenv::dotenv().ok();
        let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");
        assert_response_contains(
            &router,
            "/content.secret1",
            &format!("{}/img/secret1.png", origin_server),
        )
        .await;
        assert_response_contains(
            &router,
            "/content.secret1",
            "Oops, my secret&#x27;s been revealed!",
        )
        .await;
    }

    #[tokio::test]
    async fn test_content_secret2() {
        let router = create_router();
        dotenv::dotenv().ok();
        let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");
        assert_response_contains(
            &router,
            "/content.secret2",
            &format!("{}/img/secret2.png", origin_server),
        )
        .await;
        assert_response_contains(
            &router,
            "/content.secret2",
            "Believe it or not, it&#x27;s absolutely not me!",
        )
        .await;
    }

    #[tokio::test]
    async fn test_content_secret1_without_hx_request() {
        let router = create_router();
        assert_response_not_ok(&router, "/content.secret1").await;
    }

    #[tokio::test]
    async fn test_content_secret2_without_hx_request() {
        let router = create_router();
        assert_response_not_ok(&router, "/content.secret2").await;
    }
}
