#[cfg(test)]
mod tests {
    use api_server_htmx::spa::create_router;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use hyper::body::Bytes;
    use tower::ServiceExt; // for `app.oneshot()`

    async fn get_body_bytes(response: axum::response::Response<Body>) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    async fn get_body_string(response: axum::response::Response<Body>) -> String {
        let body_bytes = get_body_bytes(response).await;
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_get_spa() {
        let app = create_router();

        let request = Request::builder()
            .uri("/test-page")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        // println!("{}", body_str);
        assert!(body_str.contains("test-page"));
    }

    #[tokio::test]
    async fn test_get_spa_not_found() {
        let app = create_router();

        let request = Request::builder()
            .uri("/non-existent-page")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("non-existent-page"));
    }
}
