#[cfg(test)]
mod tests {
    use api_server_htmx::htmx::create_router;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::{Sqlite, Pool};
    use tower::ServiceExt; // for `app.oneshot()`
    use http_body_util::BodyExt; // for `collect`
    use hyper::body::Bytes;

    async fn get_body_bytes(response: axum::response::Response<Body>) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    async fn get_body_string(response: axum::response::Response<Body>) -> String {
        let body_bytes = get_body_bytes(response).await;
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_content_top_with_hx_request() {
        // Set up the in-memory SQLite pool
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request with the HX-Request header
        let request = Request::builder()
            .uri("/content.top")
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Htmx Spa Top"));
    }

    #[tokio::test]
    async fn test_content_top_without_hx_request() {
        // Set up the in-memory SQLite pool
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request without the HX-Request header
        let request = Request::builder()
            .uri("/content.top")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Only HX request is allowed to this endpoint."));
    }

    #[tokio::test]
    async fn test_content_list_with_hx_request() {
        // Set up the in-memory SQLite pool
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request with the HX-Request header
        let request = Request::builder()
            .uri("/content.list")
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Incremental hx-get demo"));
    }

    #[tokio::test]
    async fn test_content_list_without_hx_request() {
        // Set up the in-memory SQLite pool
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request without the HX-Request header
        let request = Request::builder()
            .uri("/content.list")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Only HX request is allowed to this endpoint."));
    }

    #[tokio::test]
    async fn test_content_list_tbody_with_hx_request() {
        // Set up the in-memory SQLite pool and create a test customer table
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE customer (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            );
            INSERT INTO customer (name, email) VALUES ('John Doe', 'john.doe@example.com');
            "#
        ).execute(&pool).await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request with the HX-Request header
        let request = Request::builder()
            .uri("/content.list.tbody")
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("John Doe"));
    }

    #[tokio::test]
    async fn test_content_list_tbody_without_hx_request() {
        // Set up the in-memory SQLite pool
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();

        // Create the router
        let app = create_router(pool.clone());

        // Create a request without the HX-Request header
        let request = Request::builder()
            .uri("/content.list.tbody")
            .body(Body::empty())
            .unwrap();

        // Send the request
        let response = app.oneshot(request).await.unwrap();

        // Assert the response status and body
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Only HX request is allowed to this endpoint."));
    }
}
