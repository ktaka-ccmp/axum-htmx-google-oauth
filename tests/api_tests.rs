#[cfg(test)]
mod tests {
    use api_server_htmx::api::create_router;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use hyper::body::Bytes;
    use sqlx::{Pool, Sqlite};
    use tower::ServiceExt; // for `app.oneshot()`

    async fn get_body_bytes(response: axum::response::Response<Body>) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    async fn get_body_string(response: axum::response::Response<Body>) -> String {
        let body_bytes = get_body_bytes(response).await;
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_get_customers() {
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE customer (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            );
            INSERT INTO customer (name, email) VALUES ('John Doe', 'john.doe@example.com');
            INSERT INTO customer (name, email) VALUES ('Jane Doe', 'jane.doe@example.com');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = create_router(pool.clone());

        let request = Request::builder()
            .uri("/customers")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("John Doe"));
        assert!(body_str.contains("Jane Doe"));
    }

    #[tokio::test]
    async fn test_get_customer_by_id() {
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE customer (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            );
            INSERT INTO customer (name, email) VALUES ('John Doe', 'john.doe@example.com');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = create_router(pool.clone());

        let request = Request::builder()
            .uri("/customer/1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("John Doe"));
    }

    #[tokio::test]
    async fn test_get_customer_by_id_not_found() {
        let pool = Pool::<Sqlite>::connect(":memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE customer (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = create_router(pool.clone());

        let request = Request::builder()
            .uri("/customer/1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_str = get_body_string(response).await;
        assert!(body_str.contains("Customer not found"));
    }
}
