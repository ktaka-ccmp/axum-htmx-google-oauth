#[cfg(test)]
mod tests {
    use aide::axum::ApiRouter;
    use api_server_htmx::htmx_secret::create_router;
    use api_server_htmx::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use http_body_util::BodyExt;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;
    use async_trait::async_trait;
    use api_server_htmx::models::Session;
    use api_server_htmx::cachestore::{CacheStore, CacheStoreError};
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct MockCacheStore {
        sessions: Mutex<HashMap<String, Session>>,
    }

    #[async_trait]
    impl CacheStore for MockCacheStore {
        async fn get_session(&self, session_id: &str) -> Result<Option<Session>, CacheStoreError> {
            let sessions = self.sessions.lock().await;
            Ok(sessions.get(session_id).cloned())
        }

        async fn list_sessions(&self) -> Result<Vec<Session>, CacheStoreError> {
            let sessions = self.sessions.lock().await;
            Ok(sessions.values().cloned().collect())
        }

        async fn create_session(&self, user_id: i64, email: &str) -> Result<Session, CacheStoreError> {
            let mut sessions = self.sessions.lock().await;
            let session = Session {
                session_id: format!("test_session_{}", user_id),
                csrf_token: "test_csrf_token".to_string(),
                user_id,
                email: email.to_string(),
                expires: chrono::Utc::now().timestamp() + 3600, // 1 hour from now
            };
            sessions.insert(session.session_id.clone(), session.clone());
            Ok(session)
        }

        async fn delete_session(&self, session_id: &str) -> Result<(), CacheStoreError> {
            let mut sessions = self.sessions.lock().await;
            sessions.remove(session_id);
            Ok(())
        }

        async fn cleanup_sessions(&self) -> Result<(), CacheStoreError> {
            let mut sessions = self.sessions.lock().await;
            let now = chrono::Utc::now().timestamp();
            sessions.retain(|_, session| session.expires > now);
            Ok(())
        }
    }

    async fn create_test_app_state() -> Arc<AppState> {
        // Create a SQLite connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        // Create a mock cache store
        let cache = Arc::new(MockCacheStore {
            sessions: Mutex::new(HashMap::new()),
        });

        Arc::new(AppState { pool, cache })
    }

    async fn send_request(router: &ApiRouter, uri: &str) -> Response {
        let request = Request::builder()
            .uri(uri)
            .header("HX-Request", "true")
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

    async fn assert_response_not_ok_wo_hx_request(router: &ApiRouter, uri: &str) {
        let request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::OK);
    }

    async fn create_test_router() -> ApiRouter {
        let state = create_test_app_state().await;
        create_router(state)
    }

    #[tokio::test]
    async fn test_content_secret1() {
        let router = create_test_router().await;
        dotenv::dotenv().ok();
        let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");
        assert_response_contains(
            &router,
            "/content.secret1",
            &format!("{}/asset/secret1.png", origin_server),
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
        let router = create_test_router().await;
        dotenv::dotenv().ok();
        let origin_server = std::env::var("ORIGIN_SERVER").expect("ORIGIN_SERVER must be set");
        assert_response_contains(
            &router,
            "/content.secret2",
            &format!("{}/asset/secret2.png", origin_server),
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
        let router = create_test_router().await;
        assert_response_not_ok_wo_hx_request(&router, "/content.secret1").await;
    }

    #[tokio::test]
    async fn test_content_secret2_without_hx_request() {
        let router = create_test_router().await;
        assert_response_not_ok_wo_hx_request(&router, "/content.secret2").await;
    }
}
