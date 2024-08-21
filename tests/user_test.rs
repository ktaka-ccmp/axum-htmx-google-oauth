#[cfg(test)]
mod tests {
    use aide::axum::ApiRouter;
    use api_server_htmx::{models::User, user::create_router};
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use serde::{Deserialize, Serialize};
    use sqlx::{Pool, Sqlite};
    use tokio;
    use tower::ServiceExt;

    // use sqlx::{Encode, Pool, Sqlite, Type};
    type DB = Sqlite;

    async fn create_app(pool: Pool<DB>) -> Result<ApiRouter, sqlx::Error> {
        match prep_pool(&pool).await {
            Ok(_) => {
                let app = create_router(pool);
                Ok(app)
            }
            Err(e) => return Err(e),
        }
    }

    async fn prep_pool(pool: &Pool<DB>) -> Result<&Pool<DB>, sqlx::Error> {
        let user = User {
            id: Some(1),
            sub: "sub".to_string(),
            name: "name".to_string(),
            email: "email".to_string(),
            enabled: Some(true),
            admin: Some(false),
            picture: None,
        };

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sub TEXT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            admin BOOLEAN DEFAULT FALSE,
            picture TEXT)",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "INSERT INTO user (id, sub, name, email, enabled, admin, picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(user.id)
        .bind(user.sub)
        .bind(user.name)
        .bind(user.email)
        .bind(user.enabled)
        .bind(user.admin)
        .bind(user.picture)
        .execute(pool)
        .await?;

        Ok(pool)
    }

    #[tokio::test]
    async fn test_get_users() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let request = Request::builder()
            .uri("/users")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_user_by_name() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/user/name")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_user_by_name_not_found() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/user/name_not_found")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_user_by_sub() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/user/sub/sub")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_user_by_id() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/user/id/1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[derive(Serialize, Deserialize)]
    struct UserPatch {
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        admin: Option<bool>,
        picture: Option<String>,
    }

    #[tokio::test]
    async fn test_update_user() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let user_patch = UserPatch {
            id: 1,
            name: Some("new_name".to_string()),
            enabled: None,
            admin: None,
            picture: None,
        };

        let request = Request::builder()
            .method(Method::PATCH)
            .uri("/user")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&user_patch).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // let status = response.status().clone();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(response_body["name"], "new_name");

        // println!("response_body: {:?}", response_body["name"]);
        // assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_user() {
        let pool = Pool::<DB>::connect(":memory:").await.unwrap();
        let app = create_app(pool).await.unwrap();

        let user = User {
            id: None,
            sub: "sub".to_string(),
            name: "name".to_string(),
            email: "email2".to_string(),
            enabled: None,
            admin: None,
            picture: None,
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/user")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&user).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
