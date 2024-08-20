use aide::axum::{
    routing::{get_with, post_with},
    ApiRouter, IntoApiResponse,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::error;

use crate::models::{Error, Params, User};

// pub fn create_router(pool: SqlitePool) -> ApiRouter {
//     ApiRouter::new()
//         .api_route("/users", get_with(get_users, |op| op.tag("user")))
//         .api_route(
//             "/user/:name",
//             get_with(get_user_by_name, |op| op.tag("user")),
//         )
//         .api_route("/user", post_with(create_user, |op| op.tag("user")))
//         // .api_route("/user/:name", delete_with(delete_user, |op| op.tag("user")))
//         .with_state(pool)
// }

pub fn create_router(pool: SqlitePool) -> ApiRouter {
    ApiRouter::new()
        .api_route("/users", get_with(get_users, |op| op.tag("user")))
        .api_route(
            "/user/:name",
            get_with(get_user_by_name, |op| op.tag("user")),
        )
        .api_route("/user", post_with(create_user, |op| op.tag("user")))
        .with_state(pool)
}

async fn get_users(
    Query(params): Query<Params>,
    State(pool): State<SqlitePool>,
) -> impl IntoApiResponse {
    let skip = params.skip.unwrap_or(0);
    let limit = params.limit.unwrap_or(10);

    let users_result = sqlx::query_as::<_, User>("SELECT * FROM user LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(skip)
        .fetch_all(&pool)
        .await;

    println!("users_result: {:?}", users_result);

    match users_result {
        Ok(users) => (StatusCode::OK, Json(users)).into_response(),
        Err(e) => {
            error!("Database error: {:?}", e);
            let error_response = Error {
                error: format!("Internal Server Error: {:?}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

async fn get_user_by_name(
    Path(name): Path<String>,
    State(pool): State<SqlitePool>,
) -> impl IntoApiResponse {
    let user_result = sqlx::query_as::<_, User>("SELECT * FROM user WHERE name = ?")
        .bind(name)
        .fetch_one(&pool)
        .await;

    match user_result {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(e) => match e {
            sqlx::Error::RowNotFound => (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: "User not found".to_string(),
                }),
            )
                .into_response(),
            _ => {
                error!("Database error: {:?}", e);
                let error_response = Error {
                    error: format!("Internal Server Error: {:?}", e),
                };
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
            }
        },
    }
}

async fn create_user(
    Json(user_data): Json<User>,
    State(pool): State<SqlitePool>,
) -> impl IntoApiResponse {
    match get_user_by_email(&user_data.email, &pool).await {
        Ok(existing_user) => {
            let error_response = json!({
                "error": format!(
                    "User already exists with email: {:?}, sub: {:?}",
                    existing_user.email, existing_user.sub
                )
            });
            (StatusCode::BAD_REQUEST, Json(error_response))
        }
        Err(_) => match insert_user(&user_data, &pool).await {
            Ok(new_user) => (StatusCode::CREATED, Json(json!(new_user))),
            Err(e) => {
                let error_response = json!({
                    "error": format!("Failed to create user: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            }
        },
    }
}

async fn insert_user(user_data: &User, pool: &SqlitePool) -> Result<User, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO user (sub, name, email, enabled, admin, picture) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&user_data.sub)
    .bind(&user_data.name)
    .bind(&user_data.email)
    .bind(user_data.enabled)
    .bind(user_data.admin)
    .bind(&user_data.picture)
    .execute(pool)
    .await?;

    let id = result.last_insert_rowid();
    get_user_by_id(&id, pool).await
}

async fn get_user_by_email(
    email: &String,
    pool: &sqlx::Pool<sqlx::Sqlite>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM user WHERE email = ?")
        .bind(email)
        .fetch_one(pool)
        .await
}

async fn get_user_by_id(id: &i64, pool: &sqlx::Pool<sqlx::Sqlite>) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM user WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}
