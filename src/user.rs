use aide::axum::{
    routing::{delete_with, get_with, post_with},
    ApiRouter, IntoApiResponse,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use tracing::error;

use sqlx::{Encode, MySql, Pool, Postgres, Sqlite, Type};
type DB = Sqlite;
// type DB = Postgres;

use crate::models::{Error, Params, User};

pub fn create_router(pool: Pool<DB>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/users", get_with(hn_get_users, |op| op.tag("user")))
        .api_route(
            "/user/:name",
            get_with(hn_get_user_by_name, |op| op.tag("user")),
        )
        .api_route("/user", post_with(hn_create_user, |op| op.tag("user")))
        .api_route(
            "/user/sub/:sub",
            delete_with(hn_delete_user_by_sub, |op| op.tag("user")),
        )
        .api_route(
            "/user/id/:id",
            delete_with(hn_delete_user_by_id, |op| op.tag("user")),
        )
        .with_state(pool)
}

async fn hn_get_users(
    Query(params): Query<Params>,
    State(pool): State<Pool<DB>>,
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

async fn hn_get_user_by_name(
    Path(name): Path<String>,
    State(pool): State<Pool<DB>>,
) -> impl IntoApiResponse {
    let user_result = sqlx::query_as::<_, User>("SELECT * FROM user WHERE name = ?")
        .bind(name)
        .fetch_all(&pool)
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

async fn hn_delete_user_by_sub(
    State(pool): State<Pool<DB>>,
    Path(sub): Path<i64>,
) -> impl IntoApiResponse {
    hn_delete_user_by_field("sub", &sub, &pool).await
}

async fn hn_delete_user_by_id(
    State(pool): State<Pool<DB>>,
    Path(id): Path<i64>,
) -> impl IntoApiResponse {
    hn_delete_user_by_field("id", &id, &pool).await
}

async fn hn_delete_user_by_field<'a, T>(
    field: &str,
    value: &T,
    pool: &Pool<DB>,
) -> impl IntoApiResponse
where
    T: Type<DB> + Send + Sync,
    for<'q> &'q T: Encode<'q, DB> + Type<DB>,
{
    match delete_user_by_field(field, &value, &pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "User deleted" }))).into_response(),
        Err(sqlx::Error::RowNotFound) => (
            StatusCode::NOT_FOUND,
            Json(Error {
                error: "User not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            error!("Database error: {:?}", e);
            let error_response = Error {
                error: format!("Internal Server Error: {:?}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

async fn hn_create_user(
    State(pool): State<Pool<DB>>,
    Json(user_data): Json<User>,
) -> impl IntoApiResponse {
    match get_user_by_email(&user_data.email, &pool).await {
        Ok(Some(user_data)) => {
            let error_response = json!({
                "error": format!(
                    "User already exists with email: {:?}, sub: {:?}",
                    user_data.email, user_data.sub
                )
            });
            (StatusCode::BAD_REQUEST, Json(error_response))
        }
        Ok(None) => match create_user(user_data, &pool).await {
            Ok(new_user) => (StatusCode::CREATED, Json(json!(new_user))),
            Err(e) => {
                let error_response = json!({
                    "error": format!("Failed to create user: {}", e)
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            }
        },
        Err(e) => {
            let error_response = json!({
                "error": format!("Failed to create user: {}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        }
    }
}

pub async fn create_user(mut user_data: User, pool: &Pool<DB>) -> Result<User, sqlx::Error> {
    if user_data.admin.is_none() {
        user_data.admin = Some(false);
    }
    if user_data.enabled.is_none() {
        user_data.enabled = Some(true);
    }
    if user_data.picture.is_none() {
        user_data.picture = None;
    }

    println!("user_data: {:?}", user_data);

    let result = sqlx::query(
        "INSERT INTO user (sub, name, email, enabled, admin, picture) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_data.sub)
    .bind(user_data.name)
    .bind(user_data.email)
    .bind(user_data.enabled)
    .bind(user_data.admin)
    .bind(user_data.picture)
    .execute(pool)
    .await?;

    let id = result.last_insert_rowid();

    match get_user_by_id(&id, pool).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(sqlx::Error::RowNotFound),
        Err(e) => Err(e),
    }
}

pub async fn get_user_by_email(email: &String, pool: &Pool<DB>) -> Result<Option<User>, sqlx::Error> {
    get_user_by_field("email", email, pool).await
}

pub async fn get_user_by_sub(sub: &i64, pool: &Pool<DB>) -> Result<Option<User>, sqlx::Error> {
    get_user_by_field("sub", sub, pool).await
}

pub async fn get_user_by_id(id: &i64, pool: &Pool<DB>) -> Result<Option<User>, sqlx::Error> {
    get_user_by_field("id", id, pool).await
}

async fn get_user_by_field<'a, T>(
    field: &str,
    value: &T,
    pool: &Pool<DB>,
) -> Result<Option<User>, sqlx::Error>
where
    T: Type<DB> + Send + Sync,
    for<'q> &'q T: Encode<'q, DB> + Type<DB>,
{
    let query = format!("SELECT * FROM user WHERE {} = ?", field);
    let user_in_db = sqlx::query_as::<_, User>(&query)
        .bind(value)
        .fetch_one(pool)
        .await;

    match user_in_db {
        Ok(user) => Ok(Some(user)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => {
            error!("DB error in get_user_by_{}: {:?}", field, e);
            Err(e)
        }
    }
}

pub async fn delete_user_by_sub(sub: &i64, pool: &Pool<DB>) -> Result<(), sqlx::Error> {
    delete_user_by_field("sub", sub, pool).await
}

pub async fn delete_user_by_id(id: &i64, pool: &Pool<DB>) -> Result<(), sqlx::Error> {
    delete_user_by_field("id", id, pool).await
}

async fn delete_user_by_field<'a, T>(
    field: &str,
    value: &T,
    pool: &Pool<DB>,
) -> Result<(), sqlx::Error>
where
    T: Type<DB> + Send + Sync,
    for<'q> &'q T: Encode<'q, DB> + Type<DB>,
{
    let query = format!("DELETE FROM user WHERE {} = ?", field);
    let result = sqlx::query(&query).bind(value).execute(pool).await?;

    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    Ok(())
}
