use aide::axum::{routing::get_with, ApiRouter, IntoApiResponse};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::Pool;
use tracing::error;

use crate::DB;

use crate::models::{Customer, CustomerId, Error, Params};

async fn customers(
    Query(params): Query<Params>,
    State(pool): State<Pool<DB>>,
) -> impl IntoApiResponse {
    let skip = params.skip.unwrap_or(0);
    let limit = params.limit.unwrap_or(10); // Adjusted default limit from 1 to 10

    let customers_result = sqlx::query_as::<_, Customer>("SELECT * FROM customer LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(skip)
        .fetch_all(&pool)
        .await;

    match customers_result {
        Ok(customers) => (StatusCode::OK, Json(customers)).into_response(),
        Err(e) => {
            error!("Database error: {:?}", e);
            let error_response = Error {
                error: format!("Internal Server Error: {:?}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

async fn customer(
    Path(cid): Path<CustomerId>,
    State(pool): State<Pool<DB>>,
) -> impl IntoApiResponse {
    let customer_result = sqlx::query_as::<_, Customer>("SELECT * FROM customer WHERE id = ?")
        .bind(cid.id)
        .fetch_one(&pool)
        .await;

    match customer_result {
        Ok(customer) => (StatusCode::OK, Json(customer)).into_response(),
        Err(e) => match e {
            sqlx::Error::RowNotFound => (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: "Customer not found".to_string(),
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

pub fn create_router(pool: Pool<DB>) -> ApiRouter {
    ApiRouter::new()
        .api_route("/customers", get_with(customers, |op| op.tag("api")))
        .api_route("/customer/:id", get_with(customer, |op| op.tag("api")))
        .with_state(pool)
}
