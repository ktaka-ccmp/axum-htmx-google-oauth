use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(FromRow, Serialize, JsonSchema)]
pub struct Customer {
    pub id: i32,
    pub name: String,
    pub email: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct CustomerId {
    /// The ID of the Customer.
    pub id: i32,
}

#[derive(Serialize)]
pub struct Error {
    pub error: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    pub skip: Option<i32>,
    pub limit: Option<i32>,
}
