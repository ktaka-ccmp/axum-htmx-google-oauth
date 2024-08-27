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

#[derive(Serialize, Debug)]
pub struct Error {
    pub error: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    pub skip: Option<i32>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct IdInfo {
    pub iss: String,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub picture: Option<String>,
    pub given_name: String,
    pub family_name: String,
    pub locale: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub jti: String,
    pub nonce: Option<String>,
    pub hd: Option<String>,
}

#[derive(FromRow, Serialize, JsonSchema, Deserialize, Debug, Clone)]
pub struct User {
    pub id: Option<i64>,
    pub sub: String,
    pub name: String,
    pub email: String,
    pub enabled: Option<bool>,
    pub admin: Option<bool>,
    pub picture: Option<String>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub csrf_token: String,
    pub user_id: i64,
    pub email: String,
    pub expires: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct XCsrfToken {
    pub x_csrf_token: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct XUserToken {
    pub x_user_token: String,
}
