use async_trait::async_trait;
use chrono::Utc;
use rand::{thread_rng, Rng};
use redis;
use redis::{AsyncCommands, Client as RedisClient};
use serde::{Deserialize, Serialize};
use sqlx::Pool;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::DB;

#[derive(Error, Debug)]
pub enum CacheStoreError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Session not found")]
    SessionNotFound,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Environment variable not set: {0}")]
    EnvVarError(#[from] std::env::VarError),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug)]
pub struct Session {
    pub session_id: String,
    pub csrf_token: String,
    pub user_id: i64,
    pub email: String,
    expires: i64,
}

#[async_trait]
pub trait CacheStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, CacheStoreError>;
    async fn list_sessions(&self) -> Result<Vec<Session>, CacheStoreError>;
    async fn create_session(&self, user_id: i64, email: &str) -> Result<Session, CacheStoreError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), CacheStoreError>;
    async fn cleanup_sessions(&self) -> Result<(), CacheStoreError>;
}

struct SqlCacheStore {
    pool: Pool<DB>,
}

#[async_trait]
impl CacheStore for SqlCacheStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, CacheStoreError> {
        let session = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(session)
    }

    async fn list_sessions(&self) -> Result<Vec<Session>, CacheStoreError> {
        let sessions = sqlx::query_as::<_, Session>("SELECT * FROM sessions LIMIT 100")
            .fetch_all(&self.pool)
            .await?;

        Ok(sessions)
    }

    async fn create_session(&self, user_id: i64, email: &str) -> Result<Session, CacheStoreError> {
        let session_id = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>();
        let csrf_token = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let expires = Utc::now() + Duration::from_secs(3600); // 1 hour expiration

        let session = sqlx::query_as::<_, Session>(
            "INSERT INTO sessions (session_id, csrf_token, user_id, email, expires) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING *",
        )
        .bind(&session_id)
        .bind(&csrf_token)
        .bind(user_id)
        .bind(email)
        .bind(expires.timestamp())
        .fetch_one(&self.pool)
        .await?;

        Ok(session)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), CacheStoreError> {
        sqlx::query("DELETE FROM sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn cleanup_sessions(&self) -> Result<(), CacheStoreError> {
        let now = Utc::now().timestamp();
        sqlx::query("DELETE FROM sessions WHERE expires <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
struct RedisCacheStore {
    client: RedisClient,
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, CacheStoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_data: Option<String> = conn.get(format!("session:{}", session_id)).await?;
        Ok(session_data
            .map(|data| serde_json::from_str(&data).map_err(CacheStoreError::from))
            .transpose()?)
    }

    async fn list_sessions(&self) -> Result<Vec<Session>, CacheStoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let keys: Vec<String> = conn.keys("session:*").await?;
        let mut sessions = Vec::new();
        for key in keys {
            let data: String = conn.get(&key).await?;
            sessions.push(serde_json::from_str(&data)?);
        }
        Ok(sessions)
    }

    async fn create_session(&self, user_id: i64, email: &str) -> Result<Session, CacheStoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let session_id = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>();
        let csrf_token = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let expires = Utc::now() + Duration::from_secs(3600); // 1 hour expiration

        let session = Session {
            session_id: session_id.clone(),
            csrf_token,
            user_id,
            email: email.to_string(),
            expires: expires.timestamp(),
        };

        conn.set_ex(
            format!("session:{}", session_id),
            serde_json::to_string(&session)?,
            3600,
        )
        .await?;

        Ok(session)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), CacheStoreError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del(format!("session:{}", session_id)).await?;
        Ok(())
    }

    async fn cleanup_sessions(&self) -> Result<(), CacheStoreError> {
        // Redis handles expiration automatically
        Ok(())
    }
}

pub async fn get_cache_store() -> Result<Arc<dyn CacheStore + Send + Sync>, CacheStoreError> {
    let cache_store = std::env::var("CACHE_STORE").unwrap_or_else(|_| "sql".to_string());

    match cache_store.as_str() {
        "redis" => {
            let redis_url = std::env::var("CACHE_REDIS_URL")?;
            let client = RedisClient::open(redis_url)?;
            Ok(Arc::new(RedisCacheStore { client }))
        }
        _ => {
            let database_url = std::env::var("CACHE_DB_URL")?;
            let pool = Pool::connect(&database_url).await?;
            Ok(Arc::new(SqlCacheStore { pool }))
        }
    }
}
