//! Async Postgres pool construction.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Error returned when async Postgres pool setup fails.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// SQLx could not establish the pool.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Builds a SQLx Postgres pool.
///
/// The caller chooses the connection string, including TLS mode. Production
/// callers should use a TLS-enforcing `PgConnectOptions` when they need
/// stricter configuration than URL parameters provide.
///
/// # Errors
///
/// Returns [`PoolError::Sqlx`] when SQLx cannot connect or initialize the pool.
pub async fn build_pool(connection_url: &str, max_connections: u32) -> Result<PgPool, PoolError> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connection_url)
        .await?;
    Ok(pool)
}
