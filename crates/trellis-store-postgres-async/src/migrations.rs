//! Async migration runner for the Trellis Postgres schema.

use sqlx::PgPool;
use trellis_store_postgres_shared::migrations::{ADVISORY_LOCK_KEY, MIGRATIONS};

/// Error returned by async migration setup.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// Database schema has a migration version this binary does not know.
    #[error(
        "schema ahead of binary: applied version {applied_version}, declared max {declared_max}"
    )]
    SchemaAhead {
        /// Highest version recorded in the database.
        applied_version: i32,
        /// Highest version declared by this binary.
        declared_max: i32,
    },
    /// SQL execution failed while applying or recording migrations.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Applies pending Trellis Postgres migrations.
///
/// The migration list and advisory-lock key are shared with the sync adapter.
/// Rows are append-only: old migration SQL must not be edited after landing.
///
/// # Errors
///
/// Returns [`MigrationError::SchemaAhead`] when the database records a newer
/// migration than this binary declares, or [`MigrationError::Sqlx`] for SQL
/// execution failures.
pub async fn run_migrations(pool: &PgPool) -> Result<(), MigrationError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "\
CREATE TABLE IF NOT EXISTS trellis_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)",
    )
    .execute(&mut *tx)
    .await?;

    let applied: Vec<i32> = sqlx::query_scalar("SELECT version FROM trellis_schema_migrations")
        .fetch_all(&mut *tx)
        .await?;
    detect_forward_rollback(&applied)?;

    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }
        sqlx::raw_sql(migration.up_sql).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO trellis_schema_migrations (version) VALUES ($1)")
            .bind(migration.version)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}

fn detect_forward_rollback(applied: &[i32]) -> Result<(), MigrationError> {
    let Some(applied_version) = applied.iter().max().copied() else {
        return Ok(());
    };
    let declared_max = MIGRATIONS
        .iter()
        .map(|migration| migration.version)
        .max()
        .unwrap_or_default();
    if applied_version > declared_max {
        return Err(MigrationError::SchemaAhead {
            applied_version,
            declared_max,
        });
    }
    Ok(())
}
