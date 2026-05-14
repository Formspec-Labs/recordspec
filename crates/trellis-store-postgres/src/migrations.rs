// Rust guideline compliant 2026-02-21
//! Versioned schema migrations for `trellis-store-postgres`.
//!
//! Replaces the prior ad-hoc `CREATE TABLE IF NOT EXISTS` with an
//! append-only migration ledger (`trellis_schema_migrations`). The migration
//! list lives below; **never edit a landed migration**, only append new ones.
//!
//! Each version's SQL must be idempotent **at that version**: running v1 on
//! an empty database creates the table; rerunning v1 against a v1 database
//! is a no-op skipped via the migrations table. The runner takes a
//! transaction-bracketed advisory lock so two replicas connecting at startup
//! cannot race a duplicate apply.

use crate::{PostgresStoreError, PostgresStoreErrorKind};
pub use trellis_store_postgres_shared::migrations::{ADVISORY_LOCK_KEY, MIGRATIONS};

/// Apply pending migrations against an existing client (connection or pooled).
pub(crate) fn apply<C>(client: &mut C) -> Result<(), PostgresStoreError>
where
    C: ClientLike,
{
    client
        .batch_execute(
            "\
CREATE TABLE IF NOT EXISTS trellis_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);",
        )
        .map_err(|error| {
            PostgresStoreError::new(
                PostgresStoreErrorKind::MigrationFailed,
                format!("failed to ensure trellis_schema_migrations table: {error}"),
            )
        })?;

    let mut tx = client.transaction().map_err(|error| {
        PostgresStoreError::new(
            PostgresStoreErrorKind::MigrationFailed,
            format!("failed to begin migration transaction: {error}"),
        )
    })?;

    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY])
        .map_err(|error| {
            PostgresStoreError::new(
                PostgresStoreErrorKind::MigrationFailed,
                format!("failed to acquire advisory lock for migrations: {error}"),
            )
        })?;

    let applied = tx
        .query("SELECT version FROM trellis_schema_migrations", &[])
        .map_err(|error| {
            PostgresStoreError::new(
                PostgresStoreErrorKind::MigrationFailed,
                format!("failed to read trellis_schema_migrations: {error}"),
            )
        })?
        .into_iter()
        .map(|row| row.get::<_, i32>("version"))
        .collect::<std::collections::BTreeSet<_>>();

    // Refuse-on-future-version guard. "Append-only migrations" is convention;
    // at v3+ a binary that ships only v1+v2 must NOT silently re-skip and
    // declare success against a database that has already seen v4. Compare
    // the highest applied version against the highest declared version; if
    // the database is ahead, the binary is stale — bail with a clear error
    // so the operator rolls forward (or rolls back the database) rather than
    // silently truncating schema awareness.
    if let (Some(applied_max), Some(declared_max)) = (
        applied.iter().max().copied(),
        MIGRATIONS.iter().map(|migration| migration.version).max(),
    ) && applied_max > declared_max
    {
        return Err(PostgresStoreError::new(
            PostgresStoreErrorKind::MigrationFailed,
            format!(
                "schema ahead of binary: database recorded migration v{applied_max} but this binary declares only v{declared_max}; refusing to apply"
            ),
        ));
    }

    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }
        tx.batch_execute(migration.up_sql).map_err(|error| {
            PostgresStoreError::new(
                PostgresStoreErrorKind::MigrationFailed,
                format!(
                    "migration v{} ({}) failed: {error}",
                    migration.version, migration.name
                ),
            )
        })?;
        tx.execute(
            "INSERT INTO trellis_schema_migrations (version) VALUES ($1)",
            &[&migration.version],
        )
        .map_err(|error| {
            PostgresStoreError::new(
                PostgresStoreErrorKind::MigrationFailed,
                format!(
                    "failed to record migration v{} applied: {error}",
                    migration.version
                ),
            )
        })?;
    }

    tx.commit().map_err(|error| {
        PostgresStoreError::new(
            PostgresStoreErrorKind::MigrationFailed,
            format!("failed to commit migration transaction: {error}"),
        )
    })?;

    Ok(())
}

/// Minimal abstraction so [`apply`] runs against either a `&mut Client`
/// or a `&mut PooledConnection` — both expose `batch_execute` and `transaction`.
pub(crate) trait ClientLike {
    fn batch_execute(&mut self, sql: &str) -> Result<(), postgres::Error>;
    fn transaction(&mut self) -> Result<postgres::Transaction<'_>, postgres::Error>;
}

impl ClientLike for postgres::Client {
    fn batch_execute(&mut self, sql: &str) -> Result<(), postgres::Error> {
        postgres::Client::batch_execute(self, sql)
    }
    fn transaction(&mut self) -> Result<postgres::Transaction<'_>, postgres::Error> {
        postgres::Client::transaction(self)
    }
}

impl<M: r2d2::ManageConnection<Connection = postgres::Client>> ClientLike
    for r2d2::PooledConnection<M>
{
    fn batch_execute(&mut self, sql: &str) -> Result<(), postgres::Error> {
        postgres::Client::batch_execute(self, sql)
    }
    fn transaction(&mut self) -> Result<postgres::Transaction<'_>, postgres::Error> {
        postgres::Client::transaction(self)
    }
}
