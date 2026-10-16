//! Async migration runner for the Trellis Postgres schema.

use sqlx::PgPool;
use stack_common_postgres::{Migration, MigrationSet, run_sqlx_migrations};

const LEDGER_TABLE: &str = "trellis_schema_migrations";

/// Postgres advisory-lock key for the migration runner.
///
/// The lock is transaction-scoped: Postgres releases it atomically on commit
/// or rollback, so failed migration attempts do not leave a process-held lock.
const ADVISORY_LOCK_KEY: i64 = 0x7472_656c_6c69_7300; // "trellis\0"

/// Append-only schema migrations for `trellis_events`.
///
/// Never edit a row that has shipped. Add a new row instead.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_events",
        up_sql: "\
CREATE TABLE trellis_events (
    scope BYTEA NOT NULL,
    sequence BIGINT NOT NULL,
    canonical_event BYTEA NOT NULL,
    signed_event BYTEA NOT NULL,
    PRIMARY KEY (scope, sequence)
);
",
    },
    Migration {
        version: 2,
        name: "idempotency_key",
        up_sql: "\
ALTER TABLE trellis_events
    ADD COLUMN idempotency_key BYTEA NULL;

CREATE UNIQUE INDEX trellis_events_scope_idempotency_uidx
    ON trellis_events (scope, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

ALTER TABLE trellis_events
    ADD CONSTRAINT trellis_events_idempotency_key_length
    CHECK (
        idempotency_key IS NULL OR (
            octet_length(idempotency_key) BETWEEN 1 AND 64
        )
    );
",
    },
    Migration {
        version: 3,
        name: "canonical_event_hash",
        up_sql: "\
ALTER TABLE trellis_events ADD COLUMN canonical_event_hash BYTEA NULL;
",
    },
    Migration {
        version: 4,
        name: "bundle_publications",
        up_sql: "\
CREATE TABLE trellis_bundle_publications (
    scope BYTEA NOT NULL,
    seal_version BIGINT NOT NULL,
    checkpoint_digest TEXT NOT NULL,
    export_attempt_id TEXT NOT NULL,
    artifact_ref TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ NULL,
    PRIMARY KEY (scope, seal_version),
    UNIQUE (scope, checkpoint_digest),
    CHECK (seal_version >= 1),
    CHECK (length(checkpoint_digest) BETWEEN 8 AND 128),
    CHECK (length(export_attempt_id) BETWEEN 8 AND 128),
    CHECK (artifact_ref IS NULL OR length(artifact_ref) BETWEEN 1 AND 2048)
);
",
    },
    Migration {
        version: 5,
        name: "external_attachment_retention",
        up_sql: "\
CREATE TABLE trellis_external_attachments (
    scope BYTEA NOT NULL,
    sequence BIGINT NOT NULL,
    idempotency_key BYTEA NOT NULL,
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    replay_identity BYTEA NOT NULL CHECK (octet_length(replay_identity) = 32),
    compute_json TEXT NOT NULL,
    PRIMARY KEY (scope, sequence),
    UNIQUE (scope, idempotency_key),
    CHECK (octet_length(idempotency_key) BETWEEN 1 AND 64),
    FOREIGN KEY (scope, sequence) REFERENCES trellis_events(scope, sequence)
);
",
    },
];

/// Versions declared by this binary, in application order.
///
/// Tests derive the expected ledger from this so adding a migration cannot
/// leave a hand-written version list behind.
#[must_use]
pub fn declared_migration_versions() -> Vec<i32> {
    MIGRATIONS
        .iter()
        .map(|migration| migration.version)
        .collect()
}

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
    /// Shared migration runner rejected the request.
    #[error("shared migration runner: {0}")]
    Shared(String),
}

impl From<stack_common_postgres::MigrationError> for MigrationError {
    fn from(error: stack_common_postgres::MigrationError) -> Self {
        match error {
            stack_common_postgres::MigrationError::SchemaAhead {
                applied_version,
                declared_max,
            } => Self::SchemaAhead {
                applied_version,
                declared_max,
            },
            stack_common_postgres::MigrationError::Sqlx(error) => Self::Sqlx(error),
            other => Self::Shared(other.to_string()),
        }
    }
}

/// Applies pending Trellis Postgres migrations.
///
/// The migration list and advisory-lock key come from the shared Postgres contract.
/// Rows are append-only: old migration SQL must not be edited after landing.
///
/// # Errors
///
/// Returns [`MigrationError::SchemaAhead`] when the database records a newer
/// migration than this binary declares, or [`MigrationError::Sqlx`] for SQL
/// execution failures.
pub async fn run_migrations(pool: &PgPool) -> Result<(), MigrationError> {
    run_sqlx_migrations(
        pool,
        MigrationSet::new(LEDGER_TABLE, ADVISORY_LOCK_KEY, MIGRATIONS),
    )
    .await?;
    Ok(())
}
