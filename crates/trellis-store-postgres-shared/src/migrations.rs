//! Shared migration list for Trellis Postgres adapters.

/// One append-only schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Monotonic migration version.
    pub version: i32,
    /// Stable migration name for diagnostics and tests.
    pub name: &'static str,
    /// SQL applied for this migration.
    pub up_sql: &'static str,
}

/// Postgres advisory-lock key for the migration runner.
///
/// The lock is transaction-scoped: Postgres releases it atomically on commit
/// or rollback, so failed migration attempts do not leave a process-held lock.
pub const ADVISORY_LOCK_KEY: i64 = 0x7472_656c_6c69_7300; // "trellis\0"

/// Append-only schema migrations for `trellis_events`.
///
/// Never edit a row that has shipped. Add a new row instead.
pub const MIGRATIONS: &[Migration] = &[
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
];
