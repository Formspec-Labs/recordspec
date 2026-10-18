//! The Trellis Postgres schema, its migration ledger and the serving role's grants.
//!
//! Every table's key leads with `scope_key` (ADR 0168 §1.3): one bind, one index prefix, and a
//! request's rows are one contiguous range. The stack's own schema
//! ([`stack_common_postgres::SCOPE_MIGRATIONS`]) is applied first; the second migration turns
//! row security on for every table, so a connection reaches only the rows of the scope keys its
//! transaction set, whatever SQL it runs, and one that set none reaches nothing.
//!
//! The schema was squashed when `scope_key` arrived (no production data existed). A database that
//! recorded the old versions 1–6 is refused as ahead of this binary; recreate it.

use stack_common_postgres::{Grant, Migration, MigrationSet, ServedSchema};

const LEDGER_TABLE: &str = "trellis_schema_migrations";

/// Postgres advisory-lock key for the migration runner.
///
/// The lock is transaction-scoped: Postgres releases it atomically on commit
/// or rollback, so failed migration attempts do not leave a process-held lock.
const ADVISORY_LOCK_KEY: i64 = 0x7472_656c_6c69_7300; // "trellis\0"

/// Every Trellis table, in dependency order.
pub const TABLES: [&str; 4] = [
    "trellis_events",
    "trellis_checkpoints",
    "trellis_external_attachments",
    "trellis_source_contents",
];

/// Append-only schema migrations. Never edit a row that has shipped; add a new row instead.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "scope_keyed_ledgers",
        up_sql: "\
CREATE TABLE trellis_events (
    scope_key BYTEA NOT NULL CHECK (octet_length(scope_key) = 32),
    scope BYTEA NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    canonical_event BYTEA NOT NULL,
    signed_event BYTEA NOT NULL,
    idempotency_key BYTEA NULL CHECK (
        idempotency_key IS NULL OR octet_length(idempotency_key) BETWEEN 1 AND 64
    ),
    canonical_event_hash BYTEA NOT NULL CHECK (octet_length(canonical_event_hash) = 32),
    PRIMARY KEY (scope_key, scope, sequence)
);

CREATE UNIQUE INDEX trellis_events_idempotency_uidx
    ON trellis_events (scope_key, scope, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE trellis_checkpoints (
    scope_key BYTEA NOT NULL CHECK (octet_length(scope_key) = 32),
    scope BYTEA NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 1),
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    checkpoint BYTEA NOT NULL,
    frontier BYTEA NOT NULL,
    profile_state BYTEA NOT NULL,
    PRIMARY KEY (scope_key, scope, tree_size),
    CONSTRAINT trellis_checkpoints_digest_key UNIQUE (scope_key, scope, digest),
    CHECK (octet_length(frontier) = 32 * bit_count(tree_size::bit(64)))
);

CREATE TABLE trellis_external_attachments (
    scope_key BYTEA NOT NULL CHECK (octet_length(scope_key) = 32),
    scope BYTEA NOT NULL,
    sequence BIGINT NOT NULL,
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 64),
    content_hash BYTEA NOT NULL CHECK (octet_length(content_hash) = 32),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    replay_identity BYTEA NOT NULL CHECK (octet_length(replay_identity) = 32),
    compute_json TEXT NOT NULL,
    PRIMARY KEY (scope_key, scope, sequence),
    CONSTRAINT trellis_external_attachments_idempotency_key UNIQUE (scope_key, scope, idempotency_key),
    FOREIGN KEY (scope_key, scope, sequence)
        REFERENCES trellis_events (scope_key, scope, sequence)
);

CREATE TABLE trellis_source_contents (
    scope_key BYTEA NOT NULL CHECK (octet_length(scope_key) = 32),
    scope BYTEA NOT NULL,
    sequence BIGINT NOT NULL,
    batch_hash BYTEA NOT NULL CHECK (octet_length(batch_hash) = 32),
    size BIGINT NOT NULL CHECK (size > 0),
    artifact_ref TEXT NOT NULL CHECK (length(artifact_ref) BETWEEN 1 AND 2048),
    PRIMARY KEY (scope_key, scope, sequence),
    FOREIGN KEY (scope_key, scope, sequence)
        REFERENCES trellis_events (scope_key, scope, sequence)
);

-- A served ledger scope names its scope key (`<key hex>.<ledger id>`), but the planner assumes the
-- two key columns independent and, once rows spread over many scope keys, estimates a ledger at a
-- fraction of a row and picks among indexes sharing the (scope_key, scope) prefix by cost ties
-- (measured: event by key walked the primary key and filtered). Dependency statistics tell it.
CREATE STATISTICS trellis_events_scope_dependency (dependencies) ON scope_key, scope
    FROM trellis_events;
CREATE STATISTICS trellis_checkpoints_scope_dependency (dependencies) ON scope_key, scope
    FROM trellis_checkpoints;
CREATE STATISTICS trellis_external_attachments_scope_dependency (dependencies) ON scope_key, scope
    FROM trellis_external_attachments;
CREATE STATISTICS trellis_source_contents_scope_dependency (dependencies) ON scope_key, scope
    FROM trellis_source_contents;
",
    },
    Migration {
        version: 2,
        name: "row_security",
        up_sql: "\
SELECT stack_enable_scope_rls('trellis_events');
SELECT stack_enable_scope_rls('trellis_checkpoints');
SELECT stack_enable_scope_rls('trellis_external_attachments');
SELECT stack_enable_scope_rls('trellis_source_contents');
",
    },
];

/// The Trellis migration set, applied after `SCOPE_MIGRATIONS` by `stack_common_postgres::migrate`.
pub const TRELLIS_MIGRATIONS: MigrationSet =
    MigrationSet::new(LEDGER_TABLE, ADVISORY_LOCK_KEY, MIGRATIONS);

/// Trellis's schema as the deployment serves it: its migrations, and `SELECT` and `INSERT` on
/// every table for the serving role. Ledgers are append-only, so the role holds no `UPDATE` or
/// `DELETE`. `trellis-server migrate` applies it with `stack_common_postgres::migrate`;
/// `ScopedPool::open` refuses to serve a database it does not describe.
pub const SCHEMA: ServedSchema = ServedSchema {
    migrations: &[TRELLIS_MIGRATIONS],
    grants: &[Grant {
        privileges: &["SELECT", "INSERT"],
        tables: &TABLES,
    }],
    // Trellis starts no runner, so no transaction spans scopes.
    spanning: &[],
};
