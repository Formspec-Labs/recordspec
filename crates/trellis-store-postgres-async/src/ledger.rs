// Rust guideline compliant 2026-02-21
//! Flat-cost ledger rows: an event, its checkpoint, and the point reads an append needs.
//!
//! Every event commits together with the checkpoint for the tree it produced
//! (`trellis_checkpoints`, one row per `tree_size`). The head is the highest `tree_size`, found by
//! a backward index scan, so an append reads the head checkpoint, the last event and the
//! idempotency index, and writes two rows, whatever the ledger's length.
//!
//! Every statement runs in a [`ScopedTx`]: `$1` is the scope key, so each query is
//! `WHERE scope_key = $1 AND scope = $2 …` and walks the `(scope_key, scope, …)` key in order. The
//! scope key comes from the transaction, never from a caller, so these functions cannot reach
//! another scope's rows; they write `event.scope()` as given, and the [`crate::PgLedgers`]
//! adapter checks it against the ledger it was opened for.

use stack_common_postgres::ScopedTx;

use crate::statements;
use trellis_types::{
    StoredCheckpoint, StoredEvent, domain_separated_sha256, idempotency_key_length_in_bound,
};

pub use trellis_server_ports::SourceContentBinding;

/// Domain tag of the per-ledger advisory lock key.
const LEDGER_LOCK_DOMAIN: &str = "trellis-append-scope-lock-v1";

/// Error returned when a stored row cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// SQL execution failed.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A stored row violates an invariant the schema is meant to guarantee.
    #[error("stored row malformed: {0}")]
    Malformed(&'static str),
}

/// Error returned when a checkpointed event cannot be written.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    /// `idempotency_key` violates the Core §6.1 `1..=64` byte bound.
    #[error("idempotency_key length {0} outside Core §6.1 bound 1..=64")]
    IdempotencyKeyTooLong(usize),
    /// Sequence does not fit Postgres `BIGINT`.
    #[error("sequence {0} does not fit Postgres BIGINT")]
    DomainViolation(u64),
    /// The checkpoint does not belong to the event, or the event has no canonical hash.
    #[error("checkpoint does not describe the event: {0}")]
    CheckpointMismatch(&'static str),
    /// A unique key was taken: another writer committed this `(scope, sequence)`, idempotency key
    /// or checkpoint between this caller's reads and its insert. Nothing was written.
    #[error("unique key already taken: {0}")]
    Conflict(String),
    /// SQL execution failed.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Takes the ledger's advisory lock as the transaction's first work, under `READ COMMITTED`.
///
/// `READ COMMITTED` is set first, so every later statement sees every commit that finished while
/// this caller waited for the lock; the connection default may be stricter.
///
/// # Errors
/// Returns the SQL error if the isolation level or the lock cannot be taken.
pub async fn lock_ledger(tx: &mut ScopedTx, ledger: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(tx.conn())
        .await?;
    let hash = domain_separated_sha256(LEDGER_LOCK_DOMAIN, ledger);
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash[..8]);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(prefix))
        .execute(tx.conn())
        .await?;
    Ok(())
}

type EventRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>);

fn event_from_row(row: EventRow) -> Result<StoredEvent, ReadError> {
    let (scope, sequence, canonical, signed, key, hash) = row;
    event_from_row_parts(scope, sequence, canonical, signed, key, hash)
}

pub(crate) fn event_from_row_parts(
    scope: Vec<u8>,
    sequence: i64,
    canonical: Vec<u8>,
    signed: Vec<u8>,
    key: Option<Vec<u8>>,
    hash: Vec<u8>,
) -> Result<StoredEvent, ReadError> {
    let sequence =
        u64::try_from(sequence).map_err(|_| ReadError::Malformed("negative sequence"))?;
    let event = match key {
        Some(key) => StoredEvent::with_idempotency_key(scope, sequence, canonical, signed, key),
        None => StoredEvent::new(scope, sequence, canonical, signed),
    };
    Ok(event.with_canonical_event_hash(Some(
        hash.try_into()
            .map_err(|_| ReadError::Malformed("canonical_event_hash is not 32 bytes"))?,
    )))
}

type CheckpointRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn checkpoint_from_row(
    (scope, tree_size, digest, checkpoint, frontier, profile_state): CheckpointRow,
) -> Result<StoredCheckpoint, ReadError> {
    Ok(StoredCheckpoint {
        scope,
        tree_size: u64::try_from(tree_size).map_err(|_| ReadError::Malformed("tree_size"))?,
        digest: digest
            .try_into()
            .map_err(|_| ReadError::Malformed("checkpoint digest is not 32 bytes"))?,
        checkpoint,
        frontier,
        profile_state,
    })
}

fn bigint(value: u64, what: &'static str) -> Result<i64, ReadError> {
    i64::try_from(value).map_err(|_| ReadError::Malformed(what))
}

/// The ledger's head checkpoint: the row with the highest `tree_size`. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn head_checkpoint(
    tx: &mut ScopedTx,
    ledger: &[u8],
) -> Result<Option<StoredCheckpoint>, ReadError> {
    let query = tx.query_as::<CheckpointRow>(statements::HEAD_CHECKPOINT);
    query
        .bind(ledger)
        .fetch_optional(tx.conn())
        .await?
        .map(checkpoint_from_row)
        .transpose()
}

/// The checkpoint at exactly `tree_size`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoint_at(
    tx: &mut ScopedTx,
    ledger: &[u8],
    tree_size: u64,
) -> Result<Option<StoredCheckpoint>, ReadError> {
    let tree_size = bigint(tree_size, "tree_size")?;
    let query = tx.query_as::<CheckpointRow>(statements::CHECKPOINT_AT);
    query
        .bind(ledger)
        .bind(tree_size)
        .fetch_optional(tx.conn())
        .await?
        .map(checkpoint_from_row)
        .transpose()
}

/// The checkpoint whose Core §11.2 digest is `digest`, within the ledger.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoint_by_digest(
    tx: &mut ScopedTx,
    ledger: &[u8],
    digest: &[u8; 32],
) -> Result<Option<StoredCheckpoint>, ReadError> {
    let query = tx.query_as::<CheckpointRow>(statements::CHECKPOINT_BY_DIGEST);
    query
        .bind(ledger)
        .bind(digest.as_slice())
        .fetch_optional(tx.conn())
        .await?
        .map(checkpoint_from_row)
        .transpose()
}

/// Every checkpoint with `tree_size <= through`, ascending: the `040-checkpoints.cbor` rows of an
/// export whose head is the checkpoint at `through`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoints_through(
    tx: &mut ScopedTx,
    ledger: &[u8],
    through: u64,
) -> Result<Vec<StoredCheckpoint>, ReadError> {
    let through = bigint(through, "tree_size")?;
    let query = tx.query_as::<CheckpointRow>(statements::CHECKPOINTS_THROUGH);
    query
        .bind(ledger)
        .bind(through)
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .map(checkpoint_from_row)
        .collect()
}

/// The ledger's most recent event. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn last_event(
    tx: &mut ScopedTx,
    ledger: &[u8],
) -> Result<Option<StoredEvent>, ReadError> {
    let query = tx.query_as::<EventRow>(statements::LAST_EVENT);
    query
        .bind(ledger)
        .fetch_optional(tx.conn())
        .await?
        .map(event_from_row)
        .transpose()
}

/// The event committed under `key` in the ledger, if any. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn event_by_key(
    tx: &mut ScopedTx,
    ledger: &[u8],
    key: &[u8],
) -> Result<Option<StoredEvent>, ReadError> {
    let query = tx.query_as::<EventRow>(statements::EVENT_BY_KEY);
    query
        .bind(ledger)
        .bind(key)
        .fetch_optional(tx.conn())
        .await?
        .map(event_from_row)
        .transpose()
}

/// The ledger's first `limit` events, ascending: a bounded prefix read for the flows that validate
/// a whole small ledger (the completion seal, attachments, a Source closeout).
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn prefix(
    tx: &mut ScopedTx,
    ledger: &[u8],
    limit: u64,
) -> Result<Vec<StoredEvent>, ReadError> {
    let limit = bigint(limit, "limit")?;
    let query = tx.query_as::<EventRow>(statements::PREFIX);
    query
        .bind(ledger)
        .bind(limit)
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .map(event_from_row)
        .collect()
}

/// Events with `sequence < before`, ascending: the `events` member of an export whose head has
/// tree size `before`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn events_before(
    tx: &mut ScopedTx,
    ledger: &[u8],
    before: u64,
) -> Result<Vec<StoredEvent>, ReadError> {
    let before = bigint(before, "sequence")?;
    let query = tx.query_as::<EventRow>(statements::EVENTS_BEFORE);
    query
        .bind(ledger)
        .bind(before)
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .map(event_from_row)
        .collect()
}

/// Writes one event and the checkpoint for the tree it produced: two inserts, nothing read.
///
/// The caller holds the ledger's lock (see [`lock_ledger`]) and has already read the head, so a
/// failed unique key means another writer got there first and is reported as
/// [`AppendError::Conflict`] with nothing written.
///
/// # Errors
/// [`AppendError`] for a malformed pair, a taken key or a SQL failure.
pub async fn append_checkpointed(
    tx: &mut ScopedTx,
    event: &StoredEvent,
    checkpoint: &StoredCheckpoint,
) -> Result<(), AppendError> {
    if let Some(key) = event.idempotency_key()
        && !idempotency_key_length_in_bound(key)
    {
        return Err(AppendError::IdempotencyKeyTooLong(key.len()));
    }
    let sequence = i64::try_from(event.sequence())
        .map_err(|_| AppendError::DomainViolation(event.sequence()))?;
    let hash = event
        .canonical_event_hash()
        .ok_or(AppendError::CheckpointMismatch(
            "event has no canonical hash",
        ))?;
    if event.scope() != checkpoint.scope.as_slice() || checkpoint.tree_size != event.sequence() + 1
    {
        return Err(AppendError::CheckpointMismatch(
            "checkpoint tree_size is not sequence + 1 of the same scope",
        ));
    }
    if checkpoint.frontier.len() != 32 * checkpoint.tree_size.count_ones() as usize {
        return Err(AppendError::CheckpointMismatch(
            "frontier is not popcount(tree_size) hashes",
        ));
    }
    let tree_size = i64::try_from(checkpoint.tree_size)
        .map_err(|_| AppendError::DomainViolation(checkpoint.tree_size))?;
    let query = tx.query(
        "INSERT INTO trellis_events (scope_key, scope, sequence, canonical_event, signed_event, \
         idempotency_key, canonical_event_hash) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    );
    query
        .bind(event.scope())
        .bind(sequence)
        .bind(event.canonical_event())
        .bind(event.signed_event())
        .bind(event.idempotency_key())
        .bind(hash.as_slice())
        .execute(tx.conn())
        .await
        .map_err(unique_violation_or_sqlx)?;
    let query = tx.query(
        "INSERT INTO trellis_checkpoints (scope_key, scope, tree_size, digest, checkpoint, \
         frontier, profile_state) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    );
    query
        .bind(&checkpoint.scope)
        .bind(tree_size)
        .bind(checkpoint.digest.as_slice())
        .bind(&checkpoint.checkpoint)
        .bind(&checkpoint.frontier)
        .bind(&checkpoint.profile_state)
        .execute(tx.conn())
        .await
        .map_err(unique_violation_or_sqlx)?;
    Ok(())
}

pub(crate) fn unique_violation_or_sqlx(error: sqlx::Error) -> AppendError {
    match &error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            AppendError::Conflict(db.constraint().unwrap_or("unique").to_owned())
        }
        _ => AppendError::Sqlx(error),
    }
}

/// Binds the closeout event at `sequence` to its batch copy. Same transaction as the event.
///
/// # Errors
/// [`AppendError`] for a domain violation, a taken key or a SQL failure.
pub async fn insert_source_content(
    tx: &mut ScopedTx,
    ledger: &[u8],
    sequence: u64,
    binding: &SourceContentBinding,
) -> Result<(), AppendError> {
    let sequence = i64::try_from(sequence).map_err(|_| AppendError::DomainViolation(sequence))?;
    let size =
        i64::try_from(binding.size).map_err(|_| AppendError::DomainViolation(binding.size))?;
    let query = tx.query(
        "INSERT INTO trellis_source_contents \
         (scope_key, scope, sequence, batch_hash, size, artifact_ref) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    );
    query
        .bind(ledger)
        .bind(sequence)
        .bind(binding.batch_hash.as_slice())
        .bind(size)
        .bind(&binding.artifact_ref)
        .execute(tx.conn())
        .await
        .map_err(unique_violation_or_sqlx)?;
    Ok(())
}

/// The batch copy bound to the event at `sequence`, if that event is a Source closeout.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn source_content(
    tx: &mut ScopedTx,
    ledger: &[u8],
    sequence: u64,
) -> Result<Option<SourceContentBinding>, ReadError> {
    let sequence = bigint(sequence, "sequence")?;
    let query = tx.query_as::<(Vec<u8>, i64, String)>(statements::SOURCE_CONTENT);
    let row = query
        .bind(ledger)
        .bind(sequence)
        .fetch_optional(tx.conn())
        .await?;
    row.map(|(hash, size, artifact_ref)| {
        Ok(SourceContentBinding {
            artifact_ref,
            batch_hash: hash
                .try_into()
                .map_err(|_| ReadError::Malformed("batch_hash is not 32 bytes"))?,
            size: u64::try_from(size).map_err(|_| ReadError::Malformed("size"))?,
        })
    })
    .transpose()
}
