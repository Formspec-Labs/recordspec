// Rust guideline compliant 2026-02-21
//! Flat-cost ledger rows: an event, its checkpoint, and the point reads an append needs.
//!
//! Every event commits together with the checkpoint for the tree it produced
//! (`trellis_checkpoints`, one row per `tree_size`). The head is the highest `tree_size`, found by
//! a backward index scan, so an append reads the head checkpoint, the last event and the
//! idempotency index, and writes two rows, whatever the ledger's length.
//!
//! Callers choose the executor: pass `&PgPool` for a stand-alone read or `&mut *tx` inside the
//! scope-locked transaction [`begin_scope`] opens.

use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use trellis_types::{
    StoredCheckpoint, StoredEvent, domain_separated_sha256, idempotency_key_length_in_bound,
};

/// Domain tag of the per-scope advisory lock key.
const SCOPE_LOCK_DOMAIN: &str = "trellis-append-scope-lock-v1";

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

/// Opens a transaction that holds the scope's advisory lock before it does anything else.
///
/// `READ COMMITTED` is set first, so every later statement sees every commit that finished while
/// this caller waited for the lock; the connection default may be stricter.
///
/// # Errors
/// Returns the SQL error if the transaction cannot start or take the lock.
pub async fn begin_scope(
    pool: &PgPool,
    scope: &[u8],
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    let hash = domain_separated_sha256(SCOPE_LOCK_DOMAIN, scope);
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash[..8]);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(prefix))
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

type EventRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>);
const EVENT_COLUMNS: &str =
    "scope, sequence, canonical_event, signed_event, idempotency_key, canonical_event_hash";

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
const CHECKPOINT_COLUMNS: &str = "scope, tree_size, digest, checkpoint, frontier, profile_state";

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

/// The scope's head checkpoint: the row with the highest `tree_size`. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn head_checkpoint<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
) -> Result<Option<StoredCheckpoint>, ReadError> {
    sqlx::query_as::<_, CheckpointRow>(&format!(
        "SELECT {CHECKPOINT_COLUMNS} FROM trellis_checkpoints \
         WHERE scope = $1 ORDER BY tree_size DESC LIMIT 1"
    ))
    .bind(scope)
    .fetch_optional(executor)
    .await?
    .map(checkpoint_from_row)
    .transpose()
}

/// The checkpoint at exactly `tree_size`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoint_at<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    tree_size: u64,
) -> Result<Option<StoredCheckpoint>, ReadError> {
    let tree_size = i64::try_from(tree_size).map_err(|_| ReadError::Malformed("tree_size"))?;
    sqlx::query_as::<_, CheckpointRow>(&format!(
        "SELECT {CHECKPOINT_COLUMNS} FROM trellis_checkpoints WHERE scope = $1 AND tree_size = $2"
    ))
    .bind(scope)
    .bind(tree_size)
    .fetch_optional(executor)
    .await?
    .map(checkpoint_from_row)
    .transpose()
}

/// The checkpoint whose Core §11.2 digest is `digest`, within `scope`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoint_by_digest<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    digest: &[u8; 32],
) -> Result<Option<StoredCheckpoint>, ReadError> {
    sqlx::query_as::<_, CheckpointRow>(&format!(
        "SELECT {CHECKPOINT_COLUMNS} FROM trellis_checkpoints WHERE scope = $1 AND digest = $2"
    ))
    .bind(scope)
    .bind(digest.as_slice())
    .fetch_optional(executor)
    .await?
    .map(checkpoint_from_row)
    .transpose()
}

/// Every checkpoint with `tree_size <= through`, ascending: the `040-checkpoints.cbor` rows of an
/// export whose head is the checkpoint at `through`.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn checkpoints_through<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    through: u64,
) -> Result<Vec<StoredCheckpoint>, ReadError> {
    let through = i64::try_from(through).map_err(|_| ReadError::Malformed("tree_size"))?;
    sqlx::query_as::<_, CheckpointRow>(&format!(
        "SELECT {CHECKPOINT_COLUMNS} FROM trellis_checkpoints \
         WHERE scope = $1 AND tree_size <= $2 ORDER BY tree_size"
    ))
    .bind(scope)
    .bind(through)
    .fetch_all(executor)
    .await?
    .into_iter()
    .map(checkpoint_from_row)
    .collect()
}

/// The scope's most recent event. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn last_event<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
) -> Result<Option<StoredEvent>, ReadError> {
    sqlx::query_as::<_, EventRow>(&format!(
        "SELECT {EVENT_COLUMNS} FROM trellis_events WHERE scope = $1 \
         ORDER BY sequence DESC LIMIT 1"
    ))
    .bind(scope)
    .fetch_optional(executor)
    .await?
    .map(event_from_row)
    .transpose()
}

/// The event committed under `key` in `scope`, if any. One index row.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn event_by_key<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    key: &[u8],
) -> Result<Option<StoredEvent>, ReadError> {
    sqlx::query_as::<_, EventRow>(&format!(
        "SELECT {EVENT_COLUMNS} FROM trellis_events WHERE scope = $1 AND idempotency_key = $2"
    ))
    .bind(scope)
    .bind(key)
    .fetch_optional(executor)
    .await?
    .map(event_from_row)
    .transpose()
}

/// Events with `sequence < before`, ascending, at most `limit` of them: a bounded prefix read for
/// the flows that validate a whole small ledger (the completion seal, attachments, a Source
/// closeout) and the `events` member of an export.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn events_before<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    before: u64,
    limit: u64,
) -> Result<Vec<StoredEvent>, ReadError> {
    let before = i64::try_from(before).map_err(|_| ReadError::Malformed("sequence"))?;
    let limit = i64::try_from(limit).map_err(|_| ReadError::Malformed("limit"))?;
    sqlx::query_as::<_, EventRow>(&format!(
        "SELECT {EVENT_COLUMNS} FROM trellis_events \
         WHERE scope = $1 AND sequence < $2 ORDER BY sequence LIMIT $3"
    ))
    .bind(scope)
    .bind(before)
    .bind(limit)
    .fetch_all(executor)
    .await?
    .into_iter()
    .map(event_from_row)
    .collect()
}

/// Writes one event and the checkpoint for the tree it produced: two inserts, nothing read.
///
/// The caller owns the transaction (see [`begin_scope`]) and has already read the head, so a
/// failed unique key means another writer got there first and is reported as
/// [`AppendError::Conflict`] with nothing written.
///
/// # Errors
/// [`AppendError`] for a malformed pair, a taken key or a SQL failure.
pub async fn append_checkpointed_in_tx(
    tx: &mut Transaction<'_, Postgres>,
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
    sqlx::query(&format!(
        "INSERT INTO trellis_events ({EVENT_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6)"
    ))
    .bind(event.scope())
    .bind(sequence)
    .bind(event.canonical_event())
    .bind(event.signed_event())
    .bind(event.idempotency_key())
    .bind(hash.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(unique_violation_or_sqlx)?;
    sqlx::query(&format!(
        "INSERT INTO trellis_checkpoints ({CHECKPOINT_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6)"
    ))
    .bind(&checkpoint.scope)
    .bind(
        i64::try_from(checkpoint.tree_size)
            .map_err(|_| AppendError::DomainViolation(checkpoint.tree_size))?,
    )
    .bind(checkpoint.digest.as_slice())
    .bind(&checkpoint.checkpoint)
    .bind(&checkpoint.frontier)
    .bind(&checkpoint.profile_state)
    .execute(&mut **tx)
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

/// Trellis's own copy of a Source closeout's admitted batch: where it lives, not the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceContentBinding {
    /// SHA-256 of the stored batch; the object key is derived from it.
    pub batch_hash: [u8; 32],
    /// Byte length of the stored batch.
    pub size: u64,
    /// The artifact store's own locator for the batch object.
    pub artifact_ref: String,
}

/// Binds the closeout event at `sequence` to its batch copy. Same transaction as the event.
///
/// # Errors
/// [`AppendError`] for a domain violation, a taken key or a SQL failure.
pub async fn insert_source_content(
    tx: &mut Transaction<'_, Postgres>,
    scope: &[u8],
    sequence: u64,
    binding: &SourceContentBinding,
) -> Result<(), AppendError> {
    sqlx::query(
        "INSERT INTO trellis_source_contents (scope, sequence, batch_hash, size, artifact_ref) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(scope)
    .bind(i64::try_from(sequence).map_err(|_| AppendError::DomainViolation(sequence))?)
    .bind(binding.batch_hash.as_slice())
    .bind(i64::try_from(binding.size).map_err(|_| AppendError::DomainViolation(binding.size))?)
    .bind(&binding.artifact_ref)
    .execute(&mut **tx)
    .await
    .map_err(unique_violation_or_sqlx)?;
    Ok(())
}

/// The batch copy bound to the event at `sequence`, if that event is a Source closeout.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn source_content<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    sequence: u64,
) -> Result<Option<SourceContentBinding>, ReadError> {
    let sequence = i64::try_from(sequence).map_err(|_| ReadError::Malformed("sequence"))?;
    let row: Option<(Vec<u8>, i64, String)> = sqlx::query_as(
        "SELECT batch_hash, size, artifact_ref FROM trellis_source_contents \
         WHERE scope = $1 AND sequence = $2",
    )
    .bind(scope)
    .bind(sequence)
    .fetch_optional(executor)
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
