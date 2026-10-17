// Rust guideline compliant 2026-02-21
//! Retained protected attachment bodies, joined to the committed event that binds them.

use sqlx::{PgExecutor, Postgres, Transaction};
use trellis_types::StoredEvent;

use crate::ledger::{AppendError, ReadError, event_from_row_parts};

/// One retained attachment row and its committed event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentRow {
    pub event: StoredEvent,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub replay_identity: Vec<u8>,
    pub content_hash: Vec<u8>,
    pub idempotency_key: Vec<u8>,
    /// The custody disclosure the body was retained under, as JSON text.
    pub compute_json: String,
}

type JoinedRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
);

const SELECT: &str = "SELECT e.scope, e.sequence, e.canonical_event, e.signed_event, \
    e.idempotency_key, e.canonical_event_hash, a.ciphertext, a.nonce, a.replay_identity, \
    a.content_hash, a.idempotency_key, a.compute_json \
    FROM trellis_external_attachments a \
    JOIN trellis_events e ON e.scope = a.scope AND e.sequence = a.sequence";

fn row_from_joined(
    (
        scope,
        sequence,
        canonical,
        signed,
        event_key,
        event_hash,
        ciphertext,
        nonce,
        identity,
        hash,
        key,
        compute,
    ): JoinedRow,
) -> Result<AttachmentRow, ReadError> {
    Ok(AttachmentRow {
        event: event_from_row_parts(scope, sequence, canonical, signed, event_key, event_hash)?,
        ciphertext,
        nonce,
        replay_identity: identity,
        content_hash: hash,
        idempotency_key: key,
        compute_json: compute,
    })
}

/// The attachment retained under `key` in `scope`, if any.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn attachment_by_key<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    key: &[u8],
) -> Result<Option<AttachmentRow>, ReadError> {
    sqlx::query_as::<_, JoinedRow>(&format!(
        "{SELECT} WHERE a.scope = $1 AND a.idempotency_key = $2"
    ))
    .bind(scope)
    .bind(key)
    .fetch_optional(executor)
    .await?
    .map(row_from_joined)
    .transpose()
}

/// The earliest attachment in `scope` whose ciphertext has `content_hash`, if any.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn attachment_by_content_hash<'e>(
    executor: impl PgExecutor<'e>,
    scope: &[u8],
    content_hash: &[u8; 32],
) -> Result<Option<AttachmentRow>, ReadError> {
    sqlx::query_as::<_, JoinedRow>(&format!(
        "{SELECT} WHERE a.scope = $1 AND a.content_hash = $2 ORDER BY a.sequence LIMIT 1"
    ))
    .bind(scope)
    .bind(content_hash.as_slice())
    .fetch_optional(executor)
    .await?
    .map(row_from_joined)
    .transpose()
}

/// Retains an attachment body for the event at `row.event.sequence()`; same transaction as the
/// event.
///
/// # Errors
/// [`AppendError`] for a domain violation, a taken key or a SQL failure.
pub async fn insert_attachment(
    tx: &mut Transaction<'_, Postgres>,
    row: &AttachmentRow,
) -> Result<(), AppendError> {
    let sequence = i64::try_from(row.event.sequence())
        .map_err(|_| AppendError::DomainViolation(row.event.sequence()))?;
    sqlx::query(
        "INSERT INTO trellis_external_attachments (scope, sequence, idempotency_key, content_hash, \
         ciphertext, nonce, replay_identity, compute_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(row.event.scope())
    .bind(sequence)
    .bind(&row.idempotency_key)
    .bind(&row.content_hash)
    .bind(&row.ciphertext)
    .bind(&row.nonce)
    .bind(&row.replay_identity)
    .bind(&row.compute_json)
    .execute(&mut **tx)
    .await
    .map_err(crate::ledger::unique_violation_or_sqlx)?;
    Ok(())
}
