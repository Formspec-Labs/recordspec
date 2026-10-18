// Rust guideline compliant 2026-02-21
//! Retained protected attachment bodies, joined to the committed event that binds them.

use stack_common_postgres::ScopedTx;

pub use trellis_server_ports::AttachmentRow;

use crate::ledger::{AppendError, ReadError, event_from_row_parts, unique_violation_or_sqlx};
use crate::statements;

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

/// The attachment retained under `key` in the ledger, if any.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn attachment_by_key(
    tx: &mut ScopedTx,
    ledger: &[u8],
    key: &[u8],
) -> Result<Option<AttachmentRow>, ReadError> {
    let query = tx.query_as::<JoinedRow>(statements::ATTACHMENT_BY_KEY);
    query
        .bind(ledger)
        .bind(key)
        .fetch_optional(tx.conn())
        .await?
        .map(row_from_joined)
        .transpose()
}

/// The attachments retained for events below `before`, ascending by sequence (the primary key),
/// read only until their bodies first exceed `max_bytes` or their count exceeds `max_rows`: the
/// row that crosses is included, and none after it is read.
///
/// The lengths are read first (`octet_length` reads no body), so a ledger whose bodies are far
/// past the bound costs its lengths, not its bodies.
///
/// # Errors
/// [`ReadError`] on SQL failure or a malformed row.
pub async fn attachments_within(
    tx: &mut ScopedTx,
    ledger: &[u8],
    before: u64,
    max_bytes: u64,
    max_rows: u64,
) -> Result<Vec<AttachmentRow>, ReadError> {
    let before = i64::try_from(before).unwrap_or(i64::MAX);
    let query = tx.query_as::<(i64, i64)>(statements::ATTACHMENT_LENGTHS);
    let lengths = query
        .bind(ledger)
        .bind(before)
        .bind(i64::try_from(max_rows.saturating_add(1)).unwrap_or(i64::MAX))
        .fetch_all(tx.conn())
        .await?;
    let mut total = 0_u64;
    let mut through = None;
    for (count, (sequence, length)) in lengths.iter().enumerate() {
        through = Some(*sequence);
        total = total.saturating_add(u64::try_from(*length).unwrap_or(u64::MAX));
        if total > max_bytes || count as u64 >= max_rows {
            break;
        }
    }
    let Some(through) = through else {
        return Ok(Vec::new());
    };
    let query = tx.query_as::<JoinedRow>(statements::ATTACHMENTS_BEFORE);
    query
        .bind(ledger)
        .bind(through.saturating_add(1))
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .map(row_from_joined)
        .collect()
}

/// Retains an attachment body for the event at `row.event.sequence()`; same transaction as the
/// event.
///
/// # Errors
/// [`AppendError`] for a domain violation, a taken key or a SQL failure.
pub async fn insert_attachment(tx: &mut ScopedTx, row: &AttachmentRow) -> Result<(), AppendError> {
    let sequence = i64::try_from(row.event.sequence())
        .map_err(|_| AppendError::DomainViolation(row.event.sequence()))?;
    let query = tx.query(
        "INSERT INTO trellis_external_attachments (scope_key, scope, sequence, idempotency_key, \
         content_hash, ciphertext, nonce, replay_identity, compute_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    );
    query
        .bind(row.event.scope())
        .bind(sequence)
        .bind(&row.idempotency_key)
        .bind(&row.content_hash)
        .bind(&row.ciphertext)
        .bind(&row.nonce)
        .bind(&row.replay_identity)
        .bind(&row.compute_json)
        .execute(tx.conn())
        .await
        .map_err(unique_violation_or_sqlx)?;
    Ok(())
}
