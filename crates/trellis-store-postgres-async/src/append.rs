//! Async append helpers for caller-owned Postgres transactions.

use sqlx::{Postgres, Transaction};
use trellis_store_postgres_shared::collision::{CollisionDecision, resolve_collision};
use trellis_types::{StoredEvent, idempotency_key_length_in_bound};

/// Error returned when async append cannot complete.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    /// `idempotency_key` violates the Core §6.1 `1..=64` byte bound.
    #[error("idempotency_key length {0} outside Core §6.1 bound 1..=64")]
    IdempotencyKeyTooLong(usize),
    /// Sequence does not fit Postgres `BIGINT`.
    #[error("sequence {0} does not fit Postgres BIGINT")]
    DomainViolation(u64),
    /// Non-genesis chain append is missing its predecessor row.
    #[error("sequence gap: no predecessor at sequence {0} for scope")]
    SequenceGap(i64),
    /// Same `(scope, idempotency_key)` was already stored with different bytes.
    #[error(
        "Core §17.3 clause 3: same (scope, idempotency_key), different canonical_event or signed_event"
    )]
    IdempotencyKeyPayloadMismatch,
    /// Same `(scope, sequence)` was already stored with different bytes.
    #[error("PK collision on (scope, sequence) with different payloads")]
    PkCollisionMismatch,
    /// SQL execution failed.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Appends one already-canonical event inside `tx`.
///
/// The caller owns transaction lifetime and commit/rollback. This function
/// writes the real Trellis schema columns: `scope`, `sequence`,
/// `canonical_event`, `signed_event`, `idempotency_key`, and
/// `canonical_event_hash`.
///
/// # Errors
///
/// Returns [`AppendError`] for idempotency conflicts, sequence-domain
/// violations, missing predecessors, and underlying SQL failures.
pub async fn append_event_in_tx<'c>(
    tx: &mut Transaction<'c, Postgres>,
    event: &StoredEvent,
) -> Result<(), AppendError> {
    let idempotency_key = event.idempotency_key();

    if let Some(key) = idempotency_key
        && !idempotency_key_length_in_bound(key)
    {
        return Err(AppendError::IdempotencyKeyTooLong(key.len()));
    }

    let sequence = i64::try_from(event.sequence())
        .map_err(|_| AppendError::DomainViolation(event.sequence()))?;

    let scope = event.scope();
    let canonical = event.canonical_event();
    let signed = event.signed_event();
    let chain_hash: Option<Vec<u8>> = event.canonical_event_hash().map(|h| h.to_vec());

    if event.canonical_event_hash().is_some() && event.sequence() > 0 {
        let predecessor_seq = sequence - 1;
        let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT canonical_event_hash FROM trellis_events WHERE scope = $1 AND sequence = $2",
        )
        .bind(scope)
        .bind(predecessor_seq)
        .fetch_optional(&mut **tx)
        .await?;

        if row.is_none() {
            return Err(AppendError::SequenceGap(predecessor_seq));
        }
    }

    if idempotency_key.is_some() {
        append_with_idempotency(
            tx,
            scope,
            sequence,
            canonical,
            signed,
            idempotency_key,
            &chain_hash,
        )
        .await
    } else {
        append_without_idempotency(tx, scope, sequence, canonical, signed, &chain_hash).await
    }
}

async fn append_with_idempotency<'c>(
    tx: &mut Transaction<'c, Postgres>,
    scope: &[u8],
    sequence: i64,
    canonical: &[u8],
    signed: &[u8],
    idempotency_key: Option<&[u8]>,
    chain_hash: &Option<Vec<u8>>,
) -> Result<(), AppendError> {
    sqlx::query("SAVEPOINT trellis_idem")
        .execute(&mut **tx)
        .await?;
    let insert = sqlx::query(
        "\
INSERT INTO trellis_events (scope, sequence, canonical_event, signed_event, idempotency_key, canonical_event_hash) \
VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(scope)
    .bind(sequence)
    .bind(canonical)
    .bind(signed)
    .bind(idempotency_key)
    .bind(chain_hash.as_deref())
    .execute(&mut **tx)
    .await;

    match insert {
        Ok(_) => release_savepoint(tx, "trellis_idem").await,
        Err(error) => {
            let is_idem_violation =
                is_unique_violation(&error, "trellis_events_scope_idempotency_uidx");
            let is_pk_violation = is_unique_violation(&error, "trellis_events_pkey");
            rollback_and_release_savepoint(tx, "trellis_idem").await?;

            if !is_idem_violation && !is_pk_violation {
                return Err(error.into());
            }

            let (existing_canonical, existing_signed): (Vec<u8>, Vec<u8>) = if is_idem_violation {
                sqlx::query_as(
                    "\
SELECT canonical_event, signed_event \
FROM trellis_events \
WHERE scope = $1 AND idempotency_key = $2",
                )
                .bind(scope)
                .bind(idempotency_key)
                .fetch_one(&mut **tx)
                .await?
            } else {
                sqlx::query_as(
                    "\
SELECT canonical_event, signed_event \
FROM trellis_events \
WHERE scope = $1 AND sequence = $2",
                )
                .bind(scope)
                .bind(sequence)
                .fetch_one(&mut **tx)
                .await?
            };

            if payloads_match(&existing_canonical, canonical, &existing_signed, signed) {
                Ok(())
            } else if is_idem_violation {
                Err(AppendError::IdempotencyKeyPayloadMismatch)
            } else {
                Err(AppendError::PkCollisionMismatch)
            }
        }
    }
}

async fn append_without_idempotency<'c>(
    tx: &mut Transaction<'c, Postgres>,
    scope: &[u8],
    sequence: i64,
    canonical: &[u8],
    signed: &[u8],
    chain_hash: &Option<Vec<u8>>,
) -> Result<(), AppendError> {
    sqlx::query("SAVEPOINT trellis_pk")
        .execute(&mut **tx)
        .await?;
    let insert = sqlx::query(
        "\
INSERT INTO trellis_events (scope, sequence, canonical_event, signed_event, idempotency_key, canonical_event_hash) \
VALUES ($1, $2, $3, $4, NULL, $5)",
    )
    .bind(scope)
    .bind(sequence)
    .bind(canonical)
    .bind(signed)
    .bind(chain_hash.as_deref())
    .execute(&mut **tx)
    .await;

    match insert {
        Ok(_) => release_savepoint(tx, "trellis_pk").await,
        Err(error) => {
            let is_pk_violation = is_unique_violation(&error, "trellis_events_pkey");
            rollback_and_release_savepoint(tx, "trellis_pk").await?;

            if !is_pk_violation {
                return Err(error.into());
            }

            let (existing_canonical, existing_signed): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                "\
SELECT canonical_event, signed_event \
FROM trellis_events \
WHERE scope = $1 AND sequence = $2",
            )
            .bind(scope)
            .bind(sequence)
            .fetch_one(&mut **tx)
            .await?;

            if payloads_match(&existing_canonical, canonical, &existing_signed, signed) {
                Ok(())
            } else {
                Err(AppendError::PkCollisionMismatch)
            }
        }
    }
}

async fn release_savepoint<'c>(
    tx: &mut Transaction<'c, Postgres>,
    savepoint: &str,
) -> Result<(), AppendError> {
    sqlx::query(&format!("RELEASE SAVEPOINT {savepoint}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn rollback_and_release_savepoint<'c>(
    tx: &mut Transaction<'c, Postgres>,
    savepoint: &str,
) -> Result<(), AppendError> {
    sqlx::query(&format!("ROLLBACK TO SAVEPOINT {savepoint}"))
        .execute(&mut **tx)
        .await?;
    release_savepoint(tx, savepoint).await
}

fn is_unique_violation(error: &sqlx::Error, constraint: &str) -> bool {
    let sqlx::Error::Database(db) = error else {
        return false;
    };
    if db.code().as_deref() != Some("23505") {
        return false;
    }
    db.constraint() == Some(constraint)
}

fn payloads_match(
    existing_canonical: &[u8],
    canonical: &[u8],
    existing_signed: &[u8],
    signed: &[u8],
) -> bool {
    matches!(
        resolve_collision(existing_canonical, canonical),
        CollisionDecision::Replay(_)
    ) && matches!(
        resolve_collision(existing_signed, signed),
        CollisionDecision::Replay(_)
    )
}
