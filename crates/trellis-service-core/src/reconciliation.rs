// Rust guideline compliant 2026-02-21
//! Read-only append reconciliation from one scope-locked read point.

use integrity_cbor::{Value, domain_separated_sha256};
use stack_common_error::StackError;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_service_client::{
    AppendReconciliation, AppendReconciliationRequest, ReconciliationUnknown,
};
use trellis_types::{EVENT_DOMAIN, StoredEvent};

use trellis_server_ports::LedgerScope;

use crate::TrellisScoped;
use crate::ledger::{append_result, prior_event_hash};

fn unknown(reason: ReconciliationUnknown) -> AppendReconciliation {
    AppendReconciliation::Unknown { reason }
}

/// Validates stored identity and recomputes the hash instead of trusting the materialised value.
///
/// # Errors
/// Refuses a malformed signed row or inconsistent stored identity and hash.
pub(crate) fn checked_event(
    scope: &[u8],
    index: u64,
    event: StoredEvent,
) -> Result<StoredEvent, StackError> {
    let parsed = trellis_cddl::parse_canonical_event(event.canonical_event())
        .map_err(|_| StackError::unavailable("reconciliation canonical event invalid"))?;
    if event.scope() != scope
        || event.sequence() != index
        || parsed.ledger_scope != scope
        || parsed.sequence != event.sequence()
        || Some(parsed.idempotency_key.as_slice()) != event.idempotency_key()
    {
        return Err(StackError::unavailable(
            "reconciliation stored identity differs",
        ));
    }
    let signed = integrity_cbor::decode_cbor_value(event.signed_event())
        .map_err(|_| StackError::unavailable("reconciliation signed event invalid"))?;
    let Value::Tag(18, inner) = signed else {
        return Err(StackError::unavailable(
            "reconciliation signed event tag invalid",
        ));
    };
    if inner
        .as_array()
        .filter(|fields| fields.len() == 4)
        .and_then(|fields| fields[2].as_bytes())
        .map(Vec::as_slice)
        != Some(event.canonical_event())
    {
        return Err(StackError::unavailable(
            "reconciliation signed payload differs",
        ));
    }
    let hash = domain_separated_sha256(
        EVENT_DOMAIN,
        &canonical_event_hash_preimage(scope, event.canonical_event()),
    );
    if event
        .canonical_event_hash()
        .is_some_and(|cached| *cached != hash)
    {
        return Err(StackError::unavailable(
            "reconciliation materialized hash differs",
        ));
    }
    Ok(event.with_canonical_event_hash(Some(hash)))
}

/// [`checked_event`] over a whole prefix.
///
/// # Errors
/// Refuses the first event that fails its check.
pub(crate) fn checked_prefix(
    scope: &[u8],
    events: Vec<StoredEvent>,
) -> Result<Vec<StoredEvent>, StackError> {
    events
        .into_iter()
        .enumerate()
        .map(|(index, event)| checked_event(scope, index as u64, event))
        .collect()
}

/// Checks the stored event against the lookup's identity: the content hash, or for the
/// completion seal its certificate id.
fn matches_identity(
    event: &StoredEvent,
    request: &AppendReconciliationRequest,
) -> Result<(), StackError> {
    if let Some(content_hash) = request.content_hash {
        return crate::validate_existing_replay(event, &request.event_type, content_hash);
    }
    if crate::event_summary(event)?.event_type != request.event_type {
        return Err(StackError::conflict(
            "idempotency key reused with a different event type",
        ));
    }
    if Some(crate::completion::committed_certificate_id(event)?) != request.certificate_id {
        return Err(StackError::conflict(
            "idempotency key reused with a different certificate id",
        ));
    }
    Ok(())
}

/// Reconciles without append, Source prefetch or artifact writes.
///
/// One scope-locked read point yields the head, the event under the key and that event's stored
/// checkpoint; the receipt is built from those rows alone.
pub(crate) async fn reconcile(
    scoped: &TrellisScoped,
    ledger: &LedgerScope,
    request: &AppendReconciliationRequest,
) -> AppendReconciliation {
    let scope = ledger.as_str();
    let point = async {
        let mut tx = scoped.ledgers().begin(ledger).await?;
        let head = tx.head().await?;
        let found = tx.event_by_key(request.idempotency_key.as_bytes()).await?;
        match found {
            Some(event) => {
                let checkpoint = tx.checkpoint_at(event.sequence() + 1).await?;
                Ok::<_, StackError>((head, Some((event, checkpoint)), None))
            }
            None => Ok((head, None, tx.last_event().await?)),
        }
    }
    .await;
    let (head, found, last) = match point {
        Ok(point) => point,
        Err(_) => return unknown(ReconciliationUnknown::StoreUnavailable),
    };
    let Some((event, checkpoint)) = found else {
        let last_event_hash = match last
            .map(|event| checked_event(scope.as_bytes(), event.sequence(), event))
            .transpose()
        {
            Ok(last) => last.map(|event| {
                format!(
                    "sha256:{}",
                    hex::encode(
                        event
                            .canonical_event_hash()
                            .expect("checked event sets its hash")
                    )
                )
            }),
            Err(_) => return unknown(ReconciliationUnknown::VerificationFailed),
        };
        return AppendReconciliation::Absent {
            event_count: head.map_or(0, |head| head.tree_size),
            last_event_hash,
        };
    };
    let Some(checkpoint) = checkpoint else {
        return unknown(ReconciliationUnknown::ReceiptUnavailable);
    };
    let Ok(event) = checked_event(scope.as_bytes(), event.sequence(), event) else {
        return unknown(ReconciliationUnknown::VerificationFailed);
    };
    if let Err(error) = matches_identity(&event, request) {
        return if error.status() == http::StatusCode::CONFLICT {
            AppendReconciliation::Conflict
        } else {
            unknown(ReconciliationUnknown::VerificationFailed)
        };
    }
    match prior_event_hash(&event)
        .and_then(|prior| append_result(scope, &event, prior, &checkpoint))
    {
        Ok(receipt) => AppendReconciliation::Committed { receipt },
        Err(_) => unknown(ReconciliationUnknown::VerificationFailed),
    }
}
