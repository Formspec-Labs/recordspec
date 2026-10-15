// Rust guideline compliant 2026-02-21
//! Read-only append reconciliation from a serialized prefix and retained publication.

use integrity_cbor::{Value, domain_separated_sha256};
use stack_common_error::StackError;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_service_client::{
    AppendReconciliation, AppendReconciliationRequest, ReconciliationUnknown,
};
use trellis_types::{ArtifactType, EVENT_DOMAIN, StoredEvent};

use crate::{
    TrellisServerState, append_result_for_event, event_hash, export_attempt_id,
    verify_retained_publication,
};

fn unknown(reason: ReconciliationUnknown) -> AppendReconciliation {
    AppendReconciliation::Unknown { reason }
}

/// Validates stored identity and recomputes hashes instead of trusting materialized values.
///
/// # Errors
/// Refuses duplicate keys, malformed signed rows or inconsistent stored identities and hashes.
pub(crate) fn checked_prefix(
    scope: &[u8],
    events: Vec<StoredEvent>,
) -> Result<Vec<StoredEvent>, StackError> {
    let mut keys = std::collections::BTreeSet::new();
    if events
        .iter()
        .filter_map(StoredEvent::idempotency_key)
        .any(|key| !keys.insert(key))
    {
        return Err(StackError::unavailable("reconciliation duplicate key"));
    }
    events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let parsed = trellis_cddl::parse_canonical_event(event.canonical_event())
                .map_err(|_| StackError::unavailable("reconciliation canonical event invalid"))?;
            if event.scope() != scope
                || event.sequence() != index as u64
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
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciliation_duplicate_key_gate_precedes_decode_or_first_match() {
        // Deliberately ambiguous raw rows must be rejected before interpreting either record.
        let event = StoredEvent::with_idempotency_key(
            b"neutral-scope".to_vec(),
            0,
            vec![],
            vec![],
            b"neutral-key".to_vec(),
        );
        let error = checked_prefix(b"neutral-scope", vec![event.clone(), event]).unwrap_err();
        assert_eq!(error.title(), "reconciliation duplicate key");
    }
}

/// Reconciles without append, Source prefetch, publication reservation or artifact writes.
pub(crate) async fn reconcile(
    state: &TrellisServerState,
    scope: &str,
    request: &AppendReconciliationRequest,
) -> AppendReconciliation {
    // Release both repository and process-local serialization before immutable artifact reads.
    let snapshot = {
        let _guard = state.scope_locks.lock(scope.as_bytes()).await;
        state
            .repository
            .reconciliation_snapshot(scope.as_bytes())
            .await
    };
    let events = match snapshot {
        Err(_) => return unknown(ReconciliationUnknown::StoreUnavailable),
        Ok(events) => match checked_prefix(scope.as_bytes(), events) {
            Ok(events) => events,
            Err(_) => return unknown(ReconciliationUnknown::VerificationFailed),
        },
    };
    let Some(event) = events
        .iter()
        .find(|event| event.idempotency_key() == Some(request.idempotency_key.as_bytes()))
    else {
        return AppendReconciliation::Absent {
            event_count: events.len() as u64,
            last_event_hash: events.last().map(|event| {
                format!(
                    "sha256:{}",
                    hex::encode(
                        event
                            .canonical_event_hash()
                            .expect("checked prefix sets hashes")
                    )
                )
            }),
        };
    };
    let prefix = &events[..=event.sequence() as usize];
    let seal = event.sequence() + 1;
    let record = match state.bundles.get_by_seal(scope.as_bytes(), seal).await {
        Ok(Some(record)) => record,
        Ok(None) => return unknown(ReconciliationUnknown::ReceiptUnavailable),
        Err(_) => return unknown(ReconciliationUnknown::StoreUnavailable),
    };
    let Ok(attempt) = export_attempt_id(
        scope.as_bytes(),
        seal,
        event.sequence(),
        *event
            .canonical_event_hash()
            .expect("checked prefix sets hashes"),
    ) else {
        return unknown(ReconciliationUnknown::VerificationFailed);
    };
    if record.seal_version != seal || record.export_attempt_id != attempt {
        return unknown(ReconciliationUnknown::VerificationFailed);
    }
    if verify_retained_publication(state, scope.as_bytes(), prefix, &record)
        .await
        .is_err()
    {
        return unknown(ReconciliationUnknown::VerificationFailed);
    }
    // Only valid retained cryptographic evidence can establish a semantic key conflict.
    if let Err(error) =
        crate::validate_existing_replay(event, &request.event_type, request.content_hash)
    {
        return if error.status() == http::StatusCode::CONFLICT {
            AppendReconciliation::Conflict
        } else {
            unknown(ReconciliationUnknown::VerificationFailed)
        };
    }
    let prior = event
        .sequence()
        .checked_sub(1)
        .map(|sequence| event_hash(scope.as_bytes(), &events[sequence as usize]));
    let prior = match prior.transpose() {
        Ok(prior) => prior,
        Err(_) => return unknown(ReconciliationUnknown::VerificationFailed),
    };
    match append_result_for_event(
        scope,
        event,
        prior,
        ArtifactType::Event,
        &request.event_type,
        &record,
        true,
    ) {
        Ok(receipt) => AppendReconciliation::Committed { receipt },
        Err(_) => unknown(ReconciliationUnknown::VerificationFailed),
    }
}
