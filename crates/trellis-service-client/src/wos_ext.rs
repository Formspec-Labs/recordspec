// Rust guideline compliant 2026-02-21
//! WOS-typed extension helpers over the shared Trellis HTTP client (DI-004 / D12).
//!
//! D12 settled that producer-facing typed convenience for WOS provenance
//! events belongs in the shared `trellis-service-client` crate rather than a
//! separate WOS client dialect. This module is the **only** place
//! `trellis-service-client` is permitted to depend on `wos-events`: the core
//! `SubstrateClient` trait, `SubstrateAppendRequest`, response DTOs, and
//! generic constructors stay WOS-agnostic.
//!
//! Future overlay helpers (Formspec, other producers) should not live here —
//! they belong in their own binding crates (e.g.
//! `formspec-signature-trellis-binding` under the `formspec-trellis-bindings`
//! wrapper; future `<producer>-<family>-trellis-binding`). See
//! `TRELLIS-DI-TOPOLOGY-TODO.md` DI-004 "Contain The D12 Shared Client
//! Surface".

use async_trait::async_trait;
use stack_common_error::StackError;
use wos_events::{NativeProvenanceEvent, ProvenanceRecord};
pub use wos_events::{WOS_CANONICAL_EVENT_LITERALS, WOS_NATIVE_PROVENANCE_EVENT_LITERAL};

use crate::{
    AppendActor, ComputeContext, LedgerScope, SubstrateAppendRequest, SubstrateAppendResult,
    SubstrateClient,
};

/// Builds a typed WOS provenance append request from a [`ProvenanceRecord`].
///
/// Preserves existing canonical routes. Other known kinds use the shared native
/// record validator and retain their original fields inside `record`.
///
/// # Errors
/// Returns an error when native record validation or JSON serialization fails.
pub fn wos_provenance_append_request(
    scope: LedgerScope,
    idempotency_key: impl Into<String>,
    actor: AppendActor,
    record: ProvenanceRecord,
    compute_context: ComputeContext,
) -> Result<SubstrateAppendRequest, StackError> {
    if record.record_kind.canonical_event_literal().is_none() {
        let native = NativeProvenanceEvent::from_record(&record)
            .map_err(|_| StackError::bad_request("invalid native provenance record"))?;
        return SubstrateAppendRequest::new_json(
            scope,
            WOS_NATIVE_PROVENANCE_EVENT_LITERAL,
            idempotency_key,
            actor,
            native.payload().clone(),
            compute_context,
        );
    }
    let event_type = record
        .event
        .clone()
        .or_else(|| {
            record
                .record_kind
                .canonical_event_literal()
                .map(str::to_string)
        })
        .ok_or_else(|| {
            StackError::bad_request("WOS provenance record kind has no Trellis event literal")
        })?;
    let payload = serde_json::to_value(&record).map_err(|error| {
        StackError::bad_request(format!(
            "failed to serialize WOS provenance payload: {error}"
        ))
    })?;
    SubstrateAppendRequest::new_json(
        scope,
        event_type,
        idempotency_key,
        actor,
        payload,
        compute_context,
    )
}

/// Producer-facing inputs for the typed WOS provenance helper.
#[derive(Clone, Debug)]
pub struct WosProvenanceAppend {
    pub scope: LedgerScope,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub record: ProvenanceRecord,
    pub compute_context: ComputeContext,
}

/// Ergonomic WOS-typed extensions layered over [`SubstrateClient`].
///
/// Blanket-implemented for every [`SubstrateClient`], so callers compose the
/// helper without owning the implementor type. The extension stays
/// WOS-specific by design (D12).
#[async_trait]
pub trait SubstrateClientExt: SubstrateClient {
    /// Builds and appends a typed WOS provenance record.
    ///
    /// # Errors
    /// Returns an error when request construction or append fails.
    async fn append_wos_provenance(
        &self,
        input: WosProvenanceAppend,
    ) -> Result<SubstrateAppendResult, StackError> {
        let request = wos_provenance_append_request(
            input.scope,
            input.idempotency_key,
            input.actor,
            input.record,
            input.compute_context,
        )?;
        self.append_event(request).await
    }
}

impl<T> SubstrateClientExt for T where T: SubstrateClient + ?Sized {}

#[cfg(test)]
mod native_provenance_tests {
    use super::*;
    use stack_common_typeid::testing::fixture_minter;
    #[test]
    fn native_provenance_client_preserves_original_record() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/conformance/native-provenance-routing.json"
        ))
        .unwrap();
        let record: ProvenanceRecord =
            serde_json::from_value(fixture["payload"]["record"].clone()).unwrap();
        // This helper accepts a typed record. Its original JSON follows the
        // maintained serializer, which omits empty optional collections.
        let original = serde_json::to_value(&record).unwrap();
        let request = wos_provenance_append_request(
            crate::test_ledger("case-1"),
            "native-client",
            AppendActor::service("wos-server"),
            record,
            ComputeContext::no_delegated_compute("wos-server"),
        )
        .unwrap();
        assert_eq!(request.event_type, WOS_NATIVE_PROVENANCE_EVENT_LITERAL);
        assert_eq!(request.payload["record"], original);
        assert_eq!(request.payload["record"]["event"], "original-entry-trigger");
    }
    #[test]
    fn native_provenance_client_keeps_all_canonical_routes_exact() {
        for literal in WOS_CANONICAL_EVENT_LITERALS {
            let kind = wos_events::ProvenanceKind::from_canonical_event_literal(literal).unwrap();
            let record = ProvenanceRecord::blank(&fixture_minter(), kind);
            let original = serde_json::to_value(&record).unwrap();
            let request = wos_provenance_append_request(
                crate::test_ledger("case-1"),
                "canonical-client",
                AppendActor::service("wos-server"),
                record,
                ComputeContext::no_delegated_compute("wos-server"),
            )
            .unwrap();
            assert_eq!(&request.event_type, literal);
            assert_eq!(request.payload, original);
        }
    }
}
