// Rust guideline compliant 2026-02-21
#![allow(clippy::result_large_err, clippy::collapsible_if)]
// `StackError` carries operational context callers rely on; boxing it would change every fallible
// signature in this crate. Follow-up: convert `StackError` to a `Box<...>` newtype workspace-wide.
//! Trellis substrate HTTP service.
//!
//! The service sits between product-facing HTTP append calls and Trellis Core
//! byte construction. Consumers share the `trellis-service-client` wire DTOs;
//! this crate owns admission dispatch, authorization, persistence, export
//! assembly, and registry reads.
//!
//! The crate is producer-neutral: each producer arrives as [`ServerAdapters`]
//! (admission, event-type vocabulary, attachment admission, export profile, tenant
//! headers) and the `NativeCloseout` port, assembled by `trellis-server`.
//! `deny.toml` keeps the adapter crates out of this crate's build graph.
//!
//! Axum routing is exposed via [`router`]; durable bootstrap and HTTP replay state via
//! [`TrellisServerState`] / [`state_from_env`] (implemented in `src/http.rs` and `src/state.rs`).
//!
//! **HTTP replay idempotency** is enforced only through
//! [`stack_common_idempotency::InMemoryHttpReplayStore`] wired into
//! [`stack_common_http::idempotency::HttpIdempotencyState`] middleware (ADR
//! 0092c). There is no parallel `IdempotencyStore` port in `trellis-server-ports`.
//!
//! **Governance overlay (TWREF-064):** a producer server may restrict which literals it emits
//! over HTTP before calling Trellis, while Trellis admits whatever the installed admission
//! policy registers. Bearer credentials targeting Trellis are the substrate trust root:
//! durable non-permissive startups require current OIDC authority and exact deployment
//! resource grants.
//!
//! **Case scope versus Trellis URL scope (TWREF-005):** Admission here keys off `event_type` and payload shape for the
//! HTTP `{scope}` segment plus tenant headers. It does not fetch a producer's case relationship rows; product servers must map
//! their governed case identity into scope and credentials deliberately. Dispatch to a producer's rules is the
//! installed `AdmissionRouter`'s literal lookup, never an event-type prefix match here.

#![forbid(unsafe_code)]

mod adapters;
mod admission;
mod append;
mod artifacts;
mod auth;
mod completion;
mod export;
#[cfg(test)]
mod export_vector;
mod ledger;
mod reconciliation;
#[cfg(test)]
mod repository_probes;
mod signing_history;
mod source_content;
mod source_content_startup;
mod source_diagnostics;
pub use completion::{
    CompletionAttestor, CompletionRequest, CompletionSigner, CompletionSignerLabel,
    CoseCompletionSigner, SelectedCompletion, seal_completion,
};
#[doc(inline)]
pub use source_content::{
    ConfiguredSourceContentPins, PreparedSourceContentBatchV1, PreparedSourceContentRecordV1,
    SourceContentBatchChecker, SourceContentClaim, SourceContentComposition, SourceContentFactory,
    SourceContentFinalPrefixGuard, SourceContentIdentityV1, SourceContentInputs,
    SourceContentObjectReader, SourceContentOccurrenceV1, SourceContentParts,
    SourceContentPrefixClass, SourceContentRecordPins, SourceContentRoleV1, SourceContentSelection,
    StoreSourceContentReader, StructuralSourcePublicationVerifier, source_content_batch_key,
};
#[doc(inline)]
pub use source_content_startup::source_content_composition_from_configuration;
mod event_repository;
mod external_attachment;
mod external_repository;
mod external_transport;
pub(crate) use external_attachment::ExternalAttachmentRecipientPolicy;
pub use external_transport::{ExternalAttachmentRecipient, ExternalAttachmentRecipientSelector};
mod completion_startup;
mod http;
mod oidc_startup;
pub mod openapi;
mod posture;
mod state;
#[cfg(test)]
mod test_adapters;

#[doc(inline)]
pub use adapters::{AdmissionRouter, EventTypeCatalog, ServerAdapters, TenantHeaders};

#[doc(inline)]
pub use event_repository::{
    EventRepository, ExportRows, InMemoryEventRepository, PostgresEventRepository, ScopeTx,
};
#[doc(inline)]
pub use external_repository::ExternalAttachmentFactory;

#[doc(inline)]
pub use http::{documents, router};
#[doc(inline)]
pub use state::{TrellisServerState, state_from_env};

use std::time::{SystemTime, UNIX_EPOCH};

use integrity_cbor::Value;
#[cfg(test)]
use serde::{Deserialize, Serialize};
#[cfg(test)]
use stack_common_auth::{BaseClaims, Claims};
use stack_common_error::StackError;
use trellis_core::SigningKeyMaterial as CoreSigningKey;
use trellis_export_writer::{
    SigningKeyMaterial as ExportSigningKey, SigningKeyRegistryEntry, TrellisTimestamp,
    encode_signing_key_registry,
};
use trellis_types::StoredEvent;

use trellis_server_ports::event_codec::{
    cbor_bad_request, encode_value, event_hash, event_summary, event_timestamp, text_map, uint,
};

use trellis_service_client::endpoints::{EventTypeRegistryEntry, EventTypeRegistryView};

// Catalog version label is producer-neutral: the catalog projects whatever
// admitted literals the injected adapters declare.
pub(crate) const EVENT_TYPE_REGISTRY_VERSION: &str = "trellis-events:2026-05-15";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[must_use]
pub const fn default_bind_addr() -> &'static str {
    DEFAULT_BIND_ADDR
}

/// Local JWT claims used by isolated unit-test fixtures.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrellisClaims {
    #[serde(flatten)]
    pub base: BaseClaims,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[cfg(test)]
impl Claims for TrellisClaims {
    fn base(&self) -> &BaseClaims {
        &self.base
    }
}

/// Parsed signing material shared by append and export paths.
#[derive(Clone, Debug)]
pub struct ServerSigningKey {
    cose_key: Vec<u8>,
    export_key: ExportSigningKey,
    valid_to: Option<TrellisTimestamp>,
    /// Retired predecessors of `export_key`, oldest first. Public material only.
    history: Vec<SigningKeyRegistryEntry>,
}

impl ServerSigningKey {
    /// Parses Ed25519 COSE_Key bytes.
    ///
    /// # Errors
    /// Returns an error when the key cannot be decoded as Trellis Ed25519
    /// signing material.
    pub fn from_cose_key_bytes(
        cose_key: Vec<u8>,
        valid_from: TrellisTimestamp,
    ) -> Result<Self, StackError> {
        let parsed = trellis_cddl::parse_ed25519_cose_key(&cose_key)
            .map_err(|error| StackError::bad_request(format!("invalid signing key: {error}")))?;
        Ok(Self {
            cose_key,
            export_key: ExportSigningKey {
                private_seed: parsed.private_seed,
                public_key: parsed.public_key,
                valid_from,
                valid_to: None,
            },
            valid_to: None,
            history: Vec::new(),
        })
    }

    /// Lowercase hex of the 16-byte key id derived from the public key: the key's fingerprint.
    #[must_use]
    pub fn kid_hex(&self) -> String {
        hex::encode(self.export_key.kid())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_valid_to(mut self, valid_to: Option<TrellisTimestamp>) -> Self {
        self.valid_to = valid_to;
        self.export_key.valid_to = valid_to;
        self
    }

    #[must_use]
    pub fn is_active_at(&self, timestamp: TrellisTimestamp) -> bool {
        self.valid_to
            .map(|valid_to| {
                (timestamp.unix_secs, timestamp.subsec_nanos)
                    <= (valid_to.unix_secs, valid_to.subsec_nanos)
            })
            .unwrap_or(true)
    }

    pub(crate) fn core_key(&self) -> CoreSigningKey {
        CoreSigningKey::new(self.cose_key.clone())
    }

    pub(crate) fn export_key(&self) -> ExportSigningKey {
        self.export_key.clone()
    }

    /// Every registry row this server's exports must carry: retired predecessors in
    /// order, then the current key (Core §8.5 completeness, §8.4 retired rows stay).
    #[must_use]
    pub fn registry_entries(&self) -> Vec<SigningKeyRegistryEntry> {
        let mut rows = self.history.clone();
        let mut current = self.export_key.registry_entry();
        if let Some(previous) = rows.last() {
            current.supersedes = Some(previous.kid);
        }
        rows.push(current);
        rows
    }

    /// Public-key registry as published for export verification.
    ///
    /// # Errors
    /// Returns an internal error when the registry cannot be canonically encoded.
    pub fn public_key_registry_cbor(&self) -> Result<Vec<u8>, StackError> {
        encode_signing_key_registry(&self.registry_entries())
    }
}

pub(crate) fn validate_existing_replay(
    event: &StoredEvent,
    event_type: &str,
    content_hash: [u8; 32],
) -> Result<(), StackError> {
    let summary = event_summary(event)?;
    if summary.event_type != event_type {
        return Err(StackError::conflict(
            "idempotency key reused with a different event type",
        ));
    }
    if summary.content_hash != content_hash {
        return Err(StackError::conflict(
            "idempotency key reused with a different payload",
        ));
    }
    Ok(())
}

pub(crate) fn now_timestamp() -> Result<TrellisTimestamp, StackError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StackError::internal(format!("system clock before epoch: {error}")))?;
    TrellisTimestamp::new(duration.as_secs(), duration.subsec_nanos())
}

pub(crate) fn timestamp_value(timestamp: TrellisTimestamp) -> Value {
    Value::Array(vec![
        uint(timestamp.unix_secs),
        uint(u64::from(timestamp.subsec_nanos)),
    ])
}

pub(crate) fn event_type_registry_view(catalog: &EventTypeCatalog) -> EventTypeRegistryView {
    debug_assert!(
        !catalog.is_empty(),
        "default event-type catalog must not be empty"
    );
    let mut event_types = Vec::with_capacity(catalog.len());
    for entry in catalog.entries() {
        debug_assert!(
            catalog.get(&entry.event_type).is_some(),
            "catalog entry must resolve by its own event type"
        );
        event_types.push(EventTypeRegistryEntry {
            event_type: entry.event_type.clone(),
            schema_ref: entry.schema_ref.as_str().to_string(),
        });
    }
    EventTypeRegistryView {
        registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
        event_types,
    }
}

pub(crate) fn event_type_registry_cbor(catalog: &EventTypeCatalog) -> Result<Vec<u8>, StackError> {
    const SERVICE_CLASSIFICATION: &str = "x-trellis-service/public-metadata";
    const ATTACHMENT_CLASSIFICATION: &str = "x-trellis-service/private-attachment";
    let mut event_types = Vec::with_capacity(catalog.len());
    for entry in catalog.entries() {
        let map_entry = text_map(vec![
            (
                "privacy_class",
                Value::Text(
                    if entry.privacy_class
                        == trellis_server_ports::EventPrivacyClass::PrivateAttachment
                    {
                        "privateAttachment"
                    } else {
                        "publicMetadata"
                    }
                    .to_string(),
                ),
            ),
            (
                "binding_family",
                Value::Text(entry.event_family.as_str().to_string()),
            ),
        ])?;
        event_types.push((Value::Text(entry.event_type.clone()), map_entry));
    }
    let registry = text_map(vec![
        ("event_types", Value::Map(event_types)),
        (
            "classifications",
            Value::Array(vec![
                Value::Text(SERVICE_CLASSIFICATION.to_string()),
                Value::Text(ATTACHMENT_CLASSIFICATION.to_string()),
            ]),
        ),
        (
            "registry_version",
            Value::Text(EVENT_TYPE_REGISTRY_VERSION.to_string()),
        ),
    ])?;
    encode_value(&registry)
}

#[cfg(test)]
mod tests {
    use stack_common_typeid::testing::fixture_minter;
    mod flat_cost_tests {
        include!("flat_cost_tests.rs");
    }
    mod reconciliation_tests {
        include!("reconciliation_tests.rs");
    }
    mod source_diagnostic_state_tests {
        include!("source_diagnostic_state_tests.rs");
    }

    mod source_content_tests {
        include!("source_content_tests.rs");
    }
    mod completion_tests {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/completion_tests.rs"
        ));
    }
    mod external_attachment_tests {
        include!("external_attachment_tests.rs");
    }
    mod external_transport_tests {
        include!("external_transport_tests.rs");
    }
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use integrity_seam::OsSecureRandom;
    use jsonwebtoken::Algorithm;
    use stack_common_auth::{JwtConfig, JwtIssuer, JwtVerifier};
    use stack_common_http::idempotency::{IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_REPLAY_HEADER};
    use stack_common_ops::HealthProbe;
    use tower::ServiceExt;
    use trellis_server_ports::{AdmissionEvent, ArtifactRef};
    use trellis_service_client::{ClientAttestation, SubstrateAppendBody, SubstrateAppendResult};
    use wos_events::{
        ProvenanceKind, ProvenanceRecord, SignatureAdmissionFailedInput, SignatureAffirmationInput,
        WOS_CANONICAL_EVENT_LITERALS,
    };

    use crate::admission::ScopedAllowlistScopeAuthorizer;
    use crate::append::{AppendRunner, DefaultAppendRunner};
    use crate::state::TrellisHealthProbe;
    use crate::test_adapters::{
        self, FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH, FORMSPEC_RESPONSE_SUBMITTED,
        export_bundle_cryptographically_verified,
    };
    use integrity_cbor::{map_lookup_bytes, map_lookup_map, map_lookup_u64};

    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::http::StatusCode;
    use trellis_server_ports::{ArtifactStore, EventAdmissionPolicy};

    use super::*;

    #[test]
    fn encode_value_canonicalizes_nested_maps() {
        let value = Value::Map(vec![(
            Value::Text("consent".to_string()),
            Value::Map(vec![
                (
                    Value::Text("z".to_string()),
                    Value::Text("last".to_string()),
                ),
                (
                    Value::Text("a".to_string()),
                    Value::Text("first".to_string()),
                ),
            ]),
        )]);

        let bytes = encode_value(&value).expect("canonical bytes");
        let decoded = integrity_cbor::decode_cbor_value(&bytes).expect("decode canonical bytes");
        let root = decoded.as_map().expect("root map");
        let consent = root[0].1.as_map().expect("consent map");
        let keys = consent
            .iter()
            .map(|(key, _)| key.as_text().expect("text key"))
            .collect::<Vec<_>>();

        assert_eq!(keys, vec!["a", "z"]);
    }

    #[derive(Clone)]
    struct RecordingAppendRunner {
        /// Increments for each `AppendRunner::run_append` entry (HTTP → orchestration seam).
        invocations: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AppendRunner for RecordingAppendRunner {
        async fn run_append(
            &self,
            state: &TrellisServerState,
            command: append::AppendCommand,
        ) -> Result<append::AppendOutcome, StackError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            DefaultAppendRunner.run_append(state, command).await
        }
    }

    /// Given a Trellis router built with an injected append runner probe, when `POST …/events`
    /// succeeds, then the HTTP handler routed through `AppendRunner` exactly once (TWREF-021:
    /// orchestration is not inlined past the outer HTTP/auth boundary).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_append_runner_records_single_coordinator_pass()
    {
        // Given: Axum state substitutes [`RecordingAppendRunner`] ahead of [`DefaultAppendRunner`].
        let invocations = Arc::new(AtomicUsize::new(0));
        let runner = Arc::new(RecordingAppendRunner {
            invocations: invocations.clone(),
        });
        let app = router(test_state().with_append_runner(runner)).expect("router");

        // When: Client posts a valid append body.
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-append-runner-delegation"),
            ))
            .await
            .expect("append response");

        // Then: Handler invoked the injected runner once; coordinator path executed underneath.
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "POST append must delegate through AppendRunner (AppendCoordinator) rather than inlining orchestration"
        );
    }

    /// Given a fresh append, when the HTTP handler runs, then admission executes
    /// exactly once inside the append coordinator (not duplicated in the handler).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_admission_runs_once_in_coordinator() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = test_adapters::admission_policy();
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let app = router(test_state().with_admission_policy(counting)).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-coordinator-admission"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            1,
            "append coordinator must call admission exactly once per fresh append"
        );
    }

    /// Given a ledger idempotency replay, when the coordinator runs again with the
    /// same key, then admission runs once per pass and the sequence is unchanged.
    #[tokio::test]
    async fn given_ledger_idempotency_replay_when_coordinator_runs_then_admission_once_per_pass() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = test_adapters::admission_policy();
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let state = test_state().with_admission_policy(counting);
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-replay")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            client_attestation: body.client_attestation.clone(),
        };
        let first = state
            .append_coordinator()
            .append(command.clone())
            .await
            .expect("first append");
        assert_eq!(first.result.sequence, 0);
        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);

        let second = state
            .append_coordinator()
            .append(command)
            .await
            .expect("ledger replay");
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            2,
            "each coordinator pass admits once; ledger replay must not duplicate events"
        );
        assert_eq!(second.result.sequence, first.result.sequence);
        assert_eq!(
            second.result.canonical_event_hash,
            first.result.canonical_event_hash
        );
        assert_eq!(
            second.result.prior_event_hash,
            first.result.prior_event_hash
        );
    }

    /// Given a second append in a scope, when the coordinator returns the receipt,
    /// then `priorEventHash` points at the immediate predecessor.
    #[tokio::test]
    async fn given_second_append_when_coordinator_returns_then_prior_event_hash_points_to_previous()
    {
        let state = test_state();
        let first_body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prior-first")).unwrap();
        let first_command = append::AppendCommand {
            scope: "case_prior_hash".to_string(),
            event_type: first_body.event_type.clone(),
            idempotency_key: first_body.idempotency_key.clone(),
            payload: first_body.payload.clone(),
            client_attestation: first_body.client_attestation.clone(),
        };
        let first = state
            .append_coordinator()
            .append(first_command)
            .await
            .expect("first append");

        let second_body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prior-second")).unwrap();
        let second_command = append::AppendCommand {
            scope: "case_prior_hash".to_string(),
            event_type: second_body.event_type.clone(),
            idempotency_key: second_body.idempotency_key.clone(),
            payload: second_body.payload.clone(),
            client_attestation: second_body.client_attestation.clone(),
        };
        let second = state
            .append_coordinator()
            .append(second_command.clone())
            .await
            .expect("second append");
        assert_eq!(second.result.sequence, 1);
        assert_eq!(
            second.result.prior_event_hash.as_deref(),
            Some(first.result.canonical_event_hash.as_str())
        );

        let replay = state
            .append_coordinator()
            .append(second_command)
            .await
            .expect("second append replay");
        assert_eq!(
            replay.result.prior_event_hash,
            second.result.prior_event_hash
        );
    }

    /// Given a WOS provenance append, when the handler completes, then the receipt names a
    /// checkpoint and the export pinned at it commits to that same checkpoint.
    #[tokio::test]
    async fn given_wos_append_when_completed_then_the_receipt_names_a_checkpoint_the_export_commits_to()
     {
        let app = router(test_state()).expect("router");
        let result = post_append(
            &app,
            "/v1/scopes/case_123/events",
            append_body("idem-wos-profile"),
        )
        .await;
        assert_eq!(result.sequence, 0);
        let zip = pinned_zip(&app, "case_123", &result).await;
        assert_eq!(
            manifest_head_checkpoint_digest(&zip),
            checkpoint_digest_of(&result)
        );
    }

    /// Given a Formspec aggregate append, when admission runs, then the event is accepted under
    /// its own literal and the receipt names its checkpoint.
    #[tokio::test]
    async fn given_formspec_response_submitted_when_appended_then_the_event_keeps_its_literal() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let result = post_append(
            &app,
            "/v1/scopes/formspec.managed-single-cell/events",
            formspec_append_body("idem-fspec-profile"),
        )
        .await;
        let stored = state
            .repository
            .list_scope(b"formspec.managed-single-cell")
            .await
            .unwrap();
        assert_eq!(
            event_summary(&stored[0]).unwrap().event_type,
            FORMSPEC_RESPONSE_SUBMITTED
        );
        assert_eq!(result.sequence, 0);
    }

    /// Given a Formspec Response Actions session-batch append, when admission runs,
    /// then the event is accepted under its own literal.
    #[tokio::test]
    async fn given_formspec_response_action_session_batch_when_appended_then_event_type_is_preserved()
     {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.managed-single-cell/events",
                formspec_append_body_with_event_type(
                    "idem-fspec-action-profile",
                    FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
                    serde_json::json!({
                        "aggregateType": "formspec.response_action_session_op_batch",
                        "aggregateId": "urn:formspec:session:session-action-1",
                        "payload": {
                            "ledgerScope": "urn:formspec:session:session-action-1",
                            "branchId": "branch-main",
                            "opBatch": {
                                "semanticOps": []
                            },
                            "opBatchHash": "sha256:e7a089ec840bca120002285859beed5ed98b0aaae8ea512e357bf87b926485b3",
                            "ledgerPortIdempotencyKey": "sha256:a409097f6e5def98de1a7abd9e359a0741011e732cc0ff68a745a7b8dd73b8b7",
                            "mode": "require-anchored"
                        }
                    }),
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let stored = state
            .repository
            .list_scope(b"formspec.managed-single-cell")
            .await
            .unwrap();
        assert_eq!(
            event_summary(&stored[0]).unwrap().event_type,
            FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH
        );
    }

    #[test]
    fn event_type_registry_cbor_maps_privacy_class_to_published_label() {
        let catalog = EventTypeCatalog::from_specs(test_adapters::adapters().event_type_specs);
        let decoded = integrity_cbor::decode_cbor_value(
            &event_type_registry_cbor(&catalog).expect("encode event-type registry"),
        )
        .expect("decode registry");
        let types = integrity_cbor::map_lookup_map(decoded.as_map().unwrap(), "event_types")
            .expect("event_types");
        let privacy = |event_type: &str| {
            let entry = integrity_cbor::map_lookup_map(types, event_type).expect("registered type");
            match integrity_cbor::map_lookup_optional_value(entry, "privacy_class") {
                Some(Value::Text(label)) => label.clone(),
                other => panic!("privacy_class {other:?}"),
            }
        };
        let private = catalog
            .entries()
            .find(|entry| {
                entry.privacy_class == trellis_server_ports::EventPrivacyClass::PrivateAttachment
            })
            .expect("a private-attachment type is registered");
        assert_eq!(privacy(&private.event_type), "privateAttachment");
        assert_eq!(privacy(FORMSPEC_RESPONSE_SUBMITTED), "publicMetadata");
    }

    #[test]
    fn given_signing_key_with_valid_to_when_registry_cbor_built_then_valid_to_is_encoded() {
        let valid_from = TrellisTimestamp::new(1_700_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_800_000_000, 0).expect("valid to");
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let registry_cbor = signing_key
            .public_key_registry_cbor()
            .expect("encode signing-key registry");
        let decoded = integrity_cbor::decode_cbor_value(&registry_cbor).expect("decode registry");
        let integrity_cbor::Value::Array(entries) = decoded else {
            panic!("registry must be a CBOR array");
        };
        let integrity_cbor::Value::Map(entry) = entries
            .first()
            .expect("registry must contain one signing-key entry")
        else {
            panic!("registry entry must be a CBOR map");
        };
        let valid_to_value = entry
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (integrity_cbor::Value::Text(label), value) if label == "valid_to" => Some(value),
                _ => None,
            })
            .expect("registry entry must include valid_to");
        assert_eq!(
            valid_to_value,
            &integrity_cbor::Value::Array(vec![
                integrity_cbor::Value::Integer(1_800_000_000.into()),
                integrity_cbor::Value::Integer(0.into()),
            ]),
            "registry valid_to must reflect signing key expiry"
        );
    }

    #[test]
    fn given_corrupt_export_zip_when_verified_then_returns_false() {
        assert!(!export_bundle_cryptographically_verified(
            b"not-a-valid-export-zip"
        ));
    }

    /// The export at a receipt's checkpoint verifies with the independent verifier, which is the
    /// only check of the bytes: the server no longer verifies its own output.
    #[tokio::test]
    async fn the_export_at_a_receipts_checkpoint_passes_independent_verification() {
        let app = router(test_state()).expect("router");
        let result = post_append(
            &app,
            "/v1/scopes/case_123/events",
            append_body("idem-export-verified"),
        )
        .await;
        let zip = pinned_zip(&app, "case_123", &result).await;
        assert!(export_bundle_cryptographically_verified(&zip));
    }

    #[tokio::test]
    async fn given_non_public_compute_context_when_append_requested_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&append_body("idem-non-public-compute")).unwrap();
        body["computeContext"]["sensitivity"] = serde_json::Value::String("readerHeld".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Inactive signing key (`valid_to` before wall-clock time) rejects append with BAD_REQUEST via
    /// `AppendCoordinator`; temporarily removing its `is_active_at` guard turns this case RED (201).
    #[tokio::test]
    async fn given_expired_signing_key_when_http_append_then_bad_request() {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let valid_from = TrellisTimestamp::new(1_600_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_700_000_010, 0).expect("valid to");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let state = TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            crate::test_adapters::adapters(),
        );
        let app = router(state).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-expired-signing-key"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn given_production_like_posture_when_router_builds_with_allow_all_then_err() {
        let state = test_state().with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject misleading posture");
        let msg = err.to_string();
        assert!(msg.contains("explicit resource ScopeAuthorizer"), "{msg}");
    }

    #[test]
    fn given_production_like_posture_when_scoped_authorizer_without_jwt_then_router_err() {
        let state = test_state()
            .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
            .with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject missing jwt verifier");
        let msg = err.to_string();
        assert!(msg.contains("injected access-token verifier"), "{msg}");
    }

    const TEST_JWT_SECRET: &[u8] = b"trellis-test-jwt-secret";

    fn test_jwt_config() -> JwtConfig {
        JwtConfig {
            algorithm: Algorithm::HS256,
            validate_exp: true,
            validate_iss: None,
            validate_aud: None,
            leeway_secs: 30,
        }
    }

    fn test_trellis_token(scopes: Vec<String>) -> String {
        let issuer = JwtIssuer::<TrellisClaims>::from_hs256(
            test_jwt_config(),
            TEST_JWT_SECRET,
            Box::new(OsSecureRandom),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let jti = issuer.generate_jti().unwrap();
        let claims = TrellisClaims {
            base: BaseClaims {
                sub: "test-subject".to_string(),
                exp: now + 3600,
                iat: now,
                jti,
            },
            scopes,
        };
        issuer.issue(&claims).unwrap()
    }

    fn test_state_scoped_production_like() -> TrellisServerState {
        let verifier = JwtVerifier::<TrellisClaims>::from_hs256(test_jwt_config(), TEST_JWT_SECRET);
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            test_signing_key(),
            crate::test_adapters::adapters(),
        )
        .with_jwt_verifier(verifier)
        .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
        .with_production_like_scope_posture(true)
    }

    fn post_request_bearer(path: &str, body: Vec<u8>, bearer: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn authorized_append_replay_without_bearer_is_unauthorized() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let state = test_state_scoped_production_like();
        let app = router(state.clone()).expect("router");
        let path = "/v1/scopes/case_123/events";
        let body = append_body("replay-current-auth-missing");
        let first = app
            .clone()
            .oneshot(post_request_bearer(path, body.clone(), &token))
            .await
            .expect("authorized append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let replay = app
            .oneshot(post_request(path, body))
            .await
            .expect("unauthenticated replay");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert!(replay.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none());
        assert_eq!(
            state
                .repository
                .list_scope(b"case_123")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn authorized_append_replay_with_other_scope_is_forbidden() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let other = test_trellis_token(vec!["other_scope".to_string()]);
        let state = test_state_scoped_production_like();
        let app = router(state.clone()).expect("router");
        let path = "/v1/scopes/case_123/events";
        let body = append_body("replay-current-auth-other-scope");
        let first = app
            .clone()
            .oneshot(post_request_bearer(path, body.clone(), &token))
            .await
            .expect("authorized append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let replay = app
            .oneshot(post_request_bearer(path, body, &other))
            .await
            .expect("ungranted replay");
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        assert!(replay.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none());
        assert_eq!(
            state
                .repository
                .list_scope(b"case_123")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_without_bearer_then_unauthorized() {
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-bearer"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_jwt_missing_scope_then_forbidden() {
        let token = test_trellis_token(vec!["other_scope".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-wrong-scope"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_omits_client_attestation_then_created() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-attest"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_includes_client_attestation_then_bad_request()
    {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-attest")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let combined = format!(
            "{} {}",
            problem
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            problem
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        assert!(
            combined.contains("clientAttestation") && combined.contains("TWREF"),
            "problem should cite clientAttestation and TWREF, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_production_like_server_when_client_attestation_has_empty_kid_then_bad_request() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-empty-kid")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: String::new(),
            cose_sign1: "00".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn given_test_server_when_append_includes_client_attestation_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-client-attestation-present")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let ctype = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            ctype.contains("application/problem+json"),
            "expected application/problem+json, got {ctype:?}"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let mut message = problem
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(detail) = problem.get("detail").and_then(|value| value.as_str()) {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(detail);
        }
        assert!(
            message.contains("clientAttestation"),
            "problem title/detail should cite clientAttestation, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_fresh_append_when_coordinator_completes_then_persisted_hash_matches_wire() {
        let repo = Arc::new(InMemoryEventRepository::new());
        let state = TrellisServerState::new(
            repo.clone(),
            test_signing_key(),
            crate::test_adapters::adapters(),
        );
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-persisted-hash")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            client_attestation: body.client_attestation.clone(),
        };
        let outcome = state
            .append_coordinator()
            .append(command)
            .await
            .expect("coordinator append");
        let stored = repo
            .list_scope(b"case_123")
            .await
            .expect("list scope")
            .pop()
            .expect("one event");
        let hex_digest = outcome
            .result
            .canonical_event_hash
            .strip_prefix("sha256:")
            .expect("hash prefix");
        let bytes = hex::decode(hex_digest).expect("digest hex");
        let hash: [u8; 32] = bytes.try_into().expect("canonical hash is 32 bytes");
        assert_eq!(
            stored
                .canonical_event_hash()
                .expect("persisted substrate hash"),
            &hash,
            "coordinator commits before returning the append receipt canonical hash field",
        );
    }

    #[tokio::test]
    async fn append_wos_event_serves_an_export_and_registries() {
        let app = router(test_state()).expect("router");
        let result = post_append(&app, "/v1/scopes/case_123/events", append_body("idem-1")).await;
        assert_eq!(result.sequence, 0);
        assert!(result.canonical_event_hash.starts_with("sha256:"));

        let bundle = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_123/bundles/head"))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        assert!(bundle_bytes.len() > 100);

        let registry = app
            .oneshot(get_request("/v1/scopes/case_123/registries/event-types"))
            .await
            .expect("registry response");
        assert_eq!(registry.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pinned_bundle_returns_existing_checkpoint_with_normalized_digest_forms() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_pinned_bundle/events",
                append_body("idem-pinned-bundle"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("append response body");
        let result: SubstrateAppendResult =
            serde_json::from_slice(&body).expect("append response JSON");
        let digest = result
            .checkpoint_ref
            .rsplit('/')
            .next()
            .expect("checkpoint digest in ref");
        let hex_digest = digest.strip_prefix("sha256:").expect("sha256 digest");

        let head = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_pinned_bundle/bundles/head"))
            .await
            .expect("head bundle response");
        assert_eq!(head.status(), StatusCode::OK);
        let head_bytes = to_bytes(head.into_body(), 10 * 1024 * 1024)
            .await
            .expect("head bundle bytes")
            .to_vec();

        let prefixed_path = format!("/v1/scopes/case_pinned_bundle/bundles/{digest}");
        let prefixed = app
            .clone()
            .oneshot(get_request(&prefixed_path))
            .await
            .expect("prefixed pinned bundle response");
        assert_eq!(prefixed.status(), StatusCode::OK);
        let prefixed_bytes = to_bytes(prefixed.into_body(), 10 * 1024 * 1024)
            .await
            .expect("prefixed pinned bundle bytes")
            .to_vec();

        let bare_path = format!("/v1/scopes/case_pinned_bundle/bundles/{hex_digest}");
        let bare = app
            .clone()
            .oneshot(get_request(&bare_path))
            .await
            .expect("bare pinned bundle response");
        assert_eq!(bare.status(), StatusCode::OK);
        let bare_bytes = to_bytes(bare.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bare pinned bundle bytes")
            .to_vec();

        let uppercase_path = format!(
            "/v1/scopes/case_pinned_bundle/bundles/sha256:{}",
            hex_digest.to_ascii_uppercase()
        );
        let uppercase = app
            .oneshot(get_request(&uppercase_path))
            .await
            .expect("uppercase pinned bundle response");
        assert_eq!(uppercase.status(), StatusCode::OK);
        let uppercase_bytes = to_bytes(uppercase.into_body(), 10 * 1024 * 1024)
            .await
            .expect("uppercase pinned bundle bytes")
            .to_vec();

        assert_eq!(head_bytes, prefixed_bytes);
        assert_eq!(head_bytes, bare_bytes);
        assert_eq!(head_bytes, uppercase_bytes);
    }

    #[tokio::test]
    async fn pinned_bundle_returns_not_found_for_a_checkpoint_the_scope_never_issued() {
        let state = test_state();
        let app = router(state).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_pinned_missing/events",
                append_body("idem-pinned-missing"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let missing = app
            .oneshot(get_request(&format!(
                "/v1/scopes/case_pinned_missing/bundles/sha256:{}",
                "ff".repeat(32)
            )))
            .await
            .expect("missing pinned bundle response");

        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn signature_affirmation_append_publishes_profile_members_verified_by_wos_verifier() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_signature/events",
                signature_affirmation_append_body("idem-signature-export"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request("/v1/scopes/case_signature/bundles/head"))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "signature exports must carry 067-policy-closure.cbor"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.substrate().structure_verified && report.substrate().integrity_verified,
            "{report:#?}"
        );
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    #[tokio::test]
    async fn signature_affirmation_with_deployment_local_intent_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_deployment_local_signature/events",
                signature_affirmation_append_body_with_intent(
                    "idem-deployment-local-signature",
                    "urn:acme:signing-intent:supervisor-approval",
                    None,
                    None,
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_deployment_local_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "deployment-local policy inputs are not represented by the default closure evidence"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert_missing_policy_closure_advisory(&report);
        assert!(report.relying_party_valid(), "{report:#?}");
    }

    #[tokio::test]
    async fn signature_affirmation_with_unregistered_wos_intent_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_unregistered_wos_signature/events",
                signature_affirmation_append_body_with_intent(
                    "idem-unregistered-wos-signature",
                    "urn:wos:signing-intent:not-registered",
                    None,
                    None,
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_unregistered_wos_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "unregistered WOS namespace intents are not covered by the baseline policy closure"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert_missing_policy_closure_advisory(&report);
        assert!(report.relying_party_valid(), "{report:#?}");
    }

    #[tokio::test]
    async fn signature_admission_failed_append_publishes_rejected_profile_projection() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_rejected_signature/events",
                signature_admission_failed_append_body("idem-rejected-signature-export"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_rejected_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        let signed_acts = members
            .iter()
            .find(|entry| {
                entry
                    .path()
                    .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)
            })
            .expect("signed acts member");
        let catalog =
            integrity_cbor::decode_cbor_value(signed_acts.bytes()).expect("signed acts cbor");
        let root = catalog.as_map().expect("signed acts root map");
        let acts = integrity_cbor::map_lookup_array(root, "acts").expect("acts");
        let act = acts.first().expect("one rejected act").as_map().unwrap();
        let admission = integrity_cbor::map_lookup_map(act, "admission").expect("admission");
        assert_eq!(
            integrity_cbor::map_lookup_text(admission, "outcome").expect("outcome"),
            "rejected"
        );
        assert_eq!(
            integrity_cbor::map_lookup_text(admission, "failure_reason").expect("failure_reason"),
            "method_unregistered"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    #[tokio::test]
    async fn signature_admission_failed_with_posture_floor_unmet_suppresses_policy_closure() {
        let app = router(test_state()).expect("router");
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_posture_failed_signature/events",
                signature_admission_failed_append_body_with_reason(
                    "idem-posture-failed-signature",
                    "posture_floor_unmet",
                    "urn:wos:signing-intent:applicant-signature",
                ),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let bundle = app
            .oneshot(get_request(
                "/v1/scopes/case_posture_failed_signature/bundles/head",
            ))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .expect("bundle bytes")
            .to_vec();
        let members = integrity_bundle::read_stored_zip(&bundle_bytes).expect("parse bundle");
        assert!(
            members.iter().any(|entry| entry
                .path()
                .ends_with(trellis_export_writer::SIGNED_ACTS_MEMBER)),
            "signature exports must still carry 066-signed-acts.cbor"
        );
        assert!(
            members.iter().all(|entry| !entry
                .path()
                .ends_with(trellis_export_writer::POLICY_CLOSURE_MEMBER)),
            "posture-specific rejection policy is not represented by the default closure evidence"
        );

        let report = trellis_verify_wos::verify_export_zip(&bundle_bytes);
        assert!(
            report.wos_findings.is_empty() && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    /// An export is a function of the stored prefix: assembling the same checkpoint twice gives the
    /// same bytes, and the manifest's seal fence names the prefix it closes.
    #[tokio::test]
    async fn exporting_the_same_checkpoint_twice_gives_identical_zip_bytes() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        post_append(
            &app,
            "/v1/scopes/case_deterministic/events",
            append_body("idem-deterministic-1"),
        )
        .await;
        let head = state
            .repository
            .head_checkpoint(b"case_deterministic")
            .await
            .unwrap()
            .expect("head checkpoint");
        let first = export::assemble(&state, b"case_deterministic", &head)
            .await
            .expect("first export");
        let second = export::assemble(&state, b"case_deterministic", &head)
            .await
            .expect("second export");
        assert_eq!(first, second);

        let event = state
            .repository
            .last_event(b"case_deterministic")
            .await
            .unwrap()
            .unwrap();
        let expected_attempt = export::export_attempt_id(
            b"case_deterministic",
            1,
            0,
            event_hash(b"case_deterministic", &event).unwrap(),
        )
        .unwrap();
        let manifest = manifest_payload_from_bundle(&first);
        let extensions = map_lookup_map(manifest.as_map().expect("manifest map"), "extensions")
            .expect("extensions");
        let seal_fence = extensions
            .iter()
            .find(|(key, _)| key.as_text() == Some("trellis.export.seal-fence.v1"))
            .map(|(_, value)| value.as_map().expect("seal fence map"))
            .expect("seal fence extension");
        assert_eq!(
            map_lookup_bytes(seal_fence, "bundle_scope")
                .expect("bundle scope")
                .as_slice(),
            b"case_deterministic"
        );
        assert_eq!(
            seal_fence
                .iter()
                .find(|(key, _)| key.as_text() == Some("export_attempt_id"))
                .and_then(|(_, value)| value.as_text()),
            Some(expected_attempt.as_str())
        );
        assert_eq!(
            seal_fence
                .iter()
                .find(|(key, _)| key.as_text() == Some("policy_closure_digest"))
                .map(|(_, value)| value),
            Some(&Value::Null)
        );
    }

    /// Substrate-determinism invariant: identical (signing key, ledger rows) produce a
    /// byte-identical export whichever `TrellisServerState` assembles it. Two independent states
    /// over one stored ledger catch per-instance non-determinism (random nonces, instance
    /// counters, time-of-day leaks) that assembling twice on one state could hide.
    #[tokio::test]
    async fn exports_are_byte_identical_across_independent_states() {
        let signing_key = test_signing_key();
        let repository = Arc::new(InMemoryEventRepository::new());
        let source_state = TrellisServerState::new(
            repository.clone(),
            signing_key.clone(),
            crate::test_adapters::adapters(),
        );
        let app = router(source_state.clone()).expect("router");
        for key in ["idem-cross-state-1", "idem-cross-state-2"] {
            post_append(
                &app,
                "/v1/scopes/case_cross_state_identity/events",
                append_body(key),
            )
            .await;
        }
        let head = repository
            .head_checkpoint(b"case_cross_state_identity")
            .await
            .unwrap()
            .expect("head");
        let state_a = TrellisServerState::new(
            repository.clone(),
            signing_key.clone(),
            crate::test_adapters::adapters(),
        );
        let state_b =
            TrellisServerState::new(repository, signing_key, crate::test_adapters::adapters());
        let bytes_a = export::assemble(&state_a, b"case_cross_state_identity", &head)
            .await
            .expect("export on state A");
        let bytes_b = export::assemble(&state_b, b"case_cross_state_identity", &head)
            .await
            .expect("export on state B");
        assert_eq!(bytes_a, bytes_b);
    }

    #[tokio::test]
    async fn signature_profile_exports_are_byte_identical_for_the_same_checkpoint() {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        post_append(
            &app,
            "/v1/scopes/case_signature_deterministic/events",
            signature_affirmation_append_body("idem-signature-deterministic-1"),
        )
        .await;
        post_append(
            &app,
            "/v1/scopes/case_signature_deterministic/events",
            signature_admission_failed_append_body("idem-signature-deterministic-2"),
        )
        .await;
        let head = state
            .repository
            .head_checkpoint(b"case_signature_deterministic")
            .await
            .unwrap()
            .expect("head");
        assert_eq!(head.tree_size, 2);
        let first = export::assemble(&state, b"case_signature_deterministic", &head)
            .await
            .expect("first export");
        let second = export::assemble(&state, b"case_signature_deterministic", &head)
            .await
            .expect("second export");
        assert_eq!(
            first, second,
            "profile-bearing exports must remain byte-identical for the same closed signature event set"
        );
    }

    #[tokio::test]
    async fn given_unreachable_artifact_store_when_health_probe_runs_then_reports_degraded() {
        struct FailingArtifactStore;

        #[async_trait]
        impl ArtifactStore for FailingArtifactStore {
            type Error = StackError;

            async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
                Err(StackError::unavailable("artifact store offline"))
            }

            async fn put_immutable(
                &self,
                _key: &str,
                _bytes: &[u8],
            ) -> Result<ArtifactRef, Self::Error> {
                Err(StackError::unavailable("artifact store offline"))
            }

            async fn get(
                &self,
                _artifact_ref: &ArtifactRef,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let state = test_state().with_artifact_store(Arc::new(FailingArtifactStore));
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "unreachable artifact store must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn given_repository_unreachable_when_health_probe_runs_then_reports_degraded() {
        let state = TrellisServerState::new(
            Arc::new(crate::repository_probes::UnreachableRepository),
            test_signing_key(),
            crate::test_adapters::adapters(),
        );
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "repository probe failure must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn openapi_document_is_served_and_declares_substrate_routes() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(get_request("/openapi.json"))
            .await
            .expect("OpenAPI response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // The mounted route serves the document the committed copy is checked against.
        assert_eq!(doc, documents_of_test_state().public);
    }

    /// Given a successful substrate append, when the same JSON body and idempotency key are
    /// POSTed again, then the HTTP replay middleware returns the stored response with
    /// `x-replay: true` (no second ledger append).
    #[tokio::test]
    async fn given_identical_append_when_posted_twice_then_http_middleware_replays() {
        let app = router(test_state()).expect("router");
        let body = append_body("idem-2");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert_eq!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).unwrap(),
            "true"
        );
    }

    /// Given a recorded HTTP idempotency entry for key K, when a second POST reuses K with a
    /// different body hash, then the shared middleware returns 409 and must not set `x-replay`.
    #[tokio::test]
    async fn given_recorded_replay_when_same_key_different_body_then_conflict_without_replay_header()
     {
        let app = router(test_state()).expect("router");
        let idem = "twref055-body-conflict";
        let first_body = append_body(idem);
        let first = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                first_body.clone(),
            ))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let mut variant: serde_json::Value = serde_json::from_slice(&first_body).expect("json");
        variant["payload"]["id"] = serde_json::Value::String("prov-alternate-body-hash".into());
        let second_body = serde_json::to_vec(&variant).expect("encode");

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", second_body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CONFLICT);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "409 conflict path must not mark responses as replayed"
        );
        let bytes = to_bytes(second.into_body(), 1024 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["error_code"], "INFRA-4090");
        let title = problem["title"].as_str().unwrap_or_default();
        let detail = problem["detail"].as_str().unwrap_or_default();
        let combined = format!("{title} {detail}");
        assert!(
            combined.contains("idempotency"),
            "unexpected problem payload: {problem}"
        );
    }

    /// Given TWREF-055 closure, when `trellis-server-ports` is audited, then it must not reintroduce
    /// a parallel HTTP `IdempotencyStore` trait—replay stays on `stack_common_idempotency`.
    #[test]
    fn twref055_trellis_server_ports_has_no_parallel_http_idempotency_trait() {
        const PORTS_LIB: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-server-ports/src/lib.rs"
        ));
        assert!(
            !PORTS_LIB.contains("trait IdempotencyStore"),
            "TWREF-055: HTTP replay stays on stack_common_idempotency::HttpReplayStore (ADR 0092c)"
        );
        assert!(
            !PORTS_LIB.contains("IdempotencyReplay"),
            "TWREF-055: orphan IdempotencyReplay must not return alongside duplicate traits"
        );
    }

    /// Given distinct WOS tenant headers, when the same idempotency key and POST body are used,
    /// then the second tenant must not replay the first tenant's HTTP middleware cache entry.
    #[tokio::test]
    async fn given_distinct_wos_tenants_when_same_idempotency_body_then_no_cross_tenant_http_replay()
     {
        let app = router(test_state()).expect("router");
        let body = append_body("twref055-tenant-scope");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("tenant-a append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request_with_wos_tenant(
                "/v1/scopes/case_123/events",
                body,
                "tenant-b",
            ))
            .await
            .expect("tenant-b append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "tenant B must not replay tenant A's HttpReplayStore entry"
        );
    }

    #[test]
    fn given_admission_wos_literals_when_defined_then_aliases_substrate_canonical_export() {
        // TWREF-017: the WOS admission adapter's canonical literal table must
        // remain the same slice as `wos-events::WOS_CANONICAL_EVENT_LITERALS`.
        // After DI-001 the alias lives in trellis-admission-wos; this test guards
        // against drift through the parent trellis-server build.
        assert!(
            std::ptr::eq(
                wos_events::WOS_CANONICAL_EVENT_LITERALS.as_ptr(),
                WOS_CANONICAL_EVENT_LITERALS.as_ptr()
            ),
            "trellis-admission-wos::WOS_CANONICAL_EVENT_LITERALS must alias wos-events WOS_CANONICAL_EVENT_LITERALS (TWREF-017)"
        );
        assert_eq!(
            wos_events::WOS_CANONICAL_EVENT_LITERALS.len(),
            WOS_CANONICAL_EVENT_LITERALS.len(),
            "substrate literal slice length drift"
        );
    }

    #[tokio::test]
    async fn unknown_wos_event_type_is_rejected() {
        let app = router(test_state()).expect("router");
        let mut value: serde_json::Value = serde_json::from_slice(&append_body("idem-3")).unwrap();
        value["eventType"] = serde_json::Value::String("wos.kernel.unknown".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&value).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_wrong_event_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-wrong-type")).unwrap();
        body["eventType"] = serde_json::Value::String("wos.kernel.case_created".to_string());
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.managed-single-cell/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_missing_aggregate_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-missing-aggregate")).unwrap();
        body["payload"] = serde_json::json!({
            "aggregateId": "resp-missing-aggregate",
            "payload": { "status": "submitted" }
        });
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.managed-single-cell/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn assert_missing_policy_closure_advisory(report: &trellis_verify_wos::WosVerificationReport) {
        assert_eq!(
            report.wos_findings.len(),
            1,
            "signed-scope bundle without closure evidence should emit one advisory: {report:#?}"
        );
        let finding = &report.wos_findings[0];
        assert_eq!(finding.kind, "policy_closure_missing_for_signed_scope");
        assert_eq!(
            finding.severity,
            integrity_verify::trellis::Severity::Advisory
        );
    }

    fn test_signing_key() -> ServerSigningKey {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).unwrap())
            .expect("signing key")
    }

    fn test_state() -> TrellisServerState {
        test_state_with_signing_key(test_signing_key())
    }

    /// The documents the declared routes produce.
    pub(crate) fn documents_of_test_state() -> stack_common_http::routes::Documents {
        documents(test_state()).expect("route declarations agree")
    }

    /// Builds a `TrellisServerState` with a caller-supplied signing key.
    ///
    /// Used by cross-state byte-identity assertions to construct two independent
    /// server instances that share signing material; otherwise mirrors `test_state`.
    fn test_state_with_signing_key(signing_key: ServerSigningKey) -> TrellisServerState {
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            crate::test_adapters::adapters(),
        )
    }

    /// POSTs an append and returns the decoded receipt; the append must have been created.
    async fn post_append(app: &axum::Router, path: &str, body: Vec<u8>) -> SubstrateAppendResult {
        let response = app
            .clone()
            .oneshot(post_request(path, body))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).expect("append receipt")
    }

    /// The `sha256:<hex>` digest a receipt's `checkpointRef` names.
    fn checkpoint_digest_of(receipt: &SubstrateAppendResult) -> [u8; 32] {
        let hex_digest = receipt
            .checkpoint_ref
            .rsplit("sha256:")
            .next()
            .expect("checkpoint digest in ref");
        hex::decode(hex_digest)
            .expect("hex digest")
            .try_into()
            .expect("32-byte digest")
    }

    /// The export pinned at a receipt's checkpoint, fetched over HTTP.
    async fn pinned_zip(
        app: &axum::Router,
        scope: &str,
        receipt: &SubstrateAppendResult,
    ) -> Vec<u8> {
        let response = app
            .clone()
            .oneshot(get_request(&format!(
                "/v1/scopes/{scope}/bundles/sha256:{}",
                hex::encode(checkpoint_digest_of(receipt))
            )))
            .await
            .expect("pinned export response");
        assert_eq!(response.status(), StatusCode::OK);
        to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    fn manifest_head_checkpoint_digest(zip: &[u8]) -> [u8; 32] {
        let manifest = manifest_payload_from_bundle(zip);
        map_lookup_bytes(
            manifest.as_map().expect("manifest map"),
            "head_checkpoint_digest",
        )
        .expect("head checkpoint digest")
        .try_into()
        .expect("32-byte digest")
    }

    fn manifest_payload_from_bundle(bundle_bytes: &[u8]) -> Value {
        const COSE_SIGN1_TAG: u64 = 18;

        let entries = integrity_bundle::read_stored_zip(bundle_bytes).expect("parse bundle ZIP");
        let manifest_bytes = entries
            .iter()
            .find(|entry| {
                entry
                    .path()
                    .ends_with(trellis_export_writer::MANIFEST_MEMBER)
            })
            .map(|entry| entry.bytes())
            .expect("manifest member");
        let sign1 = integrity_cbor::decode_cbor_value(manifest_bytes).expect("manifest COSE CBOR");
        let Value::Tag(tag, inner) = sign1 else {
            panic!("manifest member must be tagged COSE_Sign1");
        };
        assert_eq!(tag, COSE_SIGN1_TAG);
        let fields = inner.as_array().expect("COSE_Sign1 array");
        let payload = fields
            .get(2)
            .and_then(Value::as_bytes)
            .expect("embedded manifest payload");
        integrity_cbor::decode_cbor_value(payload).expect("manifest payload CBOR")
    }

    fn formspec_append_body(idempotency_key: &str) -> Vec<u8> {
        formspec_append_body_with_event_type(
            idempotency_key,
            FORMSPEC_RESPONSE_SUBMITTED,
            serde_json::json!({
                "aggregateType": "formspec.response",
                "aggregateId": format!("resp-{idempotency_key}"),
                "payload": { "status": "submitted" }
            }),
        )
    }

    fn formspec_append_body_with_event_type(
        idempotency_key: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Vec<u8> {
        let body = SubstrateAppendBody {
            event_type: event_type.to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("formspec-server"),
            payload,
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "formspec-server",
            ),
            client_attestation: None,
            source_content: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn formspec_post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-formspec-tenant-id", "tenant-a")
            .header("x-formspec-workspace-id", "workspace-a")
            .header("x-formspec-environment-id", "prod")
            .header("x-formspec-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn append_body(idempotency_key: &str) -> Vec<u8> {
        let mut record = ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::CaseCreated);
        record.id = format!("prov-{idempotency_key}");
        let body = SubstrateAppendBody {
            event_type: "wos.kernel.case_created".to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("wos-server"),
            payload: serde_json::to_value(record).unwrap(),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "wos-server",
            ),
            client_attestation: None,
            source_content: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn signature_affirmation_append_body(idempotency_key: &str) -> Vec<u8> {
        signature_affirmation_append_body_with_intent(
            idempotency_key,
            "urn:wos:signing-intent:applicant-signature",
            None,
            None,
        )
    }

    fn signature_affirmation_append_body_with_intent(
        idempotency_key: &str,
        signing_intent: &str,
        profile_ref: Option<&str>,
        profile_key: Option<&str>,
    ) -> Vec<u8> {
        let mut record = ProvenanceRecord::signature_affirmation(
            &fixture_minter(),
            SignatureAffirmationInput {
                signer_id: "applicant",
                role_id: "role-applicant-signer",
                role: "applicant",
                document_id: "benefits-application",
                signing_act_id: "signing-act-server-test",
                document_ref: serde_json::json!({
                    "documentId": "benefits-application",
                    "locale": "en-US"
                }),
                document_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                presentation_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                document_hash_algorithm: "sha-256",
                source_signature_system: "formspec",
                source_signature_id: "sig-server-test",
                signed_payload_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                signed_payload_digest_algorithm: "sha-256",
                signing_intent,
                signed_at: "2026-05-16T18:31:00Z",
                identity_binding: serde_json::json!({
                    "kind": "subjectRef",
                    "ref": "applicant"
                }),
                consent_reference: serde_json::json!({
                    "textRef": "consent-v1",
                    "acceptedAt": "2026-05-16T18:30:00Z"
                }),
                signature_provider: "formspec-local",
                ceremony_id: "ceremony-server-test",
                profile_ref,
                profile_key,
                source_response_ref: "formspec://responses/resp-server-test",
                signer_authority: None,
                custody_hook_eligible: true,
                primitive_verification: serde_json::json!({
                    "status": "verified"
                }),
                verification_receipt: None,
                witnessed_signature_ref: None,
            },
        );
        record.id = format!("prov-{idempotency_key}");
        record.timestamp = "2026-05-16T18:31:00Z".to_string();
        let event_type = ProvenanceKind::SignatureAffirmation
            .canonical_event_literal()
            .expect("signature affirmation has event literal")
            .to_string();
        let body = SubstrateAppendBody {
            event_type,
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("wos-server"),
            payload: serde_json::to_value(record).unwrap(),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "wos-server",
            ),
            client_attestation: None,
            source_content: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn signature_admission_failed_append_body(idempotency_key: &str) -> Vec<u8> {
        signature_admission_failed_append_body_with_reason(
            idempotency_key,
            "method_unregistered",
            "urn:wos:signing-intent:applicant-signature",
        )
    }

    fn signature_admission_failed_append_body_with_reason(
        idempotency_key: &str,
        reason: &'static str,
        signing_intent: &'static str,
    ) -> Vec<u8> {
        let mut failure_context = serde_json::Map::new();
        failure_context.insert(
            "methodUri".to_string(),
            serde_json::Value::String("urn:formspec:sig-method:unknown@1".to_string()),
        );
        let mut record = ProvenanceRecord::signature_admission_failed(
            &fixture_minter(),
            SignatureAdmissionFailedInput {
                reason,
                response_id: "resp-rejected-server-test",
                signed_payload_digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                signature_id: "sig-rejected-server-test",
                signing_intent,
                signer_id: Some("applicant"),
                signer_authority: None,
                failure_context: Some(failure_context),
                emitted_at: "2026-05-16T18:32:00Z",
            },
        );
        record.id = format!("prov-{idempotency_key}");
        record.timestamp = "2026-05-16T18:32:00Z".to_string();
        let event_type = ProvenanceKind::SignatureAdmissionFailed
            .canonical_event_literal()
            .expect("signature admission failed has event literal")
            .to_string();
        let body = SubstrateAppendBody {
            event_type,
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("wos-server"),
            payload: serde_json::to_value(record).unwrap(),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "wos-server",
            ),
            client_attestation: None,
            source_content: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn post_request_with_wos_tenant(path: &str, body: Vec<u8>, tenant: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", tenant)
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn get_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::empty())
            .unwrap()
    }

    fn idempotency_from_body(body: &[u8]) -> String {
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        value["idempotencyKey"].as_str().unwrap().to_string()
    }

    /// Admission that bounds every scope to three events, as a family cap would.
    struct ThreeEventScopes(Arc<dyn EventAdmissionPolicy<Error = StackError>>);

    #[async_trait]
    impl EventAdmissionPolicy for ThreeEventScopes {
        type Error = StackError;

        async fn admit(
            &self,
            event: &AdmissionEvent<'_>,
        ) -> Result<trellis_server_ports::AdmittedEvent, Self::Error> {
            let mut admitted = self.0.admit(event).await?;
            admitted.max_scope_events = Some(3);
            Ok(admitted)
        }
    }

    #[tokio::test]
    async fn a_scope_refuses_appends_past_its_family_cap_under_concurrency() {
        let state = Arc::new(
            test_state().with_admission_policy(Arc::new(ThreeEventScopes(
                test_adapters::admission_policy(),
            ))),
        );
        let command = |index: usize| {
            let body: SubstrateAppendBody =
                serde_json::from_slice(&append_body(&format!("idem-cap-{index}"))).unwrap();
            append::AppendCommand {
                scope: "case_cap".to_string(),
                event_type: body.event_type.clone(),
                idempotency_key: body.idempotency_key.clone(),
                payload: body.payload.clone(),
                client_attestation: body.client_attestation.clone(),
            }
        };
        let mut racers = tokio::task::JoinSet::new();
        for index in 0..8 {
            let state = state.clone();
            let command = command(index);
            racers.spawn(async move { (index, state.append_coordinator().append(command).await) });
        }
        let mut committed = Vec::new();
        let mut refused = 0;
        while let Some(done) = racers.join_next().await {
            match done.unwrap() {
                (index, Ok(outcome)) => committed.push((index, outcome.result)),
                (_, Err(error)) => {
                    assert_eq!(error.status(), StatusCode::CONFLICT);
                    refused += 1;
                }
            }
        }
        assert_eq!((committed.len(), refused), (3, 5));
        assert_eq!(
            state
                .repository
                .list_scope(b"case_cap")
                .await
                .unwrap()
                .len(),
            3
        );
        for (index, original) in committed {
            let replay = state
                .append_coordinator()
                .append(command(index))
                .await
                .expect("a committed key replays even though the scope is full");
            assert_eq!(replay.result, original);
        }
    }

    struct CountingAdmissionPolicy {
        inner: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventAdmissionPolicy for CountingAdmissionPolicy {
        type Error = StackError;

        async fn admit(
            &self,
            event: &AdmissionEvent<'_>,
        ) -> Result<trellis_server_ports::AdmittedEvent, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.admit(event).await
        }
    }
    mod oidc_startup_tests {
        include!("oidc_startup_tests.rs");
    }

    mod auth_boundary_tests {
        include!("auth_boundary_tests.rs");
    }

    // IF034 qualification fixtures exercise the real maintained HTTP append and ZIP path.
    async fn if034_062_head_bytes(app: &axum::Router, scope: &str) -> Vec<u8> {
        let response = app
            .clone()
            .oneshot(get_request(&format!("/v1/scopes/{scope}/bundles/head")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn if034_062_actual_append_exports_catalog_originals_and_continuation() {
        let state = test_state();
        let app = router(state.clone()).unwrap();
        let scope = "case_if034_062_actual";
        let mut originals = Vec::new();
        for (key, act) in [
            ("if034-062-first", "retained-act-first"),
            ("if034-062-second", "retained-act-second"),
        ] {
            let mut body: serde_json::Value =
                serde_json::from_slice(&signature_affirmation_append_body(key)).unwrap();
            body["payload"]["data"]["signingActId"] = serde_json::json!(act);
            body["payload"]["data"]["identityBinding"] =
                serde_json::json!({"nested":[{"identity":"original"},null,true]});
            body["payload"]["data"]["consentReference"] =
                serde_json::json!({"exactText":"original consent", "nested":[1,2]});
            body["payload"]["data"]["profileRef"] = serde_json::Value::Null;
            body["payload"]["data"]
                .as_object_mut()
                .unwrap()
                .remove("profileKey");
            originals.push(integrity_cbor::json_to_dcbor_bytes(&body["payload"], &[]).unwrap());
            let response = app
                .clone()
                .oneshot(post_request(
                    &format!("/v1/scopes/{scope}/events"),
                    serde_json::to_vec(&body).unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let zip = if034_062_head_bytes(&app, scope).await;
            let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
            let catalog = entries
                .iter()
                .find(|entry| entry.path().ends_with("062-signature-affirmations.cbor"))
                .expect("actual affirmation exports must include062");
            let decoded = integrity_cbor::decode_cbor_value(catalog.bytes()).unwrap();
            let rows = decoded.as_array().unwrap();
            assert_eq!(rows.len(), originals.len());
            let events = state.repository.list_scope(scope.as_bytes()).await.unwrap();
            for (index, (row, original)) in rows.iter().zip(&originals).enumerate() {
                let row = row.as_map().unwrap();
                assert_eq!(
                    integrity_cbor::map_lookup_bytes(row, "canonical_event_hash").unwrap(),
                    events[index].canonical_event_hash().unwrap().to_vec()
                );
                let value = integrity_cbor::decode_cbor_value(original).unwrap();
                let data = integrity_cbor::map_lookup_map(value.as_map().unwrap(), "data").unwrap();
                for (source, output) in [
                    ("identityBinding", "identity_binding"),
                    ("consentReference", "consent_reference"),
                    ("profileRef", "profile_ref"),
                ] {
                    assert_eq!(
                        integrity_cbor::map_lookup_value(row, output).unwrap(),
                        integrity_cbor::map_lookup_value(data, source).unwrap()
                    );
                }
                assert!(integrity_cbor::map_lookup_optional_value(row, "profile_key").is_none());
                let hash = integrity_cbor::domain_separated_sha256(
                    trellis_types::CONTENT_DOMAIN,
                    original,
                );
                let path = format!("060-payloads/{}.bin", hex::encode(hash));
                assert_eq!(
                    entries
                        .iter()
                        .find(|entry| entry.path().ends_with(&path))
                        .expect("exact060 original")
                        .bytes(),
                    original.as_slice()
                );
            }
            for member in [
                "066-signed-acts.cbor",
                "068-signed-acts-manifest.cbor",
                "067-policy-closure.cbor",
            ] {
                assert!(
                    entries.iter().any(|entry| entry.path().ends_with(member)),
                    "prior profile member must survive"
                );
            }
            let report = trellis_verify_wos::verify_export_zip(&zip);
            assert!(
                report.substrate().structure_verified
                    && report.substrate().integrity_verified
                    && report.relying_party_valid(),
                "{report:#?}"
            );
        }
        let before = if034_062_head_bytes(&app, scope).await;
        let before_entries = integrity_bundle::read_stored_zip(&before).unwrap();
        let prior_catalog = before_entries
            .iter()
            .find(|entry| entry.path().ends_with("062-signature-affirmations.cbor"))
            .unwrap()
            .bytes()
            .to_vec();
        let prior_events = state.repository.list_scope(scope.as_bytes()).await.unwrap();
        let ordinary = app
            .clone()
            .oneshot(post_request(
                &format!("/v1/scopes/{scope}/events"),
                append_body("if034-062-later-ordinary"),
            ))
            .await
            .unwrap();
        assert_eq!(ordinary.status(), StatusCode::CREATED);
        let zip = if034_062_head_bytes(&app, scope).await;
        let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
        let catalog = entries
            .iter()
            .find(|entry| entry.path().ends_with("062-signature-affirmations.cbor"))
            .unwrap()
            .bytes();
        assert_eq!(
            catalog,
            prior_catalog.as_slice(),
            "ordinary continuation must preserve the exact prior062 rows"
        );
        let decoded = integrity_cbor::decode_cbor_value(catalog).unwrap();
        let rows = decoded.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let current = state.repository.list_scope(scope.as_bytes()).await.unwrap();
        assert_eq!(current.len(), 3);
        assert_ne!(
            event_summary(&current[2]).unwrap().event_type,
            trellis_export_profile_wos::wos_signature_affirmation_event_type()
        );
        for ((row, event), original) in rows.iter().zip(&prior_events).zip(&originals) {
            assert_eq!(
                integrity_cbor::map_lookup_bytes(row.as_map().unwrap(), "canonical_event_hash")
                    .unwrap(),
                event.canonical_event_hash().unwrap().to_vec()
            );
            let hash =
                integrity_cbor::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, original);
            let path = format!("060-payloads/{}.bin", hex::encode(hash));
            assert_eq!(
                entries
                    .iter()
                    .find(|entry| entry.path().ends_with(&path))
                    .unwrap()
                    .bytes(),
                original.as_slice(),
                "ordinary continuation must preserve exact admitted original060 bytes"
            );
        }
        let report = trellis_verify_wos::verify_export_zip(&zip);
        assert!(
            report.substrate().structure_verified
                && report.substrate().integrity_verified
                && report.relying_party_valid(),
            "{report:#?}"
        );
    }

    #[tokio::test]
    async fn if034_062_missing_act_refuses_before_native_repository_commit() {
        let state = test_state();
        let app = router(state.clone()).unwrap();
        let scope = "case_if034_062_missing_act";
        let mut body: serde_json::Value =
            serde_json::from_slice(&signature_affirmation_append_body("if034-062-missing-act"))
                .unwrap();
        body["payload"]["data"]
            .as_object_mut()
            .unwrap()
            .remove("signingActId");
        let response = app
            .oneshot(post_request(
                &format!("/v1/scopes/{scope}/events"),
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::CREATED);
        assert!(
            state
                .repository
                .list_scope(scope.as_bytes())
                .await
                .unwrap()
                .is_empty(),
            "unrepresentable062 must refuse before committing actual event"
        );
    }

    #[tokio::test]
    async fn if034_062_aggregate_refuses_before_native_repository_commit() {
        let state = test_state();
        let app = router(state.clone()).unwrap();
        let scope = "case_if034_062_large";
        let mut body: serde_json::Value =
            serde_json::from_slice(&signature_affirmation_append_body("if034-062-large")).unwrap();
        body["payload"]["data"]["identityBinding"] =
            serde_json::json!({"retainedIdentity":"x".repeat(350 * 1024)});
        let original = integrity_cbor::json_to_dcbor_bytes(&body["payload"], &[]).unwrap();
        assert!(
            2 * original.len() + 4096 < 1024 * 1024,
            "event metadata plus060 must independently fit"
        );
        assert!(
            3 * original.len() > 1024 * 1024,
            "adding copied062 identity must cross aggregate bound"
        );
        let response = app
            .oneshot(post_request(
                &format!("/v1/scopes/{scope}/events"),
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::CREATED);
        assert!(
            state
                .repository
                .list_scope(scope.as_bytes())
                .await
                .unwrap()
                .is_empty(),
            "oversized062 aggregate must refuse before committing actual event"
        );
    }
}
