use super::*;
use crate::completion::*;
use trellis_service_client::CompletionSelection;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod postgres_support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

/// The facts a product would send: one label per signing event and the last event's time.
pub(super) fn selection_for(signing_events: &[[u8; 32]], last: &StoredEvent) -> CompletionSelection {
    let at = crate::event_summary(last).unwrap().authored_at;
    CompletionSelection {
        case_ref: "case-test".into(),
        workflow_ref: "workflow-test".into(),
        workflow_status: "completed".into(),
        completed_at: (at.unix_secs, at.subsec_nanos),
        impact_level: None,
        signer_labels: signing_events
            .iter()
            .map(|hash| CompletionSignerLabel {
                signing_event: *hash,
                display_name: "Applicant <script>alert(1)</script>".into(),
                display_role: Some("applicant".into()),
            })
            .collect(),
        required_attestors: vec![CompletionAttestor {
            authority: "urn:test:operator".into(),
            authority_class: "new".into(),
            public_key: fixture_key(-2),
        }],
    }
}

fn fixture_key(label: i64) -> [u8; 32] {
    let value = integrity_cbor::decode_cbor_value(include_bytes!(
        "../../../fixtures/vectors/_keys/issuer-001.cose_key"
    ))
    .unwrap();
    value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| {
            k.as_integer()
                .is_some_and(|v| i128::from(v) == i128::from(label))
        })
        .unwrap()
        .1
        .as_bytes()
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
}
/// The principal `MappedAuthorizer` admits and the configured publisher the seal pins.
pub(super) const PUBLISHER: &str = "internal-operator";
pub(super) struct Signer {
    pub(super) calls: AtomicUsize,
    pub(super) corrupt: bool,
}
#[async_trait]
impl CompletionSigner for Signer {
    async fn sign(
        &self,
        _authority: &CompletionAttestor,
        preimage: &[u8],
    ) -> Result<[u8; 64], StackError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.corrupt {
            return Ok([0; 64]);
        }
        Ok(integrity_cose::sign_ed25519(fixture_key(-4), preimage))
    }
}
async fn fixture() -> (
    TrellisServerState,
    axum::http::HeaderMap,
    stack_common_http::tenant::TenantScope,
    CompletionRequest,
) {
    let state = test_state().with_scope_authorizer(Arc::new(MappedAuthorizer))
    .with_completion(Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false }), PUBLISHER);
    fixture_on(state).await
}
/// The same case ledger (one retained signing event) on a state the caller composed.
pub(super) async fn fixture_on(state: TrellisServerState) -> (
    TrellisServerState,
    axum::http::HeaderMap,
    stack_common_http::tenant::TenantScope,
    CompletionRequest,
) {
    let body: SubstrateAppendBody = serde_json::from_slice(&signature_affirmation_append_body(
        "completion-signing-evidence",
    ))
    .unwrap();
    let outcome = state
        .append_coordinator()
        .append(crate::append::AppendCommand {
            scope: "case_completion".into(),
            event_type: body.event_type,
            idempotency_key: body.idempotency_key,
            payload: body.payload,
            client_attestation: None,
        })
        .await
        .unwrap();
    let hash = *outcome.stored.canonical_event_hash().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("idempotency-key", "completion-manual".parse().unwrap());
    let tenant = stack_common_http::tenant::TenantScope {
        tenant: "tenant-test".into(),
        workspace: "workspace-test".into(),
        environment: "test".into(),
        cell: "cell-test".into(),
    };
    (
        state,
        headers,
        tenant,
        CompletionRequest {
            idempotency_key: "completion-manual".into(),
            certificate_id: "urn:test:certificate".into(),
            expected_head: hash,
            signing_events: vec![hash],
            selection: selection_for(&[hash], &outcome.stored),
        },
    )
}

#[tokio::test]
async fn completion_postgres_reopened_state_retries_exact_retained_bytes() {
    let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
    let pool = postgres_support::tls_pool(&cluster, 2).await;
    trellis_store_postgres_async::run_migrations(&pool)
        .await
        .unwrap();
    let composed = |pool: &sqlx::PgPool, artifacts: Option<Arc<dyn trellis_server_ports::ArtifactStore<Error = StackError>>>| {
        let state = TrellisServerState::new(
            Arc::new(PostgresEventRepository::new(pool.clone())),
            test_signing_key(),
            crate::test_adapters::adapters(),
        )
        .with_scope_authorizer(Arc::new(MappedAuthorizer))
        .with_completion(Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false }), PUBLISHER);
        match artifacts {
            Some(artifacts) => state.with_artifact_store(artifacts),
            None => state,
        }
    };
    let (state, headers, tenant, request) = fixture_on(composed(&pool, None)).await;
    // The artifact service survives application state recreation, like external object storage.
    let artifacts = state.artifact_store.clone();
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let first = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &signer,
    )
    .await
    .unwrap();
    let committed = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    assert_eq!(committed.len(), 2);
    let html = crate::completion::certificate_html(&committed[1]).unwrap();
    let head = state
        .repository
        .head_checkpoint(b"case_completion")
        .await
        .unwrap()
        .unwrap();
    let zip = crate::export::assemble(&state, b"case_completion", &head)
        .await
        .unwrap();
    drop(state);
    pool.close().await;

    let reopened_pool = postgres_support::tls_pool(&cluster, 2).await;
    let reopened = composed(&reopened_pool, Some(artifacts.clone()));
    let retry_signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: true,
    };
    let retry = seal_completion(
        &reopened,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &retry_signer,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_signer.calls.load(Ordering::SeqCst), 0);
    let rows = reopened
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    assert_eq!(rows.len(), committed.len());
    for (before, after) in committed.iter().zip(&rows) {
        assert_eq!(before.canonical_event(), after.canonical_event());
        assert_eq!(before.signed_event(), after.signed_event());
    }
    assert_eq!(crate::completion::certificate_html(&rows[1]).unwrap(), html);
    // The export is a function of the stored rows, so a reopened server assembles the same bytes.
    assert_eq!(
        crate::export::assemble(&reopened, b"case_completion", &head)
            .await
            .unwrap(),
        zip
    );
    // A different request must be refused even before any replay cache is repopulated.
    let changed_state = composed(&reopened_pool, Some(artifacts.clone()));
    let mut changed = request.clone();
    changed.certificate_id = "urn:test:changed-retry".into();
    let refused = seal_completion(
        &changed_state,
        &headers,
        &tenant,
        "case_completion",
        &changed,
        &retry_signer,
    )
    .await
    .unwrap_err();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(retry_signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        reopened
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap()
            .len(),
        2
    );
    drop(changed_state);
    drop(reopened);
    reopened_pool.close().await;
}

#[tokio::test]
async fn completion_manual_exports_exact_html_and_retries_without_signing() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let first = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &signer,
    )
    .await
    .unwrap();
    let retry = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&retry).unwrap()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let events = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    let bytes = crate::completion::certificate_html(&events[1]).unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>"));
    let head = state
        .repository
        .head_checkpoint(b"case_completion")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.tree_size, 2);
    let zip = crate::export::assemble(&state, b"case_completion", &head)
        .await
        .unwrap();
    assert!(export_bundle_cryptographically_verified(&zip));
    assert!(trellis_verify_wos::verify_export_zip(&zip).relying_party_valid());
    use integrity_verify::trellis::{
        CertificateAttestationAuthorityStatus, CertificateAuthorityRegistry,
        TrustedCertificateAuthority,
    };
    let unchecked = trellis_verify_wos::verify_export_zip(&zip);
    let extracted =
        trellis_verify_wos::certificate_html_from_export(&zip, &request.certificate_id, None)
            .unwrap();
    assert_eq!(extracted.bytes, bytes);
    assert_eq!(
        extracted.operator_authority,
        CertificateAttestationAuthorityStatus::Unchecked
    );
    assert!(
        trellis_verify_wos::certificate_html_from_export(&zip, "urn:test:missing", None).is_err()
    );
    assert_eq!(
        unchecked.trellis.certificates_of_completion[0].attestation_authority,
        CertificateAttestationAuthorityStatus::Unchecked
    );
    let mut registry = CertificateAuthorityRegistry::new();
    registry.insert(
        "urn:test:operator".into(),
        TrustedCertificateAuthority {
            public_key: fixture_key(-2),
            authority_class: "new".into(),
            allowed_purpose: COMPLETION_EVENT.into(),
            valid_from: integrity_verify::trellis::TrellisTimestamp {
                seconds: 0,
                nanos: 0,
            },
            valid_until: integrity_verify::trellis::TrellisTimestamp {
                seconds: 1_900_000_000,
                nanos: 0,
            },
        },
    );
    let verified =
        trellis_verify_wos::verify_export_zip_with_certificate_authorities(&zip, &registry);
    assert!(verified.trellis.integrity_verified, "{verified:?}");
    assert_eq!(
        verified.trellis.certificates_of_completion[0].attestation_authority,
        CertificateAttestationAuthorityStatus::Verified
    );
    let extracted = trellis_verify_wos::certificate_html_from_export(
        &zip,
        &request.certificate_id,
        Some(&registry),
    )
    .unwrap();
    assert_eq!(extracted.bytes, bytes);
    assert_eq!(
        extracted.operator_authority,
        CertificateAttestationAuthorityStatus::Verified
    );
    registry.get_mut("urn:test:operator").unwrap().public_key = [0; 32];
    let refused =
        trellis_verify_wos::verify_export_zip_with_certificate_authorities(&zip, &registry);
    assert!(!refused.trellis.integrity_verified);
    assert_eq!(
        refused.trellis.certificates_of_completion[0].attestation_authority,
        CertificateAttestationAuthorityStatus::Failed
    );
    let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
    assert!(entries
        .iter()
        .any(|entry| entry.path().contains("060-payloads/") && entry.bytes() == bytes));
    assert!(!entries.iter().any(|entry| {
        entry
            .path()
            .ends_with("065-certificates-of-completion.cbor")
    }));
}

#[tokio::test]
async fn completion_binds_two_distinct_signed_responses_in_one_certificate() {
    let (state, headers, tenant, mut request) = fixture().await;
    let mut body: SubstrateAppendBody = serde_json::from_slice(&signature_affirmation_append_body(
        "completion-second-response",
    ))
    .unwrap();
    body.payload["data"]["signedPayloadDigest"] =
        serde_json::json!("dd".repeat(32));
    body.payload["data"]["signingActId"] = serde_json::json!("signing-act-second-response");
    body.payload["data"]["sourceSignatureId"] = serde_json::json!("sig-second-response");
    body.payload["data"]["ceremonyId"] = serde_json::json!("ceremony-second-response");
    body.payload["data"]["sourceResponseRef"] =
        serde_json::json!("formspec://responses/resp-second-response");
    let outcome = state
        .append_coordinator()
        .append(crate::append::AppendCommand {
            scope: "case_completion".into(),
            event_type: body.event_type,
            idempotency_key: body.idempotency_key,
            payload: body.payload,
            client_attestation: None,
        })
        .await
        .unwrap();
    let second = *outcome.stored.canonical_event_hash().unwrap();
    request.expected_head = second;
    request.signing_events.push(second);
    request.selection = selection_for(&request.signing_events, &outcome.stored);
    seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        },
    )
    .await
    .unwrap();
    let events = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    let value = integrity_cbor::decode_cbor_value(events[2].canonical_event()).unwrap();
    let extensions = integrity_cbor::map_lookup_map(value.as_map().unwrap(), "extensions").unwrap();
    let certificate = integrity_cbor::map_lookup_map(extensions, COMPLETION_EVENT).unwrap();
    let summary = integrity_cbor::map_lookup_map(certificate, "chain_summary").unwrap();
    assert!(integrity_cbor::map_lookup_optional_value(summary, "response_ref").is_none());
    let rows = integrity_cbor::map_lookup_optional_value(summary, "signer_display")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (row, expected) in rows.iter().zip([[0xcc; 32], [0xdd; 32]]) {
        assert_eq!(
            integrity_cbor::map_lookup_bytes(row.as_map().unwrap(), "response_ref").unwrap(),
            expected
        );
    }
    let head = state
        .repository
        .head_checkpoint(b"case_completion")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.tree_size, 3);
    let zip = crate::export::assemble(&state, b"case_completion", &head)
        .await
        .unwrap();
    let report = trellis_verify_wos::verify_export_zip(&zip);
    assert!(report.trellis.integrity_verified, "{report:?}");
    assert_eq!(report.trellis.certificates_of_completion.len(), 1);
    // Explicit fixture generation retains actual Rust-authored bytes after verification.
    if let Some(directory) = std::env::var_os("TRELLIS_COMPLETION_V2_VECTOR_DIR") {
        let directory = std::path::PathBuf::from(directory);
        struct FixtureStore;
        impl trellis_core::LedgerStore for FixtureStore {
            type Error = StackError;
            fn append_event(&mut self, _event: StoredEvent) -> Result<(), StackError> {
                Ok(())
            }
        }
        let authored = integrity_cbor::encode_cbor_value(&Value::Map(
            value
                .as_map()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.as_text() != Some("author_event_hash"))
                .cloned()
                .collect(),
        ))
        .unwrap();
        let rebuilt = trellis_core::append_event(
            &mut FixtureStore,
            &CoreSigningKey::new(
                include_bytes!("../../../fixtures/vectors/_keys/issuer-001.cose_key").to_vec(),
            ),
            &trellis_core::AuthoredEvent::new(authored.clone()),
        )
        .unwrap();
        assert_eq!(rebuilt.canonical_event, events[2].canonical_event());
        assert_eq!(rebuilt.signed_event, events[2].signed_event());
        for (name, bytes) in [
            ("input-author-event-hash-preimage.cbor", authored),
            ("author-event-hash.bin", rebuilt.author_event_hash.to_vec()),
            ("sig-structure.bin", rebuilt.sig_structure),
            ("expected-event-payload.cbor", rebuilt.canonical_event),
            ("expected-event.cbor", rebuilt.signed_event),
            ("expected-append-head.cbor", rebuilt.append_head),
            (
                "input-certificate-payload.cbor",
                integrity_cbor::encode_cbor_value(&Value::Map(certificate.to_vec())).unwrap(),
            ),
            (
                "presentation-artifact.bin",
                crate::completion::certificate_html(&events[2]).unwrap(),
            ),
        ] {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        crate::export_vector::write_export_vector(&directory, &zip);
    }
}

#[tokio::test]
async fn completion_refuses_bad_vocabulary_and_bad_operator_signature_without_committing() {
    let (state, headers, tenant, request) = fixture().await;
    let corrupt = Signer {
        calls: AtomicUsize::new(0),
        corrupt: true,
    };
    let good = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let mut unsettled = request.clone();
    unsettled.selection.workflow_status = "in-progress".into();
    let mut unknown_impact = request.clone();
    unknown_impact.selection.impact_level = Some("catastrophic".into());
    for (request, signer) in [(&unsettled, &good), (&unknown_impact, &good), (&request, &corrupt)] {
        assert!(
            seal_completion(&state, &headers, &tenant, "case_completion", request, signer)
                .await
                .is_err()
        );
        assert_eq!(
            state
                .repository
                .list_scope(b"case_completion")
                .await
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn completion_bad_selection_is_a_400_before_any_effect() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let mut label_count = request.clone();
    label_count.selection.signer_labels.clear();
    let mut blank = request.clone();
    blank.selection.signer_labels[0].display_name = "   ".into();
    let mut no_case = request.clone();
    no_case.selection.case_ref = String::new();
    let mut nanos = request;
    nanos.selection.completed_at.1 = 1_000_000_000;
    for bad in [&label_count, &blank, &no_case, &nanos] {
        let error = seal_completion(&state, &headers, &tenant, "case_completion", bad, &signer)
            .await
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn completion_retry_with_a_different_selection_is_a_changed_retry() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap();
    let mut changed = request.clone();
    changed.selection.signer_labels[0].display_name = "Someone Else".into();
    // Same process: the reserved request fingerprint covers the whole body.
    let error = seal_completion(&state, &headers, &tenant, "case_completion", &changed, &signer)
        .await
        .unwrap_err();
    assert_eq!(error.status(), StatusCode::CONFLICT);
    // After a restart the replay cache is empty; the retained event refuses instead.
    let restarted = TrellisServerState::new(
        state.repository.clone(),
        test_signing_key(),
        crate::test_adapters::adapters(),
    )
    .with_scope_authorizer(Arc::new(MappedAuthorizer))
    .with_completion(Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false }), PUBLISHER)
    .with_artifact_store(state.artifact_store.clone());
    for edit in 0..4 {
        let mut other = request.clone();
        match edit {
            0 => other.selection.signer_labels[0].display_name = "Someone Else".into(),
            1 => other.selection.case_ref = "another-case".into(),
            2 => other.selection.completed_at.0 += 1,
            _ => other.selection.required_attestors[0].authority_class = "prior".into(),
        }
        let error =
            seal_completion(&restarted, &headers, &tenant, "case_completion", &other, &signer)
                .await
                .unwrap_err();
        assert_eq!(error.status(), StatusCode::CONFLICT, "edit {edit}");
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap()
            .len(),
        2
    );
}

struct MappedAuthorizer;
#[async_trait]
impl trellis_server_ports::ScopeAuthorizer for MappedAuthorizer {
    type Error = StackError;
    async fn authorize(
        &self,
        request: &trellis_server_ports::ScopeAuthorization<'_>,
    ) -> Result<trellis_server_ports::AuthorizedScope, StackError> {
        Ok(trellis_server_ports::AuthorizedScope {
            principal: "internal-operator".into(),
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        })
    }
}

/// Appends a valid foreign event the first time the certificate object is written, as a
/// concurrent writer would while the operator signs and the object is stored.
struct ForeignEventOnCertificateWrite {
    foreign: TrellisServerState,
    inner: Arc<dyn trellis_server_ports::ArtifactStore<Error = StackError>>,
    fired: AtomicBool,
}
#[async_trait]
impl trellis_server_ports::ArtifactStore for ForeignEventOnCertificateWrite {
    type Error = StackError;
    async fn put(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<trellis_server_ports::ArtifactRef, StackError> {
        self.inner.put(key, bytes).await
    }
    async fn put_immutable(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<trellis_server_ports::ArtifactRef, StackError> {
        if key.starts_with("certificates/") && !self.fired.swap(true, Ordering::SeqCst) {
            let body: SubstrateAppendBody =
                serde_json::from_slice(&append_body("concurrent-census-change")).unwrap();
            self.foreign
                .append_coordinator()
                .append(crate::append::AppendCommand {
                    scope: "case_completion".into(),
                    event_type: body.event_type,
                    idempotency_key: body.idempotency_key,
                    payload: body.payload,
                    client_attestation: None,
                })
                .await?;
        }
        self.inner.put_immutable(key, bytes).await
    }
    async fn get(
        &self,
        reference: &trellis_server_ports::ArtifactRef,
    ) -> Result<Option<Vec<u8>>, StackError> {
        self.inner.get(reference).await
    }
}

#[tokio::test]
async fn completion_refuses_a_native_census_change_between_reading_the_prefix_and_committing() {
    let (state, headers, tenant, request) = fixture().await;
    let foreign = TrellisServerState::new(
        state.repository.clone(),
        test_signing_key(),
        crate::test_adapters::adapters(),
    );
    let state = state.clone().with_artifact_store(Arc::new(ForeignEventOnCertificateWrite {
        foreign,
        inner: state.artifact_store.clone(),
        fired: AtomicBool::new(false),
    }));
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let error = seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap_err();
    assert_eq!(error.status(), StatusCode::CONFLICT);
    assert!(error.to_string().contains("head changed"), "{error}");
    let events = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    assert_eq!(events.len(), 2, "only the foreign event; the certificate is not committed");
    assert_eq!(
        events[1].idempotency_key(),
        Some(b"concurrent-census-change".as_slice())
    );
}

struct CompletionRevokingAuthorizer(Arc<AtomicBool>);

#[async_trait]
impl trellis_server_ports::ScopeAuthorizer for CompletionRevokingAuthorizer {
    type Error = StackError;

    async fn authorize(
        &self,
        request: &trellis_server_ports::ScopeAuthorization<'_>,
    ) -> Result<trellis_server_ports::AuthorizedScope, StackError> {
        if self.0.load(Ordering::SeqCst) {
            return Err(StackError::conflict("scope permission revoked"));
        }
        trellis_server_ports::ScopeAuthorizer::authorize(&MappedAuthorizer, request).await
    }
}

#[tokio::test]
async fn completion_rechecks_current_scope_authority_before_committing() {
    let (state, headers, tenant, request) = fixture().await;
    let revoked = Arc::new(AtomicBool::new(false));
    let state =
        state.with_scope_authorizer(Arc::new(CompletionRevokingAuthorizer(revoked.clone())));
    // Revoke as soon as the certificate object is written, before the commit recheck.
    let state = state.clone().with_artifact_store(Arc::new(RevokingStore {
        inner: state.artifact_store.clone(),
        revoked: revoked.clone(),
        trigger: |key| key.starts_with("certificates/"),
    }));
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let error = seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("scope permission revoked"));
    assert!(revoked.load(Ordering::SeqCst));
    assert_eq!(
        state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap()
            .len(),
        1
    );
}

struct RevokingStore {
    inner: Arc<dyn trellis_server_ports::ArtifactStore<Error = StackError>>,
    revoked: Arc<AtomicBool>,
    /// Which immutable write flips the revocation.
    trigger: fn(&str) -> bool,
}
#[async_trait]
impl trellis_server_ports::ArtifactStore for RevokingStore {
    type Error = StackError;
    async fn put(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<trellis_server_ports::ArtifactRef, StackError> {
        self.inner.put(key, bytes).await
    }
    async fn put_immutable(
        &self,
        key: &str,
        bytes: &[u8],
    ) -> Result<trellis_server_ports::ArtifactRef, StackError> {
        let result = self.inner.put_immutable(key, bytes).await?;
        if (self.trigger)(key) {
            self.revoked.store(true, Ordering::SeqCst);
        }
        Ok(result)
    }
    async fn get(
        &self,
        reference: &trellis_server_ports::ArtifactRef,
    ) -> Result<Option<Vec<u8>>, StackError> {
        self.inner.get(reference).await
    }
}
#[tokio::test]
async fn completion_refuses_stale_prefix_changed_retry_and_duplicate_certificate_id() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let mut stale = request.clone();
    stale.expected_head = [99; 32];
    assert!(seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &stale,
        &signer
    )
    .await
    .is_err());
    // A failed reservation retains the exact request fingerprint. Use a new key.
    let mut headers = headers;
    let mut request = request;
    request.idempotency_key = "completion-other".into();
    headers.insert("idempotency-key", request.idempotency_key.parse().unwrap());
    seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &signer,
    )
    .await
    .unwrap();
    let mut changed = request.clone();
    changed.certificate_id = "urn:test:changed".into();
    assert!(seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &changed,
        &signer
    )
    .await
    .is_err());
    let events = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    let mut collision = request;
    collision.idempotency_key = "completion-collision".into();
    collision.expected_head = *events.last().unwrap().canonical_event_hash().unwrap();
    headers.insert(
        "idempotency-key",
        collision.idempotency_key.parse().unwrap(),
    );
    assert!(seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &collision,
        &signer
    )
    .await
    .is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn completion_native_record_binder_requires_exact_one_to_one_census() {
    let (state, _, _, _) = fixture().await;
    let events = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    let event_type = crate::event_summary(&events[0]).unwrap().event_type;
    let canonical = integrity_cbor::decode_cbor_value(events[0].canonical_event()).unwrap();
    let reference =
        integrity_cbor::map_lookup_map(canonical.as_map().unwrap(), "payload_ref").unwrap();
    let payload = integrity_cbor::map_lookup_bytes(reference, "ciphertext").unwrap();
    let vocabulary = vec![event_type.clone()];
    let exact = trellis_cddl::CompletionRecord {
        event_type: event_type.clone(),
        payload: payload.clone(),
    };
    assert_eq!(
        trellis_cddl::completion_record_bindings(&events, b"case_completion", &[exact], &vocabulary).unwrap(),
        vec![*events[0].canonical_event_hash().unwrap()]
    );
    assert!(trellis_cddl::completion_record_bindings(&events, b"case_completion", &[], &vocabulary).is_err());
    assert!(trellis_cddl::completion_record_bindings(
        &events,
        b"case_completion",
        &[trellis_cddl::CompletionRecord {
            event_type,
            payload: b"{}".to_vec()
        }],
        &vocabulary
    )
    .is_err());
    let duplicate = || trellis_cddl::CompletionRecord {
        event_type: vocabulary[0].clone(),
        payload: payload.clone(),
    };
    assert!(trellis_cddl::completion_record_bindings(&events, b"case_completion", &[duplicate(), duplicate()], &vocabulary).is_err());
}

fn completion_post(request: &CompletionRequest) -> axum::http::Request<axum::body::Body> {
    post_request(
        "/v1/scopes/case_completion/completion",
        serde_json::to_vec(request).unwrap(),
    )
}

#[tokio::test]
async fn completion_route_commits_one_event_and_ignores_the_retired_person_header() {
    use tower::ServiceExt;
    let (state, _, _, request) = fixture().await;
    let state = state.with_completion(
        Arc::new(Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        }),
        PUBLISHER,
    );
    let app = router(state.clone()).unwrap();
    let mut with_header = completion_post(&request);
    with_header.headers_mut().insert(
        "x-stack-completion-caller-authorization",
        "Bearer retired-person-credential".parse().unwrap(),
    );
    // The header is never read: the request succeeds exactly as without it.
    let response = app.clone().oneshot(with_header).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap()
            .len(),
        2
    );
    let mut bad = request;
    bad.idempotency_key = "completion-bad".into();
    bad.selection.signer_labels.clear();
    let response = app.oneshot(completion_post(&bad)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn completion_route_without_a_signer_is_unavailable() {
    use tower::ServiceExt;
    let (_, _, _, request) = fixture().await;
    let state = test_state().with_scope_authorizer(Arc::new(MappedAuthorizer));
    let response = router(state)
        .unwrap()
        .oneshot(completion_post(&request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn completion_route_body_limit_admits_the_worst_case_selection_and_no_more() {
    use tower::ServiceExt;
    let (state, _, _, mut request) = fixture().await;
    // 64 labels with two maximal text fields of control characters, which JSON escapes
    // to six bytes each: the largest body the validator admits.
    let hashes: Vec<[u8; 32]> = (0..64u8).map(|i| [i; 32]).collect();
    request.signing_events = hashes.clone();
    request.selection.signer_labels = hashes
        .iter()
        .map(|hash| CompletionSignerLabel {
            signing_event: *hash,
            display_name: "\u{1}".repeat(1024),
            display_role: Some("\u{1}".repeat(1024)),
        })
        .collect();
    request.selection.required_attestors = (0..8)
        .map(|i| CompletionAttestor {
            authority: format!("{i}{}", "\u{1}".repeat(1023)),
            authority_class: "new".into(),
            public_key: [i as u8; 32],
        })
        .collect();
    request.selection.case_ref = "\u{1}".repeat(1024);
    request.selection.workflow_ref = "\u{1}".repeat(1024);
    request.selection.impact_level = Some("\u{1}".repeat(1024));
    request.certificate_id = "\u{1}".repeat(1024);
    request.validate().unwrap();
    let size = serde_json::to_vec(&request).unwrap().len();
    assert!(size < 1024 * 1024 && size > 800 * 1024, "{size}");
    let app = router(state.with_completion(
        Arc::new(Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        }),
        PUBLISHER,
    ))
    .unwrap();
    // Admitted by the limit; refused later because the head is not this ledger's.
    let response = app.clone().oneshot(completion_post(&request)).await.unwrap();
    assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let oversized = post_request(
        "/v1/scopes/case_completion/completion",
        format!(r#"{{"idempotencyKey":"oversized","pad":"{}"}}"#, "x".repeat(1024 * 1024)).into_bytes(),
    );
    let response = app.oneshot(oversized).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

use trellis_service_client::{AppendReconciliation, AppendReconciliationRequest};

fn seal_lookup(request: &CompletionRequest) -> AppendReconciliationRequest {
    AppendReconciliationRequest::for_completion(&request.idempotency_key, &request.certificate_id)
        .unwrap()
}

#[tokio::test]
async fn completion_reconcile_by_certificate_id_is_absent_then_committed_without_effects() {
    let (mut state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let lookup = seal_lookup(&request);
    let before = state.repository.list_scope(b"case_completion").await.unwrap();
    let head = format!(
        "sha256:{}",
        hex::encode(before.last().unwrap().canonical_event_hash().unwrap())
    );
    assert_eq!(
        crate::reconciliation::reconcile(&state, "case_completion", &lookup).await,
        AppendReconciliation::Absent {
            event_count: 1,
            last_event_hash: Some(head)
        }
    );
    let sealed = seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap();
    let committed = state.repository.list_scope(b"case_completion").await.unwrap();
    // From here the artifact store refuses every write: reconcile must never write.
    state.artifact_store = Arc::new(super::reconciliation_tests::ReadOnlyArtifacts(
        state.artifact_store.clone(),
    ));
    assert_eq!(
        crate::reconciliation::reconcile(&state, "case_completion", &lookup).await,
        AppendReconciliation::Committed { receipt: sealed }
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.repository.list_scope(b"case_completion").await.unwrap(),
        committed
    );
}

#[tokio::test]
async fn completion_reconcile_same_key_other_certificate_or_event_type_is_a_conflict() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap();
    let other_certificate = AppendReconciliationRequest::for_completion(
        &request.idempotency_key,
        "urn:test:another-certificate",
    )
    .unwrap();
    assert_eq!(
        crate::reconciliation::reconcile(&state, "case_completion", &other_certificate).await,
        AppendReconciliation::Conflict
    );
    // The key of the signature-affirmation evidence event holds another event type.
    let other_type =
        AppendReconciliationRequest::for_completion("completion-signing-evidence", "urn:test:certificate")
            .unwrap();
    assert_eq!(
        crate::reconciliation::reconcile(&state, "case_completion", &other_type).await,
        AppendReconciliation::Conflict
    );
}

#[tokio::test]
async fn completion_reconcile_route_takes_the_certificate_id_identity() {
    use tower::ServiceExt;
    let (state, headers, tenant, request) = fixture().await;
    seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        &Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        },
    )
    .await
    .unwrap();
    let lookup = serde_json::to_vec(&seal_lookup(&request)).unwrap();
    let response = router(state.clone())
        .unwrap()
        .oneshot(post_request(
            "/v1/scopes/case_completion/events/reconcile",
            lookup,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["status"], "committed");
    assert!(
        body["receipt"]["checkpointRef"]
            .as_str()
            .unwrap()
            .starts_with("trellis://case_completion/checkpoints/sha256:")
    );
    // A completion lookup that names a content hash is not a valid identity.
    let both = serde_json::json!({"eventType": COMPLETION_EVENT, "idempotencyKey": "k",
        "contentHash": vec![0u8; 32], "certificateId": "c"});
    let response = router(state)
        .unwrap()
        .oneshot(post_request(
            "/v1/scopes/case_completion/events/reconcile",
            serde_json::to_vec(&both).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_the_configured_publisher_may_seal() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let other = state.clone().with_completion(
        Arc::new(Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        }),
        "another-principal",
    );
    let error = seal_completion(&other, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap_err();
    assert_eq!(error.status(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "nothing was signed");
    // Refused before anything was reserved, so the real publisher still seals the same request.
    seal_completion(&state, &headers, &tenant, "case_completion", &request, &signer)
        .await
        .unwrap();
}

/// The route answer as `(status, title)`: refusals are pinned by code, not just "an error".
async fn seal_answer(app: &axum::Router, request: &CompletionRequest) -> (StatusCode, String) {
    use tower::ServiceExt;
    let response = app.clone().oneshot(completion_post(request)).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let title = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|body| body["title"].as_str().map(str::to_owned))
        .unwrap_or_default();
    (status, title)
}

#[tokio::test]
async fn seal_refuses_signing_events_that_are_not_this_ledgers_signatures() {
    let (state, _, _, request) = fixture().await;
    // A later event that is not a signature affirmation becomes the head the caller names.
    let body: SubstrateAppendBody = serde_json::from_slice(&append_body("not-a-signature")).unwrap();
    let outcome = state
        .append_coordinator()
        .append(crate::append::AppendCommand {
            scope: "case_completion".into(),
            event_type: body.event_type,
            idempotency_key: body.idempotency_key,
            payload: body.payload,
            client_attestation: None,
        })
        .await
        .unwrap();
    let plain = *outcome.stored.canonical_event_hash().unwrap();
    let mut forged = request.clone();
    forged.expected_head = plain;
    forged.signing_events = vec![plain];
    forged.selection = selection_for(&[plain], &outcome.stored);
    let signer = Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false });
    let app = router(state.clone().with_completion(signer.clone(), PUBLISHER)).unwrap();
    let (status, title) = seal_answer(&app, &forged).await;
    assert_eq!(
        (status, title.as_str()),
        (StatusCode::CONFLICT, "completion signing evidence unreadable or unqualified")
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "the operator key attested nothing");
    assert_eq!(state.repository.list_scope(b"case_completion").await.unwrap().len(), 2);
}

#[tokio::test]
async fn seal_refuses_a_completion_that_predates_its_signatures() {
    let (state, _, _, mut request) = fixture().await;
    request.selection.completed_at.0 -= 1_000;
    let signer = Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false });
    let app = router(state.clone().with_completion(signer.clone(), PUBLISHER)).unwrap();
    let (status, title) = seal_answer(&app, &request).await;
    assert_eq!(
        (status, title.as_str()),
        (StatusCode::CONFLICT, "completion certificate evidence invalid")
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.repository.list_scope(b"case_completion").await.unwrap().len(), 1);
}

#[tokio::test]
async fn seal_refuses_an_unknown_status_or_impact_vocabulary_as_a_bad_request() {
    let (state, _, _, request) = fixture().await;
    let signer = Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false });
    let app = router(state.clone().with_completion(signer.clone(), PUBLISHER)).unwrap();
    let mut unsettled = request.clone();
    unsettled.selection.workflow_status = "in-progress".into();
    let mut unknown_impact = request;
    unknown_impact.selection.impact_level = Some("catastrophic".into());
    for refused in [unsettled, unknown_impact] {
        let (status, title) = seal_answer(&app, &refused).await;
        assert_eq!(
            (status, title.as_str()),
            (StatusCode::BAD_REQUEST, "completion selection vocabulary refused")
        );
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.repository.list_scope(b"case_completion").await.unwrap().len(), 1);
}

/// Append and Read admit different principals for one caller: the seal cannot tell whose it is.
struct SplitAuthorizer;
#[async_trait]
impl trellis_server_ports::ScopeAuthorizer for SplitAuthorizer {
    type Error = StackError;
    async fn authorize(
        &self,
        request: &trellis_server_ports::ScopeAuthorization<'_>,
    ) -> Result<trellis_server_ports::AuthorizedScope, StackError> {
        Ok(trellis_server_ports::AuthorizedScope {
            principal: match request.action {
                trellis_server_ports::ScopeAction::Append => PUBLISHER.into(),
                _ => "another-principal".into(),
            },
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        })
    }
}

#[tokio::test]
async fn seal_is_a_conflict_when_append_and_read_admit_different_principals() {
    let (state, _, _, request) = fixture().await;
    let signer = Arc::new(Signer { calls: AtomicUsize::new(0), corrupt: false });
    let split = state.with_scope_authorizer(Arc::new(SplitAuthorizer)).with_completion(signer.clone(), PUBLISHER);
    let (status, title) = seal_answer(&router(split).unwrap(), &request).await;
    assert_eq!(
        (status, title.as_str()),
        (StatusCode::CONFLICT, "completion permissions admit different principals")
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}
