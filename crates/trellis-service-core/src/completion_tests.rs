use super::*;
use crate::completion::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod postgres_support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

struct Selection {
    refuse: bool,
}
#[async_trait]
impl CompletionSelector for Selection {
    async fn select(
        &self,
        _tenant: &stack_common_http::tenant::TenantScope,
        principal: &str,
        _caller: &CompletionCallerContext<'_>,
        _scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError> {
        assert_eq!(principal, "internal-operator");
        if self.refuse {
            return Err(StackError::conflict("workflow evidence is unsettled"));
        }
        Ok(SelectedCompletion {
            selection_revision: [1; 32],
            case_ref: "case-test".into(),
            workflow_ref: "workflow-test".into(),
            workflow_status: "completed".into(),
            completed_at: crate::event_summary(prefix.last().unwrap())?.authored_at,
            impact_level: None,
            signer_labels: request
                .signing_events
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
        })
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
struct Signer {
    calls: AtomicUsize,
    corrupt: bool,
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
    let state = test_state().with_scope_authorizer(Arc::new(MappedAuthorizer));
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
            compute_context: body.compute_context,
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
        },
    )
}

#[tokio::test]
async fn completion_postgres_reopened_state_retries_exact_retained_bytes() {
    let (template, headers, tenant, request) = fixture().await;
    let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
    let pool = postgres_support::tls_pool(&cluster, 2).await;
    trellis_store_postgres_async::run_migrations(&pool)
        .await
        .unwrap();
    let repository = Arc::new(PostgresEventRepository::new(pool.clone()));
    let initial = template
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    repository.append_event(initial[0].clone()).await.unwrap();
    // The artifact service survives application state recreation, like external object storage.
    let artifacts = template.artifact_store.clone();
    let state = TrellisServerState::new(
        repository,
        test_signing_key(),
        crate::test_adapters::adapters(),
    )
    .with_scope_authorizer(Arc::new(MappedAuthorizer))
    .with_artifact_store(artifacts.clone())
    .with_bundle_index(Arc::new(crate::event_repository::PostgresBundleIndex::new(
        pool.clone(),
    )));
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
        Some(&Selection { refuse: false }),
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
    let published = state
        .bundles
        .get_by_seal(b"case_completion", 2)
        .await
        .unwrap()
        .unwrap();
    let zip = artifacts
        .get(&published.artifact_ref)
        .await
        .unwrap()
        .unwrap();
    drop(state);
    pool.close().await;

    let reopened_pool = postgres_support::tls_pool(&cluster, 2).await;
    let reopened = TrellisServerState::new(
        Arc::new(PostgresEventRepository::new(reopened_pool.clone())),
        test_signing_key(),
        crate::test_adapters::adapters(),
    )
    .with_scope_authorizer(Arc::new(MappedAuthorizer))
    .with_artifact_store(artifacts.clone())
    .with_bundle_index(Arc::new(crate::event_repository::PostgresBundleIndex::new(
        reopened_pool.clone(),
    )));
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
        Some(&Selection { refuse: false }),
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
    let publication = reopened
        .bundles
        .get_by_seal(b"case_completion", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publication.artifact_ref, published.artifact_ref);
    assert_eq!(
        artifacts
            .get(&publication.artifact_ref)
            .await
            .unwrap()
            .unwrap(),
        zip
    );
    // A different request must be refused even before any replay cache is repopulated.
    let changed_state = TrellisServerState::new(
        Arc::new(PostgresEventRepository::new(reopened_pool.clone())),
        test_signing_key(),
        crate::test_adapters::adapters(),
    )
    .with_scope_authorizer(Arc::new(MappedAuthorizer))
    .with_artifact_store(artifacts.clone())
    .with_bundle_index(Arc::new(crate::event_repository::PostgresBundleIndex::new(
        reopened_pool.clone(),
    )));
    let mut changed = request.clone();
    changed.certificate_id = "urn:test:changed-retry".into();
    let refused = seal_completion(
        &changed_state,
        &headers,
        &tenant,
        "case_completion",
        &changed,
        Some(&Selection { refuse: false }),
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
        Some(&Selection { refuse: false }),
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
        Some(&Selection { refuse: false }),
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
    let record = state
        .bundles
        .get_by_seal(b"case_completion", 2)
        .await
        .unwrap()
        .unwrap();
    let zip = state
        .artifact_store
        .get(&record.artifact_ref)
        .await
        .unwrap()
        .unwrap();
    assert!(export_bundle_cryptographically_verified(&zip));
    assert!(crate::test_adapters::adapters()
            .export_profile
            .verify(&zip)
            .profile_verified);
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
            compute_context: body.compute_context,
            client_attestation: None,
        })
        .await
        .unwrap();
    let second = *outcome.stored.canonical_event_hash().unwrap();
    request.expected_head = second;
    request.signing_events.push(second);
    seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        Some(&Selection { refuse: false }),
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
    let record = state
        .bundles
        .get_by_seal(b"case_completion", 3)
        .await
        .unwrap()
        .unwrap();
    let zip = state
        .artifact_store
        .get(&record.artifact_ref)
        .await
        .unwrap()
        .unwrap();
    let report = trellis_verify_wos::verify_export_zip(&zip);
    assert!(report.trellis.integrity_verified, "{report:?}");
    assert_eq!(report.trellis.certificates_of_completion.len(), 1);
    // Explicit fixture generation retains actual Rust-authored bytes after verification.
    if let Some(directory) = std::env::var_os("TRELLIS_COMPLETION_V2_VECTOR_DIR") {
        let directory = std::path::PathBuf::from(directory);
        assert!(directory.is_absolute());
        std::fs::create_dir(&directory).unwrap();
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
            ("expected-export.zip", zip.clone()),
        ] {
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
        let root = entries
            .iter()
            .find_map(|entry| entry.path().strip_suffix("/010-events.cbor"))
            .unwrap();
        let prefix = format!("{root}/");
        let mut members = Vec::new();
        for entry in &entries {
            let member = entry.path().strip_prefix(&prefix).unwrap();
            let path = directory.join(member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, entry.bytes()).unwrap();
            members.push(Value::Text(member.into()));
        }
        let ledger = crate::text_map(vec![
            ("root_dir", Value::Text(root.into())),
            ("members", Value::Array(members)),
        ])
        .unwrap();
        std::fs::write(
            directory.join("input-ledger-state.cbor"),
            integrity_cbor::encode_cbor_value(&ledger).unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn completion_refuses_unselected_unsettled_and_bad_operator_signature() {
    let (state, headers, tenant, request) = fixture().await;
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: true,
    };
    for selection in [
        None,
        Some(&Selection { refuse: true } as &dyn CompletionSelector),
        Some(&Selection { refuse: false } as &dyn CompletionSelector),
    ] {
        assert!(seal_completion(
            &state,
            &headers,
            &tenant,
            "case_completion",
            &request,
            selection,
            &signer
        )
        .await
        .is_err());
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

struct RevokingSelection(Arc<AtomicBool>);

struct LockingSelection {
    state: TrellisServerState,
    calls: AtomicUsize,
    change_on_call: Option<usize>,
    revoke_authority: Option<Arc<AtomicBool>>,
}

#[async_trait]
impl CompletionSelector for LockingSelection {
    async fn select(
        &self,
        tenant: &stack_common_http::tenant::TenantScope,
        principal: &str,
        caller: &CompletionCallerContext<'_>,
        scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError> {
        // An owning archive reader may contend for the same native scope.
        let _guard = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            self.state.scope_locks.lock(scope.as_bytes()),
        )
        .await
        .map_err(|_| StackError::conflict("selection ran under scope lock"))?;
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(revoked) = &self.revoke_authority {
            revoked.store(true, Ordering::SeqCst);
        }
        if self.change_on_call == Some(call) {
            let events = self.state.repository.list_scope(scope.as_bytes()).await?;
            self.state
                .repository
                .append_event(StoredEvent::new(
                    scope.as_bytes().to_vec(),
                    events.len() as u64,
                    b"concurrent census change".to_vec(),
                    b"concurrent signed bytes".to_vec(),
                ))
                .await?;
        }
        Selection { refuse: false }
            .select(tenant, principal, caller, scope, request, prefix)
            .await
    }
}

#[tokio::test]
async fn completion_selection_releases_scope_lock_on_new_and_retained_paths() {
    let (state, headers, tenant, request) = fixture().await;
    let selector = LockingSelection {
        state: state.clone(),
        calls: AtomicUsize::new(0),
        change_on_call: None,
        revoke_authority: None,
    };
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
        Some(&selector),
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(selector.calls.load(Ordering::SeqCst), 4);
    let retained = state
        .repository
        .list_scope(b"case_completion")
        .await
        .unwrap();
    let retry = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        Some(&selector),
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(first, retry);
    assert_eq!(selector.calls.load(Ordering::SeqCst), 7);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap(),
        retained
    );
}

#[tokio::test]
async fn completion_refuses_native_census_changes_during_each_unlocked_selection() {
    for change_on_call in 1..=4 {
        let (state, headers, tenant, request) = fixture().await;
        let selector = LockingSelection {
            state: state.clone(),
            calls: AtomicUsize::new(0),
            change_on_call: Some(change_on_call),
            revoke_authority: None,
        };
        let signer = Signer {
            calls: AtomicUsize::new(0),
            corrupt: false,
        };
        let error = seal_completion(
            &state,
            &headers,
            &tenant,
            "case_completion",
            &request,
            Some(&selector),
            &signer,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("native snapshot changed"),
            "{error}"
        );
        let events = state
            .repository
            .list_scope(b"case_completion")
            .await
            .unwrap();
        assert_eq!(events.len(), if change_on_call <= 2 { 2 } else { 3 });
        assert_eq!(events[0].sequence(), 0);
        if change_on_call >= 3 {
            // A confirmed append remains retained when a later disclosure check fails.
            assert!(crate::completion::certificate_html(&events[1]).is_ok());
        }
    }
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
async fn completion_rechecks_current_scope_authority_after_reacquiring_lock() {
    let (state, headers, tenant, request) = fixture().await;
    let revoked = Arc::new(AtomicBool::new(false));
    let state =
        state.with_scope_authorizer(Arc::new(CompletionRevokingAuthorizer(revoked.clone())));
    let selector = LockingSelection {
        state: state.clone(),
        calls: AtomicUsize::new(0),
        change_on_call: None,
        revoke_authority: Some(revoked.clone()),
    };
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let error = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        Some(&selector),
        &signer,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("scope permission revoked"));
    assert!(revoked.load(Ordering::SeqCst));
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

#[async_trait]
impl CompletionSelector for RevokingSelection {
    async fn select(
        &self,
        tenant: &stack_common_http::tenant::TenantScope,
        principal: &str,
        caller: &CompletionCallerContext<'_>,
        scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError> {
        if self.0.load(Ordering::SeqCst) {
            return Err(StackError::conflict("case disclosure revoked"));
        }
        Selection { refuse: false }
            .select(tenant, principal, caller, scope, request, prefix)
            .await
    }
}
struct RevisingSelection(Arc<AtomicBool>);
#[async_trait]
impl CompletionSelector for RevisingSelection {
    async fn select(
        &self,
        tenant: &stack_common_http::tenant::TenantScope,
        principal: &str,
        caller: &CompletionCallerContext<'_>,
        scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError> {
        let mut selected = Selection { refuse: false }
            .select(tenant, principal, caller, scope, request, prefix)
            .await?;
        if self.0.load(Ordering::SeqCst) {
            selected.selection_revision = [2; 32];
        }
        Ok(selected)
    }
}
struct RevokingStore {
    inner: Arc<dyn trellis_server_ports::ArtifactStore<Error = StackError>>,
    revoked: Arc<AtomicBool>,
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
        if key.ends_with(".zip") {
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
async fn completion_refuses_locator_when_only_owning_snapshot_changes_during_publication() {
    let (state, headers, tenant, request) = fixture().await;
    let changed = Arc::new(AtomicBool::new(false));
    let state = state.clone().with_artifact_store(Arc::new(RevokingStore {
        inner: state.artifact_store.clone(),
        revoked: changed.clone(),
    }));
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let error = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        Some(&RevisingSelection(changed.clone())),
        &signer,
    )
    .await
    .unwrap_err();
    assert!(changed.load(Ordering::SeqCst));
    assert!(error.to_string().contains("snapshot changed"));
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
#[tokio::test]
async fn completion_refuses_locator_when_case_disclosure_revoked_during_publication() {
    let (state, headers, tenant, request) = fixture().await;
    let revoked = Arc::new(AtomicBool::new(false));
    let state = state.clone().with_artifact_store(Arc::new(RevokingStore {
        inner: state.artifact_store.clone(),
        revoked: revoked.clone(),
    }));
    let signer = Signer {
        calls: AtomicUsize::new(0),
        corrupt: false,
    };
    let error = seal_completion(
        &state,
        &headers,
        &tenant,
        "case_completion",
        &request,
        Some(&RevokingSelection(revoked.clone())),
        &signer,
    )
    .await
    .unwrap_err();
    assert!(revoked.load(Ordering::SeqCst));
    assert!(error.to_string().contains("disclosure revoked"));
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
        Some(&Selection { refuse: false }),
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
        Some(&Selection { refuse: false }),
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
        Some(&Selection { refuse: false }),
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
        Some(&Selection { refuse: false }),
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
