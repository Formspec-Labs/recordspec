// Neutral composition regressions; these mocks do not qualify Source cryptography.
// Rust guideline compliant 2026-02-21
use stack_common_typeid::testing::fixture_minter;
use super::*;
use crate::source_content::*;
use serde_json::json;

struct NeutralPorts {
    final_prefix: bool,
    reads: AtomicUsize,
    structural_calls: AtomicUsize,
}
#[async_trait]
impl SourceContentSelectionResolver for NeutralPorts {
    async fn select(
        &self,
        _request: &SourceContentSelectionRequest<'_>,
    ) -> Result<SourceContentSelection, StackError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(StackError::new(
            stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
            StatusCode::FORBIDDEN,
            "current owning human permission revoked",
        ))
    }
}
#[async_trait]
impl SourceContentContributor for NeutralPorts {
    async fn read(
        &self,
        _request: &SourceContentRequest<'_>,
    ) -> Result<PreparedSourceContentBatchV1, StackError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(StackError::unavailable(
            "neutral content deliberately unavailable",
        ))
    }
}
impl SourceContentFinalPrefixGuard for NeutralPorts {
    fn classify(
        &self,
        _scope: &[u8],
        _events: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError> {
        Ok(if self.final_prefix {
            SourceContentPrefixClass::FinalCloseout {
                reserved_closeout_record_id: "neutral-record".into(),
                native_policy_hash: [17; 32],
            }
        } else {
            SourceContentPrefixClass::Ordinary
        })
    }
    fn classify_append(
        &self,
        scope: &[u8],
        _body: &SubstrateAppendBody,
        prefix: &[StoredEvent],
    ) -> Result<SourceContentPrefixClass, StackError> {
        self.classify(scope, prefix)
    }
}
impl StructuralSourcePublicationVerifier for NeutralPorts {
    fn verify(
        &self,
        zip: &[u8],
    ) -> Result<trellis_verify_wos::SourceContentPublicationReport, StackError> {
        self.structural_calls.fetch_add(1, Ordering::SeqCst);
        Ok(trellis_verify_wos::verify_source_content_publication(
            zip, None,
        ))
    }
}
fn selected(final_prefix: bool) -> (SourceContentComposition, Arc<NeutralPorts>) {
    let ports = Arc::new(NeutralPorts {
        final_prefix,
        reads: AtomicUsize::new(0),
        structural_calls: AtomicUsize::new(0),
    });
    (
        SourceContentComposition {
            selection_resolver: ports.clone(),
            contributor: ports.clone(),
            final_prefix_guard: ports.clone(),
            structural: ports.clone(),
        },
        ports,
    )
}
fn command(body: &[u8]) -> append::AppendCommand {
    let body: SubstrateAppendBody = serde_json::from_slice(body).unwrap();
    append::AppendCommand {
        scope: "case_123".into(),
        event_type: body.event_type,
        idempotency_key: body.idempotency_key,
        payload: body.payload,
        compute_context: append::default_public_compute_context(),
        client_attestation: None,
    }
}

#[tokio::test]
async fn source_content_final_guard_refuses_plain_append_before_repository_write() {
    let (composition, ports) = selected(true);
    let state = test_state().with_source_content(composition);
    let error = state
        .append_coordinator()
        .append(command(&append_body("source-final-guard")))
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "final closeout requires committed Source content"
    );
    assert!(
        state
            .repository
            .list_scope(b"case_123")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(ports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_content_final_guard_precedes_retained_seal_shortcut() {
    let state = test_state();
    state
        .append_coordinator()
        .append(command(&append_body("source-old-prefix")))
        .await
        .unwrap();
    let events = state.repository.list_scope(b"case_123").await.unwrap();
    let (composition, ports) = selected(true);
    let state = state.with_source_content(composition);
    let error = publish_bundle(
        &state,
        b"case_123",
        &events,
        false,
        &append::default_public_compute_context(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.title(),
        "final closeout requires committed Source content"
    );
    assert_eq!(ports.reads.load(Ordering::SeqCst), 0);
    let response = router(state)
        .unwrap()
        .oneshot(get_request("/v1/scopes/case_123/bundles/head"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_content_ordinary_publication_keeps_prior_profile_gate_and_never_reads_contributor()
{
    let (composition, ports) = selected(false);
    let state = test_state()
        .with_source_content(composition)
        .with_profile_export_verifier(Arc::new(|_| false));
    let error = state
        .append_coordinator()
        .append(command(&signature_affirmation_append_body(
            "source-ordinary-gate",
        )))
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "published export bundle failed WOS/Formspec profile verification"
    );
    assert_eq!(ports.reads.load(Ordering::SeqCst), 0);
    assert_eq!(ports.structural_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn source_content_locator_is_optional_closed_and_does_not_grant_authority() {
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(preparation_key(&headers).unwrap(), None);
    headers.insert(
        PREPARATION_KEY_HEADER,
        "opaque-preparation-key".parse().unwrap(),
    );
    assert_eq!(
        preparation_key(&headers).unwrap(),
        Some("opaque-preparation-key")
    );
    headers.append(PREPARATION_KEY_HEADER, "other-key".parse().unwrap());
    assert!(preparation_key(&headers).is_err());
    headers.remove(PREPARATION_KEY_HEADER);
    headers.insert(PREPARATION_KEY_HEADER, " ".parse().unwrap());
    assert!(preparation_key(&headers).is_err());
}

fn neutral_native_body(key: &str, event: &str) -> SubstrateAppendBody {
    let mut original = wos_events::ProvenanceRecord::state_entered(&fixture_minter(), "Neutral");
    original.timestamp = "2026-10-09T14:00:00.123Z".into();
    original.definition_version = Some("1.0.0".into());
    original.audit_layer = Some("facts".into());
    original.event = Some(event.into());
    original.data = Some(json!({"closed":true}));
    let native = wos_events::NativeProvenanceEvent::from_record(&original).unwrap();
    SubstrateAppendBody {
        event_type: wos_events::WOS_NATIVE_PROVENANCE_EVENT_LITERAL.into(),
        idempotency_key: key.into(),
        actor: trellis_service_client::AppendActor::service("wos-server"),
        payload: native.payload().clone(),
        compute_context: trellis_service_client::ComputeContext::no_delegated_compute("wos-server"),
        client_attestation: None,
    }
}
fn real_guard() -> ConfiguredNativeCloseoutGuard {
    let kind = serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap();
    let rule = serde_json::from_value(json!({"recordKind":kind,"event":"neutral.closeout",
        "tests":[{"test":"equals","pointer":"/data/closed","value":true}]}))
    .unwrap();
    ConfiguredNativeCloseoutGuard::new([17; 32], rule).unwrap()
}

#[tokio::test]
async fn source_content_real_native_guard_requires_one_closeout_last_without_case_scope_alias() {
    let state = test_state();
    let body = neutral_native_body("real-native-closeout", "neutral.closeout");
    let mut cmd = command(&serde_json::to_vec(&body).unwrap());
    cmd.scope = "distinct-ledger-namespace".into();
    state.append_coordinator().append(cmd).await.unwrap();
    let mut events = state
        .repository
        .list_scope(b"distinct-ledger-namespace")
        .await
        .unwrap();
    let guard = real_guard();
    assert!(matches!(
        guard
            .classify(b"distinct-ledger-namespace", &events)
            .unwrap(),
        SourceContentPrefixClass::FinalCloseout { .. }
    ));
    let duplicate = events[0].clone();
    events.push(duplicate);
    assert!(
        guard
            .classify(b"distinct-ledger-namespace", &events)
            .is_err()
    );
    events.pop();
    let ordinary = neutral_native_body("real-native-after", "neutral.other");
    let mut cmd = command(&serde_json::to_vec(&ordinary).unwrap());
    cmd.scope = "distinct-ledger-namespace".into();
    state.append_coordinator().append(cmd).await.unwrap();
    let after = state
        .repository
        .list_scope(b"distinct-ledger-namespace")
        .await
        .unwrap();
    assert!(
        guard
            .classify(b"distinct-ledger-namespace", &after)
            .is_err()
    );
}

#[tokio::test]
async fn source_content_locatorless_cached_append_is_refused_before_http_replay() {
    use tower::ServiceExt;
    let state = test_state();
    let payload = append_body("source-preexisting-http-cache");
    let app = router(state.clone()).unwrap();
    let first = app
        .oneshot(post_request("/v1/scopes/case_123/events", payload.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let (composition, ports) = selected(true);
    let app = router(state.with_source_content(composition)).unwrap();
    let second = app
        .oneshot(post_request("/v1/scopes/case_123/events", payload))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        second
            .headers()
            .get(stack_common_http::idempotency::IDEMPOTENCY_REPLAY_HEADER)
            .is_none()
    );
    assert_eq!(ports.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_content_revoked_owning_selection_blocks_cached_opaque_append_response() {
    use tower::ServiceExt;
    let state = test_state();
    let payload = append_body("source-revoked-http-cache");
    let first = router(state.clone())
        .unwrap()
        .oneshot(post_request("/v1/scopes/case_123/events", payload.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let (composition, ports) = selected(false);
    let mut retry = post_request("/v1/scopes/case_123/events", payload);
    retry.headers_mut().insert(
        PREPARATION_KEY_HEADER,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap(),
    );
    retry.headers_mut().insert(
        trellis_service_client::COMPLETION_CALLER_AUTHORIZATION_HEADER,
        "Bearer neutral-person".parse().unwrap(),
    );
    let response = router(state.with_source_content(composition))
        .unwrap()
        .oneshot(retry)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .get(stack_common_http::idempotency::IDEMPOTENCY_REPLAY_HEADER)
            .is_none()
    );
    assert_eq!(ports.reads.load(Ordering::SeqCst), 1);
}

fn neutral_map(rows: Vec<(&str, Value)>) -> Value {
    Value::Map(
        rows.into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn neutral_encoded(value: &Value) -> Vec<u8> {
    integrity_cbor::encode_canonical_cbor_value(value).unwrap()
}
struct CommittedOriginal {
    batch: PreparedSourceContentBatchV1,
    reads: AtomicUsize,
    lock_wait: Option<(Arc<crate::artifacts::ScopeLocks>, Arc<LockWaitAuthority>)>,
}
#[async_trait]
impl SourceContentContributor for CommittedOriginal {
    async fn read(
        &self,
        request: &SourceContentRequest<'_>,
    ) -> Result<PreparedSourceContentBatchV1, StackError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some((locks, authority)) = &self.lock_wait {
            let guard = locks.lock(request.scope).await;
            let authority = authority.clone();
            tokio::spawn(async move {
                authority.before_lock.notified().await;
                authority.revoked.store(true, Ordering::SeqCst);
                drop(guard);
            });
        }
        Ok(self.batch.clone())
    }
}
// This authority changes only after the pre-lock check, while the append waits.
struct LockWaitAuthority {
    calls: AtomicUsize,
    revoked: std::sync::atomic::AtomicBool,
    before_lock: tokio::sync::Notify,
}
#[async_trait]
impl trellis_server_ports::ScopeAuthorizer for LockWaitAuthority {
    type Error = StackError;
    async fn authorize(
        &self,
        request: &trellis_server_ports::ScopeAuthorization<'_>,
    ) -> Result<trellis_server_ports::AuthorizedScope, StackError> {
        let revoked = self.revoked.load(Ordering::SeqCst);
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.before_lock.notify_one();
        }
        if revoked {
            return Err(StackError::conflict(
                "neutral Append permission revoked during lock wait",
            ));
        }
        Ok(trellis_server_ports::AuthorizedScope {
            principal: request.actor.into(),
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        })
    }
}

// Real neutral encryption and canonical catalogs exercise publication plumbing.
// These fixtures confer no Source signing authority or independent-reader readiness.
async fn committed_original_fixture() -> (
    TrellisServerState,
    SubstrateAppendBody,
    SourceContentSelection,
    PreparedSourceContentBatchV1,
) {
    use integrity_cbor::{domain_separated_sha256, sha256_bytes};
    use integrity_hpke::external_attachment::{
        AttachmentContext, ProtectionLimits, Recipient, protect_external_attachment,
    };
    let state = test_state();
    let mut intake_record =
        wos_events::ProvenanceRecord::blank(&fixture_minter(), wos_events::ProvenanceKind::IntakeAccepted);
    intake_record.timestamp = "2026-10-09T14:00:00.123Z".into();
    intake_record.definition_version = Some("1.0.0".into());
    intake_record.event = Some("wos.kernel.intake_accepted".into());
    // Reuse the maintained minted UUIDv7 tail for a syntactically valid neutral
    // case TypeID, independent of the ledger namespace used by this test.
    let case_id = format!(
        "neutral_case_{}",
        intake_record.id.rsplit('_').next().unwrap()
    );
    intake_record.outputs = vec![case_id.clone()];
    intake_record.data = Some(
        json!({"caseRef":case_id,"intakeId":"neutral-handoff","caseIntent":"attachToExistingCase","caseDisposition":"attachToExistingCase"}),
    );
    let intake_context = wos_events::CustodyAppendContext {
        event_type_prefix: "wos".into(),
        case_id: Some(case_id.clone()),
        max_inline_record_bytes: None,
        workflow_ref: Some("urn:neutral:workflow".into()),
    };
    let intake_metadata = intake_context
        .metadata_for_provenance_record("neutral-process", 0, &intake_record)
        .unwrap();
    let intake_input = wos_events::CustodyAppendInput::from_provenance_record(
        &intake_record,
        &intake_context,
        intake_metadata,
    )
    .unwrap();
    let mut intake_body = neutral_native_body("neutral-original", "neutral.other");
    intake_body.event_type = intake_input.event_type.clone();
    intake_body.payload = intake_input.record_json_view().unwrap();
    state
        .append_coordinator()
        .append(command(&serde_json::to_vec(&intake_body).unwrap()))
        .await
        .unwrap();
    let prefix = state.repository.list_scope(b"case_123").await.unwrap();
    let occurrence_hash = event_hash(b"case_123", &prefix[0]).unwrap();
    let closeout = neutral_native_body("neutral-source-closeout", "neutral.closeout");
    let original_record: wos_events::ProvenanceRecord = serde_json::from_value(
        wos_events::NativeProvenanceEvent::from_json(&closeout.payload)
            .unwrap()
            .record()
            .clone(),
    )
    .unwrap();
    let context = wos_events::CustodyAppendContext {
        event_type_prefix: "wos".into(),
        case_id: Some(case_id.clone()),
        max_inline_record_bytes: None,
        workflow_ref: Some("urn:neutral:workflow".into()),
    };
    let metadata = context
        .metadata_for_provenance_record("neutral-process", 1, &original_record)
        .unwrap();
    let input = wos_events::CustodyAppendInput::from_provenance_record(
        &original_record,
        &context,
        metadata,
    )
    .unwrap();
    let identity = SourceContentIdentityV1 {
        case_ledger_id: case_id.clone(),
        process_id: "neutral-process".into(),
        native_prefix_digest:
            trellis_types::completion_selection::completion_selection_prefix_digest(
                b"case_123",
                &prefix,
            )
            .unwrap(),
        reserved_closeout_record_id: input.record_id.clone(),
        reserved_native_closeout_record_sha256: sha256_bytes(input.record_bytes()),
        provider_selection_hash: [3; 32],
        native_policy_hash: [17; 32],
        recipient_policy_hash: [7; 32],
        recipient_set_sha256: [9; 32],
        workflow_url: "urn:neutral:workflow".into(),
        workflow_version: "1.0.0".into(),
        tenant_id: "tenant-a".into(),
        workspace_id: "workspace-a".into(),
        environment_id: "prod".into(),
        cell_id: "cell-a".into(),
        source_id: "neutral-source".into(),
        service_binding_id: "neutral-binding".into(),
    };
    let original =
        br#"{"id":"neutral-response","data":{"original":"complete"},"authoredSignatures":[]}"#;
    let original_sha = sha256_bytes(original);
    let context_key = b"neutral-source-response-context";
    let public_key: [u8; 32] =
        hex::decode("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13")
            .unwrap()
            .try_into()
            .unwrap();
    let protected = protect_external_attachment(
        &integrity_seam::OsSecureRandom,
        AttachmentContext {
            idempotency_key: context_key,
            original_sha256: original_sha,
            original_byte_length: original.len() as u64,
        },
        original,
        &[Recipient {
            id: b"neutral-reader",
            public_key,
        }],
        ProtectionLimits {
            original_bytes: 1024,
            recipients: 1,
            recipient_id_bytes: 256,
        },
    )
    .unwrap();
    let entries = protected
        .key_bag
        .into_iter()
        .map(|wrap| {
            neutral_map(vec![
                ("recipient", Value::Bytes(wrap.recipient)),
                ("suite", Value::Integer(wrap.suite.into())),
                (
                    "ephemeral_pubkey",
                    Value::Bytes(wrap.ephemeral_pubkey.to_vec()),
                ),
                ("wrapped_dek", Value::Bytes(wrap.wrapped_dek)),
            ])
        })
        .collect();
    let response_hash = format!("sha256:{}", hex::encode(original_sha));
    let mut locator_rows = vec![
        ("version", Value::Integer(1.into())),
        ("native_event_hash", Value::Bytes(occurrence_hash.to_vec())),
        (
            "response_ref",
            Value::Text("urn:formspec:response:neutral-response".into()),
        ),
        ("response_id", Value::Text("neutral-response".into())),
        ("response_hash", Value::Text(response_hash.clone())),
        (
            "original_byte_length",
            Value::Integer((original.len() as u64).into()),
        ),
        (
            "content_hash",
            Value::Bytes(
                domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &protected.ciphertext)
                    .to_vec(),
            ),
        ),
        ("context_key", Value::Bytes(context_key.to_vec())),
        ("source_binding_hash", Value::Bytes(vec![4; 32])),
        ("publication_hash", Value::Bytes(vec![5; 32])),
        ("public_policy_hash", Value::Bytes(vec![6; 32])),
        ("recipient_policy_hash", Value::Bytes(vec![7; 32])),
        ("nonce", Value::Bytes(protected.nonce.to_vec())),
        (
            "key_bag",
            neutral_map(vec![("entries", Value::Array(entries))]),
        ),
    ];
    let protected_record = neutral_encoded(&neutral_map(vec![
        ("locator", neutral_map(locator_rows.clone())),
        ("ciphertext", Value::Bytes(protected.ciphertext)),
    ]));
    let record_sha256 = sha256_bytes(&protected_record);
    locator_rows.push(("record_hash", Value::Bytes(record_sha256.to_vec())));
    let locator = neutral_map(locator_rows);
    let catalog = neutral_encoded(&Value::Array(vec![neutral_map(vec![
        ("intake_event_hash", Value::Bytes(occurrence_hash.to_vec())),
        (
            "handoff",
            neutral_map(vec![
                ("handoffId", Value::Text("neutral-handoff".into())),
                ("initiationMode", Value::Text("workflowInitiated".into())),
                ("caseRef", Value::Text(case_id.clone())),
                (
                    "definitionRef",
                    neutral_map(vec![
                        ("url", Value::Text("urn:neutral:form".into())),
                        ("version", Value::Text("1".into())),
                    ]),
                ),
                (
                    "responseRef",
                    Value::Text("urn:formspec:response:neutral-response".into()),
                ),
                ("responseHash", Value::Text(response_hash)),
                ("validationReportRef", Value::Text("neutral-report".into())),
                ("ledgerHeadRef", Value::Text("neutral-head".into())),
            ]),
        ),
        ("protected_response", locator.clone()),
    ])]));
    let member_content_hash =
        domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &protected_record);
    let record = PreparedSourceContentRecordV1 {
        occurrence: SourceContentOccurrenceV1 {
            role: SourceContentRoleV1::OriginalResponse,
            occurrence_event_hash: occurrence_hash,
            response_id: Some("neutral-response".into()),
            publication_hash: [5; 32],
            public_signing_policy_hash: [6; 32],
            evaluation_registration_hash: [8; 32],
        },
        record_sha256,
        member_content_hash,
        protected_record_bytes: protected_record,
        locator_cbor: neutral_encoded(&locator),
    };
    let batch = PreparedSourceContentBatchV1 {
        version: 1,
        selection: identity.clone(),
        records: vec![record.clone()],
        intake_handoffs: catalog,
        source_signed_tasks: neutral_encoded(&Value::Array(vec![])),
    };
    let occurrences = batch
        .records
        .iter()
        .map(|row| &row.occurrence)
        .collect::<Vec<_>>();
    let preparation_key = stack_common_hash::canonical_json_hash(
        &serde_json::to_value((&batch.selection, occurrences)).unwrap(),
    )
    .unwrap();
    let selection = SourceContentSelection {
        preparation_key,
        identity,
        native_prefix_event_hashes: vec![occurrence_hash],
        photo_event_hashes: vec![],
        intake_catalog_sha256: sha256_bytes(&batch.intake_handoffs),
        task_catalog_sha256: sha256_bytes(&batch.source_signed_tasks),
        record_pins: vec![SourceContentRecordPins {
            role: record.occurrence.role,
            occurrence_event_hash: occurrence_hash,
            response_id: record.occurrence.response_id.clone(),
            source_publication_hash: [5; 32],
            public_signing_policy_hash: [6; 32],
            evaluation_registration_hash: [8; 32],
            record_sha256,
            member_content_hash,
            locator_sha256: sha256_bytes(&record.locator_cbor),
        }],
    };
    (state, closeout, selection, batch)
}

fn original_composition(contributor: Arc<CommittedOriginal>) -> SourceContentComposition {
    let (_, verifier) = selected(false);
    SourceContentComposition {
        selection_resolver: verifier.clone(),
        contributor,
        final_prefix_guard: Arc::new(real_guard()),
        structural: verifier,
    }
}
fn source_headers_tenant() -> (
    axum::http::HeaderMap,
    stack_common_http::tenant::TenantScope,
) {
    let headers = post_request("/v1/scopes/case_123/events", append_body("unused"))
        .headers()
        .clone();
    let mut headers = headers;
    headers.insert(
        trellis_service_client::COMPLETION_CALLER_AUTHORIZATION_HEADER,
        "Bearer public-neutral-person".parse().unwrap(),
    );
    let tenant = stack_common_http::tenant::TenantScope {
        tenant: "tenant-a".into(),
        workspace: "workspace-a".into(),
        environment: "prod".into(),
        cell: "cell-a".into(),
    };
    (headers, tenant)
}
#[tokio::test]
async fn source_content_committed_original_read_writer_and_immutable_replay() {
    let (state, body, selection, batch) = committed_original_fixture().await;
    let contributor = Arc::new(CommittedOriginal {
        batch: batch.clone(),
        reads: AtomicUsize::new(0),
        lock_wait: None,
    });
    let state = state.with_source_content(original_composition(contributor.clone()));
    let (headers, tenant) = source_headers_tenant();
    let context = SourceContentAppendContext {
        selection: &selection,
        headers: &headers,
        tenant: &tenant,
        body: &body,
    };
    let cmd = command(&serde_json::to_vec(&body).unwrap());
    let first = state
        .append_coordinator()
        .append_selected_source_content(cmd.clone(), &context)
        .await
        .unwrap();
    let retained = state
        .bundles
        .get_by_seal(b"case_123", 2)
        .await
        .unwrap()
        .unwrap();
    let bytes = state
        .artifact_store
        .get(&retained.artifact_ref)
        .await
        .unwrap()
        .unwrap();
    let entries = integrity_bundle::read_stored_zip(&bytes).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.bytes() == batch.records[0].protected_record_bytes)
    );
    let replay = state
        .append_coordinator()
        .append_selected_source_content(cmd, &context)
        .await
        .unwrap();
    assert_eq!(first.stored, replay.stored);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_123")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        state
            .bundles
            .get_by_seal(b"case_123", 2)
            .await
            .unwrap()
            .unwrap(),
        retained
    );
    assert_eq!(
        state
            .artifact_store
            .get(&retained.artifact_ref)
            .await
            .unwrap()
            .unwrap(),
        bytes
    );
    assert_eq!(contributor.reads.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn source_content_permission_revoked_during_scope_lock_wait_prevents_commit() {
    let (state, body, selection, batch) = committed_original_fixture().await;
    let authority = Arc::new(LockWaitAuthority {
        calls: AtomicUsize::new(0),
        revoked: std::sync::atomic::AtomicBool::new(false),
        before_lock: tokio::sync::Notify::new(),
    });
    let contributor = Arc::new(CommittedOriginal {
        batch,
        reads: AtomicUsize::new(0),
        lock_wait: Some((state.scope_locks.clone(), authority.clone())),
    });
    let state = state
        .with_source_content(original_composition(contributor))
        .with_scope_authorizer(authority.clone());
    let (headers, tenant) = source_headers_tenant();
    let context = SourceContentAppendContext {
        selection: &selection,
        headers: &headers,
        tenant: &tenant,
        body: &body,
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state
            .append_coordinator()
            .append_selected_source_content(command(&serde_json::to_vec(&body).unwrap()), &context),
    )
    .await
    .unwrap();
    assert_eq!(
        result.unwrap_err().title(),
        "neutral Append permission revoked during lock wait"
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_123")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        state
            .bundles
            .get_by_seal(b"case_123", 2)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn source_content_response_claims_cannot_change_with_consistent_batch_key_and_selected_pins()
{
    for change in 0..4 {
        let (state, body, mut selection, mut batch) = committed_original_fixture().await;
        match change {
            0 => {
                batch.records[0].occurrence.publication_hash = [99; 32];
                selection.record_pins[0].source_publication_hash = [99; 32];
            }
            1 => {
                batch.records[0].occurrence.public_signing_policy_hash = [99; 32];
                selection.record_pins[0].public_signing_policy_hash = [99; 32];
            }
            2 => {
                batch.records[0].occurrence.response_id = Some("foreign-response".into());
                selection.record_pins[0].response_id = Some("foreign-response".into());
            }
            _ => {
                batch.selection.recipient_policy_hash = [99; 32];
                selection.identity.recipient_policy_hash = [99; 32];
            }
        }
        let occurrences = batch
            .records
            .iter()
            .map(|record| &record.occurrence)
            .collect::<Vec<_>>();
        let key = stack_common_hash::canonical_json_hash(
            &serde_json::to_value((&batch.selection, occurrences)).unwrap(),
        )
        .unwrap();
        selection.preparation_key = key;
        let contributor = Arc::new(CommittedOriginal {
            batch,
            reads: AtomicUsize::new(0),
            lock_wait: None,
        });
        let state = state.with_source_content(original_composition(contributor.clone()));
        let (headers, tenant) = source_headers_tenant();
        let context = SourceContentAppendContext {
            selection: &selection,
            headers: &headers,
            tenant: &tenant,
            body: &body,
        };
        let error = state
            .append_coordinator()
            .append_selected_source_content(command(&serde_json::to_vec(&body).unwrap()), &context)
            .await
            .unwrap_err();
        assert_eq!(error.title(), "committed Source content selection differs");
        assert_eq!(contributor.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            state
                .repository
                .list_scope(b"case_123")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            state
                .bundles
                .get_by_seal(b"case_123", 2)
                .await
                .unwrap()
                .is_none()
        );
    }
}

struct CurrentRecipientSetSelection {
    original: SourceContentSelection,
    rotated: SourceContentSelection,
    use_rotated: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl SourceContentSelectionResolver for CurrentRecipientSetSelection {
    async fn select(
        &self,
        _request: &SourceContentSelectionRequest<'_>,
    ) -> Result<SourceContentSelection, StackError> {
        Ok(if self.use_rotated.load(Ordering::SeqCst) {
            self.rotated.clone()
        } else {
            self.original.clone()
        })
    }
}
#[tokio::test]
async fn source_content_recipient_set_rotation_rekeys_batch_and_refuses_old_bytes_and_cached_replay()
 {
    use tower::ServiceExt;
    let (state, body, selection, batch) = committed_original_fixture().await;
    let mut rotated_batch = batch.clone();
    rotated_batch.selection.recipient_set_sha256 = [10; 32];
    let occurrences = rotated_batch
        .records
        .iter()
        .map(|record| &record.occurrence)
        .collect::<Vec<_>>();
    let rotated_key = stack_common_hash::canonical_json_hash(
        &serde_json::to_value((&rotated_batch.selection, occurrences)).unwrap(),
    )
    .unwrap();
    assert_ne!(rotated_key, selection.preparation_key);
    assert_eq!(
        rotated_batch.selection.recipient_policy_hash,
        batch.selection.recipient_policy_hash
    );
    let mut rotated = selection.clone();
    rotated.identity = rotated_batch.selection;
    rotated.preparation_key = rotated_key;
    let resolver = Arc::new(CurrentRecipientSetSelection {
        original: selection.clone(),
        rotated: rotated.clone(),
        use_rotated: std::sync::atomic::AtomicBool::new(false),
    });
    let contributor = Arc::new(CommittedOriginal {
        batch,
        reads: AtomicUsize::new(0),
        lock_wait: None,
    });
    let mut composition = original_composition(contributor.clone());
    composition.selection_resolver = resolver.clone();
    let state = state.with_source_content(composition);
    let app = router(state.clone()).unwrap();
    let request = |key: &str| {
        let mut request = post_request(
            "/v1/scopes/case_123/events",
            serde_json::to_vec(&body).unwrap(),
        );
        request
            .headers_mut()
            .insert(PREPARATION_KEY_HEADER, key.parse().unwrap());
        request.headers_mut().insert(
            trellis_service_client::COMPLETION_CALLER_AUTHORIZATION_HEADER,
            "Bearer public-neutral-person".parse().unwrap(),
        );
        request
    };
    let first = app
        .clone()
        .oneshot(request(&selection.preparation_key))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let retained = state
        .bundles
        .get_by_seal(b"case_123", 2)
        .await
        .unwrap()
        .unwrap();
    let bytes = state
        .artifact_store
        .get(&retained.artifact_ref)
        .await
        .unwrap()
        .unwrap();
    resolver.use_rotated.store(true, Ordering::SeqCst);
    let retry = app
        .oneshot(request(&rotated.preparation_key))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(
        retry
            .headers()
            .get(stack_common_http::idempotency::IDEMPOTENCY_REPLAY_HEADER)
            .is_none()
    );
    assert_eq!(contributor.reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_123")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        state
            .artifact_store
            .get(&retained.artifact_ref)
            .await
            .unwrap()
            .unwrap(),
        bytes
    );
}
