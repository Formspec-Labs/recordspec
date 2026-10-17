// Neutral composition regressions; these mocks do not qualify Source cryptography.
// Rust guideline compliant 2026-02-21
use stack_common_typeid::testing::fixture_minter;
use super::*;
use crate::source_content::*;
use serde_json::json;

struct NeutralPorts {
    final_prefix: bool,
    structural_calls: AtomicUsize,
}
impl SourceContentBatchChecker for NeutralPorts {
    fn check_batch(
        &self,
        selected: &SourceContentSelection,
        batch: &PreparedSourceContentBatchV1,
    ) -> Result<(), StackError> {
        trellis_export_profile_wos::check_source_content_batch(selected, batch)
    }
}

/// Counts reads and delegates to the real store-backed reader.
struct CountingReader {
    inner: StoreSourceContentReader,
    reads: AtomicUsize,
}
#[async_trait]
impl SourceContentObjectReader for CountingReader {
    async fn read(
        &self,
        tenant: &stack_common_http::tenant::TenantScope,
        claim: &SourceContentClaim,
        budget: std::time::Duration,
    ) -> Result<PreparedSourceContentBatchV1, StackError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(tenant, claim, budget).await
    }
}

fn config() -> trellis_server_ports::S3ObjectConfig {
    trellis_server_ports::S3ObjectConfig {
        bucket: "source-content".into(),
        endpoint: None,
        region: None,
    }
}
fn store_over(
    backend: &Arc<object_store::memory::InMemory>,
) -> trellis_server_ports::S3CompatibleArtifactStore {
    trellis_server_ports::S3CompatibleArtifactStore::from_object_store_for_test(
        config(),
        "pfx/",
        backend.clone(),
    )
}
fn tenant_a() -> stack_common_http::tenant::TenantScope {
    stack_common_http::tenant::TenantScope {
        tenant: "tenant-a".into(),
        workspace: "workspace-a".into(),
        environment: "prod".into(),
        cell: "cell-a".into(),
    }
}
fn pins() -> ConfiguredSourceContentPins {
    ConfiguredSourceContentPins {
        provider_selection_hash: [3; 32],
        native_policy_hash: [17; 32],
        recipient_policy_hash: [7; 32],
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
        last: Option<&StoredEvent>,
    ) -> Result<SourceContentPrefixClass, StackError> {
        self.classify(scope, last.map(std::slice::from_ref).unwrap_or_default())
    }
}
impl StructuralSourcePublicationVerifier for NeutralPorts {
    fn verify(&self, zip: &[u8]) -> Result<(), StackError> {
        self.structural_calls.fetch_add(1, Ordering::SeqCst);
        trellis_export_profile_wos::verify_source_content_export(zip, None)
    }
}
fn composition_over(
    reader: Arc<dyn SourceContentObjectReader>,
    final_prefix: bool,
) -> (SourceContentComposition, Arc<NeutralPorts>) {
    let ports = Arc::new(NeutralPorts {
        final_prefix,
        structural_calls: AtomicUsize::new(0),
    });
    (
        SourceContentComposition {
            object_reader: reader,
            batch_checker: ports.clone(),
            final_prefix_guard: ports.clone(),
            structural: ports.clone(),
            pins: pins(),
            publisher: "wos-server".into(),
        },
        ports,
    )
}
/// A composition whose store holds nothing; for tests that must never reach the object.
fn selected(final_prefix: bool) -> (SourceContentComposition, Arc<CountingReader>) {
    let reader = Arc::new(CountingReader {
        inner: StoreSourceContentReader::new(store_over(&Arc::new(
            object_store::memory::InMemory::new(),
        ))),
        reads: AtomicUsize::new(0),
    });
    (composition_over(reader.clone(), final_prefix).0, reader)
}
fn command(body: &[u8]) -> append::AppendCommand {
    let body: SubstrateAppendBody = serde_json::from_slice(body).unwrap();
    append::AppendCommand {
        scope: "case_123".into(),
        event_type: body.event_type,
        idempotency_key: body.idempotency_key,
        payload: body.payload,
        client_attestation: None,
    }
}

#[tokio::test]
async fn source_content_final_guard_refuses_plain_append_before_repository_write() {
    let (composition, reader) = selected(true);
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
    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_content_final_guard_refuses_a_bare_final_closeout_export() {
    let state = test_state();
    state
        .append_coordinator()
        .append(command(&append_body("source-old-prefix")))
        .await
        .unwrap();
    let head = state
        .repository
        .head_checkpoint(b"case_123")
        .await
        .unwrap()
        .unwrap();
    let (composition, reader) = selected(true);
    let state = state.with_source_content(composition);
    let error = export::assemble(&state, b"case_123", &head)
        .await
        .unwrap_err();
    assert_eq!(
        error.title(),
        "final closeout requires committed Source content"
    );
    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
    let response = router(state)
        .unwrap()
        .oneshot(get_request("/v1/scopes/case_123/bundles/head"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_content_ordinary_append_never_reads_the_contributor() {
    let (composition, reader) = selected(false);
    let state = test_state().with_source_content(composition);
    state
        .append_coordinator()
        .append(command(&signature_affirmation_append_body(
            "source-ordinary-gate",
        )))
        .await
        .unwrap();
    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
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
            source_content: None,
    }
}
fn real_guard() -> ConfiguredNativeCloseoutGuard {
    let kind = serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap();
    let rule = json!({"closeoutRecord":{"recordKind":kind,"event":"neutral.closeout",
        "tests":[{"test":"equals","pointer":"/data/closed","value":true}]}});
    ConfiguredNativeCloseoutGuard::new(crate::test_adapters::closeout(), [17; 32], rule).unwrap()
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
    let (composition, reader) = selected(true);
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
    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
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

fn object_key(tenant: &stack_common_http::tenant::TenantScope, claim: &SourceContentClaim) -> String {
    trellis_server_ports::source_content_object_key(tenant, &claim.selection.preparation_key)
        .unwrap()
}

/// A fixture whose closeout body carries a claim for a real prepared batch.
struct Sourced {
    state: TrellisServerState,
    body: SubstrateAppendBody,
    batch: PreparedSourceContentBatchV1,
    claim: SourceContentClaim,
    backend: Arc<object_store::memory::InMemory>,
    reader: Arc<CountingReader>,
}
impl Sourced {
    async fn put_object(&self, tenant: &stack_common_http::tenant::TenantScope) {
        use trellis_server_ports::ArtifactStore;
        store_over(&self.backend)
            .put_immutable(
                &object_key(tenant, &self.claim),
                &serde_json::to_vec(&self.batch).unwrap(),
            )
            .await
            .unwrap();
    }
    fn payload(&self) -> Vec<u8> {
        serde_json::to_vec(&self.body).unwrap()
    }
    async fn ledger_len(&self) -> usize {
        self.state.repository.list_scope(b"case_123").await.unwrap().len()
    }
}
async fn sourced(
    stored: bool,
    adjust: impl FnOnce(&mut SourceContentComposition),
) -> Sourced {
    let (state, mut body, selection, batch) = committed_original_fixture().await;
    let backend = Arc::new(object_store::memory::InMemory::new());
    let bytes = serde_json::to_vec(&batch).unwrap();
    let claim = SourceContentClaim {
        hash: hex::encode(integrity_cbor::sha256_bytes(&bytes)),
        size: bytes.len() as u64,
        selection,
    };
    body.source_content = Some(claim.clone());
    let reader = Arc::new(CountingReader {
        inner: StoreSourceContentReader::new(store_over(&backend)),
        reads: AtomicUsize::new(0),
    });
    let (mut composition, _) = composition_over(reader.clone(), false);
    composition.final_prefix_guard = Arc::new(real_guard());
    adjust(&mut composition);
    let fixture = Sourced {
        state: state.with_source_content(composition),
        body,
        batch,
        claim,
        backend,
        reader,
    };
    if stored {
        fixture.put_object(&tenant_a()).await;
    }
    fixture
}

const EVENTS: &str = "/v1/scopes/case_123/events";

async fn refusal_title(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let title = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value["title"].as_str().map(str::to_owned))
        .unwrap_or_default();
    (status, title)
}

#[tokio::test]
async fn source_content_committed_original_read_writer_and_immutable_replay() {
    // A lost 201: the same admitted claim again reaches the ledger branch and returns the record.
    let f = sourced(true, |_| {}).await;
    let admitted = AdmittedSourceContent {
        claim: f.claim.clone(),
        batch: f.batch.clone(),
    };
    let context = SourceContentAppendContext {
        admitted: &admitted,
        body: &f.body,
    };
    let cmd = command(&f.payload());
    let first = f
        .state
        .append_coordinator()
        .append_selected_source_content(cmd.clone(), &context)
        .await
        .unwrap();
    let head = f.state.repository.head_checkpoint(b"case_123").await.unwrap().unwrap();
    assert_eq!(head.tree_size, 2);
    let bytes = export::assemble(&f.state, b"case_123", &head).await.unwrap();
    let entries = integrity_bundle::read_stored_zip(&bytes).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.bytes() == f.batch.records[0].protected_record_bytes)
    );
    let replay = f
        .state
        .append_coordinator()
        .append_selected_source_content(cmd, &context)
        .await
        .unwrap();
    assert_eq!(first.stored, replay.stored);
    assert_eq!(first.result, replay.result);
    assert_eq!(f.ledger_len().await, 2);
    assert_eq!(
        export::assemble(&f.state, b"case_123", &head).await.unwrap(),
        bytes,
        "the export is a function of the stored rows and the retained batch"
    );
}

/// ADR 0163 lets WOS purge its copy of the batch once the closeout commits. Trellis keeps its own,
/// so the closeout's export is still assembled from Trellis alone.
#[tokio::test]
async fn a_purged_case_still_exports() {
    use object_store::ObjectStore;
    let f = sourced(true, |_| {}).await;
    let response = router(f.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, f.payload()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let head = f.state.repository.head_checkpoint(b"case_123").await.unwrap().unwrap();
    let before = export::assemble(&f.state, b"case_123", &head).await.unwrap();

    // WOS purges its object: nothing remains under the contributor's key.
    let location = object_store::path::Path::from(format!(
        "pfx/{}",
        object_key(&tenant_a(), &f.claim)
    ));
    f.backend.delete(&location).await.unwrap();
    assert!(f.backend.get(&location).await.is_err(), "the WOS copy is gone");
    let reads_before = f.reader.reads.load(Ordering::SeqCst);

    let after = export::assemble(&f.state, b"case_123", &head).await.unwrap();
    assert_eq!(after, before);
    assert_eq!(
        f.reader.reads.load(Ordering::SeqCst),
        reads_before,
        "the export never reaches back to the contributor"
    );
    assert!(
        integrity_bundle::read_stored_zip(&after)
            .unwrap()
            .iter()
            .any(|entry| entry.bytes() == f.batch.records[0].protected_record_bytes)
    );
}

#[tokio::test]
async fn source_content_append_over_http_commits_with_the_object_and_no_person_credential() {
    let f = sourced(true, |_| {}).await;
    let response = router(f.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, f.payload()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(f.ledger_len().await, 2);
    assert_eq!(f.reader.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn source_content_missing_object_is_503_and_the_identical_retry_succeeds_once_it_exists() {
    let f = sourced(false, |_| {}).await;
    let app = router(f.state.clone()).unwrap();
    let first = app.clone().oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(
        refusal_title(first).await,
        (StatusCode::SERVICE_UNAVAILABLE, "source-content.object-missing".into())
    );
    assert_eq!(f.ledger_len().await, 1);
    f.put_object(&tenant_a()).await;
    let retry = app.oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CREATED);
    assert_eq!(f.ledger_len().await, 2);
}

#[tokio::test]
async fn source_content_hash_mismatch_is_422_with_no_ledger_record() {
    use trellis_server_ports::ArtifactStore;
    let f = sourced(false, |_| {}).await;
    store_over(&f.backend)
        .put(&object_key(&tenant_a(), &f.claim), b"corrupted object bytes")
        .await
        .unwrap();
    let app = router(f.state.clone()).unwrap();
    let response = app.clone().oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(
        refusal_title(response).await,
        (StatusCode::UNPROCESSABLE_ENTITY, "source-content.hash-mismatch".into())
    );
    assert_eq!(f.ledger_len().await, 1);
    assert!(f.state.repository.checkpoint_at(b"case_123", 2).await.unwrap().is_none());
}

#[tokio::test]
async fn source_content_claim_that_differs_from_the_ledger_is_refused_with_no_record() {
    let mut f = sourced(true, |_| {}).await;
    f.claim.selection.photo_event_hashes = vec![[9; 32]];
    f.body.source_content = Some(f.claim.clone());
    let response = router(f.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, f.payload()))
        .await
        .unwrap();
    assert_eq!(
        refusal_title(response).await,
        (StatusCode::CONFLICT, "source-content.claim-differs".into())
    );
    assert_eq!(f.ledger_len().await, 1);
}

#[tokio::test]
async fn source_content_wrong_publisher_or_pins_are_refused_before_any_object_read() {
    let wrong_publisher = sourced(true, |c| c.publisher = "someone-else".into()).await;
    let response = router(wrong_publisher.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, wrong_publisher.payload()))
        .await
        .unwrap();
    assert_eq!(
        refusal_title(response).await,
        (StatusCode::FORBIDDEN, "source-content.publisher-mismatch".into())
    );
    assert_eq!(wrong_publisher.reader.reads.load(Ordering::SeqCst), 0);
    assert_eq!(wrong_publisher.ledger_len().await, 1);

    let wrong_pins = sourced(true, |c| c.pins.recipient_policy_hash = [99; 32]).await;
    let response = router(wrong_pins.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, wrong_pins.payload()))
        .await
        .unwrap();
    assert_eq!(
        refusal_title(response).await,
        (StatusCode::CONFLICT, "source-content.pins-differ".into())
    );
    assert_eq!(wrong_pins.reader.reads.load(Ordering::SeqCst), 0);
    assert_eq!(wrong_pins.ledger_len().await, 1);
}

#[tokio::test]
async fn source_content_claim_cannot_resolve_outside_the_append_tenant_scope() {
    // The object exists, but only under another tenant's key; the claim carries no address.
    let f = sourced(false, |_| {}).await;
    let mut other = tenant_a();
    other.tenant = "tenant-b".into();
    f.put_object(&other).await;
    let response = router(f.state.clone())
        .unwrap()
        .oneshot(post_request(EVENTS, f.payload()))
        .await
        .unwrap();
    assert_eq!(
        refusal_title(response).await,
        (StatusCode::SERVICE_UNAVAILABLE, "source-content.object-missing".into())
    );
    assert_eq!(f.reader.reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.ledger_len().await, 1);
}

#[tokio::test]
async fn source_content_claim_without_a_composition_is_refused() {
    let f = sourced(true, |_| {}).await;
    let mut state = f.state.clone();
    state.source_content = None;
    let response = router(state)
        .unwrap()
        .oneshot(post_request(EVENTS, f.payload()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.ledger_len().await, 1);
}

/// Probe store: records each immutable key and proves the scope lock is free while it is written.
struct LockProbeStore {
    repository: Arc<dyn EventRepository>,
    keys: std::sync::Mutex<Vec<String>>,
    inner: crate::artifacts::InMemoryArtifactStore,
}

#[async_trait::async_trait]
impl trellis_server_ports::ArtifactStore for LockProbeStore {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        self.inner.put(key, bytes).await
    }

    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        tokio::time::timeout(std::time::Duration::from_secs(2), self.repository.begin(b"case_123"))
            .await
            .expect("the scope lock is free while the batch copy is written")
            .expect("begin");
        self.keys.lock().unwrap().push(key.to_string());
        self.inner.put_immutable(key, bytes).await
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
        self.inner.get(artifact_ref).await
    }
}

/// The batch copy is written under the ledger scope's key, before the scope lock is taken.
#[tokio::test]
async fn source_content_batch_copy_is_scope_keyed_and_written_before_the_scope_lock() {
    let f = sourced(true, |_| {}).await;
    let probe = Arc::new(LockProbeStore {
        repository: f.state.repository.clone(),
        keys: Default::default(),
        inner: Default::default(),
    });
    let state = f.state.clone().with_artifact_store(probe.clone());
    let app = router(state.clone()).unwrap();
    let response = app.oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let keys = probe.keys.lock().unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].starts_with("case_123/source-content-batches/"), "{}", keys[0]);
}

#[tokio::test]
async fn source_content_batch_copy_failure_commits_nothing_and_the_resend_succeeds() {
    // The copy is written before the commit, so a failed copy leaves no closeout behind, and the
    // answer is a retryable 5xx that the HTTP layer does not cache.
    let f = sourced(true, |_| {}).await;
    let state = f.state.clone().with_artifact_store(Arc::new(
        crate::repository_probes::FailsFirstImmutablePut {
            remaining: AtomicUsize::new(1),
            inner: Default::default(),
        },
    ));
    let app = router(state.clone()).unwrap();
    let first = app.clone().oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.repository.list_scope(b"case_123").await.unwrap().len(), 1);
    let resend = app.oneshot(post_request(EVENTS, f.payload())).await.unwrap();
    assert_eq!(resend.status(), StatusCode::CREATED);
    assert_eq!(state.repository.list_scope(b"case_123").await.unwrap().len(), 2);
    let head = state.repository.head_checkpoint(b"case_123").await.unwrap().unwrap();
    let zip = export::assemble(&state, b"case_123", &head).await.unwrap();
    assert!(
        integrity_bundle::read_stored_zip(&zip)
            .unwrap()
            .iter()
            .any(|entry| entry.bytes() == f.batch.records[0].protected_record_bytes)
    );
}

#[tokio::test]
async fn source_content_response_claims_cannot_change_with_consistent_batch_key_and_selected_pins()
{
    for change in 0..4 {
        let f = sourced(true, |_| {}).await;
        let mut selection = f.claim.selection.clone();
        let mut batch = f.batch.clone();
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
        selection.preparation_key = source_content_batch_key(&batch).unwrap();
        let admitted = AdmittedSourceContent {
            claim: SourceContentClaim {
                selection,
                ..f.claim.clone()
            },
            batch,
        };
        let context = SourceContentAppendContext {
            admitted: &admitted,
            body: &f.body,
        };
        let error = f
            .state
            .append_coordinator()
            .append_selected_source_content(command(&f.payload()), &context)
            .await
            .unwrap_err();
        assert_eq!(error.title(), "source-content.claim-differs");
        assert_eq!(f.ledger_len().await, 1);
        assert!(f.state.repository.checkpoint_at(b"case_123", 2).await.unwrap().is_none());
    }
}

#[test]
fn refusal_codes_map_to_the_adr_statuses() {
    for (refusal, code, status) in [
        (SourceContentRefusal::ObjectMissing, "source-content.object-missing", 503),
        (SourceContentRefusal::HashMismatch, "source-content.hash-mismatch", 422),
        (SourceContentRefusal::ClaimDiffers, "source-content.claim-differs", 409),
        (SourceContentRefusal::PublisherMismatch, "source-content.publisher-mismatch", 403),
        (SourceContentRefusal::PinsDiffer, "source-content.pins-differ", 409),
    ] {
        let error = refusal.error();
        assert_eq!((error.title(), error.status().as_u16()), (code, status));
        assert_eq!(error.into_problem().status, i64::from(status));
    }
}
