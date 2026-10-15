// Rust guideline compliant 2026-02-21
// Controlled service authorization and actual native append/export composition tests.
// Fixture Source facts are test inputs, not proof of accepted Source authority.

use super::*;
use axum::http::HeaderMap;
use stack_common_auth::{AccessTokenError, AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_http::tenant::TenantScope;
use std::sync::atomic::AtomicBool;
use trellis_admission_formspec::accepted_attachment::{
    ACCEPTED_ATTACHMENT_EVENT, AcceptedAttachmentDescriptor, AttachmentLimits,
};
use trellis_core::external_attachment::{
    ExternalAppendLimits, ExternalAttachmentAppend, ExternalAttachmentHeader,
    open_native_external_attachment,
};
use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_http_retryable_completion_preserves_success_in_both_orders_and_concurrently() {
    use stack_common_http::idempotency::{
        HttpIdempotencyState, IdempotencyCall, IdempotencyDecision, IdempotencyRequest,
        IdempotencyReservation, IdempotencyResponseDisposition,
    };
    use stack_common_idempotency::{StoredResponse, hash_http_request_body};

    for order in 0..3 {
        let (state, _, _) = native_state();
        // This is the trusted tuple minted by typed authorization, not a caller header.
        let call = IdempotencyCall {
            request: IdempotencyRequest {
                scope: "POST:/v1/scopes/case_123/accepted-attachments".into(),
                key: format!("completion-order-{order}"),
                request_hash: hash_http_request_body(b"exact authorized original request"),
            },
            headers: HeaderMap::new(),
            replay_partition: Some(
                serde_json::to_string(&(
                    "owning-producer",
                    native_tenant(),
                    "case_123",
                    "accepted-attachment",
                    "selected-policy",
                ))
                .unwrap(),
            ),
        };
        for _ in 0..2 {
            assert!(matches!(
                state.reserve_http_idempotency_attempt(&call).await,
                Ok(IdempotencyReservation::Fresh(None))
            ));
        }
        let success = StoredResponse {
            status: 201,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"exact successful native append response".to_vec(),
        };
        let failure = StoredResponse {
            status: 503,
            headers: vec![],
            body: b"storage temporarily unavailable".to_vec(),
        };
        let mut failed_response = axum::response::Response::new(axum::body::Body::empty());
        *failed_response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        failed_response
            .extensions_mut()
            .insert(crate::external_transport::RetryableStorageAttempt);
        let retryable = state.http_idempotency_response_disposition(&call, &failed_response);
        assert_eq!(retryable, IdempotencyResponseDisposition::RetryableAttempt);
        let mut successful_response = axum::response::Response::new(axum::body::Body::empty());
        *successful_response.status_mut() = StatusCode::CREATED;
        let completed = state.http_idempotency_response_disposition(&call, &successful_response);
        assert_eq!(completed, IdempotencyResponseDisposition::Replay);

        if order == 2 {
            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let success_task = {
                let state = state.clone();
                let call = call.clone();
                let barrier = barrier.clone();
                let success = success.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    state
                        .finish_http_idempotency_attempt(&call, None, completed, success)
                        .await
                        .is_ok()
                })
            };
            let failure_task = {
                let state = state.clone();
                let call = call.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    state
                        .finish_http_idempotency_attempt(&call, None, retryable, failure)
                        .await
                        .is_ok()
                })
            };
            barrier.wait().await;
            assert!(success_task.await.unwrap());
            assert!(failure_task.await.unwrap());
        } else {
            let completions = if order == 0 {
                [(completed, success.clone()), (retryable, failure)]
            } else {
                [(retryable, failure), (completed, success.clone())]
            };
            for (disposition, response) in completions {
                assert!(
                    state
                        .finish_http_idempotency_attempt(&call, None, disposition, response)
                        .await
                        .is_ok()
                );
            }
        }
        match state.reserve_http_idempotency_attempt(&call).await {
            Ok(IdempotencyReservation::Replay(actual)) => assert_eq!(actual, success),
            _ => panic!("completed native response was not preserved for order {order}"),
        }
        let mut changed = call.clone();
        changed.request.request_hash =
            hash_http_request_body(b"changed authorized original request");
        assert!(matches!(
            state.reserve_http_idempotency(&changed).await,
            Ok(IdempotencyDecision::Conflict)
        ));
    }
}

struct NativeVerifier {
    allowed: Arc<AtomicBool>,
}

#[async_trait]
impl AccessTokenVerifier for NativeVerifier {
    async fn verify(&self, token: &str) -> Result<VerifiedAccessIdentity, AccessTokenError> {
        if token != "controlled-native-token" || !self.allowed.load(Ordering::SeqCst) {
            return Err(AccessTokenError::rejected());
        }
        Ok(VerifiedAccessIdentity {
            issuer: "https://controlled-native-issuer.example".into(),
            subject: "owning-producer".into(),
            client_id: Some("owning-producer-client".into()),
            scopes: Default::default(),
            expires_at: i64::MAX,
            token_id: None,
        })
    }
}

struct NativeGrants {
    allowed: Arc<AtomicBool>,
}

fn native_tenant() -> TenantScope {
    TenantScope {
        tenant: "tenant-a".into(),
        workspace: "workspace-a".into(),
        environment: "prod".into(),
        cell: "cell-a".into(),
    }
}

#[async_trait]
impl ScopeAuthorizer for NativeGrants {
    type Error = StackError;

    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, StackError> {
        let valid_identity = request.identity.is_some_and(|identity| {
            identity.issuer == "https://controlled-native-issuer.example"
                && identity.subject == "owning-producer"
                && identity.client_id.as_deref() == Some("owning-producer-client")
        });
        let valid_actor = request.action != ScopeAction::Append
            || request.append_body.is_some_and(|body| {
                matches!(
                    body.actor.subject.as_str(),
                    "formspec-server" | "wos-server"
                )
            });
        if !self.allowed.load(Ordering::SeqCst)
            || !valid_identity
            || !valid_actor
            || request.tenant_scope != &native_tenant()
            || !matches!(request.scope, b"case_123" | b"case_other")
        {
            return Err(StackError::new(
                stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
                StatusCode::FORBIDDEN,
                "controlled native grant refused",
            ));
        }
        Ok(AuthorizedScope {
            principal: "internal-owning-producer".into(),
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        })
    }
}

fn native_state() -> (TrellisServerState, Arc<AtomicBool>, Arc<AtomicBool>) {
    let identity = Arc::new(AtomicBool::new(true));
    let grants = Arc::new(AtomicBool::new(true));
    let state = test_state()
        .with_access_token_verifier(Arc::new(NativeVerifier {
            allowed: identity.clone(),
        }))
        .with_scope_authorizer(Arc::new(NativeGrants {
            allowed: grants.clone(),
        }))
        .with_production_like_scope_posture(true);
    (state, identity, grants)
}

#[tokio::test]
async fn retained_head_read_advances_after_an_actual_accepted_attachment() {
    struct ReadAppendOnly(Arc<dyn ScopeAuthorizer<Error = StackError>>);
    #[async_trait]
    impl ScopeAuthorizer for ReadAppendOnly {
        type Error = StackError;
        async fn authorize(
            &self,
            request: &ScopeAuthorization<'_>,
        ) -> Result<AuthorizedScope, StackError> {
            if request.action == ScopeAction::Administer {
                return Err(StackError::new(
                    stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
                    StatusCode::FORBIDDEN,
                    "controlled publication refused",
                ));
            }
            self.0.authorize(request).await
        }
    }
    let (mut state, _, _) = native_state();
    state.authorizer = Arc::new(ReadAppendOnly(state.authorizer.clone()));
    let app = router(state.clone()).unwrap();
    let first = app
        .clone()
        .oneshot(post_request_bearer(
            "/v1/scopes/case_123/events",
            append_body("before-accepted-photo"),
            "controlled-native-token",
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first: trellis_service_client::SubstrateAppendResult =
        serde_json::from_slice(&to_bytes(first.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let before = native_bundle(&state, &first).await;
    let (descriptor, mut input, original) = external_fixture_input();
    let prior = state.repository.list_scope(b"case_123").await.unwrap();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &prior,
            preparation_limits(),
        )
        .unwrap();
    input.expected_head = prepared.expected_head();
    input.preparation_identity = prepared.replay_digest();
    let authorization = native_authorization(&descriptor, &input);
    let result = append_prepared_external_attachment(
        &state,
        &native_headers(&authorization.idempotency_key),
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    let expected = native_bundle(&state, &result).await;
    assert_ne!(expected, before);
    let mut head = get_request("/v1/scopes/case_123/bundles/head");
    head.headers_mut().insert(
        "authorization",
        "Bearer controlled-native-token".parse().unwrap(),
    );
    let response = app.oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let actual = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        state
            .repository
            .list_scope(b"case_123")
            .await
            .unwrap()
            .len(),
        2
    );
}

fn native_headers(key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        "Bearer controlled-native-token".parse().unwrap(),
    );
    headers.insert(IDEMPOTENCY_KEY_HEADER, key.parse().unwrap());
    headers
}

fn recipient_policy() -> ExternalAttachmentRecipientPolicy {
    ExternalAttachmentRecipientPolicy {
        designated_readers: vec![b"fixture-reader".to_vec()],
        operator_recipients: vec![],
    }
}

fn preparation_limits() -> AttachmentLimits {
    AttachmentLimits {
        original_bytes: 8192,
        ciphertext_bytes: 8192,
        prior_events: 16,
        prior_event_bytes: 64 * 1024,
    }
}

pub(super) fn external_fixture_input() -> (
    AcceptedAttachmentDescriptor,
    ExternalAttachmentAppend,
    Vec<u8>,
) {
    let canonical = include_bytes!(
        "../../../fixtures/vectors/append/047-native-external-attachment/expected-event-payload.cbor"
    );
    let original = include_bytes!(
        "../../../fixtures/vectors/append/047-native-external-attachment/input-original.bin"
    )
    .to_vec();
    let ciphertext = include_bytes!("../../../fixtures/vectors/append/047-native-external-attachment/input-attachment-ciphertext.bin").to_vec();
    let nonce = *include_bytes!(
        "../../../fixtures/vectors/append/047-native-external-attachment/nonce.bin"
    );
    let value = integrity_cbor::decode_cbor_value(canonical).unwrap();
    let fields = value.as_map().unwrap();
    let key_bag = integrity_cbor::map_lookup_value(fields, "key_bag")
        .unwrap()
        .clone();
    let descriptor = AcceptedAttachmentDescriptor {
        version: 1,
        response_id: "controlled-accepted-response".into(),
        response_hash: format!(
            "sha256:{}",
            hex::encode(integrity_cbor::sha256_bytes(
                b"controlled accepted response"
            ))
        ),
        source_id: "urn:controlled:source".into(),
        service_binding_id: "controlled-service-binding".into(),
        accepted_actor_ref: "actor:human:controlled-original".into(),
        form_id: "controlled-form".into(),
        subject_ref: "controlled-subject".into(),
        field_path: "/file".into(),
        upload_id: "controlled-upload".into(),
        accepted_attachment_id: "controlled-occurrence".into(),
        binding_attachment_id: "logical-slot-047".into(),
        filename: None,
        media_type: "application/octet-stream".into(),
        byte_length: original.len() as u64,
        attachment_sha256: format!(
            "sha256:{}",
            hex::encode(integrity_cbor::sha256_bytes(&original))
        ),
        object_uri: "urn:controlled:object".into(),
        prior_binding_hash: None,
    };
    let prepared = descriptor
        .clone()
        .prepare(
            b"case_123",
            &original,
            &ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let input = ExternalAttachmentAppend {
        scope: b"case_123".to_vec(),
        idempotency_key: b"native-external-047".to_vec(),
        header: ExternalAttachmentHeader {
            event_type: ACCEPTED_ATTACHMENT_EVENT.into(),
            authored_at_seconds: 0,
            authored_at_nanos: 0,
            classification: "x-trellis-service/private-attachment".into(),
            retention_tier: 0,
        },
        extensions: integrity_cbor::decode_cbor_value(&prepared.extensions_cbor().unwrap())
            .unwrap(),
        key_bag,
        ciphertext: ciphertext.clone(),
        nonce,
        original_sha256: integrity_cbor::sha256_bytes(&original),
        original_byte_length: original.len() as u64,
        preparation_identity: prepared.replay_digest(),
        expected_head: None,
        limits: ExternalAppendLimits {
            ciphertext_bytes: 8192,
            events: 16,
            metadata_bytes: 64 * 1024,
        },
    };
    (descriptor, input, original)
}

fn native_authorization(
    descriptor: &AcceptedAttachmentDescriptor,
    input: &ExternalAttachmentAppend,
) -> SubstrateAppendBody {
    SubstrateAppendBody {
        event_type: ACCEPTED_ATTACHMENT_EVENT.into(),
        idempotency_key: String::from_utf8(input.idempotency_key.clone()).unwrap(),
        actor: trellis_service_client::AppendActor::service("formspec-server"),
        payload: serde_json::to_value(descriptor).unwrap(),
        compute_context: trellis_service_client::ComputeContext::new(
            "compute:formspec-server:readerHeld",
            "formspec-server",
            trellis_service_client::ComputeSensitivity::ReaderHeld,
        ),
        client_attestation: None,
    }
}

async fn native_bundle(
    state: &TrellisServerState,
    result: &trellis_service_client::SubstrateAppendResult,
) -> Vec<u8> {
    state
        .artifact_store
        .get(&ArtifactRef::new(&result.bundle_ref))
        .await
        .unwrap()
        .unwrap()
}

#[derive(Default)]
struct PublicationHead {
    inner: crate::artifacts::BundleIndex,
    head: tokio::sync::Mutex<Option<crate::artifacts::BundleRecord>>,
}

#[async_trait]
impl crate::artifacts::BundleIndexPort for PublicationHead {
    async fn reserve_publishable(
        &self,
        scope: &[u8],
        identity: &crate::artifacts::BundleIdentity,
    ) -> Result<(), StackError> {
        self.inner.reserve_publishable(scope, identity).await
    }
    async fn get_by_seal(
        &self,
        scope: &[u8],
        seal: u64,
    ) -> Result<Option<crate::artifacts::BundleRecord>, StackError> {
        self.inner.get_by_seal(scope, seal).await
    }
    async fn get_by_digest(
        &self,
        scope: &[u8],
        digest: &str,
    ) -> Result<Option<crate::artifacts::BundleRecord>, StackError> {
        self.inner.get_by_digest(scope, digest).await
    }
    async fn insert_published_record(
        &self,
        scope: &[u8],
        record: &crate::artifacts::BundleRecord,
        update_head: bool,
    ) -> Result<(), StackError> {
        self.inner
            .insert_published_record(scope, record, update_head)
            .await?;
        if update_head {
            *self.head.lock().await = Some(record.clone());
        }
        Ok(())
    }
}

#[tokio::test]
async fn native_service_append_exports_verified_ciphertext_and_recipient_opens_original() {
    let (state, _, _) = native_state();
    let (descriptor, input, original) = external_fixture_input();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let authorization = native_authorization(&descriptor, &input);
    let result = append_prepared_external_attachment(
        &state,
        &native_headers(&authorization.idempotency_key),
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    result
        .validate_for_event_append("case_123", ACCEPTED_ATTACHMENT_EVENT)
        .unwrap();
    let zip = native_bundle(&state, &result).await;
    let report = integrity_verify::trellis::verify_export_zip(&zip);
    assert!(
        report.structure_verified && report.integrity_verified,
        "{report:?}"
    );
    assert!(
        !report.readability_verified,
        "generic verifier has no recipient private key"
    );
    let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
    let content =
        integrity_cbor::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &input.ciphertext);
    let body_path = format!("060-payloads/{}.bin", hex::encode(content));
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.path().ends_with(&body_path))
            .unwrap()
            .bytes(),
        input.ciphertext
    );
    let catalog = entries
        .iter()
        .find(|entry| entry.path().ends_with("061-attachments.cbor"))
        .unwrap();
    assert_eq!(
        integrity_cbor::decode_cbor_value(catalog.bytes())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let events = state.repository.list_scope(b"case_123").await.unwrap();
    assert_eq!(events.len(), 1);
    let public = trellis_cddl::parse_ed25519_cose_key(test_signing_key().core_key().as_bytes())
        .unwrap()
        .public_key;
    let opened = open_native_external_attachment(
        public,
        events[0].signed_event(),
        &input.ciphertext,
        b"fixture-reader",
        &[17; 32],
        integrity_hpke::external_attachment::ProtectionLimits {
            original_bytes: 8192,
            recipients: 4,
            recipient_id_bytes: 64,
        },
        64 * 1024,
    )
    .unwrap();
    assert_eq!(opened, original);
}

#[tokio::test]
async fn native_exact_replay_after_head_advance_preserves_original_event_and_export() {
    let (mut state, _, _) = native_state();
    let publications = Arc::new(PublicationHead::default());
    state.bundles = publications.clone();
    let (descriptor, input, original) = external_fixture_input();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let authorization = native_authorization(&descriptor, &input);
    let headers = native_headers(&authorization.idempotency_key);
    let first = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    let before = state.repository.list_scope(b"case_123").await.unwrap()[0].clone();
    let first_zip = native_bundle(&state, &first).await;
    let app = router(state.clone()).unwrap();
    let continuation = app
        .oneshot(post_request_bearer(
            "/v1/scopes/case_123/events",
            append_body("native-continuation"),
            "controlled-native-token",
        ))
        .await
        .unwrap();
    assert_eq!(continuation.status(), StatusCode::CREATED);
    let published_head = publications.head.lock().await.clone().unwrap();
    assert_ne!(published_head.artifact_ref.uri, first.bundle_ref);
    let replay = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&replay).unwrap()
    );
    assert_eq!(native_bundle(&state, &replay).await, first_zip);
    let events = state.repository.list_scope(b"case_123").await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], before);
    assert_eq!(
        *publications.head.lock().await,
        Some(published_head),
        "old exact retry must preserve the later published head"
    );
}

#[tokio::test]
async fn native_changed_preparation_wrap_and_body_conflict_without_replacing_retained_output() {
    let (state, _, _) = native_state();
    let (descriptor, input, original) = external_fixture_input();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let authorization = native_authorization(&descriptor, &input);
    let headers = native_headers(&authorization.idempotency_key);
    let first = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    let before = state.repository.list_scope(b"case_123").await.unwrap();
    for change in 0..3 {
        let mut changed_descriptor = descriptor.clone();
        let mut changed = input.clone();
        match change {
            0 => changed_descriptor.accepted_actor_ref = "actor:human:changed".into(),
            1 => {
                let Value::Map(bag) = &mut changed.key_bag else {
                    panic!("key bag")
                };
                let Value::Array(rows) = &mut bag[0].1 else {
                    panic!("wraps")
                };
                let Value::Map(row) = &mut rows[0] else {
                    panic!("wrap")
                };
                let value = &mut row
                    .iter_mut()
                    .find(|(key, _)| key.as_text() == Some("wrapped_dek"))
                    .unwrap()
                    .1;
                let Value::Bytes(bytes) = value else {
                    panic!("wrapped key")
                };
                bytes[0] ^= 1;
            }
            _ => changed.ciphertext[0] ^= 1,
        }
        let body = changed.ciphertext.clone();
        let changed_prepared = changed_descriptor
            .clone()
            .prepare(&changed.scope, &original, &body, &[], preparation_limits())
            .unwrap();
        changed.preparation_identity = changed_prepared.replay_digest();
        changed.extensions =
            integrity_cbor::decode_cbor_value(&changed_prepared.extensions_cbor().unwrap())
                .unwrap();
        let changed_authorization = native_authorization(&changed_descriptor, &changed);
        let error = append_prepared_external_attachment(
            &state,
            &headers,
            &native_tenant(),
            &changed_authorization,
            &changed_prepared,
            changed,
            &recipient_policy(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), StatusCode::CONFLICT);
    }
    assert_eq!(
        state.repository.list_scope(b"case_123").await.unwrap(),
        before
    );
    assert_eq!(
        state
            .repository
            .external_attachment_body(b"case_123", &prepared.content_hash())
            .await
            .unwrap()
            .unwrap(),
        input.ciphertext
    );
    assert!(!native_bundle(&state, &first).await.is_empty());
}

#[tokio::test]
async fn native_replay_rechecks_current_identity_grant_tenant_and_service_actor() {
    let (state, identity, grants) = native_state();
    let (descriptor, input, original) = external_fixture_input();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let authorization = native_authorization(&descriptor, &input);
    let headers = native_headers(&authorization.idempotency_key);
    append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    identity.store(false, Ordering::SeqCst);
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    identity.store(true, Ordering::SeqCst);
    grants.store(false, Ordering::SeqCst);
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
    let mut changed_scope = input.clone();
    changed_scope.scope = b"case_other".to_vec();
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        changed_scope,
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.status(),
        StatusCode::BAD_REQUEST,
        "even an otherwise grantable scope must match the sealed preparation"
    );
    assert!(
        state
            .repository
            .list_scope(b"case_other")
            .await
            .unwrap()
            .is_empty()
    );
    grants.store(true, Ordering::SeqCst);
    let mut foreign = native_tenant();
    foreign.workspace = "foreign-workspace".into();
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &foreign,
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
    let mut foreign_actor = authorization.clone();
    foreign_actor.actor = trellis_service_client::AppendActor::service("foreign-service");
    foreign_actor.compute_context.actor = "foreign-service".into();
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &foreign_actor,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
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

struct RetryPublication {
    inner: crate::artifacts::InMemoryArtifactStore,
    unavailable: Arc<AtomicBool>,
}

#[async_trait]
impl ArtifactStore for RetryPublication {
    type Error = StackError;
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StackError::unavailable("controlled publication failure"));
        }
        self.inner.put(key, bytes).await
    }
    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StackError::unavailable("controlled publication failure"));
        }
        self.inner.put_immutable(key, bytes).await
    }
    async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
        self.inner.get(reference).await
    }
}

#[tokio::test]
async fn native_publication_failure_retries_committed_operation_without_new_protection() {
    let (state, _, _) = native_state();
    let unavailable = Arc::new(AtomicBool::new(true));
    let state = state.with_artifact_store(Arc::new(RetryPublication {
        inner: Default::default(),
        unavailable: unavailable.clone(),
    }));
    let (descriptor, input, original) = external_fixture_input();
    let prepared = descriptor
        .clone()
        .prepare(
            &input.scope,
            &original,
            &input.ciphertext,
            &[],
            preparation_limits(),
        )
        .unwrap();
    let authorization = native_authorization(&descriptor, &input);
    let headers = native_headers(&authorization.idempotency_key);
    let error = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    let committed = state.repository.list_scope(b"case_123").await.unwrap();
    assert_eq!(committed.len(), 1);
    assert_eq!(
        state
            .repository
            .external_attachment_body(b"case_123", &prepared.content_hash())
            .await
            .unwrap()
            .unwrap(),
        input.ciphertext
    );
    unavailable.store(false, Ordering::SeqCst);
    let recovered = append_prepared_external_attachment(
        &state,
        &headers,
        &native_tenant(),
        &authorization,
        &prepared,
        input.clone(),
        &recipient_policy(),
    )
    .await
    .unwrap();
    assert_eq!(
        state.repository.list_scope(b"case_123").await.unwrap(),
        committed
    );
    let zip = native_bundle(&state, &recovered).await;
    assert!(export_bundle_cryptographically_verified(&zip));
    assert_eq!(recovered.sequence, 0);
}
