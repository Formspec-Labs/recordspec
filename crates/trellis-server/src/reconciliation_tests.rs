// Rust guideline compliant 2026-02-21
use super::*;
use trellis_service_client::{
    AppendReconciliation, AppendReconciliationRequest, ReconciliationUnknown,
};

async fn committed_state(
    key: &str,
) -> (
    TrellisServerState,
    AppendReconciliationRequest,
    SubstrateAppendResult,
) {
    let state = test_state();
    let body = append_body(key);
    let lookup =
        AppendReconciliationRequest::from_append_body(&serde_json::from_slice(&body).unwrap())
            .unwrap();
    let response = router(state.clone())
        .unwrap()
        .oneshot(post_request("/v1/scopes/scope-a/events", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (state, lookup, serde_json::from_slice(&bytes).unwrap())
}

#[derive(Clone)]
struct ReadOnlyArtifacts(Arc<dyn ArtifactStore<Error = StackError>>);

#[async_trait]
impl ArtifactStore for ReadOnlyArtifacts {
    type Error = StackError;
    async fn put(&self, _: &str, _: &[u8]) -> Result<ArtifactRef, StackError> {
        panic!("reconciliation attempted mutable write")
    }
    async fn put_immutable(&self, _: &str, _: &[u8]) -> Result<ArtifactRef, StackError> {
        panic!("reconciliation attempted immutable write")
    }
    async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
        self.0.get(reference).await
    }
}

#[tokio::test]
async fn reconciliation_returns_exact_verified_receipt_and_conflict_without_effects() {
    let (mut state, lookup, receipt) = committed_state("neutral-committed").await;
    state.artifact_store = Arc::new(ReadOnlyArtifacts(state.artifact_store.clone()));
    let before = state.repository.list_scope(b"scope-a").await.unwrap();
    assert_eq!(
        crate::reconciliation::reconcile(&state, "scope-a", &lookup).await,
        AppendReconciliation::Committed { receipt }
    );
    let mut changed = lookup.clone();
    changed.content_hash[0] ^= 1;
    assert_eq!(
        crate::reconciliation::reconcile(&state, "scope-a", &changed).await,
        AppendReconciliation::Conflict
    );
    changed = lookup;
    changed.event_type.push_str(".changed");
    assert_eq!(
        crate::reconciliation::reconcile(&state, "scope-a", &changed).await,
        AppendReconciliation::Conflict
    );
    assert_eq!(
        state.repository.list_scope(b"scope-a").await.unwrap(),
        before
    );
}

#[tokio::test]
async fn reconciliation_distinguishes_event_without_receipt_from_absence() {
    let (source, lookup, _) = committed_state("neutral-missing-receipt").await;
    let mut state = test_state();
    state.repository = source.repository;
    state.artifact_store = Arc::new(ReadOnlyArtifacts(state.artifact_store.clone()));
    assert_eq!(
        crate::reconciliation::reconcile(&state, "scope-a", &lookup).await,
        AppendReconciliation::Unknown {
            reason: ReconciliationUnknown::ReceiptUnavailable
        }
    );
    let absent = AppendReconciliationRequest {
        idempotency_key: "another-key".into(),
        ..lookup
    };
    assert!(matches!(
        crate::reconciliation::reconcile(&state, "scope-a", &absent).await,
        AppendReconciliation::Absent {
            event_count: 1,
            last_event_hash: Some(_)
        }
    ));
}

#[tokio::test]
async fn reconciliation_refuses_cached_hash_and_signed_key_corruption() {
    let (source, lookup, _) = committed_state("neutral-corruption").await;
    let event = source
        .repository
        .list_scope(b"scope-a")
        .await
        .unwrap()
        .remove(0);
    for corrupted in [
        event.clone().with_canonical_event_hash(Some([7; 32])),
        StoredEvent::with_idempotency_key(
            event.scope().to_vec(),
            event.sequence(),
            event.canonical_event().to_vec(),
            event.signed_event().to_vec(),
            b"wrong-key".to_vec(),
        ),
    ] {
        let mut state = source.clone();
        let repo = InMemoryEventRepository::new();
        repo.append_event(corrupted).await.unwrap();
        state.repository = Arc::new(repo);
        assert_eq!(
            crate::reconciliation::reconcile(&state, "scope-a", &lookup).await,
            AppendReconciliation::Unknown {
                reason: ReconciliationUnknown::VerificationFailed
            }
        );
    }
}

#[tokio::test]
async fn reconciliation_rechecks_current_read_authority_before_disclosure() {
    use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer};
    struct RevokedAfterFirst(AtomicUsize);
    #[async_trait]
    impl ScopeAuthorizer for RevokedAfterFirst {
        type Error = StackError;
        async fn authorize(
            &self,
            request: &ScopeAuthorization<'_>,
        ) -> Result<AuthorizedScope, StackError> {
            assert_eq!(request.action, ScopeAction::Read);
            if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
                return Err(StackError::new(
                    stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
                    StatusCode::FORBIDDEN,
                    "neutral revocation",
                ));
            }
            Ok(AuthorizedScope {
                principal: "neutral-reader".into(),
                tenant_scope: request.tenant_scope.clone(),
                scope: request.scope.to_vec(),
                action: request.action,
            })
        }
    }
    let mut state = test_state();
    state.authorizer = Arc::new(RevokedAfterFirst(AtomicUsize::new(0)));
    let request = AppendReconciliationRequest {
        event_type: "neutral.event".into(),
        idempotency_key: "neutral-key".into(),
        content_hash: [0; 32],
    };
    let response = router(state)
        .unwrap()
        .oneshot(post_request(
            "/v1/scopes/scope-a/events/reconcile",
            serde_json::to_vec(&request).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reconciliation_refuses_tampered_proof_and_changed_attempt_identity() {
    struct TamperedProof(Arc<dyn ArtifactStore<Error = StackError>>);
    #[async_trait]
    impl ArtifactStore for TamperedProof {
        type Error = StackError;
        async fn put(&self, _: &str, _: &[u8]) -> Result<ArtifactRef, StackError> {
            panic!("unexpected write")
        }
        async fn put_immutable(&self, _: &str, _: &[u8]) -> Result<ArtifactRef, StackError> {
            panic!("unexpected immutable write")
        }
        async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
            let mut bytes = self.0.get(reference).await?;
            if let Some(bytes) = &mut bytes {
                bytes[0] ^= 1;
            }
            Ok(bytes)
        }
    }
    let (source, lookup, _) = committed_state("neutral-proof").await;
    let mut tampered = source.clone();
    tampered.artifact_store = Arc::new(TamperedProof(source.artifact_store.clone()));
    assert_eq!(
        crate::reconciliation::reconcile(&tampered, "scope-a", &lookup).await,
        AppendReconciliation::Unknown {
            reason: ReconciliationUnknown::VerificationFailed
        }
    );
    let mut changed = test_state();
    changed.repository = source.repository.clone();
    changed.artifact_store = Arc::new(ReadOnlyArtifacts(source.artifact_store.clone()));
    let mut record = source
        .bundles
        .get_by_seal(b"scope-a", 1)
        .await
        .unwrap()
        .unwrap();
    record.export_attempt_id = "sha256:changed-attempt".into();
    changed
        .bundles
        .insert_published_record(b"scope-a", &record, false)
        .await
        .unwrap();
    assert_eq!(
        crate::reconciliation::reconcile(&changed, "scope-a", &lookup).await,
        AppendReconciliation::Unknown {
            reason: ReconciliationUnknown::VerificationFailed
        }
    );
}

#[tokio::test]
async fn reconciliation_unsupported_store_is_unknown_without_unserialized_fallback() {
    struct Unsupported;
    #[async_trait]
    impl EventRepository for Unsupported {
        async fn list_scope(&self, _: &[u8]) -> Result<Vec<StoredEvent>, StackError> {
            panic!("unsupported snapshot must not fall back")
        }
        async fn append_event(&self, _: StoredEvent) -> Result<(), StackError> {
            panic!("unexpected append")
        }
    }
    let mut state = test_state();
    state.repository = Arc::new(Unsupported);
    let lookup = AppendReconciliationRequest {
        event_type: "neutral.event".into(),
        idempotency_key: "neutral-key".into(),
        content_hash: [0; 32],
    };
    assert_eq!(
        crate::reconciliation::reconcile(&state, "scope-a", &lookup).await,
        AppendReconciliation::Unknown {
            reason: ReconciliationUnknown::StoreUnavailable
        }
    );
}

#[tokio::test]
async fn reconciliation_route_requires_current_authentication_and_exact_scope_grant() {
    let state = test_state_scoped_production_like();
    let request = AppendReconciliationRequest {
        event_type: "neutral.event".into(),
        idempotency_key: "neutral-key".into(),
        content_hash: [0; 32],
    };
    let body = serde_json::to_vec(&request).unwrap();
    let path = "/v1/scopes/case_123/events/reconcile";
    let missing = router(state.clone())
        .unwrap()
        .oneshot(post_request(path, body.clone()))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let wrong = test_trellis_token(vec!["other_scope".into()]);
    let refused = router(state.clone())
        .unwrap()
        .oneshot(post_request_bearer(path, body.clone(), &wrong))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let admitted = test_trellis_token(vec!["case_123".into()]);
    let response = router(state)
        .unwrap()
        .oneshot(post_request_bearer(path, body, &admitted))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn reconciliation_route_reports_read_point_absence_without_publishing() {
    let state = test_state();
    let response = router(state.clone())
        .unwrap()
        .oneshot(post_request(
            "/v1/scopes/scope-a/events/reconcile",
            serde_json::to_vec(&serde_json::json!({
                "eventType": "wos.kernel.process_started",
                "idempotencyKey": "neutral-reconciliation-key",
                "contentHash": vec![0_u8; 32]
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "absent");
    assert_eq!(value["eventCount"], 0);
    assert!(
        state
            .repository
            .list_scope(b"scope-a")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        state
            .bundles
            .get_by_seal(b"scope-a", 1)
            .await
            .unwrap()
            .is_none()
    );
}
