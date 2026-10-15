// Controlled identity/permission tests, not live identity-provider qualification.
use super::*;
use stack_common_auth::{AccessTokenError, AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_http::tenant::TenantScope;
use std::sync::atomic::{AtomicBool, AtomicU8};
use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer};

struct CurrentVerifier {
    status: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl AccessTokenVerifier for CurrentVerifier {
    async fn verify(&self, token: &str) -> Result<VerifiedAccessIdentity, AccessTokenError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.status.load(Ordering::SeqCst) {
            1 => return Err(AccessTokenError::rejected()),
            2 => return Err(AccessTokenError::unavailable()),
            _ => {}
        }
        if token != "controlled-current-token" {
            return Err(AccessTokenError::rejected());
        }
        Ok(VerifiedAccessIdentity {
            issuer: "https://controlled-issuer.example".into(),
            subject: "producer-subject".into(),
            client_id: Some("producer-client".into()),
            scopes: Default::default(),
            expires_at: i64::MAX,
            token_id: None,
        })
    }
}

struct ExactGrants {
    allowed: Arc<AtomicBool>,
    administer: Arc<AtomicBool>,
    invalid_permit: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    principal: Arc<AtomicU8>,
    delegation: Arc<AtomicBool>,
}

fn denied() -> StackError {
    StackError::new(
        stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
        StatusCode::FORBIDDEN,
        "controlled grant denied",
    )
}

#[async_trait]
impl ScopeAuthorizer for ExactGrants {
    type Error = StackError;
    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, StackError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let identity = request.identity.ok_or_else(denied)?;
        if !self.allowed.load(Ordering::SeqCst)
            || identity.issuer != "https://controlled-issuer.example"
            || identity.subject != "producer-subject"
            || identity.client_id.as_deref() != Some("producer-client")
            || request.tenant_scope != &expected_tenant()
            || request.scope != b"case_123"
            || (request.action == ScopeAction::Administer
                && !self.administer.load(Ordering::SeqCst))
            || (request.action == ScopeAction::Append
                && request.append_body.is_none_or(|body| {
                    !self.delegation.load(Ordering::SeqCst)
                        || body.actor.subject != "wos-server"
                        || body
                            .payload
                            .get("actorId")
                            .is_some_and(|actor| actor.as_str() != Some("delegated-human"))
                }))
        {
            return Err(denied());
        }
        let mut permit = AuthorizedScope {
            principal: format!(
                "internal-producer-{}",
                self.principal.load(Ordering::SeqCst)
            ),
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        };
        match self.invalid_permit.load(Ordering::SeqCst) {
            1 => permit.principal.clear(),
            2 => permit.tenant_scope.workspace = "foreign-workspace".into(),
            3 => permit.scope = b"foreign-scope".to_vec(),
            4 => permit.action = ScopeAction::Read,
            5 if request.action == ScopeAction::Administer => {
                permit.principal = "changed-principal".into()
            }
            _ => {}
        }
        Ok(permit)
    }
}

fn expected_tenant() -> TenantScope {
    TenantScope {
        tenant: "tenant-a".into(),
        workspace: "workspace-a".into(),
        environment: "prod".into(),
        cell: "cell-a".into(),
    }
}

struct Controls {
    verifier: Arc<AtomicU8>,
    verification_calls: Arc<AtomicUsize>,
    grants: Arc<AtomicBool>,
    administer: Arc<AtomicBool>,
    invalid_permit: Arc<AtomicU8>,
    grant_calls: Arc<AtomicUsize>,
    principal: Arc<AtomicU8>,
    delegation: Arc<AtomicBool>,
}

fn external_state() -> (TrellisServerState, Controls) {
    let controls = Controls {
        verifier: Arc::new(AtomicU8::new(0)),
        verification_calls: Arc::new(AtomicUsize::new(0)),
        grants: Arc::new(AtomicBool::new(true)),
        administer: Arc::new(AtomicBool::new(false)),
        invalid_permit: Arc::new(AtomicU8::new(0)),
        grant_calls: Arc::new(AtomicUsize::new(0)),
        principal: Arc::new(AtomicU8::new(17)),
        delegation: Arc::new(AtomicBool::new(true)),
    };
    let state = TrellisServerState::new(
        Arc::new(InMemoryEventRepository::new()),
        test_signing_key(),
        TenantHeaderMode::MultiProducer,
    )
    .with_access_token_verifier(Arc::new(CurrentVerifier {
        status: controls.verifier.clone(),
        calls: controls.verification_calls.clone(),
    }))
    .with_scope_authorizer(Arc::new(ExactGrants {
        allowed: controls.grants.clone(),
        administer: controls.administer.clone(),
        invalid_permit: controls.invalid_permit.clone(),
        calls: controls.grant_calls.clone(),
        principal: controls.principal.clone(),
        delegation: controls.delegation.clone(),
    }))
    .with_production_like_scope_posture(true);
    (state, controls)
}

#[tokio::test]
async fn retained_head_read_returns_the_exact_current_publication_without_administer() {
    let (state, _) = external_state();
    let app = router(state).unwrap();
    let appended = app
        .clone()
        .oneshot(request(append_body("retained-head-read")))
        .await
        .unwrap();
    assert_eq!(appended.status(), StatusCode::CREATED);
    let receipt: SubstrateAppendResult =
        serde_json::from_slice(&to_bytes(appended.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let mut head = get_request("/v1/scopes/case_123/bundles/head");
    head.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    let response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let actual = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let mut pinned = get_request(&format!(
        "/v1/scopes/case_123/bundles/{}",
        receipt.checkpoint_ref.rsplit('/').next().unwrap()
    ));
    pinned.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    let expected = app.oneshot(pinned).await.unwrap();
    assert_eq!(expected.status(), StatusCode::OK);
    assert_eq!(
        actual,
        to_bytes(expected.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap()
    );
}

fn request(body: Vec<u8>) -> Request<Body> {
    post_request_bearer(
        "/v1/scopes/case_123/events",
        body,
        "controlled-current-token",
    )
}

fn head_request() -> Request<Body> {
    let mut request = get_request("/v1/scopes/case_123/bundles/head");
    request.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    request
}

struct HeadReadStore {
    inner: Arc<dyn ArtifactStore<Error = StackError>>,
    mode: u8,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
    grants: Arc<AtomicBool>,
    principal: Arc<AtomicU8>,
}

#[async_trait]
impl ArtifactStore for HeadReadStore {
    type Error = StackError;
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put(key, bytes).await
    }
    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put_immutable(key, bytes).await
    }
    async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.mode == 1 {
            return Ok(None);
        }
        let mut bytes = self.inner.get(reference).await?;
        if self.mode == 2 || (self.mode == 5 && read > 0) {
            bytes.as_mut().unwrap()[0] ^= 1;
        }
        if self.mode == 3 {
            self.grants.store(false, Ordering::SeqCst);
        }
        if self.mode == 4 {
            self.principal.store(18, Ordering::SeqCst);
        }
        Ok(bytes)
    }
}

struct HeadReadIndex {
    inner: Arc<dyn crate::artifacts::BundleIndexPort>,
    fault: u8,
}

#[async_trait]
impl crate::artifacts::BundleIndexPort for HeadReadIndex {
    async fn reserve_publishable(
        &self,
        _: &[u8],
        _: &crate::artifacts::BundleIdentity,
    ) -> Result<(), StackError> {
        panic!("retained head read attempted publication reservation")
    }
    async fn insert_published_record(
        &self,
        _: &[u8],
        _: &crate::artifacts::BundleRecord,
        _: bool,
    ) -> Result<(), StackError> {
        panic!("retained head read attempted index mutation")
    }
    async fn get_by_digest(
        &self,
        scope: &[u8],
        digest: &str,
    ) -> Result<Option<crate::artifacts::BundleRecord>, StackError> {
        self.inner.get_by_digest(scope, digest).await
    }
    async fn get_by_seal(
        &self,
        scope: &[u8],
        seal: u64,
    ) -> Result<Option<crate::artifacts::BundleRecord>, StackError> {
        let mut record = self.inner.get_by_seal(scope, seal).await?;
        if let Some(record) = &mut record {
            match self.fault {
                1 => record.seal_version += 1,
                2 => record.export_attempt_id.push_str("foreign"),
                3 => record.checkpoint_digest = format!("sha256:{}", "f".repeat(64)),
                _ => {}
            }
        }
        Ok(record)
    }
}

async fn retained_head_fixture(
    mode: u8,
    fault: u8,
) -> (
    TrellisServerState,
    Controls,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let (mut state, controls) = external_state();
    let response = router(state.clone())
        .unwrap()
        .oneshot(request(append_body("head-read-fixture")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    state.artifact_store = Arc::new(HeadReadStore {
        inner: state.artifact_store,
        mode,
        reads: reads.clone(),
        writes: writes.clone(),
        grants: controls.grants.clone(),
        principal: controls.principal.clone(),
    });
    state.bundles = Arc::new(HeadReadIndex {
        inner: state.bundles,
        fault,
    });
    (state, controls, reads, writes)
}

#[tokio::test]
async fn retained_head_read_has_no_writes_and_returns_the_single_verified_fetch() {
    for mode in [0, 5] {
        let (state, _, reads, writes) = retained_head_fixture(mode, 0).await;
        let response = router(state)
            .unwrap()
            .oneshot(head_request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap();
        assert!(export_bundle_cryptographically_verified(&bytes));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn retained_head_read_refuses_missing_corrupt_and_revoked_evidence_without_publication() {
    for (mode, expected) in [
        (1, StatusCode::SERVICE_UNAVAILABLE),
        (2, StatusCode::CONFLICT),
        (3, StatusCode::FORBIDDEN),
        (4, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let (state, _, reads, writes) = retained_head_fixture(mode, 0).await;
        let response = router(state)
            .unwrap()
            .oneshot(head_request())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "mode {mode}");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn retained_head_read_refuses_changed_seal_attempt_or_checkpoint_without_publication() {
    for fault in 1..=3 {
        let (state, _, _, writes) = retained_head_fixture(0, fault).await;
        assert_eq!(
            router(state)
                .unwrap()
                .oneshot(head_request())
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn retained_head_read_refuses_foreign_scope_before_artifact_access() {
    let (state, _, reads, writes) = retained_head_fixture(0, 0).await;
    let mut request = head_request();
    *request.uri_mut() = "/v1/scopes/foreign-scope/bundles/head".parse().unwrap();
    assert_eq!(
        router(state)
            .unwrap()
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retained_head_missing_publication_still_requires_administer() {
    let (mut state, controls, _, writes) = retained_head_fixture(0, 0).await;
    state.bundles = Arc::new(crate::artifacts::BundleIndex::default());
    let app = router(state.clone()).unwrap();
    assert_eq!(
        app.clone().oneshot(head_request()).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    controls.administer.store(true, Ordering::SeqCst);
    assert_eq!(
        app.oneshot(head_request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(writes.load(Ordering::SeqCst) > 0);
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
async fn retained_head_read_never_substitutes_an_older_publication_for_a_later_unpublished_event() {
    let (mut state, _, _, writes) = retained_head_fixture(0, 0).await;
    // Keep only the old seal while a second committed event lacks its publication.
    let first = state
        .bundles
        .get_by_seal(b"case_123", 1)
        .await
        .unwrap()
        .unwrap();
    let index = Arc::new(crate::artifacts::BundleIndex::default());
    use crate::artifacts::BundleIndexPort;
    index
        .insert_published_record(b"case_123", &first, true)
        .await
        .unwrap();
    let source = test_state();
    for key in ["head-read-fixture", "later-uncertain-record"] {
        let body: SubstrateAppendBody = serde_json::from_slice(&append_body(key)).unwrap();
        source
            .append_coordinator()
            .append(append::AppendCommand {
                scope: "case_123".into(),
                event_type: body.event_type,
                idempotency_key: body.idempotency_key,
                payload: body.payload,
                compute_context: body.compute_context,
                client_attestation: None,
            })
            .await
            .unwrap();
    }
    state.repository = source.repository;
    state.bundles = Arc::new(HeadReadIndex {
        inner: index,
        fault: 0,
    });
    assert_eq!(
        router(state)
            .unwrap()
            .oneshot(head_request())
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authorized_append_replay_rechecks_current_identity_and_grants() {
    let (state, controls) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let body = append_body("current-authority-retry");
    let first = app.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let original = to_bytes(first.into_body(), 64 * 1024).await.unwrap();
    let replay = app.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers().get("x-replay").unwrap(), "true");
    assert_eq!(
        to_bytes(replay.into_body(), 64 * 1024).await.unwrap(),
        original
    );
    controls.verifier.store(1, Ordering::SeqCst);
    let rejected = app.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert!(!rejected.headers().contains_key("x-replay"));
    controls.verifier.store(2, Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    controls.verifier.store(0, Ordering::SeqCst);
    controls.grants.store(false, Ordering::SeqCst);
    let forbidden = app.oneshot(request(body)).await.unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert!(!forbidden.headers().contains_key("x-replay"));
    assert_eq!(controls.verification_calls.load(Ordering::SeqCst), 5);
    assert_eq!(controls.grant_calls.load(Ordering::SeqCst), 3);
    assert_eq!(repository.list_scope(b"case_123").await.unwrap().len(), 1);
}

#[tokio::test]
async fn authorized_append_replay_refuses_each_foreign_tenant_and_actor() {
    let (state, _) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let body = append_body("exact-grants");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    for header in [
        "x-wos-tenant-id",
        "x-wos-workspace-id",
        "x-wos-environment-id",
        "x-wos-cell-id",
    ] {
        let mut foreign = request(body.clone());
        foreign
            .headers_mut()
            .insert(header, "foreign".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(foreign).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut actor: SubstrateAppendBody = serde_json::from_slice(&body).unwrap();
    actor.actor.subject = "ungranted-producer".into();
    assert_eq!(
        app.oneshot(request(serde_json::to_vec(&actor).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(repository.list_scope(b"case_123").await.unwrap().len(), 1);
}

#[tokio::test]
async fn authorized_append_replay_refuses_mismatched_authorizer_result() {
    let (state, controls) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    for invalid in 1..=4 {
        controls.invalid_permit.store(invalid, Ordering::SeqCst);
        assert_eq!(
            app.clone()
                .oneshot(request(append_body("foreign-permit")))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert!(repository.list_scope(b"case_123").await.unwrap().is_empty());
}

#[tokio::test]
async fn authorized_append_replay_retained_head_is_readable_without_administer() {
    let (state, controls) = external_state();
    let app = router(state).unwrap();
    let appended = app
        .clone()
        .oneshot(request(append_body("head-admin")))
        .await
        .unwrap();
    assert_eq!(appended.status(), StatusCode::CREATED);
    let receipt: SubstrateAppendResult =
        serde_json::from_slice(&to_bytes(appended.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let mut head = get_request("/v1/scopes/case_123/bundles/head");
    head.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(head).await.unwrap().status(),
        StatusCode::OK
    );
    let mut pinned = get_request(&format!(
        "/v1/scopes/case_123/bundles/{}",
        receipt.checkpoint_ref.rsplit('/').next().unwrap()
    ));
    pinned.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(pinned).await.unwrap().status(),
        StatusCode::OK
    );
    controls.administer.store(true, Ordering::SeqCst);
    let mut head = get_request("/v1/scopes/case_123/bundles/head");
    head.headers_mut().insert(
        "authorization",
        "Bearer controlled-current-token".parse().unwrap(),
    );
    assert_eq!(app.oneshot(head).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn authorized_append_replay_refuses_ungranted_payload_human() {
    let (state, _) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let mut body: SubstrateAppendBody =
        serde_json::from_slice(&append_body("human-delegation")).unwrap();
    body.payload["actorId"] = serde_json::json!("delegated-human");
    assert_eq!(
        app.clone()
            .oneshot(request(serde_json::to_vec(&body).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    body.payload["actorId"] = serde_json::json!("ungranted-human");
    assert_eq!(
        app.oneshot(request(serde_json::to_vec(&body).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(repository.list_scope(b"case_123").await.unwrap().len(), 1);
}

#[test]
fn authorized_append_replay_external_mode_requires_injected_host_grants() {
    let state = TrellisServerState::new(
        Arc::new(InMemoryEventRepository::new()),
        test_signing_key(),
        TenantHeaderMode::MultiProducer,
    )
    .with_access_token_verifier(Arc::new(CurrentVerifier {
        status: Arc::new(AtomicU8::new(0)),
        calls: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(router(state).is_err());
}

#[tokio::test]
async fn authorized_append_replay_external_mode_has_no_local_jwt_fallback() {
    let (state, _) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let local = test_trellis_token(vec!["case_123".into()]);
    assert_eq!(
        app.oneshot(post_request_bearer(
            "/v1/scopes/case_123/events",
            append_body("no-local-fallback"),
            &local
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(repository.list_scope(b"case_123").await.unwrap().is_empty());
}

#[tokio::test]
async fn authorized_append_replay_separates_two_admitted_principals() {
    let (state, controls) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let body = append_body("partition-principals");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    controls.principal.store(18, Ordering::SeqCst);
    let second = app.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
    assert!(!second.headers().contains_key("x-replay"));
    let second_replay = app.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(second_replay.headers().get("x-replay").unwrap(), "true");
    controls.principal.store(17, Ordering::SeqCst);
    let first_replay = app.oneshot(request(body)).await.unwrap();
    assert_eq!(first_replay.headers().get("x-replay").unwrap(), "true");
    assert_eq!(repository.list_scope(b"case_123").await.unwrap().len(), 1);
}

#[tokio::test]
async fn authorized_append_replay_rechecks_delegation_for_unchanged_body() {
    let (state, controls) = external_state();
    let app = router(state).unwrap();
    let body = append_body("revoked-delegation");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    controls.delegation.store(false, Ordering::SeqCst);
    let refused = app.oneshot(request(body)).await.unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(!refused.headers().contains_key("x-replay"));
}

#[tokio::test]
async fn authorized_append_replay_publication_refuses_changed_principal_and_pinned_miss() {
    let (state, controls) = external_state();
    let publication_calls = Arc::new(AtomicUsize::new(0));
    struct CountingPublicationStore {
        inner: crate::artifacts::InMemoryArtifactStore,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ArtifactStore for CountingPublicationStore {
        type Error = StackError;
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.put(key, bytes).await
        }
        async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.put_immutable(key, bytes).await
        }
        async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
            self.inner.get(reference).await
        }
    }
    let mut state = state.with_artifact_store(Arc::new(CountingPublicationStore {
        inner: crate::artifacts::InMemoryArtifactStore::default(),
        calls: publication_calls.clone(),
    }));
    let app = router(state.clone()).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(append_body("publication-grants")))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let baseline = publication_calls.load(Ordering::SeqCst);
    assert!(baseline > 0);
    // Exercise publication misses, rather than the already-retained read path.
    state.bundles = Arc::new(crate::artifacts::BundleIndex::default());
    let app = router(state).unwrap();
    let missing = format!("/v1/scopes/case_123/bundles/{}", "a".repeat(64));
    for path in ["/v1/scopes/case_123/bundles/head", &missing] {
        let mut read_only = get_request(path);
        read_only.headers_mut().insert(
            "authorization",
            "Bearer controlled-current-token".parse().unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(read_only).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    controls.administer.store(true, Ordering::SeqCst);
    controls.invalid_permit.store(5, Ordering::SeqCst);
    for path in ["/v1/scopes/case_123/bundles/head", &missing] {
        let mut changed = get_request(path);
        changed.headers_mut().insert(
            "authorization",
            "Bearer controlled-current-token".parse().unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(changed).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(publication_calls.load(Ordering::SeqCst), baseline);
}

#[tokio::test]
async fn authorized_append_replay_hashes_original_body_bytes() {
    let (state, _) = external_state();
    let app = router(state).unwrap();
    let body = append_body("raw-body-hash");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_ne!(pretty, body);
    assert_eq!(
        app.oneshot(request(pretty)).await.unwrap().status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn authorized_append_replay_preserves_json_rejections_without_append() {
    let (state, _) = external_state();
    let repository = state.repository.clone();
    let app = router(state).unwrap();
    let valid = append_body("parse-rejections");
    for (content_type, bytes, expected) in [
        (
            "text/plain",
            valid.clone(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        ("application/json", b"{".to_vec(), StatusCode::BAD_REQUEST),
        (
            "application/json",
            b"{}".to_vec(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "application/json",
            vec![b' '; 2 * 1024 * 1024 + 1],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let mut malformed = request(valid.clone());
        malformed
            .headers_mut()
            .insert("content-type", content_type.parse().unwrap());
        *malformed.body_mut() = Body::from(bytes);
        assert_eq!(
            app.clone().oneshot(malformed).await.unwrap().status(),
            expected
        );
    }
    assert!(repository.list_scope(b"case_123").await.unwrap().is_empty());
}
