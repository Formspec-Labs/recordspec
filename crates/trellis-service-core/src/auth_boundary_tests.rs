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
        crate::test_adapters::adapters(),
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
async fn head_export_read_equals_the_export_pinned_at_the_head_checkpoint_without_administer() {
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

/// Reads the head export while `Read` authority changes mid-request, counting the export reads.
async fn head_read_with_authority_change(
    change: impl Fn(&Controls) + Send + Sync + 'static,
) -> (StatusCode, usize) {
    use crate::repository_probes::{FaultyRepository, Fault};
    let (mut state, controls) = external_state();
    let response = router(state.clone())
        .unwrap()
        .oneshot(request(append_body("head-read-fixture")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    state.repository = Arc::new(FaultyRepository {
        inner: state.repository,
        fault: Arc::new(Fault::AfterExportRows(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            change(&controls);
        }))),
    });
    let status = router(state)
        .unwrap()
        .oneshot(head_request())
        .await
        .unwrap()
        .status();
    (status, reads.load(Ordering::SeqCst))
}

#[tokio::test]
async fn head_export_read_returns_a_verifiable_export_and_writes_nothing() {
    let (state, _) = external_state();
    let counts = Arc::new(crate::repository_probes::Counts::default());
    let state = state.with_artifact_store(Arc::new(crate::repository_probes::CountingArtifactStore {
        inner: Arc::new(crate::artifacts::InMemoryArtifactStore::default()),
        counts: counts.clone(),
    }));
    let app = router(state).unwrap();
    let appended = app
        .clone()
        .oneshot(request(append_body("head-read-fixture")))
        .await
        .unwrap();
    assert_eq!(appended.status(), StatusCode::CREATED);
    let response = app.oneshot(head_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    assert!(export_bundle_cryptographically_verified(&bytes));
    assert_eq!(counts.snapshot()[3], 0, "neither the append nor the read writes objects");
}

#[tokio::test]
async fn head_export_read_is_refused_when_read_authority_changes_while_it_is_assembled() {
    // Grants revoked mid-read: the export is assembled but never disclosed.
    let (status, reads) =
        head_read_with_authority_change(|c| c.grants.store(false, Ordering::SeqCst)).await;
    assert_eq!((status, reads), (StatusCode::FORBIDDEN, 1));
    // A different principal admitted mid-read: the same refusal as any changed authority.
    let (status, reads) =
        head_read_with_authority_change(|c| c.principal.store(18, Ordering::SeqCst)).await;
    assert_eq!((status, reads), (StatusCode::SERVICE_UNAVAILABLE, 1));
}

#[tokio::test]
async fn head_export_read_refuses_a_foreign_scope_before_reading_the_ledger() {
    use crate::repository_probes::{FaultyRepository, Fault};
    let (mut state, _) = external_state();
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    state.repository = Arc::new(FaultyRepository {
        inner: state.repository,
        fault: Arc::new(Fault::AfterExportRows(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }))),
    });
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
        crate::test_adapters::adapters(),
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
async fn export_reads_need_only_read_and_refuse_a_permit_for_another_resource() {
    let (state, controls) = external_state();
    let app = router(state).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(append_body("publication-grants")))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let missing = format!("/v1/scopes/case_123/bundles/{}", "a".repeat(64));
    let read = |path: &str| {
        let mut read_only = get_request(path);
        read_only.headers_mut().insert(
            "authorization",
            "Bearer controlled-current-token".parse().unwrap(),
        );
        read_only
    };
    // Read alone serves the head; a digest the scope never issued is simply absent.
    assert_eq!(
        app.clone()
            .oneshot(read("/v1/scopes/case_123/bundles/head"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(read(&missing)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // An authorizer that admits a different resource than the one asked for is refused.
    controls.invalid_permit.store(3, Ordering::SeqCst);
    for path in ["/v1/scopes/case_123/bundles/head", &missing] {
        assert_eq!(
            app.clone().oneshot(read(path)).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
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
