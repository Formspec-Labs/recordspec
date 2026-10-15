// Cross-process transport qualification with neutral fixture facts and disposable TLS storage.
// This does not establish actual Source acceptance, live grant authority or deployment readiness.
use super::*;
use stack_common_auth::{
    AccessTokenError, AccessTokenVerifier, ClientCredentialsTokenProvider, ServiceAccessToken,
    TokenAcquisitionError, VerifiedAccessIdentity,
};
use stack_common_http::tenant::{HeaderConfig, TenantScope};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trellis_server_ports::{
    ArtifactStore, AuthorizedScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer,
};
use trellis_service_client::{
    AcceptedAttachmentAppendBody, AppendActor, SubstrateClient, TrellisServiceClient,
    TrellisServiceClientConfig,
};
mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

fn tenant() -> TenantScope {
    TenantScope {
        tenant: "native-test".into(),
        workspace: "workspace".into(),
        environment: "test".into(),
        cell: "cell".into(),
    }
}
struct CurrentToken {
    token: String,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl ClientCredentialsTokenProvider for CurrentToken {
    async fn access_token(&self) -> Result<ServiceAccessToken, TokenAcquisitionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ServiceAccessToken::new(self.token.clone(), i64::MAX)
    }
}
struct Verifier;
#[async_trait]
impl AccessTokenVerifier for Verifier {
    async fn verify(&self, token: &str) -> Result<VerifiedAccessIdentity, AccessTokenError> {
        if !["all", "no-append", "no-read", "no-admin"].contains(&token) {
            return Err(AccessTokenError::rejected());
        }
        Ok(VerifiedAccessIdentity {
            issuer: "https://controlled-transport.example".into(),
            subject: "controlled-producer".into(),
            client_id: Some("controlled-client".into()),
            scopes: [token.to_owned()].into_iter().collect(),
            expires_at: i64::MAX,
            token_id: None,
        })
    }
}
struct Grants(TenantScope);
#[async_trait]
impl ScopeAuthorizer for Grants {
    type Error = StackError;
    async fn authorize(&self, r: &ScopeAuthorization<'_>) -> Result<AuthorizedScope, StackError> {
        let valid = r.identity.is_some_and(|i| {
            i.issuer == "https://controlled-transport.example"
                && i.subject == "controlled-producer"
                && i.client_id.as_deref() == Some("controlled-client")
                && !(r.action == ScopeAction::Append && i.scopes.contains("no-append"))
                && !(r.action == ScopeAction::Read && i.scopes.contains("no-read"))
                && !(r.action == ScopeAction::Administer && i.scopes.contains("no-admin"))
        });
        let actor = r.action != ScopeAction::Append
            || r.append_body
                .is_some_and(|b| b.actor.kind == "service" && b.actor.subject == "formspec-server");
        if !valid || !actor || r.tenant_scope != &self.0 || r.scope != b"case_123" {
            return Err(StackError::new(
                stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
                StatusCode::FORBIDDEN,
                "controlled exact scope permission refused",
            ));
        }
        Ok(AuthorizedScope {
            principal: "controlled-producer".into(),
            tenant_scope: r.tenant_scope.clone(),
            scope: r.scope.to_vec(),
            action: r.action,
        })
    }
}
struct Recipients(PathBuf);
#[async_trait]
impl crate::ExternalAttachmentRecipientSelector for Recipients {
    async fn select(
        &self,
        _permit: &AuthorizedScope,
        _descriptor: &trellis_admission_formspec::accepted_attachment::AcceptedAttachmentDescriptor,
    ) -> Result<Vec<crate::ExternalAttachmentRecipient>, StackError> {
        // Public X25519 key derived from fixture seed [17;32]; not production key material.
        let mut public: [u8; 32] =
            hex::decode("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13")
                .unwrap()
                .try_into()
                .unwrap();
        let policy =
            std::fs::read_to_string(&self.0).map_err(|e| StackError::unavailable(e.to_string()))?;
        if policy == "changed-key" {
            public[0] ^= 1;
        }
        let id = if policy == "changed-id" {
            b"new-reader".to_vec()
        } else {
            b"fixture-reader".to_vec()
        };
        Ok(vec![crate::ExternalAttachmentRecipient {
            id,
            public_key: public,
            operator_held: false,
        }])
    }
}
struct CountedOsRandom {
    path: PathBuf,
    lock: std::sync::Mutex<()>,
}
impl integrity_seam::SecureRandom for CountedOsRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| std::io::Error::other("random counter poisoned"))?;
        integrity_seam::SecureRandom::fill_bytes(&integrity_seam::OsSecureRandom, dest)?;
        let count = std::fs::read_to_string(&self.path)?.parse::<usize>()?;
        std::fs::write(&self.path, (count + 1).to_string())?;
        Ok(())
    }
}
struct FileArtifacts(PathBuf);
impl FileArtifacts {
    fn path(&self, key: &str) -> Result<PathBuf, StackError> {
        if key.is_empty()
            || key.starts_with('/')
            || key.split('/').any(|p| p == ".." || p.is_empty())
        {
            return Err(StackError::bad_request("invalid test artifact key"));
        }
        Ok(self.0.join(key))
    }
}
#[async_trait]
impl ArtifactStore for FileArtifacts {
    type Error = StackError;
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        if trellis_server_ports::artifact_key_requires_immutable_put(key) {
            return Err(StackError::conflict(
                "immutable bundle requires immutable put",
            ));
        }
        let path = self.path(key)?;
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|e| StackError::unavailable(e.to_string()))?;
        std::fs::write(path, bytes).map_err(|e| StackError::unavailable(e.to_string()))?;
        Ok(ArtifactRef::new(format!("test-file:{key}")))
    }
    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, StackError> {
        if self.0.parent().unwrap().join("fail-publication").exists() {
            return Err(StackError::unavailable(
                "controlled immutable publication failure",
            ));
        }
        use std::io::Write;
        let path = self.path(key)?;
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|e| StackError::unavailable(e.to_string()))?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| StackError::unavailable(e.to_string()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::fs::read(&path).map_err(|e| StackError::unavailable(e.to_string()))?
                    != bytes
                {
                    return Err(StackError::conflict("immutable artifact bytes changed"));
                }
            }
            Err(e) => return Err(StackError::unavailable(e.to_string())),
        }
        Ok(ArtifactRef::new(format!("test-file:{key}")))
    }
    async fn get(&self, reference: &ArtifactRef) -> Result<Option<Vec<u8>>, StackError> {
        let key = reference
            .uri
            .strip_prefix("test-file:")
            .ok_or_else(|| StackError::bad_request("invalid test artifact reference"))?;
        match std::fs::read(self.path(key)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StackError::unavailable(e.to_string())),
        }
    }
}

#[tokio::test]
#[ignore = "Child process fixture; launched only by cross_process_native_transport_qualification"]
async fn native_transport_child_server() {
    let database = std::env::var("TRELLIS_NATIVE_TEST_DATABASE").expect("disposable database");
    let root = PathBuf::from(std::env::var("TRELLIS_NATIVE_TEST_ROOT").unwrap());
    let port: u16 = std::env::var("TRELLIS_NATIVE_TEST_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let pool = sqlx::PgPool::connect(&database).await.unwrap();
    trellis_store_postgres_async::run_migrations(&pool)
        .await
        .unwrap();
    let configured_tenant = if root.join("tenant.json").exists() {
        serde_json::from_slice(&std::fs::read(root.join("tenant.json")).unwrap()).unwrap()
    } else {
        tenant()
    };
    let mut state = TrellisServerState::new(
        Arc::new(PostgresEventRepository::new(pool.clone())),
        test_signing_key(),
        TenantHeaderMode::MultiProducer,
    )
    .with_bundle_index(Arc::new(crate::event_repository::PostgresBundleIndex::new(
        pool,
    )))
    .with_artifact_store(Arc::new(FileArtifacts(root.join("artifacts"))))
    .with_access_token_verifier(Arc::new(Verifier))
    .with_scope_authorizer(Arc::new(Grants(configured_tenant)))
    .with_production_like_scope_posture(true)
    .with_external_attachment_recipients(Arc::new(Recipients(root.join("policy"))));
    state.external_attachment_random = Arc::new(CountedOsRandom {
        path: root.join("random-count"),
        lock: std::sync::Mutex::new(()),
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    axum::serve(listener, router(state).unwrap()).await.unwrap();
}
struct ChildServer(Child);
impl Drop for ChildServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn start_child(root: &Path, database: &str, port: u16) -> ChildServer {
    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("child.log"))
        .unwrap();
    // Inherits the native operation's owned process group, including deadline cleanup.
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::external_transport_tests::native_transport_child_server",
            "--ignored",
            "--nocapture",
        ])
        .env("TRELLIS_NATIVE_TEST_DATABASE", database)
        .env("TRELLIS_NATIVE_TEST_ROOT", root)
        .env("TRELLIS_NATIVE_TEST_PORT", port.to_string())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut server = ChildServer(child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "child server exited; see {}",
            root.join("child.log").display()
        );
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return server;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "child startup timed out"
        );
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
}
fn client(endpoint: &str, token: &str, calls: Arc<AtomicUsize>) -> TrellisServiceClient {
    TrellisServiceClient::new(TrellisServiceClientConfig::new(
        endpoint,
        HeaderConfig::formspec(),
    ))
    .unwrap()
    .with_token_provider(Arc::new(CurrentToken {
        token: token.into(),
        calls,
    }))
    .unwrap()
}
async fn raw_status(
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    token: &str,
    key: &str,
) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nidempotency-key: {key}\r\nx-formspec-tenant-id: native-test\r\nx-formspec-workspace-id: workspace\r\nx-formspec-environment-id: test\r\nx-formspec-cell-id: cell\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    std::str::from_utf8(&bytes)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn verify_and_open(zip: &[u8], original: &[u8], public: [u8; 32]) {
    let report = integrity_verify::trellis::verify_export_zip(zip);
    assert!(
        report.structure_verified && report.integrity_verified,
        "{report:?}"
    );
    assert!(
        !report.readability_verified,
        "generic verification alone cannot open protected originals"
    );
    let entries = integrity_bundle::read_stored_zip(zip).unwrap();
    let event_member = entries
        .iter()
        .find(|e| e.path().ends_with(trellis_export_writer::EVENTS_MEMBER))
        .expect("signed event array member");
    let events = integrity_cbor::decode_cbor_value(event_member.bytes()).unwrap();
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 1);
    let signed_bytes = integrity_cbor::encode_cbor_value(&events[0]).unwrap();
    let signed = signed_bytes.as_slice();
    let body = entries
        .iter()
        .find(|e| e.path().contains("060-payloads/") && e.path().ends_with(".bin"))
        .expect("protected body member")
        .bytes();
    let limits = integrity_hpke::external_attachment::ProtectionLimits {
        original_bytes: 1024 * 1024,
        recipients: 64,
        recipient_id_bytes: 256,
    };
    let opened = trellis_core::external_attachment::open_native_external_attachment(
        public,
        signed,
        body,
        b"fixture-reader",
        &[17; 32],
        limits,
        64 * 1024,
    )
    .unwrap();
    assert_eq!(opened, original);
    assert_eq!(
        integrity_cbor::sha256_bytes(&opened),
        integrity_cbor::sha256_bytes(original)
    );
    assert!(
        trellis_core::external_attachment::open_native_external_attachment(
            public,
            signed,
            body,
            b"fixture-reader",
            &[18; 32],
            limits,
            64 * 1024
        )
        .is_err()
    );
    let mut tampered = body.to_vec();
    tampered[0] ^= 1;
    assert!(
        trellis_core::external_attachment::open_native_external_attachment(
            public,
            signed,
            &tampered,
            b"fixture-reader",
            &[17; 32],
            limits,
            64 * 1024
        )
        .is_err()
    );
}

#[tokio::test]
async fn cross_process_native_transport_qualification() {
    let cluster = support::TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(4).await;
    let database = format!(
        "postgres://postgres@127.0.0.1:{}/postgres?sslmode=require",
        pool.connect_options().get_port()
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("policy"), "reader").unwrap();
    std::fs::write(root.join("random-count"), "0").unwrap();
    let reserve = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let mut server = Some(start_child(root, &database, port).await);
    let endpoint = format!("http://127.0.0.1:{port}");
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = client(&endpoint, "all", calls.clone());
    let (descriptor, _input, original) = super::external_attachment_tests::external_fixture_input();
    let body = AcceptedAttachmentAppendBody {
        idempotency_key: "transport-native-047".into(),
        actor: AppendActor::service("formspec-server"),
        descriptor: serde_json::to_value(descriptor).unwrap(),
        original_bytes: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &original,
        ),
    };
    // Publication fails after the durable native event/body commit, before a receipt exists.
    std::fs::write(root.join("fail-publication"), "controlled fault").unwrap();
    let failure = transport
        .append_accepted_attachment("case_123", &tenant(), &body)
        .await
        .unwrap_err();
    assert_eq!(failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    let after_failure: i64 = sqlx::query_scalar("SELECT count(*) FROM trellis_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after_failure, 1);
    let initial_row:(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=sqlx::query_as("SELECT e.canonical_event,e.signed_event,a.ciphertext,a.nonce FROM trellis_events e JOIN trellis_external_attachments a ON a.scope=e.scope AND a.sequence=e.sequence WHERE e.scope=$1").bind(b"case_123".as_slice()).fetch_one(&pool).await.unwrap();
    let failure_entropy = std::fs::read_to_string(root.join("random-count")).unwrap();
    assert!(failure_entropy.parse::<usize>().unwrap() > 0);
    let mut changed = body.clone();
    changed.descriptor["acceptedActorRef"] =
        serde_json::json!("actor:human:changed-neutral-fixture");
    assert_eq!(
        raw_status(
            port,
            "POST",
            "/v1/scopes/case_123/accepted-attachments",
            &serde_json::to_string(&changed).unwrap(),
            "all",
            &body.idempotency_key
        )
        .await,
        409
    );
    assert_eq!(
        std::fs::read_to_string(root.join("random-count")).unwrap(),
        failure_entropy
    );
    std::fs::remove_file(root.join("fail-publication")).unwrap();
    let first = transport
        .append_accepted_attachment("case_123", &tenant(), &body)
        .await
        .unwrap();
    let checkpoint = first.checkpoint_ref.rsplit('/').next().unwrap();
    let pinned = transport
        .bundle("case_123", checkpoint, &tenant())
        .await
        .unwrap();
    let head = transport.head_bundle("case_123", &tenant()).await.unwrap();
    assert_eq!(pinned, head);
    let public = trellis_cddl::parse_ed25519_cose_key(test_signing_key().core_key().as_bytes())
        .unwrap()
        .public_key;
    verify_and_open(&pinned, &original, public);
    let count = std::fs::read_to_string(root.join("random-count")).unwrap();
    assert!(count.parse::<usize>().unwrap() > 0);
    assert_eq!(
        count, failure_entropy,
        "exact retry after publication failure must retain protection"
    );
    assert_eq!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        std::fs::read_to_string(root.join("random-count")).unwrap(),
        count
    );
    // Current policy must be checked before a cached successful HTTP response.
    std::fs::write(root.join("policy"), "changed-key").unwrap();
    assert!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .is_err()
    );
    std::fs::write(root.join("policy"), "changed-id").unwrap();
    assert!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .is_err()
    );
    drop(server.take());
    server = Some(start_child(root, &database, port).await);
    // This retry has no process-local HTTP cache and still refuses the changed selection.
    assert!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .is_err()
    );
    std::fs::write(root.join("policy"), "reader").unwrap();
    assert_eq!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        transport
            .bundle("case_123", checkpoint, &tenant())
            .await
            .unwrap(),
        pinned
    );
    assert_eq!(
        transport.head_bundle("case_123", &tenant()).await.unwrap(),
        pinned
    );
    assert_eq!(
        std::fs::read_to_string(root.join("random-count")).unwrap(),
        count
    );
    assert!(
        client(&endpoint, "no-append", calls.clone())
            .append_accepted_attachment("case_123", &tenant(), &body)
            .await
            .is_err()
    );
    assert!(
        client(&endpoint, "no-read", calls.clone())
            .bundle("case_123", checkpoint, &tenant())
            .await
            .is_err()
    );
    assert_eq!(
        client(&endpoint, "no-admin", calls.clone())
            .head_bundle("case_123", &tenant())
            .await
            .unwrap(),
        pinned
    );
    assert!(
        client(&endpoint, "no-read", calls.clone())
            .head_bundle("case_123", &tenant())
            .await
            .is_err()
    );
    assert!(
        transport
            .append_accepted_attachment("case_other", &tenant(), &body)
            .await
            .is_err()
    );
    let mut foreign = tenant();
    foreign.tenant = "foreign".into();
    assert!(
        transport
            .append_accepted_attachment("case_123", &foreign, &body)
            .await
            .is_err()
    );
    let request = serde_json::to_value(&body).unwrap();
    let mut unknown = request.clone();
    unknown["unknown"] = serde_json::Value::Bool(true);
    assert_eq!(
        raw_status(
            port,
            "POST",
            "/v1/scopes/case_123/accepted-attachments",
            &unknown.to_string(),
            "all",
            &body.idempotency_key
        )
        .await,
        400
    );
    let duplicate =
        request
            .to_string()
            .replacen("\"descriptor\":{", "\"descriptor\":{\"version\":1,", 1);
    assert_eq!(
        raw_status(
            port,
            "POST",
            "/v1/scopes/case_123/accepted-attachments",
            &duplicate,
            "all",
            &body.idempotency_key
        )
        .await,
        400
    );
    let mut wrong = body.clone();
    wrong.original_bytes = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"wrong-original",
    );
    assert!(
        transport
            .append_accepted_attachment("case_123", &tenant(), &wrong)
            .await
            .is_err()
    );
    assert!(
        calls.load(Ordering::SeqCst) >= 10,
        "current provider must run for each maintained client request"
    );
    let event_count: i64 = sqlx::query_scalar("SELECT count(*) FROM trellis_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(event_count, 1);
    let final_row:(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=sqlx::query_as("SELECT e.canonical_event,e.signed_event,a.ciphertext,a.nonce FROM trellis_events e JOIN trellis_external_attachments a ON a.scope=e.scope AND a.sequence=e.sequence WHERE e.scope=$1").bind(b"case_123".as_slice()).fetch_one(&pool).await.unwrap();
    assert_eq!(
        initial_row, final_row,
        "failed publication and restart must preserve exact committed bytes"
    );
    let evidence_root = std::env::var_os("TRELLIS_NATIVE_TEST_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../transport-evidence")
        });
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let evidence = evidence_root.join(format!("run-{run}"));
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("retained-export.zip"), &pinned).unwrap();
    std::fs::write(evidence.join("original.bin"), &original).unwrap();
    std::fs::write(evidence.join("canonical-event.cbor"), &final_row.0).unwrap();
    std::fs::write(evidence.join("signed-event.cose"), &final_row.1).unwrap();
    let receipt = serde_json::json!({
        "provenance":"neutral controlled fixture; no actual Source acceptance or live authority claim",
        "originalFixture":"fixtures/vectors/append/047-native-external-attachment/input-original.bin",
        "originalSha256":hex::encode(integrity_cbor::sha256_bytes(&original)),
        "originalBytes":original.len(), "zipSha256":hex::encode(integrity_cbor::sha256_bytes(&pinned)),
        "canonicalSha256":hex::encode(integrity_cbor::sha256_bytes(&final_row.0)),
        "signedEventSha256":hex::encode(integrity_cbor::sha256_bytes(&final_row.1)),
        "committedEvents":event_count,"randomCallsAfterPublicationFailure":failure_entropy.parse::<usize>().unwrap(),
        "randomCallsAfterRestartReplay":std::fs::read_to_string(root.join("random-count")).unwrap().parse::<usize>().unwrap(),
        "currentProviderCalls":calls.load(Ordering::SeqCst),
        "genericIntegrityVerified":true,"actualRecipientOriginalEquality":true,
        "wrongRecipientRefused":true,"tamperedBodyRefused":true,"restartByteExactReplay":true,
        "http503PublicationFailureAfterCommit":true,"exactRetryAfter503NoNewRandomness":true,
        "changedBodyAfterFailedFingerprint409":true,
        "changedRecipientIdRefusedCachedAndRestarted":true,"sameRecipientIdChangedKeyRefusedCached":true,
        "closedUnknownAndDuplicateRefused":true,"wrongOriginalRefused":true,
        "noAppendOrReadRefused":true,"retainedHeadReadWithoutAdminister":true,
        "wrongTenantAndScopeRefused":true
    });
    std::fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!(
        "retained cross-process qualification evidence: {}",
        evidence.display()
    );
    drop(server.take());
    pool.close().await;
}

#[tokio::test]
async fn actual_source_png_jpeg_cross_process_protection() {
    for (kind, input_bytes, original) in [
        (
            "png",
            include_bytes!(
                "../../../fixtures/private/actual-source-submits-v1/png/accepted-source-input.json"
            )
            .as_slice(),
            include_bytes!("../../../fixtures/private/actual-source-submits-v1/png/original.bin")
                .as_slice(),
        ),
        (
            "jpeg",
            include_bytes!(
                "../../../fixtures/private/actual-source-submits-v1/jpeg/accepted-source-input.json"
            )
            .as_slice(),
            include_bytes!("../../../fixtures/private/actual-source-submits-v1/jpeg/original.bin")
                .as_slice(),
        ),
    ] {
        let pins: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/private/actual-source-submits-v1/pins.json"
        ))
        .unwrap();
        let input_hash = hex::encode(integrity_cbor::sha256_bytes(input_bytes));
        assert_eq!(
            pins[kind]["accepted-source-input.json"]["sha256"]
                .as_str()
                .unwrap(),
            input_hash
        );
        assert_eq!(
            pins[kind]["original.bin"]["sha256"].as_str().unwrap(),
            hex::encode(integrity_cbor::sha256_bytes(original))
        );
        let input: serde_json::Value = serde_json::from_slice(input_bytes).unwrap();
        assert!(
            input["acceptedIntakeReceipt"].is_null(),
            "this scenario must not claim WOS acceptance"
        );
        let scope = &input["scope"];
        let exact_tenant = TenantScope {
            tenant: scope["tenant_id"].as_str().unwrap().into(),
            workspace: scope["workspace_id"].as_str().unwrap().into(),
            environment: scope["environment_id"].as_str().unwrap().into(),
            cell: scope["cell_id"].as_str().unwrap().into(),
        };
        let cluster = support::TestCluster::start_without_migrations();
        let pool = cluster.tls_pool(4).await;
        let database = format!(
            "postgres://postgres@127.0.0.1:{}/postgres?sslmode=require",
            pool.connect_options().get_port()
        );
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(
            root.join("tenant.json"),
            serde_json::to_vec(&exact_tenant).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("policy"), "reader").unwrap();
        std::fs::write(root.join("random-count"), "0").unwrap();
        let reserve = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let mut server = Some(start_child(root, &database, port).await);
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = client(&format!("http://127.0.0.1:{port}"), "all", calls.clone());
        // Exact maintained Source mapping of the retained long logical operation key.
        let raw_source_key = input["idempotencyKey"].as_str().unwrap();
        assert!(
            !raw_source_key.starts_with("formspec:v1:"),
            "reserved Source mapping prefix must not be caller-authored"
        );
        let mut preimage = b"formspec-trellis-idempotency-v1\0".to_vec();
        preimage.extend_from_slice(raw_source_key.as_bytes());
        let transport_key = format!(
            "formspec:v1:{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                integrity_cbor::sha256_bytes(&preimage)
            )
        );
        assert_eq!(transport_key.len(), 55);
        let body = AcceptedAttachmentAppendBody {
            idempotency_key: transport_key.clone(),
            actor: AppendActor::service("formspec-server"),
            descriptor: input["descriptor"].clone(),
            original_bytes: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                original,
            ),
        };
        let result = transport
            .append_accepted_attachment("case_123", &exact_tenant, &body)
            .await
            .unwrap();
        let checkpoint = result.checkpoint_ref.rsplit('/').next().unwrap();
        let zip = transport
            .bundle("case_123", checkpoint, &exact_tenant)
            .await
            .unwrap();
        assert_eq!(
            transport
                .head_bundle("case_123", &exact_tenant)
                .await
                .unwrap(),
            zip
        );
        let public = trellis_cddl::parse_ed25519_cose_key(test_signing_key().core_key().as_bytes())
            .unwrap()
            .public_key;
        verify_and_open(&zip, original, public);
        let entropy = std::fs::read_to_string(root.join("random-count")).unwrap();
        assert!(entropy.parse::<usize>().unwrap() > 0);
        drop(server.take());
        server = Some(start_child(root, &database, port).await);
        assert_eq!(
            transport
                .append_accepted_attachment("case_123", &exact_tenant, &body)
                .await
                .unwrap(),
            result
        );
        assert_eq!(
            transport
                .bundle("case_123", checkpoint, &exact_tenant)
                .await
                .unwrap(),
            zip
        );
        assert_eq!(
            std::fs::read_to_string(root.join("random-count")).unwrap(),
            entropy
        );
        let row: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT canonical_event,signed_event FROM trellis_events WHERE scope=$1",
        )
        .bind(b"case_123".as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        let evidence_root = std::env::var_os("TRELLIS_NATIVE_TEST_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../transport-evidence")
            });
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let evidence = evidence_root.join(format!("actual-source-{kind}-{run}"));
        std::fs::create_dir_all(&evidence).unwrap();
        std::fs::write(evidence.join("retained-export.zip"), &zip).unwrap();
        std::fs::write(evidence.join("original.bin"), original).unwrap();
        std::fs::write(evidence.join("canonical-event.cbor"), &row.0).unwrap();
        std::fs::write(evidence.join("signed-event.cose"), &row.1).unwrap();
        let receipt = serde_json::json!({"provenance":"actual controlled Formspec Submit descriptor and original bytes, unchanged; separately controlled Trellis case_123 test scope; no WOS case acceptance",
            "acceptedIntakeReceipt":null,"sourceInputSha256":input_hash,"sourceDescriptorSha256":pins[kind]["descriptorSha256"],"originalSha256":hex::encode(integrity_cbor::sha256_bytes(original)),"originalBytes":original.len(),"mediaType":body.descriptor["mediaType"],"transportIdempotencyKey":transport_key,"transportMapping":"maintained Source formspec:v1: URL_SAFE_NO_PAD SHA256 over formspec-trellis-idempotency-v1 NUL and raw Source key", "sourceIdempotencyKeyBytes":input["idempotencyKey"].as_str().unwrap().len(),
            "zipSha256":hex::encode(integrity_cbor::sha256_bytes(&zip)),"canonicalSha256":hex::encode(integrity_cbor::sha256_bytes(&row.0)),"signedEventSha256":hex::encode(integrity_cbor::sha256_bytes(&row.1)),"actualRecipientOriginalEquality":true,"wrongRecipientRefused":true,"tamperedBodyRefused":true,"restartExactReplayNoNewRandomness":true,"randomCalls":entropy.parse::<usize>().unwrap(),"currentProviderCalls":calls.load(Ordering::SeqCst)});
        std::fs::write(
            evidence.join("result.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        println!(
            "retained actual Source {kind} qualification evidence: {}",
            evidence.display()
        );
        drop(server.take());
        pool.close().await;
    }
}
