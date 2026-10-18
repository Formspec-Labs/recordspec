// Rust guideline compliant 2026-02-21
//! The tests' composition root: a one-scope in-memory deployment over shared ledgers and buckets.
//!
//! Tests name ledgers by their id (`case_123`); the fixture puts every ledger under scope A, as a
//! producer's ledger scope `<A's key>.case_123` would be (ADR 0168 §1.6). [`scoped_uri`] rewrites a
//! request path the same way, and [`TestLedgers`] reads A's ledgers by id. The fixture holds the
//! deployment's stores, never the router state: [`router`] builds a fresh `Deployment` over them for
//! each app, as `trellis-main` builds one over the stores it opened.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use object_store::ObjectStore;
use object_store::memory::InMemory;
use stack_common_error::StackError;
use stack_common_http::routes::Built;
use stack_common_object_store::ScopedBucket;
use stack_common_ops::HealthRouter;
use stack_common_scope::{
    Cell, Deployment, DeploymentConfig, Scope, ScopeConfig, Store, VerifiedBinding,
};
use trellis_server_ports::{LedgerScope, LedgerTx, Ledgers, ScopedLedgers};
use trellis_types::{StoredCheckpoint, StoredEvent};

use crate::{MemoryLedgers, TrellisScoped, TrellisServerState, TrellisStore};

/// The tests' served app: the sealed service `router` returns.
pub(crate) type App = Built<()>;

const A: (&str, &str, &str) = ("acme", "benefits", "prod");
const B: (&str, &str, &str) = ("globex", "benefits", "prod");

fn config((tenant, workspace, environment): (&str, &str, &str)) -> ScopeConfig {
    ScopeConfig {
        tenant: tenant.into(),
        workspace: workspace.into(),
        environment: Some(environment.into()),
    }
}

/// Scope A, the scope every fixture ledger lives under.
pub(crate) fn a() -> Scope {
    Scope::fixture(A.0, A.1, Some(A.2))
}

/// Scope B: another tenant of the same deployment.
pub(crate) fn b() -> Scope {
    Scope::fixture(B.0, B.1, Some(B.2))
}

/// Ledger `id` under scope A.
pub(crate) fn ledger(id: &str) -> LedgerScope {
    LedgerScope::of(&a(), id).expect("fixture ledger ids follow the grammar")
}

/// Ledger `id` under `scope`, or the ledger scope itself when `id` already names one.
fn resolve(scope: &Scope, id: &[u8]) -> LedgerScope {
    let text = std::str::from_utf8(id).expect("fixture ledger ids are text");
    LedgerScope::within(scope, text).unwrap_or_else(|_| {
        LedgerScope::of(scope, text).expect("fixture ledger ids follow the grammar")
    })
}

/// `/v1/scopes/<id>/…` with `<id>` put under scope A's key; a path that already names a ledger
/// scope (64 hex digits and a dot) is left alone.
pub(crate) fn scoped_uri(uri: &str) -> String {
    let Some(rest) = uri.strip_prefix("/v1/scopes/") else {
        return uri.to_owned();
    };
    let (segment, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let already = segment
        .split_once('.')
        .is_some_and(|(key, _)| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()));
    if already {
        return uri.to_owned();
    }
    format!("/v1/scopes/{}.{segment}{tail}", a().key())
}

/// The `x-stack-scope-key` a client sends for `uri`: the key its ledger scope names, as
/// `trellis-service-client` derives it.
pub(crate) fn scope_selector(uri: &str) -> Option<String> {
    let segment = uri.strip_prefix("/v1/scopes/")?.split('/').next()?;
    let (key, _) = segment.split_once('.')?;
    (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())).then(|| key.to_owned())
}

/// A request builder for `uri` under scope A, carrying the selector its ledger scope names.
pub(crate) fn scoped_request(method: &str, uri: &str) -> axum::http::request::Builder {
    let uri = scoped_uri(uri);
    let builder = axum::http::Request::builder().method(method).uri(&uri);
    match scope_selector(&uri) {
        Some(key) => builder.header("x-stack-scope-key", key),
        None => builder,
    }
}

/// Provisions an in-memory bucket for cell `cell-a` and opens it. Both complete over `InMemory`
/// without a reactor, so a synchronous fixture can call this.
pub(crate) fn bucket(store: Arc<dyn ObjectStore + Send + Sync>) -> ScopedBucket {
    futures::executor::block_on(provisioned(store)).expect("an in-memory bucket opens")
}

/// Records cell `cell-a` in `store`, as provisioning does, and opens it.
async fn provisioned(
    store: Arc<dyn ObjectStore + Send + Sync>,
) -> Result<ScopedBucket, StackError> {
    let cell = Cell::parse("cell-a").unwrap();
    stack_common_object_store::record_bucket_cell(store.as_ref(), &cell).await?;
    ScopedBucket::open(store, &cell).await
}

/// A one-scope deployment's state and stores, as the composition root would hold them.
#[derive(Clone)]
pub(crate) struct Fixture {
    pub(crate) state: TrellisServerState,
    pub(crate) ledgers: Arc<dyn Ledgers>,
    pub(crate) artifacts: ScopedBucket,
    /// The bucket WOS prepares Source batches in.
    pub(crate) source_objects: ScopedBucket,
    /// Scope A's ledgers, read by ledger id.
    pub(crate) repository: TestLedgers,
    /// Scope A's handle over the fixture's stores.
    scoped_a: TrellisScoped,
    scopes: Vec<ScopeConfig>,
}

impl Fixture {
    /// In-memory ledgers and buckets serving scope A.
    pub(crate) fn new(state: TrellisServerState) -> Self {
        Self::over(
            state,
            Arc::new(MemoryLedgers::new()),
            Arc::new(InMemory::new()),
        )
    }

    /// The given ledgers and artifact backend, serving scope A.
    pub(crate) fn over(
        state: TrellisServerState,
        ledgers: Arc<dyn Ledgers>,
        artifacts: Arc<dyn ObjectStore + Send + Sync>,
    ) -> Self {
        Self::with_buckets(state, ledgers, bucket(artifacts))
    }

    /// The given ledgers and an artifact backend that needs the runtime (a local filesystem).
    pub(crate) async fn open(
        state: TrellisServerState,
        ledgers: Arc<dyn Ledgers>,
        artifacts: Arc<dyn ObjectStore + Send + Sync>,
    ) -> Self {
        let artifacts = provisioned(artifacts)
            .await
            .expect("the artifact bucket opens");
        Self::with_buckets(state, ledgers, artifacts)
    }

    fn with_buckets(
        state: TrellisServerState,
        ledgers: Arc<dyn Ledgers>,
        artifacts: ScopedBucket,
    ) -> Self {
        let source_objects = bucket(Arc::new(InMemory::new()));
        let scoped_a = TrellisStore::new(Arc::clone(&ledgers), artifacts.clone())
            .with_source_content(source_objects.clone())
            .scoped(&a());
        Self {
            state,
            repository: TestLedgers(ledgers.scoped(&a())),
            ledgers,
            artifacts,
            source_objects,
            scoped_a,
            scopes: vec![config(A)],
        }
    }

    fn rescope(mut self) -> Self {
        self.repository = TestLedgers(self.ledgers.scoped(&a()));
        self.scoped_a = self.store().scoped(&a());
        self
    }

    /// Replaces the ledgers (a counting or faulting decorator, Postgres).
    pub(crate) fn with_ledgers(mut self, ledgers: Arc<dyn Ledgers>) -> Self {
        self.ledgers = ledgers;
        self.rescope()
    }

    /// Replaces the artifact bucket's backend.
    pub(crate) fn with_artifact_backend(
        mut self,
        store: Arc<dyn ObjectStore + Send + Sync>,
    ) -> Self {
        self.artifacts = bucket(store);
        self.rescope()
    }

    /// Replaces the Source-content bucket's backend.
    pub(crate) fn with_source_backend(mut self, store: Arc<dyn ObjectStore + Send + Sync>) -> Self {
        self.source_objects = bucket(store);
        self.rescope()
    }

    /// Also serves scope B, so an identity bound to both must select one.
    pub(crate) fn serving_b(self) -> Self {
        self.serving(config(B))
    }

    /// Also serves `scope`.
    pub(crate) fn serving(mut self, scope: ScopeConfig) -> Self {
        self.scopes.push(scope);
        self
    }

    /// Applies a builder to the state.
    pub(crate) fn map(mut self, f: impl FnOnce(TrellisServerState) -> TrellisServerState) -> Self {
        self.state = f(self.state);
        self
    }

    fn store(&self) -> TrellisStore {
        TrellisStore::new(Arc::clone(&self.ledgers), self.artifacts.clone())
            .with_source_content(self.source_objects.clone())
    }

    /// A fresh deployment over the fixture's stores.
    pub(crate) fn deployment(&self) -> Arc<Deployment<TrellisStore>> {
        let config = DeploymentConfig {
            cell: "cell-a".into(),
            scopes: self.scopes.clone(),
            public: None,
        };
        Arc::new(Deployment::new(&config, self.store()).expect("fixture deployment"))
    }

    /// Scope A's handle, as a request admitted to A holds it.
    pub(crate) fn scoped(&self) -> TrellisScoped {
        self.scoped_a.clone()
    }

    /// The append coordinator over scope A, as the append handler builds it.
    pub(crate) fn append_coordinator(&self) -> crate::append::AppendCoordinator<'_> {
        self.state.append_coordinator(&self.scoped_a)
    }

    /// Scope `scope`'s handle.
    pub(crate) fn scoped_for(&self, scope: &Scope) -> TrellisScoped {
        let deployment = self.deployment();
        let binding = VerifiedBinding::select(&[*scope.key()], None).expect("one binding");
        deployment
            .admit(&binding)
            .expect("the fixture serves the scope")
    }
}

impl Deref for Fixture {
    type Target = TrellisServerState;

    fn deref(&self) -> &TrellisServerState {
        &self.state
    }
}

impl DerefMut for Fixture {
    fn deref_mut(&mut self) -> &mut TrellisServerState {
        &mut self.state
    }
}

/// Forwards the state's builders, so a test writes `test_state().with_…(…)` as before.
macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*);)*) => {
        impl Fixture {
            $(
                pub(crate) fn $name(self, $($arg: $ty),*) -> Self {
                    self.map(|state| state.$name($($arg),*))
                }
            )*
        }
    };
}

forward! {
    with_admission_policy(policy: Arc<dyn trellis_server_ports::EventAdmissionPolicy<Error = StackError>>);
    with_append_runner(runner: Arc<dyn crate::append::AppendRunner>);
    with_completion(signer: Arc<dyn crate::CompletionSigner>, publisher: impl Into<String>);
    with_scope_authorizer(authorizer: Arc<dyn trellis_server_ports::ScopeAuthorizer<Error = StackError>>);
    with_jwt_verifier(verifier: stack_common_auth::JwtVerifier<crate::TrellisClaims>);
    with_access_token_verifier(verifier: Arc<dyn stack_common_auth::AccessTokenVerifier>);
    with_production_like_scope_posture(production_like: bool);
    with_source_content(composition: crate::SourceContentComposition);
    with_external_attachment_recipients(selector: Arc<dyn crate::ExternalAttachmentRecipientSelector>);
}

/// The tests' `router`: the fixture's state served over a fresh deployment of its stores.
pub(crate) fn router(fixture: Fixture) -> Result<App, StackError> {
    let deployment = fixture.deployment();
    crate::router(fixture.state, deployment, HealthRouter::new())
}

/// The documents the declared routes produce over `fixture`.
pub(crate) fn documents(
    fixture: &Fixture,
) -> Result<stack_common_http::routes::Documents, StackError> {
    crate::documents(fixture.state.clone(), fixture.deployment())
}

/// Scope A's ledgers, named by ledger id (or by a full ledger scope).
#[derive(Clone)]
pub(crate) struct TestLedgers(Arc<dyn ScopedLedgers>);

impl TestLedgers {
    pub(crate) async fn begin(&self, id: &[u8]) -> Result<Box<dyn LedgerTx>, StackError> {
        self.0.begin(&resolve(&a(), id)).await
    }

    pub(crate) async fn head_checkpoint(
        &self,
        id: &[u8],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.0.head_checkpoint(&resolve(&a(), id)).await
    }

    pub(crate) async fn checkpoint_at(
        &self,
        id: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.0.checkpoint_at(&resolve(&a(), id), tree_size).await
    }

    pub(crate) async fn checkpoint_by_digest(
        &self,
        id: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.0
            .checkpoint_by_digest(&resolve(&a(), id), digest)
            .await
    }

    pub(crate) async fn last_event(&self, id: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        self.0.last_event(&resolve(&a(), id)).await
    }

    /// Every event of A's ledger `id`, as its head export reads them.
    pub(crate) async fn list_scope(&self, id: &[u8]) -> Result<Vec<StoredEvent>, StackError> {
        Ok(self
            .0
            .export(&resolve(&a(), id), trellis_server_ports::ExportAt::Head)
            .await?
            .map(|rows| rows.events)
            .unwrap_or_default())
    }
}

/// The export of A's ledger `id` at `head`, assembled as the bundle routes assemble it.
pub(crate) async fn assemble(
    fixture: &Fixture,
    id: &[u8],
    head: &StoredCheckpoint,
) -> Result<Vec<u8>, StackError> {
    let scoped = fixture.scoped();
    let ledger = resolve(&a(), id);
    let rows = scoped
        .ledgers()
        .export(&ledger, trellis_server_ports::ExportAt::Digest(head.digest))
        .await?
        .ok_or_else(|| StackError::not_found("checkpoint bundle not found"))?;
    crate::export::assemble(&fixture.state, &scoped, &ledger, rows).await
}

/// Reconciles against A's ledger `id`, as the reconcile route does.
pub(crate) async fn reconcile(
    fixture: &Fixture,
    id: &str,
    request: &trellis_service_client::AppendReconciliationRequest,
) -> trellis_service_client::AppendReconciliation {
    crate::reconciliation::reconcile(&fixture.scoped(), &resolve(&a(), id.as_bytes()), request)
        .await
}

/// Seals a completion on `scope`'s ledger `id`, as the seal route does for a request admitted to
/// `scope`.
pub(crate) async fn seal(
    fixture: &Fixture,
    headers: &axum::http::HeaderMap,
    scope: &Scope,
    id: &str,
    request: &crate::CompletionRequest,
    signer: &dyn crate::CompletionSigner,
) -> Result<trellis_service_client::SubstrateAppendResult, StackError> {
    let ledger = resolve(scope, id.as_bytes());
    crate::seal_completion(
        &fixture.state,
        &fixture.scoped_for(scope),
        headers,
        &ledger,
        request,
        signer,
    )
    .await
}
