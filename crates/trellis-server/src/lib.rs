// Rust guideline compliant 2026-02-21
//! Trellis substrate HTTP service.
//!
//! The service is the composition root between product-facing HTTP append
//! calls and Trellis Core byte construction. Consumers share the
//! `trellis-service-client` wire DTOs; this crate owns admission,
//! authorization, persistence, export publication, and registry reads.
//!
//! **HTTP replay idempotency** is enforced only through
//! [`stack_common_idempotency::InMemoryHttpReplayStore`] wired into
//! [`stack_common_http::idempotency::HttpIdempotencyState`] middleware (ADR
//! 0092c). There is no parallel `IdempotencyStore` port in `trellis-server-ports`.
//!
//! **Governance overlay (TWREF-064):** `wos-server` may restrict which WOS literals it emits
//! over HTTP before calling Trellis, while Trellis admits the union of WOS registry
//! literals plus Formspec append dialect subjects to admission policy. Bearer
//! credentials targeting Trellis are the substrate trust root: durable non-permissive
//! startups require HS256 JWTs whose `scopes` claim authorizes the URL scope (TWREF-022);
//! dev/demo may use `TRELLIS_STORAGE=memory` or `TRELLIS_PERMISSIVE_SCOPE_AUTH=1` for allow-all scope checks.
//!
//! **Case scope versus Trellis URL scope (TWREF-005):** Admission here keys off `event_type` and payload shape for the
//! HTTP `{scope}` segment plus tenant headers. It does not fetch WOS case relationship rows; product servers must map
//! their governed case identity into scope and credentials deliberately. Formspec and WOS append dialects share the
//! same route but diverge in `RoutedEventAdmissionPolicy` on the `substrate.append.*` prefix versus `wos.*` literals.

#![forbid(unsafe_code)]

mod admission;
mod append;
mod artifacts;
mod event_repository;
pub mod openapi;
mod scope_startup;

#[doc(inline)]
pub use admission::{FormspecAppendAdmissionPolicy, RoutedEventAdmissionPolicy, WosEventAdmissionPolicy};

use admission::{AllowAllScopeAuthorizer, ScopedAllowlistScopeAuthorizer};

use artifacts::{BundleIndex, BundleRecord, InMemoryArtifactStore, ScopeLocks};

#[doc(inline)]
pub use event_repository::{EventRepository, InMemoryEventRepository, PostgresEventRepository};
#[doc(inline)]
pub use scope_startup::TrellisScopeAuthorizerStartupInputs;

#[doc(inline)]
pub use openapi::TrellisServerOpenApi;

#[cfg(feature = "test-harness")]
pub mod test_harness;

use std::env;
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use http::header::AUTHORIZATION;
use integrity_cbor::{
    CborHelperError, Value, domain_separated_sha256, map_lookup_bytes, map_lookup_fixed_bytes,
    map_lookup_map,
};
use serde::{Deserialize, Serialize};
use stack_common_auth::{BaseClaims, Claims, JwtConfig, JwtVerifier};
use stack_common_error::{ErrorCode, ProblemJson, StackError};
use stack_common_http::idempotency::{
    HttpIdempotencyState, IDEMPOTENCY_KEY_HEADER, IdempotencyCall, IdempotencyDecision,
    IdempotencyDriverError, IdempotencyFailure, IdempotencyOperation, idempotency_middleware,
};
use stack_common_http::problem_response;
use stack_common_http::tenant::{
    HeaderConfig, TenantHeaderConfigProvider, TenantScope, extract_tenant,
    extract_tenant_multi_producer,
};
use stack_common_idempotency::{
    HttpReplayStore, InMemoryHttpReplayStore, ReplayOutcome, StoredResponse,
};
use stack_common_ops::{ComponentHealth, HealthProbe, HealthRouter};
use trellis_cddl::canonical_event_hash_preimage;
use trellis_core::SigningKeyMaterial as CoreSigningKey;
use trellis_export_writer::{
    ExportWriterInput, RegistrySnapshot as ExportRegistrySnapshot,
    SigningKeyMaterial as ExportSigningKey, TrellisTimestamp, write_export,
};
use trellis_server_ports::{
    ArtifactStore, EventAdmissionPolicy, S3CompatibleArtifactStore, S3ObjectConfig, ScopeAction,
    ScopeAuthorization, ScopeAuthorizer,
};
use trellis_service_client::{
    ComputeContext, ComputeSensitivity, SubstrateAppendBody, SubstrateAppendResult,
    VerificationReceipt,
};
use trellis_types::{EVENT_DOMAIN, StoredEvent};
use wos_events::SUBSTRATE_CANONICAL_EVENT_LITERALS;

use crate::openapi::EventTypeRegistryView;

/// Formspec intake proof append event literal admitted at the service edge.
pub use trellis_service_client::FORMSPEC_APPEND_EVENT_TYPE_LITERAL as FORMSPEC_RESPONSE_SUBMITTED;
const EVENT_TYPE_REGISTRY_VERSION: &str = "wos-events:2026-05-15";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[must_use]
pub const fn default_bind_addr() -> &'static str {
    DEFAULT_BIND_ADDR
}

fn profile_id_for_admitted_event(event_type: &str) -> Result<u64, StackError> {
    if event_type.starts_with("wos.") {
        Ok(integrity_verify::WOS_PROFILE_ID)
    } else if event_type.starts_with("substrate.append.") {
        Ok(integrity_verify::FORMSPEC_PROFILE_ID)
    } else {
        Err(StackError::internal(format!(
            "unknown event type for profile dispatch: {event_type}"
        )))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantHeaderMode {
    Wos,
    Formspec,
    MultiProducer,
}

const WOS_EVENT_TYPES: &[&str] = SUBSTRATE_CANONICAL_EVENT_LITERALS;

/// Server-owned JWT claims for optional service auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrellisClaims {
    #[serde(flatten)]
    pub base: BaseClaims,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl Claims for TrellisClaims {
    fn base(&self) -> &BaseClaims {
        &self.base
    }
}

/// Parsed signing material shared by append and export paths.
#[derive(Clone, Debug)]
pub struct ServerSigningKey {
    cose_key: Vec<u8>,
    export_key: ExportSigningKey,
    valid_to: Option<TrellisTimestamp>,
}

impl ServerSigningKey {
    /// Parses Ed25519 COSE_Key bytes.
    ///
    /// # Errors
    /// Returns an error when the key cannot be decoded as Trellis Ed25519
    /// signing material.
    pub fn from_cose_key_bytes(
        cose_key: Vec<u8>,
        valid_from: TrellisTimestamp,
    ) -> Result<Self, StackError> {
        let parsed = trellis_cddl::parse_ed25519_cose_key(&cose_key)
            .map_err(|error| StackError::bad_request(format!("invalid signing key: {error}")))?;
        Ok(Self {
            cose_key,
            export_key: ExportSigningKey {
                private_seed: parsed.private_seed,
                public_key: parsed.public_key,
                valid_from,
                valid_to: None,
            },
            valid_to: None,
        })
    }

    #[must_use]
    pub fn with_valid_to(mut self, valid_to: Option<TrellisTimestamp>) -> Self {
        self.valid_to = valid_to;
        self.export_key.valid_to = valid_to;
        self
    }

    #[must_use]
    pub fn is_active_at(&self, timestamp: TrellisTimestamp) -> bool {
        self.valid_to
            .map(|valid_to| {
                (timestamp.unix_secs, timestamp.subsec_nanos)
                    <= (valid_to.unix_secs, valid_to.subsec_nanos)
            })
            .unwrap_or(true)
    }

    pub(crate) fn core_key(&self) -> CoreSigningKey {
        CoreSigningKey::new(self.cose_key.clone())
    }

    fn export_key(&self) -> ExportSigningKey {
        self.export_key.clone()
    }
}

/// Cloneable Axum state for the Trellis service.
#[derive(Clone)]
pub struct TrellisServerState {
    pub(crate) repository: Arc<dyn EventRepository>,
    artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    pub(crate) admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    pub(crate) signing_key: ServerSigningKey,
    tenant_header_mode: TenantHeaderMode,
    replay_store: Arc<InMemoryHttpReplayStore>,
    bundles: Arc<BundleIndex>,
    pub(crate) scope_locks: Arc<ScopeLocks>,
    jwt_verifier: Option<Arc<JwtVerifier<TrellisClaims>>>,
    /// True when [`state_from_env`] used durable storage without `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`.
    production_like_scope_posture: bool,
    /// True while the built-in [`AllowAllScopeAuthorizer`] from [`Self::new`] is still installed.
    scope_authorizer_allow_all: bool,
    append_runner: Arc<dyn AppendRunner>,
}

/// Runs append orchestration after HTTP validation and outer authorization (TWREF-021).
///
/// Production wiring delegates to [`AppendCoordinator`]; tests may substitute a recorder that
/// forwards to [`DefaultAppendRunner`] without monkeypatching globals.
#[async_trait]
pub(crate) trait AppendRunner: Send + Sync {
    async fn run_append(
        &self,
        state: &TrellisServerState,
        command: append::AppendCommand,
    ) -> Result<append::AppendOutcome, StackError>;
}

/// Production [`AppendRunner`] implementation (`AppendCoordinator::append`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DefaultAppendRunner;

#[async_trait]
impl AppendRunner for DefaultAppendRunner {
    async fn run_append(
        &self,
        state: &TrellisServerState,
        command: append::AppendCommand,
    ) -> Result<append::AppendOutcome, StackError> {
        state.append_coordinator().append(command).await
    }
}

impl TrellisServerState {
    #[must_use]
    pub fn new(
        repository: Arc<dyn EventRepository>,
        signing_key: ServerSigningKey,
        tenant_header_mode: TenantHeaderMode,
    ) -> Self {
        Self {
            repository,
            artifact_store: Arc::new(InMemoryArtifactStore::default()),
            admission_policy: Arc::new(RoutedEventAdmissionPolicy {
                wos: WosEventAdmissionPolicy,
                formspec: FormspecAppendAdmissionPolicy,
            }),
            authorizer: Arc::new(AllowAllScopeAuthorizer),
            signing_key,
            tenant_header_mode,
            replay_store: Arc::new(InMemoryHttpReplayStore::new()),
            bundles: Arc::new(BundleIndex::default()),
            scope_locks: Arc::new(ScopeLocks::default()),
            jwt_verifier: None,
            production_like_scope_posture: false,
            scope_authorizer_allow_all: true,
            append_runner: Arc::new(DefaultAppendRunner),
        }
    }

    /// Test-only: replace the append runner (constructor injection for delegation proofs).
    #[cfg(test)]
    pub(crate) fn with_append_runner(mut self, runner: Arc<dyn AppendRunner>) -> Self {
        self.append_runner = runner;
        self
    }

    #[must_use]
    pub fn production_like_scope_posture(&self) -> bool {
        self.production_like_scope_posture
    }

    #[must_use]
    pub fn with_production_like_scope_posture(mut self, production_like: bool) -> Self {
        self.production_like_scope_posture = production_like;
        self
    }

    #[must_use]
    pub fn with_artifact_store(
        mut self,
        artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    ) -> Self {
        self.artifact_store = artifact_store;
        self
    }

    #[must_use]
    pub fn with_jwt_verifier(mut self, verifier: JwtVerifier<TrellisClaims>) -> Self {
        self.jwt_verifier = Some(Arc::new(verifier));
        self
    }

    #[must_use]
    pub fn with_admission_policy(
        mut self,
        admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    ) -> Self {
        self.admission_policy = admission_policy;
        self
    }

    #[must_use]
    pub fn with_scope_authorizer(
        mut self,
        authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    ) -> Self {
        self.authorizer = authorizer;
        self.scope_authorizer_allow_all = false;
        self
    }

    /// Refuses misleading compositions: production-like posture must not run with allow-all scope auth.
    ///
    /// # Errors
    /// When the state would advertise production scope posture while still using dev-only authorization.
    pub fn ensure_serving_posture_twref022(&self) -> Result<(), StackError> {
        if !self.production_like_scope_posture {
            return Ok(());
        }
        if self.scope_authorizer_allow_all {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 a scoped ScopeAuthorizer (JWT scopes allowlist), not AllowAll—set \
                 TRELLIS_PERMISSIVE_SCOPE_AUTH=1 for explicit dev bypass (TWREF-022).",
            ));
        }
        if self.jwt_verifier.is_none() {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 TRELLIS_JWT_HS256_SECRET / jwt_verifier (TWREF-022).",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn append_coordinator(&self) -> append::AppendCoordinator<'_> {
        append::AppendCoordinator::new(self)
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<Option<TrellisClaims>, StackError> {
        let Some(verifier) = &self.jwt_verifier else {
            return Ok(None);
        };
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| {
                StackError::new(
                    ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                    StatusCode::UNAUTHORIZED,
                    "missing bearer token",
                )
            })?;
        verifier.verify(token).map(Some)
    }
}

impl TenantHeaderConfigProvider for TrellisServerState {
    fn tenant_header_config(&self) -> HeaderConfig {
        match self.tenant_header_mode {
            TenantHeaderMode::Wos => HeaderConfig::wos(),
            TenantHeaderMode::Formspec => HeaderConfig::formspec(),
            TenantHeaderMode::MultiProducer => HeaderConfig::wos(),
        }
    }

    fn extract_tenant_scope(&self, headers: &HeaderMap) -> Result<TenantScope, StackError> {
        match self.tenant_header_mode {
            TenantHeaderMode::MultiProducer => extract_tenant_multi_producer(headers),
            TenantHeaderMode::Wos => extract_tenant(&HeaderConfig::wos(), headers),
            TenantHeaderMode::Formspec => extract_tenant(&HeaderConfig::formspec(), headers),
        }
    }
}

#[async_trait]
impl HttpIdempotencyState for TrellisServerState {
    type Error = StackError;

    async fn reserve_http_idempotency(
        &self,
        call: &IdempotencyCall,
    ) -> Result<IdempotencyDecision, IdempotencyDriverError<Self::Error>> {
        match self
            .replay_store
            .check(
                &tenant_replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
            )
            .await
            .map_err(IdempotencyDriverError::store)?
        {
            ReplayOutcome::Fresh => Ok(IdempotencyDecision::Fresh),
            ReplayOutcome::Replay(response) => Ok(IdempotencyDecision::Replay(response)),
            ReplayOutcome::Conflict => Ok(IdempotencyDecision::Conflict),
        }
    }

    async fn record_http_idempotency_response(
        &self,
        call: &IdempotencyCall,
        response: StoredResponse,
    ) -> Result<(), IdempotencyDriverError<Self::Error>> {
        self.replay_store
            .record(
                &tenant_replay_scope(call),
                &call.request.key,
                &call.request.request_hash,
                response,
            )
            .await
            .map_err(IdempotencyDriverError::store)
    }

    fn idempotency_failure_response(&self, failure: IdempotencyFailure) -> Response {
        let error = match failure {
            IdempotencyFailure::MissingKey => StackError::bad_request("idempotency key required"),
            IdempotencyFailure::RequestBodyCaptureFailed => {
                StackError::bad_request("request body capture failed")
            }
            IdempotencyFailure::Conflict => {
                StackError::conflict("idempotency key reused with a different body")
            }
            IdempotencyFailure::ResponseBodyCaptureFailed => {
                StackError::internal("response body capture failed")
            }
        };
        problem_response(error)
    }

    fn idempotency_store_error_response(
        &self,
        _operation: IdempotencyOperation,
        error: Self::Error,
    ) -> Response {
        problem_response(error)
    }
}

/// Builds the Trellis Axum router.
///
/// # Errors
/// Returns an error when shared HTTP middleware cannot be constructed.
pub fn router(state: TrellisServerState) -> Result<Router, StackError> {
    state.ensure_serving_posture_twref022()?;
    let http_layer = stack_common_http::MiddlewareBuilder::new()
        .with_request_id()
        .with_tracing()
        .with_catch_panic()
        .build()
        .map_err(|error| StackError::internal(format!("http middleware: {error}")))?;

    let append = post(append_event).route_layer(middleware::from_fn_with_state(
        state.clone(),
        idempotency_middleware::<TrellisServerState>,
    ));

    Ok(Router::new()
        .route("/openapi.json", get(openapi::openapi_json))
        .route("/v1/scopes/{scope}/events", append)
        .route("/v1/scopes/{scope}/bundles/head", get(head_bundle))
        .route(
            "/v1/scopes/{scope}/bundles/{checkpoint_digest}",
            get(pinned_bundle),
        )
        .route(
            "/v1/scopes/{scope}/registries/signing-keys",
            get(signing_key_registry),
        )
        .route(
            "/v1/scopes/{scope}/registries/event-types",
            get(event_type_registry),
        )
        .merge(
            HealthRouter::new()
                .with_probe(TrellisHealthProbe::new(state.clone()))
                .into_router_for_state(),
        )
        .with_state(state)
        .layer(http_layer))
}

/// Builds a server state from environment variables.
///
/// Required unless `TRELLIS_STORAGE=memory`:
/// - `TRELLIS_DATABASE_URL`
///
/// Always required:
/// - `TRELLIS_SIGNING_KEY_COSE_PATH`
///
/// Optional:
/// - `TRELLIS_STORAGE=memory` (in-memory repository; skips `TRELLIS_DATABASE_URL`)
/// - `TRELLIS_PERMISSIVE_SCOPE_AUTH=1` (durable storage: keep `AllowAllScopeAuthorizer`; optional JWT)
/// - `TRELLIS_JWT_HS256_SECRET` (**required** for durable storage unless `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`; optional otherwise)
/// - `TRELLIS_TENANT_HEADER_SET=wos|formspec|mixed`
/// - `TRELLIS_SIGNING_KEY_VALID_TO_UNIX_SECS`
/// - `TRELLIS_ARTIFACT_BUCKET`
/// - `TRELLIS_ARTIFACT_PREFIX`
/// - `TRELLIS_ARTIFACT_ENDPOINT`
/// - `TRELLIS_ARTIFACT_REGION`
///
/// # Errors
/// Returns an error when config is missing or backend setup fails.
pub async fn state_from_env() -> Result<TrellisServerState, StackError> {
    let scope_inputs = TrellisScopeAuthorizerStartupInputs::from_env();
    let trellis_storage_is_memory = scope_inputs.storage_is_memory;

    let signing_key_path = env::var("TRELLIS_SIGNING_KEY_COSE_PATH")
        .map_err(|_| StackError::bad_request("TRELLIS_SIGNING_KEY_COSE_PATH is required"))?;
    let signing_key_bytes = fs::read(&signing_key_path).map_err(|error| {
        StackError::bad_request(format!(
            "failed to read TRELLIS_SIGNING_KEY_COSE_PATH: {error}"
        ))
    })?;
    let signing_key_valid_to = env_optional_timestamp("TRELLIS_SIGNING_KEY_VALID_TO_UNIX_SECS")?;
    let signing_key =
        ServerSigningKey::from_cose_key_bytes(signing_key_bytes, TrellisTimestamp::new(0, 0)?)?
            .with_valid_to(signing_key_valid_to);

    let tenant_header_mode = match env::var("TRELLIS_TENANT_HEADER_SET")
        .unwrap_or_else(|_| "mixed".to_string())
        .as_str()
    {
        "wos" => TenantHeaderMode::Wos,
        "formspec" => TenantHeaderMode::Formspec,
        "mixed" => TenantHeaderMode::MultiProducer,
        other => {
            return Err(StackError::bad_request(format!(
                "unsupported TRELLIS_TENANT_HEADER_SET `{other}`"
            )));
        }
    };

    let repository: Arc<dyn EventRepository> = if trellis_storage_is_memory {
        Arc::new(InMemoryEventRepository::new())
    } else {
        let database_url = env::var("TRELLIS_DATABASE_URL")
            .map_err(|_| StackError::bad_request("TRELLIS_DATABASE_URL is required"))?;
        let pool = trellis_store_postgres_async::build_pool(&database_url, 10)
            .await
            .map_err(|error| StackError::unavailable(format!("postgres pool: {error}")))?;
        trellis_store_postgres_async::run_migrations(&pool)
            .await
            .map_err(|error| StackError::unavailable(format!("postgres migrations: {error}")))?;
        Arc::new(PostgresEventRepository::new(pool))
    };

    let mut state = TrellisServerState::new(repository, signing_key, tenant_header_mode);
    if let Some(artifact_store) = artifact_store_from_env() {
        state = state.with_artifact_store(artifact_store);
    }

    let jwt_secret = env::var("TRELLIS_JWT_HS256_SECRET")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if trellis_storage_is_memory || scope_inputs.permissive_scope_auth {
        if let Some(secret) = jwt_secret {
            state = state.with_jwt_verifier(JwtVerifier::from_hs256(
                trellis_jwt_config(),
                secret.as_bytes(),
            ));
        }
        return Ok(state);
    }

    let Some(secret) = jwt_secret else {
        return Err(StackError::bad_request(
            "TRELLIS_JWT_HS256_SECRET is required when using durable storage without \
             TRELLIS_PERMISSIVE_SCOPE_AUTH=1 (TWREF-022). For dev/demo only, set \
             TRELLIS_PERMISSIVE_SCOPE_AUTH=1 to keep AllowAll scope authorization.",
        ));
    };

    state = state
        .with_jwt_verifier(JwtVerifier::from_hs256(
            trellis_jwt_config(),
            secret.as_bytes(),
        ))
        .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer));
    Ok(state.with_production_like_scope_posture(true))
}

#[must_use]
fn trellis_jwt_config() -> JwtConfig {
    JwtConfig {
        algorithm: jsonwebtoken::Algorithm::HS256,
        validate_exp: true,
        validate_iss: None,
        validate_aud: None,
        leeway_secs: 30,
    }
}

fn artifact_store_from_env() -> Option<Arc<dyn ArtifactStore<Error = StackError>>> {
    let bucket = env_optional("TRELLIS_ARTIFACT_BUCKET")?;
    let prefix = env_optional("TRELLIS_ARTIFACT_PREFIX").unwrap_or_else(|| "trellis".to_string());
    let config = S3ObjectConfig {
        bucket,
        endpoint: env_optional("TRELLIS_ARTIFACT_ENDPOINT"),
        region: env_optional("TRELLIS_ARTIFACT_REGION"),
    };
    Some(Arc::new(S3CompatibleArtifactStore::new(config, prefix)))
}

fn env_optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_optional_timestamp(name: &str) -> Result<Option<TrellisTimestamp>, StackError> {
    let Some(raw) = env_optional(name) else {
        return Ok(None);
    };
    let seconds: u64 = raw.parse().map_err(|error| {
        StackError::bad_request(format!("{name} must be a u64 unix timestamp: {error}"))
    })?;
    Ok(Some(TrellisTimestamp::new(seconds, 0)?))
}

#[derive(Clone)]
struct TrellisHealthProbe {
    state: TrellisServerState,
}

impl TrellisHealthProbe {
    fn new(state: TrellisServerState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl HealthProbe for TrellisHealthProbe {
    async fn check(&self) -> ComponentHealth {
        let mut issues = Vec::new();
        if let Err(error) = self.state.repository.list_scope(b"__healthz__").await {
            issues.push(format!("repository: {error}"));
        }
        let probe_key = "__healthz__/artifact-roundtrip";
        let probe_bytes = b"trellis-health-probe";
        match self.state.artifact_store.put(probe_key, probe_bytes).await {
            Ok(artifact_ref) => match self.state.artifact_store.get(&artifact_ref).await {
                Ok(Some(bytes)) if bytes == probe_bytes => {}
                Ok(Some(_)) => issues.push("artifact-store: roundtrip bytes mismatch".into()),
                Ok(None) => issues.push("artifact-store: stored object missing".into()),
                Err(error) => issues.push(format!("artifact-store read: {error}")),
            },
            Err(error) => issues.push(format!("artifact-store write: {error}")),
        }
        if issues.is_empty() {
            ComponentHealth::healthy("trellis-server", "repository and artifact store reachable")
        } else {
            ComponentHealth::degraded("trellis-server", issues.join("; "))
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/scopes/{scope}/events",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("idempotency-key" = String, Header, description = "HTTP replay key; must match body idempotencyKey.")
    ),
    request_body = SubstrateAppendBody,
    responses(
        (status = 201, description = "Event appended and proof bundle published.", body = SubstrateAppendResult),
        (status = 400, description = "Invalid append request.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "Service token rejected.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 403, description = "Scope action forbidden.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 409, description = "Idempotency key or sequence conflict.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Substrate dependency unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "events",
    operation_id = "appendEvent",
)]
async fn append_event(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    _tenant_scope: TenantScope,
    headers: HeaderMap,
    Json(body): Json<SubstrateAppendBody>,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), StackError> {
    validate_scope(&scope)?;
    body.validate()?;
    reject_unverified_client_attestation(&body)?;
    validate_idempotency_header(&headers, &body.idempotency_key)?;
    validate_compute_context(&body)?;
    let claims = state.authenticate(&headers)?;
    let actor_subject = claims
        .as_ref()
        .map(|claims| claims.base().sub.as_str())
        .unwrap_or(body.actor.subject.as_str());
    let jwt_scopes = claims.as_ref().map(|c| c.scopes.as_slice());
    state
        .authorizer
        .authorize(&ScopeAuthorization {
            actor: actor_subject,
            scope: scope.as_bytes(),
            action: ScopeAction::Append,
            jwt_scopes,
        })
        .await?;

    let command = append::AppendCommand {
        scope: scope.clone(),
        event_type: body.event_type.clone(),
        idempotency_key: body.idempotency_key.clone(),
        payload: body.payload.clone(),
        compute_context: append::port_compute_context(&body),
    };
    let outcome = state.append_runner.run_append(&state, command).await?;
    Ok((StatusCode::CREATED, Json(outcome.result)))
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/bundles/head",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "Current Trellis export bundle.", content_type = "application/zip"),
        (status = 404, description = "Scope has no bundle.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Bundle store unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "bundles",
    operation_id = "getHeadBundle",
)]
async fn head_bundle(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let events = state.repository.list_scope(scope.as_bytes()).await?;
    let bundle = publish_bundle(
        &state,
        scope.as_bytes(),
        &events,
        true,
        &append::default_public_compute_context(),
    )
    .await?;
    bundle_response(&state, &bundle).await
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/bundles/{checkpointDigest}",
    params(
        ("scope" = String, Path, description = "Trellis ledger scope."),
        ("checkpointDigest" = String, Path, description = "Checkpoint digest in `sha256:<64 hex>` form.")
    ),
    responses(
        (status = 200, description = "Pinned Trellis export bundle.", content_type = "application/zip"),
        (status = 400, description = "Invalid checkpoint digest.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "Pinned checkpoint bundle not found.", body = ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Bundle store unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "bundles",
    operation_id = "getBundleByCheckpointDigest",
)]
async fn pinned_bundle(
    State(state): State<TrellisServerState>,
    Path((scope, checkpoint_digest)): Path<(String, String)>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let digest = normalize_checkpoint_digest(&checkpoint_digest)?;
    let record = {
        let by_digest = state.bundles.by_digest.lock().await;
        by_digest
            .get(&(scope.as_bytes().to_vec(), digest.clone()))
            .cloned()
    };
    let Some(record) = record else {
        let events = state.repository.list_scope(scope.as_bytes()).await?;
        let head = publish_bundle(
            &state,
            scope.as_bytes(),
            &events,
            true,
            &append::default_public_compute_context(),
        )
        .await?;
        if head.checkpoint_digest == digest {
            return bundle_response(&state, &head).await;
        }
        return Err(StackError::not_found("checkpoint bundle not found"));
    };
    bundle_response(&state, &record).await
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/registries/signing-keys",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "CBOR signing-key registry snapshot.", content_type = "application/cbor"),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getSigningKeyRegistry",
)]
async fn signing_key_registry(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Response, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    let bytes = signing_key_registry_cbor(&state.signing_key.export_key())?;
    Ok(bytes_response("application/cbor", bytes))
}

#[utoipa::path(
    get,
    path = "/v1/scopes/{scope}/registries/event-types",
    params(("scope" = String, Path, description = "Trellis ledger scope.")),
    responses(
        (status = 200, description = "Event-type registry projection.", body = EventTypeRegistryView),
        (status = 503, description = "Registry unavailable.", body = ProblemJson, content_type = "application/problem+json")
    ),
    tag = "registries",
    operation_id = "getEventTypeRegistry",
)]
async fn event_type_registry(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant_scope: TenantScope,
    headers: HeaderMap,
) -> Result<Json<EventTypeRegistryView>, StackError> {
    read_authorized(&state, &scope, &tenant_scope, &headers).await?;
    Ok(Json(event_type_registry_view()))
}

async fn read_authorized(
    state: &TrellisServerState,
    scope: &str,
    _tenant_scope: &TenantScope,
    headers: &HeaderMap,
) -> Result<(), StackError> {
    validate_scope(scope)?;
    let claims = state.authenticate(headers)?;
    let actor = claims
        .as_ref()
        .map(|claims| claims.base().sub.as_str())
        .unwrap_or("anonymous");
    let jwt_scopes = claims.as_ref().map(|c| c.scopes.as_slice());
    state
        .authorizer
        .authorize(&ScopeAuthorization {
            actor,
            scope: scope.as_bytes(),
            action: ScopeAction::Read,
            jwt_scopes,
        })
        .await
}

/// Returns true when the export ZIP passes the same independent verifier used in conformance.
#[must_use]
pub(crate) fn export_bundle_cryptographically_verified(zip_bytes: &[u8]) -> bool {
    let report = integrity_verify::trellis::verify_export_zip(zip_bytes);
    report.structure_verified && report.integrity_verified
}

pub(crate) async fn publish_bundle(
    state: &TrellisServerState,
    scope: &[u8],
    events: &[StoredEvent],
    update_head: bool,
    compute: &ComputeContext,
) -> Result<BundleRecord, StackError> {
    if events.is_empty() {
        return Err(StackError::not_found("scope has no events"));
    }
    let timestamps = events
        .iter()
        .map(event_timestamp)
        .collect::<Result<Vec<_>, _>>()?;
    let generated_at = timestamps
        .last()
        .copied()
        .ok_or_else(|| StackError::internal("empty timestamp set"))?;
    let registry_bytes = event_type_registry_cbor()?;
    let package = write_export(ExportWriterInput {
        scope: scope.to_vec(),
        events: events.to_vec(),
        registries: vec![ExportRegistrySnapshot {
            bytes: registry_bytes,
            registry_format: 1,
            registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
            bound_at_sequence: 0,
        }],
        signing_key: state.signing_key.export_key(),
        generator: "trellis-server".to_string(),
        generated_at,
        checkpoint_timestamps: timestamps,
        posture_declaration: append::export_posture_from_compute(compute),
        omitted_payload_checks: Vec::new(),
        readme_title: format!("Trellis export for {}", String::from_utf8_lossy(scope)),
        root_dir_override: None,
        external_anchors: Vec::new(),
        extensions: None,
        witness_key_registry: None,
    })?;
    let checkpoint_digest = format!("sha256:{}", hex::encode(package.head_checkpoint_digest));
    let key = format!(
        "{}/bundles/{}.zip",
        encode_path_segment(&String::from_utf8_lossy(scope)),
        checkpoint_digest.trim_start_matches("sha256:")
    );
    if !export_bundle_cryptographically_verified(&package.zip_bytes) {
        return Err(StackError::internal(
            "published export bundle failed independent verification",
        ));
    }
    let artifact_ref = state.artifact_store.put(&key, &package.zip_bytes).await?;
    let record = BundleRecord {
        checkpoint_digest,
        artifact_ref,
    };
    state
        .bundles
        .insert_published_record(scope, &record, update_head)
        .await;
    Ok(record)
}

pub(crate) fn append_result_for_event(
    scope: &str,
    event: &StoredEvent,
    event_type: &str,
    bundle: &BundleRecord,
    export_verified: bool,
) -> Result<SubstrateAppendResult, StackError> {
    let canonical_hash = event_hash(scope.as_bytes(), event)?;
    let hash_hex = hex::encode(canonical_hash);
    Ok(SubstrateAppendResult {
        event_id: format!("evt_{}", &hash_hex[..16]),
        sequence: event.sequence(),
        canonical_event_hash: format!("sha256:{hash_hex}"),
        checkpoint_ref: format!("trellis://{scope}/checkpoints/{}", bundle.checkpoint_digest),
        bundle_ref: bundle.artifact_ref.uri.clone(),
        verification_receipt: VerificationReceipt {
            verified: export_verified,
            profile_id: profile_id_for_admitted_event(event_type)?,
            event_type: event_type.to_string(),
        },
    })
}

async fn bundle_response(
    state: &TrellisServerState,
    bundle: &BundleRecord,
) -> Result<Response, StackError> {
    let bytes = state
        .artifact_store
        .get(&bundle.artifact_ref)
        .await?
        .ok_or_else(|| StackError::not_found("bundle artifact bytes not found"))?;
    Ok(bytes_response("application/zip", bytes))
}

fn bytes_response(content_type: &'static str, bytes: Vec<u8>) -> Response {
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

pub(crate) fn validate_existing_replay(
    event: &StoredEvent,
    event_type: &str,
    content_hash: [u8; 32],
) -> Result<(), StackError> {
    let summary = event_summary(event)?;
    if summary.event_type != event_type {
        return Err(StackError::conflict(
            "idempotency key reused with a different event type",
        ));
    }
    if summary.content_hash != content_hash {
        return Err(StackError::conflict(
            "idempotency key reused with a different payload",
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct EventSummary {
    event_type: String,
    content_hash: [u8; 32],
    authored_at: TrellisTimestamp,
}

fn event_summary(event: &StoredEvent) -> Result<EventSummary, StackError> {
    let value = integrity_cbor::decode_cbor_value(event.canonical_event()).map_err(|error| {
        StackError::bad_request(format!("canonical event decode failed: {error}"))
    })?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::bad_request("canonical event is not a map"))?;
    let content_hash = map_lookup_fixed_bytes(map, "content_hash", 32)
        .map_err(cbor_bad_request)?
        .try_into()
        .map_err(|_| StackError::internal("content_hash length changed"))?;
    let header = map_lookup_map(map, "header").map_err(cbor_bad_request)?;
    let event_type =
        String::from_utf8(map_lookup_bytes(header, "event_type").map_err(cbor_bad_request)?)
            .map_err(|_| StackError::bad_request("event_type is not UTF-8"))?;
    let authored_at = timestamp_from_header(header)?;
    Ok(EventSummary {
        event_type,
        content_hash,
        authored_at,
    })
}

fn event_timestamp(event: &StoredEvent) -> Result<TrellisTimestamp, StackError> {
    event_summary(event).map(|summary| summary.authored_at)
}

pub(crate) fn event_hash(scope: &[u8], event: &StoredEvent) -> Result<[u8; 32], StackError> {
    if let Some(hash) = event.canonical_event_hash() {
        return Ok(*hash);
    }
    Ok(domain_separated_sha256(
        EVENT_DOMAIN,
        &canonical_event_hash_preimage(scope, event.canonical_event()),
    ))
}

fn timestamp_from_header(map: &[(Value, Value)]) -> Result<TrellisTimestamp, StackError> {
    let value = integrity_cbor::map_lookup_value(map, "authored_at").map_err(cbor_bad_request)?;
    let Value::Array(items) = value else {
        return Err(StackError::bad_request(
            "authored_at is not a timestamp array",
        ));
    };
    if items.len() != 2 {
        return Err(StackError::bad_request(
            "authored_at timestamp length is invalid",
        ));
    }
    let seconds = value_to_u64(&items[0], "authored_at seconds")?;
    let nanos = value_to_u64(&items[1], "authored_at nanos")?;
    let nanos = u32::try_from(nanos)
        .map_err(|_| StackError::bad_request("authored_at nanos exceeds u32"))?;
    TrellisTimestamp::new(seconds, nanos)
}

fn value_to_u64(value: &Value, label: &str) -> Result<u64, StackError> {
    let Value::Integer(integer) = value else {
        return Err(StackError::bad_request(format!(
            "{label} is not an integer"
        )));
    };
    u64::try_from(*integer)
        .map_err(|_| StackError::bad_request(format!("{label} is negative or too large")))
}

fn validate_idempotency_header(headers: &HeaderMap, body_key: &str) -> Result<(), StackError> {
    let header_key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| StackError::bad_request("idempotency key required"))?;
    if header_key != body_key {
        return Err(StackError::bad_request(
            "idempotency header must match request idempotencyKey",
        ));
    }
    Ok(())
}

fn validate_compute_context(body: &SubstrateAppendBody) -> Result<(), StackError> {
    if body.compute_context.sensitivity != ComputeSensitivity::PublicMetadata {
        return Err(StackError::bad_request(
            "this Trellis server path only admits publicMetadata payloads",
        ));
    }
    Ok(())
}

/// Rejects any `clientAttestation` object: COSE_Sign1 is not verified yet (TWREF-0103).
///
/// **Narrowing:** Until verification lands, the field must be omitted on the wire. When the JSON
/// object is present, [`SubstrateAppendBody::validate`] rejects empty `kid` / `cose_sign1` before
/// this check runs. Durable non-permissive startups enforce JWT scope allowlists on append
/// ([`TrellisServerState::production_like_scope_posture`]) in addition to this admission rule (TWREF-022).
fn reject_unverified_client_attestation(body: &SubstrateAppendBody) -> Result<(), StackError> {
    if body.client_attestation.is_some() {
        return Err(StackError::bad_request(
            "clientAttestation is not verified on trellis-server—omit this field. \
             COSE_Sign1 is not validated in this release (TWREF-0103).",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<(), StackError> {
    if scope.trim().is_empty() {
        return Err(StackError::bad_request("scope is required"));
    }
    if scope.contains('/') {
        return Err(StackError::bad_request("scope must be one path segment"));
    }
    if !scope.is_ascii() {
        return Err(StackError::bad_request("scope must be ASCII"));
    }
    Ok(())
}

fn normalize_checkpoint_digest(value: &str) -> Result<String, StackError> {
    if let Some(hex) = value.strip_prefix("sha256:") {
        validate_digest_hex(hex)?;
        Ok(value.to_string())
    } else {
        validate_digest_hex(value)?;
        Ok(format!("sha256:{value}"))
    }
}

fn validate_digest_hex(value: &str) -> Result<(), StackError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StackError::bad_request(
            "checkpoint digest must be sha256:<64 hex chars>",
        ));
    }
    Ok(())
}

pub(crate) fn now_timestamp() -> Result<TrellisTimestamp, StackError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StackError::internal(format!("system clock before epoch: {error}")))?;
    TrellisTimestamp::new(duration.as_secs(), duration.subsec_nanos())
}

pub(crate) fn timestamp_value(timestamp: TrellisTimestamp) -> Value {
    Value::Array(vec![
        uint(timestamp.unix_secs),
        uint(u64::from(timestamp.subsec_nanos)),
    ])
}

fn event_type_registry_view() -> EventTypeRegistryView {
    EventTypeRegistryView {
        registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
        event_types: WOS_EVENT_TYPES
            .iter()
            .map(|event_type| crate::openapi::EventTypeRegistryEntry {
                event_type: (*event_type).to_string(),
                schema_ref: format!("wos-events://{event_type}"),
            })
            .collect(),
    }
}

fn event_type_registry_cbor() -> Result<Vec<u8>, StackError> {
    const SERVICE_CLASSIFICATION: &str = "x-trellis-service/public-metadata";
    let mut event_types = Vec::new();
    for event_type in WOS_EVENT_TYPES {
        let entry = text_map(vec![
            ("privacy_class", Value::Text("publicMetadata".to_string())),
            ("binding_family", Value::Text("wos.kernel".to_string())),
        ])?;
        event_types.push((Value::Text((*event_type).to_string()), entry));
    }
    let formspec_entry = text_map(vec![
        ("privacy_class", Value::Text("publicMetadata".to_string())),
        (
            "binding_family",
            Value::Text("formspec.response".to_string()),
        ),
    ])?;
    event_types.push((
        Value::Text(FORMSPEC_RESPONSE_SUBMITTED.to_string()),
        formspec_entry,
    ));
    let registry = text_map(vec![
        ("event_types", Value::Map(event_types)),
        (
            "classifications",
            Value::Array(vec![Value::Text(SERVICE_CLASSIFICATION.to_string())]),
        ),
        (
            "registry_version",
            Value::Text(EVENT_TYPE_REGISTRY_VERSION.to_string()),
        ),
    ])?;
    encode_value(&registry)
}

fn signing_key_registry_cbor(signing_key: &ExportSigningKey) -> Result<Vec<u8>, StackError> {
    let entry = text_map(vec![
        ("kid", Value::Bytes(signing_key.kid().to_vec())),
        ("pubkey", Value::Bytes(signing_key.public_key.to_vec())),
        ("suite_id", uint(1)),
        ("status", uint(0)),
        ("valid_from", timestamp_value(signing_key.valid_from)),
        (
            "valid_to",
            signing_key.valid_to.map_or(Value::Null, timestamp_value),
        ),
        ("supersedes", Value::Null),
        ("attestation", Value::Null),
    ])?;
    encode_value(&Value::Array(vec![entry]))
}

pub(crate) fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, StackError> {
    canonical_map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_string()), value))
            .collect(),
    )
}

fn canonical_map(fields: Vec<(Value, Value)>) -> Result<Value, StackError> {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_value(&key)?;
            Ok((encoded, key, value))
        })
        .collect::<Result<Vec<_>, StackError>>()?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

pub(crate) fn encode_value(value: &Value) -> Result<Vec<u8>, StackError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))?;
    Ok(bytes)
}

pub(crate) fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn cbor_bad_request(error: CborHelperError) -> StackError {
    StackError::bad_request(error.to_string())
}

fn tenant_replay_scope(call: &IdempotencyCall) -> String {
    let tenant = header_value(&call.headers, "x-wos-tenant-id")
        .or_else(|| header_value(&call.headers, "x-formspec-tenant-id"))
        .unwrap_or("unknown-tenant");
    format!("{tenant}:{}", call.request.scope)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn encode_path_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push(hex_digit(other >> 4));
                out.push(hex_digit(other & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + (value - 10)) as char,
        _ => unreachable!("nibble is in range"),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use integrity_seam::OsSecureRandom;
    use jsonwebtoken::Algorithm;
    use stack_common_auth::JwtIssuer;
    use stack_common_http::idempotency::IDEMPOTENCY_REPLAY_HEADER;
    use tower::ServiceExt;
    use trellis_server_ports::{AdmissionEvent, ArtifactRef};
    use trellis_service_client::ClientAttestation;
    use wos_events::{ProvenanceKind, ProvenanceRecord, SUBSTRATE_CANONICAL_EVENT_LITERALS};

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Clone)]
    struct RecordingAppendRunner {
        /// Increments for each `AppendRunner::run_append` entry (HTTP → orchestration seam).
        invocations: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AppendRunner for RecordingAppendRunner {
        async fn run_append(
            &self,
            state: &TrellisServerState,
            command: append::AppendCommand,
        ) -> Result<append::AppendOutcome, StackError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            DefaultAppendRunner.run_append(state, command).await
        }
    }

    /// Given a Trellis router built with an injected append runner probe, when `POST …/events`
    /// succeeds, then the HTTP handler routed through `AppendRunner` exactly once (TWREF-021:
    /// orchestration is not inlined past the outer HTTP/auth boundary).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_append_runner_records_single_coordinator_pass()
    {
        // Given: Axum state substitutes [`RecordingAppendRunner`] ahead of [`DefaultAppendRunner`].
        let invocations = Arc::new(AtomicUsize::new(0));
        let runner = Arc::new(RecordingAppendRunner {
            invocations: invocations.clone(),
        });
        let app = router(test_state().with_append_runner(runner)).expect("router");

        // When: Client posts a valid append body.
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-append-runner-delegation"),
            ))
            .await
            .expect("append response");

        // Then: Handler invoked the injected runner once; coordinator path executed underneath.
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "POST append must delegate through AppendRunner (AppendCoordinator) rather than inlining orchestration"
        );
    }

    /// Given a fresh append, when the HTTP handler runs, then admission executes
    /// exactly once inside the append coordinator (not duplicated in the handler).
    #[tokio::test]
    async fn given_fresh_append_when_http_post_then_admission_runs_once_in_coordinator() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(RoutedEventAdmissionPolicy {
            wos: WosEventAdmissionPolicy,
            formspec: FormspecAppendAdmissionPolicy,
        });
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let app = router(test_state().with_admission_policy(counting)).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-coordinator-admission"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            1,
            "append coordinator must call admission exactly once per fresh append"
        );
    }

    /// Given a ledger idempotency replay, when the coordinator runs again with the
    /// same key, then admission runs once per pass and the sequence is unchanged.
    #[tokio::test]
    async fn given_ledger_idempotency_replay_when_coordinator_runs_then_admission_once_per_pass() {
        let admission_calls = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(RoutedEventAdmissionPolicy {
            wos: WosEventAdmissionPolicy,
            formspec: FormspecAppendAdmissionPolicy,
        });
        let counting = Arc::new(CountingAdmissionPolicy {
            inner,
            calls: admission_calls.clone(),
        });
        let state = test_state().with_admission_policy(counting);
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-replay")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            compute_context: append::port_compute_context(&body),
        };
        let first = state
            .append_coordinator()
            .append(command.clone())
            .await
            .expect("first append");
        assert_eq!(first.result.sequence, 0);
        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);

        let second = state
            .append_coordinator()
            .append(command)
            .await
            .expect("ledger replay");
        assert_eq!(
            admission_calls.load(Ordering::SeqCst),
            2,
            "each coordinator pass admits once; ledger replay must not duplicate events"
        );
        assert_eq!(second.result.sequence, first.result.sequence);
        assert_eq!(
            second.result.canonical_event_hash,
            first.result.canonical_event_hash
        );
    }

    /// Given a WOS provenance append, when the handler completes, then the receipt
    /// carries WOS profile id 1 (not the global Formspec profile 2).
    #[tokio::test]
    async fn given_wos_append_when_completed_then_receipt_profile_id_is_wos() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-wos-profile"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result.verification_receipt.profile_id,
            integrity_verify::WOS_PROFILE_ID,
            "WOS append receipts must use profile 1"
        );
    }

    /// Given a Formspec aggregate append, when admission runs, then the event is
    /// accepted and the receipt carries Formspec profile id 2.
    #[tokio::test]
    async fn given_formspec_response_submitted_when_appended_then_profile_id_is_formspec() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                formspec_append_body("idem-fspec-profile"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result.verification_receipt.event_type,
            FORMSPEC_RESPONSE_SUBMITTED
        );
        assert_eq!(
            result.verification_receipt.profile_id,
            integrity_verify::FORMSPEC_PROFILE_ID,
            "Formspec append receipts must use profile 2"
        );
    }

    #[test]
    fn given_signing_key_with_valid_to_when_registry_cbor_built_then_valid_to_is_encoded() {
        let valid_from = TrellisTimestamp::new(1_700_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_800_000_000, 0).expect("valid to");
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let registry_cbor = signing_key_registry_cbor(&signing_key.export_key())
            .expect("encode signing-key registry");
        let decoded = integrity_cbor::decode_cbor_value(&registry_cbor).expect("decode registry");
        let integrity_cbor::Value::Array(entries) = decoded else {
            panic!("registry must be a CBOR array");
        };
        let integrity_cbor::Value::Map(entry) = entries
            .first()
            .expect("registry must contain one signing-key entry")
        else {
            panic!("registry entry must be a CBOR map");
        };
        let valid_to_value = entry
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (integrity_cbor::Value::Text(label), value) if label == "valid_to" => Some(value),
                _ => None,
            })
            .expect("registry entry must include valid_to");
        assert_eq!(
            valid_to_value,
            &integrity_cbor::Value::Array(vec![
                integrity_cbor::Value::Integer(1_800_000_000.into()),
                integrity_cbor::Value::Integer(0.into()),
            ]),
            "registry valid_to must reflect signing key expiry"
        );
    }

    #[test]
    fn given_corrupt_export_zip_when_verified_then_returns_false() {
        assert!(!export_bundle_cryptographically_verified(
            b"not-a-valid-export-zip"
        ));
    }

    #[tokio::test]
    async fn given_fresh_append_when_completed_then_receipt_verified_reflects_export_verify() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-export-verified"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert!(
            result.verification_receipt.verified,
            "append receipt verified must be true only after export ZIP passes independent verification"
        );
    }

    #[tokio::test]
    async fn given_non_public_compute_context_when_append_requested_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&append_body("idem-non-public-compute")).unwrap();
        body["computeContext"]["sensitivity"] = serde_json::Value::String("readerHeld".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Inactive signing key (`valid_to` before wall-clock time) rejects append with BAD_REQUEST via
    /// `AppendCoordinator`; temporarily removing its `is_active_at` guard turns this case RED (201).
    #[tokio::test]
    async fn given_expired_signing_key_when_http_append_then_bad_request() {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        let valid_from = TrellisTimestamp::new(1_600_000_000, 0).expect("valid from");
        let valid_to = TrellisTimestamp::new(1_700_000_010, 0).expect("valid to");
        let signing_key = ServerSigningKey::from_cose_key_bytes(key, valid_from)
            .expect("parse signing key")
            .with_valid_to(Some(valid_to));
        let state = TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            TenantHeaderMode::MultiProducer,
        );
        let app = router(state).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-expired-signing-key"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn given_memory_storage_when_production_like_scope_posture_evaluated_then_false() {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: true,
            permissive_scope_auth: false,
        };
        assert!(!inputs.production_like_scope_posture());
    }

    #[test]
    fn given_durable_storage_with_permissive_when_production_like_scope_posture_evaluated_then_false()
     {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: true,
        };
        assert!(!inputs.production_like_scope_posture());
    }

    #[test]
    fn given_durable_storage_without_permissive_when_production_like_scope_posture_evaluated_then_true()
     {
        let inputs = TrellisScopeAuthorizerStartupInputs {
            storage_is_memory: false,
            permissive_scope_auth: false,
        };
        assert!(inputs.production_like_scope_posture());
    }

    #[test]
    fn given_production_like_posture_when_router_builds_with_allow_all_then_err() {
        let state = test_state().with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject misleading posture");
        let msg = err.to_string();
        assert!(
            msg.contains("scoped ScopeAuthorizer") && msg.contains("TWREF-022"),
            "{msg}"
        );
    }

    #[test]
    fn given_production_like_posture_when_scoped_authorizer_without_jwt_then_router_err() {
        let state = test_state()
            .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
            .with_production_like_scope_posture(true);
        let err = router(state).expect_err("router must reject missing jwt verifier");
        let msg = err.to_string();
        assert!(
            msg.contains("jwt_verifier") && msg.contains("TWREF-022"),
            "{msg}"
        );
    }

    const TEST_JWT_SECRET: &[u8] = b"trellis-test-jwt-secret";

    fn test_jwt_config() -> JwtConfig {
        JwtConfig {
            algorithm: Algorithm::HS256,
            validate_exp: true,
            validate_iss: None,
            validate_aud: None,
            leeway_secs: 30,
        }
    }

    fn test_trellis_token(scopes: Vec<String>) -> String {
        let issuer = JwtIssuer::<TrellisClaims>::from_hs256(
            test_jwt_config(),
            TEST_JWT_SECRET,
            Box::new(OsSecureRandom),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let jti = issuer.generate_jti().unwrap();
        let claims = TrellisClaims {
            base: BaseClaims {
                sub: "test-subject".to_string(),
                exp: now + 3600,
                iat: now,
                jti,
            },
            scopes,
        };
        issuer.issue(&claims).unwrap()
    }

    fn test_state_scoped_production_like() -> TrellisServerState {
        let verifier = JwtVerifier::<TrellisClaims>::from_hs256(test_jwt_config(), TEST_JWT_SECRET);
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        )
        .with_jwt_verifier(verifier)
        .with_scope_authorizer(Arc::new(ScopedAllowlistScopeAuthorizer))
        .with_production_like_scope_posture(true)
    }

    fn post_request_bearer(path: &str, body: Vec<u8>, bearer: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_without_bearer_then_unauthorized() {
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-bearer"),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn given_scoped_production_like_when_append_jwt_missing_scope_then_forbidden() {
        let token = test_trellis_token(vec!["other_scope".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-wrong-scope"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_omits_client_attestation_then_created() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                append_body("idem-prodlike-no-attest"),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn given_production_like_server_when_append_includes_client_attestation_then_bad_request()
    {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-attest")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let combined = format!(
            "{} {}",
            problem
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            problem
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        assert!(
            combined.contains("clientAttestation") && combined.contains("TWREF"),
            "problem should cite clientAttestation and TWREF, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_production_like_server_when_client_attestation_has_empty_kid_then_bad_request() {
        let token = test_trellis_token(vec!["case_123".to_string()]);
        let app = router(test_state_scoped_production_like()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-prodlike-empty-kid")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: String::new(),
            cose_sign1: "00".into(),
        });
        let response = app
            .oneshot(post_request_bearer(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
                &token,
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn given_test_server_when_append_includes_client_attestation_then_bad_request() {
        let app = router(test_state()).expect("router");
        let mut body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-client-attestation-present")).unwrap();
        body.client_attestation = Some(ClientAttestation {
            kid: "fixture-kid".into(),
            cose_sign1: "deadbeef".into(),
        });
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let ctype = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            ctype.contains("application/problem+json"),
            "expected application/problem+json, got {ctype:?}"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        let mut message = problem
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(detail) = problem.get("detail").and_then(|value| value.as_str()) {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(detail);
        }
        assert!(
            message.contains("clientAttestation"),
            "problem title/detail should cite clientAttestation, got {problem:?}"
        );
    }

    #[tokio::test]
    async fn given_fresh_append_when_coordinator_completes_then_persisted_hash_matches_wire() {
        let repo = Arc::new(InMemoryEventRepository::new());
        let state = TrellisServerState::new(
            repo.clone(),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        );
        let body: SubstrateAppendBody =
            serde_json::from_slice(&append_body("idem-coordinator-persisted-hash")).unwrap();
        let command = append::AppendCommand {
            scope: "case_123".to_string(),
            event_type: body.event_type.clone(),
            idempotency_key: body.idempotency_key.clone(),
            payload: body.payload.clone(),
            compute_context: append::port_compute_context(&body),
        };
        let outcome = state
            .append_coordinator()
            .append(command)
            .await
            .expect("coordinator append");
        let stored = repo
            .list_scope(b"case_123")
            .await
            .expect("list scope")
            .pop()
            .expect("one event");
        let hex_digest = outcome
            .result
            .canonical_event_hash
            .strip_prefix("sha256:")
            .expect("hash prefix");
        let bytes = hex::decode(hex_digest).expect("digest hex");
        let hash: [u8; 32] = bytes.try_into().expect("canonical hash is 32 bytes");
        assert_eq!(
            stored
                .canonical_event_hash()
                .expect("persisted substrate hash"),
            &hash,
            "coordinator commits before returning the append receipt canonical hash field",
        );
    }

    #[tokio::test]
    async fn append_wos_event_publishes_bundle_and_registries() {
        let app = router(test_state()).expect("router");
        let body = append_body("idem-1");
        let response = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let result: SubstrateAppendResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.sequence, 0);
        assert_eq!(
            result.verification_receipt.event_type,
            "wos.kernel.case_created"
        );
        assert!(result.canonical_event_hash.starts_with("sha256:"));

        let bundle = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_123/bundles/head"))
            .await
            .expect("bundle response");
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle_bytes = to_bytes(bundle.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        assert!(bundle_bytes.len() > 100);

        let registry = app
            .oneshot(get_request("/v1/scopes/case_123/registries/event-types"))
            .await
            .expect("registry response");
        assert_eq!(registry.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn given_same_scope_and_events_when_bundle_published_twice_then_zip_bytes_are_identical()
    {
        let state = test_state();
        let app = router(state.clone()).expect("router");
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_deterministic/events",
                append_body("idem-deterministic-1"),
            ))
            .await
            .expect("append deterministic event response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let events = state
            .repository
            .list_scope(b"case_deterministic")
            .await
            .expect("load deterministic scope events");
        let compute = append::default_public_compute_context();
        let first = publish_bundle(&state, b"case_deterministic", &events, false, &compute)
            .await
            .expect("first publish");
        let second = publish_bundle(&state, b"case_deterministic", &events, false, &compute)
            .await
            .expect("second publish");
        let first_bytes = state
            .artifact_store
            .get(&first.artifact_ref)
            .await
            .expect("load first bundle")
            .expect("first bundle bytes");
        let second_bytes = state
            .artifact_store
            .get(&second.artifact_ref)
            .await
            .expect("load second bundle")
            .expect("second bundle bytes");
        assert_eq!(
            first_bytes, second_bytes,
            "publishing identical ledger state twice must produce byte-identical ZIP output"
        );
    }

    #[tokio::test]
    async fn given_unreachable_artifact_store_when_health_probe_runs_then_reports_degraded() {
        struct FailingArtifactStore;

        #[async_trait]
        impl ArtifactStore for FailingArtifactStore {
            type Error = StackError;

            async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
                Err(StackError::unavailable("artifact store offline"))
            }

            async fn get(
                &self,
                _artifact_ref: &ArtifactRef,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(None)
            }
        }

        let state = test_state().with_artifact_store(Arc::new(FailingArtifactStore));
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "unreachable artifact store must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn given_repository_list_scope_unreachable_when_health_probe_runs_then_reports_degraded()
    {
        struct FailingEventRepository;

        #[async_trait]
        impl EventRepository for FailingEventRepository {
            async fn list_scope(&self, _scope: &[u8]) -> Result<Vec<StoredEvent>, StackError> {
                Err(StackError::unavailable(
                    "repository list_scope unreachable for test probe",
                ))
            }

            async fn append_event(&self, _event: StoredEvent) -> Result<(), StackError> {
                Err(StackError::internal("append not exercised in probe test"))
            }
        }

        let state = TrellisServerState::new(
            Arc::new(FailingEventRepository),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        );
        let health = TrellisHealthProbe::new(state).check().await;
        assert_eq!(
            health.status,
            stack_common_ops::ComponentStatus::Degraded,
            "repository probe failure must degrade readiness: {health:?}"
        );
    }

    #[tokio::test]
    async fn openapi_document_is_served_and_declares_substrate_routes() {
        let app = router(test_state()).expect("router");
        let response = app
            .oneshot(get_request("/openapi.json"))
            .await
            .expect("OpenAPI response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        crate::openapi::assert_trellis_openapi_shape(&doc);
    }

    /// Given a successful substrate append, when the same JSON body and idempotency key are
    /// POSTed again, then the HTTP replay middleware returns the stored response with
    /// `x-replay: true` (no second ledger append).
    #[tokio::test]
    async fn given_identical_append_when_posted_twice_then_http_middleware_replays() {
        let app = router(test_state()).expect("router");
        let body = append_body("idem-2");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert_eq!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).unwrap(),
            "true"
        );
    }

    /// Given a recorded HTTP idempotency entry for key K, when a second POST reuses K with a
    /// different body hash, then the shared middleware returns 409 and must not set `x-replay`.
    #[tokio::test]
    async fn given_recorded_replay_when_same_key_different_body_then_conflict_without_replay_header()
     {
        let app = router(test_state()).expect("router");
        let idem = "twref055-body-conflict";
        let first_body = append_body(idem);
        let first = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                first_body.clone(),
            ))
            .await
            .expect("first append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let mut variant: serde_json::Value = serde_json::from_slice(&first_body).expect("json");
        variant["payload"]["id"] = serde_json::Value::String("prov-alternate-body-hash".into());
        let second_body = serde_json::to_vec(&variant).expect("encode");

        let second = app
            .oneshot(post_request("/v1/scopes/case_123/events", second_body))
            .await
            .expect("second append");
        assert_eq!(second.status(), StatusCode::CONFLICT);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "409 conflict path must not mark responses as replayed"
        );
        let bytes = to_bytes(second.into_body(), 1024 * 1024).await.unwrap();
        let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["error_code"], "INFRA-4090");
        let title = problem["title"].as_str().unwrap_or_default();
        let detail = problem["detail"].as_str().unwrap_or_default();
        let combined = format!("{title} {detail}");
        assert!(
            combined.contains("idempotency"),
            "unexpected problem payload: {problem}"
        );
    }

    /// Given TWREF-055 closure, when `trellis-server-ports` is audited, then it must not reintroduce
    /// a parallel HTTP `IdempotencyStore` trait—replay stays on `stack_common_idempotency`.
    #[test]
    fn twref055_trellis_server_ports_has_no_parallel_http_idempotency_trait() {
        const PORTS_LIB: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-server-ports/src/lib.rs"
        ));
        assert!(
            !PORTS_LIB.contains("trait IdempotencyStore"),
            "TWREF-055: HTTP replay stays on stack_common_idempotency::HttpReplayStore (ADR 0092c)"
        );
        assert!(
            !PORTS_LIB.contains("IdempotencyReplay"),
            "TWREF-055: orphan IdempotencyReplay must not return alongside duplicate traits"
        );
    }

    /// Given distinct WOS tenant headers, when the same idempotency key and POST body are used,
    /// then the second tenant must not replay the first tenant's HTTP middleware cache entry.
    #[tokio::test]
    async fn given_distinct_wos_tenants_when_same_idempotency_body_then_no_cross_tenant_http_replay()
     {
        let app = router(test_state()).expect("router");
        let body = append_body("twref055-tenant-scope");
        let first = app
            .clone()
            .oneshot(post_request("/v1/scopes/case_123/events", body.clone()))
            .await
            .expect("tenant-a append");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_request_with_wos_tenant(
                "/v1/scopes/case_123/events",
                body,
                "tenant-b",
            ))
            .await
            .expect("tenant-b append");
        assert_eq!(second.status(), StatusCode::CREATED);
        assert!(
            second.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
            "tenant B must not replay tenant A's HttpReplayStore entry"
        );
    }

    #[test]
    fn given_wos_event_types_when_checked_against_provenance_kind_then_all_resolve() {
        for literal in WOS_EVENT_TYPES {
            assert!(
                ProvenanceKind::from_canonical_event_literal(literal).is_some(),
                "WOS_EVENT_TYPES literal `{literal}` must resolve through ProvenanceKind"
            );
        }
    }

    #[test]
    fn given_wos_event_types_when_defined_then_aliases_substrate_canonical_export() {
        assert!(
            std::ptr::eq(
                WOS_EVENT_TYPES.as_ptr(),
                SUBSTRATE_CANONICAL_EVENT_LITERALS.as_ptr()
            ),
            "trellis-server WOS_EVENT_TYPES must alias wos-events SUBSTRATE_CANONICAL_EVENT_LITERALS (TWREF-017)"
        );
        assert_eq!(
            WOS_EVENT_TYPES.len(),
            SUBSTRATE_CANONICAL_EVENT_LITERALS.len(),
            "substrate literal slice length drift"
        );
    }

    #[tokio::test]
    async fn unknown_wos_event_type_is_rejected() {
        let app = router(test_state()).expect("router");
        let mut value: serde_json::Value = serde_json::from_slice(&append_body("idem-3")).unwrap();
        value["eventType"] = serde_json::Value::String("wos.kernel.unknown".to_string());
        let response = app
            .oneshot(post_request(
                "/v1/scopes/case_123/events",
                serde_json::to_vec(&value).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_wrong_event_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-wrong-type")).unwrap();
        body["eventType"] = serde_json::Value::String("wos.kernel.case_created".to_string());
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn formspec_append_rejects_missing_aggregate_type() {
        let app = router(test_state()).expect("router");
        let mut body: serde_json::Value =
            serde_json::from_slice(&formspec_append_body("idem-fspec-missing-aggregate")).unwrap();
        body["payload"] = serde_json::json!({
            "aggregateId": "resp-missing-aggregate",
            "payload": { "status": "submitted" }
        });
        let response = app
            .oneshot(formspec_post_request(
                "/v1/scopes/formspec.prod-mvp/events",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .expect("append response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn test_signing_key() -> ServerSigningKey {
        let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
        let key = fs::read(key_path).expect("fixture key");
        ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).unwrap())
            .expect("signing key")
    }

    fn test_state() -> TrellisServerState {
        TrellisServerState::new(
            Arc::new(InMemoryEventRepository::new()),
            test_signing_key(),
            TenantHeaderMode::MultiProducer,
        )
    }

    fn formspec_append_body(idempotency_key: &str) -> Vec<u8> {
        let body = SubstrateAppendBody {
            event_type: FORMSPEC_RESPONSE_SUBMITTED.to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("formspec-server"),
            payload: serde_json::json!({
                "aggregateType": "formspec.response",
                "aggregateId": format!("resp-{idempotency_key}"),
                "payload": { "status": "submitted" }
            }),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "formspec-server",
            ),
            client_attestation: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn formspec_post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-formspec-tenant-id", "tenant-a")
            .header("x-formspec-workspace-id", "workspace-a")
            .header("x-formspec-environment-id", "prod")
            .header("x-formspec-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn append_body(idempotency_key: &str) -> Vec<u8> {
        let mut record = ProvenanceRecord::blank(ProvenanceKind::CaseCreated);
        record.id = format!("prov-{idempotency_key}");
        let body = SubstrateAppendBody {
            event_type: "wos.kernel.case_created".to_string(),
            idempotency_key: idempotency_key.to_string(),
            actor: trellis_service_client::AppendActor::service("wos-server"),
            payload: serde_json::to_value(record).unwrap(),
            compute_context: trellis_service_client::ComputeContext::no_delegated_compute(
                "wos-server",
            ),
            client_attestation: None,
        };
        serde_json::to_vec(&body).unwrap()
    }

    fn post_request(path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn post_request_with_wos_tenant(path: &str, body: Vec<u8>, tenant: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_from_body(&body))
            .header("x-wos-tenant-id", tenant)
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap()
    }

    fn get_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::empty())
            .unwrap()
    }

    fn idempotency_from_body(body: &[u8]) -> String {
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        value["idempotencyKey"].as_str().unwrap().to_string()
    }

    struct CountingAdmissionPolicy {
        inner: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventAdmissionPolicy for CountingAdmissionPolicy {
        type Error = StackError;

        async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.admit(event).await
        }
    }
}
