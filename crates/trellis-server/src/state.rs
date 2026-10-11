// Rust guideline compliant 2026-02-21
//! Cloneable Axum state, env bootstrap, and health probe (TWREF-086 `state` split).

use std::env;
use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use stack_common_auth::{AccessTokenVerifier, JwtConfig, JwtVerifier, VerifiedAccessIdentity};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::idempotency::{
    HttpIdempotencyState, IdempotencyCall, IdempotencyClaim, IdempotencyDecision,
    IdempotencyDriverError, IdempotencyFailure, IdempotencyOperation,
    IdempotencyResponseDisposition,
};
use stack_common_http::problem_response;
use stack_common_http::tenant::{
    HeaderConfig, TenantHeaderConfigProvider, TenantScope, extract_tenant,
    extract_tenant_multi_producer,
};
use stack_common_idempotency::{
    HttpReplayScope, HttpReplayStore, InMemoryHttpReplayStore, ReplayOutcome,
    ScopedHttpReplayStore, ScopedReplayOutcome, StoredResponse,
};
use stack_common_ops::{ComponentHealth, HealthProbe};
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{
    ArtifactStore, EventAdmissionPolicy, S3CompatibleArtifactStore, S3ObjectConfig, ScopeAuthorizer,
};

use crate::admission::{AllowAllScopeAuthorizer, ScopedAllowlistScopeAuthorizer};
use crate::append::{AppendRunner, DefaultAppendRunner};
use crate::artifacts::{BundleIndex, BundleIndexPort, InMemoryArtifactStore, ScopeLocks};
use crate::composition::{EventTypeCatalog, default_admission_policy};
use crate::event_repository::{
    EventRepository, InMemoryEventRepository, PostgresBundleIndex, PostgresEventRepository,
};
use crate::scope_startup::TrellisScopeAuthorizerStartupInputs;
use crate::{ServerSigningKey, TenantHeaderMode, TrellisClaims};

pub(crate) type ProfileExportVerifier = dyn Fn(&[u8]) -> bool + Send + Sync;

/// Explicit verifier selection; verification never falls back between modes.
#[derive(Clone)]
enum Authentication {
    Unconfigured,
    LocalJwt(Arc<JwtVerifier<TrellisClaims>>),
    External(Arc<dyn AccessTokenVerifier>),
}

pub(crate) enum AuthenticatedRequest {
    Anonymous,
    LocalJwt(TrellisClaims),
    External(VerifiedAccessIdentity),
}

impl AuthenticatedRequest {
    pub(crate) fn actor<'a>(&'a self, fallback: &'a str) -> &'a str {
        match self {
            Self::Anonymous => fallback,
            Self::LocalJwt(claims) => &claims.base.sub,
            Self::External(identity) => &identity.subject,
        }
    }

    pub(crate) fn external_identity(&self) -> Option<&VerifiedAccessIdentity> {
        match self {
            Self::External(identity) => Some(identity),
            _ => None,
        }
    }

    pub(crate) fn legacy_scopes(&self) -> Option<&[String]> {
        match self {
            Self::LocalJwt(claims) => Some(&claims.scopes),
            _ => None,
        }
    }
}

/// Cloneable Axum state for the Trellis service.
#[derive(Clone)]
pub struct TrellisServerState {
    pub(crate) external_attachment_recipients:
        Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>,
    pub(crate) external_attachment_random: Arc<dyn integrity_seam::SecureRandom>,
    pub(crate) repository: Arc<dyn EventRepository>,
    pub(crate) artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    pub(crate) admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    pub(crate) authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    pub(crate) signing_key: ServerSigningKey,
    tenant_header_mode: TenantHeaderMode,
    replay_store: Arc<InMemoryHttpReplayStore>,
    pub(crate) bundles: Arc<dyn BundleIndexPort>,
    pub(crate) scope_locks: Arc<ScopeLocks>,
    authentication: Authentication,
    /// True when [`state_from_env`] used durable storage without `TRELLIS_PERMISSIVE_SCOPE_AUTH=1`.
    production_like_scope_posture: bool,
    /// True while the built-in [`AllowAllScopeAuthorizer`] from [`Self::new`] is still installed.
    scope_authorizer_allow_all: bool,
    pub(crate) append_runner: Arc<dyn AppendRunner>,
    /// Event-type catalog snapshot built from registered admission specs at
    /// startup; the catalog projection routes consult this and never re-parse
    /// literals or hand-build constants.
    pub(crate) event_type_catalog: Arc<EventTypeCatalog>,
    pub(crate) profile_export_verifier: Arc<ProfileExportVerifier>,
}

impl TrellisServerState {
    #[must_use]
    pub fn in_memory(signing_key: ServerSigningKey, tenant_header_mode: TenantHeaderMode) -> Self {
        Self::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            tenant_header_mode,
        )
    }

    #[must_use]
    pub(crate) fn new(
        repository: Arc<dyn EventRepository>,
        signing_key: ServerSigningKey,
        tenant_header_mode: TenantHeaderMode,
    ) -> Self {
        Self {
            external_attachment_recipients: None,
            external_attachment_random: Arc::new(integrity_seam::OsSecureRandom),
            repository,
            artifact_store: Arc::new(InMemoryArtifactStore::default()),
            admission_policy: default_admission_policy(),
            authorizer: Arc::new(AllowAllScopeAuthorizer),
            signing_key,
            tenant_header_mode,
            replay_store: Arc::new(InMemoryHttpReplayStore::new()),
            bundles: Arc::new(BundleIndex::default()),
            scope_locks: Arc::new(ScopeLocks::default()),
            authentication: Authentication::Unconfigured,
            production_like_scope_posture: false,
            scope_authorizer_allow_all: true,
            append_runner: Arc::new(DefaultAppendRunner),
            event_type_catalog: Arc::new(EventTypeCatalog::default_stack()),
            profile_export_verifier: Arc::new(crate::composition::wos_profile_export_verified),
        }
    }

    /// Selects trusted recipient lookup for the closed protected transport.
    #[must_use]
    pub fn with_external_attachment_recipients(
        mut self,
        selector: Arc<dyn crate::ExternalAttachmentRecipientSelector>,
    ) -> Self {
        self.external_attachment_recipients = Some(selector);
        self
    }

    /// Test-only: replace the append runner (constructor injection for delegation proofs).
    #[cfg(test)]
    pub(crate) fn with_append_runner(mut self, runner: Arc<dyn AppendRunner>) -> Self {
        self.append_runner = runner;
        self
    }

    /// Test-only: replace profile export verification to prove publication is fail-closed.
    #[cfg(test)]
    pub(crate) fn with_profile_export_verifier(
        mut self,
        verifier: Arc<ProfileExportVerifier>,
    ) -> Self {
        self.profile_export_verifier = verifier;
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

    pub(crate) fn with_bundle_index(mut self, bundles: Arc<dyn BundleIndexPort>) -> Self {
        self.bundles = bundles;
        self
    }

    #[must_use]
    pub fn with_jwt_verifier(mut self, verifier: JwtVerifier<TrellisClaims>) -> Self {
        self.authentication = Authentication::LocalJwt(Arc::new(verifier));
        self
    }

    /// Selects injected external access-token verification without local-token fallback.
    ///
    /// Supply the maintained current-authority verifier when revocation is required.
    /// The host must also inject an authorizer that maps identities and grants exact
    /// tenant, scope, action and actor delegation; router construction rejects allow-all.
    #[must_use]
    pub fn with_access_token_verifier(mut self, verifier: Arc<dyn AccessTokenVerifier>) -> Self {
        self.authentication = Authentication::External(verifier);
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
        if matches!(&self.authentication, Authentication::External(_))
            && self.scope_authorizer_allow_all
        {
            return Err(StackError::bad_request(
                "external access-token mode requires a host scope authorizer with explicit grants",
            ));
        }
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
        if matches!(&self.authentication, Authentication::Unconfigured) {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 TRELLIS_JWT_HS256_SECRET / jwt_verifier or injected access_token_verifier (TWREF-022).",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn append_coordinator(&self) -> crate::append::AppendCoordinator<'_> {
        crate::append::AppendCoordinator::new(self)
    }

    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedRequest, StackError> {
        if matches!(&self.authentication, Authentication::Unconfigured) {
            return Ok(AuthenticatedRequest::Anonymous);
        }
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                StackError::new(
                    ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                    StatusCode::UNAUTHORIZED,
                    "missing bearer token",
                )
            })?;
        match &self.authentication {
            Authentication::Unconfigured => unreachable!("unconfigured mode returned above"),
            Authentication::LocalJwt(verifier) => {
                verifier.verify(token).map(AuthenticatedRequest::LocalJwt)
            }
            Authentication::External(verifier) => verifier
                .verify(token)
                .await
                .map(AuthenticatedRequest::External)
                .map_err(|error| {
                    if error.is_unavailable() {
                        StackError::unavailable("access-token current authority unavailable")
                    } else {
                        StackError::new(
                            ErrorCode::new("INFRA-4010").expect("static error code is valid"),
                            StatusCode::UNAUTHORIZED,
                            "access token rejected",
                        )
                    }
                }),
        }
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
        if native_replay_call(call) {
            return match self
                .replay_store
                .check_or_record(
                    &NativeReplayScope(tenant_replay_scope(call)),
                    "",
                    &call.request.key,
                    &call.request.request_hash,
                )
                .await
            {
                Ok(ScopedReplayOutcome::Recorded) => Ok(IdempotencyDecision::Fresh),
                Ok(ScopedReplayOutcome::Replayed { response }) => {
                    Ok(IdempotencyDecision::Replay(response))
                }
                Err(error) if error.status() == StatusCode::CONFLICT => {
                    Ok(IdempotencyDecision::Conflict)
                }
                Err(error) => Err(IdempotencyDriverError::store(error)),
            };
        }
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
        if native_replay_call(call) {
            return self
                .replay_store
                .record_response(
                    &NativeReplayScope(tenant_replay_scope(call)),
                    "",
                    &call.request.key,
                    &call.request.request_hash,
                    response,
                )
                .await
                .map_err(IdempotencyDriverError::store);
        }
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

    fn http_idempotency_response_disposition(
        &self,
        call: &IdempotencyCall,
        response: &Response,
    ) -> IdempotencyResponseDisposition {
        if native_replay_call(call)
            && response
                .extensions()
                .get::<crate::external_transport::RetryableStorageAttempt>()
                .is_some()
        {
            IdempotencyResponseDisposition::RetryableAttempt
        } else {
            IdempotencyResponseDisposition::Replay
        }
    }

    async fn finish_http_idempotency_attempt(
        &self,
        call: &IdempotencyCall,
        claim: Option<&IdempotencyClaim>,
        disposition: IdempotencyResponseDisposition,
        response: StoredResponse,
    ) -> Result<(), IdempotencyDriverError<Self::Error>> {
        if claim.is_some() {
            return Err(IdempotencyDriverError::store(StackError::unavailable(
                "unexpected HTTP replay claim",
            )));
        }
        if native_replay_call(call)
            && disposition == IdempotencyResponseDisposition::RetryableAttempt
        {
            // Reservation already retained the exact fingerprint. Failed storage attempts
            // leave response=None; completion never overwrites a concurrent success.
            return Ok(());
        }
        self.record_http_idempotency_response(call, response).await
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

fn tenant_replay_scope(call: &IdempotencyCall) -> String {
    if let Some(partition) = &call.replay_partition {
        // Length-prefix the trusted partition so arbitrary principal/route text cannot collide.
        return format!("{}:{}{}", partition.len(), partition, call.request.scope);
    }
    let tenant = header_value(&call.headers, "x-wos-tenant-id")
        .or_else(|| header_value(&call.headers, "x-formspec-tenant-id"))
        .unwrap_or("unknown-tenant");
    format!("{tenant}:{}", call.request.scope)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
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

    let (repository, bundle_index): (Arc<dyn EventRepository>, Option<Arc<dyn BundleIndexPort>>) =
        if trellis_storage_is_memory {
            (Arc::new(InMemoryEventRepository::new()), None)
        } else {
            let database_url = env::var("TRELLIS_DATABASE_URL")
                .map_err(|_| StackError::bad_request("TRELLIS_DATABASE_URL is required"))?;
            let pool = trellis_store_postgres_async::build_pool(&database_url, 10)
                .await
                .map_err(|error| StackError::unavailable(format!("postgres pool: {error}")))?;
            trellis_store_postgres_async::run_migrations(&pool)
                .await
                .map_err(|error| {
                    StackError::unavailable(format!("postgres migrations: {error}"))
                })?;
            (
                Arc::new(PostgresEventRepository::new(pool.clone())),
                Some(Arc::new(PostgresBundleIndex::new(pool))),
            )
        };

    let mut state = TrellisServerState::new(repository, signing_key, tenant_header_mode);
    if let Some(bundle_index) = bundle_index {
        state = state.with_bundle_index(bundle_index);
    }
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
pub(crate) struct TrellisHealthProbe {
    state: TrellisServerState,
}

impl TrellisHealthProbe {
    pub(crate) fn new(state: TrellisServerState) -> Self {
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

// This partition is minted by the authenticated typed middleware, never a request header.
fn native_replay_call(call: &IdempotencyCall) -> bool {
    call.replay_partition
        .as_deref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| {
            value
                .as_array()
                .and_then(|values| values.get(3))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|route| route == "accepted-attachment")
}
struct NativeReplayScope(String);
impl HttpReplayScope for NativeReplayScope {
    fn replay_scope_id(&self) -> String {
        self.0.clone()
    }
}
