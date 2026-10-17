// Rust guideline compliant 2026-02-21
//! Cloneable Axum state, env bootstrap, and health probe (TWREF-086 `state` split).

use std::env;
use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
#[cfg(test)]
use stack_common_auth::JwtVerifier;
use stack_common_auth::{AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::idempotency::{
    HttpIdempotencyState, IdempotencyCall, IdempotencyDecision, IdempotencyDriverError,
    IdempotencyFailure, IdempotencyOperation,
};
use stack_common_http::problem_response;
use stack_common_http::tenant::{HeaderConfig, TenantHeaderConfigProvider, TenantScope};
use stack_common_idempotency::{
    HttpReplayScope, HttpReplayStore, InMemoryHttpReplayStore, ReplayOutcome,
    ScopedHttpReplayStore, ScopedReplayOutcome, StoredResponse,
};
use stack_common_ops::{ComponentHealth, HealthProbe};
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{
    ArtifactStore, EventAdmissionPolicy, ExportProfile, NativeCloseout, S3CompatibleArtifactStore,
    S3ObjectConfig, ScopeAuthorizer,
};

use crate::ServerSigningKey;
#[cfg(test)]
use crate::TrellisClaims;
use crate::adapters::{EventTypeCatalog, ServerAdapters, TenantHeaders};
use crate::admission::AllowAllScopeAuthorizer;
use crate::append::{AppendRunner, DefaultAppendRunner};
use crate::artifacts::InMemoryArtifactStore;
use crate::event_repository::{EventRepository, InMemoryEventRepository, PostgresEventRepository};
use crate::oidc_startup::StartupAuth;

/// Explicit verifier selection; verification never falls back between modes.
#[derive(Clone)]
enum Authentication {
    Unconfigured,
    #[cfg(test)]
    LocalJwt(Arc<JwtVerifier<TrellisClaims>>),
    External(Arc<dyn AccessTokenVerifier>),
}

pub(crate) enum AuthenticatedRequest {
    Anonymous,
    #[cfg(test)]
    LocalJwt(TrellisClaims),
    External(VerifiedAccessIdentity),
}

impl AuthenticatedRequest {
    pub(crate) fn actor<'a>(&'a self, fallback: &'a str) -> &'a str {
        match self {
            Self::Anonymous => fallback,
            #[cfg(test)]
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
            #[cfg(test)]
            Self::LocalJwt(claims) => Some(&claims.scopes),
            _ => None,
        }
    }
}

/// Cloneable Axum state for the Trellis service.
#[derive(Clone)]
pub struct TrellisServerState {
    /// The operator signer and the one principal that may ask for a seal (the WOS machine):
    /// the signer attests whatever selection that caller sent, so neither exists without the other.
    pub(crate) completion: Option<(Arc<dyn crate::CompletionSigner>, String)>,
    pub(crate) external_attachment_recipients:
        Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>,
    pub(crate) external_attachment_admission:
        Arc<dyn trellis_server_ports::ExternalAttachmentAdmission>,
    pub(crate) external_attachment_random: Arc<dyn integrity_seam::SecureRandom>,
    pub(crate) repository: Arc<dyn EventRepository>,
    pub(crate) artifact_store: Arc<dyn ArtifactStore<Error = StackError>>,
    pub(crate) admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    pub(crate) authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    pub(crate) signing_key: ServerSigningKey,
    tenant_headers: TenantHeaders,
    replay_store: Arc<InMemoryHttpReplayStore>,
    authentication: Authentication,
    /// True when startup selected current provider verification and exact resource grants.
    production_like_scope_posture: bool,
    /// True while the built-in [`AllowAllScopeAuthorizer`] from [`Self::new`] is still installed.
    scope_authorizer_allow_all: bool,
    pub(crate) append_runner: Arc<dyn AppendRunner>,
    pub(crate) native_closeout: Arc<dyn NativeCloseout>,
    /// Event-type catalog snapshot built from registered admission specs at
    /// startup; the catalog projection routes consult this and never re-parse
    /// literals or hand-build constants.
    pub(crate) event_type_catalog: Arc<EventTypeCatalog>,
    pub(crate) export_profile: Arc<dyn ExportProfile>,
    pub(crate) source_content: Option<crate::SourceContentComposition>,
}

impl TrellisServerState {
    #[must_use]
    pub fn in_memory(signing_key: ServerSigningKey, adapters: ServerAdapters) -> Self {
        Self::new(
            Arc::new(InMemoryEventRepository::new()),
            signing_key,
            adapters,
        )
    }

    /// State over a caller-supplied repository, so several servers (for example before and
    /// after a key rotation) can share one ledger.
    #[must_use]
    pub fn new(
        repository: Arc<dyn EventRepository>,
        signing_key: ServerSigningKey,
        adapters: ServerAdapters,
    ) -> Self {
        Self {
            completion: None,
            external_attachment_recipients: None,
            external_attachment_admission: adapters.external_attachment_admission,
            external_attachment_random: Arc::new(integrity_seam::OsSecureRandom),
            repository,
            artifact_store: Arc::new(InMemoryArtifactStore::default()),
            admission_policy: adapters.admission_policy,
            authorizer: Arc::new(AllowAllScopeAuthorizer),
            signing_key,
            tenant_headers: adapters.tenant_headers,
            replay_store: Arc::new(InMemoryHttpReplayStore::new()),
            authentication: Authentication::Unconfigured,
            production_like_scope_posture: false,
            scope_authorizer_allow_all: true,
            append_runner: Arc::new(DefaultAppendRunner),
            event_type_catalog: Arc::new(EventTypeCatalog::from_specs(adapters.event_type_specs)),
            export_profile: adapters.export_profile,
            native_closeout: adapters.native_closeout,
            source_content: None,
        }
    }

    /// Selects the separate operator signer that enables the completion seal, and the only
    /// principal allowed to ask for it: the signer attests whatever selection that caller sent.
    #[must_use]
    pub fn with_completion(
        mut self,
        signer: Arc<dyn crate::CompletionSigner>,
        publisher: impl Into<String>,
    ) -> Self {
        self.completion = Some((signer, publisher.into()));
        self
    }

    pub(crate) async fn reserve_completion_request(
        &self,
        tenant: &TenantScope,
        principal: &str,
        scope: &str,
        request: &trellis_service_client::CompletionRequest,
    ) -> Result<(), StackError> {
        let partition = serde_json::to_string(&(principal, tenant, scope, "completion"))
            .map_err(|_| StackError::internal("completion replay partition failed"))?;
        let body = serde_json::to_vec(request)
            .map_err(|_| StackError::bad_request("completion trigger invalid"))?;
        // Retain only the fingerprint. Never cache a completion locator: every
        // replay must recheck selected case and field disclosure permissions.
        self.replay_store
            .check_or_record(
                &NativeReplayScope(partition),
                "",
                &request.idempotency_key,
                &hex::encode(integrity_cbor::sha256_bytes(&body)),
            )
            .await?;
        Ok(())
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

    /// Selects committed Source reads and separate structural/final verification.
    #[must_use]
    pub fn with_source_content(mut self, composition: crate::SourceContentComposition) -> Self {
        self.source_content = Some(composition);
        self
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

    #[cfg(test)]
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
                 an explicit resource ScopeAuthorizer rather than AllowAll.",
            ));
        }
        if matches!(&self.authentication, Authentication::Unconfigured) {
            return Err(StackError::bad_request(
                "trellis-server refuses to build router: production_like_scope_posture requires \
                 an injected access-token verifier.",
            ));
        }
        Ok(())
    }

    /// Issues the checkpoint that follows a head with this server's signing key and export profile.
    pub(crate) fn checkpointer(&self) -> crate::ledger::Checkpointer<'_> {
        crate::ledger::Checkpointer {
            signing_key: self.signing_key.core_key(),
            export_profile: self.export_profile.as_ref(),
        }
    }

    #[must_use]
    pub(crate) fn append_coordinator(&self) -> crate::append::AppendCoordinator<'_> {
        crate::append::AppendCoordinator::new(self)
    }

    pub(crate) async fn bearer_identity(
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
            #[cfg(test)]
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
        self.tenant_headers.primary()
    }

    fn extract_tenant_scope(&self, headers: &HeaderMap) -> Result<TenantScope, StackError> {
        self.tenant_headers.extract(headers)
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
                    &NativeReplayScope(tenant_replay_scope(&self.tenant_headers, call)),
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
                &tenant_replay_scope(&self.tenant_headers, call),
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
                    &NativeReplayScope(tenant_replay_scope(&self.tenant_headers, call)),
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
                &tenant_replay_scope(&self.tenant_headers, call),
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

fn tenant_replay_scope(tenant_headers: &TenantHeaders, call: &IdempotencyCall) -> String {
    if let Some(partition) = &call.replay_partition {
        // Length-prefix the trusted partition so arbitrary principal/route text cannot collide.
        return format!("{}:{}{}", partition.len(), partition, call.request.scope);
    }
    let tenant = tenant_headers
        .extract(&call.headers)
        .map_or_else(|_| "unknown-tenant".to_owned(), |scope| scope.tenant);
    format!("{tenant}:{}", call.request.scope)
}

/// Builds a server state from environment variables.
///
/// Required unless `TRELLIS_STORAGE=memory`:
/// - `TRELLIS_DATABASE_URL`
///
/// Always required:
/// - `TRELLIS_SIGNING_KEY_COSE_PATH`
/// - `TRELLIS_OIDC_CONFIG_FILE` (strict current provider and exact resource grants)
///
/// Optional:
/// - `TRELLIS_PROFILE=development|production` (default `production`); production refuses in-memory
///   storage, a signing key file other users can read, and any publicly known fixture signing key
/// - `TRELLIS_STORAGE=memory` (in-memory repository; skips `TRELLIS_DATABASE_URL`)
/// - `TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE` (completion operator signing keys)
/// - `TRELLIS_SOURCE_CONTENT_CONFIG_FILE` (Source-content publisher, pins, object store, native policy)
/// - `TRELLIS_ARTIFACT_BUCKET`
/// - `TRELLIS_ARTIFACT_PREFIX`
/// - `TRELLIS_ARTIFACT_ENDPOINT`
/// - `TRELLIS_ARTIFACT_REGION`
///
/// # Errors
/// Returns an error when OIDC configuration is missing or invalid, legacy auth
/// environment settings are supplied, or signing-key/backend setup fails.
pub async fn state_from_env(adapters: ServerAdapters) -> Result<TrellisServerState, StackError> {
    // Qualify required authentication before reading signing keys or opening storage.
    let authentication = StartupAuth::from_env()?;
    let completion = crate::completion_startup::StartupCompletion::from_env(&adapters)?;
    let trellis_storage_is_memory = matches!(env::var("TRELLIS_STORAGE").as_deref(), Ok("memory"));

    let signing_key_path = env::var("TRELLIS_SIGNING_KEY_COSE_PATH")
        .map_err(|_| StackError::bad_request("TRELLIS_SIGNING_KEY_COSE_PATH is required"))?;
    let profile = crate::posture::profile_from_env()?;
    let signing_key_bytes = crate::posture::read_signing_key(profile, &signing_key_path)?;
    let signing_key =
        ServerSigningKey::from_cose_key_bytes(signing_key_bytes, TrellisTimestamp::new(0, 0)?)?;
    crate::posture::check(profile, trellis_storage_is_memory, &signing_key)?;
    let signing_key = match env_optional("TRELLIS_SIGNING_KEY_HISTORY_PATH") {
        Some(path) => {
            let history = fs::read(&path).map_err(|error| {
                StackError::bad_request(format!(
                    "failed to read TRELLIS_SIGNING_KEY_HISTORY_PATH: {error}"
                ))
            })?;
            signing_key.with_history_json(&history)?
        }
        None => signing_key,
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

    let mut state = TrellisServerState::new(repository, signing_key, adapters);
    if let Some(artifact_store) = artifact_store_from_env() {
        state = state.with_artifact_store(artifact_store);
    }

    let state = authentication.apply(state);
    Ok(match completion {
        Some(completion) => completion.apply(state),
        None => state,
    })
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
        if let Err(error) = self.state.repository.head_checkpoint(b"__healthz__").await {
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
