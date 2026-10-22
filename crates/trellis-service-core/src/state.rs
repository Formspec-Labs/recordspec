// Rust guideline compliant 2026-02-21
//! Cloneable Axum state and env bootstrap (TWREF-086 `state` split).
//!
//! The router state holds configuration and verifiers only, never a ledger, pool or bucket: data
//! is reached through the scoped handle each request's gate admits (ADR 0168 §1.2). Startup reads
//! the environment into a [`Startup`]: the state, the deployment's scopes, and the storage the
//! composition root opens.

use std::env;
use std::fs;
use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
#[cfg(test)]
use stack_common_auth::JwtVerifier;
use stack_common_auth::{AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::idempotency::IdempotencyCall;
use stack_common_idempotency::{HttpReplayScope, InMemoryHttpReplayStore, ScopedHttpReplayStore};
use stack_common_object_store::S3ObjectConfig;
use stack_common_scope::{DeploymentConfig, ScopeKey};
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{EventAdmissionPolicy, ExportProfile, NativeCloseout, ScopeAuthorizer};

use crate::ServerSigningKey;
#[cfg(test)]
use crate::TrellisClaims;
use crate::adapters::{EventTypeCatalog, ServerAdapters};
use crate::admission::AllowAllScopeAuthorizer;
use crate::append::{AppendRunner, DefaultAppendRunner};
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
    pub(crate) admission_policy: Arc<dyn EventAdmissionPolicy<Error = StackError>>,
    pub(crate) authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    /// The Ledger purpose key: signs events and checkpoints.
    pub(crate) signing_key: ServerSigningKey,
    /// The Manifest purpose key: signs export manifests (Core `artifact_type = "manifest"`).
    /// The Ledger key until [`Self::with_manifest_key`]; production refuses that (ADR 0169 §1.2).
    pub(crate) manifest_key: ServerSigningKey,
    pub(crate) replay_store: Arc<InMemoryHttpReplayStore>,
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
    /// State with the shipped adapters and no authentication: every request is admitted to the
    /// deployment's one scope (or the one its `x-stack-scope-key` selects). Router construction
    /// refuses it beside external authentication or a production posture.
    ///
    /// The ledgers and buckets are not part of the state: the composition root moves them into
    /// the deployment it passes to [`crate::router`], so several servers (before and after a key
    /// rotation, say) can serve one ledger store.
    #[must_use]
    pub fn new(signing_key: ServerSigningKey, adapters: ServerAdapters) -> Self {
        let signing_key = signing_key.with_purpose(integrity_seam::Purpose::Ledger);
        let manifest_key = signing_key
            .clone()
            .with_purpose(integrity_seam::Purpose::Manifest);
        Self {
            completion: None,
            external_attachment_recipients: None,
            external_attachment_admission: adapters.external_attachment_admission,
            external_attachment_random: Arc::new(integrity_seam::OsSecureRandom),
            admission_policy: adapters.admission_policy,
            authorizer: Arc::new(AllowAllScopeAuthorizer),
            manifest_key,
            signing_key,
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

    /// Signs export manifests with `manifest_key`, its own purpose key (ADR 0169 §1.2).
    #[must_use]
    pub fn with_manifest_key(mut self, manifest_key: ServerSigningKey) -> Self {
        self.manifest_key = manifest_key.with_purpose(integrity_seam::Purpose::Manifest);
        self
    }

    /// Alias for [`Self::with_manifest_key`] binding the manifest signing key to
    /// [`integrity_seam::Purpose::Manifest`].
    #[must_use]
    pub fn with_manifest_signing_key(self, manifest_signing_key: ServerSigningKey) -> Self {
        self.with_manifest_key(manifest_signing_key)
    }

    /// Returns the Ledger signing key (`Purpose::Ledger`).
    #[must_use]
    pub const fn signing_key(&self) -> &ServerSigningKey {
        &self.signing_key
    }

    /// Returns the Manifest signing key (`Purpose::Manifest`).
    #[must_use]
    pub const fn manifest_key(&self) -> &ServerSigningKey {
        &self.manifest_key
    }

    /// Returns the Manifest signing key (`Purpose::Manifest`).
    #[must_use]
    pub const fn manifest_signing_key(&self) -> &ServerSigningKey {
        &self.manifest_key
    }

    /// Returns the Ledger [`integrity_seam::PurposeSigner`] (`KeyFileSigner`).
    #[must_use]
    pub fn ledger_purpose_signer(&self) -> &Arc<dyn integrity_seam::PurposeSigner> {
        self.signing_key.purpose_signer()
    }

    /// Returns the Manifest [`integrity_seam::PurposeSigner`] (`KeyFileSigner`).
    #[must_use]
    pub fn manifest_purpose_signer(&self) -> &Arc<dyn integrity_seam::PurposeSigner> {
        self.manifest_key.purpose_signer()
    }

    /// Every registry row an export carries: the Ledger key's history, then the Manifest key's
    /// when it is a different key. Each is its own supersession chain.
    #[must_use]
    pub fn signing_key_registry(&self) -> Vec<trellis_export_writer::SigningKeyRegistryEntry> {
        let mut rows = self.signing_key.registry_entries();
        if self.manifest_key.kid_hex() != self.signing_key.kid_hex() {
            rows.extend(self.manifest_key.registry_entries());
        }
        rows
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
        principal: &str,
        scope: &trellis_server_ports::LedgerScope,
        request: &trellis_service_client::CompletionRequest,
    ) -> Result<(), StackError> {
        // The ledger scope names its scope key, so the partition is per scope and principal.
        let partition = serde_json::to_string(&(principal, scope.as_str(), "completion"))
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

    #[cfg(test)]
    #[must_use]
    pub fn with_jwt_verifier(mut self, verifier: JwtVerifier<TrellisClaims>) -> Self {
        self.authentication = Authentication::LocalJwt(Arc::new(verifier));
        self
    }

    /// Selects injected external access-token verification without local-token fallback.
    ///
    /// Supply the maintained current-authority verifier when revocation is required.
    /// The host must also inject an authorizer that maps identities to their bound scopes and
    /// grants exact ledger, action and actor delegation; router construction rejects allow-all.
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
        assert_eq!(
            self.signing_key.purpose(),
            integrity_seam::Purpose::Ledger,
            "checkpoint signing key must be bound to Purpose::Ledger"
        );
        crate::ledger::Checkpointer {
            signing_key: self.signing_key.core_key(),
            purpose: self.signing_key.purpose(),
            export_profile: self.export_profile.as_ref(),
        }
    }

    #[must_use]
    pub(crate) fn append_coordinator<'a>(
        &'a self,
        scoped: &'a crate::TrellisScoped,
    ) -> crate::append::AppendCoordinator<'a> {
        crate::append::AppendCoordinator::new(self, scoped)
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

/// What startup read from the environment: the router state, the deployment's scopes and the
/// storage the composition root opens.
///
/// Reading it opens nothing: no pool, no bucket, no network. The composition root (`trellis-main`)
/// opens [`StorageConfig`]'s database and buckets for [`Startup::deployment`]'s cell, builds the
/// [`crate::TrellisStore`], and moves it into the `Deployment` it serves.
pub struct Startup {
    pub state: TrellisServerState,
    pub deployment: DeploymentConfig,
    pub storage: StorageConfig,
}

/// Where the deployment's ledgers and objects live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageConfig {
    /// Postgres, or `None` for in-memory ledgers (`TRELLIS_STORAGE=memory`).
    pub database: Option<DatabaseConfig>,
    /// Trellis's own bucket, or `None` for an in-memory bucket.
    pub artifacts: Option<ObjectStoreConfig>,
    /// The bucket WOS prepares Source batches in, when Source content is composed.
    pub source_content: Option<ObjectStoreConfig>,
}

/// The serving role's Postgres connection (ADR 0168 §6.5). Serving never migrates, so it holds
/// no owner credential; `trellis-server migrate` reads `TRELLIS_MIGRATION_DATABASE_URL` itself.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// The serving role: owns no table, neither superuser nor `BYPASSRLS`.
    pub url: String,
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // URLs carry credentials.
        f.debug_struct("DatabaseConfig").finish_non_exhaustive()
    }
}

/// An S3-compatible bucket and the key prefix the deployment's objects sit under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreConfig {
    pub s3: S3ObjectConfig,
    pub prefix: String,
}

/// Reads the server's configuration from environment variables.
///
/// Always required:
/// - `TRELLIS_SIGNING_KEY_COSE_PATH` (the Ledger key: events and checkpoints)
/// - `TRELLIS_DEPLOYMENT_FILE` (the deployment's cell and scopes, ADR 0168 §3.3)
/// - `TRELLIS_OIDC_CONFIG_FILE` (strict current provider and exact resource grants)
///
/// Required unless `TRELLIS_STORAGE=memory`:
/// - `TRELLIS_DATABASE_URL` (the serving role; `trellis-server migrate` ran as the owner first)
///
/// Optional:
/// - `TRELLIS_SIGNING_KEY_HISTORY_PATH`, `TRELLIS_MANIFEST_SIGNING_KEY_HISTORY_PATH` (each key's
///   public history, oldest first, ending at the key)
/// - `TRELLIS_MANIFEST_SIGNING_KEY_COSE_PATH` (the Manifest key: export manifests); the Ledger key
///   signs manifests without it, which production refuses (ADR 0169 §1.2)
/// - `TRELLIS_PROFILE=development|production` (default `production`); production refuses in-memory
///   storage, a signing key file other users can read, any publicly known fixture signing key,
///   and one public key serving both purposes
/// - `TRELLIS_STORAGE=memory` (in-memory ledgers; skips the database URLs)
/// - `TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE` (completion operator signing keys)
/// - `TRELLIS_SOURCE_CONTENT_CONFIG_FILE` (Source-content publisher, pins, object store, native policy)
/// - `TRELLIS_ARTIFACT_BUCKET`, `TRELLIS_ARTIFACT_PREFIX`, `TRELLIS_ARTIFACT_ENDPOINT`,
///   `TRELLIS_ARTIFACT_REGION` (Trellis's own bucket; in memory without a bucket)
///
/// # Errors
/// Returns an error when OIDC or deployment configuration is missing or invalid, legacy auth
/// environment settings are supplied, or the signing key is refused.
pub fn startup_from_env(adapters: ServerAdapters) -> Result<Startup, StackError> {
    let deployment = deployment_from_env()?;
    // Qualify required authentication before reading signing keys.
    let authentication = StartupAuth::from_env(&deployment)?;
    let completion = crate::completion_startup::StartupCompletion::from_env(&adapters)?;
    let trellis_storage_is_memory = matches!(env::var("TRELLIS_STORAGE").as_deref(), Ok("memory"));

    let profile = crate::posture::profile_from_env()?;
    let signing_key = purpose_key_from_env(
        profile,
        integrity_seam::Purpose::Ledger,
        "TRELLIS_SIGNING_KEY_COSE_PATH",
        "TRELLIS_SIGNING_KEY_HISTORY_PATH",
    )?
    .ok_or_else(|| StackError::bad_request("TRELLIS_SIGNING_KEY_COSE_PATH is required"))?;
    let manifest_key = purpose_key_from_env(
        profile,
        integrity_seam::Purpose::Manifest,
        "TRELLIS_MANIFEST_SIGNING_KEY_COSE_PATH",
        "TRELLIS_MANIFEST_SIGNING_KEY_HISTORY_PATH",
    )?
    .unwrap_or_else(|| {
        signing_key
            .clone()
            .with_purpose(integrity_seam::Purpose::Manifest)
    });
    crate::posture::check(
        profile,
        trellis_storage_is_memory,
        &signing_key,
        &manifest_key,
    )?;

    let database = if trellis_storage_is_memory {
        None
    } else {
        Some(DatabaseConfig {
            url: env_optional("TRELLIS_DATABASE_URL")
                .ok_or_else(|| StackError::bad_request("TRELLIS_DATABASE_URL is required"))?,
        })
    };
    let state = authentication
        .apply(TrellisServerState::new(signing_key, adapters).with_manifest_key(manifest_key));
    let (state, source_content) = match completion {
        Some(completion) => completion.apply(state),
        None => (state, None),
    };
    Ok(Startup {
        state,
        deployment,
        storage: StorageConfig {
            database,
            artifacts: artifact_store_from_env(),
            source_content,
        },
    })
}

/// One purpose's signing key from `key_variable` (absent when unset), with the public history
/// `history_variable` names applied when set.
fn purpose_key_from_env(
    profile: stack_common_posture::Profile,
    purpose: integrity_seam::Purpose,
    key_variable: &str,
    history_variable: &str,
) -> Result<Option<ServerSigningKey>, StackError> {
    let Some(path) = env_optional(key_variable) else {
        return Ok(None);
    };
    let bytes = crate::posture::read_signing_key(profile, key_variable, &path)?;
    let key = ServerSigningKey::from_cose_key_bytes(bytes, TrellisTimestamp::new(0, 0)?)?;
    let key = match env_optional(history_variable) {
        Some(history) => {
            let history = fs::read(&history).map_err(|error| {
                StackError::bad_request(format!("failed to read {history_variable}: {error}"))
            })?;
            key.with_history_json(&history)?
        }
        None => key,
    };
    Ok(Some(key.with_purpose(purpose)))
}

/// Longest deployment file accepted, in bytes.
const MAX_DEPLOYMENT_FILE: u64 = 1024 * 1024;

/// Reads `TRELLIS_DEPLOYMENT_FILE`: the deployment's cell and the scopes it serves.
///
/// # Errors
/// Refuses a missing, oversized or malformed file, or scopes whose keys collide.
pub fn deployment_from_env() -> Result<DeploymentConfig, StackError> {
    let path = env_optional("TRELLIS_DEPLOYMENT_FILE")
        .ok_or_else(|| StackError::bad_request("TRELLIS_DEPLOYMENT_FILE is required"))?;
    let invalid = || StackError::bad_request("TRELLIS_DEPLOYMENT_FILE is not a deployment");
    let file = fs::File::open(&path).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_DEPLOYMENT_FILE + 1),
        &mut bytes,
    )
    .map_err(|_| invalid())?;
    if bytes.len() as u64 > MAX_DEPLOYMENT_FILE {
        return Err(invalid());
    }
    let config: DeploymentConfig = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    deployment_keys(&config)?;
    Ok(config)
}

/// The keys of the deployment's scopes, sorted; `Deployment::new` makes the remaining checks
/// (no scope listed twice, the public scope listed) when the composition root builds it.
///
/// # Errors
/// A bad request when a name breaks the scope grammar.
pub(crate) fn deployment_keys(config: &DeploymentConfig) -> Result<Vec<ScopeKey>, StackError> {
    let mut keys = config
        .scopes
        .iter()
        .map(|scope| {
            scope
                .key()
                .map_err(|e| StackError::bad_request(format!("deployment: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    Ok(keys)
}

fn artifact_store_from_env() -> Option<ObjectStoreConfig> {
    let bucket = env_optional("TRELLIS_ARTIFACT_BUCKET")?;
    let prefix = env_optional("TRELLIS_ARTIFACT_PREFIX").unwrap_or_else(|| "trellis".to_string());
    Some(ObjectStoreConfig {
        s3: S3ObjectConfig {
            bucket,
            endpoint: env_optional("TRELLIS_ARTIFACT_ENDPOINT"),
            region: env_optional("TRELLIS_ARTIFACT_REGION"),
        },
        prefix,
    })
}

fn env_optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Whether the trusted partition names the accepted-attachment route.
///
/// The gate mints the partition as `{scope key}:{principal}` (never from a request header), and
/// the accepted-attachment admission's principal is the JSON tuple
/// `(principal, ledger scope, "accepted-attachment", policy fingerprint)`.
pub(crate) fn native_replay_call(call: &IdempotencyCall) -> bool {
    call.replay_partition
        .as_deref()
        .and_then(|value| value.split_once(':'))
        .and_then(|(_, principal)| serde_json::from_str::<serde_json::Value>(principal).ok())
        .and_then(|value| {
            value
                .as_array()
                .and_then(|values| values.get(2))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|route| route == "accepted-attachment")
}

pub(crate) struct NativeReplayScope(pub(crate) String);
impl HttpReplayScope for NativeReplayScope {
    fn replay_scope_id(&self) -> String {
        self.0.clone()
    }
}
