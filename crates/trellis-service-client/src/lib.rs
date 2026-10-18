// Rust guideline compliant 2026-02-21
#![allow(clippy::result_large_err)]
// `ServiceClientError` carries operational context (URL, status, body excerpt, source error chain)
// that callers rely on for retry/dispatch decisions. Boxing the error would change the public
// signature of every fallible method. Follow-up: convert `ServiceClientError` to a `Box<...>` newtype
// once a consumer needs the smaller `Result` size (none today; tracked separately).
//! Shared Trellis service HTTP client contract.
//!
//! Applications append to Trellis through this crate instead of each carrying
//! a bespoke substrate dialect. The core surface ([`SubstrateClient`],
//! [`SubstrateAppendRequest`], wire DTOs) is intentionally WOS-agnostic.
//! Typed WOS producer ergonomics live in the [`wos_ext`] module behind D12's
//! "blessed helper client with containment" contract — no other producer
//! vocabulary belongs in this crate; future overlays ship their own
//! `<producer>-trellis-binding` crate.
//!
//! ## Append dialects
//!
//! Ordinary event producers post through [`SubstrateClient::append_event`]
//! (`POST /v1/scopes/{scope}/events`). The Trellis admission composition root
//! (`trellis-server::composition::default_admission_policy`) routes the request
//! to one of two adapters before append commits:
//!
//! - **WOS provenance** — construct via [`wos_provenance_append_request`]
//!   (or the [`SubstrateClientExt::append_wos_provenance`] helper). The JSON
//!   Existing canonical payloads agree with their event literal. Remaining
//!   known native kinds use the owning validated original-record wrapper.
//! - **Formspec substrate** — construct via [`SubstrateAppendRequest::new_json`]
//!   with Formspec's aggregate envelope (`aggregateType`, `aggregateId`,
//!   `payload`). Trellis routes Formspec admission for the response-submitted
//!   proof literal and the Response Actions session operation-batch literal.
//!   Additional Formspec literals require extending `trellis-admission-formspec`
//!   and the Trellis composition router alongside admission updates.
//!
//! Accepted attachments use [`TrellisServiceClient::append_accepted_attachment`]
//! (`POST /v1/scopes/{scope}/accepted-attachments`). The caller sends its accepted
//! descriptor and exact original bytes; the server selects protection and recipients.
//! The client preserves the descriptor as JSON and leaves domain validation to admission.
//!
//! ## Trust boundaries
//!
//! **Case scope versus URL scope (TWREF-005).** The `{scope}` path segment
//! is a ledger scope, `<scope key hex>.<ledger id>` (ADR 0168 §1.6): the
//! deployment scope the caller is bound to, then a ledger id, not a governed
//! WOS case identity by itself. Callers such as `wos-server` or
//! `formspec-server` map their product identifiers into the ledger id; the
//! client selects the scope (`x-stack-scope-key`) from the ledger scope. Trellis admission enforces event shape and registry literals for
//! whatever scope is supplied; it does not substitute WOS relationship checks
//! from other services.
//!
//! **Governance overlay versus substrate admission (TWREF-064).** A reference
//! WOS HTTP surface may publish only a subset of WOS event literals while
//! still delegating to Trellis for append. The Trellis `trellis-admission-wos`
//! adapter admits the full `wos-events` substrate registry for callers that
//! bear Trellis service credentials. Treat Trellis bearer scope plus
//! admission as the substrate trust root for vocabulary allowance; WOS HTTP
//! routing remains a narrower product gate until shared authorizers align.
//!
//! **Why WOS helpers share this crate (TWREF-065 / D12).** WOS provenance
//! JSON and Formspec aggregate JSON differ in payload shape but share one
//! HTTP route. The D12-blessed WOS helpers live in [`wos_ext`] to keep the
//! generic client free of producer dialects while still offering typed
//! convenience for the dominant first-party producer.

#![forbid(unsafe_code)]

mod completion;
pub mod endpoints;
mod ledger_scope;
mod reconciliation;
pub mod source_content;
mod source_diagnostics;
pub use completion::{
    COMPLETION_EVENT, CompletionAttestor, CompletionRequest, CompletionSelection,
    CompletionSignerLabel,
};
#[doc(inline)]
pub use reconciliation::{
    AppendReconciliation, AppendReconciliationRequest, CanonicalAppendContent,
    ReconciliationUnknown, canonical_append_content,
};
pub use source_diagnostics::public_code;

#[doc(inline)]
pub use source_content::MAX_PREPARED_SOURCE_CONTENT_BYTES;
mod wos_ext;

pub use wos_ext::{SubstrateClientExt, WosProvenanceAppend, wos_provenance_append_request};

use std::{fmt, sync::Arc, time::Duration};

use stack_common_auth::client_credentials::ClientCredentialsTokenProvider;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use ledger_scope::{LedgerScope, validate_ledger_id};
use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_http::routes::{Absent, CallError, Target};
pub use stack_common_scope::SCOPE_KEY_HEADER;
use utoipa::ToSchema;
use utoipa::openapi::schema::{ObjectBuilder, SchemaType, Type};
use utoipa::openapi::{RefOr, Schema};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Formspec aggregate append `eventType` literal admitted at the Trellis HTTP edge.
///
/// `trellis-admission-formspec` declares the same literal as `FORMSPEC_RESPONSE_SUBMITTED`. The Trellis HTTP JSON
/// schema `$defs.EventType` enum must include the same literal (see `check-http-api-schema.py`).
pub const FORMSPEC_APPEND_EVENT_TYPE_LITERAL: &str = "substrate.append.response_submitted";

/// Formspec Response Actions session operation-batch append `eventType` literal.
///
/// `trellis-admission-formspec` declares the same literal as `FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH`.
/// The Trellis HTTP JSON schema `$defs.EventType` enum must include the same literal.
pub const FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH_EVENT_TYPE_LITERAL: &str =
    "substrate.append.response_action_session_op_batch";

#[must_use]
fn trellis_admitted_event_type_openapi_schema() -> RefOr<Schema> {
    let mut values: Vec<String> = wos_ext::WOS_CANONICAL_EVENT_LITERALS
        .iter()
        .copied()
        .map(str::to_string)
        .collect();
    values.push(wos_ext::WOS_NATIVE_PROVENANCE_EVENT_LITERAL.to_string());
    values.push(FORMSPEC_APPEND_EVENT_TYPE_LITERAL.to_string());
    values.push(FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH_EVENT_TYPE_LITERAL.to_string());
    values.sort();
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::String))
        .enum_values(Some(values))
        .description(Some(
            "Admitted Trellis append literals: `wos-events` substrate registry plus Formspec appends.",
        ))
        .into()
}

/// Maximum Trellis HTTP error response body bytes folded into [`StackError`] text.
///
/// Reverse proxies often return HTML pages; cap inclusion so logs and downstream copies stay bounded.
const APPEND_HTTP_ERROR_BODY_PREVIEW_BYTES: usize = 8 * 1024;

#[must_use]
fn truncate_utf8_body_for_error_preview(mut body: String, max_bytes: usize) -> String {
    if body.len() <= max_bytes {
        return body;
    }
    let mut end = max_bytes;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body.truncate(end);
    body.push_str("… (truncated)");
    body
}

/// Actor block carried by the Trellis append wire body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppendActor {
    pub kind: String,
    pub subject: String,
}

impl AppendActor {
    #[must_use]
    pub fn service(subject: impl Into<String>) -> Self {
        Self {
            kind: "service".to_string(),
            subject: subject.into(),
        }
    }

    #[must_use]
    pub fn user(subject: impl Into<String>) -> Self {
        Self {
            kind: "user".to_string(),
            subject: subject.into(),
        }
    }
}

/// Sensitivity class disclosed for a producer's compute path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ComputeSensitivity {
    PublicMetadata,
    ProviderReadable,
    ReaderHeld,
    Restricted,
}

impl ComputeSensitivity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicMetadata => "publicMetadata",
            Self::ProviderReadable => "providerReadable",
            Self::ReaderHeld => "readerHeld",
            Self::Restricted => "restricted",
        }
    }
}

/// Required delegated-compute disclosure context for append producers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComputeContext {
    pub declaration_id: String,
    pub actor: String,
    pub sensitivity: ComputeSensitivity,
}

impl ComputeContext {
    #[must_use]
    pub fn new(
        declaration_id: impl Into<String>,
        actor: impl Into<String>,
        sensitivity: ComputeSensitivity,
    ) -> Self {
        Self {
            declaration_id: declaration_id.into(),
            actor: actor.into(),
            sensitivity,
        }
    }

    #[must_use]
    pub fn no_delegated_compute(actor: impl Into<String>) -> Self {
        let actor = actor.into();
        Self {
            declaration_id: format!("compute:{actor}:publicMetadata"),
            actor,
            sensitivity: ComputeSensitivity::PublicMetadata,
        }
    }
}

/// Optional direct-client attestation block.
///
/// **Trellis-server (2026-05-15):** Requests that include this field are rejected with
/// `400`; `cose_sign1` is not cryptographically verified yet. Omit the field until
/// verification lands (TWREF-0103). Durable deployments without `TRELLIS_PERMISSIVE_SCOPE_AUTH`
/// use the same HTTP admission as tests (TWREF-022 narrowing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientAttestation {
    pub kid: String,
    pub cose_sign1: String,
}

/// One append request against `POST /v1/scopes/{scope}/events`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendRequest {
    /// The ledger the event is appended to.
    #[serde(skip)]
    pub scope: LedgerScope,
    pub event_type: String,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub payload: serde_json::Value,
    pub compute_context: ComputeContext,
    /// Optional client attestation reserved for direct-signer flows — **omit** for
    /// `trellis-server` until verification is implemented (see [`ClientAttestation`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientAttestation>,
    /// Claim about the prepared Source-content batch object (ADR 0163); only the final
    /// Source closeout carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content: Option<source_content::SourceContentClaim>,
}

/// JSON body for `POST /v1/scopes/{scope}/events`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendBody {
    #[schema(schema_with = trellis_admitted_event_type_openapi_schema)]
    pub event_type: String,
    pub idempotency_key: String,
    pub actor: AppendActor,
    pub payload: serde_json::Value,
    pub compute_context: ComputeContext,
    /// Optional client attestation reserved for direct-signer flows — **omit** for
    /// `trellis-server` until verification is implemented (see [`ClientAttestation`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_attestation: Option<ClientAttestation>,
    /// Claim about the prepared Source-content batch object (ADR 0163): the object's hash and
    /// size and the selection WOS derived. Trellis reads the object from its own derived key,
    /// so no address or credential travels. The reconcile lookup identity ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content: Option<source_content::SourceContentClaim>,
}

/// Maximum original bytes accepted by the protected attachment HTTP route.
pub const ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT: usize = 1024 * 1024;
/// Maximum serialized descriptor metadata accepted by the attachment HTTP route.
pub const ACCEPTED_ATTACHMENT_DESCRIPTOR_BYTES_LIMIT: usize = 64 * 1024;
/// Event literal used to validate accepted attachment receipts.
pub const ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL: &str =
    "substrate.append.accepted_attachment_binding";

/// Original attachment and accepted descriptor sent to the protected append route.
///
/// The server selects protection, recipients and compute disclosure. The descriptor
/// remains generic JSON here; the server validates its closed domain schema and
/// the authenticated caller's authority. `original_bytes` uses standard padded Base64.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedAttachmentAppendBody {
    #[schema(min_length = 1, max_length = 64)]
    pub idempotency_key: String,
    #[serde(deserialize_with = "deserialize_attachment_actor")]
    #[schema(value_type = ClosedAttachmentActor)]
    pub actor: AppendActor,
    #[schema(schema_with = attachment_descriptor_openapi_schema)]
    pub descriptor: serde_json::Value,
    /// Standard padded Base64 for one nonempty original, bounded to 1 MiB decoded.
    #[schema(min_length = 4, max_length = 1398104, format = Byte)]
    pub original_bytes: String,
}

/// OpenAPI schema for the accepted-attachment descriptor object, shared with the server route.
pub fn attachment_descriptor_openapi_schema() -> RefOr<Schema> {
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::Object))
        .description(Some("Accepted Source descriptor object; serialized metadata is limited to 64 KiB and the server validates its closed domain schema."))
        .into()
}

fn attachment_actor_kind_openapi_schema() -> RefOr<Schema> {
    ObjectBuilder::new()
        .schema_type(SchemaType::new(Type::String))
        .enum_values(Some(["service"]))
        .into()
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ClosedAttachmentActor {
    #[schema(schema_with = attachment_actor_kind_openapi_schema)]
    kind: String,
    subject: String,
}

fn deserialize_attachment_actor<'de, D>(deserializer: D) -> Result<AppendActor, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let actor = ClosedAttachmentActor::deserialize(deserializer)?;
    Ok(AppendActor {
        kind: actor.kind,
        subject: actor.subject,
    })
}

impl AcceptedAttachmentAppendBody {
    /// Encodes bounded original bytes using the maintained attachment wire format.
    /// # Errors
    /// Refuses invalid actor, descriptor, key, or original byte bounds.
    pub fn from_original_bytes(
        idempotency_key: String,
        actor: AppendActor,
        descriptor: serde_json::Value,
        bytes: &[u8],
    ) -> Result<Self, StackError> {
        if bytes.is_empty() || bytes.len() > ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT {
            return Err(StackError::bad_request(
                "attachment original bytes exceed bound",
            ));
        }
        let body = Self {
            idempotency_key,
            actor,
            descriptor,
            original_bytes: STANDARD.encode(bytes),
        };
        body.validate()?;
        Ok(body)
    }
    /// Validates bounded attachment transport fields before sending original bytes.
    ///
    /// # Errors
    /// Refuses an invalid idempotency key, nonservice actor, oversized or nonobject
    /// descriptor, and empty, oversized or noncanonical standard Base64 bytes.
    pub fn validate(&self) -> Result<(), StackError> {
        validate_required("idempotency_key", &self.idempotency_key)?;
        if self.idempotency_key.len() > 64 || self.actor.kind != "service" {
            return Err(StackError::bad_request(
                "attachment requires a 1..64-byte key and service actor",
            ));
        }
        validate_required("actor.subject", &self.actor.subject)?;
        if !self.descriptor.is_object()
            || serde_json::to_vec(&self.descriptor)
                .map_err(|_| StackError::bad_request("attachment descriptor encoding failed"))?
                .len()
                > ACCEPTED_ATTACHMENT_DESCRIPTOR_BYTES_LIMIT
        {
            return Err(StackError::bad_request(
                "attachment descriptor must be a bounded object",
            ));
        }
        let encoded_limit = ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT.div_ceil(3) * 4;
        if self.original_bytes.is_empty() || self.original_bytes.len() > encoded_limit {
            return Err(StackError::bad_request("attachment original byte limit"));
        }
        let original = STANDARD.decode(&self.original_bytes).map_err(|_| {
            StackError::bad_request("attachment original bytes require standard padded Base64")
        })?;
        if original.is_empty()
            || original.len() > ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT
            || STANDARD.encode(&original) != self.original_bytes
        {
            return Err(StackError::bad_request(
                "attachment original bytes are oversized or noncanonical Base64",
            ));
        }
        Ok(())
    }
}

impl SubstrateAppendRequest {
    /// Builds a request for an already-typed JSON event payload.
    ///
    /// # Errors
    /// Returns an error when required routing or event fields are empty.
    pub fn new_json(
        scope: LedgerScope,
        event_type: impl Into<String>,
        idempotency_key: impl Into<String>,
        actor: AppendActor,
        payload: serde_json::Value,
        compute_context: ComputeContext,
    ) -> Result<Self, StackError> {
        let request = Self {
            scope,
            event_type: event_type.into(),
            idempotency_key: idempotency_key.into(),
            actor,
            payload,
            compute_context,
            client_attestation: None,
            source_content: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Attaches the claim for the final Source closeout.
    #[must_use]
    pub fn with_source_content(mut self, claim: source_content::SourceContentClaim) -> Self {
        self.source_content = Some(claim);
        self
    }

    /// Attaches a direct-client attestation block.
    #[must_use]
    pub fn with_client_attestation(mut self, attestation: ClientAttestation) -> Self {
        self.client_attestation = Some(attestation);
        self
    }

    #[must_use]
    pub fn body(&self) -> SubstrateAppendBody {
        SubstrateAppendBody {
            event_type: self.event_type.clone(),
            idempotency_key: self.idempotency_key.clone(),
            actor: self.actor.clone(),
            payload: self.payload.clone(),
            compute_context: self.compute_context.clone(),
            client_attestation: self.client_attestation.clone(),
            source_content: self.source_content.clone(),
        }
    }

    fn validate(&self) -> Result<(), StackError> {
        self.body().validate()?;
        Ok(())
    }
}

impl SubstrateAppendBody {
    /// Validates route-independent append body fields.
    ///
    /// # Errors
    /// Returns an error when the body is missing load-bearing wire fields.
    pub fn validate(&self) -> Result<(), StackError> {
        validate_required("event_type", &self.event_type)?;
        validate_required("idempotency_key", &self.idempotency_key)?;
        validate_required("actor.kind", &self.actor.kind)?;
        validate_required("actor.subject", &self.actor.subject)?;
        validate_required(
            "compute_context.declaration_id",
            &self.compute_context.declaration_id,
        )?;
        validate_required("compute_context.actor", &self.compute_context.actor)?;
        if let Some(attestation) = &self.client_attestation {
            validate_required("client_attestation.kid", &attestation.kid)?;
            validate_required("client_attestation.cose_sign1", &attestation.cose_sign1)?;
        }
        if let Some(claim) = &self.source_content {
            claim.validate()?;
        }
        Ok(())
    }
}

/// Append response returned by the Trellis service.
///
/// `checkpoint_ref` names the signed checkpoint at `sequence + 1`, durable when the response is
/// sent. The Core §18 export at that checkpoint (`GET .../bundles/{checkpointDigest}`) is the
/// receipt's proof; nothing is published at append time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateAppendResult {
    pub event_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_event_hash: Option<String>,
    pub canonical_event_hash: String,
    pub checkpoint_ref: String,
}

impl SubstrateAppendResult {
    /// Validates a response from the Trellis event-append endpoint.
    ///
    /// # Errors
    /// Returns an error when the append response is missing an identity or names a checkpoint
    /// outside the requested scope.
    pub fn validate_for_event_append(&self, scope: &LedgerScope) -> Result<(), StackError> {
        validate_required("event_id", &self.event_id)?;
        if let Some(prior_event_hash) = &self.prior_event_hash {
            validate_required("prior_event_hash", prior_event_hash)?;
        }
        validate_required("canonical_event_hash", &self.canonical_event_hash)?;
        validate_required("checkpoint_ref", &self.checkpoint_ref)?;
        let checkpoint_prefix = format!("trellis://{scope}/checkpoints/");
        if !self.checkpoint_ref.starts_with(&checkpoint_prefix) {
            return Err(StackError::unavailable(
                "trellis append response checkpointRef is outside the requested scope",
            ));
        }
        Ok(())
    }
}

/// Core shared substrate client contract.
#[async_trait]
pub trait SubstrateClient: Send + Sync {
    /// Reconciles an original append without creating events or publications.
    ///
    /// Absence describes a single read point and grants no authority to append.
    /// # Errors
    /// Refuses unsupported clients, invalid input or unavailable transport/admission.
    async fn reconcile_event(
        &self,
        _scope: &LedgerScope,
        _request: &AppendReconciliationRequest,
    ) -> Result<AppendReconciliation, StackError> {
        Err(StackError::unavailable(
            "append reconciliation is unsupported",
        ))
    }

    /// Appends one event through the Trellis service.
    ///
    /// # Errors
    /// Returns an error if the request is invalid, the service rejects it, or
    /// the response cannot be decoded.
    async fn append_event(
        &self,
        request: SubstrateAppendRequest,
    ) -> Result<SubstrateAppendResult, StackError>;

    /// Fetches the current export bundle for `scope`.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn head_bundle(&self, scope: &LedgerScope) -> Result<Vec<u8>, StackError>;

    /// Fetches the export bundle pinned at `checkpoint_digest`.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn bundle(
        &self,
        scope: &LedgerScope,
        checkpoint_digest: &str,
    ) -> Result<Vec<u8>, StackError>;

    /// Fetches the current signing-key registry projection.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn signing_key_registry(&self, scope: &LedgerScope) -> Result<Vec<u8>, StackError>;

    /// Fetches the current event-type registry projection.
    ///
    /// # Errors
    /// Returns an error if the service rejects the request.
    async fn event_type_registry(
        &self,
        scope: &LedgerScope,
    ) -> Result<serde_json::Value, StackError>;
}

/// Configures the concrete HTTP client.
#[derive(Clone, PartialEq, Eq)]
pub struct TrellisServiceClientConfig {
    pub endpoint: String,
    pub service_bearer_token: Option<String>,
    pub timeout: Duration,
}

impl fmt::Debug for TrellisServiceClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrellisServiceClientConfig")
            .field("endpoint", &self.endpoint)
            .field(
                "service_bearer_token",
                &self.service_bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl TrellisServiceClientConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service_bearer_token: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_service_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.service_bearer_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Reqwest-backed Trellis service client.
#[derive(Clone)]
pub struct TrellisServiceClient {
    config: TrellisServiceClientConfig,
    http: reqwest::Client,
    token_provider: Option<Arc<dyn ClientCredentialsTokenProvider>>,
}

impl fmt::Debug for TrellisServiceClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrellisServiceClient")
            .field("config", &self.config)
            .field(
                "token_provider",
                &self.token_provider.as_ref().map(|_| "[configured]"),
            )
            .finish_non_exhaustive()
    }
}

impl TrellisServiceClient {
    /// Creates a concrete Trellis service client.
    ///
    /// # Errors
    /// Returns an error if endpoint is empty or the HTTP client cannot be
    /// constructed.
    pub fn new(config: TrellisServiceClientConfig) -> Result<Self, StackError> {
        validate_endpoint(&config.endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                StackError::internal(format!("failed to construct Trellis HTTP client: {error}"))
            })?;
        Ok(Self {
            config,
            http,
            token_provider: None,
        })
    }

    /// Sends original attachment bytes through the server's selected protection path.
    ///
    /// Reuses bearer, scope-selector and idempotency headers from the maintained client.
    /// The descriptor is domain-validated by the server; successful responses must
    /// identify the requested scope and accepted attachment event literal.
    ///
    /// # Errors
    /// Refuses invalid transport fields, HTTP failures and invalid append receipts.
    pub async fn append_accepted_attachment(
        &self,
        scope: &LedgerScope,
        body: &AcceptedAttachmentAppendBody,
    ) -> Result<SubstrateAppendResult, StackError> {
        body.validate()?;
        let request = self.target().call(
            endpoints::ACCEPTED_ATTACHMENT,
            &endpoints::ScopePath {
                scope: scope.to_string(),
            },
            &Absent,
            body,
            Some(&body.idempotency_key),
        );
        let response = self
            .authorized(request, scope)
            .await?
            .send()
            .await
            .map_err(|error| {
                StackError::unavailable(format!("trellis attachment append failed: {error}"))
            })?;
        Self::append_response(response, scope).await
    }

    /// Seals a completion certificate from the facts the caller embeds in `body.selection`.
    ///
    /// The caller authenticates as a machine; the selection is bound by the idempotency key
    /// and `expected_head`, so a retry with a different selection is a changed retry.
    ///
    /// # Errors
    /// Refuses invalid triggers or selections and invalid append receipts.
    pub async fn seal_completion(
        &self,
        scope: &LedgerScope,
        body: &CompletionRequest,
    ) -> Result<SubstrateAppendResult, StackError> {
        body.validate()?;
        let request = self.target().call(
            endpoints::SEAL_COMPLETION,
            &endpoints::ScopePath {
                scope: scope.to_string(),
            },
            &Absent,
            body,
            Some(&body.idempotency_key),
        );
        let response = self
            .authorized(request, scope)
            .await?
            .send()
            .await
            .map_err(|_| StackError::unavailable("trellis completion request failed"))?;
        Self::append_response(response, scope).await
    }

    async fn append_response(
        response: reqwest::Response,
        scope: &LedgerScope,
    ) -> Result<SubstrateAppendResult, StackError> {
        Self::append_response_diagnostic(response, scope, false).await
    }

    async fn append_response_diagnostic(
        response: reqwest::Response,
        scope: &LedgerScope,
        selected: bool,
    ) -> Result<SubstrateAppendResult, StackError> {
        use source_diagnostics::{Outcome, Stage};
        source_diagnostics::mark(selected, Stage::Response, Outcome::Enter);
        if !response.status().is_success() {
            let status = response.status();
            let body = truncate_utf8_body_for_error_preview(
                response.text().await.unwrap_or_default(),
                APPEND_HTTP_ERROR_BODY_PREVIEW_BYTES,
            );
            source_diagnostics::http_refusal(selected, status.as_u16(), &body);
            return Err(StackError::unavailable(format!(
                "trellis append returned HTTP {status}: {body}"
            )));
        }
        source_diagnostics::mark(selected, Stage::Response, Outcome::ReturnedOk);
        source_diagnostics::mark(selected, Stage::Decode, Outcome::Enter);
        let result = response
            .json::<SubstrateAppendResult>()
            .await
            .map_err(|error| {
                source_diagnostics::mark(selected, Stage::Decode, Outcome::Refused);
                StackError::unavailable(format!("trellis append response is invalid: {error}"))
            })?;
        source_diagnostics::mark(selected, Stage::Decode, Outcome::ReturnedOk);
        source_diagnostics::mark(selected, Stage::Receipt, Outcome::Enter);
        source_diagnostics::observed(
            selected,
            Stage::Receipt,
            result.validate_for_event_append(scope),
        )?;
        Ok(result)
    }

    /// Selects current workload tokens from a maintained injected provider.
    ///
    /// The provider owns issuer, audience, scopes, credentials and renewal. This
    /// client acquires once per request and never caches or falls back to a token.
    ///
    /// # Errors
    /// Refuses any simultaneous configured static bearer token.
    pub fn with_token_provider(
        mut self,
        provider: Arc<dyn ClientCredentialsTokenProvider>,
    ) -> Result<Self, StackError> {
        if self.config.service_bearer_token.is_some() {
            return Err(StackError::bad_request(
                "Trellis static bearer and current token provider are mutually exclusive",
            ));
        }
        self.token_provider = Some(provider);
        Ok(self)
    }

    fn target(&self) -> Target<'_> {
        Target::new(&self.http, &self.config.endpoint)
    }

    /// Adds the scope selector and the service credential to a request an endpoint described.
    ///
    /// The `x-stack-scope-key` selector is the key the [`LedgerScope`] was made under, so a
    /// principal bound to several scopes is admitted to the one its ledger lives under, and the
    /// server checks the ledger against it.
    async fn authorized(
        &self,
        request: Result<reqwest::RequestBuilder, CallError>,
        scope: &LedgerScope,
    ) -> Result<reqwest::RequestBuilder, StackError> {
        let mut request = request.map_err(|error| {
            StackError::bad_request(format!("trellis request refused: {error}"))
        })?;
        request = request.header(SCOPE_KEY_HEADER, scope.key().to_string());
        if let Some(provider) = &self.token_provider {
            let token = provider
                .access_token()
                .await
                .map_err(|_| StackError::unavailable("Trellis service token acquisition failed"))?;
            request = request.bearer_auth(token.expose_secret());
        } else if let Some(token) = &self.config.service_bearer_token {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }
}

impl TrellisServiceClient {
    async fn send_event_append(
        &self,
        request: SubstrateAppendRequest,
    ) -> Result<SubstrateAppendResult, StackError> {
        use source_diagnostics::{Outcome, Stage};
        let source_selected = request.source_content.is_some();
        source_diagnostics::mark(source_selected, Stage::Input, Outcome::Enter);
        source_diagnostics::observed(source_selected, Stage::Input, request.validate())?;
        source_diagnostics::mark(source_selected, Stage::Request, Outcome::Enter);
        let called = self.target().call(
            endpoints::APPEND_EVENT,
            &endpoints::ScopePath {
                scope: request.scope.to_string(),
            },
            &Absent,
            &request.body(),
            Some(&request.idempotency_key),
        );
        let outgoing = self
            .authorized(called, &request.scope)
            .await
            .map_err(|error| {
                source_diagnostics::mark(source_selected, Stage::Request, Outcome::Refused);
                error
            })?;
        source_diagnostics::mark(source_selected, Stage::Request, Outcome::ReturnedOk);
        source_diagnostics::mark(source_selected, Stage::Send, Outcome::Enter);
        let response = outgoing.send().await.map_err(|error| {
            if error.is_builder() {
                source_diagnostics::mark(source_selected, Stage::Request, Outcome::Refused);
            } else {
                source_diagnostics::send_error(source_selected, &error);
            }
            if source_selected {
                StackError::unavailable("trellis Source-content append transport failed")
            } else {
                StackError::unavailable(format!("trellis append failed: {error}"))
            }
        })?;
        source_diagnostics::mark(source_selected, Stage::Send, Outcome::ReturnedOk);
        Self::append_response_diagnostic(response, &request.scope, source_selected).await
    }
}

#[async_trait]
impl SubstrateClient for TrellisServiceClient {
    async fn reconcile_event(
        &self,
        scope: &LedgerScope,
        request: &AppendReconciliationRequest,
    ) -> Result<AppendReconciliation, StackError> {
        request.validate()?;
        // Bound token acquisition, HTTP and decoding together; never retry or fall back to append.
        tokio::time::timeout(self.config.timeout, async {
            let called = self.target().call(
                endpoints::RECONCILE_EVENT,
                &endpoints::ScopePath {
                    scope: scope.to_string(),
                },
                &Absent,
                request,
                None,
            );
            let response = self
                .authorized(called, scope)
                .await?
                .send()
                .await
                .map_err(|_| {
                    StackError::unavailable("append reconciliation transport unavailable")
                })?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(StackError::unavailable(
                    "append reconciliation admission refused",
                ));
            }
            let result = response
                .json::<AppendReconciliation>()
                .await
                .map_err(|_| StackError::unavailable("append reconciliation response invalid"))?;
            if let AppendReconciliation::Committed { receipt } = &result {
                receipt.validate_for_event_append(scope)?;
            }
            Ok(result)
        })
        .await
        .map_err(|_| StackError::unavailable("append reconciliation deadline exceeded"))?
    }

    async fn append_event(
        &self,
        request: SubstrateAppendRequest,
    ) -> Result<SubstrateAppendResult, StackError> {
        self.send_event_append(request).await
    }

    async fn head_bundle(&self, scope: &LedgerScope) -> Result<Vec<u8>, StackError> {
        let called = self.target().call(
            endpoints::HEAD_BUNDLE,
            &endpoints::ScopePath {
                scope: scope.to_string(),
            },
            &Absent,
            &Absent,
            None,
        );
        self.bytes_get(called, scope, "head bundle").await
    }

    async fn bundle(
        &self,
        scope: &LedgerScope,
        checkpoint_digest: &str,
    ) -> Result<Vec<u8>, StackError> {
        validate_required("checkpoint_digest", checkpoint_digest)?;
        let called = self.target().call(
            endpoints::PINNED_BUNDLE,
            &endpoints::BundlePath {
                scope: scope.to_string(),
                checkpoint_digest: checkpoint_digest.to_owned(),
            },
            &Absent,
            &Absent,
            None,
        );
        self.bytes_get(called, scope, "pinned bundle").await
    }

    async fn signing_key_registry(&self, scope: &LedgerScope) -> Result<Vec<u8>, StackError> {
        let called = self.target().call(
            endpoints::SIGNING_KEY_REGISTRY,
            &endpoints::ScopePath {
                scope: scope.to_string(),
            },
            &Absent,
            &Absent,
            None,
        );
        self.bytes_get(called, scope, "signing-key registry").await
    }

    async fn event_type_registry(
        &self,
        scope: &LedgerScope,
    ) -> Result<serde_json::Value, StackError> {
        let called = self.target().call(
            endpoints::EVENT_TYPE_REGISTRY,
            &endpoints::ScopePath {
                scope: scope.to_string(),
            },
            &Absent,
            &Absent,
            None,
        );
        let response = self
            .authorized(called, scope)
            .await?
            .send()
            .await
            .map_err(|error| {
                StackError::unavailable(format!(
                    "trellis event-type registry fetch failed: {error}"
                ))
            })?;
        if !response.status().is_success() {
            return Err(StackError::unavailable(format!(
                "trellis event-type registry returned HTTP {}",
                response.status()
            )));
        }
        let view = response
            .json::<endpoints::EventTypeRegistryView>()
            .await
            .map_err(|error| {
                StackError::unavailable(format!(
                    "trellis event-type registry response is invalid: {error}"
                ))
            })?;
        serde_json::to_value(view).map_err(|error| {
            StackError::unavailable(format!(
                "trellis event-type registry response is invalid: {error}"
            ))
        })
    }
}

impl TrellisServiceClient {
    /// Downloads a pinned ZIP while bounding accumulated response bytes.
    ///
    /// Uses the existing service credentials, scope selector, and request timeout.
    /// Checks every chunk before growing the output, including chunked responses.
    /// This qualifies media type and size; callers must verify ZIP evidence separately.
    ///
    /// # Errors
    /// Refuses invalid selectors, a zero limit, failed HTTP responses, non-ZIP
    /// media types, oversized bodies, allocation failure, and interrupted reads.
    pub async fn bundle_bounded(
        &self,
        scope: &LedgerScope,
        checkpoint_digest: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StackError> {
        validate_required("checkpoint_digest", checkpoint_digest)?;
        if max_bytes == 0 {
            return Err(StackError::bad_request(
                "bundle byte limit must be positive",
            ));
        }
        let called = self.target().call(
            endpoints::PINNED_BUNDLE,
            &endpoints::BundlePath {
                scope: scope.to_string(),
                checkpoint_digest: checkpoint_digest.to_owned(),
            },
            &Absent,
            &Absent,
            None,
        );
        self.bytes_get_inner(called, scope, "pinned bundle", Some(max_bytes))
            .await
    }

    async fn bytes_get(
        &self,
        called: Result<reqwest::RequestBuilder, CallError>,
        scope: &LedgerScope,
        label: &str,
    ) -> Result<Vec<u8>, StackError> {
        self.bytes_get_inner(called, scope, label, None).await
    }

    async fn bytes_get_inner(
        &self,
        called: Result<reqwest::RequestBuilder, CallError>,
        scope: &LedgerScope,
        label: &str,
        max_bytes: Option<usize>,
    ) -> Result<Vec<u8>, StackError> {
        let mut response = self
            .authorized(called, scope)
            .await?
            .send()
            .await
            .map_err(|error| {
                StackError::unavailable(format!("trellis {label} fetch failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(StackError::unavailable(format!(
                "trellis {label} returned HTTP {}",
                response.status()
            )));
        }
        if let Some(limit) = max_bytes {
            let mut types = response
                .headers()
                .get_all(reqwest::header::CONTENT_TYPE)
                .iter();
            let media_type = types.next().and_then(|value| value.to_str().ok());
            if types.next().is_some()
                || !media_type.is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .eq_ignore_ascii_case("application/zip")
                })
            {
                return Err(StackError::unavailable("trellis bundle media type refused"));
            }
            let refused = || StackError::unavailable("trellis bundle byte limit exceeded");
            if response
                .content_length()
                .is_some_and(|length| length > limit as u64)
            {
                return Err(refused());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| StackError::unavailable("trellis bundle response read failed"))?
            {
                if chunk.len() > limit - bytes.len() {
                    return Err(refused());
                }
                bytes
                    .try_reserve_exact(chunk.len())
                    .map_err(|_| StackError::unavailable("trellis bundle allocation refused"))?;
                bytes.extend_from_slice(&chunk);
            }
            return Ok(bytes);
        }
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|error| {
                StackError::unavailable(format!("trellis {label} response is invalid: {error}"))
            })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), StackError> {
    validate_required("endpoint", endpoint)?;
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err(StackError::bad_request(
            "trellis endpoint must start with http:// or https://",
        ));
    }
    Ok(())
}

fn validate_required(field: &str, value: &str) -> Result<(), StackError> {
    if value.trim().is_empty() {
        return Err(StackError::bad_request(format!("{field} is required")));
    }
    Ok(())
}

/// A ledger under the tests' fixture scope (acme/benefits/prod).
#[cfg(test)]
pub(crate) fn test_ledger(id: &str) -> LedgerScope {
    LedgerScope::of(
        &stack_common_scope::Scope::fixture("acme", "benefits", Some("prod")),
        id,
    )
    .unwrap()
}

/// `text` with the bare ledger id `case_123` replaced by its ledger scope, for wire assertions.
#[cfg(test)]
pub(crate) fn scoped_text(text: &str) -> String {
    text.replace("case_123", test_ledger("case_123").as_str())
}

#[cfg(test)]
mod tests {
    use stack_common_typeid::testing::fixture_minter;
    mod reconciliation_tests {
        include!("reconciliation_tests.rs");
    }
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use wos_events::{ProvenanceKind, ProvenanceRecord};

    use super::*;

    mod current_token_tests {
        include!("current_token_tests.rs");
        mod source_diagnostic_http_tests {
            include!("source_diagnostic_http_tests.rs");
        }
    }

    fn attachment_body() -> AcceptedAttachmentAppendBody {
        AcceptedAttachmentAppendBody {
            idempotency_key: "attachment-1".into(),
            actor: AppendActor::service("formspec-server"),
            descriptor: serde_json::json!({"sourceArtifactRef":"fixture"}),
            original_bytes: STANDARD.encode(b"original attachment"),
        }
    }

    #[tokio::test]
    async fn attachment_append_posts_closed_body_with_authenticated_headers() {
        let endpoint = test_server(|request| {
            assert!(request.starts_with(&crate::scoped_text(
                "POST /v1/scopes/case_123/accepted-attachments "
            )));
            assert!(request.contains("authorization: Bearer attachment-token\r\n"));
            assert!(request.contains("idempotency-key: attachment-1\r\n"));
            assert!(
                !request.contains("x-wos-tenant-id"),
                "tenant headers are gone"
            );
            let value: serde_json::Value = serde_json::from_str(request_body(&request)).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 4);
            assert_eq!(value["actor"]["kind"], "service");
            assert_eq!(
                STANDARD
                    .decode(value["originalBytes"].as_str().unwrap())
                    .unwrap(),
                b"original attachment"
            );
            response(
                "application/json",
                &crate::scoped_text(
                    r#"{"eventId":"evt_1","sequence":0,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/cp_1"}"#,
                ),
            )
        });
        let client = TrellisServiceClient::new(
            TrellisServiceClientConfig::new(endpoint).with_service_bearer_token("attachment-token"),
        )
        .unwrap();
        assert!(
            client
                .append_accepted_attachment(&crate::test_ledger("case_123"), &attachment_body())
                .await
                .is_ok()
        );
    }

    #[test]
    fn attachment_body_refuses_unknown_fields_and_invalid_transport() {
        let body = attachment_body();
        assert!(body.validate().is_ok());
        let mut wire = serde_json::to_value(&body).unwrap();
        wire["computeContext"] = serde_json::json!({});
        assert!(serde_json::from_value::<AcceptedAttachmentAppendBody>(wire).is_err());
        let mut wire = serde_json::to_value(&body).unwrap();
        wire["actor"]["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AcceptedAttachmentAppendBody>(wire).is_err());
        assert!(serde_json::from_str::<AcceptedAttachmentAppendBody>(r#"{"idempotencyKey":"a","idempotencyKey":"b","actor":{"kind":"service","subject":"s"},"descriptor":{},"originalBytes":"YQ=="}"#).is_err());
        for invalid in ["", "YQ", "YQ=", "YR==", "YQ==\n", "____"] {
            let mut changed = body.clone();
            changed.original_bytes = invalid.into();
            assert!(changed.validate().is_err(), "accepted {invalid:?}");
        }
        let mut changed = body.clone();
        changed.original_bytes =
            STANDARD.encode(vec![1; ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT + 1]);
        assert!(changed.validate().is_err());
        changed = body.clone();
        changed.actor = AppendActor::user("person");
        assert!(changed.validate().is_err());
        changed = body.clone();
        changed.idempotency_key = "k".repeat(65);
        assert!(changed.validate().is_err());
        changed = body.clone();
        changed.descriptor =
            serde_json::json!({"large":"x".repeat(ACCEPTED_ATTACHMENT_DESCRIPTOR_BYTES_LIMIT)});
        assert!(changed.validate().is_err());
        changed.descriptor = serde_json::json!([]);
        assert!(changed.validate().is_err());
    }

    #[test]
    fn attachment_openapi_schema_declares_closed_body_and_service_actor() {
        let schema =
            serde_json::to_value(<AcceptedAttachmentAppendBody as utoipa::PartialSchema>::schema())
                .unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"].as_object().unwrap().len(), 4);
        assert_eq!(schema["properties"]["descriptor"]["type"], "object");
        let actor =
            serde_json::to_value(<ClosedAttachmentActor as utoipa::PartialSchema>::schema())
                .unwrap();
        assert_eq!(actor["additionalProperties"], false);
        assert_eq!(
            actor["properties"]["kind"]["enum"],
            serde_json::json!(["service"])
        );
    }

    #[tokio::test]
    async fn append_wos_provenance_posts_shared_wire_shape() {
        let endpoint = test_server(|request| {
            assert!(
                request.starts_with(&crate::scoped_text("POST /v1/scopes/case_123/events ")),
                "wrong request line: {request}"
            );
            assert!(request.contains("idempotency-key: idem-1\r\n"));
            assert!(
                !request.contains("x-wos-tenant-id"),
                "tenant headers are gone"
            );
            let body = request_body(&request);
            let value: serde_json::Value = serde_json::from_str(body).expect("append body is JSON");
            assert_eq!(value["eventType"], "wos.kernel.case_created");
            assert_eq!(value["idempotencyKey"], "idem-1");
            assert_eq!(value["actor"]["kind"], "service");
            assert_eq!(value["payload"]["recordKind"], "caseCreated");
            assert_eq!(value["computeContext"]["sensitivity"], "publicMetadata");
            response(
                "application/json",
                &crate::scoped_text(
                    r#"{"eventId":"evt_1","sequence":7,"canonicalEventHash":"sha256:abc","checkpointRef":"trellis://case_123/checkpoints/cp_1"}"#,
                ),
            )
        });
        let client =
            TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).expect("client");
        let mut record = ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::CaseCreated);
        record.id = "prov_1".to_string();

        let result = client
            .append_wos_provenance(WosProvenanceAppend {
                scope: crate::test_ledger("case_123"),
                idempotency_key: "idem-1".to_string(),
                actor: AppendActor::service("wos-server"),
                record,
                compute_context: ComputeContext::no_delegated_compute("wos-server"),
            })
            .await
            .expect("append");

        assert_eq!(result.event_id, "evt_1");
        assert_eq!(result.sequence, 7);
    }

    #[tokio::test]
    async fn head_bundle_uses_v1_bundle_endpoint() {
        let endpoint = test_server(|request| {
            assert!(
                request.starts_with(&crate::scoped_text("GET /v1/scopes/case_123/bundles/head ")),
                "wrong request line: {request}"
            );
            response("application/zip", "zip-bytes")
        });
        let client =
            TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).expect("client");

        let bytes = client
            .head_bundle(&crate::test_ledger("case_123"))
            .await
            .expect("bundle");

        assert_eq!(bytes, b"zip-bytes");
    }

    #[test]
    fn append_result_rejects_a_checkpoint_outside_the_requested_scope() {
        let result = SubstrateAppendResult {
            event_id: "evt_1".to_string(),
            sequence: 1,
            prior_event_hash: None,
            canonical_event_hash: "sha256:abc".to_string(),
            checkpoint_ref: "trellis://other_scope/checkpoints/cp_1".to_string(),
        };

        let error = result
            .validate_for_event_append(&crate::test_ledger("case_123"))
            .expect_err("a checkpoint of another scope is no receipt for this one");
        assert!(
            error.to_string().contains("outside the requested scope"),
            "unexpected error: {error}"
        );
        assert!(
            SubstrateAppendResult {
                checkpoint_ref: crate::scoped_text("trellis://case_123/checkpoints/cp_1"),
                ..result
            }
            .validate_for_event_append(&crate::test_ledger("case_123"))
            .is_ok()
        );
    }

    #[test]
    fn original_attachment_constructor_preserves_bytes_and_rejects_invalid_inputs() {
        let descriptor = serde_json::json!({"original": "descriptor"});
        let body = AcceptedAttachmentAppendBody::from_original_bytes(
            "bounded-original".into(),
            AppendActor::service("producer"),
            descriptor.clone(),
            &[0, 255, 17],
        )
        .expect("bounded original");
        assert_eq!(body.descriptor, descriptor);
        assert_eq!(STANDARD.decode(body.original_bytes).unwrap(), [0, 255, 17]);
        for bytes in [
            Vec::new(),
            vec![0; ACCEPTED_ATTACHMENT_ORIGINAL_BYTES_LIMIT + 1],
        ] {
            assert!(
                AcceptedAttachmentAppendBody::from_original_bytes(
                    "bounded-original".into(),
                    AppendActor::service("producer"),
                    descriptor.clone(),
                    &bytes,
                )
                .is_err()
            );
        }
        assert!(
            AcceptedAttachmentAppendBody::from_original_bytes(
                "bounded-original".into(),
                AppendActor::user("person"),
                descriptor,
                &[1],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn bounded_bundle_exact_limit_preserves_bytes_and_pinned_path() {
        let endpoint = test_server(|request| {
            assert!(request.starts_with(&crate::scoped_text(
                "GET /v1/scopes/case_123/bundles/sha256%3Aabc "
            )));
            response("application/zip", "zip-bytes")
        });
        let client = TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
        assert_eq!(
            client
                .bundle_bounded(&crate::test_ledger("case_123"), "sha256:abc", 9)
                .await
                .unwrap(),
            b"zip-bytes"
        );
    }

    #[tokio::test]
    async fn bounded_bundle_refuses_declared_oversize_and_wrong_media_type() {
        for (mime, limit) in [("application/zip", 8), ("text/html", 64)] {
            let endpoint = test_server(move |_| response(mime, "zip-bytes"));
            let client =
                TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
            assert!(
                client
                    .bundle_bounded(&crate::test_ledger("case_123"), "sha256:abc", limit)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn bounded_bundle_checks_chunked_body_without_content_length() {
        for limit in [8, 9] {
            let endpoint = test_server(|_| {
                "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nzip-\r\n5\r\nbytes\r\n0\r\n\r\n".to_string()
            });
            let client =
                TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
            let result = client
                .bundle_bounded(&crate::test_ledger("case_123"), "sha256:abc", limit)
                .await;
            if limit == 9 {
                assert_eq!(result.unwrap(), b"zip-bytes");
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn bounded_bundle_refuses_missing_duplicate_media_type_and_truncated_body() {
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nzip",
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Type: application/zip\r\nContent-Length: 3\r\n\r\nzip",
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 9\r\n\r\nzip",
        ] {
            let endpoint = test_server(move |_| raw.to_owned());
            let client =
                TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
            assert!(
                client
                    .bundle_bounded(&crate::test_ledger("case_123"), "sha256:abc", 9)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn bounded_bundle_zero_limit_refuses_before_network() {
        let client =
            TrellisServiceClient::new(TrellisServiceClientConfig::new("http://127.0.0.1:1"))
                .unwrap();
        let error = client
            .bundle_bounded(&crate::test_ledger("case_123"), "sha256:abc", 0)
            .await
            .expect_err("invalid limit");
        assert!(
            error
                .to_string()
                .contains("bundle byte limit must be positive")
        );
    }

    /// The client sends the key the ledger scope was made under as the scope selector, for
    /// every ledger it names.
    #[tokio::test]
    async fn the_scope_selector_is_the_key_the_ledger_scope_names() {
        for ledger in [
            crate::test_ledger("case_123"),
            LedgerScope::of(
                &stack_common_scope::Scope::fixture("globex", "benefits", None),
                "case.with.dots",
            )
            .unwrap(),
        ] {
            let expected = format!("x-stack-scope-key: {}\r\n", ledger.key());
            let endpoint = test_server(move |request| {
                assert!(request.contains(&expected), "{request}");
                response("application/zip", "PK")
            });
            let client =
                TrellisServiceClient::new(TrellisServiceClientConfig::new(endpoint)).unwrap();
            assert!(client.head_bundle(&ledger).await.is_ok(), "{ledger}");
        }
    }

    fn test_server(handler: impl FnOnce(String) -> String + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock trellis");
        let address = listener.local_addr().expect("mock trellis address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let response = handler(request);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        format!("http://{address}")
    }

    fn request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("request has body")
    }

    fn response(content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }
}
