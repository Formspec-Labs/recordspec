// Rust guideline compliant 2026-02-21
//! Manual certificate composition from selected authority and retained signing evidence.

use async_trait::async_trait;
use axum::http::HeaderMap;
use integrity_cbor::{
    decode_cbor_value, domain_separated_sha256, map_lookup_bytes, map_lookup_map,
    map_lookup_optional_value, map_lookup_text, sha256_bytes, Value,
};
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use std::collections::BTreeSet;
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{ArtifactRef, ScopeAction};
use trellis_service_client::SubstrateAppendResult;
use trellis_types::StoredEvent;

const BINDING: &str = "trellis.evidence-attachment-binding.v1";
const TEMPLATE_ID: &str = "trellis.reference.certificate-of-completion.v2";
const TEMPLATE: &str =
    include_str!("../../../reference/certificate-of-completion/template-v2/template.html");
const MAX_BYTES: usize = 1024 * 1024;

pub(crate) struct SigningFact {
    pub(crate) principal: String,
    pub(crate) response_hash: [u8; 32],
    pub(crate) authored_at: TrellisTimestamp,
}

#[doc(inline)]
pub use trellis_verify_wos::CompletionRecord;

/// Binds owning records through the shared structural verifier.
///
/// # Errors
/// Refuses any shared prefix or complete census mismatch.
pub fn completion_record_bindings(
    prefix: &[StoredEvent],
    records: &[CompletionRecord],
    relevant_event_types: &[String],
) -> Result<Vec<[u8; 32]>, StackError> {
    trellis_verify_wos::completion_record_bindings(prefix, records, relevant_event_types)
        .map_err(StackError::conflict)
}

pub use trellis_service_client::{CompletionRequest, COMPLETION_EVENT};

/// Product-owned labels for one retained signing event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionSignerLabel {
    pub signing_event: [u8; 32],
    pub display_name: String,
    pub display_role: Option<String>,
}

/// Explicit operator authority and current verification key selected by deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionAttestor {
    pub authority: String,
    pub authority_class: String,
    pub public_key: [u8; 32],
}

/// Authorized facts for the exact governed snapshot, including derived disclosure.
///
/// `workflow_status` describes processing disposition and does not imply approval.
/// The product must resolve current permissions, required delivered evidence and
/// genuine workflow completion; Trellis does not infer these from case status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedCompletion {
    /// Hash of the owning service's complete consistent case snapshot.
    ///
    /// Compare on every selection recheck; this does not establish permission.
    pub selection_revision: [u8; 32],
    pub case_ref: String,
    pub workflow_ref: String,
    pub workflow_status: String,
    pub completed_at: TrellisTimestamp,
    pub impact_level: Option<String>,
    pub signer_labels: Vec<CompletionSignerLabel>,
    pub required_attestors: Vec<CompletionAttestor>,
}

/// Request-local secret for independent human verification by the selected service.
pub struct CompletionCallerContext<'a> {
    person_authorization: Option<&'a str>,
}

impl std::fmt::Debug for CompletionCallerContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletionCallerContext")
            .field(
                "person_authorization",
                &self.person_authorization.map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl<'a> CompletionCallerContext<'a> {
    fn from_headers(headers: &'a HeaderMap) -> Result<Self, StackError> {
        let all_values =
            headers.get_all(trellis_service_client::COMPLETION_CALLER_AUTHORIZATION_HEADER);
        let mut values = all_values.iter();
        let value = values.next();
        if values.next().is_some() {
            return Err(StackError::bad_request(
                "completion caller authorization is ambiguous",
            ));
        }
        let person_authorization = value
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| StackError::bad_request("completion caller authorization is invalid"))?;
        if let Some(value) = person_authorization {
            trellis_service_client::validate_completion_caller_authorization(value)?;
        }
        Ok(Self {
            person_authorization,
        })
    }

    /// Returns the person credential for independent selected-service verification.
    ///
    /// Forward only to the fixed owning service; never persist or log this value.
    #[must_use]
    pub fn person_authorization(&self) -> Option<&str> {
        self.person_authorization
    }
}

/// Product selection for genuine completion and permission to disclose the summary.
#[async_trait]
pub trait CompletionSelector: Send + Sync {
    /// Selects authorized facts for the exact retained prefix.
    ///
    /// # Errors
    /// Refuses unsettled or changed completion facts, insufficient evidence or permission.
    async fn select(
        &self,
        tenant: &TenantScope,
        principal: &str,
        caller: &CompletionCallerContext<'_>,
        scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError>;
}

/// Completion adapter for the independently selected owning WOS service.
///
/// The supplied client uses the fixed WOS origin and a current machine provider.
/// WOS must independently qualify the Source case association, complete census,
/// exact archive-to-prefix correspondence, and all current disclosure permissions.
/// Callers release the scope lock before awaiting this external selection.
pub struct WosCompletionSelector {
    client: trellis_service_client::TrellisServiceClient,
    tenant: Option<TenantScope>,
}

impl std::fmt::Debug for WosCompletionSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WosCompletionSelector")
            .finish_non_exhaustive()
    }
}

impl WosCompletionSelector {
    /// Fixes the deployment tenant for the normal startup composition.
    #[must_use]
    pub fn for_tenant(
        client: trellis_service_client::TrellisServiceClient,
        tenant: TenantScope,
    ) -> Self {
        Self {
            client,
            tenant: Some(tenant),
        }
    }

    /// Selects the existing client for one independently configured owning service.
    #[must_use]
    pub fn new(client: trellis_service_client::TrellisServiceClient) -> Self {
        Self {
            client,
            tenant: None,
        }
    }
}

#[async_trait]
impl CompletionSelector for WosCompletionSelector {
    async fn select(
        &self,
        tenant: &TenantScope,
        _principal: &str,
        caller: &CompletionCallerContext<'_>,
        scope: &str,
        request: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<SelectedCompletion, StackError> {
        if self
            .tenant
            .as_ref()
            .is_some_and(|expected| expected != tenant)
        {
            return Err(StackError::bad_request(
                "completion deployment tenant mismatch",
            ));
        }
        let person = caller.person_authorization().ok_or_else(|| {
            StackError::unavailable("completion person authorization is required")
        })?;
        validate_prefix(prefix, scope)?;
        let body =
            trellis_service_client::completion_selection::CompletionSelectionRequest::from_prefix(
                tenant, scope, request, prefix,
            )?;
        let reply = self.client.completion_selection(&body, person).await?;
        let selected = reply.selected;
        Ok(SelectedCompletion {
            selection_revision: selected.selection_revision,
            case_ref: selected.case_ref,
            workflow_ref: selected.workflow_ref,
            workflow_status: selected.workflow_status,
            completed_at: TrellisTimestamp::new(selected.completed_at.0, selected.completed_at.1)?,
            impact_level: selected.impact_level,
            signer_labels: selected
                .signer_labels
                .into_iter()
                .map(|row| CompletionSignerLabel {
                    signing_event: row.signing_event,
                    display_name: row.display_name,
                    display_role: row.display_role,
                })
                .collect(),
            required_attestors: selected
                .required_attestors
                .into_iter()
                .map(|row| CompletionAttestor {
                    authority: row.authority,
                    authority_class: row.authority_class,
                    public_key: row.public_key,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod startup_selection_tests {
    use super::*;

    #[tokio::test]
    async fn fixed_completion_tenant_is_checked_before_credentials_or_network() {
        let tenant = TenantScope {
            tenant: "tenant-a".into(),
            workspace: "workspace-a".into(),
            environment: "environment-a".into(),
            cell: "cell-a".into(),
        };
        let client = trellis_service_client::TrellisServiceClient::new(
            trellis_service_client::TrellisServiceClientConfig::new(
                "https://unused.example",
                stack_common_http::tenant::HeaderConfig::wos(),
            ),
        )
        .unwrap();
        let selector = WosCompletionSelector::for_tenant(client, tenant.clone());
        let headers = HeaderMap::new();
        let caller = CompletionCallerContext::from_headers(&headers).unwrap();
        let request = CompletionRequest {
            idempotency_key: "selection".into(),
            certificate_id: "certificate".into(),
            expected_head: [0; 32],
            signing_events: vec![[1; 32]],
        };
        let mut changed = tenant;
        changed.cell = "other-cell".into();
        let error = selector
            .select(&changed, "principal", &caller, "scope", &request, &[])
            .await
            .unwrap_err();
        assert_eq!(error.title(), "completion deployment tenant mismatch");
    }
}

/// Selected signing provider; no private key is accepted in a trigger request.
#[async_trait]
pub trait CompletionSigner: Send + Sync {
    /// Signs the exact Companion A.5 domain-separated preimage.
    ///
    /// # Errors
    /// Refuses unselected authority, inactive key or signing-provider failure.
    async fn sign(
        &self,
        authority: &CompletionAttestor,
        preimage: &[u8],
    ) -> Result<[u8; 64], StackError>;
}

/// Local COSE-key provider selected for one explicit certificate authority.
///
/// Keys belong outside source control. This provider never reuses the ledger
/// event key implicitly and signs only the registered completion preimage.
pub struct CoseCompletionSigner {
    authority: CompletionAttestor,
    valid_from: TrellisTimestamp,
    valid_to: TrellisTimestamp,
    private_seed: [u8; 32],
}
impl CoseCompletionSigner {
    /// Loads an explicitly bound operator key and finite trusted interval.
    ///
    /// # Errors
    /// Refuses inconsistent key bytes, unknown class or an empty validity interval.
    pub fn from_cose_key_bytes(
        authority: CompletionAttestor,
        valid_from: TrellisTimestamp,
        valid_to: TrellisTimestamp,
        bytes: &[u8],
    ) -> Result<Self, StackError> {
        let key = trellis_cddl::parse_ed25519_cose_key(bytes).map_err(|_| invalid())?;
        if authority.authority.trim().is_empty()
            || !matches!(authority.authority_class.as_str(), "prior" | "new")
            || key.public_key != authority.public_key
            || timestamp_pair(valid_from) >= timestamp_pair(valid_to)
            || !integrity_cose::verify_ed25519_signature(
                key.public_key,
                b"trellis-completion-key-pair-check",
                integrity_cose::sign_ed25519(
                    key.private_seed,
                    b"trellis-completion-key-pair-check",
                ),
            )
        {
            return Err(invalid());
        }
        Ok(Self {
            authority,
            valid_from,
            valid_to,
            private_seed: key.private_seed,
        })
    }
}
fn timestamp_pair(value: TrellisTimestamp) -> (u64, u32) {
    (value.unix_secs, value.subsec_nanos)
}
#[async_trait]
impl CompletionSigner for CoseCompletionSigner {
    async fn sign(
        &self,
        authority: &CompletionAttestor,
        preimage: &[u8],
    ) -> Result<[u8; 64], StackError> {
        const TAG: &[u8] = b"trellis-transition-attestation-v1";
        let header_len = 4 + TAG.len() + 4;
        if authority != &self.authority
            || preimage.len() < header_len
            || preimage[..4] != (TAG.len() as u32).to_be_bytes()
            || &preimage[4..4 + TAG.len()] != TAG
        {
            return Err(invalid());
        }
        let encoded = &preimage[header_len..];
        if preimage[4 + TAG.len()..header_len] != (encoded.len() as u32).to_be_bytes() {
            return Err(invalid());
        }
        let value = decode_cbor_value(encoded).map_err(crate::cbor_bad_request)?;
        let fields = value
            .as_array()
            .filter(|v| v.len() == 3)
            .ok_or_else(invalid)?;
        let id = fields[0].as_text().ok_or_else(invalid)?;
        let time = fields[1]
            .as_array()
            .filter(|v| v.len() == 2)
            .ok_or_else(invalid)?;
        let seconds =
            u64::try_from(time[0].as_integer().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let nanos =
            u32::try_from(time[1].as_integer().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let completed_at = TrellisTimestamp::new(seconds, nanos)?;
        let class = fields[2].as_text().ok_or_else(invalid)?;
        let expected = trellis_cddl::certificate_attestation_preimage(id, seconds, nanos, class)
            .map_err(|_| invalid())?;
        let now = crate::now_timestamp()?;
        if expected != preimage
            || class != authority.authority_class
            || timestamp_pair(completed_at) < timestamp_pair(self.valid_from)
            || timestamp_pair(completed_at) > timestamp_pair(self.valid_to)
            || timestamp_pair(now) < timestamp_pair(self.valid_from)
            || timestamp_pair(now) > timestamp_pair(self.valid_to)
            || timestamp_pair(completed_at) > timestamp_pair(now)
        {
            return Err(StackError::conflict("completion operator binding inactive"));
        }
        Ok(integrity_cose::sign_ed25519(self.private_seed, preimage))
    }
}

/// Issues a certificate through an explicitly selected product composition.
///
/// Every call checks current authentication and exact scope permissions. No
/// environment bootstrap enables this operation by default.
///
/// # Errors
/// Refuses absent selection, invalid evidence, changed retries or storage failures.
pub async fn seal_completion(
    state: &crate::TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    scope: &str,
    request: &CompletionRequest,
    selector: Option<&dyn CompletionSelector>,
    signer: &dyn CompletionSigner,
) -> Result<SubstrateAppendResult, StackError> {
    crate::http::validate_scope(scope)?;
    request.validate()?;
    let principal = authorize(state, headers, tenant, scope, request).await?;
    let caller = CompletionCallerContext::from_headers(headers)?;
    let selector = selector
        .ok_or_else(|| StackError::unavailable("completion composition is not selected"))?;
    state
        .reserve_completion_request(tenant, &principal, scope, request)
        .await?;
    let guard = state.scope_locks.lock(scope.as_bytes()).await;
    let events = state.repository.list_scope(scope.as_bytes()).await?;
    let mut expected_events = events.clone();
    validate_prefix(&events, scope)?;
    let retained = events
        .iter()
        .find(|event| event.idempotency_key() == Some(request.idempotency_key.as_bytes()));
    let prefix = match retained {
        Some(event) => events
            .iter()
            .filter(|prior| prior.sequence() < event.sequence())
            .cloned()
            .collect::<Vec<_>>(),
        None => events.clone(),
    };
    if prefix
        .last()
        .map(|event| crate::event_hash(scope.as_bytes(), event))
        .transpose()?
        != Some(request.expected_head)
    {
        return Err(StackError::conflict("completion snapshot head changed"));
    }
    // The owning selection can read an external archive or acquire this same lock.
    // Its result is admitted only after the exact native census is checked again.
    drop(guard);
    let selected = selector
        .select(tenant, &principal, &caller, scope, request, &prefix)
        .await?;
    let mut guard = lock_unchanged_scope(
        state,
        headers,
        tenant,
        scope,
        request,
        &principal,
        &expected_events,
    )
    .await?;
    validate_selection(request, &selected)?;
    let signers = signing_summary(state, &prefix, request, &selected)?;
    let key = artifact_key(scope, &request.certificate_id);
    let (stored, html) = if let Some(event) = retained {
        let html = certificate_html(event)?;
        let value = decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
        let extensions = map_lookup_map(value.as_map().ok_or_else(invalid)?, "extensions")
            .map_err(crate::cbor_bad_request)?;
        let certificate =
            map_lookup_map(extensions, COMPLETION_EVENT).map_err(crate::cbor_bad_request)?;
        let presentation = map_lookup_map(certificate, "presentation_artifact")
            .map_err(crate::cbor_bad_request)?;
        let key =
            map_lookup_text(presentation, "attachment_id").map_err(crate::cbor_bad_request)?;
        let attestations = map_lookup_optional_value(certificate, "attestations")
            .cloned()
            .ok_or_else(invalid)?;
        verify_attestations(request, &selected, &attestations)?;
        if certificate_payload(
            request,
            &selected,
            signers.clone(),
            &key,
            &html,
            attestations,
        )? != Value::Map(certificate.to_vec())
        {
            return Err(StackError::conflict("completion retry facts changed"));
        }
        let bytes = state
            .artifact_store
            .get(&ArtifactRef::new(&key))
            .await?
            .ok_or_else(|| StackError::unavailable("retained certificate object missing"))?;
        if bytes != html {
            return Err(StackError::conflict("retained certificate object differs"));
        }
        (event.clone(), html)
    } else {
        refuse_certificate_collision(&events, &request.certificate_id)?;
        let html = render(request, &selected, &signers)?;
        let mut attestations = Vec::new();
        for authority in &selected.required_attestors {
            let preimage = trellis_cddl::certificate_attestation_preimage(
                &request.certificate_id,
                selected.completed_at.unix_secs,
                selected.completed_at.subsec_nanos,
                &authority.authority_class,
            )
            .map_err(|_| invalid())?;
            let signature = signer.sign(authority, &preimage).await?;
            attestations.push(crate::text_map(vec![
                ("authority", Value::Text(authority.authority.clone())),
                (
                    "authority_class",
                    Value::Text(authority.authority_class.clone()),
                ),
                ("signature", Value::Bytes(signature.to_vec())),
            ])?);
        }
        let attestations = Value::Array(attestations);
        verify_attestations(request, &selected, &attestations)?;
        // Retain the store's actual opaque locator in the signed binding. Object keys
        // and returned references differ for S3 and memory stores.
        let reference = state.artifact_store.put_immutable(&key, &html).await?;
        if state.artifact_store.get(&reference).await?.as_deref() != Some(html.as_slice()) {
            return Err(StackError::unavailable(
                "certificate immutable write readback failed",
            ));
        }
        let key = reference.uri;
        let extensions = crate::text_map(vec![
            (
                COMPLETION_EVENT,
                certificate_payload(request, &selected, signers, &key, &html, attestations)?,
            ),
            (BINDING, binding(&key, &html)?),
        ])?;
        let now = crate::now_timestamp()?;
        if !state.signing_key.is_active_at(now) {
            return Err(StackError::conflict(
                "completion ledger signing key inactive",
            ));
        }
        let authored = crate::append::build_authored_event(crate::append::AuthoredEventInput {
            scope: scope.as_bytes(),
            sequence: prefix.len() as u64,
            prev_hash: Some(request.expected_head),
            event_type: COMPLETION_EVENT,
            idempotency_key: request.idempotency_key.as_bytes(),
            authored_at: now,
            extensions,
            content: crate::append::EventContent {
                content_hash: domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &html),
                nonce: crate::append::derive_payload_inline_nonce(
                    request.idempotency_key.as_bytes(),
                    &html,
                )?,
                payload_bytes: html.clone(),
            },
        })?;
        #[derive(Default)]
        struct Capture(Option<StoredEvent>);
        impl trellis_core::LedgerStore for Capture {
            type Error = StackError;
            fn append_event(&mut self, event: StoredEvent) -> Result<(), StackError> {
                if self.0.replace(event).is_some() {
                    return Err(invalid());
                }
                Ok(())
            }
        }
        let mut capture = Capture::default();
        let artifacts =
            trellis_core::append_event(&mut capture, &state.signing_key.core_key(), &authored)
                .map_err(|_| invalid())?;
        let stored = capture
            .0
            .ok_or_else(invalid)?
            .with_canonical_event_hash(Some(artifacts.canonical_event_hash));
        certificate_html(&stored)?;
        guard = recheck(
            state,
            headers,
            tenant,
            scope,
            request,
            selector,
            &principal,
            &prefix,
            &selected,
            guard,
            &expected_events,
        )
        .await?;
        state
            .repository
            .append_completion_event(stored.clone())
            .await?;
        expected_events.push(stored.clone());
        (stored, html)
    };
    // No awaited composition result confers lasting permission to disclose bytes.
    guard = recheck(
        state,
        headers,
        tenant,
        scope,
        request,
        selector,
        &principal,
        &prefix,
        &selected,
        guard,
        &expected_events,
    )
    .await?;
    let mut export_prefix = prefix.clone();
    export_prefix.push(stored.clone());
    let bundle = crate::publish_bundle(
        state,
        scope.as_bytes(),
        &export_prefix,
        false,
        &crate::append::default_public_compute_context(),
    )
    .await?;
    // Recheck after publication awaits, before returning the archive locator.
    let _guard = recheck(
        state,
        headers,
        tenant,
        scope,
        request,
        selector,
        &principal,
        &prefix,
        &selected,
        guard,
        &expected_events,
    )
    .await?;
    let _ = html; // The committed inline body is the durable source of exported060 bytes.
    crate::append_result_for_event(
        scope,
        &stored,
        Some(request.expected_head),
        trellis_types::ArtifactType::Event,
        COMPLETION_EVENT,
        &bundle,
        true,
    )
}

fn invalid() -> StackError {
    StackError::conflict("completion certificate evidence invalid")
}
pub(crate) fn event_type_spec() -> trellis_server_ports::EventTypeSpec {
    use trellis_server_ports::{BudgetReviewRecord, DirectSubmitPolicy, EventFamilyId, SchemaRef};
    trellis_server_ports::EventTypeSpec {
        event_type: COMPLETION_EVENT.into(),
        event_family: EventFamilyId::new("trellis.certificate-of-completion")
            .expect("literal family"),
        schema_ref: SchemaRef::new(
            "repo://trellis/thoughts/adr/0016-completion-signing-response-bindings.md",
        )
        .expect("literal schema reference"),
        artifact_type: trellis_types::ArtifactType::Event,
        direct_submit: DirectSubmitPolicy::ServiceOnly,
        budget_review: BudgetReviewRecord {
            reviewer: "trellis-server::completion::v1".into(),
            considered: true,
            plaintext_fields: [
                "certificate_id",
                "case_ref",
                "workflow_ref",
                "completed_at",
                "signing_events",
                "chain_summary",
                "presentation_artifact",
                "attestations",
                "authorized_certificate_html",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        },
    }
}
fn validate_selection(
    request: &CompletionRequest,
    selected: &SelectedCompletion,
) -> Result<(), StackError> {
    for text in [
        &selected.case_ref,
        &selected.workflow_ref,
        &selected.workflow_status,
    ] {
        if text.trim().is_empty() || text.len() > 1024 {
            return Err(invalid());
        }
    }
    if !matches!(
        selected.workflow_status.as_str(),
        "completed" | "countersigned" | "notarized" | "partially-completed"
    ) || selected
        .impact_level
        .as_ref()
        .is_some_and(|v| !matches!(v.as_str(), "low" | "moderate" | "high"))
    {
        return Err(invalid());
    }
    if selected.signer_labels.len() != request.signing_events.len()
        || selected.required_attestors.is_empty()
        || selected.required_attestors.len() > 8
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for (hash, label) in request.signing_events.iter().zip(&selected.signer_labels) {
        if hash != &label.signing_event
            || label.display_name.trim().is_empty()
            || label.display_name.len() > 1024
            || label
                .display_role
                .as_ref()
                .is_some_and(|role| role.len() > 1024)
        {
            return Err(invalid());
        }
    }
    for authority in &selected.required_attestors {
        if authority.authority.trim().is_empty()
            || authority.authority.len() > 1024
            || !matches!(authority.authority_class.as_str(), "prior" | "new")
            || !seen.insert((&authority.authority, &authority.authority_class))
        {
            return Err(invalid());
        }
    }
    Ok(())
}
async fn authorize(
    state: &crate::TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    scope: &str,
    request: &CompletionRequest,
) -> Result<String, StackError> {
    let identity = state.authenticate(headers).await?;
    let principal = identity.actor("trellis-server").to_owned();
    crate::http::validate_idempotency_header(headers, &request.idempotency_key)?;
    let body = trellis_service_client::SubstrateAppendBody {
        event_type: COMPLETION_EVENT.into(),
        idempotency_key: request.idempotency_key.clone(),
        actor: trellis_service_client::AppendActor::service(&principal),
        payload: serde_json::to_value(request).map_err(|_| invalid())?,
        compute_context: crate::append::default_public_compute_context(),
        client_attestation: None,
    };
    body.validate()?;
    let append_permit = crate::auth::authorize_action(
        state,
        &identity,
        tenant,
        scope,
        ScopeAction::Append,
        Some(&body),
    )
    .await?;
    let read_permit =
        crate::auth::authorize_action(state, &identity, tenant, scope, ScopeAction::Read, None)
            .await?;
    if append_permit.principal != read_permit.principal {
        return Err(StackError::conflict(
            "completion permissions admit different principals",
        ));
    }
    Ok(append_permit.principal)
}
async fn recheck(
    state: &crate::TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    scope: &str,
    request: &CompletionRequest,
    selector: &dyn CompletionSelector,
    principal: &str,
    prefix: &[StoredEvent],
    selected: &SelectedCompletion,
    guard: tokio::sync::OwnedMutexGuard<()>,
    expected_events: &[StoredEvent],
) -> Result<tokio::sync::OwnedMutexGuard<()>, StackError> {
    drop(guard);
    let caller = CompletionCallerContext::from_headers(headers)?;
    if authorize(state, headers, tenant, scope, request).await? != principal
        || selector
            .select(tenant, principal, &caller, scope, request, prefix)
            .await?
            != *selected
    {
        return Err(StackError::conflict(
            "completion authority or snapshot changed",
        ));
    }
    lock_unchanged_scope(
        state,
        headers,
        tenant,
        scope,
        request,
        principal,
        expected_events,
    )
    .await
}

async fn lock_unchanged_scope(
    state: &crate::TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    scope: &str,
    request: &CompletionRequest,
    principal: &str,
    expected_events: &[StoredEvent],
) -> Result<tokio::sync::OwnedMutexGuard<()>, StackError> {
    let guard = state.scope_locks.lock(scope.as_bytes()).await;
    if authorize(state, headers, tenant, scope, request).await? != principal
        || state.repository.list_scope(scope.as_bytes()).await? != expected_events
    {
        return Err(StackError::conflict(
            "completion authority or native snapshot changed",
        ));
    }
    Ok(guard)
}
fn artifact_key(scope: &str, id: &str) -> String {
    format!(
        "certificates/{}/{}.html",
        hex::encode(sha256_bytes(scope.as_bytes())),
        hex::encode(sha256_bytes(id.as_bytes()))
    )
}

fn signing_summary(
    state: &crate::TrellisServerState,
    prefix: &[StoredEvent],
    request: &CompletionRequest,
    selected: &SelectedCompletion,
) -> Result<Value, StackError> {
    let _ = state;
    let facts = crate::completion_signing_facts(prefix, &request.signing_events)?;
    let mut rows = Vec::new();
    for (fact, label) in facts.into_iter().zip(&selected.signer_labels) {
        if (
            selected.completed_at.unix_secs,
            selected.completed_at.subsec_nanos,
        ) < (fact.authored_at.unix_secs, fact.authored_at.subsec_nanos)
        {
            return Err(invalid());
        }
        rows.push(crate::text_map(vec![
            ("principal_ref", Value::Text(fact.principal)),
            ("response_ref", Value::Bytes(fact.response_hash.to_vec())),
            ("display_name", Value::Text(label.display_name.clone())),
            (
                "display_role",
                label.display_role.clone().map_or(Value::Null, Value::Text),
            ),
            ("signed_at", crate::timestamp_value(fact.authored_at)),
        ])?);
    }
    crate::text_map(vec![
        ("signer_count", crate::uint(rows.len() as u64)),
        ("signer_display", Value::Array(rows)),
        (
            "workflow_status",
            Value::Text(selected.workflow_status.clone()),
        ),
        (
            "impact_level",
            selected
                .impact_level
                .clone()
                .map_or(Value::Null, Value::Text),
        ),
        ("covered_claims", Value::Array(vec![])),
    ])
}
fn certificate_payload(
    request: &CompletionRequest,
    selected: &SelectedCompletion,
    summary: Value,
    key: &str,
    html: &[u8],
    attestations: Value,
) -> Result<Value, StackError> {
    crate::text_map(vec![
        (
            "certificate_id",
            Value::Text(request.certificate_id.clone()),
        ),
        ("case_ref", Value::Text(selected.case_ref.clone())),
        ("workflow_ref", Value::Text(selected.workflow_ref.clone())),
        (
            "completed_at",
            crate::timestamp_value(selected.completed_at),
        ),
        (
            "signing_events",
            Value::Array(
                request
                    .signing_events
                    .iter()
                    .map(|hash| Value::Bytes(hash.to_vec()))
                    .collect(),
            ),
        ),
        ("chain_summary", summary),
        ("attestations", attestations),
        (
            "presentation_artifact",
            crate::text_map(vec![
                ("attachment_id", Value::Text(key.into())),
                (
                    "content_hash",
                    Value::Bytes(
                        domain_separated_sha256("trellis-presentation-artifact-v1", html).to_vec(),
                    ),
                ),
                ("media_type", Value::Text("text/html".into())),
                ("byte_length", crate::uint(html.len() as u64)),
                ("template_id", Value::Text(TEMPLATE_ID.into())),
                (
                    "template_hash",
                    Value::Bytes(sha256_bytes(TEMPLATE.as_bytes()).to_vec()),
                ),
            ])?,
        ),
    ])
}
fn binding(key: &str, html: &[u8]) -> Result<Value, StackError> {
    crate::text_map(vec![
        ("attachment_id", Value::Text(key.into())),
        ("slot_path", Value::Text("certificate-of-completion".into())),
        ("media_type", Value::Text("text/html".into())),
        ("byte_length", crate::uint(html.len() as u64)),
        (
            "attachment_sha256",
            Value::Text(format!("sha256:{}", hex::encode(sha256_bytes(html)))),
        ),
        (
            "payload_content_hash",
            Value::Text(format!(
                "sha256:{}",
                hex::encode(domain_separated_sha256(trellis_types::CONTENT_DOMAIN, html))
            )),
        ),
        ("filename", Value::Text("certificate.html".into())),
        ("prior_binding_hash", Value::Null),
    ])
}
fn verify_attestations(
    request: &CompletionRequest,
    selected: &SelectedCompletion,
    value: &Value,
) -> Result<(), StackError> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() == selected.required_attestors.len())
        .ok_or_else(invalid)?;
    for (row, authority) in rows.iter().zip(&selected.required_attestors) {
        let map = row
            .as_map()
            .filter(|map| map.len() == 3)
            .ok_or_else(invalid)?;
        let signature: [u8; 64] = map_lookup_bytes(map, "signature")
            .map_err(crate::cbor_bad_request)?
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        if map_lookup_text(map, "authority").map_err(crate::cbor_bad_request)?
            != authority.authority
            || map_lookup_text(map, "authority_class").map_err(crate::cbor_bad_request)?
                != authority.authority_class
        {
            return Err(invalid());
        }
        let preimage = trellis_cddl::certificate_attestation_preimage(
            &request.certificate_id,
            selected.completed_at.unix_secs,
            selected.completed_at.subsec_nanos,
            &authority.authority_class,
        )
        .map_err(|_| invalid())?;
        if !integrity_cose::verify_ed25519_signature(authority.public_key, &preimage, signature) {
            return Err(StackError::conflict(
                "completion operator signature invalid",
            ));
        }
    }
    Ok(())
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn time_text(value: TrellisTimestamp) -> Result<String, StackError> {
    time::OffsetDateTime::from_unix_timestamp(
        i64::try_from(value.unix_secs).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?
    .replace_nanosecond(value.subsec_nanos)
    .map_err(|_| invalid())?
    .format(&time::format_description::well_known::Rfc3339)
    .map_err(|_| invalid())
}
fn render(
    request: &CompletionRequest,
    selected: &SelectedCompletion,
    summary: &Value,
) -> Result<Vec<u8>, StackError> {
    let mut facts = String::new();
    for (label, value) in [
        ("Certificate", request.certificate_id.clone()),
        ("Case", selected.case_ref.clone()),
        ("Workflow", selected.workflow_ref.clone()),
        ("Processing status", selected.workflow_status.clone()),
        ("Completion timestamp", time_text(selected.completed_at)?),
        ("Selected ledger head", hex::encode(request.expected_head)),
    ] {
        facts.push_str(&format!(
            "<dt>{}</dt><dd>{}</dd>",
            escape(label),
            escape(&value)
        ));
    }
    let summary = summary.as_map().ok_or_else(invalid)?;
    let rows = map_lookup_optional_value(summary, "signer_display")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut signers = String::new();
    for ((label, hash), row) in selected
        .signer_labels
        .iter()
        .zip(&request.signing_events)
        .zip(rows)
    {
        let map = row.as_map().ok_or_else(invalid)?;
        let timestamp = map_lookup_optional_value(map, "signed_at")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let secs =
            u64::try_from(timestamp[0].as_integer().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let nanos =
            u32::try_from(timestamp[1].as_integer().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let principal = map_lookup_text(map, "principal_ref").map_err(crate::cbor_bad_request)?;
        let response = map_lookup_bytes(map, "response_ref").map_err(crate::cbor_bad_request)?;
        signers.push_str(&format!(
            "<tr><td>{}<br><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            escape(&label.display_name),
            escape(&principal),
            escape(label.display_role.as_deref().unwrap_or("")),
            escape(&time_text(TrellisTimestamp::new(secs, nanos)?)?),
            hex::encode(hash),
            hex::encode(response)
        ));
    }
    // Replace each original placeholder once; substitutions are escaped and never reinterpreted.
    let (before, rest) = TEMPLATE.split_once("{{facts}}").ok_or_else(invalid)?;
    let (middle, after) = rest.split_once("{{signers}}").ok_or_else(invalid)?;
    let html = format!("{before}{facts}{middle}{signers}{after}").into_bytes();
    if html.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(html)
}
pub(crate) fn certificate_html(event: &StoredEvent) -> Result<Vec<u8>, StackError> {
    if crate::event_summary(event)?.event_type != COMPLETION_EVENT {
        return Err(invalid());
    }
    let value = decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
    let root = value.as_map().ok_or_else(invalid)?;
    let header = map_lookup_map(root, "header").map_err(crate::cbor_bad_request)?;
    if map_lookup_bytes(header, "classification").map_err(crate::cbor_bad_request)?
        != b"x-trellis-service/public-metadata"
    {
        return Err(invalid());
    }
    let reference = map_lookup_map(root, "payload_ref").map_err(crate::cbor_bad_request)?;
    if map_lookup_text(reference, "ref_type").map_err(crate::cbor_bad_request)? != "inline" {
        return Err(invalid());
    }
    let html = map_lookup_bytes(reference, "ciphertext").map_err(crate::cbor_bad_request)?;
    if html.is_empty()
        || html.len() > MAX_BYTES
        || crate::event_summary(event)?.content_hash
            != domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &html)
    {
        return Err(invalid());
    }
    let extensions = map_lookup_map(root, "extensions").map_err(crate::cbor_bad_request)?;
    if extensions.len() != 2 {
        return Err(invalid());
    }
    let certificate =
        map_lookup_map(extensions, COMPLETION_EVENT).map_err(crate::cbor_bad_request)?;
    let id = map_lookup_text(certificate, "certificate_id").map_err(crate::cbor_bad_request)?;
    if id.trim().is_empty() || id.len() > 1024 {
        return Err(invalid());
    }
    let bound = map_lookup_map(extensions, BINDING).map_err(crate::cbor_bad_request)?;
    let key = map_lookup_text(bound, "attachment_id").map_err(crate::cbor_bad_request)?;
    if key.trim().is_empty() || key.len() > 2048 {
        return Err(invalid());
    }
    if map_lookup_optional_value(extensions, BINDING) != Some(&binding(&key, &html)?) {
        return Err(invalid());
    }
    let presentation =
        map_lookup_map(certificate, "presentation_artifact").map_err(crate::cbor_bad_request)?;
    if map_lookup_bytes(presentation, "content_hash").map_err(crate::cbor_bad_request)?
        != domain_separated_sha256("trellis-presentation-artifact-v1", &html)
        || map_lookup_text(presentation, "attachment_id").map_err(crate::cbor_bad_request)? != key
        || map_lookup_text(presentation, "media_type").map_err(crate::cbor_bad_request)?
            != "text/html"
        || integrity_cbor::map_lookup_u64(presentation, "byte_length")
            .map_err(crate::cbor_bad_request)?
            != html.len() as u64
        || map_lookup_text(presentation, "template_id").map_err(crate::cbor_bad_request)?
            != TEMPLATE_ID
        || map_lookup_bytes(presentation, "template_hash").map_err(crate::cbor_bad_request)?
            != sha256_bytes(TEMPLATE.as_bytes())
    {
        return Err(invalid());
    }
    Ok(html)
}
fn validate_prefix(events: &[StoredEvent], scope: &str) -> Result<(), StackError> {
    trellis_verify_wos::validate_completion_prefix(events, scope.as_bytes())
        .map_err(StackError::conflict)
}
fn refuse_certificate_collision(events: &[StoredEvent], id: &str) -> Result<(), StackError> {
    for event in events {
        if crate::event_summary(event)?.event_type == COMPLETION_EVENT {
            let value =
                decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
            let extensions = map_lookup_map(value.as_map().ok_or_else(invalid)?, "extensions")
                .map_err(crate::cbor_bad_request)?;
            let certificate =
                map_lookup_map(extensions, COMPLETION_EVENT).map_err(crate::cbor_bad_request)?;
            if map_lookup_text(certificate, "certificate_id").map_err(crate::cbor_bad_request)?
                == id
            {
                return Err(StackError::conflict("certificate ID already committed"));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_commit(
    events: &[StoredEvent],
    event: &StoredEvent,
) -> Result<(), StackError> {
    let scope = std::str::from_utf8(event.scope()).map_err(|_| invalid())?;
    validate_prefix(events, scope)?;
    certificate_html(event)?;
    let value = decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
    let root = value.as_map().ok_or_else(invalid)?;
    let head = crate::event_hash(event.scope(), events.last().ok_or_else(invalid)?)?;
    if event.sequence() != events.len() as u64
        || map_lookup_optional_value(root, "prev_hash") != Some(&Value::Bytes(head.to_vec()))
    {
        return Err(StackError::conflict("completion snapshot head changed"));
    }
    let certificate = map_lookup_map(
        map_lookup_map(root, "extensions").map_err(crate::cbor_bad_request)?,
        COMPLETION_EVENT,
    )
    .map_err(crate::cbor_bad_request)?;
    refuse_certificate_collision(
        events,
        &map_lookup_text(certificate, "certificate_id").map_err(crate::cbor_bad_request)?,
    )
}

#[cfg(test)]
mod caller_context_tests {
    use super::*;

    #[test]
    fn caller_context_is_optional_bounded_opaque_and_redacted() {
        let mut headers = HeaderMap::new();
        assert!(CompletionCallerContext::from_headers(&headers)
            .unwrap()
            .person_authorization()
            .is_none());
        let name = trellis_service_client::COMPLETION_CALLER_AUTHORIZATION_HEADER;
        headers.insert(name, "Bearer private-test-person".parse().unwrap());
        let context = CompletionCallerContext::from_headers(&headers).unwrap();
        assert_eq!(
            context.person_authorization(),
            Some("Bearer private-test-person")
        );
        assert!(!format!("{context:?}").contains("private-test-person"));
        headers.append(name, "Bearer second-person".parse().unwrap());
        assert!(CompletionCallerContext::from_headers(&headers).is_err());
        headers.remove(name);
        headers.insert(name, "Basic invalid".parse().unwrap());
        assert!(CompletionCallerContext::from_headers(&headers).is_err());
        headers.insert(
            name,
            format!("Bearer {}", "a".repeat(8192)).parse().unwrap(),
        );
        assert!(CompletionCallerContext::from_headers(&headers).is_err());
    }
}
