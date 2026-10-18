// Rust guideline compliant 2026-02-21
//! Manual certificate composition from selected authority and retained signing evidence.

use async_trait::async_trait;
use axum::http::HeaderMap;
use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, map_lookup_bytes, map_lookup_map,
    map_lookup_optional_value, map_lookup_text, sha256_bytes,
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::tenant::TenantScope;
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::{ArtifactRef, ScopeAction};
use trellis_service_client::SubstrateAppendResult;
use trellis_types::StoredEvent;

const BINDING: &str = "trellis.evidence-attachment-binding.v1";
const TEMPLATE_ID: &str = "trellis.reference.certificate-of-completion.v2";
const TEMPLATE: &str =
    include_str!("../../../reference/certificate-of-completion/template-v2/template.html");
const MAX_BYTES: usize = 1024 * 1024;
/// One more than the most events a completion prefix may hold, so an overfull ledger is seen.
const BOUND: u64 = trellis_types::completion_selection::MAX_COMPLETION_EVENTS as u64 + 1;

pub use trellis_service_client::{
    COMPLETION_EVENT, CompletionAttestor, CompletionRequest, CompletionSignerLabel,
};

/// Authorized facts for the exact governed snapshot, taken from the seal request's
/// `selection`, which the product computed under its own permission checks.
///
/// `workflow_status` describes processing disposition and does not imply approval.
/// The product must resolve current permissions, required delivered evidence and
/// genuine workflow completion; Trellis does not infer these from case status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedCompletion {
    pub case_ref: String,
    pub workflow_ref: String,
    pub workflow_status: String,
    pub completed_at: TrellisTimestamp,
    pub impact_level: Option<String>,
    pub signer_labels: Vec<CompletionSignerLabel>,
    pub required_attestors: Vec<CompletionAttestor>,
}

impl TryFrom<&trellis_service_client::CompletionSelection> for SelectedCompletion {
    type Error = StackError;

    fn try_from(
        selection: &trellis_service_client::CompletionSelection,
    ) -> Result<Self, StackError> {
        Ok(Self {
            case_ref: selection.case_ref.clone(),
            workflow_ref: selection.workflow_ref.clone(),
            workflow_status: selection.workflow_status.clone(),
            completed_at: TrellisTimestamp::new(
                selection.completed_at.0,
                selection.completed_at.1,
            )?,
            impact_level: selection.impact_level.clone(),
            signer_labels: selection.signer_labels.clone(),
            required_attestors: selection.required_attestors.clone(),
        })
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
/// Every call checks current authentication and exact scope permissions. The selection
/// travels in the request and is bound by the idempotency key and `expected_head`; under
/// its scope lock Trellis checks only the head, prefix validity, authorization and
/// collision. No environment bootstrap enables this operation by default.
///
/// # Errors
/// Refuses absent selection, invalid evidence, changed retries or storage failures.
pub async fn seal_completion(
    state: &crate::TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    scope: &str,
    request: &CompletionRequest,
    signer: &dyn CompletionSigner,
) -> Result<SubstrateAppendResult, StackError> {
    crate::http::validate_scope(scope)?;
    request.validate()?;
    let selected = SelectedCompletion::try_from(&request.selection)?;
    validate_selection(&selected)?;
    let principal = authorize(state, headers, tenant, scope, request).await?;
    // Before anything is reserved or signed: only the configured publisher may seal.
    if state
        .completion
        .as_ref()
        .map(|(_, publisher)| publisher.as_str())
        != Some(principal.as_str())
    {
        return Err(StackError::new(
            ErrorCode::new("INFRA-4030").expect("static error code is valid"),
            axum::http::StatusCode::FORBIDDEN,
            "completion seal requires the configured publisher",
        ));
    }
    state
        .reserve_completion_request(tenant, &principal, scope, request)
        .await?;
    // The seal validates a whole small ledger by design (Core completion prefix bounds).
    let events = state.repository.prefix(scope.as_bytes(), BOUND).await?;
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
    let signers = signing_summary(state, &prefix, request, &selected)?;
    let key = artifact_key(scope, &request.certificate_id);
    let (stored, checkpoint) = if let Some(event) = retained {
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
        let checkpoint = state
            .repository
            .checkpoint_at(scope.as_bytes(), event.sequence() + 1)
            .await?
            .ok_or_else(|| StackError::internal("committed seal has no checkpoint"))?;
        (event.clone(), checkpoint)
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
        let now = crate::ledger::authored_at_after(prefix.last(), crate::now_timestamp()?)?;
        if !state.signing_key.is_active_at(crate::now_timestamp()?) {
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
        // Authority may have changed while the operator signed and the object was written; the
        // commit below re-checks the head under the scope lock.
        if authorize(state, headers, tenant, scope, request).await? != principal {
            return Err(StackError::conflict(
                "completion authority or native snapshot changed",
            ));
        }
        commit(state, &stored).await?
    };
    crate::ledger::append_result(scope, &stored, Some(request.expected_head), &checkpoint)
}

/// Commits the seal event with its checkpoint under the scope lock.
///
/// The lock is taken first, so the head, the certificate-id collision check and the sequence are
/// judged against the latest commit. A retry that raced its own first attempt returns the
/// committed checkpoint.
async fn commit(
    state: &crate::TrellisServerState,
    event: &StoredEvent,
) -> Result<(StoredEvent, trellis_types::StoredCheckpoint), StackError> {
    let mut tx = state.repository.begin(event.scope()).await?;
    let events = tx.prefix(BOUND).await?;
    if let Some(prior) = events
        .iter()
        .find(|e| e.idempotency_key() == event.idempotency_key())
    {
        if prior.canonical_event() != event.canonical_event()
            || prior.signed_event() != event.signed_event()
        {
            return Err(StackError::conflict("completion retry bytes changed"));
        }
        let checkpoint = tx
            .checkpoint_at(prior.sequence() + 1)
            .await?
            .ok_or_else(|| StackError::internal("committed seal has no checkpoint"))?;
        return Ok((prior.clone(), checkpoint));
    }
    validate_commit(&events, event)?;
    let head = tx.head().await?;
    let (event, checkpoint) = state.checkpointer().after(head.as_ref(), event)?;
    tx.insert(&event, &checkpoint).await?;
    tx.commit().await?;
    Ok((event, checkpoint))
}

fn invalid() -> StackError {
    StackError::conflict("completion certificate evidence invalid")
}
pub(crate) fn event_type_spec() -> trellis_server_ports::EventTypeSpec {
    use trellis_server_ports::{
        BudgetReviewRecord, DirectSubmitPolicy, EventFamilyId, EventPrivacyClass, SchemaRef,
    };
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
        privacy_class: EventPrivacyClass::PublicMetadata,
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
/// Vocabulary checks Trellis owns; shape and bounds are `CompletionRequest::validate`.
fn validate_selection(selected: &SelectedCompletion) -> Result<(), StackError> {
    if !matches!(
        selected.workflow_status.as_str(),
        "completed" | "countersigned" | "notarized" | "partially-completed"
    ) || selected
        .impact_level
        .as_ref()
        .is_some_and(|v| !matches!(v.as_str(), "low" | "moderate" | "high"))
    {
        return Err(StackError::bad_request(
            "completion selection vocabulary refused",
        ));
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
    let identity = state.bearer_identity(headers).await?;
    let principal = identity.actor("trellis-server").to_owned();
    crate::http::validate_idempotency_header(headers, &request.idempotency_key)?;
    let body = trellis_service_client::SubstrateAppendBody {
        event_type: COMPLETION_EVENT.into(),
        idempotency_key: request.idempotency_key.clone(),
        actor: trellis_service_client::AppendActor::service(&principal),
        payload: serde_json::to_value(request).map_err(|_| invalid())?,
        compute_context: crate::append::default_public_compute_context(),
        client_attestation: None,
        source_content: None,
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
    let facts = state
        .export_profile
        .signing_facts(prefix, &request.signing_events)?;
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
    trellis_cddl::validate_completion_prefix(events, scope.as_bytes()).map_err(StackError::conflict)
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
    refuse_certificate_collision(events, &committed_certificate_id(event)?)
}

/// The certificate id a committed completion event carries.
pub(crate) fn committed_certificate_id(event: &StoredEvent) -> Result<String, StackError> {
    let value = decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
    let certificate = map_lookup_map(
        map_lookup_map(value.as_map().ok_or_else(invalid)?, "extensions")
            .map_err(crate::cbor_bad_request)?,
        COMPLETION_EVENT,
    )
    .map_err(crate::cbor_bad_request)?;
    map_lookup_text(certificate, "certificate_id").map_err(crate::cbor_bad_request)
}
