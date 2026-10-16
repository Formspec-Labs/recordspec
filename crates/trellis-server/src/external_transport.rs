// Rust guideline compliant 2026-02-21
//! Closed accepted-attachment transport with composition-selected recipients.

use crate::{ExternalAttachmentFactory, ExternalAttachmentRecipientPolicy, TrellisServerState};
use async_trait::async_trait;
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Extension, Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use integrity_cbor::{Value, decode_cbor_value, map_lookup_optional_value};
use integrity_hpke::external_attachment::{
    AttachmentContext, ProtectionLimits, Recipient, protect_external_attachment,
};
use integrity_seam::SecureRandom;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use stack_common_error::StackError;
use stack_common_http::{idempotency::TrustedReplayPartition, tenant::TenantScope};
use std::sync::Arc;
use trellis_core::external_attachment::{
    ExternalAppendLimits, ExternalAttachmentAppend, ExternalAttachmentHeader,
    RetainedExternalAttachment,
};
use trellis_server_ports::{
    AttachmentLimits, AuthorizedScope, ComputeContext, ComputeSensitivity, ScopeAction,
};
use trellis_service_client::{AppendActor, SubstrateAppendBody, SubstrateAppendResult};
use trellis_types::StoredEvent;

const ORIGINAL_CAP: usize = 1024 * 1024;
const RAW_CAP: usize = 2 * 1024 * 1024;

/// Actual recipient public key selected by trusted server composition.
#[derive(Clone)]
pub struct ExternalAttachmentRecipient {
    pub id: Vec<u8>,
    /// IDs name key versions; the registry explicitly permits any historical IDs on retry.
    pub public_key: [u8; 32],
    /// True only for keys controlled by the service operator.
    pub operator_held: bool,
}
/// Selects actual permitted keys for an authenticated accepted-attachment resource.
#[async_trait]
pub trait ExternalAttachmentRecipientSelector: Send + Sync {
    /// Resolves custody from the owning registry, without trusting request assertions.
    ///
    /// # Errors
    /// Refuses unsupported accepted-resource associations or missing reader permission.
    async fn select(
        &self,
        permit: &AuthorizedScope,
        descriptor: &serde_json::Value,
    ) -> Result<Vec<ExternalAttachmentRecipient>, StackError>;
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WireActor {
    kind: String,
    subject: String,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WireRequest {
    #[schema(min_length = 1, max_length = 64)]
    idempotency_key: String,
    actor: WireActor,
    // Kept as raw text: the configured admission adapter decodes its own closed type
    // strictly, so duplicate keys survive to rejection.
    #[schema(schema_with = trellis_service_client::attachment_descriptor_openapi_schema)]
    descriptor: Box<serde_json::value::RawValue>,
    #[schema(min_length = 4, max_length = 1398104, format = Byte)]
    original_bytes: String,
}
pub(crate) struct AuthorizedExternal {
    scope: String,
    request: WireRequest,
    payload: serde_json::Value,
    original: Vec<u8>,
    compute: ComputeContext,
    recipients: Vec<ExternalAttachmentRecipient>,
}

fn selected_custody(
    recipients: &[ExternalAttachmentRecipient],
) -> Result<(ExternalAttachmentRecipientPolicy, ComputeSensitivity), StackError> {
    if recipients.is_empty() || recipients.len() > 64 {
        return Err(StackError::bad_request(
            "recipient selection outside supported bound",
        ));
    }
    let mut readers = Vec::new();
    let mut operators = Vec::new();
    for recipient in recipients {
        if recipient.id.is_empty() || recipient.id.len() > 256 || recipient.public_key == [0; 32] {
            return Err(StackError::bad_request("invalid selected recipient key"));
        }
        if recipient.operator_held {
            operators.push(recipient.id.clone());
        } else {
            readers.push(recipient.id.clone());
        }
    }
    let policy = ExternalAttachmentRecipientPolicy {
        designated_readers: readers,
        operator_recipients: operators,
    };
    let mut ids = std::collections::BTreeSet::new();
    if policy.designated_readers.is_empty() || recipients.iter().any(|r| !ids.insert(r.id.clone()))
    {
        return Err(StackError::bad_request(
            "selected recipients require a distinct designated reader",
        ));
    }
    let sensitivity = if policy.operator_recipients.is_empty() {
        ComputeSensitivity::ReaderHeld
    } else {
        ComputeSensitivity::ProviderReadable
    };
    Ok((policy, sensitivity))
}

pub(crate) async fn authorize(
    State(state): State<TrellisServerState>,
    Path(scope): Path<String>,
    tenant: TenantScope,
    mut request: Request,
    next: Next,
) -> Response {
    match admit(&state, scope, &tenant, &mut request).await {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}
async fn admit(
    state: &TrellisServerState,
    scope: String,
    tenant: &TenantScope,
    request: &mut Request,
) -> Result<(), StackError> {
    let identity = state.authenticate(request.headers()).await?;
    crate::http::validate_scope(&scope)?;
    let raw = to_bytes(
        std::mem::replace(request.body_mut(), Body::empty()),
        RAW_CAP,
    )
    .await
    .map_err(|_| StackError::bad_request("attachment request exceeds 2MiB"))?;
    let wire: WireRequest = serde_json::from_slice(&raw)
        .map_err(|_| StackError::bad_request("invalid closed accepted-attachment request"))?;
    let admission = state.external_attachment_admission.as_ref();
    let admitted = admission.admit(wire.descriptor.get())?;
    let payload = admitted.payload;
    if serde_json::to_vec(&payload)
        .map_err(|_| StackError::internal("descriptor encode failed"))?
        .len()
        > 64 * 1024
        || wire.actor.kind != "service"
        || wire.actor.subject.trim().is_empty()
        || wire.idempotency_key.is_empty()
        || wire.idempotency_key.len() > 64
        || wire.original_bytes.len() > 4 * ((ORIGINAL_CAP + 2) / 3)
    {
        return Err(StackError::bad_request(
            "attachment metadata or byte bound invalid",
        ));
    }
    crate::http::validate_idempotency_header(request.headers(), &wire.idempotency_key)?;
    let original = STANDARD
        .decode(&wire.original_bytes)
        .map_err(|_| StackError::bad_request("originalBytes must use standard padded base64"))?;
    if original.is_empty()
        || original.len() > ORIGINAL_CAP
        || STANDARD.encode(&original) != wire.original_bytes
        || admitted.byte_length != original.len() as u64
        || admitted.attachment_sha256
            != format!("sha256:{}", hex::encode(Sha256::digest(&original)))
    {
        return Err(StackError::bad_request(
            "original bytes differ from accepted descriptor",
        ));
    }
    let authorization = SubstrateAppendBody {
        event_type: admission.event_type().into(),
        idempotency_key: wire.idempotency_key.clone(),
        actor: AppendActor::service(&wire.actor.subject),
        payload: payload.clone(),
        compute_context: ComputeContext::no_delegated_compute(&wire.actor.subject),
        client_attestation: None,
    };
    authorization.validate()?;
    let permit = crate::auth::authorize_action(
        state,
        &identity,
        tenant,
        &scope,
        ScopeAction::Append,
        Some(&authorization),
    )
    .await?;
    let selector = state
        .external_attachment_recipients
        .as_ref()
        .ok_or_else(|| {
            StackError::unavailable("accepted-attachment recipient policy is not configured")
        })?;
    let recipients = selector.select(&permit, &payload).await?;
    let (_, sensitivity) = selected_custody(&recipients)?;

    let mut policy_rows = recipients
        .iter()
        .map(|r| (r.id.clone(), r.public_key, r.operator_held))
        .collect::<Vec<_>>();
    policy_rows.sort();
    let policy_bytes = serde_json::to_vec(&policy_rows)
        .map_err(|_| StackError::internal("recipient policy encoding failed"))?;
    let policy_fingerprint = hex::encode(integrity_cbor::domain_separated_sha256(
        "trellis-attachment-recipient-selection-v1",
        &policy_bytes,
    ));
    let compute = ComputeContext::new(
        format!("compute:accepted-attachment:trusted-custody-v1:{policy_fingerprint}"),
        "trellis-server",
        sensitivity,
    );
    let partition = serde_json::to_string(&(
        permit.principal,
        &permit.tenant_scope,
        &scope,
        "accepted-attachment",
        policy_fingerprint,
    ))
    .map_err(|_| StackError::internal("attachment replay partition encoding failed"))?;
    request
        .extensions_mut()
        .insert(TrustedReplayPartition::new(partition));
    // Request extensions are process-local; retain raw body for maintained replay hashing.
    request
        .extensions_mut()
        .insert(Arc::new(AuthorizedExternal {
            scope,
            request: wire,
            payload,
            original,
            compute,
            recipients,
        }));
    *request.body_mut() = Body::from(raw);
    Ok(())
}

#[utoipa::path(post,path="/v1/scopes/{scope}/accepted-attachments",
    params(("scope"=String,Path,description="Authorized Trellis scope"),("idempotency-key"=String,Header,description="Must match idempotencyKey")),
    request_body=WireRequest,
    responses((status=201,description="Protected event and verified export retained",body=SubstrateAppendResult),(status=400,description="Invalid closed request"),(status=401,description="Authentication refused"),(status=403,description="Exact permission refused"),(status=409,description="Replay or prefix conflict"),(status=503,description="Storage or selected recipient policy unavailable")),tag="events")]
pub(crate) async fn append(
    State(state): State<TrellisServerState>,
    Extension(authorized): Extension<Arc<AuthorizedExternal>>,
) -> Result<(StatusCode, Json<SubstrateAppendResult>), TransportError> {
    let _guard = state.scope_locks.lock(authorized.scope.as_bytes()).await;
    let now = crate::now_timestamp()?;
    if !state.signing_key.is_active_at(now) {
        return Err(StackError::bad_request("signing key inactive at append time").into());
    }
    let factory = Factory {
        authorized: &authorized,
        admission: state.external_attachment_admission.as_ref(),
        random: state.external_attachment_random.as_ref(),
        now,
    };
    let retained = state
        .repository
        .append_external_attachment_with(
            authorized.scope.as_bytes(),
            authorized.request.idempotency_key.as_bytes(),
            &state.signing_key.core_key(),
            &authorized.compute,
            &factory,
        )
        .await
        .map_err(TransportError::storage)?;
    let events = state
        .repository
        .list_scope(authorized.scope.as_bytes())
        .await
        .map_err(TransportError::storage)?;
    let update_head = events
        .last()
        .is_some_and(|event| event.sequence() == retained.event().sequence());
    let prefix = events
        .into_iter()
        .filter(|event| event.sequence() <= retained.event().sequence())
        .collect::<Vec<_>>();
    let prior = retained
        .event()
        .sequence()
        .checked_sub(1)
        .map(|seq| {
            prefix
                .iter()
                .find(|event| event.sequence() == seq)
                .ok_or_else(|| StackError::internal("attachment predecessor absent"))
                .and_then(|event| crate::event_hash(authorized.scope.as_bytes(), event))
        })
        .transpose()?;
    let bundle = crate::publish_bundle(
        &state,
        authorized.scope.as_bytes(),
        &prefix,
        update_head,
        &authorized.compute,
    )
    .await
    .map_err(TransportError::storage)?;
    let result = crate::append_result_for_event(
        &authorized.scope,
        retained.event(),
        prior,
        trellis_types::ArtifactType::Event,
        state.external_attachment_admission.event_type(),
        &bundle,
        true,
    )?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// Trusted handler evidence that one storage attempt may be retried.
#[derive(Clone)]
pub(crate) struct RetryableStorageAttempt;

pub(crate) struct TransportError {
    error: StackError,
    retryable: bool,
}
impl From<StackError> for TransportError {
    fn from(error: StackError) -> Self {
        Self {
            error,
            retryable: false,
        }
    }
}
impl TransportError {
    fn storage(error: StackError) -> Self {
        let retryable = error.status() == StatusCode::SERVICE_UNAVAILABLE;
        Self { error, retryable }
    }
}
impl IntoResponse for TransportError {
    fn into_response(self) -> Response {
        let mut response = self.error.into_response();
        if self.retryable {
            response.extensions_mut().insert(RetryableStorageAttempt);
        }
        response
    }
}

struct Factory<'a> {
    authorized: &'a AuthorizedExternal,
    admission: &'a dyn trellis_server_ports::ExternalAttachmentAdmission,
    random: &'a dyn SecureRandom,
    now: trellis_export_writer::TrellisTimestamp,
}
impl ExternalAttachmentFactory for Factory<'_> {
    fn prepare(
        &self,
        events: &[StoredEvent],
        retained: Option<&RetainedExternalAttachment>,
    ) -> Result<ExternalAttachmentAppend, StackError> {
        let scope = self.authorized.scope.as_bytes();
        let key = self.authorized.request.idempotency_key.as_bytes();
        let original = &self.authorized.original;
        let digest: [u8; 32] = Sha256::digest(original).into();
        let (ciphertext, nonce, key_bag) = if let Some(retained) = retained {
            let value = decode_cbor_value(retained.event().canonical_event())
                .map_err(|_| StackError::conflict("retained attachment canonical bytes invalid"))?;
            let bag = value
                .as_map()
                .and_then(|map| map_lookup_optional_value(map, "key_bag"))
                .cloned()
                .ok_or_else(|| StackError::conflict("retained attachment key bag absent"))?;
            (retained.ciphertext().to_vec(), *retained.nonce(), bag)
        } else {
            let recipients = self
                .authorized
                .recipients
                .iter()
                .map(|r| Recipient {
                    id: &r.id,
                    public_key: r.public_key,
                })
                .collect::<Vec<_>>();
            let protected = protect_external_attachment(
                self.random,
                AttachmentContext {
                    idempotency_key: key,
                    original_sha256: digest,
                    original_byte_length: original.len() as u64,
                },
                original,
                &recipients,
                ProtectionLimits {
                    original_bytes: ORIGINAL_CAP,
                    recipients: 64,
                    recipient_id_bytes: 256,
                },
            )
            .map_err(|error| {
                StackError::unavailable(format!("attachment protection unavailable: {error}"))
            })?;
            let entries = protected
                .key_bag
                .into_iter()
                .map(|wrap| {
                    Value::Map(vec![
                        (
                            Value::Text("recipient".into()),
                            Value::Bytes(wrap.recipient),
                        ),
                        (
                            Value::Text("suite".into()),
                            Value::Integer(wrap.suite.into()),
                        ),
                        (
                            Value::Text("ephemeral_pubkey".into()),
                            Value::Bytes(wrap.ephemeral_pubkey.to_vec()),
                        ),
                        (
                            Value::Text("wrapped_dek".into()),
                            Value::Bytes(wrap.wrapped_dek),
                        ),
                    ])
                })
                .collect();
            (
                protected.ciphertext,
                protected.nonce,
                Value::Map(vec![(Value::Text("entries".into()), Value::Array(entries))]),
            )
        };
        let (policy, sensitivity) = selected_custody(&self.authorized.recipients)?;
        if super::external_attachment::custody_selection(&key_bag, &policy)? != sensitivity {
            return Err(StackError::conflict(
                "retained wraps differ from currently selected custody",
            ));
        }
        let prior = events
            .iter()
            .filter(|event| retained.is_none_or(|r| event.sequence() < r.event().sequence()))
            .cloned()
            .collect::<Vec<_>>();
        let binding = self.admission.bind(
            &self.authorized.payload,
            scope,
            original,
            &ciphertext,
            &prior,
            AttachmentLimits {
                original_bytes: ORIGINAL_CAP,
                ciphertext_bytes: ORIGINAL_CAP + 16,
                prior_events: 256,
                prior_event_bytes: 1024 * 1024,
            },
        )?;
        let extensions = decode_cbor_value(&binding.extensions_cbor)
            .map_err(|_| StackError::internal("prepared attachment extensions invalid"))?;
        let preparation_identity = binding.replay_digest;
        let expected_head = binding.expected_head;
        let event_type = self.admission.event_type().to_owned();
        Ok(ExternalAttachmentAppend {
            scope: scope.to_vec(),
            idempotency_key: key.to_vec(),
            header: ExternalAttachmentHeader {
                event_type,
                authored_at_seconds: self.now.unix_secs,
                authored_at_nanos: self.now.subsec_nanos,
                classification: "x-trellis-service/private-attachment".into(),
                retention_tier: 0,
            },
            extensions,
            key_bag,
            ciphertext,
            nonce,
            original_sha256: digest,
            original_byte_length: original.len() as u64,
            preparation_identity,
            expected_head,
            limits: ExternalAppendLimits {
                ciphertext_bytes: ORIGINAL_CAP + 16,
                events: 256,
                metadata_bytes: 64 * 1024,
            },
        })
    }
}
