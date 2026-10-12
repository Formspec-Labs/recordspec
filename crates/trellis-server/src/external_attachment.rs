// Rust guideline compliant 2026-02-21
//! Invokes native protected append through maintained identity and permission checks.

use crate::TrellisServerState;
use axum::http::HeaderMap;
use integrity_cbor::{
    Value, decode_cbor_value, encode_canonical_cbor_value, map_lookup_optional_value,
};
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use trellis_admission_formspec::accepted_attachment::{
    ACCEPTED_ATTACHMENT_EVENT, ATTACHMENT_BINDING_EXTENSION, PreparedAcceptedAttachment,
};
use trellis_core::external_attachment::ExternalAttachmentAppend;
use trellis_export_writer::ExportEvidenceMember;
use trellis_server_ports::{ComputeSensitivity, ScopeAction};
use trellis_service_client::{SubstrateAppendBody, SubstrateAppendResult};
use trellis_types::{ArtifactType, StoredEvent};

/// Appends an owning service's prepared accepted attachment and publishes its export.
///
/// The caller supplies Source evidence selected by its trusted composition and
/// an already protected result. The preparation does not grant Source authority
/// or recipient permission. Credentials and case scope use the existing server
/// authorizer; every retry checks current permission before durable replay.
/// This composition API introduces no live HTTP route.
///
/// # Errors
/// Refuses missing permission, changed preparation, stale head, conflicting replay,
/// storage failure or export verification/publication failure. Publication failure
/// leaves the atomic committed operation available for an authorized retry.
/// Trusted owning-composition recipient custody selection.
///
/// The caller obtains these IDs from its authenticated reader/key registry.
/// IDs identify the custody of the actual supplied wraps, not asserted Source facts.
pub struct ExternalAttachmentRecipientPolicy {
    pub designated_readers: Vec<Vec<u8>>,
    pub operator_recipients: Vec<Vec<u8>>,
}

pub async fn append_prepared_external_attachment(
    state: &TrellisServerState,
    headers: &HeaderMap,
    tenant: &TenantScope,
    authorization: &SubstrateAppendBody,
    prepared: &PreparedAcceptedAttachment<'_>,
    mut input: ExternalAttachmentAppend,
    recipient_policy: &ExternalAttachmentRecipientPolicy,
) -> Result<SubstrateAppendResult, StackError> {
    let scope = std::str::from_utf8(&input.scope)
        .map_err(|_| StackError::bad_request("attachment scope must be UTF-8"))?;
    crate::http::validate_scope(scope)?;
    let identity = state.authenticate(headers).await?;
    authorization.validate()?;
    crate::http::validate_idempotency_header(headers, &authorization.idempotency_key)?;
    if authorization.event_type != ACCEPTED_ATTACHMENT_EVENT
        || input.header.event_type != ACCEPTED_ATTACHMENT_EVENT
        || authorization.client_attestation.is_some()
        || authorization.idempotency_key.as_bytes() != input.idempotency_key
        || input.header.classification != "x-trellis-service/private-attachment"
        || serde_json::to_value(prepared.descriptor())
            .map_err(|_| StackError::internal("descriptor encoding failed"))?
            != authorization.payload
        || input.scope != prepared.scope()
        || input.expected_head != prepared.expected_head()
        || input.preparation_identity != prepared.replay_digest()
        || input.ciphertext != prepared.ciphertext()
        || input.extensions
            != decode_cbor_value(&prepared.extensions_cbor()?)
                .map_err(|_| StackError::bad_request("prepared binding unreadable"))?
    {
        return Err(StackError::bad_request(
            "native attachment preparation or service metadata mismatch",
        ));
    }
    crate::auth::authorize_action(
        state,
        &identity,
        tenant,
        scope,
        ScopeAction::Append,
        Some(authorization),
    )
    .await?;
    let selected = custody_selection(&input.key_bag, recipient_policy)?;
    if authorization.compute_context.sensitivity != selected {
        return Err(StackError::bad_request(
            "compute declaration differs from trusted recipient custody",
        ));
    }
    let scope = scope.to_owned();
    let _guard = state.scope_locks.lock(scope.as_bytes()).await;
    let now = crate::now_timestamp()?;
    if !state.signing_key.is_active_at(now) {
        return Err(StackError::bad_request(
            "signing key inactive at append time",
        ));
    }
    input.header.authored_at_seconds = now.unix_secs;
    input.header.authored_at_nanos = now.subsec_nanos;
    let retained = state
        .repository
        .append_external_attachment(
            input,
            &state.signing_key.core_key(),
            &authorization.compute_context,
        )
        .await?;
    let events = state.repository.list_scope(scope.as_bytes()).await?;
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
                .ok_or_else(|| StackError::internal("retained attachment predecessor missing"))
                .and_then(|event| crate::event_hash(scope.as_bytes(), event))
        })
        .transpose()?;
    let bundle = crate::publish_bundle(
        state,
        scope.as_bytes(),
        &prefix,
        update_head,
        &authorization.compute_context,
    )
    .await?;
    crate::append_result_for_event(
        &scope,
        retained.event(),
        prior,
        ArtifactType::Event,
        ACCEPTED_ATTACHMENT_EVENT,
        &bundle,
        true,
    )
}

/// Collects exact retained bodies and chain-derived attachment catalog entries.
pub(crate) async fn evidence_members(
    state: &TrellisServerState,
    scope: &[u8],
    events: &[StoredEvent],
) -> Result<Vec<ExportEvidenceMember>, StackError> {
    let mut members = Vec::new();
    let mut catalog = Vec::new();
    let mut bodies = std::collections::BTreeSet::new();
    let mut aggregate = 0usize;
    for event in events {
        let profile = trellis_cddl::parse_external_attachment_profile(event.canonical_event())
            .map_err(|error| {
                StackError::conflict(format!("retained native profile invalid: {error}"))
            })?;
        let (content_hash, bytes) = if let Some(profile) = &profile {
            let bytes = state
                .repository
                .external_attachment_body(scope, &profile.content_hash)
                .await?
                .ok_or_else(|| {
                    StackError::conflict("retained protected attachment body missing")
                })?;
            if bytes.len() as u64
                != profile
                    .original_byte_length
                    .checked_add(16)
                    .ok_or_else(|| StackError::conflict("attachment length overflow"))?
            {
                return Err(StackError::conflict(
                    "retained native attachment length differs",
                ));
            }
            (profile.content_hash, bytes)
        } else if crate::event_summary(event)?.event_type == crate::completion::COMPLETION_EVENT {
            let bytes = crate::completion::certificate_html(event)?;
            let value =
                decode_cbor_value(event.canonical_event()).map_err(crate::cbor_bad_request)?;
            let extensions = integrity_cbor::map_lookup_map(
                value
                    .as_map()
                    .ok_or_else(|| StackError::conflict("certificate map absent"))?,
                "extensions",
            )
            .map_err(crate::cbor_bad_request)?;
            let binding = integrity_cbor::map_lookup_map(extensions, ATTACHMENT_BINDING_EXTENSION)
                .map_err(crate::cbor_bad_request)?;
            let key = integrity_cbor::map_lookup_text(binding, "attachment_id")
                .map_err(crate::cbor_bad_request)?;
            if state
                .artifact_store
                .get(&trellis_server_ports::ArtifactRef::new(key))
                .await?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Err(StackError::unavailable(
                    "retained certificate artifact missing or changed",
                ));
            }
            (crate::event_summary(event)?.content_hash, bytes)
        } else {
            continue;
        };
        aggregate = aggregate
            .checked_add(bytes.len())
            .ok_or_else(|| StackError::conflict("attachment export size overflow"))?;
        if aggregate > 16 * 1024 * 1024
            || events.len() > 256
            || integrity_cbor::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &bytes)
                != content_hash
        {
            return Err(StackError::conflict(
                "retained attachment body identity or export bound mismatch",
            ));
        }
        if bodies.insert(content_hash) {
            members.push(ExportEvidenceMember::Payload {
                content_hash,
                bytes,
            });
        }
        let value = decode_cbor_value(event.canonical_event())
            .map_err(|_| StackError::conflict("retained attachment event unreadable"))?;
        let extensions = value
            .as_map()
            .and_then(|map| map_lookup_optional_value(map, "extensions"))
            .and_then(Value::as_map)
            .ok_or_else(|| StackError::conflict("retained attachment extensions missing"))?;
        let binding = map_lookup_optional_value(extensions, ATTACHMENT_BINDING_EXTENSION)
            .and_then(Value::as_map)
            .ok_or_else(|| StackError::conflict("retained attachment binding missing"))?;
        let mut fields = binding.to_vec();
        for (key, value) in &mut fields {
            if matches!(
                key.as_text(),
                Some("attachment_sha256" | "payload_content_hash" | "prior_binding_hash")
            ) && *value != Value::Null
            {
                let text = value
                    .as_text()
                    .and_then(|v| v.strip_prefix("sha256:"))
                    .ok_or_else(|| StackError::conflict("binding digest malformed"))?;
                *value = Value::Bytes(
                    hex::decode(text)
                        .map_err(|_| StackError::conflict("binding digest malformed"))?,
                );
            }
        }
        fields.push((
            Value::Text("binding_event_hash".into()),
            Value::Bytes(crate::event_hash(scope, event)?.to_vec()),
        ));
        catalog.push(Value::Map(fields));
    }
    if !catalog.is_empty() {
        members.push(ExportEvidenceMember::Attachments {
            bytes: encode_canonical_cbor_value(&Value::Array(catalog))
                .map_err(|_| StackError::internal("attachment catalog encode failed"))?,
            inline_attachments: true,
        });
    }
    Ok(members)
}

pub(crate) fn custody_selection(
    key_bag: &Value,
    policy: &ExternalAttachmentRecipientPolicy,
) -> Result<ComputeSensitivity, StackError> {
    let readers = policy
        .designated_readers
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let operators = policy
        .operator_recipients
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if readers.is_empty()
        || readers.len() != policy.designated_readers.len()
        || operators.len() != policy.operator_recipients.len()
        || readers.intersection(&operators).next().is_some()
        || readers
            .iter()
            .chain(operators.iter())
            .any(|id| id.is_empty())
    {
        return Err(StackError::bad_request(
            "invalid trusted recipient custody selection",
        ));
    }
    let entries = key_bag
        .as_map()
        .and_then(|map| map_lookup_optional_value(map, "entries"))
        .and_then(Value::as_array)
        .ok_or_else(|| StackError::bad_request("key bag entries absent"))?;
    let mut reader = false;
    let mut operator = false;
    for entry in entries {
        let id = entry
            .as_map()
            .and_then(|map| map_lookup_optional_value(map, "recipient"))
            .and_then(Value::as_bytes)
            .ok_or_else(|| StackError::bad_request("key bag recipient absent"))?
            .to_vec();
        if readers.contains(&id) {
            reader = true;
        } else if operators.contains(&id) {
            operator = true;
        } else {
            return Err(StackError::bad_request(
                "key bag recipient not selected by trusted custody policy",
            ));
        }
    }
    if !reader {
        return Err(StackError::bad_request(
            "designated reader has no actual wrap",
        ));
    }
    Ok(if operator {
        ComputeSensitivity::ProviderReadable
    } else {
        ComputeSensitivity::ReaderHeld
    })
}

pub(crate) async fn export_compute(
    state: &TrellisServerState,
    scope: &[u8],
    events: &[StoredEvent],
    requested: &trellis_server_ports::ComputeContext,
) -> Result<trellis_server_ports::ComputeContext, StackError> {
    let mut selected = None;
    for event in events {
        let profile = trellis_cddl::parse_external_attachment_profile(event.canonical_event())
            .map_err(|error| {
                StackError::conflict(format!("retained native profile invalid: {error}"))
            })?;
        if let Some(profile) = profile {
            let compute = state
                .repository
                .external_attachment_compute(scope, &profile.content_hash)
                .await?
                .ok_or_else(|| {
                    StackError::conflict("retained attachment custody declaration absent")
                })?;
            if !matches!(
                compute.sensitivity,
                ComputeSensitivity::ReaderHeld | ComputeSensitivity::ProviderReadable
            ) {
                return Err(StackError::conflict(
                    "unsupported retained attachment custody declaration",
                ));
            }
            match &selected {
                Some(prior) if prior == &ComputeSensitivity::ProviderReadable => {}
                _ => selected = Some(compute.sensitivity),
            }
        }
    }
    let Some(sensitivity) = selected else {
        return Ok(requested.clone());
    };
    crate::event_repository::qualify_native_prefix(events)?;
    Ok(trellis_server_ports::ComputeContext {
        declaration_id: "compute:native-attachment:retained-custody".into(),
        actor: "trellis-server".into(),
        sensitivity,
    })
}
