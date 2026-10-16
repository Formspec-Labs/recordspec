// Rust guideline compliant 2026-02-21
//! Invokes native protected append through maintained identity and permission checks.

use crate::TrellisServerState;
use integrity_cbor::{
    Value, decode_cbor_value, encode_canonical_cbor_value, map_lookup_optional_value,
};
use stack_common_error::StackError;
use trellis_cddl::ATTACHMENT_BINDING_EXTENSION;
use trellis_export_writer::ExportEvidenceMember;
use trellis_server_ports::ComputeSensitivity;
use trellis_types::StoredEvent;

/// Trusted owning-composition recipient custody selection.
///
/// The caller obtains these IDs from its authenticated reader/key registry.
/// IDs identify the custody of the actual supplied wraps, not asserted Source facts.
pub struct ExternalAttachmentRecipientPolicy {
    pub designated_readers: Vec<Vec<u8>>,
    pub operator_recipients: Vec<Vec<u8>>,
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
