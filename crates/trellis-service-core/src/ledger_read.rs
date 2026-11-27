// Rust guideline compliant 2026-02-21
//! Reads the HTTP ledger views from retained canonical events and signed checkpoints.

use integrity_cbor::{
    Value, dcbor_bytes_to_json, decode_cbor_value, json_to_dcbor_bytes, map_lookup_bytes,
    map_lookup_map, map_lookup_optional_value,
};
use stack_common_error::StackError;
use trellis_server_ports::{CheckpointedEvent, LedgerCheckpoint, LedgerHeadRow, LedgerScope};
use trellis_service_client::endpoints::{LedgerHead, OrderedEvent};
use trellis_types::{CheckpointPayload, checkpoint_digest};

use crate::adapters::AdmissionRouter;
use crate::reconciliation::checked_canonical_event;

fn hash_text(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

fn tree_head_hash(
    scope: &LedgerScope,
    checkpoint: &LedgerCheckpoint,
    expected_size: u64,
) -> Result<String, StackError> {
    let payload = CheckpointPayload::from_sign1(&checkpoint.signed)
        .map_err(|_| StackError::internal("stored checkpoint payload is invalid"))?;
    if payload.scope != scope.as_bytes()
        || payload.tree_size != expected_size
        || checkpoint.tree_size != expected_size
    {
        return Err(StackError::internal(
            "stored checkpoint names another ledger prefix",
        ));
    }
    let signed = integrity_cose::decode_cose_sign1(&checkpoint.signed)
        .map_err(|_| StackError::internal("stored checkpoint signature structure is invalid"))?;
    let signed_payload = signed
        .payload()
        .ok_or_else(|| StackError::internal("stored checkpoint payload is absent"))?;
    if checkpoint.digest != checkpoint_digest(scope.as_bytes(), signed_payload) {
        return Err(StackError::internal("stored checkpoint digest differs"));
    }
    Ok(hash_text(&payload.tree_head_hash))
}

pub(crate) fn start_tree_head_hash(
    scope: &LedgerScope,
    checkpoint: Option<&LedgerCheckpoint>,
    after: u64,
) -> Result<String, StackError> {
    match checkpoint {
        Some(checkpoint) => tree_head_hash(scope, checkpoint, after),
        None if after == 0 => Ok(hash_text(&integrity_cbor::sha256_bytes(b""))),
        None => Err(StackError::internal(
            "stored page lacks its starting checkpoint",
        )),
    }
}

pub(crate) fn head(scope: &LedgerScope, row: LedgerHeadRow) -> Result<LedgerHead, StackError> {
    Ok(LedgerHead {
        tree_size: row.checkpoint.tree_size,
        tree_head_hash: tree_head_hash(scope, &row.checkpoint, row.checkpoint.tree_size)?,
        checkpoint_digest: hash_text(&row.checkpoint.digest),
        last_event_hash: hash_text(&row.last_event_hash),
    })
}

pub(crate) fn event(
    scope: &LedgerScope,
    row: CheckpointedEvent,
    admission: &AdmissionRouter,
) -> Result<OrderedEvent, StackError> {
    let (_, hash) = checked_canonical_event(
        scope.as_bytes(),
        row.sequence,
        &row.canonical_event,
        Some(&row.canonical_event_hash),
    )?;
    let invalid = || StackError::internal("stored canonical event is invalid");
    let decoded = decode_cbor_value(&row.canonical_event).map_err(|_| invalid())?;
    let root = decoded.as_map().ok_or_else(invalid)?;
    let header = map_lookup_map(root, "header").map_err(|_| invalid())?;
    let event_type =
        String::from_utf8(map_lookup_bytes(header, "event_type").map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    let prior_event_hash = match map_lookup_optional_value(root, "prev_hash") {
        Some(Value::Bytes(hash)) => Some(hash_text(
            hash.as_slice().try_into().map_err(|_| invalid())?,
        )),
        Some(Value::Null) | None => None,
        _ => return Err(invalid()),
    };
    let reference = map_lookup_map(root, "payload_ref").map_err(|_| invalid())?;
    let public = matches!(
        map_lookup_optional_value(header, "classification"),
        Some(Value::Bytes(classification)) if classification == crate::append::PUBLIC_METADATA_CLASSIFICATION
    );
    let inline = matches!(
        map_lookup_optional_value(reference, "ref_type"),
        Some(Value::Text(kind)) if kind == "inline"
    );
    let key_bag = map_lookup_map(root, "key_bag").map_err(|_| invalid())?;
    let plaintext = matches!(
        map_lookup_optional_value(key_bag, "entries"),
        Some(Value::Array(entries)) if entries.is_empty()
    );
    let erased = public
        && plaintext
        && matches!(
            map_lookup_optional_value(reference, "ref_type"),
            Some(Value::Text(kind)) if kind == "external"
        )
        && matches!(
            map_lookup_optional_value(reference, "availability"),
            Some(Value::Text(avail)) if avail == "erased"
        )
        && matches!(
            map_lookup_optional_value(reference, "content_hash"),
            Some(Value::Bytes(bytes)) if bytes.len() == 32
        );
    let payload = if public && inline && plaintext {
        let Some(Value::Bytes(encoded)) = map_lookup_optional_value(reference, "ciphertext") else {
            return Err(invalid());
        };
        readable_json(encoded)
    } else {
        None
    };
    if admission.is_contract_event(&event_type)
        && !erased
        && !payload.as_ref().is_some_and(serde_json::Value::is_object)
    {
        return Err(StackError::internal(
            "stored authority payload is not readable JSON",
        ));
    }
    let tree_size = row.sequence.checked_add(1).ok_or_else(invalid)?;
    Ok(OrderedEvent {
        sequence: row.sequence,
        event_type,
        payload,
        canonical_event_hash: hash_text(&hash),
        prior_event_hash,
        checkpoint_ref: format!(
            "trellis://{scope}/checkpoints/{}",
            hash_text(&row.checkpoint.digest)
        ),
        tree_head_hash: tree_head_hash(scope, &row.checkpoint, tree_size)?,
    })
}

// The HTTP writer encodes JSON as canonical CBOR. The round trip distinguishes that representation
// from other inline data, including CBOR values whose inspection view is lossy.
fn readable_json(encoded: &[u8]) -> Option<serde_json::Value> {
    let json = dcbor_bytes_to_json(encoded).ok()?;
    (json_to_dcbor_bytes(&json, &[]).ok()?.as_slice() == encoded).then_some(json)
}
