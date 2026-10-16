// Rust guideline compliant 2026-02-21
//! Canonical-event inspection and canonical-CBOR map building shared by the
//! generic server and the profile adapters it injects.

use integrity_cbor::{
    CborHelperError, Value, domain_separated_sha256, encode_canonical_cbor_value, map_lookup_bytes,
    map_lookup_fixed_bytes, map_lookup_map,
};
use stack_common_error::StackError;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_export_writer::TrellisTimestamp;
use trellis_types::{EVENT_DOMAIN, StoredEvent};

/// Header facts read from one stored canonical event.
#[derive(Debug, PartialEq, Eq)]
pub struct EventSummary {
    pub event_type: String,
    pub content_hash: [u8; 32],
    pub authored_at: TrellisTimestamp,
}

/// Reads the event type, content hash and authored-at timestamp of a stored event.
///
/// # Errors
/// Returns a bad-request error when the canonical event is not the expected map shape.
pub fn event_summary(event: &StoredEvent) -> Result<EventSummary, StackError> {
    let value = integrity_cbor::decode_cbor_value(event.canonical_event()).map_err(|error| {
        StackError::bad_request(format!("canonical event decode failed: {error}"))
    })?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::bad_request("canonical event is not a map"))?;
    let content_hash = map_lookup_fixed_bytes(map, "content_hash", 32)
        .map_err(cbor_bad_request)?
        .try_into()
        .map_err(|_| StackError::internal("content_hash length changed"))?;
    let header = map_lookup_map(map, "header").map_err(cbor_bad_request)?;
    let event_type =
        String::from_utf8(map_lookup_bytes(header, "event_type").map_err(cbor_bad_request)?)
            .map_err(|_| StackError::bad_request("event_type is not UTF-8"))?;
    let authored_at = timestamp_from_header(header)?;
    Ok(EventSummary {
        event_type,
        content_hash,
        authored_at,
    })
}

/// Authored-at timestamp of a stored event.
///
/// # Errors
/// Same as [`event_summary`].
pub fn event_timestamp(event: &StoredEvent) -> Result<TrellisTimestamp, StackError> {
    event_summary(event).map(|summary| summary.authored_at)
}

/// Canonical event hash: the stored value when present, otherwise derived from the scope.
///
/// # Errors
/// Never fails today; the signature keeps room for derivation errors.
pub fn event_hash(scope: &[u8], event: &StoredEvent) -> Result<[u8; 32], StackError> {
    if let Some(hash) = event.canonical_event_hash() {
        return Ok(*hash);
    }
    Ok(domain_separated_sha256(
        EVENT_DOMAIN,
        &canonical_event_hash_preimage(scope, event.canonical_event()),
    ))
}

fn timestamp_from_header(map: &[(Value, Value)]) -> Result<TrellisTimestamp, StackError> {
    let value = integrity_cbor::map_lookup_value(map, "authored_at").map_err(cbor_bad_request)?;
    let Value::Array(items) = value else {
        return Err(StackError::bad_request(
            "authored_at is not a timestamp array",
        ));
    };
    if items.len() != 2 {
        return Err(StackError::bad_request(
            "authored_at timestamp length is invalid",
        ));
    }
    let seconds = value_to_u64(&items[0], "authored_at seconds")?;
    let nanos = value_to_u64(&items[1], "authored_at nanos")?;
    let nanos = u32::try_from(nanos)
        .map_err(|_| StackError::bad_request("authored_at nanos exceeds u32"))?;
    TrellisTimestamp::new(seconds, nanos)
}

fn value_to_u64(value: &Value, label: &str) -> Result<u64, StackError> {
    let Value::Integer(integer) = value else {
        return Err(StackError::bad_request(format!(
            "{label} is not an integer"
        )));
    };
    u64::try_from(*integer)
        .map_err(|_| StackError::bad_request(format!("{label} is negative or too large")))
}

/// Builds a canonically key-ordered CBOR map from text keys.
///
/// # Errors
/// Returns an internal error when a key cannot be canonically encoded.
pub fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, StackError> {
    canonical_map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_string()), value))
            .collect(),
    )
}

fn canonical_map(fields: Vec<(Value, Value)>) -> Result<Value, StackError> {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_value(&key)?;
            Ok((encoded, key, value))
        })
        .collect::<Result<Vec<_>, StackError>>()?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

/// Encodes a value as canonical CBOR.
///
/// # Errors
/// Returns an internal error when the value cannot be encoded.
pub fn encode_value(value: &Value) -> Result<Vec<u8>, StackError> {
    encode_canonical_cbor_value(value)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))
}

/// Unsigned integer CBOR value.
#[must_use]
pub fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

/// Maps a CBOR lookup failure to a bad-request error.
#[must_use]
pub fn cbor_bad_request(error: CborHelperError) -> StackError {
    StackError::bad_request(error.to_string())
}
