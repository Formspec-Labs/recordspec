// Rust guideline compliant 2026-02-21
//! Minimal CDDL-facing parsers and encoders for the G-4 append scaffold.

#![forbid(unsafe_code)]

mod completion_selection;
mod external_attachment;
#[doc(inline)]
pub use completion_selection::{
    CompletionRecord, completion_record_bindings, validate_completion_prefix,
};
pub use external_attachment::{
    ATTACHMENT_BINDING_EXTENSION, EXTERNAL_ATTACHMENT_PROFILE, PROFILE_EXTENSION,
    ParsedExternalAttachment, ParsedExternalAttachmentWrap, parse_external_attachment_profile,
};

use std::backtrace::Backtrace;
use std::fmt::{Display, Formatter};

use trellis_types::{
    CborHelperError, IDEMPOTENCY_KEY_MAX_LEN, IDEMPOTENCY_KEY_MIN_LEN, Value, encode_bstr,
    encode_tstr, encode_uint, idempotency_key_length_in_bound, map_lookup_bytes,
    map_lookup_fixed_bytes, map_lookup_integer_label_bytes, map_lookup_u64,
};

/// Builds the shared certificate operator-attestation signing preimage.
///
/// Companion A.5 and ADR0007 reuse the transition domain with certificate ID
/// as `transition_id` and exact completion timestamp as `effective_at`.
///
/// # Errors
/// Refuses empty or oversized IDs, invalid nanoseconds, or unknown authority classes.
pub fn certificate_attestation_preimage(
    certificate_id: &str,
    completed_at_seconds: u64,
    completed_at_nanos: u32,
    authority_class: &str,
) -> Result<Vec<u8>, CddlError> {
    if certificate_id.trim().is_empty()
        || certificate_id.len() > 1024
        || completed_at_nanos >= 1_000_000_000
        || !matches!(authority_class, "prior" | "new")
    {
        return Err(CddlError::new(
            "certificate attestation identity, timestamp or class invalid",
        ));
    }
    let component = trellis_types::encode_canonical_cbor_value(&Value::Array(vec![
        Value::Text(certificate_id.to_owned()),
        Value::Array(vec![
            Value::Integer(completed_at_seconds.into()),
            Value::Integer(completed_at_nanos.into()),
        ]),
        Value::Text(authority_class.to_owned()),
    ]))?;
    Ok(trellis_types::domain_separated_preimage(
        "trellis-transition-attestation-v1",
        &component,
    )?)
}

#[cfg(test)]
mod certificate_attestation_tests {
    use super::*;
    #[test]
    fn certificate_attestation_matches_authored_030_preimage() {
        let component = include_bytes!(
            "../../../fixtures/vectors/append/030-certificate-of-completion-html-template/input-attestation-preimage-00-new.cbor"
        );
        let actual = certificate_attestation_preimage(
            "urn:trellis:certificate:test:030",
            1_776_899_500,
            0,
            "new",
        )
        .unwrap();
        assert_eq!(
            actual,
            trellis_types::domain_separated_preimage(
                "trellis-transition-attestation-v1",
                component
            )
            .unwrap()
        );
        assert!(certificate_attestation_preimage("", 0, 0, "new").is_err());
        assert!(certificate_attestation_preimage("id", 0, 1_000_000_000, "new").is_err());
        assert!(certificate_attestation_preimage("id", 0, 0, "operator").is_err());
    }
}

/// The authored-event fields needed by the Phase-1 append scaffold.
///
/// `idempotency_key` is the Core §6.1 / §17.2 wire-contract identity. Its
/// length is validated against `bstr .size (1..64)` at parse time; a
/// length-bound violation surfaces as [`CddlError`] with kind
/// [`CddlErrorKind::IdempotencyKeyLengthInvalid`] so callers (the verifier,
/// the append scaffold) can map it to the §17.5 `idempotency_key_length_invalid`
/// rejection code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAuthoredEvent {
    pub ledger_scope: Vec<u8>,
    pub sequence: u64,
    pub idempotency_key: Vec<u8>,
}

/// The Ed25519 key material needed by the Phase-1 append scaffold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedEd25519Key {
    pub public_key: [u8; 32],
    pub private_seed: [u8; 32],
}

/// The canonical-event fields needed by the Phase-1 append scaffold.
///
/// `idempotency_key` is parsed from the canonical EventPayload (§6.1 / §28
/// CDDL); it MUST be byte-equal to the authored-event's `idempotency_key`
/// because the canonical map is the authored map plus `author_event_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCanonicalEvent {
    pub ledger_scope: Vec<u8>,
    pub sequence: u64,
    pub author_event_hash: [u8; 32],
    pub idempotency_key: Vec<u8>,
}

/// Error kinds surfaced by the append-scaffold CDDL parsers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CddlErrorKind {
    /// The CBOR document did not decode against the expected map shape.
    StructureInvalid,
    /// `idempotency_key` violated Core §6.1 `bstr .size (1..64)` (§17.5
    /// `idempotency_key_length_invalid`).
    IdempotencyKeyLengthInvalid,
}

/// Error returned when fixture CBOR cannot be decoded into the expected shape.
#[derive(Debug)]
pub struct CddlError {
    kind: CddlErrorKind,
    message: String,
    backtrace: Backtrace,
}

impl CddlError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            kind: CddlErrorKind::StructureInvalid,
            message: message.into(),
            backtrace: Backtrace::capture(),
        }
    }

    fn with_kind(kind: CddlErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the discriminant for this decode failure.
    pub fn kind(&self) -> CddlErrorKind {
        self.kind
    }
}

impl From<CborHelperError> for CddlError {
    fn from(error: CborHelperError) -> Self {
        CddlError::new(error.0)
    }
}

impl Display for CddlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CddlError {}

impl CddlError {
    /// Returns the captured backtrace for this decode failure.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

/// Parses the authored-event bytes for the fields the append scaffold needs.
///
/// # Errors
/// Returns an error when the CBOR document cannot be decoded or does not
/// contain the expected `ledger_scope` and `sequence` fields.
pub fn parse_authored_event(bytes: &[u8]) -> Result<ParsedAuthoredEvent, CddlError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|error| {
        CddlError::new(format!("failed to decode authored event CBOR: {error}"))
    })?;
    let map = value
        .as_map()
        .ok_or_else(|| CddlError::new("authored event root is not a map"))?;

    let ledger_scope = map_lookup_bytes(map, "ledger_scope")?;
    let sequence = map_lookup_u64(map, "sequence")?;
    let idempotency_key = map_lookup_idempotency_key(map)?;

    Ok(ParsedAuthoredEvent {
        ledger_scope,
        sequence,
        idempotency_key,
    })
}

/// Parses the pinned COSE_Key for the Ed25519 public key and seed.
///
/// # Errors
/// Returns an error when the key does not decode or does not contain labels
/// `-2` and `-4` with 32-byte byte strings.
pub fn parse_ed25519_cose_key(bytes: &[u8]) -> Result<ParsedEd25519Key, CddlError> {
    let value: Value = ciborium::from_reader(bytes)
        .map_err(|error| CddlError::new(format!("failed to decode COSE_Key CBOR: {error}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| CddlError::new("COSE_Key root is not a map"))?;

    let public_key = fixed_label_bytes(map, -2, "public key")?;
    let private_seed = fixed_label_bytes(map, -4, "private seed")?;

    Ok(ParsedEd25519Key {
        public_key,
        private_seed,
    })
}

/// Parses the canonical-event bytes for the fields the append scaffold needs.
///
/// # Errors
/// Returns an error when the CBOR document cannot be decoded or does not
/// contain the expected `ledger_scope`, `sequence`, and `author_event_hash`
/// fields.
pub fn parse_canonical_event(bytes: &[u8]) -> Result<ParsedCanonicalEvent, CddlError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|error| {
        CddlError::new(format!("failed to decode canonical event CBOR: {error}"))
    })?;
    let map = value
        .as_map()
        .ok_or_else(|| CddlError::new("canonical event root is not a map"))?;

    let ledger_scope = map_lookup_bytes(map, "ledger_scope")?;
    let sequence = map_lookup_u64(map, "sequence")?;
    let author_event_hash = map_lookup_fixed_bytes(map, "author_event_hash", 32)?;
    let idempotency_key = map_lookup_idempotency_key(map)?;

    Ok(ParsedCanonicalEvent {
        ledger_scope,
        sequence,
        author_event_hash: author_event_hash
            .as_slice()
            .try_into()
            .map_err(|_| CddlError::new("author_event_hash is not 32 bytes"))?,
        idempotency_key,
    })
}

/// Map prefix for a CBOR definite-length map of `n` pairs: `(5 << 5) | n`.
///
/// Phase-1 append fixtures use a 12-field authored ledger-event map; the
/// canonical event adds `author_event_hash` as the **13th and last** map entry.
/// `integrity-verify` recovers the authored preimage by locating that field and
/// must stay in lockstep with this encoding if the CDDL map shape changes.
const AUTHORED_LEDGER_EVENT_MAP_ENTRY_COUNT: u8 = 12;
const AUTHORED_LEDGER_EVENT_MAP_PREFIX: u8 = (5 << 5) | AUTHORED_LEDGER_EVENT_MAP_ENTRY_COUNT;
const CANONICAL_LEDGER_EVENT_MAP_ENTRY_COUNT: u8 = 13;
const CANONICAL_LEDGER_EVENT_MAP_PREFIX: u8 = (5 << 5) | CANONICAL_LEDGER_EVENT_MAP_ENTRY_COUNT;

/// Builds the canonical event bytes by adding `author_event_hash` to the
/// authored-event map.
///
/// # Errors
/// Returns an error when the authored bytes do not start with the expected
/// 12-entry definite-length map used by `append/001`.
pub fn canonical_event_from_authored(
    authored_event: &[u8],
    author_event_hash: [u8; 32],
) -> Result<Vec<u8>, CddlError> {
    if authored_event.first().copied() != Some(AUTHORED_LEDGER_EVENT_MAP_PREFIX) {
        return Err(CddlError::new(
            "append/001 authored event does not start with the expected 12-entry map",
        ));
    }

    let mut canonical = Vec::with_capacity(authored_event.len() + 52);
    canonical.push(CANONICAL_LEDGER_EVENT_MAP_PREFIX);
    canonical.extend_from_slice(&authored_event[1..]);
    canonical.extend_from_slice(&encode_tstr("author_event_hash"));
    canonical.extend_from_slice(&encode_bstr(&author_event_hash));
    Ok(canonical)
}

/// Builds the canonical-event-hash preimage wrapper.
pub fn canonical_event_hash_preimage(scope: &[u8], canonical_event: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 8 + 1 + 13 + scope.len() + 14 + canonical_event.len());
    bytes.push(0xa3);
    bytes.extend_from_slice(&encode_tstr("version"));
    bytes.extend_from_slice(&encode_uint(1));
    bytes.extend_from_slice(&encode_tstr("ledger_scope"));
    bytes.extend_from_slice(&encode_bstr(scope));
    bytes.extend_from_slice(&encode_tstr("event_payload"));
    bytes.extend_from_slice(canonical_event);
    bytes
}

/// Builds the `AppendHead` bytes.
pub fn append_head_bytes(scope: &[u8], sequence: u64, canonical_event_hash: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0xa3);
    bytes.extend_from_slice(&encode_tstr("scope"));
    bytes.extend_from_slice(&encode_bstr(scope));
    bytes.extend_from_slice(&encode_tstr("sequence"));
    bytes.extend_from_slice(&encode_uint(sequence));
    bytes.extend_from_slice(&encode_tstr("canonical_event_hash"));
    bytes.extend_from_slice(&encode_bstr(&canonical_event_hash));
    bytes
}

fn fixed_label_bytes(
    map: &[(Value, Value)],
    label: i128,
    field_name: &str,
) -> Result<[u8; 32], CddlError> {
    let bytes = map_lookup_integer_label_bytes(map, label)
        .map_err(|_| CddlError::new(format!("missing COSE_Key label {label} for {field_name}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CddlError::new(format!("{field_name} must be 32 bytes")))
}

/// Extracts and validates the `idempotency_key` field per Core §6.1 + §17.2.
///
/// The CBOR value MUST be a byte string; its length MUST satisfy `bstr .size
/// (1..64)`. Length violations surface as [`CddlErrorKind::IdempotencyKeyLengthInvalid`]
/// so verifiers can map to the §17.5 `idempotency_key_length_invalid` code
/// without re-parsing the structural failure.
fn map_lookup_idempotency_key(map: &[(Value, Value)]) -> Result<Vec<u8>, CddlError> {
    let bytes = map_lookup_bytes(map, "idempotency_key")?;
    if !idempotency_key_length_in_bound(&bytes) {
        return Err(CddlError::with_kind(
            CddlErrorKind::IdempotencyKeyLengthInvalid,
            format!(
                "idempotency_key length {} outside Core §6.1 bound {}..={}",
                bytes.len(),
                IDEMPOTENCY_KEY_MIN_LEN,
                IDEMPOTENCY_KEY_MAX_LEN,
            ),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use proptest::prelude::*;

    use super::{canonical_event_from_authored, parse_canonical_event};

    fn fixture_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/append/001-minimal-inline-payload")
    }

    #[test]
    fn canonical_event_fixture_round_trips_byte_identically() {
        let root = fixture_root();
        let authored = fs::read(root.join("input-author-event-hash-preimage.cbor")).unwrap();
        let expected = fs::read(root.join("expected-event-payload.cbor")).unwrap();
        let parsed = parse_canonical_event(&expected).unwrap();

        let rebuilt = canonical_event_from_authored(&authored, parsed.author_event_hash).unwrap();
        assert_eq!(rebuilt, expected);
        assert_eq!(parsed.sequence, 0);
        assert_eq!(parsed.ledger_scope, b"test-response-ledger".to_vec());
    }

    proptest! {
        #[test]
        fn canonical_event_encoder_is_a_fixed_point(author_hash in any::<[u8; 32]>()) {
            let authored = fs::read(fixture_root().join("input-author-event-hash-preimage.cbor")).unwrap();
            let encoded = canonical_event_from_authored(&authored, author_hash).unwrap();
            let parsed = parse_canonical_event(&encoded).unwrap();
            let reencoded = canonical_event_from_authored(&authored, parsed.author_event_hash).unwrap();

            prop_assert_eq!(parsed.author_event_hash, author_hash);
            prop_assert_eq!(parsed.sequence, 0);
            prop_assert_eq!(parsed.ledger_scope, b"test-response-ledger".to_vec());
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
