//! Structural validation for the explicitly selected external attachment protection profile.
//!
//! Callers must verify event signatures and checkpoint membership before using decoding inputs.

use crate::CddlError;
use trellis_types::{Value, encode_canonical_cbor_value, idempotency_key_length_in_bound};

/// Signed extension selecting the external attachment decoding rules.
pub const PROFILE_EXTENSION: &str = "trellis.payload-protection-profile.v1";
/// Exact suite 1 external attachment protection profile identifier.
pub const EXTERNAL_ATTACHMENT_PROFILE: &str = "trellis.external-attachment-suite1.v1";
const BINDING_EXTENSION: &str = "trellis.evidence-attachment-binding.v1";

/// Structurally checked recipient wrapping material, without cryptographic verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedExternalAttachmentWrap {
    /// Stable recipient identifier from the signed key bag.
    pub recipient: Vec<u8>,
    /// Suite 1 X25519 encapsulated public key.
    pub ephemeral_pubkey: [u8; 32],
    /// HPKE ciphertext and tag sealing the 32-byte payload key.
    pub wrapped_dek: [u8; 48],
}

/// Signed decoding inputs, requiring signature verification before recipient use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedExternalAttachment {
    /// SHA-256 digest of the unchanged original attachment bytes.
    pub original_sha256: [u8; 32],
    /// Length of the unchanged original attachment bytes.
    pub original_byte_length: u64,
    /// Signed event identity used by the profile nonce derivation.
    pub idempotency_key: Vec<u8>,
    /// Signed domain-separated hash of the exact ciphertext and tag.
    pub content_hash: [u8; 32],
    /// Complete suite 1 recipient wrapping entries.
    pub key_bag_entries: Vec<ParsedExternalAttachmentWrap>,
}

type Map = [(Value, Value)];
fn map(value: &Value) -> Result<&Map, CddlError> {
    value
        .as_map()
        .map(Vec::as_slice)
        .ok_or_else(|| CddlError::new("expected map"))
}
fn optional<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}
fn field<'a>(map: &'a Map, key: &str) -> Result<&'a Value, CddlError> {
    optional(map, key).ok_or_else(|| CddlError::new(format!("missing {key}")))
}
fn text(value: &Value) -> Result<&str, CddlError> {
    value
        .as_text()
        .ok_or_else(|| CddlError::new("expected text"))
}
fn bytes(value: &Value) -> Result<&[u8], CddlError> {
    value
        .as_bytes()
        .map(Vec::as_slice)
        .ok_or_else(|| CddlError::new("expected byte string"))
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], CddlError> {
    bytes(value)?
        .try_into()
        .map_err(|_| CddlError::new("wrong byte string length"))
}
fn uint(value: &Value) -> Result<u64, CddlError> {
    value
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| CddlError::new("expected unsigned integer"))
}
fn closed(map: &Map, keys: &[&str]) -> Result<(), CddlError> {
    if map.len() != keys.len()
        || map
            .iter()
            .any(|(k, _)| !k.as_text().is_some_and(|s| keys.contains(&s)))
    {
        return Err(CddlError::new("unexpected or missing profile field"));
    }
    Ok(())
}
fn unique_keys(value: &Value) -> Result<(), CddlError> {
    match value {
        Value::Map(entries) => {
            let mut seen = std::collections::BTreeSet::new();
            for (k, v) in entries {
                if !seen.insert(encode_canonical_cbor_value(k)?) {
                    return Err(CddlError::new("duplicate CBOR map key"));
                }
                unique_keys(k)?;
                unique_keys(v)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                unique_keys(item)?;
            }
        }
        Value::Tag(_, item) => unique_keys(item)?,
        _ => {}
    }
    Ok(())
}
fn sha(value: &Value) -> Result<[u8; 32], CddlError> {
    let s = text(value)?;
    let h = s
        .strip_prefix("sha256:")
        .ok_or_else(|| CddlError::new("invalid SHA-256 text"))?;
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CddlError::new("invalid lowercase SHA-256 text"));
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
            .map_err(|_| CddlError::new("invalid SHA-256 text"))?;
    }
    Ok(out)
}
fn identity(value: &Value) -> Result<&str, CddlError> {
    let s = text(value)?;
    if s.is_empty() || s.trim() != s || s.chars().any(char::is_control) {
        return Err(CddlError::new("invalid attachment identity"));
    }
    Ok(s)
}
fn pointer(value: &Value) -> Result<(), CddlError> {
    let s = identity(value)?;
    if !s.starts_with('/') {
        return Err(CddlError::new("slot_path must be a JSON pointer"));
    }
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return Err(CddlError::new("invalid JSON pointer escape"));
        }
    }
    Ok(())
}
fn mime(value: &Value) -> Result<(), CddlError> {
    let s = text(value)?;
    let token = |v: &str| {
        !v.is_empty()
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    let (a, b) = s
        .split_once('/')
        .ok_or_else(|| CddlError::new("invalid media type"))?;
    if !token(a) || !token(b) {
        return Err(CddlError::new("invalid media type"));
    }
    Ok(())
}

fn nullable_digest(value: &Value) -> Result<(), CddlError> {
    if !matches!(value, Value::Null) {
        fixed::<32>(value)?;
    }
    Ok(())
}
fn native_header(event: &Map) -> Result<(), CddlError> {
    if uint(field(event, "version")?)? != 1 || bytes(field(event, "ledger_scope")?)?.is_empty() {
        return Err(CddlError::new("invalid native event version or scope"));
    }
    uint(field(event, "sequence")?)?;
    nullable_digest(field(event, "prev_hash")?)?;
    let header = map(field(event, "header")?)?;
    closed(
        header,
        &[
            "event_type",
            "authored_at",
            "retention_tier",
            "classification",
            "outcome_commitment",
            "subject_ref_commitment",
            "tag_commitment",
            "witness_ref",
            "extensions",
        ],
    )?;
    for key in ["event_type", "classification"] {
        let value = bytes(field(header, key)?)?;
        if value.is_empty() || std::str::from_utf8(value).is_err() {
            return Err(CddlError::new(
                "native header identity must be nonempty UTF-8 bytes",
            ));
        }
    }
    let timestamp = field(header, "authored_at")?
        .as_array()
        .ok_or_else(|| CddlError::new("invalid authored_at timestamp"))?;
    if timestamp.len() != 2 {
        return Err(CddlError::new("invalid authored_at timestamp length"));
    }
    uint(&timestamp[0])?;
    if uint(&timestamp[1])? >= 1_000_000_000 {
        return Err(CddlError::new("invalid authored_at nanoseconds"));
    }
    if uint(field(header, "retention_tier")?)? > 3 {
        return Err(CddlError::new("invalid retention tier"));
    }
    for key in [
        "outcome_commitment",
        "subject_ref_commitment",
        "tag_commitment",
    ] {
        nullable_digest(field(header, key)?)?;
    }
    match field(header, "witness_ref")? {
        Value::Null | Value::Bytes(_) => {}
        _ => return Err(CddlError::new("invalid witness reference")),
    }
    match field(header, "extensions")? {
        Value::Null => {}
        value => {
            if map(value)?.iter().any(|(key, _)| key.as_text().is_none()) {
                return Err(CddlError::new("header extension keys must be text"));
            }
        }
    }
    Ok(())
}

/// Parses explicitly profiled external attachments without authenticating their signatures.
///
/// Unmarked historical events return `None` and retain their existing interpretation.
/// Authored and canonical event maps are accepted. A present marker must select this exact
/// profile. Input must be canonical CBOR and contain no duplicate keys at any depth.
///
/// # Errors
/// Returns an error for malformed CBOR or incomplete, unknown, or inconsistent profile fields.
pub fn parse_external_attachment_profile(
    bytes_in: &[u8],
) -> Result<Option<ParsedExternalAttachment>, CddlError> {
    let value: Value = ciborium::from_reader(bytes_in)
        .map_err(|e| CddlError::new(format!("invalid external attachment CBOR: {e}")))?;
    unique_keys(&value)?;
    if encode_canonical_cbor_value(&value)? != bytes_in {
        return Err(CddlError::new("noncanonical external attachment CBOR"));
    }
    let event = map(&value)?;
    let extensions = match optional(event, "extensions") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => map(v)?,
    };
    let Some(marker) = optional(extensions, PROFILE_EXTENSION) else {
        return Ok(None);
    };
    if text(marker)? != EXTERNAL_ATTACHMENT_PROFILE {
        return Err(CddlError::new(
            "unknown external attachment protection profile",
        ));
    }
    native_header(event)?;
    let content_hash = fixed::<32>(field(event, "content_hash")?)?;
    let idempotency_key = bytes(field(event, "idempotency_key")?)?.to_vec();
    if !idempotency_key_length_in_bound(&idempotency_key) {
        return Err(CddlError::new("idempotency key length invalid"));
    }
    let reference = map(field(event, "payload_ref")?)?;
    closed(
        reference,
        &["ref_type", "content_hash", "availability", "retrieval_hint"],
    )?;
    if text(field(reference, "ref_type")?)? != "external"
        || fixed::<32>(field(reference, "content_hash")?)? != content_hash
        || uint(field(reference, "availability")?)? != 0
        || !matches!(field(reference, "retrieval_hint")?, Value::Null)
    {
        return Err(CddlError::new(
            "profile requires matching external InExport payload reference",
        ));
    }
    let binding = map(field(extensions, BINDING_EXTENSION)?)?;
    closed(
        binding,
        &[
            "attachment_id",
            "slot_path",
            "media_type",
            "byte_length",
            "attachment_sha256",
            "payload_content_hash",
            "filename",
            "prior_binding_hash",
        ],
    )?;
    identity(field(binding, "attachment_id")?)?;
    pointer(field(binding, "slot_path")?)?;
    mime(field(binding, "media_type")?)?;
    let original_byte_length = uint(field(binding, "byte_length")?)?;
    if original_byte_length == 0 {
        return Err(CddlError::new("empty original attachment"));
    }
    let original_sha256 = sha(field(binding, "attachment_sha256")?)?;
    if sha(field(binding, "payload_content_hash")?)? != content_hash {
        return Err(CddlError::new("binding ciphertext hash mismatch"));
    }
    match field(binding, "filename")? {
        Value::Null | Value::Text(_) => {}
        _ => return Err(CddlError::new("invalid filename")),
    }
    match field(binding, "prior_binding_hash")? {
        Value::Null => {}
        v => {
            sha(v)?;
        }
    }
    let bag = map(field(event, "key_bag")?)?;
    closed(bag, &["entries"])?;
    let entries = field(bag, "entries")?
        .as_array()
        .ok_or_else(|| CddlError::new("key bag entries must be an array"))?;
    if entries.is_empty() {
        return Err(CddlError::new("profile requires recipient wraps"));
    }
    let mut recipients = std::collections::BTreeSet::new();
    let mut ephemerals = std::collections::BTreeSet::new();
    let mut key_bag_entries = Vec::with_capacity(entries.len());
    for value in entries {
        let entry = map(value)?;
        closed(
            entry,
            &["recipient", "suite", "ephemeral_pubkey", "wrapped_dek"],
        )?;
        let recipient = bytes(field(entry, "recipient")?)?.to_vec();
        let ephemeral_pubkey = fixed::<32>(field(entry, "ephemeral_pubkey")?)?;
        if recipient.is_empty()
            || uint(field(entry, "suite")?)? != 1
            || !recipients.insert(recipient.clone())
            || !ephemerals.insert(ephemeral_pubkey)
        {
            return Err(CddlError::new(
                "invalid or duplicate suite 1 recipient wrap",
            ));
        }
        key_bag_entries.push(ParsedExternalAttachmentWrap {
            recipient,
            ephemeral_pubkey,
            wrapped_dek: fixed::<48>(field(entry, "wrapped_dek")?)?,
        });
    }
    Ok(Some(ParsedExternalAttachment {
        original_sha256,
        original_byte_length,
        idempotency_key,
        content_hash,
        key_bag_entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }
    fn m(fields: Vec<(&str, Value)>) -> Value {
        Value::Map(fields.into_iter().map(|(k, v)| (t(k), v)).collect())
    }
    fn hash() -> Value {
        t(&format!("sha256:{}", "08".repeat(32)))
    }
    fn event() -> Value {
        m(vec![
            ("version", Value::Integer(1.into())),
            ("ledger_scope", Value::Bytes(b"scope".to_vec())),
            ("sequence", Value::Integer(0.into())),
            ("prev_hash", Value::Null),
            (
                "header",
                m(vec![
                    (
                        "event_type",
                        Value::Bytes(b"substrate.append.accepted_attachment_binding".to_vec()),
                    ),
                    ("classification", Value::Bytes(b"service_only".to_vec())),
                    (
                        "authored_at",
                        Value::Array(vec![Value::Integer(1.into()), Value::Integer(0.into())]),
                    ),
                    ("retention_tier", Value::Integer(1.into())),
                    ("outcome_commitment", Value::Null),
                    ("subject_ref_commitment", Value::Null),
                    ("tag_commitment", Value::Null),
                    ("witness_ref", Value::Null),
                    ("extensions", Value::Null),
                ]),
            ),
            ("content_hash", Value::Bytes(vec![8; 32])),
            ("idempotency_key", Value::Bytes(vec![1])),
            (
                "payload_ref",
                m(vec![
                    ("ref_type", t("external")),
                    ("content_hash", Value::Bytes(vec![8; 32])),
                    ("availability", Value::Integer(0.into())),
                    ("retrieval_hint", Value::Null),
                ]),
            ),
            (
                "key_bag",
                m(vec![(
                    "entries",
                    Value::Array(vec![m(vec![
                        ("recipient", Value::Bytes(vec![1])),
                        ("suite", Value::Integer(1.into())),
                        ("ephemeral_pubkey", Value::Bytes(vec![3; 32])),
                        ("wrapped_dek", Value::Bytes(vec![4; 48])),
                    ])]),
                )]),
            ),
            (
                "extensions",
                m(vec![
                    (PROFILE_EXTENSION, t(EXTERNAL_ATTACHMENT_PROFILE)),
                    (
                        BINDING_EXTENSION,
                        m(vec![
                            ("attachment_id", t("logical")),
                            ("slot_path", t("/file")),
                            ("media_type", t("image/jpeg")),
                            ("byte_length", Value::Integer(4.into())),
                            ("attachment_sha256", hash()),
                            ("payload_content_hash", hash()),
                            ("filename", Value::Null),
                            ("prior_binding_hash", Value::Null),
                        ]),
                    ),
                ]),
            ),
        ])
    }
    fn set(value: &mut Value, key: &str, replacement: Value) {
        let Value::Map(fields) = value else {
            panic!("map");
        };
        fields
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap()
            .1 = replacement;
    }
    fn child<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
        let Value::Map(fields) = value else {
            panic!("map");
        };
        &mut fields
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap()
            .1
    }
    fn parse(value: &Value) -> Result<Option<ParsedExternalAttachment>, CddlError> {
        parse_external_attachment_profile(&encode_canonical_cbor_value(value).unwrap())
    }
    #[test]
    fn accepts_profile_and_preserves_decoding_inputs() {
        let parsed = parse(&event()).unwrap().unwrap();
        assert_eq!(parsed.original_sha256, [8; 32]);
        assert_eq!(parsed.original_byte_length, 4);
        assert_eq!(parsed.key_bag_entries[0].wrapped_dek, [4; 48]);
    }
    #[test]
    fn historical_unmarked_event_keeps_existing_interpretation() {
        let mut e = event();
        set(&mut e, "extensions", Value::Null);
        assert!(parse(&e).unwrap().is_none());
        set(&mut e, "extensions", m(vec![("unrelated", Value::Null)]));
        assert!(parse(&e).unwrap().is_none());
    }
    #[test]
    fn rejects_unknown_marker_and_missing_binding() {
        let mut e = event();
        set(child(&mut e, "extensions"), PROFILE_EXTENSION, t("unknown"));
        assert!(parse(&e).is_err());
        set(
            &mut e,
            "extensions",
            m(vec![(PROFILE_EXTENSION, t(EXTERNAL_ATTACHMENT_PROFILE))]),
        );
        assert!(parse(&e).is_err());
    }
    #[test]
    fn rejects_inline_and_mismatched_hash() {
        let mut e = event();
        set(child(&mut e, "payload_ref"), "ref_type", t("inline"));
        assert!(parse(&e).is_err());
        let mut e = event();
        set(
            child(&mut e, "payload_ref"),
            "content_hash",
            Value::Bytes(vec![7; 32]),
        );
        assert!(parse(&e).is_err());
        let mut e = event();
        set(
            child(child(&mut e, "extensions"), BINDING_EXTENSION),
            "attachment_sha256",
            t(&format!("sha256:{}", "AB".repeat(32))),
        );
        assert!(parse(&e).is_err());
    }
    #[test]
    fn rejects_recursive_duplicate_keys_and_noncanonical_encoding() {
        let mut e = event();
        let Value::Map(fields) = child(&mut e, "payload_ref") else {
            panic!("map");
        };
        fields.push((t("ref_type"), t("external")));
        let bytes = trellis_types::encode_cbor_value(&e).unwrap();
        assert!(parse_external_attachment_profile(&bytes).is_err());
        let bytes = trellis_types::encode_cbor_value(&event()).unwrap();
        assert!(parse_external_attachment_profile(&bytes).is_err());
    }
    #[test]
    fn rejects_empty_key_bag_and_extra_reference_fields() {
        let mut e = event();
        set(child(&mut e, "key_bag"), "entries", Value::Array(vec![]));
        assert!(parse(&e).is_err());
        let mut e = event();
        let Value::Map(fields) = child(&mut e, "payload_ref") else {
            panic!("map");
        };
        fields.push((t("nonce"), Value::Bytes(vec![0; 12])));
        assert!(parse(&e).is_err());
    }
    #[test]
    fn rejects_duplicate_wraps_wrong_suite_and_bad_wrapped_key_length() {
        for kind in ["recipient", "ephemeral", "suite", "wrapped_dek"] {
            let mut e = event();
            let Value::Array(entries) = child(child(&mut e, "key_bag"), "entries") else {
                panic!("array");
            };
            let mut second = entries[0].clone();
            match kind {
                "recipient" => set(&mut second, "ephemeral_pubkey", Value::Bytes(vec![9; 32])),
                "ephemeral" => set(&mut second, "recipient", Value::Bytes(vec![9])),
                "suite" => {
                    set(&mut entries[0], "suite", Value::Integer(2.into()));
                }
                "wrapped_dek" => {
                    set(&mut entries[0], "wrapped_dek", Value::Bytes(vec![4; 32]));
                }
                _ => unreachable!(),
            }
            if matches!(kind, "recipient" | "ephemeral") {
                entries.push(second);
            }
            assert!(parse(&e).is_err(), "accepted invalid {kind}");
        }
    }
    #[test]
    fn rejects_invalid_pointer_and_event_identity() {
        let mut e = event();
        set(
            child(child(&mut e, "extensions"), BINDING_EXTENSION),
            "slot_path",
            t("/file~2"),
        );
        assert!(parse(&e).is_err());
        for len in [0, 65] {
            let mut e = event();
            set(&mut e, "idempotency_key", Value::Bytes(vec![1; len]));
            assert!(parse(&e).is_err());
        }
    }
    #[test]
    fn rejects_malformed_native_header_and_root_fields() {
        for (key, value) in [
            ("version", Value::Integer(2.into())),
            ("ledger_scope", Value::Bytes(vec![])),
            ("sequence", t("zero")),
            ("prev_hash", Value::Bytes(vec![1; 31])),
        ] {
            let mut e = event();
            set(&mut e, key, value);
            assert!(parse(&e).is_err(), "accepted {key}");
        }
        for (key, value) in [
            ("event_type", Value::Bytes(vec![255])),
            ("classification", Value::Bytes(vec![])),
            (
                "authored_at",
                Value::Array(vec![
                    Value::Integer(1.into()),
                    Value::Integer(1_000_000_000.into()),
                ]),
            ),
            ("retention_tier", Value::Integer(4.into())),
            ("outcome_commitment", Value::Bytes(vec![1; 31])),
            ("witness_ref", t("invalid")),
            ("extensions", m(vec![])),
        ] {
            let mut e = event();
            set(child(&mut e, "header"), key, value);
            if key == "extensions" {
                assert!(parse(&e).is_ok());
            } else {
                assert!(parse(&e).is_err(), "accepted {key}");
            }
        }
        let mut e = event();
        let Value::Map(fields) = child(&mut e, "header") else {
            panic!("map");
        };
        fields.push((t("extra"), Value::Null));
        assert!(parse(&e).is_err());
    }
}
