//! Binds protected Response codec facts without conferring Source signature authority.

use super::{ParseError, bytes_array, cbor_nested_map_semantic_eq};
use ciborium::Value;
use trellis_types::{
    map_lookup_bytes, map_lookup_fixed_bytes, map_lookup_map, map_lookup_optional_value,
    map_lookup_text, map_lookup_u64,
};

// Match the existing bounded WOS signed Response qualification, not an unbounded blob API.
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_PROTECTION_METADATA_BYTES: usize = 64 * 1024;
// The maintained external-attachment protection profile adds a 16-byte AEAD tag.
const PROTECTION_TAG_BYTES: u64 = 16;
const LOCATOR_FIELDS: &[&str] = &[
    "version",
    "native_event_hash",
    "response_ref",
    "response_id",
    "response_hash",
    "original_byte_length",
    "content_hash",
    "context_key",
    "record_hash",
    "source_binding_hash",
    "publication_hash",
    "public_policy_hash",
    "recipient_policy_hash",
    "nonce",
    "key_bag",
];

/// Closed catalog reference to one retained protected Response occurrence.
#[derive(Clone, Debug)]
pub(crate) struct ProtectedResponseLocator {
    pub(crate) native_event_hash: [u8; 32],
    pub(crate) response_ref: String,
    pub(crate) response_id: String,
    pub(crate) response_hash: String,
    pub(crate) original_byte_length: u64,
    pub(crate) content_hash: [u8; 32],
    pub(crate) context_key: Vec<u8>,
    pub(crate) record_hash: [u8; 32],
    pub(crate) source_binding_hash: [u8; 32],
    pub(crate) publication_hash: [u8; 32],
    pub(crate) public_policy_hash: [u8; 32],
    pub(crate) recipient_policy_hash: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) key_bag: Value,
}

pub(crate) fn parse_protected_response(
    value: &Value,
) -> Result<ProtectedResponseLocator, ParseError> {
    let map = value
        .as_map()
        .ok_or("protected Response locator must be a map")?;
    closed_fields(map, LOCATOR_FIELDS)?;
    if map_lookup_u64(map, "version")? != 1 {
        return Err("protected Response locator version is unsupported".into());
    }
    let response_ref = map_lookup_text(map, "response_ref")?;
    let response_id = map_lookup_text(map, "response_id")?;
    let response_hash = map_lookup_text(map, "response_hash")?;
    super::parse_sha256_text(&response_hash)?;
    let length = map_lookup_u64(map, "original_byte_length")?;
    let context_key = map_lookup_bytes(map, "context_key")?;
    if response_id.trim().is_empty()
        || response_id.len() > 1024
        || response_ref.trim().is_empty()
        || response_ref.len() > 1024
        || length == 0
        || length > MAX_RESPONSE_BYTES as u64
        || !trellis_types::idempotency_key_length_in_bound(&context_key)
    {
        return Err("protected Response identity or bound is invalid".into());
    }
    let nonce = map_lookup_fixed_bytes(map, "nonce", 12)?;
    let mut nonce_array = [0; 12];
    nonce_array.copy_from_slice(&nonce);
    let key_bag = map_lookup_optional_value(map, "key_bag")
        .ok_or("protected Response key bag absent")?
        .clone();
    if key_bag.as_map().is_none()
        || trellis_types::encode_canonical_cbor_value(&key_bag)?.len()
            > MAX_PROTECTION_METADATA_BYTES
    {
        return Err("protected Response key bag codec is invalid".into());
    }
    let digest = |name| -> Result<[u8; 32], ParseError> {
        Ok(bytes_array(&map_lookup_fixed_bytes(map, name, 32)?))
    };
    Ok(ProtectedResponseLocator {
        native_event_hash: digest("native_event_hash")?,
        response_ref,
        response_id,
        response_hash,
        original_byte_length: length,
        content_hash: digest("content_hash")?,
        context_key,
        record_hash: digest("record_hash")?,
        source_binding_hash: digest("source_binding_hash")?,
        publication_hash: digest("publication_hash")?,
        public_policy_hash: digest("public_policy_hash")?,
        recipient_policy_hash: digest("recipient_policy_hash")?,
        nonce: nonce_array,
        key_bag,
    })
}

fn closed_fields(map: &[(Value, Value)], allowed: &[&str]) -> Result<(), ParseError> {
    let mut seen = std::collections::BTreeSet::new();
    for (key, _) in map {
        let key = key
            .as_text()
            .ok_or("protected Response field must be text")?;
        if !allowed.contains(&key) || !seen.insert(key) {
            return Err("protected Response field is unknown or duplicate".into());
        }
    }
    if seen.len() != allowed.len() {
        return Err("protected Response field is missing".into());
    }
    Ok(())
}

/// Independently selected identity and policy digests, never copied from a catalog.
#[derive(Clone)]
pub(crate) struct ResponseBindingPins {
    pub(crate) native_event_hash: [u8; 32],
    pub(crate) response_ref: String,
    pub(crate) response_id: String,
    pub(crate) response_hash: String,
    pub(crate) context_key: Vec<u8>,
    pub(crate) record_hash: [u8; 32],
    pub(crate) source_binding_hash: [u8; 32],
    pub(crate) publication_hash: [u8; 32],
    pub(crate) public_policy_hash: [u8; 32],
    pub(crate) recipient_policy_hash: [u8; 32],
}

/// Holds structurally joined bytes; it grants no decryption or signature authority.
pub(crate) struct CodecBoundResponse {
    pub(crate) response: serde_json::Value,
}

/// Checks exact record, ciphertext, identity, policy pins and complete Response bytes.
///
/// The caller must separately authenticate decryption and Source signature/publication.
/// This codec result cannot establish full-record readiness.
/// # Errors
/// Refuses substituted metadata, record/body hashes, lengths, response identity or JSON.
pub(crate) fn bind_opened_response(
    locator: &ProtectedResponseLocator,
    pins: &ResponseBindingPins,
    record: &[u8],
    opened: &[u8],
) -> Result<CodecBoundResponse, ParseError> {
    if locator.native_event_hash != pins.native_event_hash
        || locator.response_ref != pins.response_ref
        || locator.response_id != pins.response_id
        || locator.response_hash != pins.response_hash
        || locator.context_key != pins.context_key
        || locator.record_hash != pins.record_hash
        || locator.source_binding_hash != pins.source_binding_hash
        || locator.publication_hash != pins.publication_hash
        || locator.public_policy_hash != pins.public_policy_hash
        || locator.recipient_policy_hash != pins.recipient_policy_hash
    {
        return Err("protected Response independent binding differs".into());
    }
    let _ciphertext = validated_record_ciphertext(locator, record)?;
    if opened.len() as u64 != locator.original_byte_length
        || !super::response_hash_matches(&locator.response_hash, opened)?
    {
        return Err("protected Response opened bytes differ".into());
    }
    let response: serde_json::Value = serde_json::from_slice(opened)
        .map_err(|_| ParseError::from("protected Response JSON is invalid"))?;
    if !response.is_object()
        || response.get("id").and_then(serde_json::Value::as_str)
            != Some(locator.response_id.as_str())
    {
        return Err("protected Response full identity differs".into());
    }
    Ok(CodecBoundResponse { response })
}

impl ProtectedResponseLocator {
    /// Encodes owning locator fields using the maintained canonical CBOR writer.
    pub(crate) fn to_value(&self, include_record_hash: bool) -> Value {
        let mut rows = vec![
            ("version", Value::Integer(1.into())),
            (
                "native_event_hash",
                Value::Bytes(self.native_event_hash.to_vec()),
            ),
            ("response_ref", Value::Text(self.response_ref.clone())),
            ("response_id", Value::Text(self.response_id.clone())),
            ("response_hash", Value::Text(self.response_hash.clone())),
            (
                "original_byte_length",
                Value::Integer(self.original_byte_length.into()),
            ),
            ("content_hash", Value::Bytes(self.content_hash.to_vec())),
            ("context_key", Value::Bytes(self.context_key.clone())),
            (
                "source_binding_hash",
                Value::Bytes(self.source_binding_hash.to_vec()),
            ),
            (
                "publication_hash",
                Value::Bytes(self.publication_hash.to_vec()),
            ),
            (
                "public_policy_hash",
                Value::Bytes(self.public_policy_hash.to_vec()),
            ),
            (
                "recipient_policy_hash",
                Value::Bytes(self.recipient_policy_hash.to_vec()),
            ),
            ("nonce", Value::Bytes(self.nonce.to_vec())),
            ("key_bag", self.key_bag.clone()),
        ];
        if include_record_hash {
            rows.push(("record_hash", Value::Bytes(self.record_hash.to_vec())));
        }
        Value::Map(
            rows.into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }
}

fn validated_record_ciphertext(
    locator: &ProtectedResponseLocator,
    record: &[u8],
) -> Result<Vec<u8>, ParseError> {
    if record.len() > MAX_RESPONSE_BYTES + MAX_PROTECTION_METADATA_BYTES
        || trellis_types::sha256_bytes(record) != locator.record_hash
    {
        return Err("protected Response retained record differs".into());
    }
    let value = trellis_types::decode_cbor_value(record)?;
    let map = value
        .as_map()
        .ok_or("protected Response record must be a map")?;
    closed_fields(map, &["locator", "ciphertext"])?;
    let metadata = map_lookup_map(map, "locator")?;
    if metadata
        .iter()
        .any(|(key, _)| key.as_text() == Some("record_hash"))
    {
        return Err("protected Response record contains its own hash".into());
    }
    let mut with_hash = metadata.to_vec();
    with_hash.push((
        Value::Text("record_hash".into()),
        Value::Bytes(locator.record_hash.to_vec()),
    ));
    let actual = parse_protected_response(&Value::Map(with_hash))?;
    if !cbor_nested_map_semantic_eq(&locator.to_value(false), &actual.to_value(false)) {
        return Err("protected Response record metadata differs".into());
    }
    let ciphertext = map_lookup_bytes(map, "ciphertext")?;
    if trellis_types::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &ciphertext)
        != locator.content_hash
        || ciphertext.len() as u64
            != locator
                .original_byte_length
                .checked_add(PROTECTION_TAG_BYTES)
                .ok_or("protected Response length overflow")?
    {
        return Err("protected Response ciphertext differs".into());
    }
    Ok(ciphertext)
}

/// Validated encrypted Response metadata; this grants no read or Source authority.
///
/// The selected reader must independently admit recipient, source and publication
/// bindings before opening. This view reuses the owning closed codec unchanged.
pub struct ProtectedResponseOpeningV1 {
    locator: ProtectedResponseLocator,
    ciphertext: Vec<u8>,
}
impl ProtectedResponseOpeningV1 {
    pub(crate) fn from_record(
        locator: &ProtectedResponseLocator,
        record: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(Self {
            locator: locator.clone(),
            ciphertext: validated_record_ciphertext(locator, record)?,
        })
    }
    /// Returns the exact encrypted body after record and content hash validation.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// Returns the bound original byte length.
    pub fn original_byte_length(&self) -> u64 {
        self.locator.original_byte_length
    }
    /// Returns the complete original Response digest.
    pub fn response_hash(&self) -> &str {
        &self.locator.response_hash
    }
    /// Returns the existing protection context key.
    pub fn context_key(&self) -> &[u8] {
        &self.locator.context_key
    }
    /// Returns the maintained protection nonce.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.locator.nonce
    }
    /// Returns the encrypted content digest.
    pub fn content_hash(&self) -> [u8; 32] {
        self.locator.content_hash
    }
    /// Returns the retained whole record digest.
    pub fn record_hash(&self) -> [u8; 32] {
        self.locator.record_hash
    }
    /// Returns the independently admitted recipient policy digest to compare.
    pub fn recipient_policy_hash(&self) -> [u8; 32] {
        self.locator.recipient_policy_hash
    }
    /// Returns the bound Source identity digest to compare.
    pub fn source_binding_hash(&self) -> [u8; 32] {
        self.locator.source_binding_hash
    }
    /// Returns the bound publication digest to compare.
    pub fn publication_hash(&self) -> [u8; 32] {
        self.locator.publication_hash
    }
    /// Returns the bound public signing policy digest to compare.
    pub fn public_policy_hash(&self) -> [u8; 32] {
        self.locator.public_policy_hash
    }
    /// Returns the existing recipient wraps as canonical CBOR.
    /// # Errors
    /// Refuses encoding failure; no permission is inferred from these public wraps.
    pub fn key_bag_cbor(&self) -> Result<Vec<u8>, String> {
        trellis_types::encode_canonical_cbor_value(&self.locator.key_bag)
            .map_err(|_| "protected Response key bag encode refused".into())
    }
}
