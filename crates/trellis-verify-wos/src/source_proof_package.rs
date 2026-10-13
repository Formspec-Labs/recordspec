//! Checks closed protected proof-package metadata without granting Source authority.
// Rust guideline compliant 2026-02-21
use ciborium::Value;
use trellis_types::{
    decode_cbor_value, encode_canonical_cbor_value, map_lookup_bytes, map_lookup_fixed_bytes,
    map_lookup_text, map_lookup_u64, sha256_bytes,
};

const MAX_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const FIELDS: &[&str] = &[
    "version",
    "family",
    "task_completed_event_hash",
    "package_sha256",
    "witness_sha256",
    "original_byte_length",
    "content_hash",
    "context_key",
    "record_hash",
    "source_binding_hash",
    "current_publication_hash",
    "original_publication_hash",
    "public_policy_hash",
    "recipient_policy_hash",
    "nonce",
    "key_bag",
];

fn closed(map: &[(Value, Value)], fields: &[&str]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for (key, _) in map {
        let key = key.as_text().ok_or("proof-package field must be text")?;
        if !fields.contains(&key) || !seen.insert(key) {
            return Err("proof-package unknown or duplicate field".into());
        }
    }
    if seen.len() != fields.len() {
        return Err("proof-package missing field".into());
    }
    Ok(())
}
fn map(rows: Vec<(&str, Value)>) -> Value {
    Value::Map(
        rows.into_iter()
            .map(|(key, value)| (Value::Text(key.into()), value))
            .collect(),
    )
}
fn digest(fields: &[(Value, Value)], key: &str) -> Result<[u8; 32], String> {
    map_lookup_fixed_bytes(fields, key, 32)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "proof-package digest size".into())
}
fn key_bag(value: &Value) -> Result<(), String> {
    let fields = value.as_map().ok_or("proof-package key bag must be map")?;
    closed(fields, &["entries"])?;
    let entries = fields[0]
        .1
        .as_array()
        .ok_or("proof-package wraps must be array")?;
    if entries.is_empty() || entries.len() > 64 {
        return Err("proof-package wrap count".into());
    }
    let mut recipients = std::collections::BTreeSet::new();
    for entry in entries {
        let fields = entry.as_map().ok_or("proof-package wrap must be map")?;
        closed(
            fields,
            &["recipient", "suite", "ephemeral_pubkey", "wrapped_dek"],
        )?;
        let recipient = map_lookup_bytes(fields, "recipient").map_err(|e| e.to_string())?;
        if recipient.is_empty()
            || recipient.len() > 256
            || !recipients.insert(recipient)
            || map_lookup_u64(fields, "suite").map_err(|e| e.to_string())? != 1
            || map_lookup_bytes(fields, "ephemeral_pubkey")
                .map_err(|e| e.to_string())?
                .len()
                != 32
            || map_lookup_bytes(fields, "wrapped_dek")
                .map_err(|e| e.to_string())?
                .len()
                != 48
        {
            return Err("proof-package wrap invalid".into());
        }
    }
    if encode_canonical_cbor_value(value)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_METADATA_BYTES
    {
        return Err("proof-package key bag bound".into());
    }
    Ok(())
}

/// Closed public locator; its fields confer no authority or plaintext possession.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtectedSourceProofPackageLocatorV1 {
    pub family: String,
    pub task_completed_event_hash: [u8; 32],
    pub package_sha256: [u8; 32],
    pub witness_sha256: [u8; 32],
    pub original_byte_length: u64,
    pub content_hash: [u8; 32],
    pub context_key: Vec<u8>,
    pub record_hash: [u8; 32],
    pub source_binding_hash: [u8; 32],
    pub current_publication_hash: [u8; 32],
    pub original_publication_hash: [u8; 32],
    pub public_policy_hash: [u8; 32],
    pub recipient_policy_hash: [u8; 32],
    pub nonce: [u8; 12],
    pub key_bag: Value,
}
impl ProtectedSourceProofPackageLocatorV1 {
    /// Parses exact closed locator fields within the protection metadata bound.
    /// # Errors
    /// Refuses unsupported family, malformed fields, wraps, or codec limits.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err("proof-package locator byte bound".into());
        }
        let value = decode_cbor_value(bytes).map_err(|e| e.to_string())?;
        if encode_canonical_cbor_value(&value).map_err(|e| e.to_string())? != bytes {
            return Err("proof-package locator or context join not canonical".into());
        }
        Self::from_value(&value)
    }
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let fields = value.as_map().ok_or("proof-package locator must be map")?;
        closed(fields, FIELDS)?;
        if map_lookup_u64(fields, "version").map_err(|e| e.to_string())? != 1 {
            return Err("proof-package version unsupported".into());
        }
        let key_bag = fields
            .iter()
            .find(|(k, _)| k.as_text() == Some("key_bag"))
            .unwrap()
            .1
            .clone();
        let result = Self {
            family: map_lookup_text(fields, "family").map_err(|e| e.to_string())?,
            task_completed_event_hash: digest(fields, "task_completed_event_hash")?,
            package_sha256: digest(fields, "package_sha256")?,
            witness_sha256: digest(fields, "witness_sha256")?,
            original_byte_length: map_lookup_u64(fields, "original_byte_length")
                .map_err(|e| e.to_string())?,
            content_hash: digest(fields, "content_hash")?,
            context_key: map_lookup_bytes(fields, "context_key").map_err(|e| e.to_string())?,
            record_hash: digest(fields, "record_hash")?,
            source_binding_hash: digest(fields, "source_binding_hash")?,
            current_publication_hash: digest(fields, "current_publication_hash")?,
            original_publication_hash: digest(fields, "original_publication_hash")?,
            public_policy_hash: digest(fields, "public_policy_hash")?,
            recipient_policy_hash: digest(fields, "recipient_policy_hash")?,
            nonce: map_lookup_fixed_bytes(fields, "nonce", 12)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "proof-package nonce size")?,
            key_bag,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), String> {
        if self.family != "mixed-v2"
            || self.original_byte_length == 0
            || self.original_byte_length > MAX_PACKAGE_BYTES as u64
            || !trellis_types::idempotency_key_length_in_bound(&self.context_key)
        {
            return Err("proof-package family or content bound unsupported".into());
        }
        key_bag(&self.key_bag)
    }
    pub(crate) fn value(&self, include_record_hash: bool) -> Value {
        let b = |h: [u8; 32]| Value::Bytes(h.to_vec());
        let mut rows = vec![
            ("version", Value::Integer(1.into())),
            ("family", Value::Text(self.family.clone())),
            (
                "task_completed_event_hash",
                b(self.task_completed_event_hash),
            ),
            ("package_sha256", b(self.package_sha256)),
            ("witness_sha256", b(self.witness_sha256)),
            (
                "original_byte_length",
                Value::Integer(self.original_byte_length.into()),
            ),
            ("content_hash", b(self.content_hash)),
            ("context_key", Value::Bytes(self.context_key.clone())),
            ("source_binding_hash", b(self.source_binding_hash)),
            ("current_publication_hash", b(self.current_publication_hash)),
            (
                "original_publication_hash",
                b(self.original_publication_hash),
            ),
            ("public_policy_hash", b(self.public_policy_hash)),
            ("recipient_policy_hash", b(self.recipient_policy_hash)),
            ("nonce", Value::Bytes(self.nonce.to_vec())),
            ("key_bag", self.key_bag.clone()),
        ];
        if include_record_hash {
            rows.push(("record_hash", b(self.record_hash)));
        }
        map(rows)
    }
    /// Encodes the complete validated catalog locator.
    /// # Errors
    /// Refuses unsupported metadata, bounds or CBOR encoding.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        encode_canonical_cbor_value(&self.value(true)).map_err(|e| e.to_string())
    }
    /// Encodes record metadata without its self-referential record hash.
    /// # Errors
    /// Refuses unsupported metadata, bounds or CBOR encoding.
    pub fn to_record_locator_cbor(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        encode_canonical_cbor_value(&self.value(false)).map_err(|e| e.to_string())
    }
    pub(crate) fn opening(
        &self,
        record: &[u8],
    ) -> Result<ProtectedSourceProofPackageOpeningV1, String> {
        self.validate()?;
        if record.len() > MAX_PACKAGE_BYTES + MAX_METADATA_BYTES + 16
            || sha256_bytes(record) != self.record_hash
        {
            return Err("proof-package record differs".into());
        }
        let value = decode_cbor_value(record).map_err(|e| e.to_string())?;
        if encode_canonical_cbor_value(&value).map_err(|e| e.to_string())? != record {
            return Err("proof-package record not canonical".into());
        }
        let fields = value.as_map().ok_or("proof-package record must be map")?;
        closed(fields, &["locator", "ciphertext"])?;
        let metadata = fields
            .iter()
            .find(|(k, _)| k.as_text() == Some("locator"))
            .unwrap()
            .1
            .clone();
        if encode_canonical_cbor_value(&metadata).map_err(|e| e.to_string())?
            != self.to_record_locator_cbor()?
        {
            return Err("proof-package record metadata differs".into());
        }
        let ciphertext = map_lookup_bytes(fields, "ciphertext").map_err(|e| e.to_string())?;
        if ciphertext.len() as u64 != self.original_byte_length + 16
            || trellis_types::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &ciphertext)
                != self.content_hash
        {
            return Err("proof-package ciphertext differs".into());
        }
        Ok(ProtectedSourceProofPackageOpeningV1 {
            locator: self.clone(),
            ciphertext,
        })
    }
}

/// Exact retained encrypted package metadata; opening grants no Source authority.
pub struct ProtectedSourceProofPackageOpeningV1 {
    locator: ProtectedSourceProofPackageLocatorV1,
    ciphertext: Vec<u8>,
}
impl ProtectedSourceProofPackageOpeningV1 {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn original_byte_length(&self) -> u64 {
        self.locator.original_byte_length
    }
    pub fn package_sha256(&self) -> [u8; 32] {
        self.locator.package_sha256
    }
    pub fn witness_sha256(&self) -> [u8; 32] {
        self.locator.witness_sha256
    }
    pub fn task_completed_event_hash(&self) -> [u8; 32] {
        self.locator.task_completed_event_hash
    }
    pub fn context_key(&self) -> &[u8] {
        &self.locator.context_key
    }
    pub fn nonce(&self) -> &[u8; 12] {
        &self.locator.nonce
    }
    pub fn content_hash(&self) -> [u8; 32] {
        self.locator.content_hash
    }
    pub fn record_hash(&self) -> [u8; 32] {
        self.locator.record_hash
    }
    pub fn source_binding_hash(&self) -> [u8; 32] {
        self.locator.source_binding_hash
    }
    pub fn current_publication_hash(&self) -> [u8; 32] {
        self.locator.current_publication_hash
    }
    pub fn original_publication_hash(&self) -> [u8; 32] {
        self.locator.original_publication_hash
    }
    pub fn public_policy_hash(&self) -> [u8; 32] {
        self.locator.public_policy_hash
    }
    pub fn recipient_policy_hash(&self) -> [u8; 32] {
        self.locator.recipient_policy_hash
    }
    /// Returns canonical maintained HPKE wraps for the independently authorized reader.
    /// # Errors
    /// Refuses CBOR encoding failure.
    pub fn key_bag_cbor(&self) -> Result<Vec<u8>, String> {
        encode_canonical_cbor_value(&self.locator.key_bag).map_err(|e| e.to_string())
    }
    /// Checks exact opened bytes before the owning typed Source package decoder.
    /// # Errors
    /// Refuses substituted plaintext or length; this result grants no read authority.
    pub fn validate_opened_bytes(&self, opened: &[u8]) -> Result<(), String> {
        if opened.len() as u64 != self.original_byte_length()
            || sha256_bytes(opened) != self.package_sha256()
        {
            return Err("proof-package opened bytes differ".into());
        }
        Ok(())
    }
}

/// Exact catalog join to an original context retained by the owning MIXED loader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalContextProofV1 {
    pub task_completed_event_hash: [u8; 32],
    pub package_record_hash: [u8; 32],
    pub context_instance: String,
}
impl OriginalContextProofV1 {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let fields = value.as_map().ok_or("original context proof must be map")?;
        closed(
            fields,
            &[
                "task_completed_event_hash",
                "package_record_hash",
                "context_instance",
            ],
        )?;
        let context_instance =
            map_lookup_text(fields, "context_instance").map_err(|e| e.to_string())?;
        if context_instance.trim().is_empty()
            || context_instance.len() > 1024
            || context_instance.chars().any(char::is_control)
        {
            return Err("original context instance invalid".into());
        }
        Ok(Self {
            task_completed_event_hash: digest(fields, "task_completed_event_hash")?,
            package_record_hash: digest(fields, "package_record_hash")?,
            context_instance,
        })
    }
    /// Parses the closed context join without inventing an original task anchor.
    /// # Errors
    /// Refuses malformed fields, unsupported bounds or CBOR encoding.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 2048 {
            return Err("original context proof byte bound".into());
        }
        let value = decode_cbor_value(bytes).map_err(|e| e.to_string())?;
        if encode_canonical_cbor_value(&value).map_err(|e| e.to_string())? != bytes {
            return Err("proof-package locator or context join not canonical".into());
        }
        Self::from_value(&value)
    }
    /// Encodes the validated exact context join.
    /// # Errors
    /// Refuses invalid context identity or CBOR encoding.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let value = map(vec![
            (
                "task_completed_event_hash",
                Value::Bytes(self.task_completed_event_hash.to_vec()),
            ),
            (
                "package_record_hash",
                Value::Bytes(self.package_record_hash.to_vec()),
            ),
            (
                "context_instance",
                Value::Text(self.context_instance.clone()),
            ),
        ]);
        Self::from_value(&value)?;
        encode_canonical_cbor_value(&value).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Controlled metadata-only bytes exercise codec refusal; no crypto authority claim.
    pub(super) fn fixture() -> (ProtectedSourceProofPackageLocatorV1, Vec<u8>) {
        let ciphertext = vec![9; 48];
        let mut locator = ProtectedSourceProofPackageLocatorV1 {
            family: "mixed-v2".into(),
            task_completed_event_hash: [2; 32],
            package_sha256: [3; 32],
            witness_sha256: [10; 32],
            original_byte_length: 32,
            content_hash: trellis_types::domain_separated_sha256(
                trellis_types::CONTENT_DOMAIN,
                &ciphertext,
            ),
            context_key: vec![4; 32],
            record_hash: [0; 32],
            source_binding_hash: [4; 32],
            current_publication_hash: [5; 32],
            original_publication_hash: [6; 32],
            public_policy_hash: [6; 32],
            recipient_policy_hash: [7; 32],
            nonce: [8; 12],
            key_bag: map(vec![(
                "entries",
                Value::Array(vec![map(vec![
                    ("recipient", Value::Bytes(b"neutral-reader".to_vec())),
                    ("suite", Value::Integer(1.into())),
                    ("ephemeral_pubkey", Value::Bytes(vec![1; 32])),
                    ("wrapped_dek", Value::Bytes(vec![2; 48])),
                ])]),
            )]),
        };
        let record = encode_canonical_cbor_value(&map(vec![
            ("locator", locator.value(false)),
            ("ciphertext", Value::Bytes(ciphertext)),
        ]))
        .unwrap();
        locator.record_hash = sha256_bytes(&record);
        (locator, record)
    }
    #[test]
    fn proof_package_closed_locator_and_exact_record_roundtrip() {
        let (locator, record) = fixture();
        let canonical = locator.to_cbor().unwrap();
        let parsed = ProtectedSourceProofPackageLocatorV1::from_cbor(&canonical).unwrap();
        // Map insertion order is not part of canonical CBOR identity.
        assert_eq!(parsed.to_cbor().unwrap(), canonical);
        assert_eq!(
            parsed.opening(&record).unwrap().record_hash(),
            sha256_bytes(&record)
        );
        let opening = locator.opening(&record).unwrap();
        assert_eq!(opening.record_hash(), sha256_bytes(&record));
        assert_eq!(opening.ciphertext().len(), 48);
        assert!(opening.validate_opened_bytes(&[0; 32]).is_err());
        let mut changed = locator.clone();
        changed.witness_sha256 = [99; 32];
        assert!(changed.opening(&record).is_err());
        let mut corrupted = record.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(locator.opening(&corrupted).is_err());
    }
    #[test]
    fn proof_package_refuses_unknown_duplicate_missing_fields_and_unsupported_limits() {
        let (locator, _) = fixture();
        for key in ["response_id", "record_hash"] {
            let mut value = locator.value(true);
            value
                .as_map_mut()
                .unwrap()
                .push((Value::Text(key.into()), Value::Bytes(vec![1; 32])));
            assert!(ProtectedSourceProofPackageLocatorV1::from_value(&value).is_err());
        }
        let mut value = locator.value(true);
        value.as_map_mut().unwrap().pop();
        assert!(ProtectedSourceProofPackageLocatorV1::from_value(&value).is_err());
        let mut changed = locator.clone();
        changed.family = "native-v1".into();
        assert!(changed.to_cbor().is_err());
        changed = locator.clone();
        changed.original_byte_length = 0;
        assert!(changed.to_cbor().is_err());
        changed = locator.clone();
        changed.original_byte_length = MAX_PACKAGE_BYTES as u64 + 1;
        assert!(changed.to_cbor().is_err());
        changed = locator;
        changed.key_bag = map(vec![("entries", Value::Array(vec![]))]);
        assert!(changed.to_cbor().is_err());
    }
    #[test]
    fn original_context_proof_is_closed_and_bounded() {
        let join = OriginalContextProofV1 {
            task_completed_event_hash: [1; 32],
            package_record_hash: [2; 32],
            context_instance: "actual-origin".into(),
        };
        assert_eq!(
            OriginalContextProofV1::from_cbor(&join.to_cbor().unwrap()).unwrap(),
            join
        );
        for invalid in [
            "".to_string(),
            " ".to_string(),
            "a\nb".to_string(),
            "a".repeat(1025),
        ] {
            let mut changed = join.clone();
            changed.context_instance = invalid;
            assert!(changed.to_cbor().is_err());
        }
        let mut value = decode_cbor_value(&join.to_cbor().unwrap()).unwrap();
        value.as_map_mut().unwrap().push((
            Value::Text("response_id".into()),
            Value::Text("not-a-package-field".into()),
        ));
        assert!(OriginalContextProofV1::from_value(&value).is_err());
    }
    #[test]
    fn proof_package_locator_and_context_refuse_noncanonical_map_order_and_lengths() {
        let (locator, _) = fixture();
        let mut value = locator.value(true);
        value.as_map_mut().unwrap().reverse();
        let mut reordered = Vec::new();
        ciborium::into_writer(&value, &mut reordered).unwrap();
        assert!(ProtectedSourceProofPackageLocatorV1::from_cbor(&reordered).is_err());
        let bytes = locator.to_cbor().unwrap();
        assert_eq!(bytes[0], 0xb0);
        let mut nonminimal = vec![0xb8, 16];
        nonminimal.extend_from_slice(&bytes[1..]);
        assert!(ProtectedSourceProofPackageLocatorV1::from_cbor(&nonminimal).is_err());
        let join = OriginalContextProofV1 {
            task_completed_event_hash: [1; 32],
            package_record_hash: [2; 32],
            context_instance: "neutral-context".into(),
        };
        let bytes = join.to_cbor().unwrap();
        assert_eq!(bytes[0], 0xa3);
        let mut nonminimal = vec![0xb8, 3];
        nonminimal.extend_from_slice(&bytes[1..]);
        assert!(OriginalContextProofV1::from_cbor(&nonminimal).is_err());
    }
}
