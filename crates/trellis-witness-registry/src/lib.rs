// Rust guideline compliant 2026-05-13
//! Witness-key registry archive member.
//!
//! The registry is serialized as dCBOR and carried at
//! `031-witness-key-registry.cbor`, a lexicographic sibling of
//! `030-signing-key-registry.cbor`. Export manifests bind it through
//! `ExportManifestPayload.extensions["trellis.export.witness-key-registry.v1"]`.

#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRegistryError {
    Encode(String),
    Decode(String),
}

impl Display for WitnessRegistryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(message) | Self::Decode(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for WitnessRegistryError {}

/// Core `timestamp` wire shape: `[seconds UTC, nanos]` with `nanos <= 999_999_999` (Core §9 / CDDL `timestamp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrellisTimestamp {
    pub unix_secs: u64,
    pub subsec_nanos: u32,
}

impl TrellisTimestamp {
    pub const MAX_SUBSEC_NANOS: u32 = 999_999_999;

    /// Builds a timestamp; rejects out-of-range subsecond nanoseconds per Core CDDL.
    pub fn new(unix_secs: u64, subsec_nanos: u32) -> Result<Self, WitnessRegistryError> {
        if subsec_nanos > Self::MAX_SUBSEC_NANOS {
            return Err(WitnessRegistryError::Decode(format!(
                "timestamp nanoseconds {subsec_nanos} exceed {}",
                Self::MAX_SUBSEC_NANOS
            )));
        }
        Ok(Self {
            unix_secs,
            subsec_nanos,
        })
    }

    fn to_cbor_value(self) -> Value {
        Value::Array(vec![
            Value::Integer(self.unix_secs.into()),
            Value::Integer(self.subsec_nanos.into()),
        ])
    }

    fn from_cbor_value(value: &Value, field: &'static str) -> Result<Self, WitnessRegistryError> {
        let items = value.as_array().ok_or_else(|| {
            WitnessRegistryError::Decode(format!("`{field}` is not a CBOR array"))
        })?;
        if items.len() != 2 {
            return Err(WitnessRegistryError::Decode(format!(
                "`{field}` timestamp must be a two-element array"
            )));
        }
        let secs = nonnegative_u64(&items[0], &format!("{field}[0]"))?;
        let nanos_u64 = nonnegative_u64(&items[1], &format!("{field}[1]"))?;
        let subsec_nanos = u32::try_from(nanos_u64)
            .map_err(|_| WitnessRegistryError::Decode(format!("`{field}[1]` does not fit u32")))?;
        Self::new(secs, subsec_nanos)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessKeyEntry {
    pub kid: [u8; 16],
    pub pubkey: Vec<u8>,
    pub suite_id: u64,
    pub effective_from: TrellisTimestamp,
    pub valid_to: Option<TrellisTimestamp>,
    pub supersedes: Option<[u8; 16]>,
    pub witness_kind: WitnessKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessKind {
    LocalServer,
    Rfc3161Tsa,
    EthereumAnchor,
    OpenTimestamps,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessKeyRegistry {
    pub version: u32,
    pub entries: Vec<WitnessKeyEntry>,
}

impl WitnessKeyRegistry {
    #[must_use]
    pub fn new(entries: Vec<WitnessKeyEntry>) -> Self {
        Self {
            version: 1,
            entries,
        }
    }

    /// Serializes the registry as CBOR.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, WitnessRegistryError> {
        let value = self.to_canonical_value()?;
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).map_err(|error| {
            WitnessRegistryError::Encode(format!("failed to encode witness registry: {error}"))
        })?;
        Ok(out)
    }

    /// Parses a CBOR-encoded witness registry.
    ///
    /// # Errors
    /// Returns an error if bytes do not decode as a registry.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, WitnessRegistryError> {
        let mut reader = bytes;
        let value = ciborium::from_reader(&mut reader).map_err(|error| {
            WitnessRegistryError::Decode(format!("failed to decode witness registry: {error}"))
        })?;
        if !reader.is_empty() {
            return Err(WitnessRegistryError::Decode(
                "trailing bytes after witness registry CBOR".to_string(),
            ));
        }
        Self::from_value(&value)
    }

    /// Computes SHA-256 over the canonical CBOR registry bytes.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization fails.
    pub fn integrity_hash(&self) -> Result<[u8; 32], WitnessRegistryError> {
        let cbor = self.to_cbor()?;
        Ok(Sha256::digest(cbor).into())
    }

    fn to_canonical_value(&self) -> Result<Value, WitnessRegistryError> {
        Ok(canonical_text_map(vec![
            (
                "entries",
                Value::Array(
                    self.entries
                        .iter()
                        .map(WitnessKeyEntry::to_canonical_value)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            ("version", Value::Integer(self.version.into())),
        ]))
    }

    fn from_value(value: &Value) -> Result<Self, WitnessRegistryError> {
        let map = expect_map(value, "WitnessKeyRegistry")?;
        let version = lookup_u64(map, "version")?;
        let version = u32::try_from(version).map_err(|_| {
            WitnessRegistryError::Decode(
                "witness registry version exceeds uint .size 4".to_string(),
            )
        })?;
        let entries_value = lookup_value(map, "entries")?;
        let entries = entries_value.as_array().ok_or_else(|| {
            WitnessRegistryError::Decode("witness registry entries is not an array".to_string())
        })?;
        let entries = entries
            .iter()
            .map(WitnessKeyEntry::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { version, entries })
    }
}

impl WitnessKeyEntry {
    fn to_canonical_value(&self) -> Result<Value, WitnessRegistryError> {
        if self.pubkey.len() != 32 {
            return Err(WitnessRegistryError::Encode(
                "witness pubkey must be 32 bytes".to_string(),
            ));
        }
        Ok(canonical_text_map(vec![
            ("kid", Value::Bytes(self.kid.to_vec())),
            ("pubkey", Value::Bytes(self.pubkey.clone())),
            ("suite_id", Value::Integer(self.suite_id.into())),
            ("effective_from", self.effective_from.to_cbor_value()),
            (
                "supersedes",
                self.supersedes
                    .as_ref()
                    .map_or(Value::Null, |value| Value::Bytes(value.to_vec())),
            ),
            (
                "valid_to",
                self.valid_to
                    .as_ref()
                    .map_or(Value::Null, |ts| ts.to_cbor_value()),
            ),
            (
                "witness_kind",
                Value::Text(self.witness_kind.as_str().to_string()),
            ),
        ]))
    }

    fn from_value(value: &Value) -> Result<Self, WitnessRegistryError> {
        let map = expect_map(value, "WitnessKeyEntry")?;
        let kid = lookup_bytes(map, "kid")?;
        let kid = <[u8; 16]>::try_from(kid.as_slice()).map_err(|_| {
            WitnessRegistryError::Decode("witness kid must be 16 bytes".to_string())
        })?;
        let pubkey = lookup_bytes(map, "pubkey")?;
        if pubkey.len() != 32 {
            return Err(WitnessRegistryError::Decode(
                "witness pubkey must be 32 bytes".to_string(),
            ));
        }
        let suite_id = lookup_u64(map, "suite_id")?;
        let effective_from = TrellisTimestamp::from_cbor_value(
            lookup_value(map, "effective_from")?,
            "effective_from",
        )?;
        let valid_to = match lookup_value(map, "valid_to")? {
            Value::Null => None,
            other => Some(TrellisTimestamp::from_cbor_value(other, "valid_to")?),
        };
        let supersedes = match lookup_value(map, "supersedes")? {
            Value::Null => None,
            Value::Bytes(bytes) => Some(<[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
                WitnessRegistryError::Decode("witness supersedes must be 16 bytes".to_string())
            })?),
            _ => {
                return Err(WitnessRegistryError::Decode(
                    "witness supersedes is neither bytes nor null".to_string(),
                ));
            }
        };
        let witness_kind = WitnessKind::from_text(lookup_text(map, "witness_kind")?)?;
        Ok(Self {
            kid,
            pubkey,
            suite_id,
            effective_from,
            valid_to,
            supersedes,
            witness_kind,
        })
    }
}

impl WitnessKind {
    fn as_str(&self) -> &str {
        match self {
            Self::LocalServer => "local-server",
            Self::Rfc3161Tsa => "rfc3161-tsa",
            Self::EthereumAnchor => "ethereum-anchor",
            Self::OpenTimestamps => "open-timestamps",
            Self::Other(value) => value.as_str(),
        }
    }

    fn from_text(value: &str) -> Result<Self, WitnessRegistryError> {
        match value {
            "local-server" => Ok(Self::LocalServer),
            "rfc3161-tsa" => Ok(Self::Rfc3161Tsa),
            "ethereum-anchor" => Ok(Self::EthereumAnchor),
            "open-timestamps" => Ok(Self::OpenTimestamps),
            "" => Err(WitnessRegistryError::Decode(
                "witness kind must not be empty".to_string(),
            )),
            other => Ok(Self::Other(other.to_string())),
        }
    }
}

impl Serialize for WitnessKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WitnessKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        WitnessKind::from_text(&value).map_err(serde::de::Error::custom)
    }
}

fn nonnegative_u64(value: &Value, label: &str) -> Result<u64, WitnessRegistryError> {
    value
        .as_integer()
        .and_then(|integer| integer.try_into().ok())
        .ok_or_else(|| {
            WitnessRegistryError::Decode(format!(
                "`{label}` is not a non-negative integer that fits u64"
            ))
        })
}

fn canonical_text_map(fields: Vec<(&'static str, Value)>) -> Value {
    let mut fields = fields
        .into_iter()
        .map(|(key, value)| (encoded_text_key(key), Value::Text(key.to_string()), value))
        .collect::<Vec<_>>();
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    Value::Map(
        fields
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    )
}

fn encoded_text_key(key: &str) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Text(key.to_string()), &mut out)
        .expect("text map key encodes as CBOR");
    out
}

fn expect_map<'a>(
    value: &'a Value,
    name: &str,
) -> Result<&'a [(Value, Value)], WitnessRegistryError> {
    value
        .as_map()
        .map(Vec::as_slice)
        .ok_or_else(|| WitnessRegistryError::Decode(format!("{name} is not a map")))
}

fn lookup_value<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<&'a Value, WitnessRegistryError> {
    map.iter()
        .find(|(key, _)| key.as_text().is_some_and(|text| text == key_name))
        .map(|(_, value)| value)
        .ok_or_else(|| WitnessRegistryError::Decode(format!("missing `{key_name}` value")))
}

fn lookup_bytes(map: &[(Value, Value)], key_name: &str) -> Result<Vec<u8>, WitnessRegistryError> {
    lookup_value(map, key_name)?
        .as_bytes()
        .cloned()
        .ok_or_else(|| WitnessRegistryError::Decode(format!("`{key_name}` is not a byte string")))
}

fn lookup_text<'a>(
    map: &'a [(Value, Value)],
    key_name: &str,
) -> Result<&'a str, WitnessRegistryError> {
    lookup_value(map, key_name)?
        .as_text()
        .ok_or_else(|| WitnessRegistryError::Decode(format!("`{key_name}` is not text")))
}

fn lookup_u64(map: &[(Value, Value)], key_name: &str) -> Result<u64, WitnessRegistryError> {
    lookup_value(map, key_name)?
        .as_integer()
        .and_then(|integer| integer.try_into().ok())
        .ok_or_else(|| {
            WitnessRegistryError::Decode(format!("`{key_name}` is not an unsigned integer"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trellis_timestamp_rejects_excess_subsec_nanos() {
        let err = TrellisTimestamp::new(0, 1_000_000_000).expect_err("nanos");
        assert!(err.to_string().contains("nanoseconds"), "{err}");
    }

    #[test]
    fn witness_key_registry_round_trips_cbor() {
        let ts = TrellisTimestamp::new(1, 0).expect("ts");
        let registry = WitnessKeyRegistry::new(vec![WitnessKeyEntry {
            kid: [0x01; 16],
            pubkey: vec![0xAA; 32],
            suite_id: 1,
            effective_from: ts,
            valid_to: None,
            supersedes: None,
            witness_kind: WitnessKind::LocalServer,
        }]);

        let bytes = registry.to_cbor().expect("encode");
        let parsed = WitnessKeyRegistry::from_cbor(&bytes).expect("parse");

        assert_eq!(parsed, registry);
    }

    #[test]
    fn witness_key_registry_integrity_hash_is_deterministic() {
        let registry = WitnessKeyRegistry::new(Vec::new());

        assert_eq!(
            registry.integrity_hash().expect("hash"),
            registry.integrity_hash().expect("hash")
        );
    }

    #[test]
    fn witness_key_registry_uses_canonical_map_order() {
        let ts = TrellisTimestamp::new(1, 0).expect("ts");
        let registry = WitnessKeyRegistry::new(vec![WitnessKeyEntry {
            kid: [0x01; 16],
            pubkey: vec![0xAA; 32],
            suite_id: 1,
            effective_from: ts,
            valid_to: None,
            supersedes: None,
            witness_kind: WitnessKind::Rfc3161Tsa,
        }]);

        let bytes = registry.to_cbor().expect("encode");
        let value: Value = ciborium::from_reader(bytes.as_slice()).expect("decode");
        let root_keys = map_keys(value.as_map().expect("root map"));
        assert_eq!(root_keys, vec!["entries", "version"]);

        let entries = value
            .as_map()
            .expect("root map")
            .iter()
            .find(|(key, _)| key.as_text() == Some("entries"))
            .and_then(|(_, value)| value.as_array())
            .expect("entries array");
        let entry_keys = map_keys(entries[0].as_map().expect("entry map"));
        assert_eq!(
            entry_keys,
            vec![
                "kid",
                "pubkey",
                "suite_id",
                "valid_to",
                "supersedes",
                "witness_kind",
                "effective_from",
            ]
        );
    }

    #[test]
    fn witness_key_registry_empty_bytes_match_canonical_oracle() {
        let registry = WitnessKeyRegistry::new(Vec::new());

        assert_eq!(
            registry.to_cbor().expect("encode"),
            vec![
                0xa2, 0x67, b'e', b'n', b't', b'r', b'i', b'e', b's', 0x80, 0x67, b'v', b'e', b'r',
                b's', b'i', b'o', b'n', 0x01,
            ]
        );
    }

    #[test]
    fn witness_key_registry_rejects_trailing_bytes() {
        let registry = WitnessKeyRegistry::new(Vec::new());
        let mut bytes = registry.to_cbor().expect("encode");
        bytes.push(0);

        let err = WitnessKeyRegistry::from_cbor(&bytes).expect_err("trailing bytes");
        assert!(err.to_string().contains("trailing bytes"), "{err}");
    }

    #[test]
    fn witness_key_registry_rejects_short_pubkey() {
        let ts = TrellisTimestamp::new(1, 0).expect("ts");
        let registry = WitnessKeyRegistry::new(vec![WitnessKeyEntry {
            kid: [0x01; 16],
            pubkey: vec![0xAA; 31],
            suite_id: 1,
            effective_from: ts,
            valid_to: None,
            supersedes: None,
            witness_kind: WitnessKind::LocalServer,
        }]);

        let err = registry.to_cbor().expect_err("short pubkey");
        assert!(err.to_string().contains("pubkey"), "{err}");
    }

    #[test]
    fn witness_key_registry_preserves_extension_witness_kind() {
        let ts = TrellisTimestamp::new(1, 0).expect("ts");
        let registry = WitnessKeyRegistry::new(vec![WitnessKeyEntry {
            kid: [0x01; 16],
            pubkey: vec![0xAA; 32],
            suite_id: 1,
            effective_from: ts,
            valid_to: None,
            supersedes: Some([0x02; 16]),
            witness_kind: WitnessKind::Other("x-agency-notary".to_string()),
        }]);

        let bytes = registry.to_cbor().expect("encode");
        let parsed = WitnessKeyRegistry::from_cbor(&bytes).expect("parse");

        assert_eq!(parsed, registry);
    }

    fn map_keys(map: &[(Value, Value)]) -> Vec<&str> {
        map.iter()
            .map(|(key, _)| key.as_text().expect("text key"))
            .collect()
    }
}
