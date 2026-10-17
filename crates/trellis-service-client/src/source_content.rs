//! Prepared Source-content batch and the claim WOS sends with the closeout append (ADR 0163).
// Rust guideline compliant 2026-02-21

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use utoipa::ToSchema;

/// Encodes byte payloads as standard base64 text. JSON number arrays expand
/// protected ciphertext about 3.6x, which pushed real batches past the 16 MiB bound.
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Already committed protected content returned by the independently selected owner.
///
/// Wire encoding of the byte fields (`intake_handoffs`, `source_signed_tasks`, and the
/// per-record `protected_record_bytes` and `locator_cbor`) is standard base64 text; the
/// decoder accepts only text, so a JSON number array is a decode error.
///
/// The version stays 1 on purpose, because the retained batch of the exported real D1
/// case is already base64 and must stay readable. An array-encoded batch of D1 size
/// cannot exist in retained storage: as arrays the same content serializes about 3.6x
/// larger and exceeds the 16 MiB batch bound, and WOS refuses an oversized batch before
/// persisting it. That argument covers only batches whose array form exceeds the bound.
/// An older, smaller array-encoded batch, if one were retained, would fail to decode
/// and has no re-prepare path. A mixed-version WOS/Trellis deployment (one side still on
/// arrays) likewise fails loudly with a decode error rather than misreading bytes. Bump
/// the version only for a change that cannot be read back as this encoding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceContentBatchV1 {
    pub version: u8,
    pub selection: SourceContentIdentityV1,
    pub records: Vec<PreparedSourceContentRecordV1>,
    #[serde(with = "base64_bytes")]
    pub intake_handoffs: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub source_signed_tasks: Vec<u8>,
}

/// Exact native and independently selected provider identity for a committed batch.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentIdentityV1 {
    pub case_ledger_id: String,
    pub process_id: String,
    pub native_prefix_digest: [u8; 32],
    pub reserved_closeout_record_id: String,
    pub reserved_native_closeout_record_sha256: [u8; 32],
    pub provider_selection_hash: [u8; 32],
    pub native_policy_hash: [u8; 32],
    pub recipient_policy_hash: [u8; 32],
    /// WOS-derived digest of the canonical sorted actual recipient IDs and public keys.
    ///
    /// This required identity field distinguishes key rotation under the same
    /// recipient policy. Trellis carries and compares the owning digest; it
    /// neither computes the recipient-set algorithm nor grants read authority.
    pub recipient_set_sha256: [u8; 32],
    pub workflow_url: String,
    pub workflow_version: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub environment_id: String,
    pub cell_id: String,
    pub source_id: String,
    pub service_binding_id: String,
}

/// Owning content family within the retained batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SourceContentRoleV1 {
    OriginalResponse,
    CorrectionResponse,
    TaskProofPackage,
}

/// Public Source occurrence selected by its owner before protection.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentOccurrenceV1 {
    pub role: SourceContentRoleV1,
    pub occurrence_event_hash: [u8; 32],
    pub response_id: Option<String>,
    pub publication_hash: [u8; 32],
    pub public_signing_policy_hash: [u8; 32],
    pub evaluation_registration_hash: [u8; 32],
}

/// First complete encrypted bytes and their admitted public associations.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceContentRecordV1 {
    pub occurrence: SourceContentOccurrenceV1,
    pub record_sha256: [u8; 32],
    pub member_content_hash: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub protected_record_bytes: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub locator_cbor: Vec<u8>,
}

/// Independently admitted selection, never decoded from the returned batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentSelection {
    pub preparation_key: String,
    pub identity: SourceContentIdentityV1,
    /// Complete ordered authenticated prefix before selected photos and closeout.
    /// Includes independently bound WOS and Source events in their original order.
    /// `identity.native_prefix_digest` binds this entire prefix; the selected photo
    /// events and reserved closeout follow it.
    pub native_prefix_event_hashes: Vec<[u8; 32]>,
    #[serde(rename = "orderedPhotoEventHashes")]
    pub photo_event_hashes: Vec<[u8; 32]>,
    pub intake_catalog_sha256: [u8; 32],
    pub task_catalog_sha256: [u8; 32],
    /// Exact public inventory admitted by the existing owning selection.
    pub record_pins: Vec<SourceContentRecordPins>,
}

/// Independently admitted public identity for one protected record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentRecordPins {
    pub role: SourceContentRoleV1,
    pub occurrence_event_hash: [u8; 32],
    pub response_id: Option<String>,
    pub source_publication_hash: [u8; 32],
    pub public_signing_policy_hash: [u8; 32],
    pub evaluation_registration_hash: [u8; 32],
    pub record_sha256: [u8; 32],
    pub member_content_hash: [u8; 32],
    pub locator_sha256: [u8; 32],
}

/// Read ceiling shared by the writer's encoded batch and Trellis's object read.
pub const MAX_PREPARED_SOURCE_CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// Most records one batch may hold.
pub const MAX_SOURCE_CONTENT_RECORDS: usize = 32;

/// What WOS asserts about the batch object it wrote, built once at record build.
///
/// Every append attempt sends it unchanged in `SubstrateAppendBody::source_content`. The
/// object's address is not part of it: Trellis derives the key from its own tenant scope and
/// `selection.preparation_key`. `hash` guards the stored bytes and `preparation_key` their meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentClaim {
    /// Lowercase hex SHA-256 of the exact stored object bytes.
    pub hash: String,
    /// Byte length of the stored object; bounds the read.
    pub size: u64,
    pub selection: SourceContentSelection,
}

impl SourceContentClaim {
    /// Checks the claim's shape without reading the object.
    ///
    /// # Errors
    /// Refuses a malformed hash, an empty or oversized object, or an unbounded record list.
    pub fn validate(&self) -> Result<(), StackError> {
        let hash_ok = self.hash.len() == 64
            && self
                .hash
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !hash_ok
            || self.size == 0
            || self.size > MAX_PREPARED_SOURCE_CONTENT_BYTES as u64
            || self.selection.preparation_key.is_empty()
            || self.selection.record_pins.is_empty()
            || self.selection.record_pins.len() > MAX_SOURCE_CONTENT_RECORDS
        {
            return Err(StackError::bad_request("Source content claim invalid"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn claim() -> SourceContentClaim {
        SourceContentClaim {
            hash: "ab".repeat(32),
            size: 1024,
            selection: SourceContentSelection {
                preparation_key: format!("sha256:{}", "c".repeat(64)),
                identity: batch(1).selection,
                native_prefix_event_hashes: vec![[1; 32]],
                photo_event_hashes: vec![[2; 32]],
                intake_catalog_sha256: [3; 32],
                task_catalog_sha256: [4; 32],
                record_pins: vec![SourceContentRecordPins {
                    role: SourceContentRoleV1::TaskProofPackage,
                    occurrence_event_hash: [7; 32],
                    response_id: None,
                    source_publication_hash: [8; 32],
                    public_signing_policy_hash: [9; 32],
                    evaluation_registration_hash: [10; 32],
                    record_sha256: [11; 32],
                    member_content_hash: [12; 32],
                    locator_sha256: [13; 32],
                }],
            },
        }
    }

    fn batch(payload: usize) -> PreparedSourceContentBatchV1 {
        let identity = SourceContentIdentityV1 {
            case_ledger_id: "case".into(),
            process_id: "process".into(),
            native_prefix_digest: [1; 32],
            reserved_closeout_record_id: "closeout".into(),
            reserved_native_closeout_record_sha256: [2; 32],
            provider_selection_hash: [3; 32],
            native_policy_hash: [4; 32],
            recipient_policy_hash: [5; 32],
            recipient_set_sha256: [6; 32],
            workflow_url: "urn:test:workflow".into(),
            workflow_version: "1".into(),
            tenant_id: "tenant".into(),
            workspace_id: "workspace".into(),
            environment_id: "environment".into(),
            cell_id: "cell".into(),
            source_id: "source".into(),
            service_binding_id: "binding".into(),
        };
        PreparedSourceContentBatchV1 {
            version: 1,
            selection: identity,
            records: vec![PreparedSourceContentRecordV1 {
                occurrence: SourceContentOccurrenceV1 {
                    role: SourceContentRoleV1::TaskProofPackage,
                    occurrence_event_hash: [7; 32],
                    response_id: None,
                    publication_hash: [8; 32],
                    public_signing_policy_hash: [9; 32],
                    evaluation_registration_hash: [10; 32],
                },
                record_sha256: [11; 32],
                member_content_hash: [12; 32],
                protected_record_bytes: (0..payload).map(|i| (i * 131 % 256) as u8).collect(),
                locator_cbor: vec![0xa0],
            }],
            intake_handoffs: vec![0x80],
            source_signed_tasks: vec![0x80],
        }
    }

    #[test]
    fn byte_fields_round_trip_as_compact_base64_text() {
        let original = batch(8 * 1024 * 1024);
        let encoded = serde_json::to_vec(&original).unwrap();
        // Ciphertext near the 8 MiB package bound must fit the 16 MiB batch bound.
        assert!(encoded.len() < MAX_PREPARED_SOURCE_CONTENT_BYTES);
        assert_eq!(serde_json::from_slice::<PreparedSourceContentBatchV1>(&encoded).unwrap(), original);
        let value = serde_json::to_value(&original).unwrap();
        assert!(value["records"][0]["protectedRecordBytes"].is_string());
        assert_eq!(serde_json::from_value::<PreparedSourceContentBatchV1>(value).unwrap(), original);
    }

    #[test]
    fn non_base64_byte_text_is_refused() {
        let mut value = serde_json::to_value(batch(4)).unwrap();
        value["intakeHandoffs"] = serde_json::json!("not base64!");
        assert!(serde_json::from_value::<PreparedSourceContentBatchV1>(value).is_err());
    }

    #[test]
    fn claim_wire_shape_is_camel_case_and_closed() {
        let value = serde_json::to_value(claim()).unwrap();
        assert_eq!(value["hash"], "ab".repeat(32));
        assert_eq!(value["size"], 1024);
        assert!(value["selection"]["orderedPhotoEventHashes"].is_array());
        assert!(value["selection"]["preparationKey"].is_string());
        assert_eq!(serde_json::from_value::<SourceContentClaim>(value.clone()).unwrap(), claim());
        let mut unknown = value;
        unknown["address"] = serde_json::json!("s3://elsewhere/key");
        assert!(serde_json::from_value::<SourceContentClaim>(unknown).is_err());
    }

    #[test]
    fn claim_validation_bounds_hash_size_and_records() {
        assert!(claim().validate().is_ok());
        for edit in 0..6 {
            let mut c = claim();
            match edit {
                0 => c.hash = "AB".repeat(32),
                1 => c.hash = "ab".repeat(31),
                2 => c.size = 0,
                3 => c.size = MAX_PREPARED_SOURCE_CONTENT_BYTES as u64 + 1,
                4 => c.selection.record_pins.clear(),
                _ => {
                    let pin = c.selection.record_pins[0].clone();
                    c.selection.record_pins = vec![pin; MAX_SOURCE_CONTENT_RECORDS + 1];
                }
            }
            assert!(c.validate().is_err(), "edit {edit}");
        }
    }

    #[test]
    fn claim_at_the_record_limit_is_far_below_the_append_body_limit() {
        let mut c = claim();
        let pin = c.selection.record_pins[0].clone();
        c.selection.record_pins = vec![pin; MAX_SOURCE_CONTENT_RECORDS];
        // A long native prefix and a photo suffix of 256 events each.
        c.selection.native_prefix_event_hashes = vec![[5; 32]; 256];
        c.selection.photo_event_hashes = vec![[6; 32]; 256];
        let body = serde_json::to_vec(&c).unwrap();
        // 2 MiB is the append body limit; JSON writes each hash byte as up to four characters.
        assert!(body.len() < 256 * 1024, "{}", body.len());
    }

    #[test]
    fn append_body_omits_the_claim_when_absent_and_carries_it_when_present() {
        use crate::{AppendActor, ComputeContext, SubstrateAppendRequest};
        let request = SubstrateAppendRequest::new_json(
            "case_123",
            stack_common_http::tenant::TenantScope {
                tenant: "t".into(),
                workspace: "w".into(),
                environment: "e".into(),
                cell: "c".into(),
            },
            "wos.provenance.recorded",
            "key",
            AppendActor::service("wos-server"),
            serde_json::json!({}),
            ComputeContext::no_delegated_compute("wos-server"),
        )
        .unwrap();
        assert!(serde_json::to_value(request.body()).unwrap().get("sourceContent").is_none());
        let sourced = request.with_source_content(claim());
        let value = serde_json::to_value(sourced.body()).unwrap();
        assert_eq!(value["sourceContent"]["size"], 1024);
        assert_eq!(
            serde_json::from_value::<crate::SubstrateAppendBody>(value).unwrap(),
            sourced.body()
        );
    }
}
