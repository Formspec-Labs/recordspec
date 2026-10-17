// Rust guideline compliant 2026-05-15
#![allow(clippy::result_large_err, clippy::collapsible_if)]
// `StackError` carries operational context callers rely on; boxing it would change every fallible
// signature in this crate. Follow-up: convert `StackError` to a `Box<...>` newtype workspace-wide.
// `collapsible_if`: nested `if let ... && ...` chains are clearer split for the extension-walking
// patterns in this crate; collapsing them obscures the optional-extension semantics.
//! Trellis Phase-1 export writer.
//!
//! This crate owns the Core section 18 export-emission orchestration: deterministic bundle
//! assembly, manifest digest binding, Merkle proof material, checkpoint chain
//! construction, signing-key registry emission, and posture declaration
//! materialization. Storage adapters hand it a durable ledger snapshot; the
//! writer does not depend on WOS event types.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use integrity_bundle::{Bundle, BundleEntry};
use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, encode_bstr, encode_canonical_cbor_value,
    encode_tstr, encode_uint, map_lookup_array, map_lookup_bytes, map_lookup_map, map_lookup_u64,
    sha256_bytes,
};
use integrity_cose::{
    derive_kid, sig_structure_bytes, sign_ed25519, sign1_bytes, substrate_protected_header,
};
pub use integrity_hpke::{HPKE_SUITE1_AAD, HPKE_SUITE1_INFO};
use stack_common_error::StackError;
use trellis_types::merkle::{MerkleHasher, MerkleTree, TrellisHasher};
use trellis_types::{
    ArtifactType, CheckpointPayload, StoredCheckpoint, StoredEvent, checkpoint_digest,
};
#[doc(inline)]
pub use trellis_witness_registry::WitnessKeyRegistry;

#[cfg(any(test, feature = "fixture-inputs"))]
mod export_001_fixture_input;

#[cfg(any(test, feature = "fixture-inputs"))]
pub use export_001_fixture_input::{export_001_writer_input, issue_checkpoints};

const EVENT_DOMAIN: &str = "trellis-event-v1";
const EXPORT_MANIFEST_DOMAIN: &str = "trellis-export-manifest-v1";
const EXPORT_ATTEMPT_DOMAIN: &str = "trellis-export-attempt-v1";
const SUITE_ID_PHASE_1: u64 = 1;

pub const MANIFEST_MEMBER: &str = "000-manifest.cbor";
pub const EVENTS_MEMBER: &str = "010-events.cbor";
pub const INCLUSION_PROOFS_MEMBER: &str = "020-inclusion-proofs.cbor";
pub const CONSISTENCY_PROOFS_MEMBER: &str = "025-consistency-proofs.cbor";
pub const SIGNING_KEY_REGISTRY_MEMBER: &str = "030-signing-key-registry.cbor";
/// Core §18.2 / §18.3d — optional when no witness policy; required in the ZIP when
/// [`ExportWriterInput::witness_key_registry`](ExportWriterInput::witness_key_registry) is set.
pub const WITNESS_KEY_REGISTRY_MEMBER: &str = "031-witness-key-registry.cbor";
pub const CHECKPOINTS_MEMBER: &str = "040-checkpoints.cbor";
pub const REGISTRY_DIR: &str = "050-registries";
/// Composition-owned SignedAct projection catalog.
///
/// Trellis binds the bytes in the export manifest, but WOS/Formspec profile
/// validators own the projection semantics and deterministic re-derivation.
pub const SIGNED_ACTS_MEMBER: &str = "066-signed-acts.cbor";
/// Composition-owned SignedAct manifest digest catalog.
///
/// Sibling of [`SIGNED_ACTS_MEMBER`]. Carries the byte-deterministic
/// `(canonical_event_hash, event_type)` tuple list for sealed signed-acts
/// source events. Re-derivable from sealed source events alone, so it acts as
/// the verifier's substrate-side anchor for the `066-signed-acts.cbor`
/// projection. Trellis binds the bytes via the
/// `trellis.export.signed-acts.manifest.v1` extension; consumer profile
/// validators re-derive and compare.
pub const SIGNED_ACTS_MANIFEST_MEMBER: &str = "068-signed-acts-manifest.cbor";
/// Composition-owned effective policy closure.
///
/// Trellis binds the bytes in the export manifest. WOS/Formspec verifiers own
/// the policy-closure shape and the boundary between bundle evidence, verifier
/// trust configuration, and runtime operational configuration.
pub const POLICY_CLOSURE_MEMBER: &str = "067-policy-closure.cbor";
pub const VERIFY_MEMBER: &str = "090-verify.sh";
pub const README_MEMBER: &str = "098-README.md";

/// Core timestamp wire shape: `[seconds UTC, nanos]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrellisTimestamp {
    pub unix_secs: u64,
    pub subsec_nanos: u32,
}

impl TrellisTimestamp {
    pub const MAX_SUBSEC_NANOS: u32 = 999_999_999;

    /// Builds a Core timestamp.
    ///
    /// # Errors
    /// Returns an error if `subsec_nanos` exceeds the Core timestamp bound.
    pub fn new(unix_secs: u64, subsec_nanos: u32) -> Result<Self, StackError> {
        if subsec_nanos > Self::MAX_SUBSEC_NANOS {
            return Err(StackError::bad_request(format!(
                "timestamp nanoseconds {subsec_nanos} exceed {}",
                Self::MAX_SUBSEC_NANOS
            )));
        }
        Ok(Self {
            unix_secs,
            subsec_nanos,
        })
    }

    fn to_value(self) -> Value {
        Value::Array(vec![
            uint(self.unix_secs),
            uint(u64::from(self.subsec_nanos)),
        ])
    }
}

/// Ed25519 signing material used for the manifest, checkpoints, and embedded
/// signing-key registry snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeyMaterial {
    pub private_seed: [u8; 32],
    pub public_key: [u8; 32],
    pub valid_from: TrellisTimestamp,
    pub valid_to: Option<TrellisTimestamp>,
}

impl SigningKeyMaterial {
    #[must_use]
    pub fn kid(&self) -> [u8; 16] {
        derive_kid(SUITE_ID_PHASE_1, self.public_key)
    }

    /// The registry row of a key that has never been rotated: active, superseding nothing.
    #[must_use]
    pub fn registry_entry(&self) -> SigningKeyRegistryEntry {
        SigningKeyRegistryEntry {
            kid: self.kid(),
            public_key: self.public_key,
            status: SigningKeyStatus::Active,
            valid_from: self.valid_from,
            valid_to: self.valid_to,
            supersedes: None,
        }
    }
}

/// Core §8.4 lifecycle status of a registry row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKeyStatus {
    Active = 0,
    Retired = 2,
    Revoked = 3,
}

/// One Core §8.2 `SigningKeyEntry`: public material only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeyRegistryEntry {
    pub kid: [u8; 16],
    pub public_key: [u8; 32],
    pub status: SigningKeyStatus,
    pub valid_from: TrellisTimestamp,
    pub valid_to: Option<TrellisTimestamp>,
    /// The `kid` this entry replaces.
    pub supersedes: Option<[u8; 16]>,
}

/// Encodes registry rows as the dCBOR array `030-signing-key-registry.cbor` carries.
///
/// # Errors
/// Returns an error if CBOR encoding fails.
pub fn encode_signing_key_registry(
    entries: &[SigningKeyRegistryEntry],
) -> Result<Vec<u8>, StackError> {
    let rows = entries
        .iter()
        .map(|entry| {
            text_map(vec![
                ("kid", Value::Bytes(entry.kid.to_vec())),
                ("pubkey", Value::Bytes(entry.public_key.to_vec())),
                ("suite_id", uint(SUITE_ID_PHASE_1)),
                ("status", uint(entry.status as u64)),
                ("valid_from", entry.valid_from.to_value()),
                (
                    "valid_to",
                    entry
                        .valid_to
                        .map_or(Value::Null, TrellisTimestamp::to_value),
                ),
                (
                    "supersedes",
                    entry
                        .supersedes
                        .map_or(Value::Null, |kid| Value::Bytes(kid.to_vec())),
                ),
                ("attestation", Value::Null),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;
    encode_value(&Value::Array(rows))
}

/// Immutable domain-registry bytes to embed under `050-registries/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub bytes: Vec<u8>,
    pub registry_format: u64,
    pub registry_version: String,
    pub bound_at_sequence: u64,
}

/// Caller-supplied verifier-facing SignedAct projection catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedActsCatalogMember {
    pub bytes: Vec<u8>,
    pub derivation_rule: String,
}

/// Caller-supplied SignedAct manifest digest catalog (068 member).
///
/// Carries the canonical-CBOR encoding of the sorted
/// `(canonical_event_hash, event_type)` tuple list derived from the sealed
/// source events. Trellis binds the bytes; consumer profile validators
/// re-derive and compare byte-for-byte. The derivation rule string identifies
/// the algorithm (e.g. `signed-acts-manifest-v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedActsManifestMember {
    pub bytes: Vec<u8>,
    pub derivation_rule: String,
}

/// Caller-supplied effective policy closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyClosureMember {
    pub bytes: Vec<u8>,
    pub closure_version: String,
}

/// Admitted bytes for fixed, registered export evidence members.
///
/// The writer checks byte format and derives manifest bindings. Consumer
/// verifiers retain responsibility for record relationships and disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportEvidenceMember {
    /// Ciphertext addressed by the Core `trellis-content-v1` hash.
    Payload {
        content_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    /// Native attachment catalog; composed verification checks inlining truth.
    Attachments {
        bytes: Vec<u8>,
        inline_attachments: bool,
    },
    /// Native signature-affirmation catalog.
    SignatureAffirmations { bytes: Vec<u8> },
    /// Native intake-handoff catalog.
    IntakeHandoffs { bytes: Vec<u8> },
    /// Native completion-certificate catalog.
    CertificatesOfCompletion { bytes: Vec<u8> },
    /// Native open-clock JSON; composed verification checks canonical form.
    OpenClocks { bytes: Vec<u8> },
}

/// Export posture declaration carried in the manifest and rendered into the
/// README inspection view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureDeclaration {
    pub provider_readable: bool,
    pub reader_held: bool,
    pub delegated_compute: bool,
    pub external_anchor_required: bool,
    pub external_anchor_name: Option<String>,
    pub recovery_without_user: bool,
    pub metadata_leakage_summary: String,
}

impl PostureDeclaration {
    fn to_value(&self) -> Result<Value, StackError> {
        text_map(vec![
            ("provider_readable", Value::Bool(self.provider_readable)),
            ("reader_held", Value::Bool(self.reader_held)),
            ("delegated_compute", Value::Bool(self.delegated_compute)),
            (
                "external_anchor_required",
                Value::Bool(self.external_anchor_required),
            ),
            (
                "external_anchor_name",
                option_text(self.external_anchor_name.as_deref()),
            ),
            (
                "recovery_without_user",
                Value::Bool(self.recovery_without_user),
            ),
            (
                "metadata_leakage_summary",
                Value::Text(self.metadata_leakage_summary.clone()),
            ),
        ])
    }

    fn to_sorted_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "delegated_compute".to_string(),
            serde_json::Value::Bool(self.delegated_compute),
        );
        map.insert(
            "external_anchor_name".to_string(),
            self.external_anchor_name
                .as_ref()
                .map_or(serde_json::Value::Null, |value| {
                    serde_json::Value::String(value.clone())
                }),
        );
        map.insert(
            "external_anchor_required".to_string(),
            serde_json::Value::Bool(self.external_anchor_required),
        );
        map.insert(
            "metadata_leakage_summary".to_string(),
            serde_json::Value::String(self.metadata_leakage_summary.clone()),
        );
        map.insert(
            "provider_readable".to_string(),
            serde_json::Value::Bool(self.provider_readable),
        );
        map.insert(
            "reader_held".to_string(),
            serde_json::Value::Bool(self.reader_held),
        );
        map.insert(
            "recovery_without_user".to_string(),
            serde_json::Value::Bool(self.recovery_without_user),
        );
        serde_json::Value::Object(map)
    }
}

/// Input snapshot for one export emission.
#[derive(Clone, Debug, PartialEq)]
pub struct ExportWriterInput {
    pub scope: Vec<u8>,
    pub events: Vec<StoredEvent>,
    pub registries: Vec<RegistrySnapshot>,
    pub signing_key: SigningKeyMaterial,
    /// The public key history the export embeds (Core §8.5): a row for every `kid` any event,
    /// checkpoint or the manifest cites, and for every key those supersede. Data, not derived
    /// from `signing_key`: after a rotation the ledger still holds entries signed by retired keys.
    pub signing_key_registry: Vec<SigningKeyRegistryEntry>,
    pub generator: String,
    pub generated_at: TrellisTimestamp,
    /// The signed checkpoints for tree sizes `1..=events.len()`, as issued at append time
    /// (Core §11.2). The writer assembles them verbatim and re-signs nothing: it checks that they
    /// chain, number the prefixes in order and commit to the tree it builds from `events`.
    pub checkpoints: Vec<StoredCheckpoint>,
    pub posture_declaration: PostureDeclaration,
    pub omitted_payload_checks: Vec<Value>,
    pub readme_title: String,
    pub root_dir_override: Option<String>,
    pub external_anchors: Vec<Value>,
    pub extensions: Option<Value>,
    /// Optional export identity and high-water fence bound into the manifest.
    pub seal_fence: Option<ExportSealFence>,
    /// When set, the writer emits `031-witness-key-registry.cbor` and merges
    /// `ExportManifestPayload.extensions["trellis.export.witness-key-registry.v1"]`
    /// (`witness_key_registry_digest`, `entry_count`) per Core §18.3d.
    ///
    /// If [`Self::extensions`] already includes that key, the writer replaces it
    /// with values derived from this registry so the manifest matches the member.
    pub witness_key_registry: Option<WitnessKeyRegistry>,
    /// Optional composition-owned `066-signed-acts.cbor` projection catalog.
    ///
    /// The writer verifies only byte carriage preconditions and binds the member
    /// digest. WOS/Formspec verifiers re-derive the catalog from layered records
    /// and decide whether the projection is semantically usable.
    pub signed_acts_catalog: Option<SignedActsCatalogMember>,
    /// Optional composition-owned `068-signed-acts-manifest.cbor` digest catalog.
    ///
    /// Emitted alongside [`Self::signed_acts_catalog`]; carries the sealed
    /// `(canonical_event_hash, event_type)` tuple list. The writer binds the
    /// member digest via `trellis.export.signed-acts.manifest.v1`. WOS/Formspec
    /// verifiers re-derive from sealed source events and compare byte-for-byte.
    pub signed_acts_manifest: Option<SignedActsManifestMember>,
    /// Optional composition-owned `067-policy-closure.cbor` rule-evidence
    /// snapshot.
    ///
    /// The writer binds the bytes and closure version. WOS/Formspec verifiers
    /// enforce that the member is case-policy evidence, not verifier trust-root
    /// or adapter allowlist configuration.
    pub policy_closure: Option<PolicyClosureMember>,
    /// Fixed native members whose exact bytes determine their manifest bindings.
    ///
    /// Duplicate members, invalid content hashes, noncanonical CBOR catalogs,
    /// and advertised registered bindings without corresponding bytes reject.
    pub evidence_members: Vec<ExportEvidenceMember>,
}

/// Export identity and source high-water fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportSealFence {
    pub bundle_scope: Vec<u8>,
    pub export_attempt_id: String,
    pub seal_version: u64,
    pub event_count: u64,
    pub high_water_sequence: u64,
}

/// Complete export writer output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPackage {
    pub root_dir: String,
    pub entries: Vec<BundleEntry>,
    pub zip_bytes: Vec<u8>,
    pub manifest_payload: Vec<u8>,
    pub manifest_digest: [u8; 32],
    pub head_checkpoint_digest: [u8; 32],
    pub tree_head_hash: [u8; 32],
}

impl ExportPackage {
    #[must_use]
    pub fn member_bytes(&self, member: &str) -> Option<&[u8]> {
        let path = format!("{}/{member}", self.root_dir);
        self.entries
            .iter()
            .find(|entry| entry.path() == path)
            .map(BundleEntry::bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedEvent {
    sequence: u64,
    canonical_event: Vec<u8>,
    signed_event: Vec<u8>,
    canonical_event_hash: [u8; 32],
    leaf_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
struct RegistryBindingMaterial {
    member: String,
    bytes: Vec<u8>,
    value: Value,
}

/// Writes a Trellis Phase-1 export package.
///
/// # Errors
/// Returns `bad_request` when the snapshot violates export preconditions (empty
/// scope or events, mismatched checkpoints, invalid events) or when
/// [`ExportWriterInput::extensions`] claims `trellis.export.witness-key-registry.v1`
/// while [`ExportWriterInput::witness_key_registry`] is unset.
///
/// Returns `bad_request` when [`ExportWriterInput::witness_key_registry`] fails
/// canonical encoding (invalid entry material).
///
/// Returns `internal` for CBOR map construction, ZIP serialization, or other
/// defects treated as implementation faults.
pub fn write_export(input: ExportWriterInput) -> Result<ExportPackage, StackError> {
    validate_top_level_input(&input)?;
    let events = prepare_events(&input)?;
    validate_seal_fence(&input, &events)?;
    let hasher = TrellisHasher;
    let tree = MerkleTree::from_leaf_hashes(
        &hasher,
        events.iter().map(|event| event.leaf_hash).collect(),
    );
    let tree_head_hash = tree.root(events.len() as u64).map_err(merkle_error)?;

    let events_cbor =
        array_of_raw_cbor_values(events.iter().map(|event| event.signed_event.as_slice()))?;
    let registry_material = registry_binding_material(&input.registries)?;
    let signing_key_registry_cbor = checked_signing_key_registry(&input, &events)?;
    let checkpoints = supplied_checkpoints(&input, tree_head_hash)?;
    let checkpoints_cbor = array_of_raw_cbor_values(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.checkpoint.as_slice()),
    )?;
    let inclusion_proofs_cbor = inclusion_proofs_cbor(&events, &tree)?;
    let consistency_proofs_cbor = consistency_proofs_cbor(&events, &tree)?;
    let head_checkpoint_digest = input
        .checkpoints
        .last()
        .map(|checkpoint| checkpoint.digest)
        .ok_or_else(|| StackError::internal("checkpoint chain unexpectedly empty"))?;
    let root_dir = input
        .root_dir_override
        .clone()
        .unwrap_or_else(|| root_dir(&input.scope, events.len(), tree_head_hash));

    let evidence = prepare_evidence_members(&input, &root_dir)?;
    let verify_sh = default_verify_script();
    let readme = readme_bytes(
        &input,
        events.len(),
        tree_head_hash,
        head_checkpoint_digest,
        &registry_material,
    )?;

    let witness_registry_cbor: Option<Vec<u8>> = match &input.witness_key_registry {
        None => None,
        Some(registry) => Some(registry.to_cbor().map_err(|error| {
            StackError::bad_request(format!("witness_key_registry is invalid: {error}"))
        })?),
    };
    let existing_extensions = manifest_extensions_value(
        &input,
        input.witness_key_registry.as_ref(),
        witness_registry_cbor.as_deref(),
        head_checkpoint_digest,
        &events_cbor,
    )?;

    let manifest_extensions = merge_evidence_bindings(existing_extensions, evidence.bindings)?;
    let manifest_payload = manifest_payload_cbor(ManifestPayloadInput {
        input: &input,
        tree_size: events.len(),
        head_checkpoint_digest,
        registry_bindings: registry_material
            .iter()
            .map(|binding| binding.value.clone())
            .collect(),
        signing_key_registry_cbor: &signing_key_registry_cbor,
        events_cbor: &events_cbor,
        checkpoints_cbor: &checkpoints_cbor,
        inclusion_proofs_cbor: &inclusion_proofs_cbor,
        consistency_proofs_cbor: &consistency_proofs_cbor,
        manifest_extensions,
        payloads_inlined: evidence.payloads_inlined,
    })?;
    let signed_manifest = sign_cose(
        &input.signing_key,
        ArtifactType::Manifest,
        &manifest_payload,
    );
    let manifest_digest = export_manifest_digest(&input.scope, &manifest_payload);

    let mut bundle = Bundle::new();
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{MANIFEST_MEMBER}"),
        signed_manifest,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{EVENTS_MEMBER}"),
        events_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{INCLUSION_PROOFS_MEMBER}"),
        inclusion_proofs_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{CONSISTENCY_PROOFS_MEMBER}"),
        consistency_proofs_cbor,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{SIGNING_KEY_REGISTRY_MEMBER}"),
        signing_key_registry_cbor,
    ));
    if let Some(bytes) = witness_registry_cbor {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{WITNESS_KEY_REGISTRY_MEMBER}"),
            bytes,
        ));
    }
    if let Some(catalog) = &input.signed_acts_catalog {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{SIGNED_ACTS_MEMBER}"),
            catalog.bytes.clone(),
        ));
    }
    if let Some(manifest) = &input.signed_acts_manifest {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{SIGNED_ACTS_MANIFEST_MEMBER}"),
            manifest.bytes.clone(),
        ));
    }
    if let Some(closure) = &input.policy_closure {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{POLICY_CLOSURE_MEMBER}"),
            closure.bytes.clone(),
        ));
    }
    for entry in evidence.entries {
        bundle.add_entry(entry);
    }
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{CHECKPOINTS_MEMBER}"),
        checkpoints_cbor,
    ));
    for binding in registry_material {
        bundle.add_entry(BundleEntry::new(
            format!("{root_dir}/{}", binding.member),
            binding.bytes,
        ));
    }
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{VERIFY_MEMBER}"),
        verify_sh,
    ));
    bundle.add_entry(BundleEntry::new(
        format!("{root_dir}/{README_MEMBER}"),
        readme,
    ));

    let zip_bytes = bundle.to_zip_bytes().map_err(|error| {
        StackError::internal(format!("failed to serialize export ZIP: {error}"))
    })?;
    Ok(ExportPackage {
        root_dir,
        entries: bundle.entries().to_vec(),
        zip_bytes,
        manifest_payload,
        manifest_digest,
        head_checkpoint_digest,
        tree_head_hash,
    })
}

const EVIDENCE_BINDINGS: [(&str, &str, &str); 5] = [
    (
        "061-attachments.cbor",
        "trellis.export.attachments.v1",
        "attachment_manifest_digest",
    ),
    (
        "062-signature-affirmations.cbor",
        "trellis.export.signature-affirmations.v1",
        "signature_catalog_digest",
    ),
    (
        "063-intake-handoffs.cbor",
        "trellis.export.intake-handoffs.v1",
        "intake_catalog_digest",
    ),
    (
        "065-certificates-of-completion.cbor",
        "trellis.export.certificates-of-completion.v1",
        "catalog_digest",
    ),
    (
        "open-clocks.json",
        "trellis.export.open-clocks.v1",
        "open_clocks_digest",
    ),
];

struct PreparedEvidence {
    entries: Vec<BundleEntry>,
    bindings: Vec<(Value, Value)>,
    payloads_inlined: bool,
}

fn prepare_evidence_members(
    input: &ExportWriterInput,
    root: &str,
) -> Result<PreparedEvidence, StackError> {
    let mut prepared = PreparedEvidence {
        entries: Vec::new(),
        bindings: Vec::new(),
        payloads_inlined: false,
    };
    let mut paths = BTreeSet::new();
    let mut provided = BTreeSet::new();
    for member in &input.evidence_members {
        let (index, bytes) = match member {
            ExportEvidenceMember::Payload {
                content_hash,
                bytes,
            } => {
                if domain_separated_sha256("trellis-content-v1", bytes) != *content_hash {
                    return Err(StackError::bad_request(
                        "payload content hash does not match ciphertext",
                    ));
                }
                let path = format!("060-payloads/{}.bin", hex_lower(content_hash));
                if !paths.insert(path.clone()) {
                    return Err(StackError::bad_request(format!(
                        "duplicate evidence member: {path}"
                    )));
                }
                prepared
                    .entries
                    .push(BundleEntry::new(format!("{root}/{path}"), bytes.clone()));
                prepared.payloads_inlined = true;
                continue;
            }
            ExportEvidenceMember::Attachments { bytes, .. } => (0, bytes),
            ExportEvidenceMember::SignatureAffirmations { bytes } => (1, bytes),
            ExportEvidenceMember::IntakeHandoffs { bytes } => (2, bytes),
            ExportEvidenceMember::CertificatesOfCompletion { bytes } => (3, bytes),
            ExportEvidenceMember::OpenClocks { bytes } => (4, bytes),
        };
        let (path, extension, digest_key) = EVIDENCE_BINDINGS[index];
        if !paths.insert(path.to_string()) {
            return Err(StackError::bad_request(format!(
                "duplicate evidence member: {path}"
            )));
        }
        let count = if index == 4 {
            let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
                StackError::bad_request(format!("{path} is invalid JSON: {error}"))
            })?;
            value
                .get("open_clocks")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    StackError::bad_request("open-clocks.json requires an open_clocks array")
                })?
                .len()
        } else {
            let value = decode_cbor_value(bytes).map_err(|error| {
                StackError::bad_request(format!("{path} is invalid CBOR: {error}"))
            })?;
            let canonical = encode_canonical_cbor_value(&value).map_err(|error| {
                StackError::bad_request(format!("{path} is invalid canonical CBOR: {error}"))
            })?;
            if canonical != *bytes {
                return Err(StackError::bad_request(format!(
                    "{path} must be canonical CBOR"
                )));
            }
            value
                .as_array()
                .ok_or_else(|| StackError::bad_request(format!("{path} must be a CBOR array")))?
                .len()
        };
        let mut fields = vec![(digest_key, Value::Bytes(sha256_bytes(bytes).to_vec()))];
        match member {
            ExportEvidenceMember::Attachments {
                inline_attachments, ..
            } => fields.push(("inline_attachments", Value::Bool(*inline_attachments))),
            ExportEvidenceMember::CertificatesOfCompletion { .. } => {
                fields.push(("catalog_ref", Value::Text(path.to_string())));
                fields.push((
                    "entry_count",
                    uint(
                        u64::try_from(count)
                            .map_err(|_| StackError::bad_request("catalog count exceeds u64"))?,
                    ),
                ));
            }
            ExportEvidenceMember::OpenClocks { .. } => fields.push((
                "open_clock_count",
                uint(
                    u64::try_from(count)
                        .map_err(|_| StackError::bad_request("clock count exceeds u64"))?,
                ),
            )),
            _ => {}
        }
        provided.insert(extension);
        prepared
            .bindings
            .push((Value::Text(extension.to_string()), text_map(fields)?));
        prepared
            .entries
            .push(BundleEntry::new(format!("{root}/{path}"), bytes.clone()));
    }
    if let Some(Value::Map(entries)) = &input.extensions {
        for (_, extension, _) in EVIDENCE_BINDINGS {
            if entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(extension))
                && !provided.contains(extension)
            {
                return Err(StackError::bad_request(format!(
                    "manifest extension {extension} requires its evidence member"
                )));
            }
        }
    }
    Ok(prepared)
}

fn merge_evidence_bindings(
    base: Value,
    bindings: Vec<(Value, Value)>,
) -> Result<Value, StackError> {
    if bindings.is_empty() {
        return Ok(base);
    }
    let mut pairs = match base {
        Value::Null => Vec::new(),
        Value::Map(pairs) => pairs,
        _ => {
            return Err(StackError::bad_request(
                "manifest extensions must be a map or null",
            ));
        }
    };
    pairs.retain(|(key, _)| !bindings.iter().any(|(owned, _)| key == owned));
    pairs.extend(bindings);
    canonical_map(pairs)
}

/// Core §18.3d manifest.extensions key binding `031-witness-key-registry.cbor`.
const WITNESS_REGISTRY_MANIFEST_EXTENSION: &str = "trellis.export.witness-key-registry.v1";
/// Export seal identity and high-water source fence.
const SEAL_FENCE_MANIFEST_EXTENSION: &str = "trellis.export.seal-fence.v1";
/// Composition-owned manifest extension binding `066-signed-acts.cbor`.
const SIGNED_ACTS_MANIFEST_EXTENSION: &str = "trellis.export.signed-acts.v1";
/// Composition-owned manifest extension binding `068-signed-acts-manifest.cbor`.
const SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION: &str = "trellis.export.signed-acts.manifest.v1";
/// Composition-owned manifest extension binding `067-policy-closure.cbor`.
const POLICY_CLOSURE_MANIFEST_EXTENSION: &str = "trellis.export.policy-closure.v1";

fn manifest_extensions_value(
    input: &ExportWriterInput,
    registry: Option<&WitnessKeyRegistry>,
    witness_registry_cbor: Option<&[u8]>,
    head_checkpoint_digest: [u8; 32],
    events_cbor: &[u8],
) -> Result<Value, StackError> {
    let policy_closure_digest = input
        .policy_closure
        .as_ref()
        .map(|closure| sha256_bytes(&closure.bytes));
    let with_seal = match &input.seal_fence {
        None => input.extensions.clone(),
        Some(seal_fence) => Some(merge_seal_fence_manifest_extension(
            input.extensions.as_ref(),
            seal_fence,
            head_checkpoint_digest,
            sha256_bytes(events_cbor),
            policy_closure_digest,
        )?),
    };
    let with_witness = match (registry, witness_registry_cbor) {
        (None, None) => with_seal,
        (Some(registry), Some(cbor)) => {
            let entry_count = u64::try_from(registry.entries.len()).map_err(|_| {
                StackError::internal("witness registry entry count exceeds u64::MAX")
            })?;
            Some(merge_witness_registry_manifest_extension(
                with_seal.as_ref(),
                sha256_bytes(cbor),
                entry_count,
            )?)
        }
        (None, Some(_)) | (Some(_), None) => Err(StackError::internal(
            "witness_key_registry field and encoded witness registry bytes disagree",
        ))?,
    };
    let with_signed_acts = match &input.signed_acts_catalog {
        None => Ok(with_witness.unwrap_or(Value::Null)),
        Some(catalog) => merge_signed_acts_manifest_extension(
            with_witness.as_ref(),
            sha256_bytes(&catalog.bytes),
            &catalog.derivation_rule,
        ),
    }?;
    let with_signed_acts_manifest = match &input.signed_acts_manifest {
        None => with_signed_acts,
        Some(manifest) => merge_signed_acts_manifest_member_extension(
            Some(&with_signed_acts),
            sha256_bytes(&manifest.bytes),
            &manifest.derivation_rule,
        )?,
    };
    match &input.policy_closure {
        None => Ok(with_signed_acts_manifest),
        Some(closure) => merge_policy_closure_manifest_extension(
            Some(&with_signed_acts_manifest),
            sha256_bytes(&closure.bytes),
            &closure.closure_version,
        ),
    }
}

fn merge_seal_fence_manifest_extension(
    base_extensions: Option<&Value>,
    seal_fence: &ExportSealFence,
    head_checkpoint_digest: [u8; 32],
    events_digest: [u8; 32],
    policy_closure_digest: Option<[u8; 32]>,
) -> Result<Value, StackError> {
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    if let Some(Value::Map(entries)) = base_extensions {
        for (key, value) in entries {
            if key.as_text() == Some(SEAL_FENCE_MANIFEST_EXTENSION) {
                continue;
            }
            pairs.push((key.clone(), value.clone()));
        }
    }
    let seal_payload = text_map(vec![
        (
            "identity_rule",
            Value::Text("trellis-export-seal-fence-v1".to_string()),
        ),
        (
            "bundle_scope",
            Value::Bytes(seal_fence.bundle_scope.clone()),
        ),
        (
            "export_attempt_id",
            Value::Text(seal_fence.export_attempt_id.clone()),
        ),
        ("seal_version", uint(seal_fence.seal_version)),
        ("event_count", uint(seal_fence.event_count)),
        ("high_water_sequence", uint(seal_fence.high_water_sequence)),
        (
            "head_checkpoint_digest",
            Value::Bytes(head_checkpoint_digest.to_vec()),
        ),
        ("events_digest", Value::Bytes(events_digest.to_vec())),
        (
            "policy_closure_digest",
            policy_closure_digest.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        ),
    ])?;
    pairs.push((
        Value::Text(SEAL_FENCE_MANIFEST_EXTENSION.to_string()),
        seal_payload,
    ));
    canonical_map(pairs)
}

fn merge_witness_registry_manifest_extension(
    base_extensions: Option<&Value>,
    digest: [u8; 32],
    entry_count: u64,
) -> Result<Value, StackError> {
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    if let Some(Value::Map(entries)) = base_extensions {
        for (key, value) in entries {
            if key.as_text() == Some(WITNESS_REGISTRY_MANIFEST_EXTENSION) {
                continue;
            }
            pairs.push((key.clone(), value.clone()));
        }
    }
    let witness_payload = text_map(vec![
        ("entry_count", uint(entry_count)),
        ("witness_key_registry_digest", Value::Bytes(digest.to_vec())),
    ])?;
    pairs.push((
        Value::Text(WITNESS_REGISTRY_MANIFEST_EXTENSION.to_string()),
        witness_payload,
    ));
    canonical_map(pairs)
}

fn merge_signed_acts_manifest_extension(
    base_extensions: Option<&Value>,
    digest: [u8; 32],
    derivation_rule: &str,
) -> Result<Value, StackError> {
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    if let Some(Value::Map(entries)) = base_extensions {
        for (key, value) in entries {
            if key.as_text() == Some(SIGNED_ACTS_MANIFEST_EXTENSION) {
                continue;
            }
            pairs.push((key.clone(), value.clone()));
        }
    }
    let signed_acts_payload = text_map(vec![
        ("catalog_digest", Value::Bytes(digest.to_vec())),
        ("catalog_ref", Value::Text(SIGNED_ACTS_MEMBER.to_string())),
        ("derivation_rule", Value::Text(derivation_rule.to_string())),
    ])?;
    pairs.push((
        Value::Text(SIGNED_ACTS_MANIFEST_EXTENSION.to_string()),
        signed_acts_payload,
    ));
    canonical_map(pairs)
}

fn merge_signed_acts_manifest_member_extension(
    base_extensions: Option<&Value>,
    digest: [u8; 32],
    derivation_rule: &str,
) -> Result<Value, StackError> {
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    if let Some(Value::Map(entries)) = base_extensions {
        for (key, value) in entries {
            if key.as_text() == Some(SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION) {
                continue;
            }
            pairs.push((key.clone(), value.clone()));
        }
    }
    let manifest_payload = text_map(vec![
        (
            "catalog_ref",
            Value::Text(SIGNED_ACTS_MANIFEST_MEMBER.to_string()),
        ),
        ("derivation_rule", Value::Text(derivation_rule.to_string())),
        ("manifest_digest", Value::Bytes(digest.to_vec())),
    ])?;
    pairs.push((
        Value::Text(SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION.to_string()),
        manifest_payload,
    ));
    canonical_map(pairs)
}

fn merge_policy_closure_manifest_extension(
    base_extensions: Option<&Value>,
    digest: [u8; 32],
    closure_version: &str,
) -> Result<Value, StackError> {
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    if let Some(Value::Map(entries)) = base_extensions {
        for (key, value) in entries {
            if key.as_text() == Some(POLICY_CLOSURE_MANIFEST_EXTENSION) {
                continue;
            }
            pairs.push((key.clone(), value.clone()));
        }
    }
    let closure_payload = text_map(vec![
        ("closure_digest", Value::Bytes(digest.to_vec())),
        (
            "closure_ref",
            Value::Text(POLICY_CLOSURE_MEMBER.to_string()),
        ),
        ("closure_version", Value::Text(closure_version.to_string())),
    ])?;
    pairs.push((
        Value::Text(POLICY_CLOSURE_MANIFEST_EXTENSION.to_string()),
        closure_payload,
    ));
    canonical_map(pairs)
}

fn validate_top_level_input(input: &ExportWriterInput) -> Result<(), StackError> {
    if input.scope.is_empty() {
        return Err(StackError::bad_request("export scope must not be empty"));
    }
    if !input.scope.is_ascii() {
        return Err(StackError::bad_request(
            "export scope must be ASCII for deterministic ZIP paths",
        ));
    }
    if input.events.is_empty() {
        return Err(StackError::bad_request(
            "export requires at least one stored event",
        ));
    }
    if input.events.len() != input.checkpoints.len() {
        return Err(StackError::bad_request(format!(
            "checkpoint count {} does not match event count {}",
            input.checkpoints.len(),
            input.events.len()
        )));
    }
    if input.registries.is_empty() {
        return Err(StackError::bad_request(
            "export requires at least one registry snapshot",
        ));
    }
    if input.generator.is_empty() {
        return Err(StackError::bad_request(
            "export generator must not be empty",
        ));
    }
    if input.readme_title.is_empty() {
        return Err(StackError::bad_request("README title must not be empty"));
    }
    if let Some(root_dir) = &input.root_dir_override {
        validate_ascii_path_segment(root_dir, "root_dir_override")?;
    }
    if input.witness_key_registry.is_none() {
        if let Some(Value::Map(entries)) = &input.extensions
            && entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(WITNESS_REGISTRY_MANIFEST_EXTENSION))
        {
            return Err(StackError::bad_request(
                "manifest extensions include trellis.export.witness-key-registry.v1 \
                 but witness_key_registry was not provided",
            ));
        }
    }
    if input.seal_fence.is_none() {
        if let Some(Value::Map(entries)) = &input.extensions
            && entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(SEAL_FENCE_MANIFEST_EXTENSION))
        {
            return Err(StackError::bad_request(
                "manifest extensions include trellis.export.seal-fence.v1 \
                 but seal_fence was not provided",
            ));
        }
    }
    if input.signed_acts_catalog.is_none() {
        if let Some(Value::Map(entries)) = &input.extensions
            && entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(SIGNED_ACTS_MANIFEST_EXTENSION))
        {
            return Err(StackError::bad_request(
                "manifest extensions include trellis.export.signed-acts.v1 \
                 but signed_acts_catalog was not provided",
            ));
        }
    }
    if input.signed_acts_manifest.is_none() {
        if let Some(Value::Map(entries)) = &input.extensions
            && entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION))
        {
            return Err(StackError::bad_request(
                "manifest extensions include trellis.export.signed-acts.manifest.v1 \
                 but signed_acts_manifest was not provided",
            ));
        }
    }
    if input.policy_closure.is_none() {
        if let Some(Value::Map(entries)) = &input.extensions
            && entries
                .iter()
                .any(|(key, _)| key.as_text() == Some(POLICY_CLOSURE_MANIFEST_EXTENSION))
        {
            return Err(StackError::bad_request(
                "manifest extensions include trellis.export.policy-closure.v1 \
                 but policy_closure was not provided",
            ));
        }
    }
    if let Some(catalog) = &input.signed_acts_catalog {
        if catalog.bytes.is_empty() {
            return Err(StackError::bad_request(
                "signed_acts_catalog bytes must not be empty",
            ));
        }
        decode_cbor_value(&catalog.bytes).map_err(|error| {
            StackError::bad_request(format!("signed_acts_catalog is invalid CBOR: {error}"))
        })?;
        if catalog.derivation_rule.trim().is_empty() {
            return Err(StackError::bad_request(
                "signed_acts_catalog derivation_rule must not be empty",
            ));
        }
    }
    if let Some(manifest) = &input.signed_acts_manifest {
        if manifest.bytes.is_empty() {
            return Err(StackError::bad_request(
                "signed_acts_manifest bytes must not be empty",
            ));
        }
        decode_cbor_value(&manifest.bytes).map_err(|error| {
            StackError::bad_request(format!("signed_acts_manifest is invalid CBOR: {error}"))
        })?;
        if manifest.derivation_rule.trim().is_empty() {
            return Err(StackError::bad_request(
                "signed_acts_manifest derivation_rule must not be empty",
            ));
        }
    }
    if let Some(closure) = &input.policy_closure {
        if closure.bytes.is_empty() {
            return Err(StackError::bad_request(
                "policy_closure bytes must not be empty",
            ));
        }
        decode_cbor_value(&closure.bytes).map_err(|error| {
            StackError::bad_request(format!("policy_closure is invalid CBOR: {error}"))
        })?;
        if closure.closure_version.trim().is_empty() {
            return Err(StackError::bad_request(
                "policy_closure closure_version must not be empty",
            ));
        }
    }
    Ok(())
}

fn validate_seal_fence(
    input: &ExportWriterInput,
    events: &[PreparedEvent],
) -> Result<(), StackError> {
    let Some(seal_fence) = &input.seal_fence else {
        return Ok(());
    };
    if seal_fence.bundle_scope != input.scope {
        return Err(StackError::bad_request(
            "seal_fence bundle_scope must match export scope",
        ));
    }
    if seal_fence.export_attempt_id.is_empty() {
        return Err(StackError::bad_request(
            "seal_fence export_attempt_id must not be empty",
        ));
    }
    if seal_fence.seal_version == 0 {
        return Err(StackError::bad_request(
            "seal_fence seal_version must be positive",
        ));
    }
    let event_count =
        u64::try_from(events.len()).map_err(|_| StackError::internal("event count exceeds u64"))?;
    if seal_fence.event_count != event_count {
        return Err(StackError::bad_request(format!(
            "seal_fence event_count {} does not match export event count {event_count}",
            seal_fence.event_count
        )));
    }
    let high_water_sequence = events
        .last()
        .map(|event| event.sequence)
        .ok_or_else(|| StackError::internal("prepared events unexpectedly empty"))?;
    if seal_fence.high_water_sequence != high_water_sequence {
        return Err(StackError::bad_request(format!(
            "seal_fence high_water_sequence {} does not match export high-water sequence {high_water_sequence}",
            seal_fence.high_water_sequence
        )));
    }
    let high_water_event_hash = events
        .last()
        .map(|event| event.canonical_event_hash)
        .ok_or_else(|| StackError::internal("prepared events unexpectedly empty"))?;
    let expected_export_attempt_id = export_attempt_id(
        &seal_fence.bundle_scope,
        seal_fence.seal_version,
        seal_fence.high_water_sequence,
        high_water_event_hash,
    )?;
    if seal_fence.export_attempt_id != expected_export_attempt_id {
        return Err(StackError::bad_request(format!(
            "seal_fence export_attempt_id {} does not match deterministic identity {expected_export_attempt_id}",
            seal_fence.export_attempt_id
        )));
    }
    Ok(())
}

fn prepare_events(input: &ExportWriterInput) -> Result<Vec<PreparedEvent>, StackError> {
    let mut events = input.events.clone();
    events.sort_by_key(StoredEvent::sequence);
    let mut prepared = Vec::with_capacity(events.len());
    for (expected_sequence, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(expected_sequence)
            .map_err(|_| StackError::internal("event count exceeds u64"))?;
        if event.sequence() != expected_sequence {
            return Err(StackError::bad_request(format!(
                "stored events must be contiguous from sequence 0; expected {expected_sequence}, got {}",
                event.sequence()
            )));
        }
        if event.scope() != input.scope.as_slice() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} scope does not match export scope",
                event.sequence()
            )));
        }
        let payload = decode_cbor_value(event.canonical_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} canonical payload is invalid CBOR: {error}",
                event.sequence()
            ))
        })?;
        let payload_map = payload.as_map().ok_or_else(|| {
            StackError::bad_request(format!(
                "stored event sequence {} canonical payload is not a map",
                event.sequence()
            ))
        })?;
        let payload_scope = map_lookup_bytes(payload_map, "ledger_scope").map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} ledger_scope is invalid: {error}",
                event.sequence()
            ))
        })?;
        if payload_scope != input.scope {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} payload scope does not match export scope",
                event.sequence()
            )));
        }
        let payload_sequence = map_lookup_u64(payload_map, "sequence").map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} payload sequence is invalid: {error}",
                event.sequence()
            ))
        })?;
        if payload_sequence != event.sequence() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} payload sequence is {payload_sequence}",
                event.sequence()
            )));
        }
        let signed = integrity_cose::decode_cose_sign1(event.signed_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} signed event is invalid COSE_Sign1: {error}",
                event.sequence()
            ))
        })?;
        let signed_payload = signed.payload().ok_or_else(|| {
            StackError::bad_request(format!(
                "stored event sequence {} uses a detached payload; export/001 Phase-1 requires embedded event payloads",
                event.sequence()
            ))
        })?;
        if signed_payload != event.canonical_event() {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} signed payload does not match canonical payload bytes",
                event.sequence()
            )));
        }
        decode_cbor_value(event.signed_event()).map_err(|error| {
            StackError::bad_request(format!(
                "stored event sequence {} signed event is invalid CBOR: {error}",
                event.sequence()
            ))
        })?;
        let canonical_event_hash = canonical_event_hash(&input.scope, event.canonical_event());
        if let Some(stored_hash) = event.canonical_event_hash()
            && stored_hash != &canonical_event_hash
        {
            return Err(StackError::bad_request(format!(
                "stored event sequence {} canonical_event_hash does not match payload bytes",
                event.sequence()
            )));
        }
        let leaf_hash = TrellisHasher.leaf(&canonical_event_hash);
        prepared.push(PreparedEvent {
            sequence: event.sequence(),
            canonical_event: event.canonical_event().to_vec(),
            signed_event: event.signed_event().to_vec(),
            canonical_event_hash,
            leaf_hash,
        });
    }
    Ok(prepared)
}

fn registry_binding_material(
    registries: &[RegistrySnapshot],
) -> Result<Vec<RegistryBindingMaterial>, StackError> {
    let mut sorted = registries.to_vec();
    sorted.sort_by(|left, right| {
        left.bound_at_sequence
            .cmp(&right.bound_at_sequence)
            .then_with(|| left.registry_version.cmp(&right.registry_version))
    });
    let mut seen_members = BTreeMap::new();
    let mut material = Vec::with_capacity(sorted.len());
    for registry in sorted {
        if registry.bytes.is_empty() {
            return Err(StackError::bad_request(
                "registry snapshot bytes must not be empty",
            ));
        }
        if registry.registry_version.is_empty() {
            return Err(StackError::bad_request(
                "registry snapshot version must not be empty",
            ));
        }
        let digest = sha256_bytes(&registry.bytes);
        let digest_hex = hex_lower(&digest);
        let member = format!("{REGISTRY_DIR}/{digest_hex}.cbor");
        if seen_members.insert(member.clone(), ()).is_some() {
            return Err(StackError::bad_request(format!(
                "duplicate registry snapshot digest {digest_hex}"
            )));
        }
        let value = text_map(vec![
            ("registry_digest", Value::Bytes(digest.to_vec())),
            ("registry_format", uint(registry.registry_format)),
            (
                "registry_version",
                Value::Text(registry.registry_version.clone()),
            ),
            ("bound_at_sequence", uint(registry.bound_at_sequence)),
        ])?;
        material.push(RegistryBindingMaterial {
            member,
            bytes: registry.bytes,
            value,
        });
    }
    Ok(material)
}

/// Encodes the supplied key history after checking it is complete for this export (Core §8.5).
///
/// Every `kid` an event, a checkpoint or the manifest cites must resolve to a row, every
/// `supersedes` must resolve to a row, and `kid`s are unique and equal to the key they name.
fn checked_signing_key_registry(
    input: &ExportWriterInput,
    events: &[PreparedEvent],
) -> Result<Vec<u8>, StackError> {
    let mut rows = BTreeMap::new();
    for entry in &input.signing_key_registry {
        if entry.kid != derive_kid(SUITE_ID_PHASE_1, entry.public_key) {
            return Err(StackError::bad_request(
                "signing-key registry kid is not derived from its public key",
            ));
        }
        if rows.insert(entry.kid, entry).is_some() {
            return Err(StackError::bad_request(
                "signing-key registry repeats a kid",
            ));
        }
    }
    // The verifier enforces `valid_to` only for revoked keys, so a mistyped window would ship
    // unnoticed: the writer refuses any signature made outside its key's window.
    let cited = |kid: Option<&[u8]>, signed_at: (u64, u32), what: &str| -> Result<(), StackError> {
        let row = kid
            .and_then(|kid| <[u8; 16]>::try_from(kid).ok())
            .and_then(|kid| rows.get(&kid));
        let Some(row) = row else {
            return Err(StackError::bad_request(format!(
                "signing-key registry has no row for the kid {what} cites"
            )));
        };
        let pair = |t: TrellisTimestamp| (t.unix_secs, t.subsec_nanos);
        if signed_at < pair(row.valid_from) || row.valid_to.is_some_and(|to| signed_at > pair(to)) {
            return Err(StackError::bad_request(format!(
                "{what} was signed outside the validity window of its signing key"
            )));
        }
        Ok(())
    };
    if !rows.contains_key(&input.signing_key.kid()) {
        return Err(StackError::bad_request(
            "signing-key registry has no row for the kid the manifest cites",
        ));
    }
    for entry in rows.values() {
        if entry
            .supersedes
            .is_some_and(|prior| !rows.contains_key(&prior))
        {
            return Err(StackError::bad_request(
                "signing-key registry has no row for the kid a supersedes link cites",
            ));
        }
    }
    for event in events {
        let signed = integrity_cose::decode_cose_sign1(&event.signed_event)
            .map_err(|error| StackError::bad_request(format!("event COSE_Sign1: {error}")))?;
        cited(
            signed.kid(),
            authored_at(&event.canonical_event)?,
            "an event",
        )?;
    }
    for checkpoint in &input.checkpoints {
        let signed = integrity_cose::decode_cose_sign1(&checkpoint.checkpoint)
            .map_err(|error| StackError::bad_request(format!("checkpoint COSE_Sign1: {error}")))?;
        let payload = CheckpointPayload::from_sign1(&checkpoint.checkpoint)
            .map_err(|error| StackError::bad_request(format!("checkpoint payload: {error}")))?;
        cited(signed.kid(), payload.timestamp, "a checkpoint")?;
    }
    encode_signing_key_registry(&input.signing_key_registry)
}

/// `header.authored_at` of a canonical event payload.
fn authored_at(canonical_event: &[u8]) -> Result<(u64, u32), StackError> {
    let invalid = || StackError::bad_request("event header authored_at is invalid");
    let value = decode_cbor_value(canonical_event).map_err(|_| invalid())?;
    let header =
        map_lookup_map(value.as_map().ok_or_else(invalid)?, "header").map_err(|_| invalid())?;
    let pair = map_lookup_array(header, "authored_at").map_err(|_| invalid())?;
    let integer = |value: &Value| {
        value
            .as_integer()
            .and_then(|integer| u64::try_from(i128::from(integer)).ok())
    };
    match pair {
        [secs, nanos] => Ok((
            integer(secs).ok_or_else(invalid)?,
            u32::try_from(integer(nanos).ok_or_else(invalid)?).map_err(|_| invalid())?,
        )),
        _ => Err(invalid()),
    }
}

/// The checkpoints an export carries, checked against the events it carries.
///
/// A supplied checkpoint is trusted only as far as the writer can see without a key: one per
/// prefix in order, each digest recomputed from its own payload, each chained to the one before,
/// and the head committing to the tree root built here. Signatures are the verifier's concern.
fn supplied_checkpoints(
    input: &ExportWriterInput,
    tree_head_hash: [u8; 32],
) -> Result<&[StoredCheckpoint], StackError> {
    let mismatch = |tree_size: usize, what: &str| {
        StackError::internal(format!("supplied checkpoint {tree_size}: {what}"))
    };
    let mut prior_digest = None;
    for (index, checkpoint) in input.checkpoints.iter().enumerate() {
        let tree_size = index + 1;
        let payload = CheckpointPayload::from_sign1(&checkpoint.checkpoint)
            .map_err(|error| mismatch(tree_size, &error.to_string()))?;
        if payload.scope != input.scope
            || checkpoint.scope != input.scope
            || payload.tree_size != tree_size as u64
            || checkpoint.tree_size != tree_size as u64
        {
            return Err(mismatch(
                tree_size,
                "scope or tree size differs from its position",
            ));
        }
        let encoded = payload
            .encode()
            .map_err(|error| mismatch(tree_size, &error.to_string()))?;
        if checkpoint_digest(&input.scope, &encoded) != checkpoint.digest {
            return Err(mismatch(tree_size, "digest differs from its payload"));
        }
        if payload.prev_checkpoint_hash != prior_digest {
            return Err(mismatch(
                tree_size,
                "does not chain to the checkpoint before it",
            ));
        }
        prior_digest = Some(checkpoint.digest);
        if tree_size == input.checkpoints.len() && payload.tree_head_hash != tree_head_hash {
            return Err(mismatch(
                tree_size,
                "head root differs from the exported events",
            ));
        }
    }
    Ok(&input.checkpoints)
}

fn merkle_error(error: trellis_types::merkle::MerkleError) -> StackError {
    StackError::internal(format!("Merkle tree: {error}"))
}

fn inclusion_proofs_cbor<H: MerkleHasher>(
    events: &[PreparedEvent],
    tree: &MerkleTree<'_, H>,
) -> Result<Vec<u8>, StackError> {
    let tree_size = events.len() as u64;
    let mut proofs = Vec::with_capacity(events.len());
    for event in events {
        let audit_path = tree
            .inclusion_proof(event.sequence, tree_size)
            .map_err(merkle_error)?;
        let proof = text_map(vec![
            ("leaf_index", uint(event.sequence)),
            ("tree_size", uint(tree_size)),
            ("leaf_hash", Value::Bytes(event.leaf_hash.to_vec())),
            (
                "audit_path",
                Value::Array(
                    audit_path
                        .into_iter()
                        .map(|digest| Value::Bytes(digest.to_vec()))
                        .collect(),
                ),
            ),
        ])?;
        proofs.push((uint(event.sequence), proof));
    }
    let value = canonical_map(proofs)?;
    encode_value(&value)
}

fn consistency_proofs_cbor<H: MerkleHasher>(
    events: &[PreparedEvent],
    tree: &MerkleTree<'_, H>,
) -> Result<Vec<u8>, StackError> {
    let to_tree_size = events.len() as u64;
    let mut records = Vec::new();
    for from_tree_size in 1..to_tree_size {
        let proof_path = tree
            .consistency_proof(from_tree_size, to_tree_size)
            .map_err(merkle_error)?;
        let record = text_map(vec![
            ("from_tree_size", uint(from_tree_size)),
            ("to_tree_size", uint(to_tree_size)),
            (
                "proof_path",
                Value::Array(
                    proof_path
                        .into_iter()
                        .map(|digest| Value::Bytes(digest.to_vec()))
                        .collect(),
                ),
            ),
        ])?;
        records.push(record);
    }
    encode_value(&Value::Array(records))
}

struct ManifestPayloadInput<'a> {
    input: &'a ExportWriterInput,
    tree_size: usize,
    head_checkpoint_digest: [u8; 32],
    registry_bindings: Vec<Value>,
    signing_key_registry_cbor: &'a [u8],
    events_cbor: &'a [u8],
    checkpoints_cbor: &'a [u8],
    inclusion_proofs_cbor: &'a [u8],
    consistency_proofs_cbor: &'a [u8],
    manifest_extensions: Value,
    payloads_inlined: bool,
}

fn manifest_payload_cbor(args: ManifestPayloadInput<'_>) -> Result<Vec<u8>, StackError> {
    let tree_size =
        u64::try_from(args.tree_size).map_err(|_| StackError::internal("tree size exceeds u64"))?;
    let manifest_payload = text_map(vec![
        ("format", Value::Text("trellis-export/1".to_string())),
        ("version", uint(1)),
        ("generator", Value::Text(args.input.generator.clone())),
        ("generated_at", args.input.generated_at.to_value()),
        ("scope", Value::Bytes(args.input.scope.clone())),
        ("tree_size", uint(tree_size)),
        (
            "head_checkpoint_digest",
            Value::Bytes(args.head_checkpoint_digest.to_vec()),
        ),
        ("registry_bindings", Value::Array(args.registry_bindings)),
        (
            "signing_key_registry_digest",
            Value::Bytes(sha256_bytes(args.signing_key_registry_cbor).to_vec()),
        ),
        (
            "events_digest",
            Value::Bytes(sha256_bytes(args.events_cbor).to_vec()),
        ),
        (
            "checkpoints_digest",
            Value::Bytes(sha256_bytes(args.checkpoints_cbor).to_vec()),
        ),
        (
            "inclusion_proofs_digest",
            Value::Bytes(sha256_bytes(args.inclusion_proofs_cbor).to_vec()),
        ),
        (
            "consistency_proofs_digest",
            Value::Bytes(sha256_bytes(args.consistency_proofs_cbor).to_vec()),
        ),
        ("payloads_inlined", Value::Bool(args.payloads_inlined)),
        (
            "external_anchors",
            Value::Array(args.input.external_anchors.clone()),
        ),
        (
            "posture_declaration",
            args.input.posture_declaration.to_value()?,
        ),
        ("head_format_version", uint(1)),
        (
            "omitted_payload_checks",
            Value::Array(args.input.omitted_payload_checks.clone()),
        ),
        ("extensions", args.manifest_extensions.clone()),
    ])?;
    encode_value(&manifest_payload)
}

fn readme_bytes(
    input: &ExportWriterInput,
    tree_size: usize,
    tree_head_hash: [u8; 32],
    head_checkpoint_digest: [u8; 32],
    registries: &[RegistryBindingMaterial],
) -> Result<Vec<u8>, StackError> {
    let scope = std::str::from_utf8(&input.scope).map_err(|error| {
        StackError::bad_request(format!("export scope is not valid UTF-8: {error}"))
    })?;
    let first_registry_digest = registries
        .first()
        .and_then(|registry| {
            registry
                .member
                .strip_prefix(REGISTRY_DIR)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(|rest| rest.strip_suffix(".cbor"))
        })
        .ok_or_else(|| StackError::internal("registry material unexpectedly empty"))?;
    let posture_json = serde_json::to_string_pretty(&input.posture_declaration.to_sorted_json())
        .map_err(|error| StackError::internal(format!("failed to encode posture JSON: {error}")))?;
    let omitted_json = serde_json::to_string(&input.omitted_payload_checks).map_err(|error| {
        StackError::internal(format!("failed to encode omitted checks JSON: {error}"))
    })?;
    let readme = format!(
        "# {}\n\
         \n\
         - scope (manifest.scope): `{scope}`\n\
         - tree_size (manifest.tree_size): `{tree_size}`\n\
         - tree_head_hash (checkpoint[{}].tree_head_hash): `{}`\n\
         - head_checkpoint_digest: `{}`\n\
         - registry_digest: `{first_registry_digest}`\n\
         \n\
         ## Posture Declaration (manifest.posture_declaration)\n\
         ```json\n\
         {posture_json}\n\
         ```\n\
         \n\
         ## Omitted payload checks\n\
         ```json\n\
         {omitted_json}\n\
         ```\n\
         \n\
         ## Verify\n\
         Run `./090-verify.sh` from this directory (or run your verifier directly).\n",
        input.readme_title,
        tree_size - 1,
        hex_lower(&tree_head_hash),
        hex_lower(&head_checkpoint_digest),
    );
    Ok(readme.into_bytes())
}

fn default_verify_script() -> Vec<u8> {
    ("#!/bin/sh\n\
         set -eu\n\
         \n\
         # Trellis export verifier invocation (\u{00a7}18.8).\n\
         #\n\
         # Pass the export ZIP path as the only argument; the operator CLI\n\
         # verifies it through trellis-verify-wos.\n\
         \n\
         if [ \"$#\" -ne 1 ]; then\n\
         \x20 echo \"usage: $0 <export.zip>\" >&2\n\
         \x20 exit 2\n\
         fi\n\
         \n\
         if command -v trellis-cli >/dev/null 2>&1; then\n\
         \x20 exec trellis-cli verify-export \"$1\"\n\
         fi\n\
         \n\
         echo \"trellis-cli not found in PATH.\" >&2\n\
         echo \"Run `trellis-cli verify-export $1`.\" >&2\n\
         exit 2\n")
        .as_bytes()
        .to_vec()
}

fn root_dir(scope: &[u8], tree_size: usize, tree_head_hash: [u8; 32]) -> String {
    let scope = std::str::from_utf8(scope).expect("validated ASCII scope is valid UTF-8");
    let head_hex = hex_lower(&tree_head_hash);
    format!("trellis-export-{scope}-{tree_size}-{}", &head_hex[..8])
}

/// COSE EdDSA algorithm identifier used by Trellis Phase 1.
const ALG_EDDSA: i32 = -8;

fn sign_cose(
    signing_key: &SigningKeyMaterial,
    artifact_type: ArtifactType,
    payload: &[u8],
) -> Vec<u8> {
    let protected_header = substrate_protected_header(
        ALG_EDDSA,
        &signing_key.kid(),
        SUITE_ID_PHASE_1,
        artifact_type.cose_value(),
    );
    let sig_structure = sig_structure_bytes(&protected_header, payload);
    let signature = sign_ed25519(signing_key.private_seed, &sig_structure);
    sign1_bytes(&protected_header, payload, signature)
}

fn canonical_event_hash(scope: &[u8], canonical_event_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("ledger_scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("event_payload"));
    preimage.extend_from_slice(canonical_event_bytes);
    domain_separated_sha256(EVENT_DOMAIN, &preimage)
}

fn export_manifest_digest(scope: &[u8], manifest_payload_bytes: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.push(0xa3);
    preimage.extend_from_slice(&encode_tstr("scope"));
    preimage.extend_from_slice(&encode_bstr(scope));
    preimage.extend_from_slice(&encode_tstr("version"));
    preimage.extend_from_slice(&encode_uint(1));
    preimage.extend_from_slice(&encode_tstr("manifest_payload"));
    preimage.extend_from_slice(manifest_payload_bytes);
    domain_separated_sha256(EXPORT_MANIFEST_DOMAIN, &preimage)
}

fn export_attempt_id(
    scope: &[u8],
    seal_version: u64,
    high_water_sequence: u64,
    high_water_event_hash: [u8; 32],
) -> Result<String, StackError> {
    let material = text_map(vec![
        ("bundle_scope", Value::Bytes(scope.to_vec())),
        ("seal_version", uint(seal_version)),
        ("high_water_sequence", uint(high_water_sequence)),
        (
            "high_water_event_hash",
            Value::Bytes(high_water_event_hash.to_vec()),
        ),
    ])?;
    let digest = domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, &encode_value(&material)?);
    Ok(format!("sha256:{}", hex_lower(&digest)))
}

fn array_of_raw_cbor_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, StackError> {
    let values = values.into_iter().collect::<Vec<_>>();
    let mut out = encode_major_len(4, values.len() as u64);
    for value in values {
        decode_cbor_value(value)
            .map_err(|error| StackError::bad_request(format!("invalid raw CBOR value: {error}")))?;
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn text_map(fields: Vec<(&str, Value)>) -> Result<Value, StackError> {
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

fn encode_value(value: &Value) -> Result<Vec<u8>, StackError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| StackError::internal(format!("failed to encode CBOR: {error}")))?;
    Ok(bytes)
}

fn encode_major_len(major: u8, value: u64) -> Vec<u8> {
    let prefix = major << 5;
    match value {
        0..=23 => vec![prefix | value as u8],
        24..=0xff => vec![prefix | 24, value as u8],
        0x100..=0xffff => {
            let mut out = vec![prefix | 25];
            out.extend_from_slice(&(value as u16).to_be_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![prefix | 26];
            out.extend_from_slice(&(value as u32).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![prefix | 27];
            out.extend_from_slice(&value.to_be_bytes());
            out
        }
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn option_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::Text(value.to_string()))
}

fn validate_ascii_path_segment(value: &str, label: &str) -> Result<(), StackError> {
    if !value.is_ascii() {
        return Err(StackError::bad_request(format!(
            "{label} must be ASCII for deterministic ZIP paths"
        )));
    }
    if value.contains('/') || value.is_empty() {
        return Err(StackError::bad_request(format!(
            "{label} must be a non-empty single path segment"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use integrity_cbor::{decode_cbor_value, map_lookup_bytes, map_lookup_map, map_lookup_u64};
    use trellis_witness_registry::{
        TrellisTimestamp as WitnessRegistryTimestamp, WitnessKeyEntry, WitnessKind,
    };

    use super::*;

    fn native_input() -> ExportWriterInput {
        crate::export_001_writer_input(&fixtures_root())
    }

    #[test]
    fn evidence_catalogs_bind_exact_native_bytes_and_fixed_paths() {
        let root = fixtures_root();
        let specs = [
            (
                "export/010-certificate-of-completion-inline/061-attachments.cbor",
                0,
            ),
            (
                "export/006-signature-affirmations-inline/062-signature-affirmations.cbor",
                1,
            ),
            (
                "export/007-intake-handoffs-public-create/063-intake-handoffs.cbor",
                2,
            ),
            (
                "export/010-certificate-of-completion-inline/065-certificates-of-completion.cbor",
                3,
            ),
        ];
        // These are isolated byte/binding checks, not joined ledger histories.
        for (source, index) in specs {
            let bytes = read(&root, source);
            let member = match index {
                0 => ExportEvidenceMember::Attachments {
                    bytes: bytes.clone(),
                    inline_attachments: true,
                },
                1 => ExportEvidenceMember::SignatureAffirmations {
                    bytes: bytes.clone(),
                },
                2 => ExportEvidenceMember::IntakeHandoffs {
                    bytes: bytes.clone(),
                },
                _ => ExportEvidenceMember::CertificatesOfCompletion {
                    bytes: bytes.clone(),
                },
            };
            let mut input = native_input();
            input.evidence_members = vec![member];
            let prepared =
                prepare_evidence_members(&input, "test-root").expect("native catalog accepted");
            assert_eq!(prepared.entries.len(), 1);
            assert_eq!(
                prepared.entries[0].path(),
                format!("test-root/{}", EVIDENCE_BINDINGS[index].0)
            );
            assert_eq!(prepared.entries[0].bytes(), bytes);
            let bound = prepared.bindings[0].1.as_map().expect("binding map");
            assert_eq!(
                map_lookup_bytes(bound, EVIDENCE_BINDINGS[index].2).expect("digest"),
                sha256_bytes(&bytes)
            );
            if index == 0 {
                assert!(
                    bound
                        .iter()
                        .any(|(k, v)| k.as_text() == Some("inline_attachments")
                            && *v == Value::Bool(true))
                );
            }
            if index == 3 {
                assert!(bound.iter().any(|(k, v)| k.as_text() == Some("catalog_ref")
                    && v.as_text() == Some(EVIDENCE_BINDINGS[index].0)));
                assert_eq!(map_lookup_u64(bound, "entry_count").expect("count"), 1);
            }
        }
    }

    #[test]
    fn evidence_rejects_duplicates_bad_hashes_and_noncanonical_catalogs() {
        let bytes = b"exact ciphertext".to_vec();
        let payload = ExportEvidenceMember::Payload {
            content_hash: domain_separated_sha256("trellis-content-v1", &bytes),
            bytes,
        };
        let mut input = native_input();
        input.evidence_members = vec![payload.clone(), payload];
        assert!(
            write_export(input)
                .expect_err("duplicate payload")
                .to_string()
                .contains("duplicate evidence")
        );
        let mut input = native_input();
        input.evidence_members = vec![ExportEvidenceMember::Payload {
            content_hash: [0; 32],
            bytes: vec![1],
        }];
        assert!(
            write_export(input)
                .expect_err("wrong hash")
                .to_string()
                .contains("content hash")
        );
        for index in 0..5 {
            let member = match index {
                0 => ExportEvidenceMember::Attachments {
                    bytes: vec![0x80],
                    inline_attachments: false,
                },
                1 => ExportEvidenceMember::SignatureAffirmations { bytes: vec![0x80] },
                2 => ExportEvidenceMember::IntakeHandoffs { bytes: vec![0x80] },
                3 => ExportEvidenceMember::CertificatesOfCompletion { bytes: vec![0x80] },
                _ => ExportEvidenceMember::OpenClocks {
                    bytes: b"{\"open_clocks\":[]}".to_vec(),
                },
            };
            let mut input = native_input();
            input.evidence_members = vec![member.clone(), member];
            assert!(
                write_export(input)
                    .expect_err("duplicate family")
                    .to_string()
                    .contains("duplicate evidence")
            );
        }
        for bytes in [
            vec![0x81, 0xa2, 0x61, b'b', 1, 0x61, b'a', 2], // unsorted nested map
            vec![0x81, 0xa2, 0x61, b'a', 1, 0x61, b'a', 2], // duplicate nested key
            vec![0xa0],                                     // wrong catalog shape
            vec![0x81],                                     // truncated
        ] {
            let mut input = native_input();
            input.evidence_members = vec![ExportEvidenceMember::IntakeHandoffs { bytes }];
            assert!(write_export(input).is_err(), "invalid catalog accepted");
        }
    }

    #[test]
    fn registered_evidence_extension_requires_member_and_preserves_unknown_extensions() {
        for (_, extension, _) in EVIDENCE_BINDINGS {
            let mut input = native_input();
            input.extensions = Some(Value::Map(vec![(
                Value::Text(extension.to_string()),
                Value::Null,
            )]));
            assert!(
                write_export(input)
                    .expect_err("missing member")
                    .to_string()
                    .contains("requires its evidence member")
            );
        }
        let mut input = native_input();
        input.extensions = Some(Value::Map(vec![(
            Value::Text("x-private-test".to_string()),
            uint(7),
        )]));
        input.evidence_members = vec![ExportEvidenceMember::IntakeHandoffs { bytes: vec![0x80] }];
        let package = write_export(input).expect("extension retained");
        let value = decode_cbor_value(&package.manifest_payload).expect("manifest");
        let extensions =
            map_lookup_map(value.as_map().expect("map"), "extensions").expect("extensions");
        assert_eq!(
            map_lookup_u64(extensions, "x-private-test").expect("unknown extension"),
            7
        );
    }

    #[test]
    fn payload_presence_and_catalog_digest_replace_stale_bindings() {
        let bytes = b"exact ciphertext".to_vec();
        let hash = domain_separated_sha256("trellis-content-v1", &bytes);
        let mut input = native_input();
        input.evidence_members = vec![
            ExportEvidenceMember::Payload {
                content_hash: hash,
                bytes: bytes.clone(),
            },
            ExportEvidenceMember::IntakeHandoffs { bytes: vec![0x80] },
        ];
        input.extensions = Some(Value::Map(vec![(
            Value::Text(EVIDENCE_BINDINGS[2].1.to_string()),
            Value::Null,
        )]));
        let package = write_export(input).expect("derived bindings");
        assert_eq!(
            package.member_bytes(&format!("060-payloads/{}.bin", hex_lower(&hash))),
            Some(bytes.as_slice())
        );
        let value = decode_cbor_value(&package.manifest_payload).expect("manifest");
        let map = value.as_map().expect("map");
        assert!(
            map.iter()
                .any(|(k, v)| k.as_text() == Some("payloads_inlined") && *v == Value::Bool(true))
        );
        let ext = map_lookup_map(map, "extensions").expect("extensions");
        let binding = map_lookup_map(ext, EVIDENCE_BINDINGS[2].1).expect("binding");
        assert_eq!(
            map_lookup_bytes(binding, "intake_catalog_digest").expect("digest"),
            sha256_bytes(&[0x80])
        );
    }

    fn open_clock_input() -> ExportWriterInput {
        let mut input = native_input();
        input.generated_at = TrellisTimestamp::new(1777001200, 0).expect("timestamp");
        input.evidence_members = vec![ExportEvidenceMember::OpenClocks {
            bytes: read(
                &fixtures_root(),
                "verify/018-export-043-open-clocks/open-clocks.json",
            ),
        }];
        input
    }

    #[test]
    fn native_open_clock_count_is_derived_and_signed_count_tampering_fails() {
        let mut input = open_clock_input();
        input.extensions = Some(Value::Map(vec![(
            Value::Text(EVIDENCE_BINDINGS[4].1.to_string()),
            text_map(vec![("open_clock_count", uint(99))]).expect("stale count"),
        )]));
        let key = input.signing_key.clone();
        let package = write_export(input).expect("clock export");
        let verified = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
        assert!(verified.trellis.integrity_verified, "{verified:#?}");
        let mut manifest = decode_cbor_value(&package.manifest_payload).expect("manifest");
        let Value::Map(map) = &mut manifest else {
            panic!("manifest map");
        };
        let (_, Value::Map(extensions)) = map
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("extensions"))
            .expect("extensions")
        else {
            panic!("extensions map");
        };
        let (_, Value::Map(binding)) = extensions
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(EVIDENCE_BINDINGS[4].1))
            .expect("clock binding")
        else {
            panic!("binding map");
        };
        assert_eq!(
            map_lookup_u64(binding, "open_clock_count").expect("count"),
            1
        );
        assert_eq!(
            map_lookup_bytes(binding, "open_clocks_digest").expect("digest"),
            sha256_bytes(
                package
                    .member_bytes("open-clocks.json")
                    .expect("clock bytes")
            )
        );
        binding
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("open_clock_count"))
            .expect("count")
            .1 = uint(2);
        let signed = sign_cose(
            &key,
            ArtifactType::Manifest,
            &encode_value(&manifest).expect("tampered payload"),
        );
        let mut bundle = Bundle::new();
        for entry in package.entries {
            if entry.path().ends_with("/000-manifest.cbor") {
                bundle.add_entry(BundleEntry::new(entry.path(), signed.clone()));
            } else {
                bundle.add_entry(entry);
            }
        }
        let report =
            trellis_verify_wos::verify_export_zip(&bundle.to_zip_bytes().expect("test archive"));
        assert!(
            !report.trellis.integrity_verified,
            "signed wrong count accepted"
        );
        assert!(
            format!("{report:?}").contains("open-clocks.json"),
            "{report:#?}"
        );
    }

    #[test]
    fn open_clocks_malformed_input_and_noncanonical_output_refuse() {
        for bytes in [
            b"{".to_vec(),
            b"{}".to_vec(),
            b"{\"open_clocks\":null}".to_vec(),
        ] {
            let mut input = native_input();
            input.evidence_members = vec![ExportEvidenceMember::OpenClocks { bytes }];
            assert!(write_export(input).is_err());
        }
        let mut input = open_clock_input();
        let ExportEvidenceMember::OpenClocks { bytes } = &mut input.evidence_members[0] else {
            unreachable!();
        };
        bytes.push(b'\n');
        let package = write_export(input).expect("opaque carriage does not normalize JSON");
        let report = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
        assert!(
            !report.trellis.integrity_verified,
            "noncanonical JSON accepted by composed verifier"
        );
    }

    #[test]
    fn given_export_001_fixture_inputs_when_write_export_then_zip_and_members_match_fixture() {
        let root = fixtures_root();
        let input = crate::export_001_writer_input(root.as_path());
        let package = write_export(input).expect("write export");
        assert_eq!(
            package.root_dir,
            "trellis-export-test-response-ledger-2-280d3354"
        );
        for member in [
            MANIFEST_MEMBER,
            EVENTS_MEMBER,
            INCLUSION_PROOFS_MEMBER,
            CONSISTENCY_PROOFS_MEMBER,
            SIGNING_KEY_REGISTRY_MEMBER,
            CHECKPOINTS_MEMBER,
            "050-registries/651b13673bfa5c30f422512a2e8282479df6c903ff2d6b1cd56f0dca74d4a78a.cbor",
            VERIFY_MEMBER,
            README_MEMBER,
        ] {
            let actual = package.member_bytes(member).expect("generated member");
            let expected = read(&root, &format!("export/001-two-event-chain/{member}"));
            assert_eq!(
                hex_lower(&sha256_bytes(actual)),
                hex_lower(&sha256_bytes(&expected)),
                "{member} digest differs"
            );
            assert_eq!(actual, expected.as_slice(), "{member} bytes differ");
        }
        let expected = read(&root, "export/001-two-event-chain/expected-export.zip");
        let actual_entries =
            integrity_bundle::read_stored_zip(&package.zip_bytes).expect("actual zip parses");
        let expected_entries =
            integrity_bundle::read_stored_zip(&expected).expect("expected zip parses");
        assert_eq!(actual_entries, expected_entries);
        if package.zip_bytes != expected {
            let first_diff = package
                .zip_bytes
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
                .unwrap_or_else(|| package.zip_bytes.len().min(expected.len()));
            panic!(
                "zip bytes differ at offset {first_diff}: actual={:02x?} expected={:02x?}",
                package.zip_bytes.get(first_diff..first_diff + 16),
                expected.get(first_diff..first_diff + 16)
            );
        }
        let verification = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
        assert!(verification.trellis.structure_verified, "{verification:#?}");
        assert!(verification.trellis.integrity_verified, "{verification:#?}");
        assert_eq!(
            hex_lower(&sha256_bytes(&package.zip_bytes)),
            "e0d6ef2bdc0756a5284e3cb66beb3d79c582b1f5e0231debbe44e41a162ba1fa"
        );
    }

    #[test]
    fn rejects_empty_event_set() {
        let input = ExportWriterInput {
            scope: b"scope".to_vec(),
            events: Vec::new(),
            registries: vec![RegistrySnapshot {
                bytes: vec![0xa0],
                registry_format: 1,
                registry_version: "test".to_string(),
                bound_at_sequence: 0,
            }],
            signing_key: SigningKeyMaterial {
                private_seed: [0; 32],
                public_key: [1; 32],
                valid_from: TrellisTimestamp::new(1, 0).expect("valid timestamp"),
                valid_to: None,
            },
            signing_key_registry: Vec::new(),
            generator: "test".to_string(),
            generated_at: TrellisTimestamp::new(1, 0).expect("valid timestamp"),
            checkpoints: Vec::new(),
            posture_declaration: PostureDeclaration {
                provider_readable: true,
                reader_held: false,
                delegated_compute: false,
                external_anchor_required: false,
                external_anchor_name: None,
                recovery_without_user: true,
                metadata_leakage_summary: "test".to_string(),
            },
            omitted_payload_checks: Vec::new(),
            readme_title: "Trellis Export".to_string(),
            root_dir_override: None,
            external_anchors: Vec::new(),
            extensions: None,
            seal_fence: None,
            witness_key_registry: None,
            signed_acts_catalog: None,
            signed_acts_manifest: None,
            policy_closure: None,
            evidence_members: Vec::new(),
        };
        let error = write_export(input).expect_err("empty export must reject");
        assert!(error.to_string().contains("requires at least one"));
    }

    /// Core §18.3d — policy is explicit `witness_key_registry` presence on [`ExportWriterInput`].
    #[test]
    fn write_export_emits_witness_registry_when_registry_provided() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let registry = WitnessKeyRegistry::new(Vec::new());
        input.witness_key_registry = Some(registry.clone());

        let package = write_export(input).expect("write export");
        let member = package
            .member_bytes(WITNESS_KEY_REGISTRY_MEMBER)
            .expect("031 witness member must be present");

        assert_eq!(
            WitnessKeyRegistry::from_cbor(member).expect("round trip"),
            registry
        );
        assert_eq!(member, registry.to_cbor().expect("encode"));

        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let ext_key = "trellis.export.witness-key-registry.v1";
        let binding = extensions
            .iter()
            .find(|(k, _)| k.as_text() == Some(ext_key))
            .map(|(_, v)| v)
            .expect("witness manifest extension");
        let binding_map = binding.as_map().expect("binding map");
        let digest = map_lookup_bytes(binding_map, "witness_key_registry_digest").expect("digest");
        assert_eq!(
            digest.as_slice(),
            sha256_bytes(member).as_slice(),
            "manifest digest must match witness member bytes (Core 18.3d)"
        );
        assert_eq!(
            map_lookup_u64(binding_map, "entry_count").expect("count"),
            0
        );

        let verification = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
        assert!(
            verification.trellis.structure_verified && verification.trellis.integrity_verified,
            "witness member must not break export verification: {verification:?}"
        );
    }

    #[test]
    fn rejects_an_export_signed_outside_its_keys_validity_window() {
        let root = fixtures_root();
        // The fixture's events and checkpoints are signed at 1745000000.
        let window = |from: u64, to: Option<u64>| {
            let mut input = crate::export_001_writer_input(root.as_path());
            input.signing_key_registry[0].valid_from = TrellisTimestamp::new(from, 0).unwrap();
            input.signing_key_registry[0].valid_to =
                to.map(|to| TrellisTimestamp::new(to, 0).unwrap());
            write_export(input)
        };
        window(1_745_000_000, Some(1_745_000_100)).expect("a window holding the signatures");
        for (from, to) in [(1_745_000_001, None), (0, Some(1_744_999_999))] {
            let error = window(from, to).expect_err("out-of-window signatures must be refused");
            assert!(
                error.to_string().contains("outside the validity window"),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_witness_manifest_extension_without_registry() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let stale_binding = text_map(vec![
            ("entry_count", uint(0)),
            (
                "witness_key_registry_digest",
                Value::Bytes([0xee; 32].to_vec()),
            ),
        ])
        .expect("stale witness binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(WITNESS_REGISTRY_MANIFEST_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.witness_key_registry = None;
        let error = write_export(input).expect_err("extension without registry must reject");
        assert!(
            error
                .to_string()
                .contains("witness_key_registry was not provided"),
            "{error}"
        );
    }

    #[test]
    fn write_export_binds_seal_fence_when_provided() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let prepared_events = prepare_events(&input).expect("prepare events");
        let high_water_event_hash = prepared_events
            .last()
            .expect("fixture has events")
            .canonical_event_hash;
        let export_attempt_id =
            export_attempt_id(&input.scope, 2, 1, high_water_event_hash).expect("attempt id");
        input.seal_fence = Some(ExportSealFence {
            bundle_scope: input.scope.clone(),
            export_attempt_id: export_attempt_id.clone(),
            seal_version: 2,
            event_count: 2,
            high_water_sequence: 1,
        });
        let expected_scope = input.scope.clone();

        let package = write_export(input).expect("write export");
        let events_member = package
            .member_bytes(EVENTS_MEMBER)
            .expect("events member must be present");
        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let binding_map = extensions
            .iter()
            .find(|(key, _)| key.as_text() == Some(SEAL_FENCE_MANIFEST_EXTENSION))
            .map(|(_, value)| value.as_map().expect("seal fence binding"))
            .expect("seal fence extension");

        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("identity_rule"))
                .and_then(|(_, value)| value.as_text()),
            Some("trellis-export-seal-fence-v1")
        );
        assert_eq!(
            map_lookup_bytes(binding_map, "bundle_scope")
                .expect("bundle scope")
                .as_slice(),
            expected_scope.as_slice()
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("export_attempt_id"))
                .and_then(|(_, value)| value.as_text()),
            Some(export_attempt_id.as_str())
        );
        assert_eq!(
            map_lookup_bytes(binding_map, "head_checkpoint_digest")
                .expect("head checkpoint digest")
                .as_slice(),
            package.head_checkpoint_digest.as_slice()
        );
        assert_eq!(
            map_lookup_bytes(binding_map, "events_digest")
                .expect("events digest")
                .as_slice(),
            sha256_bytes(events_member).as_slice()
        );
        assert_eq!(
            map_lookup_u64(binding_map, "seal_version").expect("seal version"),
            2
        );
        assert_eq!(
            map_lookup_u64(binding_map, "event_count").expect("event count"),
            2
        );
        assert_eq!(
            map_lookup_u64(binding_map, "high_water_sequence").expect("high water"),
            1
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("policy_closure_digest"))
                .map(|(_, value)| value),
            Some(&Value::Null)
        );
    }

    #[test]
    fn rejects_seal_fence_manifest_extension_without_input() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let stale_binding = text_map(vec![
            (
                "identity_rule",
                Value::Text("trellis-export-seal-fence-v1".to_string()),
            ),
            ("bundle_scope", Value::Bytes(input.scope.clone())),
            ("export_attempt_id", Value::Text("sha256:stale".to_string())),
            ("seal_version", uint(2)),
            ("event_count", uint(2)),
            ("high_water_sequence", uint(1)),
        ])
        .expect("stale seal fence binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(SEAL_FENCE_MANIFEST_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.seal_fence = None;

        let error = write_export(input).expect_err("extension without seal fence must reject");

        assert!(
            error.to_string().contains("seal_fence was not provided"),
            "{error}"
        );
    }

    #[test]
    fn rejects_seal_fence_event_count_mismatch() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        input.seal_fence = Some(ExportSealFence {
            bundle_scope: input.scope.clone(),
            export_attempt_id: "sha256:test-export-attempt".to_string(),
            seal_version: 2,
            event_count: 99,
            high_water_sequence: 1,
        });

        let error = write_export(input).expect_err("wrong event count must reject");

        assert!(error.to_string().contains("event_count 99"), "{error}");
    }

    #[test]
    fn rejects_seal_fence_export_attempt_id_mismatch() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        input.seal_fence = Some(ExportSealFence {
            bundle_scope: input.scope.clone(),
            export_attempt_id: "sha256:test-export-attempt".to_string(),
            seal_version: 2,
            event_count: 2,
            high_water_sequence: 1,
        });

        let error = write_export(input).expect_err("wrong export attempt id must reject");

        assert!(
            error.to_string().contains("deterministic identity"),
            "{error}"
        );
    }

    #[test]
    fn witness_registry_encode_failure_is_bad_request() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let bad_entry = WitnessKeyEntry {
            kid: [1u8; 16],
            pubkey: vec![2u8; 31],
            suite_id: 1,
            effective_from: WitnessRegistryTimestamp::new(1, 0).expect("timestamp"),
            valid_to: None,
            supersedes: None,
            witness_kind: WitnessKind::LocalServer,
        };
        input.witness_key_registry = Some(WitnessKeyRegistry::new(vec![bad_entry]));
        let error = write_export(input).expect_err("invalid witness material must reject");
        assert!(
            error
                .to_string()
                .contains("witness_key_registry is invalid"),
            "{error}"
        );
    }

    #[test]
    fn write_export_overrides_presupplied_witness_extension_with_derived_digest() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let registry = WitnessKeyRegistry::new(Vec::new());
        let stale_binding = text_map(vec![
            ("entry_count", uint(99)),
            (
                "witness_key_registry_digest",
                Value::Bytes([0xdd; 32].to_vec()),
            ),
        ])
        .expect("stale binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(WITNESS_REGISTRY_MANIFEST_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.witness_key_registry = Some(registry.clone());
        let package = write_export(input).expect("write export");
        let member = package
            .member_bytes(WITNESS_KEY_REGISTRY_MEMBER)
            .expect("witness member");
        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let binding_map = extensions
            .iter()
            .find(|(k, _)| k.as_text() == Some(WITNESS_REGISTRY_MANIFEST_EXTENSION))
            .map(|(_, v)| v.as_map().expect("binding"))
            .expect("witness extension");
        let digest = map_lookup_bytes(binding_map, "witness_key_registry_digest")
            .expect("witness_key_registry_digest");
        assert_eq!(digest.as_slice(), sha256_bytes(member).as_slice());
        assert_eq!(
            map_lookup_u64(binding_map, "entry_count").expect("entry_count"),
            0
        );
    }

    #[test]
    fn write_export_binds_signed_acts_catalog_when_provided() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let catalog = SignedActsCatalogMember {
            bytes: encode_value(
                &text_map(vec![
                    ("projection_schema_version", uint(1)),
                    (
                        "acts",
                        Value::Array(vec![
                            text_map(vec![
                                ("act_id", Value::Text("act-001".to_string())),
                                ("outcome", Value::Text("admitted".to_string())),
                            ])
                            .expect("act"),
                        ]),
                    ),
                ])
                .expect("catalog"),
            )
            .expect("catalog bytes"),
            derivation_rule: "signed-act-projection-test-v1".to_string(),
        };
        let expected_digest = sha256_bytes(&catalog.bytes);
        input.signed_acts_catalog = Some(catalog);

        let package = write_export(input).expect("write export");
        let member = package
            .member_bytes(SIGNED_ACTS_MEMBER)
            .expect("066 signed acts member");
        assert_eq!(sha256_bytes(member), expected_digest);

        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let binding_map = extensions
            .iter()
            .find(|(k, _)| k.as_text() == Some(SIGNED_ACTS_MANIFEST_EXTENSION))
            .map(|(_, v)| v.as_map().expect("binding"))
            .expect("signed acts extension");
        assert_eq!(
            map_lookup_bytes(binding_map, "catalog_digest")
                .expect("catalog_digest")
                .as_slice(),
            expected_digest.as_slice()
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("catalog_ref"))
                .and_then(|(_, value)| value.as_text()),
            Some(SIGNED_ACTS_MEMBER)
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("derivation_rule"))
                .and_then(|(_, value)| value.as_text()),
            Some("signed-act-projection-test-v1")
        );
    }

    #[test]
    fn write_export_emits_068_member_when_signed_acts_manifest_provided() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        // Use a syntactically valid CBOR array — verifier doesn't run here, so
        // raw bytes are sufficient to exercise the writer.
        let manifest_bytes = vec![0x80u8]; // CBOR array(0)
        let expected_digest = sha256_bytes(&manifest_bytes);
        input.signed_acts_manifest = Some(SignedActsManifestMember {
            bytes: manifest_bytes.clone(),
            derivation_rule: "signed-acts-manifest-v1".to_string(),
        });

        let package = write_export(input).expect("write export");
        let member = package
            .member_bytes(SIGNED_ACTS_MANIFEST_MEMBER)
            .expect("068 signed acts manifest member");
        assert_eq!(member, manifest_bytes.as_slice());
        assert_eq!(sha256_bytes(member), expected_digest);

        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let binding_map = extensions
            .iter()
            .find(|(k, _)| k.as_text() == Some(SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION))
            .map(|(_, v)| v.as_map().expect("binding"))
            .expect("068 signed acts manifest extension");
        assert_eq!(
            map_lookup_bytes(binding_map, "manifest_digest")
                .expect("manifest_digest")
                .as_slice(),
            expected_digest.as_slice()
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("catalog_ref"))
                .and_then(|(_, value)| value.as_text()),
            Some(SIGNED_ACTS_MANIFEST_MEMBER)
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("derivation_rule"))
                .and_then(|(_, value)| value.as_text()),
            Some("signed-acts-manifest-v1")
        );
    }

    #[test]
    fn rejects_signed_acts_manifest_extension_without_member() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let stale_binding = text_map(vec![
            (
                "catalog_ref",
                Value::Text(SIGNED_ACTS_MANIFEST_MEMBER.to_string()),
            ),
            (
                "derivation_rule",
                Value::Text("signed-acts-manifest-v1".to_string()),
            ),
            ("manifest_digest", Value::Bytes([0xee; 32].to_vec())),
        ])
        .expect("stale manifest binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(SIGNED_ACTS_MANIFEST_MEMBER_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.signed_acts_manifest = None;
        let error = write_export(input).expect_err("extension without 068 manifest must reject");
        assert!(
            error
                .to_string()
                .contains("signed_acts_manifest was not provided"),
            "{error}"
        );
    }

    #[test]
    fn rejects_signed_acts_manifest_extension_without_catalog() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let stale_binding = text_map(vec![
            ("catalog_digest", Value::Bytes([0xbb; 32].to_vec())),
            ("catalog_ref", Value::Text(SIGNED_ACTS_MEMBER.to_string())),
            (
                "derivation_rule",
                Value::Text("signed-act-projection-test-v1".to_string()),
            ),
        ])
        .expect("stale signed acts binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(SIGNED_ACTS_MANIFEST_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.signed_acts_catalog = None;
        let error = write_export(input).expect_err("extension without catalog must reject");
        assert!(
            error
                .to_string()
                .contains("signed_acts_catalog was not provided"),
            "{error}"
        );
    }

    #[test]
    fn write_export_binds_policy_closure_when_provided() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let closure = PolicyClosureMember {
            bytes: encode_value(
                &text_map(vec![
                    ("closure_schema_version", uint(1)),
                    (
                        "closure_version",
                        Value::Text("policy-closure-test-v1".to_string()),
                    ),
                    (
                        "verifier_boundary",
                        text_map(vec![
                            ("bundle_admission_policy_evidence", Value::Bool(true)),
                            ("bundle_trust_roots_authoritative", Value::Bool(false)),
                            ("verifier_supplied_trust_roots_required", Value::Bool(true)),
                            (
                                "verifier_supplied_adapter_allowlists_required",
                                Value::Bool(true),
                            ),
                            ("server_operational_config_included", Value::Bool(false)),
                        ])
                        .expect("boundary"),
                    ),
                    (
                        "artifacts",
                        Value::Array(vec![
                            text_map(vec![
                                ("owner", Value::Text("wos".to_string())),
                                ("kind", Value::Text("intent-registry".to_string())),
                                ("version", Value::Text("2026-05-16".to_string())),
                                ("ref", Value::Text("urn:test:registry:intents".to_string())),
                                ("digest_algorithm", Value::Text("sha-256".to_string())),
                                ("digest", Value::Bytes([0xcc; 32].to_vec())),
                                (
                                    "valid_from",
                                    Value::Text("2026-05-16T00:00:00Z".to_string()),
                                ),
                                ("valid_to", Value::Null),
                            ])
                            .expect("artifact"),
                        ]),
                    ),
                ])
                .expect("closure"),
            )
            .expect("closure bytes"),
            closure_version: "policy-closure-test-v1".to_string(),
        };
        let expected_digest = sha256_bytes(&closure.bytes);
        input.policy_closure = Some(closure);

        let package = write_export(input).expect("write export");
        let member = package
            .member_bytes(POLICY_CLOSURE_MEMBER)
            .expect("067 policy closure member");
        assert_eq!(sha256_bytes(member), expected_digest);

        let manifest = decode_cbor_value(&package.manifest_payload).expect("manifest CBOR");
        let map = manifest.as_map().expect("manifest map");
        let extensions = map_lookup_map(map, "extensions").expect("extensions");
        let binding_map = extensions
            .iter()
            .find(|(k, _)| k.as_text() == Some(POLICY_CLOSURE_MANIFEST_EXTENSION))
            .map(|(_, v)| v.as_map().expect("binding"))
            .expect("policy closure extension");
        assert_eq!(
            map_lookup_bytes(binding_map, "closure_digest")
                .expect("closure_digest")
                .as_slice(),
            expected_digest.as_slice()
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("closure_ref"))
                .and_then(|(_, value)| value.as_text()),
            Some(POLICY_CLOSURE_MEMBER)
        );
        assert_eq!(
            binding_map
                .iter()
                .find(|(key, _)| key.as_text() == Some("closure_version"))
                .and_then(|(_, value)| value.as_text()),
            Some("policy-closure-test-v1")
        );
    }

    #[test]
    fn rejects_policy_closure_manifest_extension_without_member() {
        let root = fixtures_root();
        let mut input = crate::export_001_writer_input(root.as_path());
        let stale_binding = text_map(vec![
            ("closure_digest", Value::Bytes([0xdd; 32].to_vec())),
            (
                "closure_ref",
                Value::Text(POLICY_CLOSURE_MEMBER.to_string()),
            ),
            (
                "closure_version",
                Value::Text("policy-closure-test-v1".to_string()),
            ),
        ])
        .expect("stale policy closure binding");
        input.extensions = Some(
            canonical_map(vec![(
                Value::Text(POLICY_CLOSURE_MANIFEST_EXTENSION.to_string()),
                stale_binding,
            )])
            .expect("extensions map"),
        );
        input.policy_closure = None;
        let error = write_export(input).expect_err("extension without closure must reject");
        assert!(
            error
                .to_string()
                .contains("policy_closure was not provided"),
            "{error}"
        );
    }

    #[test]
    fn an_export_refuses_checkpoints_that_are_out_of_order_or_commit_to_other_events() {
        let mut swapped = native_input();
        swapped.checkpoints.reverse();
        let error = write_export(swapped).expect_err("swapped checkpoints must reject");
        assert!(
            error.to_string().contains("supplied checkpoint 1"),
            "{error}"
        );

        let mut repeated = native_input();
        repeated.checkpoints[1] = repeated.checkpoints[0].clone();
        let error = write_export(repeated).expect_err("a repeated checkpoint must reject");
        assert!(
            error.to_string().contains("supplied checkpoint 2"),
            "{error}"
        );

        // Checkpoints issued for a different second event chain correctly but commit to a
        // different tree head.
        let honest = native_input();
        let mut other_events = honest.events.clone();
        other_events[1] = StoredEvent::new(
            honest.scope.clone(),
            1,
            honest.events[0].canonical_event().to_vec(),
            honest.events[1].signed_event().to_vec(),
        );
        let key = read(&fixtures_root(), "_keys/issuer-001.cose_key");
        let mut foreign = honest.clone();
        foreign.checkpoints = crate::issue_checkpoints(
            &honest.scope,
            &other_events,
            &key,
            &[
                TrellisTimestamp::new(1_745_000_050, 0).unwrap(),
                TrellisTimestamp::new(1_745_000_060, 0).unwrap(),
            ],
        );
        let error = write_export(foreign).expect_err("a foreign head must reject");
        assert!(error.to_string().contains("head root differs"), "{error}");
    }

    #[test]
    fn an_export_refuses_a_checkpoint_count_that_differs_from_the_event_count() {
        let mut short = native_input();
        short.checkpoints.pop();
        let error = write_export(short).expect_err("one checkpoint per event");
        assert!(
            error.to_string().contains("does not match event count"),
            "{error}"
        );
    }

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/vectors")
    }

    fn read(root: &Path, relative: &str) -> Vec<u8> {
        std::fs::read(root.join(relative)).unwrap_or_else(|error| {
            panic!("failed to read fixture {relative}: {error}");
        })
    }
}
