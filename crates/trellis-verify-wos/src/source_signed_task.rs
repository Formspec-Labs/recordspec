// Rust guideline compliant 2026-02-21
//! Binds Source-signed completed content without promoting it to a formal ceremony.

use crate::records::{ProtectedResponseLocator, ResponseBindingPins, bind_opened_response};
use ciborium::Value;
use integrity_verify::trellis::{DomainEvent, DomainExport, DomainFinding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use trellis_types::{encode_canonical_cbor_value, sha256_bytes};
use wos_events::{NativeProvenanceEvent, ProvenanceKind, WOS_NATIVE_PROVENANCE_EVENT_LITERAL};

const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 256;
const KIND: &str = "sourceSignedCompletedTask";

/// Actual Source evidence family, independent of native formal-signing obligations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceTaskFamily {
    NativeV1,
    MixedV2,
    NativeLocalV3,
}
impl SourceTaskFamily {
    fn wire(self) -> &'static str {
        match self {
            Self::NativeV1 => "native-v1",
            Self::MixedV2 => "mixed-v2",
            Self::NativeLocalV3 => "native-local-v3",
        }
    }
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "native-v1" => Ok(Self::NativeV1),
            "mixed-v2" => Ok(Self::MixedV2),
            "native-local-v3" => Ok(Self::NativeLocalV3),
            _ => Err("unsupported Source family".into()),
        }
    }
}

/// Independently selected native signing requirement; absence never selects ordinary content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeSigningObligation {
    SourceContentOnly,
    SourceContentAndFormalKernel {
        affirmation_event_hashes: Vec<[u8; 32]>,
    },
}

/// Independent policy for one actual native task occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceTaskRequirementV1 {
    pub task_completed_event_hash: [u8; 32],
    pub task_created_event_hash: [u8; 32],
    pub family: SourceTaskFamily,
    pub descriptor_sha256: [u8; 32],
    pub provider_selection_hash: [u8; 32],
    pub native_policy_hash: [u8; 32],
    pub obligation: NativeSigningObligation,
}

/// Closed externally admitted task-content policy; catalog labels cannot select it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceTaskContentProfileV1 {
    pub version: u8,
    pub case_ref: String,
    pub workflow_url: String,
    pub workflow_version: String,
    pub workflow_hash: [u8; 32],
    pub required_tasks: Vec<SourceTaskRequirementV1>,
    pub required_intakes: Vec<crate::source_original::SourceIntakeRequirementV1>,
}
impl SourceTaskContentProfileV1 {
    /// Loads bounded external policy without deriving ordinary status from an archive.
    /// # Errors
    /// Refuses unsupported, ambiguous, empty or unbounded requirements.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 64 * 1024 {
            return Err("Source task profile exceeds bound".into());
        }
        let p: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid closed Source task profile")?;
        p.validate()?;
        Ok(p)
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || [&self.case_ref, &self.workflow_url, &self.workflow_version]
                .iter()
                .any(|s| !text_ok(s))
            || (self.required_tasks.is_empty() && self.required_intakes.is_empty())
            || self.required_tasks.len() > MAX_ROWS
            || self.required_intakes.len() > MAX_ROWS
        {
            return Err("invalid Source task profile".into());
        }
        let mut seen = BTreeSet::new();
        if self
            .required_intakes
            .iter()
            .any(|r| !seen.insert(r.intake_event_hash))
        {
            return Err("duplicate required original".into());
        }
        let mut seen = BTreeSet::new();
        for r in &self.required_tasks {
            if !seen.insert(r.task_completed_event_hash) {
                return Err("duplicate required Source task".into());
            }
            if let NativeSigningObligation::SourceContentAndFormalKernel {
                affirmation_event_hashes,
            } = &r.obligation
            {
                if affirmation_event_hashes.is_empty()
                    || affirmation_event_hashes.len() > MAX_ROWS
                    || affirmation_event_hashes
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != affirmation_event_hashes.len()
                {
                    return Err("invalid formal signing requirement".into());
                }
            }
        }
        Ok(())
    }
}

/// Bounded provider-admitted off-event witness binding, never independent commit proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTaskProofDescriptorV1 {
    pub witness_sha256: [u8; 32],
    pub native_snapshot_hash: [u8; 32],
    pub provider_selection_hash: [u8; 32],
    pub family_selection_hash: [u8; 32],
    pub original_selection_hash: Option<[u8; 32]>,
    pub committed_task_submit_key: String,
    pub native_outcome_digest: [u8; 32],
    pub http_receipt_digest: [u8; 32],
}

/// Public fields derived only from admitted retained Source and native evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSignedCompletedTaskFieldsV1 {
    pub family: SourceTaskFamily,
    pub canonical_event_hash: [u8; 32],
    pub task_created_event_hash: [u8; 32],
    pub process_id: String,
    pub task_id: String,
    pub task_ref: String,
    pub task_created_record_id: String,
    pub task_completed_record_id: String,
    pub actor_ref: String,
    pub artifact_id: String,
    pub formspec_response_ref: String,
    pub response_id: String,
    pub signature_id: String,
    pub signed_payload_digest: String,
    pub signed_payload_digest_algorithm: String,
    pub task_proof: SourceTaskProofDescriptorV1,
}

/// Validated public catalog row; complete Response and proof buffers remain protected.
#[derive(Clone, Debug)]
pub struct SourceSignedCompletedTaskV1 {
    fields: SourceSignedCompletedTaskFieldsV1,
    protected: ProtectedResponseLocator,
}
impl SourceSignedCompletedTaskV1 {
    /// Validates a closed protected locator and exact public occurrence identity.
    /// # Errors
    /// Refuses changed anchors, identity, family selection or malformed fields.
    pub fn new(
        fields: SourceSignedCompletedTaskFieldsV1,
        locator_bytes: &[u8],
    ) -> Result<Self, String> {
        if locator_bytes.len() > 64 * 1024 {
            return Err("protected locator exceeds bound".into());
        }
        let value = trellis_types::decode_cbor_value(locator_bytes)
            .map_err(|_| "invalid protected locator")?;
        let protected =
            crate::records::protected_locator(&value).map_err(|_| "invalid protected locator")?;
        let s = Self { fields, protected };
        s.validate()?;
        Ok(s)
    }
    /// Returns the bounded public fields; these values grant no authority.
    pub fn fields(&self) -> &SourceSignedCompletedTaskFieldsV1 {
        &self.fields
    }
    /// Returns the exact descriptor digest bound by the signed catalog manifest.
    /// # Errors
    /// Refuses canonical encoding failure.
    pub fn descriptor_sha256(&self) -> Result<[u8; 32], String> {
        Ok(sha256_bytes(&self.to_cbor()?))
    }
    /// Encodes the closed row for the existing062 catalog.
    /// # Errors
    /// Refuses invalid fields or canonical encoding failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        encode_canonical_cbor_value(&self.value()).map_err(|_| "Source row encoding failed".into())
    }
    /// Returns the exact protected locator without exposing original bytes.
    /// # Errors
    /// Refuses canonical encoding failure.
    pub fn protected_locator_cbor(&self) -> Result<Vec<u8>, String> {
        encode_canonical_cbor_value(&self.protected.to_value(true))
            .map_err(|_| "locator encoding failed".into())
    }
    /// Validates the encrypted record using the existing closed codec.
    /// # Errors
    /// Refuses changed record, metadata, ciphertext, lengths or digests.
    pub fn protected_response_opening(
        &self,
        record: &[u8],
    ) -> Result<crate::ProtectedResponseOpeningV1, String> {
        crate::ProtectedResponseOpeningV1::from_record(&self.protected, record)
            .map_err(|_| "protected Response record refused".into())
    }
    fn validate(&self) -> Result<(), String> {
        let f = &self.fields;
        if [
            &f.process_id,
            &f.task_id,
            &f.task_ref,
            &f.task_created_record_id,
            &f.task_completed_record_id,
            &f.actor_ref,
            &f.artifact_id,
            &f.formspec_response_ref,
            &f.response_id,
            &f.signature_id,
            &f.signed_payload_digest,
            &f.task_proof.committed_task_submit_key,
        ]
        .iter()
        .any(|s| !text_ok(s))
            || f.signed_payload_digest_algorithm != "sha-256"
        {
            return Err("invalid Source task fields".into());
        }
        if f.family == SourceTaskFamily::MixedV2 && f.task_proof.original_selection_hash.is_none()
            || f.family == SourceTaskFamily::NativeLocalV3
                && f.task_proof.original_selection_hash.is_some()
        {
            return Err("Source family proof selection mismatch".into());
        }
        if self.protected.native_event_hash != f.canonical_event_hash
            || self.protected.response_ref != f.formspec_response_ref
            || self.protected.response_id != f.response_id
        {
            return Err("Source task protected binding mismatch".into());
        }
        Ok(())
    }
    fn value(&self) -> Value {
        let f = &self.fields;
        let p = &f.task_proof;
        let mut rows = vec![
            ("kind", Value::Text(KIND.into())),
            ("version", Value::Integer(1.into())),
            ("family", Value::Text(f.family.wire().into())),
            ("canonical_event_hash", b(f.canonical_event_hash)),
            ("task_created_event_hash", b(f.task_created_event_hash)),
        ];
        for (k, v) in [
            ("process_id", &f.process_id),
            ("task_id", &f.task_id),
            ("task_ref", &f.task_ref),
            ("task_created_record_id", &f.task_created_record_id),
            ("task_completed_record_id", &f.task_completed_record_id),
            ("actor_ref", &f.actor_ref),
            ("artifact_id", &f.artifact_id),
            ("formspec_response_ref", &f.formspec_response_ref),
            ("response_id", &f.response_id),
            ("signature_id", &f.signature_id),
            ("signed_payload_digest", &f.signed_payload_digest),
            (
                "signed_payload_digest_algorithm",
                &f.signed_payload_digest_algorithm,
            ),
        ] {
            rows.push((k, Value::Text(v.clone())));
        }
        let mut proof = vec![
            ("version", Value::Integer(1.into())),
            ("admission", Value::Text("owningWosProviderAdmitted".into())),
            ("witness_sha256", b(p.witness_sha256)),
            ("native_snapshot_hash", b(p.native_snapshot_hash)),
            ("provider_selection_hash", b(p.provider_selection_hash)),
            ("family_selection_hash", b(p.family_selection_hash)),
            (
                "committed_task_submit_key",
                Value::Text(p.committed_task_submit_key.clone()),
            ),
            ("native_outcome_digest", b(p.native_outcome_digest)),
            ("http_receipt_digest", b(p.http_receipt_digest)),
        ];
        if let Some(h) = p.original_selection_hash {
            proof.push(("original_selection_hash", b(h)));
        }
        rows.push(("task_proof", m(proof)));
        rows.push(("protected_response", self.protected.to_value(true)));
        m(rows)
    }
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let map = value.as_map().ok_or("Source row must be map")?;
        closed(
            map,
            &[
                "kind",
                "version",
                "family",
                "canonical_event_hash",
                "task_created_event_hash",
                "process_id",
                "task_id",
                "task_ref",
                "task_created_record_id",
                "task_completed_record_id",
                "actor_ref",
                "artifact_id",
                "formspec_response_ref",
                "response_id",
                "signature_id",
                "signed_payload_digest",
                "signed_payload_digest_algorithm",
                "task_proof",
                "protected_response",
            ],
        )?;
        if t(map, "kind")? != KIND || u(map, "version")? != 1 {
            return Err("unsupported Source row".into());
        }
        let proof = get(map, "task_proof")?
            .as_map()
            .ok_or("task proof must be map")?;
        closed(
            proof,
            &[
                "version",
                "admission",
                "witness_sha256",
                "native_snapshot_hash",
                "provider_selection_hash",
                "family_selection_hash",
                "original_selection_hash",
                "committed_task_submit_key",
                "native_outcome_digest",
                "http_receipt_digest",
            ],
        )?;
        if u(proof, "version")? != 1 || t(proof, "admission")? != "owningWosProviderAdmitted" {
            return Err("unsupported task admission".into());
        }
        let fields = SourceSignedCompletedTaskFieldsV1 {
            family: SourceTaskFamily::parse(&t(map, "family")?)?,
            canonical_event_hash: h(map, "canonical_event_hash")?,
            task_created_event_hash: h(map, "task_created_event_hash")?,
            process_id: t(map, "process_id")?,
            task_id: t(map, "task_id")?,
            task_ref: t(map, "task_ref")?,
            task_created_record_id: t(map, "task_created_record_id")?,
            task_completed_record_id: t(map, "task_completed_record_id")?,
            actor_ref: t(map, "actor_ref")?,
            artifact_id: t(map, "artifact_id")?,
            formspec_response_ref: t(map, "formspec_response_ref")?,
            response_id: t(map, "response_id")?,
            signature_id: t(map, "signature_id")?,
            signed_payload_digest: t(map, "signed_payload_digest")?,
            signed_payload_digest_algorithm: t(map, "signed_payload_digest_algorithm")?,
            task_proof: SourceTaskProofDescriptorV1 {
                witness_sha256: h(proof, "witness_sha256")?,
                native_snapshot_hash: h(proof, "native_snapshot_hash")?,
                provider_selection_hash: h(proof, "provider_selection_hash")?,
                family_selection_hash: h(proof, "family_selection_hash")?,
                original_selection_hash: if has(proof, "original_selection_hash") {
                    Some(h(proof, "original_selection_hash")?)
                } else {
                    None
                },
                committed_task_submit_key: t(proof, "committed_task_submit_key")?,
                native_outcome_digest: h(proof, "native_outcome_digest")?,
                http_receipt_digest: h(proof, "http_receipt_digest")?,
            },
        };
        Self::new(
            fields,
            &encode_canonical_cbor_value(get(map, "protected_response")?)
                .map_err(|_| "invalid locator")?,
        )
    }
}
fn text_ok(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
}
fn b(h: [u8; 32]) -> Value {
    Value::Bytes(h.to_vec())
}
fn m(v: Vec<(&str, Value)>) -> Value {
    Value::Map(
        v.into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a Value, String> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing {key}"))
}
fn has(map: &[(Value, Value)], key: &str) -> bool {
    map.iter().any(|(k, _)| k.as_text() == Some(key))
}
fn t(map: &[(Value, Value)], key: &str) -> Result<String, String> {
    get(map, key)?
        .as_text()
        .map(str::to_owned)
        .ok_or_else(|| format!("invalid {key}"))
}
fn u(map: &[(Value, Value)], key: &str) -> Result<u64, String> {
    get(map, key)?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| format!("invalid {key}"))
}
fn h(map: &[(Value, Value)], key: &str) -> Result<[u8; 32], String> {
    get(map, key)?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or_else(|| format!("invalid {key}"))
}
fn closed(map: &[(Value, Value)], allowed: &[&str]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (k, _) in map {
        let key = k.as_text().ok_or("nontext field")?;
        if !allowed.contains(&key) || !seen.insert(key) {
            return Err("unknown or duplicate field".into());
        }
    }
    Ok(())
}

/// Parses Source task rows while preserving the strict legacy formal row parser.
/// # Errors
/// Refuses malformed, unknown tagged, ambiguous or excessive catalog rows.
pub fn source_signed_tasks_from_catalog(
    bytes: &[u8],
) -> Result<Vec<SourceSignedCompletedTaskV1>, String> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err("catalog exceeds bound".into());
    }
    let value = trellis_types::decode_cbor_value(bytes).map_err(|_| "invalid catalog")?;
    let rows = value.as_array().ok_or("catalog must be array")?;
    if rows.len() > MAX_ROWS {
        return Err("catalog row limit".into());
    }
    let mut out = Vec::new();
    for row in rows {
        let map = row.as_map().ok_or("catalog row must be map")?;
        if has(map, "kind") {
            out.push(SourceSignedCompletedTaskV1::from_value(row)?);
        } else {
            let bytes = encode_canonical_cbor_value(&Value::Array(vec![row.clone()]))
                .map_err(|_| "invalid legacy row")?;
            crate::records::parse_signature_manifest_entries(&bytes)
                .map_err(|_| "invalid legacy row")?;
        }
    }
    Ok(out)
}

/// Binds actual decoded native task records and exact archive/catalog/policy selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTaskNativeBindings {
    pub(crate) archive_sha256: [u8; 32],
    pub(crate) catalog_sha256: [u8; 32],
    pub(crate) descriptor_sha256: [u8; 32],
    pub(crate) profile: SourceTaskContentProfileV1,
    pub(crate) manifest_sha256: [u8; 32],
    pub(crate) checkpoints_sha256: [u8; 32],
    pub(crate) requirement: SourceTaskRequirementV1,
    pub(crate) created_record: serde_json::Value,
    pub(crate) completed_record: serde_json::Value,
}
impl SourceTaskNativeBindings {
    pub fn archive_sha256(&self) -> [u8; 32] {
        self.archive_sha256
    }
    pub fn catalog_sha256(&self) -> [u8; 32] {
        self.catalog_sha256
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor_sha256
    }
    pub fn profile(&self) -> &SourceTaskContentProfileV1 {
        &self.profile
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn checkpoints_sha256(&self) -> [u8; 32] {
        self.checkpoints_sha256
    }
    pub fn requirement(&self) -> &SourceTaskRequirementV1 {
        &self.requirement
    }
    pub fn created_record(&self) -> &serde_json::Value {
        &self.created_record
    }
    pub fn completed_record(&self) -> &serde_json::Value {
        &self.completed_record
    }
}

/// Owning verifier result accessors; construction stays with the selected proof owner.
pub trait VerifiedSourceTaskContent {
    fn native_binding(&self) -> &SourceTaskNativeBindings;
    fn protected_record_bytes(&self) -> &[u8];
    fn canonical_response_bytes(&self) -> &[u8];
    fn independently_admitted_pins(&self) -> SourceTaskResponsePinsV1;
}
/// Independently admitted protection pins supplied by the owning verification result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTaskResponsePinsV1 {
    pub response_ref: String,
    pub response_id: String,
    pub response_hash: String,
    pub context_key: Vec<u8>,
    pub record_hash: [u8; 32],
    pub source_binding_hash: [u8; 32],
    pub publication_hash: [u8; 32],
    pub public_policy_hash: [u8; 32],
    pub recipient_policy_hash: [u8; 32],
}
/// Selected owning Source/native proof adapter, not a boolean verification shortcut.
pub trait SourceTaskContentVerifier {
    type Verified: VerifiedSourceTaskContent;
    /// Verifies actual typed Source proof, exact native/witness joins and admitted policy.
    /// # Errors
    /// Refuses missing, foreign, untrusted, mismatched or unreadable proof/content.
    fn verify(
        &self,
        task: &SourceSignedCompletedTaskV1,
        native: &SourceTaskNativeBindings,
    ) -> Result<Self::Verified, String>;
}

pub(crate) fn legacy_catalog(
    bytes: &[u8],
) -> Result<Vec<crate::records::SignatureManifestEntry>, String> {
    source_signed_tasks_from_catalog(bytes)?;
    let value = trellis_types::decode_cbor_value(bytes).map_err(|_| "invalid catalog")?;
    let rows = value
        .as_array()
        .ok_or("invalid catalog")?
        .iter()
        .filter(|v| v.as_map().is_some_and(|m| !has(m, "kind")))
        .cloned()
        .collect();
    crate::records::parse_signature_manifest_entries(
        &encode_canonical_cbor_value(&Value::Array(rows)).map_err(|_| "invalid legacy catalog")?,
    )
    .map_err(|_| "invalid legacy catalog".into())
}
fn native_join(
    task: &SourceSignedCompletedTaskV1,
    events: &[DomainEvent],
) -> Result<(serde_json::Value, serde_json::Value), String> {
    let f = task.fields();
    let mut created = None;
    let mut completed = None;
    let mut creations = 0;
    let mut completions = 0;
    for (index, event) in events.iter().enumerate() {
        if event.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
            continue;
        }
        let Some(payload) = event.payload.as_deref() else {
            continue;
        };
        let native = NativeProvenanceEvent::from_dcbor_slice(payload)
            .map_err(|_| "invalid native task record")?;
        if native
            .record()
            .pointer("/data/taskId")
            .and_then(serde_json::Value::as_str)
            != Some(&f.task_id)
        {
            continue;
        }
        match native.record_kind() {
            ProvenanceKind::TaskCreated => {
                creations += 1;
                if event.canonical_event_hash == f.task_created_event_hash
                    && native.record_id() == f.task_created_record_id
                {
                    created = Some((index, native.record().clone()));
                }
            }
            ProvenanceKind::TaskCompleted => {
                completions += 1;
                if event.canonical_event_hash == f.canonical_event_hash
                    && native.record_id() == f.task_completed_record_id
                {
                    completed = Some((index, native.record().clone()));
                }
            }
            _ => {}
        }
    }
    let (ci, c) = created.ok_or("Source task creation unresolved")?;
    let (di, d) = completed.ok_or("Source task completion unresolved")?;
    if creations != 1
        || completions != 1
        || ci >= di
        || c.pointer("/data/details/taskRef")
            .and_then(serde_json::Value::as_str)
            != Some(&f.task_ref)
        || d.get("actorId").and_then(serde_json::Value::as_str) != Some(&f.actor_ref)
        || d.pointer("/data/details/artifactId")
            .and_then(serde_json::Value::as_str)
            != Some(&f.artifact_id)
    {
        return Err("Source native task join mismatch".into());
    }
    if c.pointer("/data/details/assignedActor")
        .is_some_and(|a| a.as_str() != Some(&f.actor_ref))
    {
        return Err("Source assigned actor mismatch".into());
    }
    Ok((c, d))
}
fn finding(kind: &str, hash: Option<[u8; 32]>) -> DomainFinding {
    DomainFinding::new(
        kind,
        hash,
        Severity::Failure,
        "Source task content requires exact admitted native, policy and owning proof bindings",
    )
}
pub(crate) fn structural_findings(
    export: &DomainExport<'_>,
    require_content: bool,
) -> Vec<DomainFinding> {
    let Some(bytes) = export.members.get("062-signature-affirmations.cbor") else {
        return Vec::new();
    };
    let tasks = match source_signed_tasks_from_catalog(bytes) {
        Ok(t) => t,
        Err(_) => return vec![finding("source_task_catalog_invalid", None)],
    };
    let mut findings = Vec::new();
    let mut anchors = BTreeSet::new();
    for task in tasks {
        let hash = task.fields.canonical_event_hash;
        if !anchors.insert(hash) {
            findings.push(finding("source_task_catalog_duplicate", Some(hash)));
        }
        if native_join(&task, export.events).is_err() {
            findings.push(finding("source_task_native_join_mismatch", Some(hash)));
        }
        if require_content {
            findings.push(finding("source_task_content_unavailable", Some(hash)));
        }
    }
    findings
}

/// Encodes one manifest-bound062 catalog, preserving legacy rows and actual task anchors.
/// # Errors
/// Refuses malformed legacy rows, changed native joins, duplicate anchors or finite limits.
pub fn encode_source_signed_task_catalog(
    legacy: Option<&[u8]>,
    tasks: &[SourceSignedCompletedTaskV1],
    events: &[DomainEvent],
) -> Result<Vec<u8>, String> {
    let mut rows = if let Some(bytes) = legacy {
        legacy_catalog(bytes)?;
        trellis_types::decode_cbor_value(bytes)
            .map_err(|_| "invalid legacy catalog")?
            .as_array()
            .ok_or("invalid legacy catalog")?
            .clone()
    } else {
        Vec::new()
    };
    let mut seen = BTreeSet::new();
    for row in &rows {
        let m = row.as_map().ok_or("invalid row")?;
        if !seen.insert(h(m, "canonical_event_hash")?) {
            return Err("duplicate catalog anchor".into());
        }
    }
    for task in tasks {
        task.validate()?;
        native_join(task, events)?;
        if !seen.insert(task.fields.canonical_event_hash) {
            return Err("duplicate catalog anchor".into());
        }
        rows.push(task.value());
    }
    if rows.len() > MAX_ROWS {
        return Err("catalog row limit".into());
    }
    let bytes =
        encode_canonical_cbor_value(&Value::Array(rows)).map_err(|_| "catalog encoding failed")?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err("catalog byte limit".into());
    }
    Ok(bytes)
}

pub(crate) fn verified_profile_findings<V: SourceTaskContentVerifier>(
    export: &DomainExport<'_>,
    archive_sha256: [u8; 32],
    profile: &SourceTaskContentProfileV1,
    verifier: &V,
) -> Vec<DomainFinding> {
    if profile.validate().is_err() {
        return vec![finding("source_task_profile_invalid", None)];
    }
    let Some(bytes) = export.members.get("062-signature-affirmations.cbor") else {
        return if profile.required_tasks.is_empty() {
            vec![]
        } else {
            vec![finding("source_task_catalog_missing", None)]
        };
    };
    let bound = export
        .manifest_extensions
        .get(crate::event_types::SIGNATURE_EXPORT_EXTENSION)
        .and_then(|e| crate::records::parse_signature_export_digest(e).ok())
        == Some(sha256_bytes(bytes));
    if !bound {
        return vec![finding("source_task_catalog_unbound", None)];
    }
    let tasks = match source_signed_tasks_from_catalog(bytes) {
        Ok(t) => t,
        Err(_) => return vec![finding("source_task_catalog_invalid", None)],
    };
    let mut findings = Vec::new();
    let mut covered = BTreeSet::new();
    for task in &tasks {
        let f = task.fields();
        let hash = f.canonical_event_hash;
        if !covered.insert(hash) {
            findings.push(finding("source_task_catalog_duplicate", Some(hash)));
            continue;
        }
        let Some(requirement) = profile
            .required_tasks
            .iter()
            .find(|r| r.task_completed_event_hash == hash)
        else {
            findings.push(finding("source_task_unselected", Some(hash)));
            continue;
        };
        let descriptor = match task.descriptor_sha256() {
            Ok(h) => h,
            Err(_) => {
                findings.push(finding("source_task_catalog_invalid", Some(hash)));
                continue;
            }
        };
        if requirement.family != f.family
            || requirement.task_created_event_hash != f.task_created_event_hash
            || requirement.descriptor_sha256 != descriptor
            || requirement.provider_selection_hash != f.task_proof.provider_selection_hash
        {
            findings.push(finding("source_task_profile_mismatch", Some(hash)));
            continue;
        }
        let (created_record, completed_record) = match native_join(task, export.events) {
            Ok(pair) => pair,
            Err(_) => {
                findings.push(finding("source_task_native_join_mismatch", Some(hash)));
                continue;
            }
        };
        let Some(manifest) = export.members.get("000-manifest.cbor") else {
            findings.push(finding("source_task_archive_binding_missing", Some(hash)));
            continue;
        };
        let Some(checkpoints) = export.members.get("040-checkpoints.cbor") else {
            findings.push(finding("source_task_archive_binding_missing", Some(hash)));
            continue;
        };
        let native = SourceTaskNativeBindings {
            archive_sha256,
            catalog_sha256: sha256_bytes(bytes),
            descriptor_sha256: descriptor,
            profile: profile.clone(),
            manifest_sha256: sha256_bytes(manifest),
            checkpoints_sha256: sha256_bytes(checkpoints),
            requirement: requirement.clone(),
            created_record,
            completed_record,
        };
        if let NativeSigningObligation::SourceContentAndFormalKernel {
            affirmation_event_hashes,
        } = &requirement.obligation
        {
            if affirmation_event_hashes.iter().any(|h| {
                !export.events.iter().any(|e| {
                    e.canonical_event_hash == *h
                        && e.event_type
                            == crate::event_types::wos_signature_affirmation_event_type()
                })
            }) {
                // Actual certificate authority/shape/outcome checks run in the existing
                // integrity verifier and final profile fold, never guessed member names.
                findings.push(finding("source_task_formal_obligation_missing", Some(hash)));
                continue;
            }
        }
        let result = match verifier.verify(task, &native) {
            Ok(v) => v,
            Err(_) => {
                findings.push(finding("source_task_content_unavailable", Some(hash)));
                continue;
            }
        };
        if result.native_binding() != &native {
            findings.push(finding("source_task_verified_binding_mismatch", Some(hash)));
            continue;
        }
        let p = result.independently_admitted_pins();
        let pins = ResponseBindingPins {
            native_event_hash: hash,
            response_ref: p.response_ref,
            response_id: p.response_id,
            response_hash: p.response_hash,
            context_key: p.context_key,
            record_hash: p.record_hash,
            source_binding_hash: p.source_binding_hash,
            publication_hash: p.publication_hash,
            public_policy_hash: p.public_policy_hash,
            recipient_policy_hash: p.recipient_policy_hash,
        };
        if bind_opened_response(
            &task.protected,
            &pins,
            result.protected_record_bytes(),
            result.canonical_response_bytes(),
        )
        .is_err()
        {
            findings.push(finding(
                "source_task_protected_content_mismatch",
                Some(hash),
            ));
        }
    }
    for r in &profile.required_tasks {
        if !covered.contains(&r.task_completed_event_hash) {
            findings.push(finding(
                "source_task_required_content_missing",
                Some(r.task_completed_event_hash),
            ));
        }
    }
    findings
}

#[cfg(test)]
#[path = "source_signed_task_tests.rs"]
mod tests;
