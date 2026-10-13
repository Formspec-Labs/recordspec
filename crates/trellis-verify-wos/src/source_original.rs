// Rust guideline compliant 2026-02-21
//! Binds protected original intake content using the unchanged intake/case catalog.
use crate::records::{
    IntakeManifestEntry, IntakeResponseContent, ResponseBindingPins, bind_opened_response,
};
use crate::source_signed_task::{SourceTaskContentProfileV1, SourceTaskResponsePinsV1};
use ciborium::Value;
use integrity_verify::trellis::{DomainExport, DomainFinding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use trellis_types::{encode_canonical_cbor_value, sha256_bytes};

/// Independent requirement for one actual original intake occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceIntakeRequirementV1 {
    pub intake_event_hash: [u8; 32],
    pub case_created_event_hash: Option<[u8; 32]>,
    pub descriptor_sha256: [u8; 32],
    pub provider_selection_hash: [u8; 32],
}
/// Validated existing063 original Response row; no invented task anchor.
#[derive(Clone, Debug)]
pub struct ProtectedIntakeResponseV1 {
    pub(crate) entry: IntakeManifestEntry,
    row: Value,
    original_context_proof: Option<crate::OriginalContextProofV1>,
}
impl ProtectedIntakeResponseV1 {
    /// Returns the exact owning MIXED context join, when present.
    pub fn original_context_proof(&self) -> Option<&crate::OriginalContextProofV1> {
        self.original_context_proof.as_ref()
    }
    /// Joins an original to exactly one actual task's protected package.
    ///
    /// The owning reader must separately verify that context_instance exists in
    /// the opened typed MIXED package and independently pin the original Source
    /// binding. Current and original Source bindings may differ through the
    /// admitted namespace association. This method grants no Source authority.
    /// # Errors
    /// Refuses missing, duplicate, foreign or differently published package joins.
    pub fn validate_original_context_proof<'a>(
        &'a self,
        tasks: &[crate::SourceSignedCompletedTaskV1],
    ) -> Result<&'a crate::OriginalContextProofV1, String> {
        let join = self
            .original_context_proof
            .as_ref()
            .ok_or("original context proof absent")?;
        let mut matches = tasks
            .iter()
            .filter(|task| task.fields().canonical_event_hash == join.task_completed_event_hash);
        let task = matches.next().ok_or("original context task absent")?;
        if matches.next().is_some() {
            return Err("original context task ambiguous".into());
        }
        let package = task
            .fields()
            .task_proof
            .protected_package
            .as_ref()
            .ok_or("original context package absent")?;
        let original = match &self.entry.response_content {
            IntakeResponseContent::Protected(p) => p,
            _ => unreachable!("validated protected row"),
        };
        if package.record_hash != join.package_record_hash
            || package.task_completed_event_hash != join.task_completed_event_hash
            || package.original_publication_hash != original.publication_hash
            || package.recipient_policy_hash != original.recipient_policy_hash
        {
            return Err("original context package association differs".into());
        }
        Ok(join)
    }
    pub fn intake_event_hash(&self) -> [u8; 32] {
        self.entry.intake_event_hash
    }
    pub fn case_created_event_hash(&self) -> Option<[u8; 32]> {
        self.entry.case_created_event_hash
    }
    pub fn handoff_id(&self) -> &str {
        &self.entry.handoff.handoff_id
    }
    pub fn response_ref(&self) -> &str {
        &self.entry.handoff.response_ref
    }
    pub fn response_hash(&self) -> &str {
        &self.entry.handoff.response_hash
    }
    pub fn definition_url(&self) -> &str {
        &self.entry.handoff.definition_url
    }
    pub fn definition_version(&self) -> &str {
        &self.entry.handoff.definition_version
    }
    /// Returns the validated handoff initiation mode.
    pub fn initiation_mode(&self) -> &str {
        &self.entry.handoff.initiation_mode
    }
    /// Returns the validated handoff's report reference.
    pub fn validation_report_ref(&self) -> &str {
        &self.entry.handoff.validation_report_ref
    }
    /// Returns the validated handoff's ledger head reference.
    pub fn ledger_head_ref(&self) -> &str {
        &self.entry.handoff.ledger_head_ref
    }
    pub fn response_id(&self) -> &str {
        match &self.entry.response_content {
            IntakeResponseContent::Protected(p) => &p.response_id,
            _ => unreachable!("validated protected row"),
        }
    }
    /// Returns canonical original row bytes bound by the signed intake catalog.
    /// # Errors
    /// Refuses encoding failure.
    pub fn descriptor_cbor(&self) -> Result<Vec<u8>, String> {
        encode_canonical_cbor_value(&self.row).map_err(|_| "intake descriptor encode failed".into())
    }
    /// Validates the encrypted original using the existing closed codec.
    /// # Errors
    /// Refuses changed record, metadata, ciphertext, lengths or digests.
    pub fn protected_response_opening(
        &self,
        record: &[u8],
    ) -> Result<crate::ProtectedResponseOpeningV1, String> {
        match &self.entry.response_content {
            IntakeResponseContent::Protected(p) => {
                crate::ProtectedResponseOpeningV1::from_record(p, record)
                    .map_err(|_| "protected original record refused".into())
            }
            _ => unreachable!("validated protected row"),
        }
    }
    /// Returns exact protected locator bytes without original content.
    /// # Errors
    /// Refuses encoding failure.
    pub fn protected_locator_cbor(&self) -> Result<Vec<u8>, String> {
        match &self.entry.response_content {
            IntakeResponseContent::Protected(p) => encode_canonical_cbor_value(&p.to_value(true))
                .map_err(|_| "intake locator encode failed".into()),
            _ => unreachable!("validated protected row"),
        }
    }
}
/// Reads existing protected intake rows using the same closed one-of parser.
/// # Errors
/// Refuses malformed, oversized or duplicate native anchors.
pub fn protected_intake_responses_from_catalog(
    bytes: &[u8],
) -> Result<Vec<ProtectedIntakeResponseV1>, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("intake catalog byte limit".into());
    }
    let value = trellis_types::decode_cbor_value(bytes).map_err(|_| "invalid intake catalog")?;
    let rows = value.as_array().ok_or("invalid intake catalog root")?;
    if rows.len() > 256 {
        return Err("intake catalog count limit".into());
    }
    let entries = crate::records::parse_intake_manifest_entries(bytes)
        .map_err(|_| "invalid intake catalog")?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (entry, row) in entries.into_iter().zip(rows) {
        if !seen.insert(entry.intake_event_hash) {
            return Err("duplicate original intake".into());
        }
        let mut joins = row
            .as_map()
            .ok_or("original row must be map")?
            .iter()
            .filter(|(key, _)| key.as_text() == Some("original_context_proof"));
        let original_context_proof = joins
            .next()
            .map(|(_, value)| crate::OriginalContextProofV1::from_value(value))
            .transpose()?;
        if joins.next().is_some() {
            return Err("duplicate original context proof".into());
        }
        if matches!(entry.response_content, IntakeResponseContent::Protected(_)) {
            out.push(ProtectedIntakeResponseV1 {
                entry,
                row: row.clone(),
                original_context_proof,
            });
        } else if original_context_proof.is_some() {
            return Err("original context proof requires protected original".into());
        }
    }
    Ok(out)
}
/// Exact archive/original-native/policy binding; not a standalone commit certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceIntakeNativeBindings {
    archive_sha256: [u8; 32],
    catalog_sha256: [u8; 32],
    descriptor_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    checkpoints_sha256: [u8; 32],
    profile: SourceTaskContentProfileV1,
    requirement: SourceIntakeRequirementV1,
    case_ref: String,
    intake_payload: Vec<u8>,
    case_created_payload: Option<Vec<u8>>,
}
impl SourceIntakeNativeBindings {
    pub fn archive_sha256(&self) -> [u8; 32] {
        self.archive_sha256
    }
    pub fn catalog_sha256(&self) -> [u8; 32] {
        self.catalog_sha256
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor_sha256
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn checkpoints_sha256(&self) -> [u8; 32] {
        self.checkpoints_sha256
    }
    pub fn profile(&self) -> &SourceTaskContentProfileV1 {
        &self.profile
    }
    pub fn requirement(&self) -> &SourceIntakeRequirementV1 {
        &self.requirement
    }
    /// Returns the actual case from the validated native intake record.
    pub fn case_ref(&self) -> &str {
        &self.case_ref
    }
    pub fn intake_record_payload(&self) -> &[u8] {
        &self.intake_payload
    }
    pub fn case_created_record_payload(&self) -> Option<&[u8]> {
        self.case_created_payload.as_deref()
    }
}
/// Owning original-public-signature result; Source policy and recipient admission stay independent.
pub trait VerifiedSourceIntakeContent {
    fn native_binding(&self) -> &SourceIntakeNativeBindings;
    fn protected_record_bytes(&self) -> &[u8];
    fn canonical_response_bytes(&self) -> &[u8];
    fn independently_admitted_pins(&self) -> SourceTaskResponsePinsV1;
}
/// Selected owning original Source verifier using actual ResponseRecord/public policy.
pub trait SourceIntakeContentVerifier {
    type Verified: VerifiedSourceIntakeContent;
    /// Verifies original signature, publication, clock, handoff and protected native identity.
    /// # Errors
    /// Refuses absent, untrusted, foreign, mismatched or unreadable original evidence.
    fn verify_original(
        &self,
        original: &ProtectedIntakeResponseV1,
        native: &SourceIntakeNativeBindings,
    ) -> Result<Self::Verified, String>;
}
fn finding(kind: &str, hash: Option<[u8; 32]>) -> DomainFinding {
    DomainFinding::new(
        kind,
        hash,
        Severity::Failure,
        "Original Response needs exact admitted opening, native identity and public Source verification",
    )
}
pub(crate) fn verified_original_findings<V: SourceIntakeContentVerifier>(
    export: &DomainExport<'_>,
    archive_sha256: [u8; 32],
    profile: &SourceTaskContentProfileV1,
    verifier: &V,
) -> Vec<DomainFinding> {
    let Some(bytes) = export.members.get("063-intake-handoffs.cbor") else {
        if profile.required_intakes.is_empty() {
            return vec![];
        }
        return vec![finding("source_original_catalog_missing", None)];
    };
    let bound = export
        .manifest_extensions
        .get(crate::event_types::INTAKE_EXPORT_EXTENSION)
        .and_then(|e| crate::records::parse_intake_export_digest(e).ok())
        == Some(sha256_bytes(bytes));
    if !bound {
        return vec![finding("source_original_catalog_unbound", None)];
    }
    let originals = match protected_intake_responses_from_catalog(bytes) {
        Ok(v) => v,
        Err(_) => return vec![finding("source_original_catalog_invalid", None)],
    };
    let mut findings = Vec::new();
    let mut covered = BTreeSet::new();
    for original in originals {
        let hash = original.intake_event_hash();
        covered.insert(hash);
        let Some(requirement) = profile
            .required_intakes
            .iter()
            .find(|r| r.intake_event_hash == hash)
        else {
            findings.push(finding("source_original_unselected", Some(hash)));
            continue;
        };
        let digest = match original.descriptor_cbor() {
            Ok(bytes) => sha256_bytes(&bytes),
            Err(_) => {
                findings.push(finding("source_original_catalog_invalid", Some(hash)));
                continue;
            }
        };
        if digest != requirement.descriptor_sha256
            || original.case_created_event_hash() != requirement.case_created_event_hash
        {
            findings.push(finding("source_original_profile_mismatch", Some(hash)));
            continue;
        }
        if crate::catalog::intake_native_findings(&original.entry, export)
            .iter()
            .any(|f| f.severity == Severity::Failure)
        {
            findings.push(finding("source_original_native_join_mismatch", Some(hash)));
            continue;
        }
        let Some(intake) = export
            .events
            .iter()
            .find(|e| e.canonical_event_hash == hash)
            .and_then(|e| e.payload.clone())
        else {
            findings.push(finding("source_original_native_join_mismatch", Some(hash)));
            continue;
        };
        let intake_record = match crate::records::parse_intake_accepted_record(
            &intake,
            crate::event_types::wos_intake_accepted_event_type(),
        ) {
            Ok(record) => record,
            Err(_) => {
                findings.push(finding("source_original_native_join_mismatch", Some(hash)));
                continue;
            }
        };
        if profile.case_ref != intake_record.case_ref {
            findings.push(finding("source_original_profile_mismatch", Some(hash)));
            continue;
        }
        let case_created = requirement
            .case_created_event_hash
            .and_then(|h| export.events.iter().find(|e| e.canonical_event_hash == h))
            .and_then(|e| e.payload.clone());
        let Some(manifest) = export.members.get("000-manifest.cbor") else {
            findings.push(finding(
                "source_original_archive_binding_missing",
                Some(hash),
            ));
            continue;
        };
        let Some(checkpoints) = export.members.get("040-checkpoints.cbor") else {
            findings.push(finding(
                "source_original_archive_binding_missing",
                Some(hash),
            ));
            continue;
        };
        let native = SourceIntakeNativeBindings {
            archive_sha256,
            catalog_sha256: sha256_bytes(bytes),
            descriptor_sha256: digest,
            manifest_sha256: sha256_bytes(manifest),
            checkpoints_sha256: sha256_bytes(checkpoints),
            profile: profile.clone(),
            requirement: requirement.clone(),
            case_ref: intake_record.case_ref,
            intake_payload: intake,
            case_created_payload: case_created,
        };
        let result = match verifier.verify_original(&original, &native) {
            Ok(v) => v,
            Err(_) => {
                findings.push(finding("source_original_content_unavailable", Some(hash)));
                continue;
            }
        };
        if result.native_binding() != &native {
            findings.push(finding(
                "source_original_verified_binding_mismatch",
                Some(hash),
            ));
            continue;
        }
        let IntakeResponseContent::Protected(locator) = &original.entry.response_content else {
            unreachable!("validated protected row")
        };
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
            locator,
            &pins,
            result.protected_record_bytes(),
            result.canonical_response_bytes(),
        )
        .is_err()
        {
            findings.push(finding(
                "source_original_protected_content_mismatch",
                Some(hash),
            ));
        }
    }
    for r in &profile.required_intakes {
        if !covered.contains(&r.intake_event_hash) {
            findings.push(finding(
                "source_original_required_content_missing",
                Some(r.intake_event_hash),
            ));
        }
    }
    findings
}

#[cfg(test)]
#[path = "source_original_tests.rs"]
mod tests;
