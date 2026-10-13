// Rust guideline compliant 2026-02-21
//! WOS export catalog validation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use integrity_verify::trellis::{DomainEvent, DomainExport, DomainFinding, Severity};
use trellis_types::sha256_bytes;

use crate::event_types::{
    INTAKE_EXPORT_EXTENSION, SIGNATURE_EXPORT_EXTENSION, wos_case_created_event_type,
    wos_intake_accepted_event_type, wos_signature_affirmation_event_type,
};
use crate::records::{
    CaseCreatedRecordDetails, IntakeAcceptedRecordDetails, IntakeManifestEntry,
    IntakeResponseContent, SignatureAffirmationRecordDetails, SignatureManifestEntry,
    cbor_nested_map_semantic_eq, hex_string, parse_case_created_record,
    parse_intake_accepted_record, parse_intake_export_digest, parse_intake_manifest_entries,
    parse_signature_affirmation_record, parse_signature_export_digest,
    parse_signature_manifest_entries, response_hash_matches,
};

pub(crate) fn validate_catalogs(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    findings.extend(validate_signature_catalog(export));
    findings.extend(validate_intake_catalog(export));
    findings
}

/// Checks publication structure without asserting protected Source content validity.
pub(crate) fn validate_source_content_publication_catalogs(
    export: &DomainExport<'_>,
) -> Vec<DomainFinding> {
    let mut findings = validate_signature_catalog_phase(export, false, false);
    findings.extend(validate_intake_catalog_mode(export, false));
    findings
}

/// Requires protected content for every independently selected native occurrence.
///
/// This is a codec/native-binding gate, not decryption or Source signature verification.
/// Protected content remains unavailable until those independent checks are composed.
pub(crate) fn validate_required_response_catalogs(
    export: &DomainExport<'_>,
    required_intakes: &BTreeSet<[u8; 32]>,
    required_signatures: &BTreeSet<[u8; 32]>,
) -> Vec<DomainFinding> {
    let mut findings = validate_catalogs(export);
    let intakes = export
        .members
        .get("063-intake-handoffs.cbor")
        .and_then(|bytes| parse_intake_manifest_entries(bytes).ok())
        .unwrap_or_default();
    let signatures = export
        .members
        .get("062-signature-affirmations.cbor")
        .and_then(|bytes| parse_signature_manifest_entries(bytes).ok())
        .unwrap_or_default();
    let intake_bound = export
        .members
        .get("063-intake-handoffs.cbor")
        .is_some_and(|bytes| {
            export
                .manifest_extensions
                .get(INTAKE_EXPORT_EXTENSION)
                .and_then(|extension| parse_intake_export_digest(extension).ok())
                == Some(sha256_bytes(bytes))
        });
    let signature_bound = export
        .members
        .get("062-signature-affirmations.cbor")
        .is_some_and(|bytes| {
            export
                .manifest_extensions
                .get(SIGNATURE_EXPORT_EXTENSION)
                .and_then(|extension| parse_signature_export_digest(extension).ok())
                == Some(sha256_bytes(bytes))
        });
    if !required_intakes.is_empty() && !intake_bound {
        findings.push(finding(
            "required_response_catalog_unbound",
            None,
            "selected original content requires its valid manifest-bound intake catalog",
        ));
    }
    if !required_signatures.is_empty() && !signature_bound {
        findings.push(finding(
            "required_response_catalog_unbound",
            None,
            "selected signing content requires its valid manifest-bound signature catalog",
        ));
    }
    // Digest mismatches already run legacy native checks; missing/malformed extensions do not.
    let intake_checks_ran = export
        .manifest_extensions
        .get(INTAKE_EXPORT_EXTENSION)
        .is_some_and(|extension| parse_intake_export_digest(extension).is_ok());
    let signature_checks_ran = export
        .manifest_extensions
        .get(SIGNATURE_EXPORT_EXTENSION)
        .is_some_and(|extension| parse_signature_export_digest(extension).is_ok());
    let fallback = (!required_intakes.is_empty() && !intake_checks_ran)
        || (!required_signatures.is_empty() && !signature_checks_ran);
    let events = if fallback {
        event_by_hash(export.events, &mut findings)
    } else {
        BTreeMap::new()
    };
    if !intake_checks_ran {
        for entry in &intakes {
            if required_intakes.contains(&entry.intake_event_hash) {
                validate_intake_entry(entry, &events, &mut findings);
            }
        }
    }
    if !signature_checks_ran {
        for entry in &signatures {
            if required_signatures.contains(&entry.canonical_event_hash) {
                validate_signature_entry(entry, &events, &mut findings);
            }
        }
    }
    for hash in required_intakes {
        if !intakes.iter().any(|entry| {
            entry.intake_event_hash == *hash
                && matches!(entry.response_content, IntakeResponseContent::Protected(_))
        }) {
            findings.push(finding(
                "required_protected_response_missing",
                Some(*hash),
                "selected original Response requires protected catalog content",
            ));
        }
    }
    for hash in required_signatures {
        if !signatures
            .iter()
            .any(|entry| entry.canonical_event_hash == *hash && entry.protected_response.is_some())
        {
            findings.push(finding(
                "required_protected_response_missing",
                Some(*hash),
                "selected signing occurrence requires protected catalog content",
            ));
        }
    }
    for hash in required_intakes.iter().chain(required_signatures) {
        let protected = intakes.iter().any(|entry| {
            entry.intake_event_hash == *hash
                && matches!(entry.response_content, IntakeResponseContent::Protected(_))
        }) || signatures
            .iter()
            .any(|entry| entry.canonical_event_hash == *hash && entry.protected_response.is_some());
        if protected
            && !findings.iter().any(|item| {
                item.kind == "protected_response_unavailable" && item.event_hash == Some(*hash)
            })
        {
            findings.push(finding("protected_response_unavailable", Some(*hash), "selected protected content requires independently admitted opening and Source verification"));
        }
    }
    findings
}

fn validate_signature_catalog(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    validate_signature_catalog_mode(export, true)
}
fn validate_signature_catalog_mode(
    export: &DomainExport<'_>,
    require_source_content: bool,
) -> Vec<DomainFinding> {
    // Existing full Source validators still require opening legacy protected
    // signature Responses; only the explicit publication phase defers that check.
    validate_signature_catalog_phase(export, require_source_content, true)
}

#[cfg(test)]
mod publication_phase_controls {
    use super::*;
    use integrity_verify::trellis::RecordValidator;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Capture(RefCell<Vec<DomainEvent>>);
    impl RecordValidator for Capture {
        fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
            self.0.replace(events.to_vec());
            Vec::new()
        }
    }

    #[test]
    fn source_content_publication_keeps_legacy_opening_required_in_full_source_phase() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../fixtures/vectors/export/006-signature-affirmations-inline/expected-export.zip",
        );
        let zip = std::fs::read(path).unwrap();
        let capture = Capture::default();
        let _ = integrity_verify::trellis::verify_export_zip_with_validator(&zip, &capture);
        let events = capture.0.into_inner();
        let members = integrity_bundle::read_stored_zip(&zip).unwrap();
        let raw = members
            .iter()
            .find(|member| member.path().ends_with("062-signature-affirmations.cbor"))
            .unwrap()
            .bytes();
        let entry = parse_signature_manifest_entries(raw).unwrap().remove(0);
        // This is a codec-phase control; no encryption or Source signature is claimed.
        let locator = crate::records::ProtectedResponseLocator {
            native_event_hash: entry.canonical_event_hash,
            response_ref: entry.formspec_response_ref.clone(),
            response_id: "codec-response".into(),
            response_hash: format!("sha256:{}", "00".repeat(32)),
            original_byte_length: 1,
            content_hash: [2; 32],
            context_key: vec![3; 32],
            record_hash: [4; 32],
            source_binding_hash: [5; 32],
            publication_hash: [6; 32],
            public_policy_hash: [7; 32],
            recipient_policy_hash: [8; 32],
            nonce: [9; 12],
            key_bag: ciborium::Value::Map(Vec::new()),
        };
        let mut catalog = trellis_types::decode_cbor_value(raw).unwrap();
        catalog.as_array_mut().unwrap()[0]
            .as_map_mut()
            .unwrap()
            .push((
                ciborium::Value::Text("protected_response".into()),
                locator.to_value(true),
            ));
        let bytes = trellis_types::encode_canonical_cbor_value(&catalog).unwrap();
        let members = BTreeMap::from([("062-signature-affirmations.cbor".into(), bytes.clone())]);
        let extension = ciborium::Value::Map(vec![(
            ciborium::Value::Text("signature_catalog_digest".into()),
            ciborium::Value::Bytes(sha256_bytes(&bytes).to_vec()),
        )]);
        let extensions = BTreeMap::from([(
            SIGNATURE_EXPORT_EXTENSION.into(),
            trellis_types::encode_canonical_cbor_value(&extension).unwrap(),
        )]);
        let export = DomainExport {
            events: &events,
            members: &members,
            manifest_extensions: &extensions,
        };
        let full = validate_signature_catalog_mode(&export, false);
        assert!(
            full.iter()
                .any(|finding| finding.kind == "protected_response_unavailable")
        );
        let publication = validate_signature_catalog_phase(&export, false, false);
        assert!(publication.is_empty(), "{publication:?}");
    }
}

fn validate_signature_catalog_phase(
    export: &DomainExport<'_>,
    require_source_content: bool,
    require_legacy_protected_content: bool,
) -> Vec<DomainFinding> {
    let Some(extension) = export.manifest_extensions.get(SIGNATURE_EXPORT_EXTENSION) else {
        return Vec::new();
    };
    let Ok(expected_digest) = parse_signature_export_digest(extension) else {
        return vec![finding(
            "signature_catalog_invalid",
            None,
            "signature export extension is invalid",
        )];
    };
    let Some(catalog_bytes) = export.members.get("062-signature-affirmations.cbor") else {
        return vec![finding(
            "missing_signature_catalog",
            None,
            "export is missing 062-signature-affirmations.cbor",
        )];
    };
    let mut findings = Vec::new();
    if sha256_bytes(catalog_bytes) != expected_digest {
        findings.push(finding(
            "signature_catalog_digest_mismatch",
            None,
            "signature catalog digest does not match manifest extension",
        ));
    }
    let entries = match crate::source_signed_task::legacy_catalog(catalog_bytes) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![finding(
                "signature_catalog_invalid",
                None,
                format!("signature catalog is invalid: {error}"),
            )];
        }
    };
    let event_by_hash = event_by_hash(export.events, &mut findings);
    let mut seen = BTreeSet::new();
    for entry in &entries {
        if !seen.insert(entry.canonical_event_hash) {
            findings.push(finding(
                "signature_catalog_duplicate_event",
                Some(entry.canonical_event_hash),
                "signature catalog repeats an event hash",
            ));
        }
    }
    for entry in &entries {
        validate_signature_entry_mode(
            entry,
            &event_by_hash,
            &mut findings,
            require_legacy_protected_content,
        );
    }
    findings.extend(crate::source_signed_task::structural_findings(
        export,
        require_source_content,
    ));
    findings
}

fn validate_signature_entry(
    entry: &SignatureManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
) {
    validate_signature_entry_mode(entry, event_by_hash, findings, true);
}

fn validate_signature_entry_mode(
    entry: &SignatureManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
    require_source_content: bool,
) {
    let Some(event) = event_by_hash.get(&entry.canonical_event_hash) else {
        findings.push(finding(
            "signature_catalog_event_unresolved",
            Some(entry.canonical_event_hash),
            "signature catalog references an event absent from the export",
        ));
        return;
    };
    if event.event_type != wos_signature_affirmation_event_type() {
        findings.push(finding(
            "signature_catalog_event_type_mismatch",
            Some(entry.canonical_event_hash),
            "signature catalog event is not a WOS signature affirmation",
        ));
        return;
    }
    let Some(payload) = event.payload.as_deref() else {
        findings.push(finding(
            "signature_affirmation_payload_unreadable",
            Some(entry.canonical_event_hash),
            "signature affirmation payload is not readable",
        ));
        return;
    };
    let record =
        match parse_signature_affirmation_record(payload, wos_signature_affirmation_event_type()) {
            Ok(record) => record,
            Err(error) => {
                findings.push(finding(
                    "signature_affirmation_payload_invalid",
                    Some(entry.canonical_event_hash),
                    format!("signature affirmation payload is invalid: {error}"),
                ));
                return;
            }
        };
    if !signature_entry_matches_record(entry, &record) {
        findings.push(finding(
            "signature_catalog_mismatch",
            Some(entry.canonical_event_hash),
            "signature catalog fields do not match the signed record",
        ));
    }
    if let Some(content) = &entry.protected_response {
        if content.native_event_hash != entry.canonical_event_hash
            || content.response_ref != entry.formspec_response_ref
        {
            findings.push(finding(
                "protected_response_native_binding_mismatch",
                Some(entry.canonical_event_hash),
                "protected Response locator differs from the actual signature anchor",
            ));
        }
        // Codec binding cannot confer decryption or Source signature authority.
        if require_source_content {
            findings.push(finding(
                "protected_response_unavailable",
                Some(entry.canonical_event_hash),
                "protected Response requires independently admitted opening and Source verification",
            ));
        }
    }
}

fn validate_intake_catalog(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    validate_intake_catalog_mode(export, true)
}
fn validate_intake_catalog_mode(
    export: &DomainExport<'_>,
    require_protected_content: bool,
) -> Vec<DomainFinding> {
    let Some(extension) = export.manifest_extensions.get(INTAKE_EXPORT_EXTENSION) else {
        return Vec::new();
    };
    let Ok(expected_digest) = parse_intake_export_digest(extension) else {
        return vec![finding(
            "intake_handoff_catalog_invalid",
            None,
            "intake export extension is invalid",
        )];
    };
    let Some(catalog_bytes) = export.members.get("063-intake-handoffs.cbor") else {
        return vec![finding(
            "missing_intake_handoff_catalog",
            None,
            "export is missing 063-intake-handoffs.cbor",
        )];
    };
    let mut findings = Vec::new();
    if sha256_bytes(catalog_bytes) != expected_digest {
        findings.push(finding(
            "intake_handoff_catalog_digest_mismatch",
            None,
            "intake handoff catalog digest does not match manifest extension",
        ));
    }
    let entries = match parse_intake_manifest_entries(catalog_bytes) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![finding(
                "intake_handoff_catalog_invalid",
                None,
                format!("intake handoff catalog is invalid: {error}"),
            )];
        }
    };
    findings.extend(validate_original_context_joins(export, catalog_bytes));
    let event_by_hash = event_by_hash(export.events, &mut findings);
    let mut seen = BTreeSet::new();
    for entry in &entries {
        if !seen.insert(entry.intake_event_hash) {
            findings.push(finding(
                "intake_handoff_catalog_duplicate_event",
                Some(entry.intake_event_hash),
                "intake handoff catalog repeats an intake event hash",
            ));
        }
    }
    for entry in &entries {
        validate_intake_entry_mode(
            entry,
            &event_by_hash,
            &mut findings,
            require_protected_content,
        );
    }
    findings
}

/// Checks supplied original/task associations without requiring them on legacy rows.
fn validate_original_context_joins(
    export: &DomainExport<'_>,
    catalog_bytes: &[u8],
) -> Vec<DomainFinding> {
    let originals = match crate::protected_intake_responses_from_catalog(catalog_bytes) {
        Ok(originals) => originals,
        Err(error) => {
            return vec![finding("intake_handoff_catalog_invalid", None, error)];
        }
    };
    if originals
        .iter()
        .all(|original| original.original_context_proof().is_none())
    {
        return Vec::new();
    }
    let tasks = export
        .members
        .get("062-signature-affirmations.cbor")
        .and_then(|bytes| crate::source_signed_tasks_from_catalog(bytes).ok())
        .unwrap_or_default();
    originals
        .iter()
        .filter(|original| original.original_context_proof().is_some())
        .filter_map(|original| {
            original
                .validate_original_context_proof(&tasks)
                .err()
                .map(|error| {
                    finding(
                        "source_original_context_join_invalid",
                        Some(original.intake_event_hash()),
                        error,
                    )
                })
        })
        .collect()
}

fn validate_intake_entry(
    entry: &IntakeManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
) {
    validate_intake_entry_mode(entry, event_by_hash, findings, true)
}
fn validate_intake_entry_mode(
    entry: &IntakeManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
    require_protected_content: bool,
) {
    let Some(event) = event_by_hash.get(&entry.intake_event_hash) else {
        findings.push(finding(
            "intake_event_unresolved",
            Some(entry.intake_event_hash),
            "intake catalog references an event absent from the export",
        ));
        return;
    };
    if event.event_type != wos_intake_accepted_event_type() {
        findings.push(finding(
            "intake_event_type_mismatch",
            Some(entry.intake_event_hash),
            "intake catalog event is not a WOS intakeAccepted event",
        ));
        return;
    }
    let Some(payload) = event.payload.as_deref() else {
        findings.push(finding(
            "intake_payload_unreadable",
            Some(entry.intake_event_hash),
            "intakeAccepted payload is not readable",
        ));
        return;
    };
    let intake_record =
        match parse_intake_accepted_record(payload, wos_intake_accepted_event_type()) {
            Ok(record) => record,
            Err(error) => {
                findings.push(finding(
                    "intake_payload_invalid",
                    Some(entry.intake_event_hash),
                    format!("intakeAccepted payload is invalid: {error}"),
                ));
                return;
            }
        };
    if !intake_entry_matches_record(entry, &intake_record) {
        findings.push(finding(
            "intake_handoff_mismatch",
            Some(entry.intake_event_hash),
            "intake handoff fields do not match the intakeAccepted record",
        ));
    }
    match &entry.response_content {
        IntakeResponseContent::Inline(bytes) => {
            match response_hash_matches(&entry.handoff.response_hash, bytes) {
                Ok(true) => {}
                Ok(false) => findings.push(finding(
                    "intake_response_hash_mismatch",
                    Some(entry.intake_event_hash),
                    "intake handoff response hash does not match response bytes",
                )),
                Err(error) => findings.push(finding(
                    "intake_handoff_catalog_invalid",
                    Some(entry.intake_event_hash),
                    format!("intake handoff response hash is invalid: {error}"),
                )),
            }
        }
        IntakeResponseContent::Protected(content) => {
            if content.native_event_hash != entry.intake_event_hash
                || content.response_ref != entry.handoff.response_ref
                || content.response_hash != entry.handoff.response_hash
            {
                findings.push(finding(
                    "protected_response_native_binding_mismatch",
                    Some(entry.intake_event_hash),
                    "protected Response locator differs from the actual intake handoff anchor",
                ));
            }
            if require_protected_content {
                findings.push(finding("protected_response_unavailable", Some(entry.intake_event_hash), "protected Response requires independently admitted opening and Source verification"));
            }
        }
    }
    validate_case_created_entry(entry, &intake_record, event_by_hash, findings);
}

fn validate_case_created_entry(
    entry: &IntakeManifestEntry,
    intake_record: &IntakeAcceptedRecordDetails,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
) {
    match (
        entry.handoff.initiation_mode.as_str(),
        entry.case_created_event_hash,
    ) {
        ("workflowInitiated", Some(_)) => findings.push(finding(
            "case_created_handoff_mismatch",
            Some(entry.intake_event_hash),
            "workflowInitiated handoff must not carry caseCreated event hash",
        )),
        ("workflowInitiated", None) => {}
        ("publicIntake", None) => findings.push(finding(
            "case_created_handoff_mismatch",
            Some(entry.intake_event_hash),
            "publicIntake handoff must carry caseCreated event hash",
        )),
        ("publicIntake", Some(case_created_hash)) => {
            let Some(case_event) = event_by_hash.get(&case_created_hash) else {
                findings.push(finding(
                    "case_created_event_unresolved",
                    Some(case_created_hash),
                    "caseCreated event hash is absent from the export",
                ));
                return;
            };
            if case_event.event_type != wos_case_created_event_type() {
                findings.push(finding(
                    "case_created_event_type_mismatch",
                    Some(case_created_hash),
                    "caseCreated hash does not reference a WOS caseCreated event",
                ));
                return;
            }
            let Some(payload) = case_event.payload.as_deref() else {
                findings.push(finding(
                    "case_created_payload_unreadable",
                    Some(case_created_hash),
                    "caseCreated payload is not readable",
                ));
                return;
            };
            let case_record =
                match parse_case_created_record(payload, wos_case_created_event_type()) {
                    Ok(record) => record,
                    Err(error) => {
                        findings.push(finding(
                            "case_created_payload_invalid",
                            Some(case_created_hash),
                            format!("caseCreated payload is invalid: {error}"),
                        ));
                        return;
                    }
                };
            if !case_created_record_matches_handoff(entry, intake_record, &case_record) {
                findings.push(finding(
                    "case_created_handoff_mismatch",
                    Some(case_created_hash),
                    "caseCreated fields do not match the intake handoff",
                ));
            }
        }
        _ => findings.push(finding(
            "intake_handoff_catalog_invalid",
            Some(entry.intake_event_hash),
            "intake handoff initiationMode is unsupported",
        )),
    }
}

fn event_by_hash<'a>(
    events: &'a [DomainEvent],
    findings: &mut Vec<DomainFinding>,
) -> BTreeMap<[u8; 32], &'a DomainEvent> {
    let mut by_hash = BTreeMap::new();
    for event in events {
        if by_hash.insert(event.canonical_event_hash, event).is_some() {
            findings.push(finding(
                "export_events_duplicate_canonical_hash",
                Some(event.canonical_event_hash),
                format!(
                    "export contains duplicate event hash {}",
                    hex_string(&event.canonical_event_hash)
                ),
            ));
        }
    }
    by_hash
}

pub(crate) fn signature_entry_matches_record(
    entry: &SignatureManifestEntry,
    record: &SignatureAffirmationRecordDetails,
) -> bool {
    entry.signer_id == record.signer_id
        && entry.role_id == record.role_id
        && entry.role == record.role
        && entry.document_id == record.document_id
        && entry.document_hash == record.document_hash
        && entry.document_hash_algorithm == record.document_hash_algorithm
        && entry.signed_at == record.signed_at
        && cbor_nested_map_semantic_eq(&entry.identity_binding, &record.identity_binding)
        && cbor_nested_map_semantic_eq(&entry.consent_reference, &record.consent_reference)
        && entry.signature_provider == record.signature_provider
        && entry.ceremony_id == record.ceremony_id
        && entry.source_signature_system == record.source_signature_system
        && entry.source_signature_id == record.source_signature_id
        && entry.signed_payload_digest == record.signed_payload_digest
        && entry.signed_payload_digest_algorithm == record.signed_payload_digest_algorithm
        && entry.signing_intent == record.signing_intent
        && entry.profile_ref == record.profile_ref
        && entry.profile_key == record.profile_key
        && entry.formspec_response_ref == record.formspec_response_ref
        && record.signing_act_id.as_ref() == Some(&entry.signing_act_id)
        && entry.presentation_hash == record.presentation_hash
        && entry.witnessed_signature_ref == record.witnessed_signature_ref
}

fn intake_entry_matches_record(
    entry: &IntakeManifestEntry,
    record: &IntakeAcceptedRecordDetails,
) -> bool {
    if entry.handoff.handoff_id != record.intake_id {
        return false;
    }
    match entry.handoff.initiation_mode.as_str() {
        "workflowInitiated" => {
            entry.handoff.case_ref.as_deref() == Some(record.case_ref.as_str())
                && record.case_intent == "attachToExistingCase"
                && record.case_disposition == "attachToExistingCase"
        }
        "publicIntake" => {
            record.case_intent == "requestGovernedCaseCreation"
                && record.case_disposition == "createGovernedCase"
                && record.definition_url.as_deref() == Some(entry.handoff.definition_url.as_str())
                && record.definition_version.as_deref()
                    == Some(entry.handoff.definition_version.as_str())
        }
        _ => false,
    }
}

fn case_created_record_matches_handoff(
    entry: &IntakeManifestEntry,
    intake_record: &IntakeAcceptedRecordDetails,
    case_record: &CaseCreatedRecordDetails,
) -> bool {
    case_record.case_ref == intake_record.case_ref
        && case_record.intake_handoff_ref == entry.handoff.handoff_id
        && case_record.formspec_response_ref == entry.handoff.response_ref
        && case_record.validation_report_ref == entry.handoff.validation_report_ref
        && case_record.ledger_head_ref == entry.handoff.ledger_head_ref
        && case_record.initiation_mode == entry.handoff.initiation_mode
}

fn finding(
    kind: impl Into<String>,
    event_hash: Option<[u8; 32]>,
    message: impl Into<String>,
) -> DomainFinding {
    DomainFinding::new(kind, event_hash, Severity::Failure, message)
}

// Explicit selected owning verification changes Source content dispatch only.
// All legacy/native/intake checks remain; no existing finding is filtered away.
pub(crate) fn validate_catalogs_with_source_content<
    V: crate::source_signed_task::SourceTaskContentVerifier,
>(
    export: &DomainExport<'_>,
    archive_sha256: [u8; 32],
    profile: &crate::source_signed_task::SourceTaskContentProfileV1,
    verifier: &V,
) -> Vec<DomainFinding> {
    let mut findings = validate_signature_catalog_mode(export, false);
    findings.extend(validate_intake_catalog(export));
    findings.extend(crate::source_signed_task::verified_profile_findings(
        export,
        archive_sha256,
        profile,
        verifier,
    ));
    findings
}

pub(crate) fn intake_native_findings(
    entry: &IntakeManifestEntry,
    export: &DomainExport<'_>,
) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    let events = event_by_hash(export.events, &mut findings);
    validate_intake_entry_mode(entry, &events, &mut findings, false);
    findings
}
pub(crate) fn validate_catalogs_with_all_source_content<
    T: crate::SourceTaskContentVerifier,
    I: crate::SourceIntakeContentVerifier,
>(
    export: &DomainExport<'_>,
    archive_sha256: [u8; 32],
    profile: &crate::SourceTaskContentProfileV1,
    tasks: &T,
    intakes: &I,
) -> Vec<DomainFinding> {
    let mut findings = validate_signature_catalog_mode(export, false);
    findings.extend(validate_intake_catalog_mode(export, false));
    findings.extend(crate::source_signed_task::verified_profile_findings(
        export,
        archive_sha256,
        profile,
        tasks,
    ));
    findings.extend(crate::source_original::verified_original_findings(
        export,
        archive_sha256,
        profile,
        intakes,
    ));
    findings
}
