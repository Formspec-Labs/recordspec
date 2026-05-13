// Rust guideline compliant 2026-02-21
//! WOS export catalog validation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use trellis_types::sha256_bytes;
use trellis_verify::{DomainEvent, DomainExport, DomainFinding, Severity};

use crate::event_types::{
    INTAKE_EXPORT_EXTENSION, SIGNATURE_EXPORT_EXTENSION, WOS_CASE_CREATED_EVENT_TYPE,
    WOS_INTAKE_ACCEPTED_EVENT_TYPE, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE,
};
use crate::records::{
    CaseCreatedRecordDetails, IntakeAcceptedRecordDetails, IntakeManifestEntry,
    SignatureAffirmationRecordDetails, SignatureManifestEntry, cbor_nested_map_semantic_eq,
    hex_string, parse_case_created_record, parse_intake_accepted_record,
    parse_intake_export_digest, parse_intake_manifest_entries, parse_signature_affirmation_record,
    parse_signature_export_digest, parse_signature_manifest_entries, response_hash_matches,
};

pub(crate) fn validate_catalogs(export: &DomainExport<'_>) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    findings.extend(validate_signature_catalog(export));
    findings.extend(validate_intake_catalog(export));
    findings
}

fn validate_signature_catalog(export: &DomainExport<'_>) -> Vec<DomainFinding> {
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
    let entries = match parse_signature_manifest_entries(catalog_bytes) {
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
        validate_signature_entry(entry, &event_by_hash, &mut findings);
    }
    findings
}

fn validate_signature_entry(
    entry: &SignatureManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
) {
    let Some(event) = event_by_hash.get(&entry.canonical_event_hash) else {
        findings.push(finding(
            "signature_catalog_event_unresolved",
            Some(entry.canonical_event_hash),
            "signature catalog references an event absent from the export",
        ));
        return;
    };
    if event.event_type != WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE {
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
        match parse_signature_affirmation_record(payload, WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE) {
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
}

fn validate_intake_catalog(export: &DomainExport<'_>) -> Vec<DomainFinding> {
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
        validate_intake_entry(entry, &event_by_hash, &mut findings);
    }
    findings
}

fn validate_intake_entry(
    entry: &IntakeManifestEntry,
    event_by_hash: &BTreeMap<[u8; 32], &DomainEvent>,
    findings: &mut Vec<DomainFinding>,
) {
    let Some(event) = event_by_hash.get(&entry.intake_event_hash) else {
        findings.push(finding(
            "intake_event_unresolved",
            Some(entry.intake_event_hash),
            "intake catalog references an event absent from the export",
        ));
        return;
    };
    if event.event_type != WOS_INTAKE_ACCEPTED_EVENT_TYPE {
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
    let intake_record = match parse_intake_accepted_record(payload, WOS_INTAKE_ACCEPTED_EVENT_TYPE)
    {
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
    match response_hash_matches(&entry.handoff.response_hash, &entry.response_bytes) {
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
            if case_event.event_type != WOS_CASE_CREATED_EVENT_TYPE {
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
            let case_record = match parse_case_created_record(payload, WOS_CASE_CREATED_EVENT_TYPE)
            {
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

fn signature_entry_matches_record(
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
