//! ADR 0071 CaseOpenPin and migration transition verification.

#![forbid(unsafe_code)]

use integrity_verify::trellis::{DomainEvent, DomainFinding, Severity};
use trellis_types::{CaseOpenPin, MigrationPinChangedPayload};

pub const PIN_MUTATION_REJECTED: &str = "pin_mutation_rejected";
pub const PIN_INVALID: &str = "pin_invalid";
pub const PIN_TRANSITION_INVALID: &str = "pin_transition_invalid";
pub const WOS_MIGRATION_PIN_CHANGED_EVENT_TYPE: &str = "wos.kernel.migration_pin_changed";

/// Extracts `CaseOpenPin` from an event payload if present.
pub fn extract_pin(payload: &[u8]) -> Option<CaseOpenPin> {
    // Try JSON first
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
        if let Some(pin_val) = v.get("pin").or_else(|| v.get("caseOpenPin")) {
            if let Ok(pin) = serde_json::from_value::<CaseOpenPin>(pin_val.clone()) {
                return Some(pin);
            }
        }
        if let Some(data) = v.get("data") {
            if let Some(pin_val) = data.get("pin").or_else(|| data.get("caseOpenPin")) {
                if let Ok(pin) = serde_json::from_value::<CaseOpenPin>(pin_val.clone()) {
                    return Some(pin);
                }
            }
        }
    }
    // Try CBOR
    if let Ok(cbor_val) = ciborium::from_reader::<ciborium::Value, _>(payload) {
        if let Ok(json_val) = serde_json::to_value(&cbor_val) {
            if let Some(pin_val) = json_val.get("pin").or_else(|| json_val.get("caseOpenPin")) {
                if let Ok(pin) = serde_json::from_value::<CaseOpenPin>(pin_val.clone()) {
                    return Some(pin);
                }
            }
            if let Some(data) = json_val.get("data") {
                if let Some(pin_val) = data.get("pin").or_else(|| data.get("caseOpenPin")) {
                    if let Ok(pin) = serde_json::from_value::<CaseOpenPin>(pin_val.clone()) {
                        return Some(pin);
                    }
                }
            }
        }
    }
    None
}

/// Parses `MigrationPinChangedPayload` from a migration event payload.
pub fn parse_migration_pin_changed(payload: &[u8]) -> Result<MigrationPinChangedPayload, &'static str> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
        if let Ok(record) = serde_json::from_value::<MigrationPinChangedPayload>(v.clone()) {
            return Ok(record);
        }
        if let Some(data) = v.get("data") {
            if let Ok(record) = serde_json::from_value::<MigrationPinChangedPayload>(data.clone()) {
                return Ok(record);
            }
        }
    }
    if let Ok(cbor_val) = ciborium::from_reader::<ciborium::Value, _>(payload) {
        if let Ok(json_val) = serde_json::to_value(&cbor_val) {
            if let Ok(record) = serde_json::from_value::<MigrationPinChangedPayload>(json_val.clone()) {
                return Ok(record);
            }
            if let Some(data) = json_val.get("data") {
                if let Ok(record) = serde_json::from_value::<MigrationPinChangedPayload>(data.clone()) {
                    return Ok(record);
                }
            }
        }
    }
    Err("payload is not a valid MigrationPinChanged record")
}

/// Verifies CaseOpenPin immutability and valid MigrationPinChanged transitions across an event chain (ADR 0071).
pub(crate) fn validate_pin_semantics(events: &[DomainEvent]) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    let mut current_pin: Option<CaseOpenPin> = None;

    for event in events {
        let Some(payload) = event.payload.as_deref() else {
            continue;
        };

        if event.event_type == WOS_MIGRATION_PIN_CHANGED_EVENT_TYPE {
            match parse_migration_pin_changed(payload) {
                Ok(record) => {
                    if let Some(active) = &current_pin {
                        if active != &record.prior_pin_set {
                            findings.push(DomainFinding::new(
                                PIN_TRANSITION_INVALID,
                                Some(event.canonical_event_hash),
                                Severity::Failure,
                                "MigrationPinChanged priorPinSet does not match active case pin",
                            ));
                        }
                    }
                    if let Err(err) = record.new_pin_set.validate() {
                        findings.push(DomainFinding::new(
                            PIN_TRANSITION_INVALID,
                            Some(event.canonical_event_hash),
                            Severity::Failure,
                            err,
                        ));
                    } else {
                        current_pin = Some(record.new_pin_set);
                    }
                }
                Err(err) => {
                    findings.push(DomainFinding::new(
                        PIN_TRANSITION_INVALID,
                        Some(event.canonical_event_hash),
                        Severity::Failure,
                        err,
                    ));
                }
            }
            continue;
        }

        // Check if event carries an explicit pin
        if let Some(pin) = extract_pin(payload) {
            if let Err(err) = pin.validate() {
                findings.push(DomainFinding::new(
                    PIN_INVALID,
                    Some(event.canonical_event_hash),
                    Severity::Failure,
                    err,
                ));
                continue;
            }

            match &current_pin {
                None => {
                    // First pin observed in chain (case-open event)
                    current_pin = Some(pin);
                }
                Some(active) => {
                    if active != &pin {
                        // Unauthorized pin mutation without MigrationPinChanged!
                        findings.push(DomainFinding::new(
                            PIN_MUTATION_REJECTED,
                            Some(event.canonical_event_hash),
                            Severity::Failure,
                            "unauthorized pin mutation in event chain without MigrationPinChanged transition",
                        ));
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_verify::trellis::TrellisTimestamp;

    fn make_event(event_type: &str, payload: serde_json::Value, hash_byte: u8) -> DomainEvent {
        DomainEvent {
            event_type: event_type.to_string(),
            payload: Some(serde_json::to_vec(&payload).unwrap()),
            canonical_event_hash: [hash_byte; 32],
            authored_at: TrellisTimestamp {
                seconds: 1700000000,
                nanos: 0,
            },
        }
    }

    fn sample_pin(def_ver: &str) -> CaseOpenPin {
        CaseOpenPin::new(def_ver, "1.0.0", "phase-1", "complete")
    }

    #[test]
    fn test_pin_set_on_case_open_is_valid() {
        let pin = sample_pin("1.0.0");
        let open_event = make_event(
            "wos.kernel.case_created",
            serde_json::json!({
                "id": "prov-1",
                "pin": pin,
                "actorId": "staff"
            }),
            1,
        );
        let subsequent_event = make_event(
            "wos.kernel.intake_accepted",
            serde_json::json!({
                "id": "prov-2",
                "actorId": "staff"
            }),
            2,
        );

        let findings = validate_pin_semantics(&[open_event, subsequent_event]);
        assert!(findings.is_empty(), "valid pin-set must have 0 findings: {:?}", findings);
    }

    #[test]
    fn test_pin_mutation_without_migration_record_is_rejected() {
        let pin1 = sample_pin("1.0.0");
        let pin2 = sample_pin("2.0.0"); // Mutated definition version

        let open_event = make_event(
            "wos.kernel.case_created",
            serde_json::json!({
                "id": "prov-1",
                "pin": pin1,
                "actorId": "staff"
            }),
            1,
        );
        // Subsequent event illicitly carries a different pin without MigrationPinChanged!
        let mutated_event = make_event(
            "wos.kernel.signature_affirmation",
            serde_json::json!({
                "id": "prov-2",
                "pin": pin2,
                "actorId": "staff"
            }),
            2,
        );

        let findings = validate_pin_semantics(&[open_event, mutated_event]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PIN_MUTATION_REJECTED);
        assert_eq!(findings[0].severity, Severity::Failure);
    }

    #[test]
    fn test_valid_pin_transition_under_migration_pin_changed() {
        let pin_v1 = sample_pin("1.0.0");
        let pin_v2 = sample_pin("2.0.0");

        let open_event = make_event(
            "wos.kernel.case_created",
            serde_json::json!({
                "id": "prov-1",
                "pin": pin_v1,
                "actorId": "staff"
            }),
            1,
        );

        // Valid MigrationPinChanged transition
        let migration_event = make_event(
            WOS_MIGRATION_PIN_CHANGED_EVENT_TYPE,
            serde_json::json!({
                "caseId": "case-001",
                "priorPinSet": pin_v1,
                "newPinSet": pin_v2,
                "migrationPolicyRef": "urn:agency:policy:migrate-v2",
                "authorizingActorId": "actor:director",
                "migrationRationale": "Routine definition upgrade",
                "timestamp": "2026-10-23T00:00:00Z"
            }),
            2,
        );

        // Subsequent event under new pin v2 is now valid!
        let post_migration_event = make_event(
            "wos.kernel.signature_affirmation",
            serde_json::json!({
                "id": "prov-3",
                "pin": pin_v2,
                "actorId": "staff"
            }),
            3,
        );

        let findings = validate_pin_semantics(&[open_event, migration_event, post_migration_event]);
        assert!(findings.is_empty(), "valid pin transition must have 0 findings: {:?}", findings);
    }

    #[test]
    fn test_invalid_migration_transition_with_mismatching_prior_pin() {
        let pin_v1 = sample_pin("1.0.0");
        let wrong_prior = sample_pin("0.9.0");
        let pin_v2 = sample_pin("2.0.0");

        let open_event = make_event(
            "wos.kernel.case_created",
            serde_json::json!({
                "id": "prov-1",
                "pin": pin_v1,
                "actorId": "staff"
            }),
            1,
        );

        // Transition claims wrong prior pin
        let migration_event = make_event(
            WOS_MIGRATION_PIN_CHANGED_EVENT_TYPE,
            serde_json::json!({
                "caseId": "case-001",
                "priorPinSet": wrong_prior,
                "newPinSet": pin_v2,
                "migrationPolicyRef": "urn:agency:policy:migrate-v2",
                "authorizingActorId": "actor:director",
                "migrationRationale": "Wrong prior",
                "timestamp": "2026-10-23T00:00:00Z"
            }),
            2,
        );

        let findings = validate_pin_semantics(&[open_event, migration_event]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PIN_TRANSITION_INVALID);
    }

    #[test]
    fn test_malformed_pin_missing_dimension_is_rejected() {
        // Missing conformanceClass
        let malformed_pin = serde_json::json!({
            "formspec": { "definitionVersion": "1.0.0" },
            "wos": { "$wosWorkflowVersion": "1.0.0" },
            "trellis": { "envelopeVersion": "phase-1", "conformanceClass": "" }
        });

        let open_event = make_event(
            "wos.kernel.case_created",
            serde_json::json!({
                "id": "prov-1",
                "pin": malformed_pin,
                "actorId": "staff"
            }),
            1,
        );

        let findings = validate_pin_semantics(&[open_event]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PIN_INVALID);
    }
}
