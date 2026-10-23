// Rust guideline compliant 2026-02-21
//! Offline checks for original native WOS provenance records.

#![forbid(unsafe_code)]

use integrity_verify::trellis::{DomainEvent, DomainFinding, Severity};
use wos_events::{NativeProvenanceEvent, WOS_NATIVE_PROVENANCE_EVENT_LITERAL};

/// Validates only the generic route using the same WOS-owned ingress rules.
pub(crate) fn validate_native_provenance(events: &[DomainEvent]) -> Vec<DomainFinding> {
    let mut findings = Vec::new();
    for event in events {
        if event.event_type != WOS_NATIVE_PROVENANCE_EVENT_LITERAL {
            continue;
        }
        let (kind, message) = match event.payload.as_deref() {
            None => (
                "native_provenance_payload_unavailable",
                "generic native provenance payload is unavailable for offline validation",
            ),
            Some(payload) if NativeProvenanceEvent::from_dcbor_slice(payload).is_err() => (
                "native_provenance_invalid",
                "generic native provenance payload fails WOS-owned shape or kind validation",
            ),
            Some(_) => continue,
        };
        // Do not include original record values or schema error details in reports.
        findings.push(DomainFinding::new(
            kind,
            Some(event.canonical_event_hash),
            Severity::Failure,
            message,
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WosRecordValidator, WosVerificationReport};
    use ciborium::Value as Cbor;
    use integrity_verify::trellis::{
        RecordValidator, RelyingPartyResult, TrellisTimestamp, VerdictState,
    };
    use serde_json::{Value, json};
    use stack_common_typeid::testing::fixture_minter;
    use wos_events::{ProvenanceKind, ProvenanceRecord, WOS_CANONICAL_EVENT_LITERALS};

    fn payload(kind: ProvenanceKind) -> Value {
        let mut record = ProvenanceRecord::blank(&fixture_minter(), kind);
        record.timestamp = "2026-10-09T12:00:00Z".into();
        record.audit_layer = Some("facts".into());
        record.definition_version = Some("0.3.0".into());
        // Preserve an original triggering event, including absence of a canonical literal.
        if kind.canonical_event_literal().is_none() {
            record.event = Some("original-trigger".into());
        }
        record.data = Some(
            json!({"nested": [null, true, 42, {"recordKind": "signatureAffirmation"}],
            "text": "Original full text", "unknownApplicationKey": "retained"}),
        );
        json!({"record": record})
    }

    fn encoded(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    fn encoded_cbor(value: &Cbor) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    fn event(hash: u8, payload: Option<Vec<u8>>) -> DomainEvent {
        DomainEvent {
            event_type: WOS_NATIVE_PROVENANCE_EVENT_LITERAL.into(),
            payload,
            canonical_event_hash: [hash; 32],
            authored_at: TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    }

    fn assert_invalid(bytes: Vec<u8>) {
        let findings = WosRecordValidator.validate_events(&[event(3, Some(bytes))]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].kind, "native_provenance_invalid");
        assert_eq!(findings[0].severity, Severity::Failure);
        assert_eq!(findings[0].event_hash, Some([3; 32]));
    }

    #[test]
    fn original_on_entry_and_notice_records_validate_without_specialized_promotion() {
        for kind in [ProvenanceKind::OnEntry, ProvenanceKind::NoticeSent] {
            let original = payload(kind);
            let bytes = encoded(&original);
            let validated = NativeProvenanceEvent::from_dcbor_slice(&bytes).unwrap();
            assert_eq!(validated.record(), &original["record"]);
            let events = vec![event(1, Some(bytes))];
            let before = events.clone();
            assert!(WosRecordValidator.validate_events(&events).is_empty());
            assert_eq!(events, before);
        }
    }

    #[test]
    fn unavailable_payload_blocks_domain_admissibility() {
        let findings = WosRecordValidator.validate_events(&[event(2, None)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "native_provenance_payload_unavailable");
        assert_eq!(findings[0].event_hash, Some([2; 32]));
        let mut substrate = integrity_verify::trellis::VerificationReport::default();
        substrate.structure_verified = true;
        substrate.integrity_verified = true;
        let verdict = WosVerificationReport {
            trellis: substrate,
            wos_findings: findings,
        }
        .verdict();
        assert_eq!(verdict.cryptographic_integrity, VerdictState::Pass);
        assert_eq!(verdict.domain_admissibility, VerdictState::Fail);
        assert_eq!(verdict.relying_party_result, RelyingPartyResult::Invalid);
    }

    #[test]
    fn malformed_wrapper_discriminator_and_original_fields_refuse() {
        let valid = payload(ProvenanceKind::OnEntry);
        let mut cases = vec![Value::Null, json!({}), json!({"record": null})];
        let mut extra_wrapper = valid.clone();
        extra_wrapper["extra"] = json!(true);
        cases.push(extra_wrapper);
        for field in [
            "recordKind",
            "id",
            "timestamp",
            "auditLayer",
            "definitionVersion",
        ] {
            let mut missing = valid.clone();
            missing["record"].as_object_mut().unwrap().remove(field);
            cases.push(missing);
        }
        for (field, value) in [
            ("recordKind", json!("futureUnknownKind")),
            ("recordKind", json!(42)),
            ("id", json!("")),
            ("id", json!("invalid")),
            ("timestamp", json!("not-a-time")),
            ("actorId", json!({"wrong": "type"})),
            ("inputs", json!("not-an-array")),
            ("unrecognizedStructuralField", json!("must not disappear")),
        ] {
            let mut invalid = valid.clone();
            invalid["record"][field] = value;
            cases.push(invalid);
        }
        for value in cases {
            assert_invalid(encoded(&value));
        }
    }

    #[test]
    fn every_existing_canonical_kind_refuses_generic_bypass() {
        assert_eq!(WOS_CANONICAL_EVENT_LITERALS.len(), 30);
        for literal in WOS_CANONICAL_EVENT_LITERALS {
            let kind = ProvenanceKind::from_canonical_event_literal(literal).unwrap();
            assert_invalid(encoded(&payload(kind)));
        }
    }

    #[test]
    fn invalid_cbor_and_ambiguous_maps_refuse_before_json_view() {
        let valid = payload(ProvenanceKind::OnEntry);
        let bytes = encoded(&valid);
        assert_invalid(vec![0xff]);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_invalid(trailing);
        let decoded: Cbor = ciborium::from_reader(bytes.as_slice()).unwrap();
        let Cbor::Map(wrapper) = decoded else {
            panic!("test wrapper must be a map")
        };
        assert_invalid(encoded_cbor(&Cbor::Map(vec![
            wrapper[0].clone(),
            wrapper[0].clone(),
        ])));
        let Cbor::Map(record) = &wrapper[0].1 else {
            panic!("test record must be a map")
        };
        let kind = record
            .iter()
            .find(|(key, _)| key.as_text() == Some("recordKind"))
            .unwrap()
            .clone();
        let mut duplicated = record.clone();
        duplicated.push(kind);
        assert_invalid(encoded_cbor(&Cbor::Map(vec![(
            Cbor::Text("record".into()),
            Cbor::Map(duplicated),
        )])));
        for invalid in [
            Cbor::Tag(0, Box::new(Cbor::Text("2026-10-09T12:00:00Z".into()))),
            Cbor::Bytes(b"record".to_vec()),
            Cbor::Map(vec![(Cbor::Integer(1.into()), Cbor::Null)]),
        ] {
            assert_invalid(encoded_cbor(&Cbor::Map(vec![(
                Cbor::Text("record".into()),
                invalid,
            )])));
        }
        // These would become valid JSON values through the inspection bridge;
        // the strict owner byte helper must reject them before that conversion.
        for (field, replacement) in [
            (
                "timestamp",
                Cbor::Tag(0, Box::new(Cbor::Text("2026-10-09T12:00:00Z".into()))),
            ),
            ("data", Cbor::Bytes(b"application bytes".to_vec())),
        ] {
            let mut unsupported = record.clone();
            unsupported
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some(field))
                .unwrap()
                .1 = replacement;
            assert_invalid(encoded_cbor(&Cbor::Map(vec![(
                Cbor::Text("record".into()),
                Cbor::Map(unsupported),
            )])));
        }
        let mut too_deep = Cbor::Null;
        for _ in 0..130 {
            too_deep = Cbor::Array(vec![too_deep]);
        }
        let mut deep_record = record.clone();
        deep_record
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("data"))
            .unwrap()
            .1 = too_deep;
        assert_invalid(encoded_cbor(&Cbor::Map(vec![(
            Cbor::Text("record".into()),
            Cbor::Map(deep_record),
        )])));
        let mut nested = record.clone();
        let data = nested
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("data"))
            .unwrap();
        data.1 = Cbor::Map(vec![
            (Cbor::Text("duplicate".into()), Cbor::Null),
            (Cbor::Text("duplicate".into()), Cbor::Bool(true)),
        ]);
        assert_invalid(encoded_cbor(&Cbor::Map(vec![(
            Cbor::Text("record".into()),
            Cbor::Map(nested),
        )])));
    }

    #[test]
    fn mixed_events_keep_existing_routes_and_identify_only_invalid_generic_record() {
        let valid = event(1, Some(encoded(&payload(ProvenanceKind::OnEntry))));
        let mut canonical = event(2, None);
        canonical.event_type = "wos.kernel.state_transition".into();
        let mut unrelated = event(3, Some(vec![0xff]));
        unrelated.event_type = "other.event".into();
        let invalid = event(
            4,
            Some(encoded(
                &json!({"record": {"recordKind": "futureUnknownKind"}}),
            )),
        );
        let findings = WosRecordValidator.validate_events(&[valid, canonical, unrelated, invalid]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].event_hash, Some([4; 32]));
        assert_eq!(findings[0].kind, "native_provenance_invalid");
        assert!(!findings[0].message.contains("futureUnknownKind"));
    }
}
