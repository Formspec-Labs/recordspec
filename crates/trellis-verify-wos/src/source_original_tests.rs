// Rust guideline compliant 2026-02-21
//! Controlled original-reader routing; no genuine Source signing or decryption claim.
use super::*;
use crate::records::ProtectedResponseLocator;
use std::collections::BTreeMap;
fn map(rows: Vec<(&str, Value)>) -> Value {
    Value::Map(
        rows.into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn encoded(v: &Value) -> Vec<u8> {
    encode_canonical_cbor_value(v).unwrap()
}
struct Fixture {
    catalog: Vec<u8>,
    events: Vec<integrity_verify::trellis::DomainEvent>,
    record: Vec<u8>,
    opened: Vec<u8>,
    pins: SourceTaskResponsePinsV1,
}
fn fixture() -> Fixture {
    // Protected plaintext is the Formspec response handoff encoding, as the producer writes it.
    let opened = integrity_canonical::canonical_response_handoff_bytes(
        serde_json::json!({"id":"response","data":{"original":"complete"},"authoredSignatures":[]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ciphertext = vec![3; opened.len() + 16];
    let mut p = ProtectedResponseLocator {
        native_event_hash: [1; 32],
        response_ref: "urn:formspec:response:response".into(),
        response_id: "response".into(),
        response_hash: format!("sha256:{}", hex::encode(sha256_bytes(&opened))),
        original_byte_length: opened.len() as u64,
        content_hash: trellis_types::domain_separated_sha256(
            trellis_types::CONTENT_DOMAIN,
            &ciphertext,
        ),
        context_key: vec![3; 32],
        record_hash: [0; 32],
        source_binding_hash: [4; 32],
        publication_hash: [5; 32],
        public_policy_hash: [6; 32],
        recipient_policy_hash: [7; 32],
        nonce: [8; 12],
        key_bag: Value::Map(vec![]),
    };
    let record = encoded(&map(vec![
        ("locator", p.to_value(false)),
        ("ciphertext", Value::Bytes(ciphertext)),
    ]));
    p.record_hash = sha256_bytes(&record);
    let catalog = encoded(&Value::Array(vec![map(vec![
        ("intake_event_hash", Value::Bytes(vec![1; 32])),
        (
            "handoff",
            map(vec![
                ("handoffId", Value::Text("handoff".into())),
                ("initiationMode", Value::Text("workflowInitiated".into())),
                ("caseRef", Value::Text("case".into())),
                (
                    "definitionRef",
                    map(vec![
                        ("url", Value::Text("urn:form".into())),
                        ("version", Value::Text("1".into())),
                    ]),
                ),
                ("responseRef", Value::Text(p.response_ref.clone())),
                ("responseHash", Value::Text(p.response_hash.clone())),
                ("validationReportRef", Value::Text("report".into())),
                ("ledgerHeadRef", Value::Text("head".into())),
            ]),
        ),
        ("protected_response", p.to_value(true)),
    ])]));
    let payload = encoded(&map(vec![
        (
            "event",
            Value::Text(crate::event_types::wos_intake_accepted_event_type().into()),
        ),
        ("outputs", Value::Array(vec![Value::Text("case".into())])),
        (
            "data",
            map(vec![
                ("caseRef", Value::Text("case".into())),
                ("intakeId", Value::Text("handoff".into())),
                ("caseIntent", Value::Text("attachToExistingCase".into())),
                (
                    "caseDisposition",
                    Value::Text("attachToExistingCase".into()),
                ),
            ]),
        ),
    ]));
    let events = vec![integrity_verify::trellis::DomainEvent {
        event_type: crate::event_types::wos_intake_accepted_event_type().into(),
        payload: Some(payload),
        canonical_event_hash: [1; 32],
        authored_at: integrity_verify::trellis::TrellisTimestamp {
            seconds: 1,
            nanos: 0,
        },
    }];
    let pins = SourceTaskResponsePinsV1 {
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
    Fixture {
        catalog,
        events,
        record,
        opened,
        pins,
    }
}
fn profile(f: &Fixture) -> SourceTaskContentProfileV1 {
    let row = protected_intake_responses_from_catalog(&f.catalog)
        .unwrap()
        .remove(0);
    SourceTaskContentProfileV1 {
        version: 1,
        case_ref: "case".into(),
        workflow_url: "urn:workflow".into(),
        workflow_version: "1".into(),
        workflow_hash: [2; 32],
        required_tasks: vec![],
        required_intakes: vec![SourceIntakeRequirementV1 {
            intake_event_hash: [1; 32],
            case_created_event_hash: None,
            descriptor_sha256: sha256_bytes(&row.descriptor_cbor().unwrap()),
            provider_selection_hash: [3; 32],
        }],
    }
}
struct Controlled {
    native: SourceIntakeNativeBindings,
    record: Vec<u8>,
    opened: Vec<u8>,
    pins: SourceTaskResponsePinsV1,
}
impl VerifiedSourceIntakeContent for Controlled {
    fn native_binding(&self) -> &SourceIntakeNativeBindings {
        &self.native
    }
    fn protected_record_bytes(&self) -> &[u8] {
        &self.record
    }
    fn canonical_response_bytes(&self) -> &[u8] {
        &self.opened
    }
    fn independently_admitted_pins(&self) -> SourceTaskResponsePinsV1 {
        self.pins.clone()
    }
}
struct RoutingOnly<'a> {
    f: &'a Fixture,
    variation: u8,
}
impl SourceIntakeContentVerifier for RoutingOnly<'_> {
    type Verified = Controlled;
    fn verify_original(
        &self,
        _: &ProtectedIntakeResponseV1,
        native: &SourceIntakeNativeBindings,
    ) -> Result<Controlled, String> {
        if self.variation == 1 {
            return Err("missing owning verifier".into());
        }
        assert_eq!(native.case_ref(), "case");
        let mut v = Controlled {
            native: native.clone(),
            record: self.f.record.clone(),
            opened: self.f.opened.clone(),
            pins: self.f.pins.clone(),
        };
        match self.variation {
            2 => v.native.archive_sha256 = [99; 32],
            3 => v.pins.public_policy_hash = [99; 32],
            4 => v.opened.push(0),
            _ => {}
        }
        Ok(v)
    }
}
fn check(
    f: &Fixture,
    p: &SourceTaskContentProfileV1,
    variation: u8,
    bound: bool,
) -> Vec<DomainFinding> {
    let members = BTreeMap::from([
        ("063-intake-handoffs.cbor".into(), f.catalog.clone()),
        ("000-manifest.cbor".into(), vec![1]),
        ("040-checkpoints.cbor".into(), vec![2]),
    ]);
    let extensions = if bound {
        BTreeMap::from([(
            crate::event_types::INTAKE_EXPORT_EXTENSION.into(),
            encoded(&map(vec![(
                "intake_catalog_digest",
                Value::Bytes(sha256_bytes(&f.catalog).to_vec()),
            )])),
        )])
    } else {
        BTreeMap::new()
    };
    verified_original_findings(
        &DomainExport {
            events: &f.events,
            members: &members,
            manifest_extensions: &extensions,
        },
        [8; 32],
        p,
        &RoutingOnly { f, variation },
    )
}
#[test]
fn source_original_reader_retains_unavailable_without_exact_owning_result() {
    let f = fixture();
    let p = profile(&f);
    assert!(check(&f, &p, 0, true).is_empty());
    for n in 1..=4 {
        assert!(!check(&f, &p, n, true).is_empty());
    }
    assert!(!check(&f, &p, 0, false).is_empty());
}
#[test]
fn source_original_exact_inventory_and_native_anchor_required() {
    let f = fixture();
    for n in 0..3 {
        let mut p = profile(&f);
        match n {
            0 => p.required_intakes[0].descriptor_sha256 = [99; 32],
            1 => p.required_intakes[0].intake_event_hash = [99; 32],
            _ => p.required_intakes.clear(),
        }
        assert!(!check(&f, &p, 0, true).is_empty());
    }
    let mut foreign = fixture();
    foreign.events[0].canonical_event_hash = [99; 32];
    assert!(!check(&foreign, &profile(&foreign), 0, true).is_empty());
}
#[test]
fn source_original_profile_case_must_match_actual_native_case() {
    let f = fixture();
    let mut p = profile(&f);
    assert!(check(&f, &p, 0, true).is_empty());
    p.case_ref = "foreign-case".into();
    assert!(
        check(&f, &p, 0, true)
            .iter()
            .any(|finding| finding.kind == "source_original_profile_mismatch")
    );
}
#[test]
fn source_original_public_catalog_never_carries_plain_complete_response() {
    let f = fixture();
    assert!(!f.catalog.windows(f.opened.len()).any(|w| w == f.opened));
    let rows = protected_intake_responses_from_catalog(&f.catalog).unwrap();
    assert_eq!(rows[0].handoff_id(), "handoff");
    assert_eq!(rows[0].response_id(), "response");
    assert_eq!(rows[0].initiation_mode(), "workflowInitiated");
    assert_eq!(rows[0].validation_report_ref(), "report");
    assert_eq!(rows[0].ledger_head_ref(), "head");
}

#[test]
fn source_original_closed_opening_view_keeps_original_namespace_and_identity() {
    let f = fixture();
    let rows = protected_intake_responses_from_catalog(&f.catalog).unwrap();
    let view = rows[0].protected_response_opening(&f.record).unwrap();
    assert_eq!(view.original_byte_length(), f.opened.len() as u64);
    assert_eq!(view.record_hash(), f.pins.record_hash);
    assert_eq!(
        view.content_hash(),
        trellis_types::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, view.ciphertext())
    );
    assert!(rows[0].protected_response_opening(b"other record").is_err());
}

#[test]
fn original_context_join_refuses_inline_and_duplicate_selectors() {
    let f = fixture();
    let join = crate::OriginalContextProofV1 {
        task_completed_event_hash: [2; 32],
        package_record_hash: [3; 32],
        context_instance: "neutral-context".into(),
    };
    let join = trellis_types::decode_cbor_value(&join.to_cbor().unwrap()).unwrap();
    let mut value = trellis_types::decode_cbor_value(&f.catalog).unwrap();
    let row = value.as_array_mut().unwrap()[0].as_map_mut().unwrap();
    row.retain(|(key, _)| key.as_text() != Some("protected_response"));
    row.push((
        Value::Text("response_bytes".into()),
        Value::Bytes(f.opened.clone()),
    ));
    row.push((Value::Text("original_context_proof".into()), join.clone()));
    assert!(protected_intake_responses_from_catalog(&encoded(&value)).is_err());
    let mut value = trellis_types::decode_cbor_value(&f.catalog).unwrap();
    let row = value.as_array_mut().unwrap()[0].as_map_mut().unwrap();
    row.push((Value::Text("original_context_proof".into()), join.clone()));
    row.push((Value::Text("original_context_proof".into()), join));
    // Serialize without canonicalizing duplicates so the owning parser sees them.
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes).unwrap();
    assert!(protected_intake_responses_from_catalog(&bytes).is_err());
}
