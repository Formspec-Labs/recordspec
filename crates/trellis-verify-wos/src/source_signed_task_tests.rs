// Rust guideline compliant 2026-02-21
//! Controlled catalog/native/reader routing tests; no Source or HPKE proof claim.
use super::*;
use stack_common_typeid::testing::fixture_minter;
use std::collections::BTreeMap;
use wos_events::ProvenanceRecord;

struct Fixture {
    task: SourceSignedCompletedTaskV1,
    events: Vec<DomainEvent>,
    record: Vec<u8>,
    opened: Vec<u8>,
    pins: SourceTaskResponsePinsV1,
}
fn fixture(family: SourceTaskFamily) -> Fixture {
    let mut created = ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::TaskCreated);
    created.timestamp = "2026-10-13T00:00:00Z".into();
    created.audit_layer = Some("facts".into());
    created.definition_version = Some("1".into());
    created.data = Some(
        serde_json::json!({"taskId":"task","details":{"taskRef":"correction","assignedActor":"actor:human:owner"}}),
    );
    let mut completed = ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::TaskCompleted);
    completed.timestamp = "2026-10-13T00:01:00Z".into();
    completed.audit_layer = Some("facts".into());
    completed.definition_version = Some("1".into());
    completed.actor_id = Some("actor:human:owner".into());
    completed.data = Some(
        serde_json::json!({"taskId":"task","details":{"artifactId":"artifact","caseMutated":true}}),
    );
    let event = |record: &ProvenanceRecord, hash| {
        let wrapped = NativeProvenanceEvent::from_record(record).unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(wrapped.payload(), &mut bytes).unwrap();
        DomainEvent {
            event_type: WOS_NATIVE_PROVENANCE_EVENT_LITERAL.into(),
            payload: Some(bytes),
            canonical_event_hash: hash,
            authored_at: integrity_verify::trellis::TrellisTimestamp {
                seconds: 1,
                nanos: 0,
            },
        }
    };
    let events = vec![event(&created, [1; 32]), event(&completed, [2; 32])];
    // Protected plaintext is the Formspec response handoff encoding, as the producer writes it.
    let opened = integrity_canonical::canonical_response_handoff_bytes(
        serde_json::json!({"id":"response","data":{"affirmation":"retained literal"},"authoredSignatures":[]}).to_string().as_bytes(),
    )
    .unwrap();
    // Deliberately fake ciphertext: exercises the existing codec, never actual opening.
    let ciphertext = vec![7; opened.len() + 16];
    let mut locator = ProtectedResponseLocator {
        native_event_hash: [2; 32],
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
    let record = encode_canonical_cbor_value(&m(vec![
        ("locator", locator.to_value(false)),
        ("ciphertext", Value::Bytes(ciphertext)),
    ]))
    .unwrap();
    locator.record_hash = sha256_bytes(&record);
    let pins = SourceTaskResponsePinsV1 {
        response_ref: locator.response_ref.clone(),
        response_id: locator.response_id.clone(),
        response_hash: locator.response_hash.clone(),
        context_key: locator.context_key.clone(),
        record_hash: locator.record_hash,
        source_binding_hash: locator.source_binding_hash,
        publication_hash: locator.publication_hash,
        public_policy_hash: locator.public_policy_hash,
        recipient_policy_hash: locator.recipient_policy_hash,
    };
    let fields = SourceSignedCompletedTaskFieldsV1 {
        family,
        canonical_event_hash: [2; 32],
        task_created_event_hash: [1; 32],
        process_id: "process".into(),
        task_id: "task".into(),
        task_ref: "correction".into(),
        task_created_record_id: created.id,
        task_completed_record_id: completed.id,
        actor_ref: "actor:human:owner".into(),
        artifact_id: "artifact".into(),
        formspec_response_ref: locator.response_ref.clone(),
        response_id: locator.response_id.clone(),
        signature_id: "source-signature".into(),
        signed_payload_digest: format!("sha256:{}", hex::encode([9; 32])),
        signed_payload_digest_algorithm: "sha-256".into(),
        task_proof: SourceTaskProofDescriptorV1 {
            protected_package: None,
            witness_sha256: [10; 32],
            native_snapshot_hash: [11; 32],
            provider_selection_hash: [12; 32],
            family_selection_hash: [13; 32],
            original_selection_hash: if family == SourceTaskFamily::NativeLocalV3 {
                None
            } else {
                Some([14; 32])
            },
            committed_task_submit_key: "original-command".into(),
            native_outcome_digest: [15; 32],
            http_receipt_digest: [16; 32],
        },
    };
    let task = SourceSignedCompletedTaskV1::new(
        fields,
        &encode_canonical_cbor_value(&locator.to_value(true)).unwrap(),
    )
    .unwrap();
    Fixture {
        task,
        events,
        record,
        opened,
        pins,
    }
}
fn profile(task: &SourceSignedCompletedTaskV1) -> SourceTaskContentProfileV1 {
    SourceTaskContentProfileV1 {
        version: 1,
        case_ref: "case".into(),
        workflow_url: "urn:workflow".into(),
        workflow_version: "1".into(),
        workflow_hash: [17; 32],
        required_intakes: vec![],
        required_tasks: vec![SourceTaskRequirementV1 {
            task_completed_event_hash: task.fields.canonical_event_hash,
            task_created_event_hash: task.fields.task_created_event_hash,
            family: task.fields.family,
            descriptor_sha256: task.descriptor_sha256().unwrap(),
            provider_selection_hash: task.fields.task_proof.provider_selection_hash,
            native_policy_hash: [18; 32],
            obligation: NativeSigningObligation::SourceContentOnly,
        }],
    }
}
struct ControlledContent {
    native: SourceTaskNativeBindings,
    record: Vec<u8>,
    opened: Vec<u8>,
    pins: SourceTaskResponsePinsV1,
}
impl VerifiedSourceTaskContent for ControlledContent {
    fn native_binding(&self) -> &SourceTaskNativeBindings {
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
// This selected stub establishes routing only; it performs no Source crypto or decryption.
struct ControlledVerifier<'a> {
    f: &'a Fixture,
    variation: u8,
}
impl SourceTaskContentVerifier for ControlledVerifier<'_> {
    type Verified = ControlledContent;
    fn verify(
        &self,
        _: &SourceSignedCompletedTaskV1,
        native: &SourceTaskNativeBindings,
    ) -> Result<Self::Verified, String> {
        if self.variation == 1 {
            return Err("controlled missing owning proof".into());
        }
        let mut out = ControlledContent {
            native: native.clone(),
            record: self.f.record.clone(),
            opened: self.f.opened.clone(),
            pins: self.f.pins.clone(),
        };
        match self.variation {
            2 => out.native.archive_sha256 = [99; 32],
            3 => out.opened.push(0),
            4 => out.pins.public_policy_hash = [99; 32],
            5 => out.pins.response_id = "foreign".into(),
            _ => {}
        }
        Ok(out)
    }
}
fn findings(f: &Fixture, p: &SourceTaskContentProfileV1, variation: u8) -> Vec<DomainFinding> {
    let catalog =
        encode_source_signed_task_catalog(None, std::slice::from_ref(&f.task), &f.events).unwrap();
    let members = BTreeMap::from([
        ("062-signature-affirmations.cbor".into(), catalog.clone()),
        ("000-manifest.cbor".into(), vec![1]),
        ("040-checkpoints.cbor".into(), vec![2]),
    ]);
    let extensions = BTreeMap::from([(
        crate::event_types::SIGNATURE_EXPORT_EXTENSION.into(),
        encode_canonical_cbor_value(&m(vec![(
            "signature_catalog_digest",
            b(sha256_bytes(&catalog)),
        )]))
        .unwrap(),
    )]);
    verified_profile_findings(
        &DomainExport {
            events: &f.events,
            members: &members,
            manifest_extensions: &extensions,
        },
        [19; 32],
        p,
        &ControlledVerifier { f, variation },
    )
}
#[test]
fn source_task_all_family_codecs_roundtrip_without_formal_promotion() {
    for family in [
        SourceTaskFamily::NativeV1,
        SourceTaskFamily::MixedV2,
        SourceTaskFamily::NativeLocalV3,
    ] {
        let f = fixture(family);
        let bytes =
            encode_source_signed_task_catalog(None, std::slice::from_ref(&f.task), &f.events)
                .unwrap();
        let rows = source_signed_tasks_from_catalog(&bytes).unwrap();
        assert_eq!(rows[0].fields(), f.task.fields());
        assert!(
            !bytes
                .windows(b"retained literal".len())
                .any(|w| w == b"retained literal")
        );
        assert!(crate::records::parse_signature_manifest_entries(&bytes).is_err());
    }
}
#[test]
fn source_task_closed_rows_reject_unknown_duplicate_version_and_mixed_fields() {
    let f = fixture(SourceTaskFamily::MixedV2);
    for variation in 0..4 {
        let mut row = f.task.value();
        let map = row.as_map_mut().unwrap();
        match variation {
            0 => map.push((Value::Text("unknown".into()), Value::Null)),
            1 => map.push((Value::Text("kind".into()), Value::Text(KIND.into()))),
            2 => {
                map.iter_mut()
                    .find(|(k, _)| k.as_text() == Some("version"))
                    .unwrap()
                    .1 = Value::Integer(2.into())
            }
            _ => map.push((
                Value::Text("signing_act_id".into()),
                Value::Text("invented".into()),
            )),
        }
        assert!(SourceSignedCompletedTaskV1::from_value(&row).is_err());
    }
    let mut f = fixture(SourceTaskFamily::MixedV2);
    f.task.fields.task_proof.original_selection_hash = None;
    assert!(f.task.to_cbor().is_err());
    let mut f = fixture(SourceTaskFamily::NativeLocalV3);
    f.task.fields.task_proof.original_selection_hash = Some([1; 32]);
    assert!(f.task.to_cbor().is_err());
}
#[test]
fn source_task_native_join_refuses_foreign_actor_artifact_order_and_duplicate() {
    let f = fixture(SourceTaskFamily::MixedV2);
    assert!(native_join(&f.task, &f.events).is_ok());
    for variation in 0..5 {
        let mut task = f.task.clone();
        let mut events = f.events.clone();
        match variation {
            0 => task.fields.actor_ref = "foreign".into(),
            1 => task.fields.artifact_id = "foreign".into(),
            2 => events.reverse(),
            3 => events.push(events[1].clone()),
            _ => task.fields.task_created_record_id = "foreign".into(),
        }
        assert!(native_join(&task, &events).is_err());
    }
}
#[test]
fn source_task_reader_requires_exact_owning_result_and_protected_bytes() {
    let f = fixture(SourceTaskFamily::MixedV2);
    let p = profile(&f.task);
    assert!(findings(&f, &p, 0).is_empty());
    for variation in 1..=5 {
        assert!(!findings(&f, &p, variation).is_empty());
    }
}

#[test]
fn source_content_publication_keeps_full_task_verification_phase_unchanged() {
    let f = fixture(SourceTaskFamily::MixedV2);
    let p = profile(&f.task);
    let catalog =
        encode_source_signed_task_catalog(None, std::slice::from_ref(&f.task), &f.events).unwrap();
    let members = BTreeMap::from([
        ("062-signature-affirmations.cbor".into(), catalog.clone()),
        ("000-manifest.cbor".into(), vec![1]),
        ("040-checkpoints.cbor".into(), vec![2]),
    ]);
    let extensions = BTreeMap::from([(
        crate::event_types::SIGNATURE_EXPORT_EXTENSION.into(),
        encode_canonical_cbor_value(&m(vec![(
            "signature_catalog_digest",
            b(sha256_bytes(&catalog)),
        )]))
        .unwrap(),
    )]);
    let export = DomainExport {
        events: &f.events,
        members: &members,
        manifest_extensions: &extensions,
    };
    // The existing controlled adapter proves phase routing only, not Source crypto.
    assert!(crate::catalog::validate_source_content_publication_catalogs(&export).is_empty());
    assert!(
        crate::catalog::validate_catalogs_with_source_content(
            &export,
            [19; 32],
            &p,
            &ControlledVerifier {
                f: &f,
                variation: 0
            },
        )
        .is_empty()
    );
    assert!(
        !crate::catalog::validate_catalogs_with_source_content(
            &export,
            [19; 32],
            &p,
            &ControlledVerifier {
                f: &f,
                variation: 1
            },
        )
        .is_empty()
    );
    assert!(
        crate::catalog::validate_catalogs(&export)
            .iter()
            .any(|finding| finding.kind == "source_task_content_unavailable")
    );
}
#[test]
fn source_task_family_does_not_override_independent_formal_obligation() {
    for family in [
        SourceTaskFamily::NativeV1,
        SourceTaskFamily::MixedV2,
        SourceTaskFamily::NativeLocalV3,
    ] {
        let f = fixture(family);
        let mut p = profile(&f.task);
        p.required_tasks[0].obligation = NativeSigningObligation::SourceContentAndFormalKernel {
            affirmation_event_hashes: vec![[20; 32]],
        };
        let fs = findings(&f, &p, 0);
        assert!(
            fs.iter()
                .any(|f| f.kind == "source_task_formal_obligation_missing")
        );
    }
}
#[test]
fn source_task_profile_and_inventory_mismatch_never_becomes_content_ready() {
    let f = fixture(SourceTaskFamily::MixedV2);
    for variation in 0..5 {
        let mut p = profile(&f.task);
        match variation {
            0 => p.required_tasks[0].descriptor_sha256 = [99; 32],
            1 => p.required_tasks[0].provider_selection_hash = [99; 32],
            2 => p.required_tasks[0].family = SourceTaskFamily::NativeLocalV3,
            3 => p.required_tasks[0].task_completed_event_hash = [99; 32],
            _ => p.required_tasks.push(p.required_tasks[0].clone()),
        }
        assert!(!findings(&f, &p, 0).is_empty());
    }
}

#[test]
fn source_task_closed_opening_view_reuses_record_and_ciphertext_refusals() {
    let f = fixture(SourceTaskFamily::MixedV2);
    let view = f.task.protected_response_opening(&f.record).unwrap();
    assert_eq!(view.original_byte_length(), f.opened.len() as u64);
    assert_eq!(view.ciphertext().len(), f.opened.len() + 16);
    assert_eq!(view.response_hash(), f.pins.response_hash);
    assert_eq!(view.context_key(), f.pins.context_key);
    assert_eq!(view.record_hash(), f.pins.record_hash);
    assert_eq!(view.recipient_policy_hash(), f.pins.recipient_policy_hash);
    assert!(!view.key_bag_cbor().unwrap().is_empty());
    let mut changed = f.record.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(f.task.protected_response_opening(&changed).is_err());
    assert!(f.task.protected_response_opening(b"malformed").is_err());
}

#[test]
fn source_package_descriptor_and_original_context_join_bind_exact_task_and_publications() {
    let f = fixture(SourceTaskFamily::MixedV2);
    let ciphertext = vec![9; 48];
    let mut package = crate::ProtectedSourceProofPackageLocatorV1 {
        family: "mixed-v2".into(),
        task_completed_event_hash: [2; 32],
        package_sha256: [3; 32],
        witness_sha256: [10; 32],
        original_byte_length: 32,
        content_hash: trellis_types::domain_separated_sha256(
            trellis_types::CONTENT_DOMAIN,
            &ciphertext,
        ),
        context_key: vec![4; 32],
        record_hash: [0; 32],
        source_binding_hash: [4; 32],
        current_publication_hash: [5; 32],
        original_publication_hash: [5; 32],
        public_policy_hash: [6; 32],
        recipient_policy_hash: [7; 32],
        nonce: [8; 12],
        key_bag: m(vec![(
            "entries",
            Value::Array(vec![m(vec![
                ("recipient", Value::Bytes(b"neutral-reader".to_vec())),
                ("suite", Value::Integer(1.into())),
                ("ephemeral_pubkey", Value::Bytes(vec![1; 32])),
                ("wrapped_dek", Value::Bytes(vec![2; 48])),
            ])]),
        )]),
    };
    let record = encode_canonical_cbor_value(&m(vec![
        (
            "locator",
            trellis_types::decode_cbor_value(&package.to_record_locator_cbor().unwrap()).unwrap(),
        ),
        ("ciphertext", Value::Bytes(ciphertext)),
    ]))
    .unwrap();
    package.record_hash = sha256_bytes(&record);
    let mut fields = f.task.fields().clone();
    fields.task_proof.protected_package = Some(package.clone());
    let task =
        SourceSignedCompletedTaskV1::new(fields.clone(), &f.task.protected_locator_cbor().unwrap())
            .unwrap();
    assert_eq!(
        task.protected_package_opening(&record)
            .unwrap()
            .witness_sha256(),
        [10; 32]
    );
    let encoded = encode_canonical_cbor_value(&Value::Array(vec![
        trellis_types::decode_cbor_value(&task.to_cbor().unwrap()).unwrap(),
    ]))
    .unwrap();
    assert_eq!(
        source_signed_tasks_from_catalog(&encoded).unwrap()[0]
            .protected_package_locator_cbor()
            .unwrap(),
        package.to_cbor().unwrap()
    );
    for change in 0..5 {
        let mut changed = fields.clone();
        let package = changed.task_proof.protected_package.as_mut().unwrap();
        match change {
            0 => package.task_completed_event_hash = [99; 32],
            1 => package.witness_sha256 = [99; 32],
            2 => package.current_publication_hash = [99; 32],
            3 => package.recipient_policy_hash = [99; 32],
            _ => package.source_binding_hash = [99; 32],
        }
        assert!(
            SourceSignedCompletedTaskV1::new(changed, &f.task.protected_locator_cbor().unwrap())
                .is_err()
        );
    }
    let original_catalog = |join: crate::OriginalContextProofV1| {
        encode_canonical_cbor_value(&Value::Array(vec![m(vec![
            ("intake_event_hash", Value::Bytes(vec![20; 32])),
            (
                "handoff",
                m(vec![
                    ("handoffId", Value::Text("neutral-handoff".into())),
                    ("initiationMode", Value::Text("workflowInitiated".into())),
                    ("caseRef", Value::Text("case".into())),
                    (
                        "definitionRef",
                        m(vec![
                            ("url", Value::Text("urn:form".into())),
                            ("version", Value::Text("1".into())),
                        ]),
                    ),
                    (
                        "responseRef",
                        Value::Text(f.task.protected.response_ref.clone()),
                    ),
                    (
                        "responseHash",
                        Value::Text(f.task.protected.response_hash.clone()),
                    ),
                    ("validationReportRef", Value::Text("report".into())),
                    ("ledgerHeadRef", Value::Text("head".into())),
                ]),
            ),
            ("protected_response", {
                let mut locator = f.task.protected.clone();
                locator.native_event_hash = [20; 32];
                locator.to_value(true)
            }),
            (
                "original_context_proof",
                trellis_types::decode_cbor_value(&join.to_cbor().unwrap()).unwrap(),
            ),
        ])]))
        .unwrap()
    };
    let join = crate::OriginalContextProofV1 {
        task_completed_event_hash: [2; 32],
        package_record_hash: package.record_hash,
        context_instance: "retained-origin-context".into(),
    };
    let originals =
        crate::protected_intake_responses_from_catalog(&original_catalog(join.clone())).unwrap();
    let catalog_join_findings = |join: crate::OriginalContextProofV1, include_task: bool| {
        let original_bytes = original_catalog(join);
        let task_bytes = encoded.clone();
        let mut members =
            BTreeMap::from([("063-intake-handoffs.cbor".into(), original_bytes.clone())]);
        if include_task {
            members.insert("062-signature-affirmations.cbor".into(), task_bytes);
        }
        let extensions = BTreeMap::from([(
            crate::event_types::INTAKE_EXPORT_EXTENSION.into(),
            encode_canonical_cbor_value(&m(vec![(
                "intake_catalog_digest",
                Value::Bytes(sha256_bytes(&original_bytes).to_vec()),
            )]))
            .unwrap(),
        )]);
        crate::catalog::validate_source_content_publication_catalogs(&DomainExport {
            events: &[],
            members: &members,
            manifest_extensions: &extensions,
        })
    };
    assert!(
        !catalog_join_findings(join.clone(), true)
            .iter()
            .any(|finding| finding.kind == "source_original_context_join_invalid")
    );
    assert!(
        catalog_join_findings(join.clone(), false)
            .iter()
            .any(|finding| finding.kind == "source_original_context_join_invalid")
    );
    assert_eq!(
        originals[0]
            .validate_original_context_proof(std::slice::from_ref(&task))
            .unwrap(),
        &join
    );
    assert!(originals[0].validate_original_context_proof(&[]).is_err());
    assert!(
        originals[0]
            .validate_original_context_proof(&[task.clone(), task.clone()])
            .is_err()
    );
    let mut foreign = join;
    foreign.package_record_hash = [99; 32];
    assert!(
        catalog_join_findings(foreign.clone(), true)
            .iter()
            .any(|finding| finding.kind == "source_original_context_join_invalid")
    );
    let originals =
        crate::protected_intake_responses_from_catalog(&original_catalog(foreign)).unwrap();
    assert!(
        originals[0]
            .validate_original_context_proof(std::slice::from_ref(&task))
            .is_err()
    );
    for change in 0..2 {
        let mut changed = fields.clone();
        let package = changed.task_proof.protected_package.as_mut().unwrap();
        if change == 0 {
            package.original_publication_hash = [99; 32];
        } else {
            package.recipient_policy_hash = [99; 32];
        }
        let package_record_hash = package.record_hash;
        // A foreign original publication remains a valid task descriptor but must
        // fail the independently bound original join. A foreign reader policy
        // already fails the correction Response/task association.
        let changed =
            SourceSignedCompletedTaskV1::new(changed, &f.task.protected_locator_cbor().unwrap());
        if let Ok(changed) = changed {
            let originals = crate::protected_intake_responses_from_catalog(&original_catalog(
                crate::OriginalContextProofV1 {
                    task_completed_event_hash: [2; 32],
                    package_record_hash,
                    context_instance: "retained-origin-context".into(),
                },
            ))
            .unwrap();
            assert!(
                originals[0]
                    .validate_original_context_proof(&[changed])
                    .is_err()
            );
        } else {
            assert_eq!(change, 1);
        }
    }
}
