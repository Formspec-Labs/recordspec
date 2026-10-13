//! Codec and native binding controls, without Source cryptographic qualification.

use super::*;

// Native handoff references and stored Response IDs are distinct owning identifiers.
const SOURCE_RESPONSE_ID: &str = "019a8cfe-9980-7000-8000-000000000001";
const NATIVE_RESPONSE_REF: &str = "urn:formspec:response:019a8cfe-9980-7000-8000-000000000001";

fn protected_catalog() -> Vec<u8> {
    let hash = format!("sha256:{}", "a".repeat(64));
    let protected = Value::Map(vec![
        (Value::Text("version".into()), Value::Integer(1.into())),
        (
            Value::Text("native_event_hash".into()),
            Value::Bytes(vec![1; 32]),
        ),
        (
            Value::Text("response_hash".into()),
            Value::Text(hash.clone()),
        ),
        (
            Value::Text("response_id".into()),
            Value::Text(SOURCE_RESPONSE_ID.into()),
        ),
        (
            Value::Text("response_ref".into()),
            Value::Text(NATIVE_RESPONSE_REF.into()),
        ),
        (
            Value::Text("original_byte_length".into()),
            Value::Integer(20.into()),
        ),
        (
            Value::Text("content_hash".into()),
            Value::Bytes(vec![2; 32]),
        ),
        (Value::Text("context_key".into()), Value::Bytes(vec![3; 32])),
        (Value::Text("record_hash".into()), Value::Bytes(vec![4; 32])),
        (
            Value::Text("source_binding_hash".into()),
            Value::Bytes(vec![9; 32]),
        ),
        (
            Value::Text("publication_hash".into()),
            Value::Bytes(vec![5; 32]),
        ),
        (
            Value::Text("public_policy_hash".into()),
            Value::Bytes(vec![6; 32]),
        ),
        (
            Value::Text("recipient_policy_hash".into()),
            Value::Bytes(vec![7; 32]),
        ),
        (Value::Text("nonce".into()), Value::Bytes(vec![8; 12])),
        (
            Value::Text("key_bag".into()),
            Value::Map(vec![(Value::Text("entries".into()), Value::Array(vec![]))]),
        ),
    ]);
    let handoff = Value::Map(vec![
        (
            Value::Text("handoffId".into()),
            Value::Text("handoff-1".into()),
        ),
        (
            Value::Text("initiationMode".into()),
            Value::Text("publicIntake".into()),
        ),
        (
            Value::Text("definitionRef".into()),
            Value::Map(vec![
                (
                    Value::Text("url".into()),
                    Value::Text("urn:neutral:form".into()),
                ),
                (Value::Text("version".into()), Value::Text("1".into())),
            ]),
        ),
        (
            Value::Text("responseRef".into()),
            Value::Text(NATIVE_RESPONSE_REF.into()),
        ),
        (Value::Text("responseHash".into()), Value::Text(hash)),
        (
            Value::Text("validationReportRef".into()),
            Value::Text("report-1".into()),
        ),
        (
            Value::Text("ledgerHeadRef".into()),
            Value::Text("head-1".into()),
        ),
    ]);
    let value = Value::Array(vec![Value::Map(vec![
        (
            Value::Text("intake_event_hash".into()),
            Value::Bytes(vec![1; 32]),
        ),
        (Value::Text("handoff".into()), handoff),
        (Value::Text("protected_response".into()), protected),
    ])]);
    trellis_types::encode_canonical_cbor_value(&value).unwrap()
}

#[test]
fn protected_response_intake_catalog_accepts_closed_protected_locator() {
    assert!(crate::records::parse_intake_manifest_entries(&protected_catalog()).is_ok());
}

fn encoded(value: &Value) -> Vec<u8> {
    trellis_types::encode_canonical_cbor_value(value).unwrap()
}
fn catalog_value() -> Value {
    trellis_types::decode_cbor_value(&protected_catalog()).unwrap()
}
fn row(value: &mut Value) -> &mut Vec<(Value, Value)> {
    value.as_array_mut().unwrap()[0].as_map_mut().unwrap()
}
fn field<'a>(map: &'a mut Vec<(Value, Value)>, name: &str) -> &'a mut Value {
    &mut map
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

#[test]
fn protected_response_legacy_inline_and_signature_comparison_are_preserved() {
    let mut value = catalog_value();
    let entry = row(&mut value);
    entry.retain(|(key, _)| key.as_text() != Some("protected_response"));
    entry.push((
        Value::Text("response_bytes".into()),
        Value::Bytes(b"retained original".to_vec()),
    ));
    let parsed = crate::records::parse_intake_manifest_entries(&encoded(&value)).unwrap();
    assert!(
        matches!(&parsed[0].response_content,crate::records::IntakeResponseContent::Inline(bytes) if bytes==b"retained original")
    );
    super::given_wrong_presentation_hash_when_catalog_compared_then_entry_does_not_match();
}

#[test]
fn protected_response_rejects_oneof_unknown_version_field_and_duplicate() {
    let mut both = catalog_value();
    row(&mut both).push((Value::Text("response_bytes".into()), Value::Bytes(vec![])));
    assert!(crate::records::parse_intake_manifest_entries(&encoded(&both)).is_err());
    let mut neither = catalog_value();
    row(&mut neither).retain(|(key, _)| key.as_text() != Some("protected_response"));
    assert!(crate::records::parse_intake_manifest_entries(&encoded(&neither)).is_err());
    for variation in 0..3 {
        let mut value = catalog_value();
        let locator = field(row(&mut value), "protected_response")
            .as_map_mut()
            .unwrap();
        match variation {
            0 => *field(locator, "version") = Value::Integer(2.into()),
            1 => locator.push((Value::Text("unknown".into()), Value::Bool(true))),
            _ => locator.push((Value::Text("version".into()), Value::Integer(1.into()))),
        }
        // Preserve duplicate keys intentionally so the negative reaches our parser.
        // Production output continues to use the canonical encoder.
        let malformed = trellis_types::encode_cbor_value(&value).unwrap();
        assert!(crate::records::parse_intake_manifest_entries(&malformed).is_err());
    }
}

fn opened_fixture() -> (
    crate::records::ProtectedResponseLocator,
    crate::records::ResponseBindingPins,
    Vec<u8>,
    Vec<u8>,
) {
    let value = catalog_value();
    let parsed = crate::records::parse_intake_manifest_entries(&encoded(&value)).unwrap();
    let crate::records::IntakeResponseContent::Protected(mut locator) =
        parsed[0].response_content.clone()
    else {
        panic!("protected fixture")
    };
    let opened =
        serde_json::to_vec(&serde_json::json!({"id":SOURCE_RESPONSE_ID,"data":{"answer":"retained"},"authoredSignatures":[]})).unwrap();
    // This codec body is not HPKE ciphertext and establishes no cryptographic claim.
    let ciphertext = vec![10; opened.len() + 16];
    locator.original_byte_length = opened.len() as u64;
    locator.response_hash = format!(
        "sha256:{}",
        crate::records::hex_string(&trellis_types::sha256_bytes(&opened))
    );
    locator.content_hash =
        trellis_types::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &ciphertext);
    let record = encoded(&Value::Map(vec![
        (Value::Text("locator".into()), locator.to_value(false)),
        (Value::Text("ciphertext".into()), Value::Bytes(ciphertext)),
    ]));
    locator.record_hash = trellis_types::sha256_bytes(&record);
    let pins = crate::records::ResponseBindingPins {
        native_event_hash: [1; 32],
        response_ref: NATIVE_RESPONSE_REF.into(),
        response_id: SOURCE_RESPONSE_ID.into(),
        response_hash: locator.response_hash.clone(),
        context_key: vec![3; 32],
        record_hash: locator.record_hash,
        source_binding_hash: [9; 32],
        publication_hash: [5; 32],
        public_policy_hash: [6; 32],
        recipient_policy_hash: [7; 32],
    };
    (locator, pins, record, opened)
}

#[test]
fn protected_response_codec_joins_complete_record_body_and_independent_pins() {
    let (locator, pins, record, opened) = opened_fixture();
    let bound = crate::records::bind_opened_response(&locator, &pins, &record, &opened).unwrap();
    assert_eq!(bound.response["data"]["answer"], "retained");
    assert_eq!(bound.response["id"], SOURCE_RESPONSE_ID);
    assert_eq!(locator.response_ref, NATIVE_RESPONSE_REF);
    assert_ne!(locator.response_ref, locator.response_id);
    let mut foreign_id = pins.clone();
    foreign_id.response_id = "foreign-id".into();
    assert!(crate::records::bind_opened_response(&locator, &foreign_id, &record, &opened).is_err());
    let mut foreign_ref = pins.clone();
    foreign_ref.response_ref = "urn:formspec:response:foreign".into();
    assert!(
        crate::records::bind_opened_response(&locator, &foreign_ref, &record, &opened).is_err()
    );
    for variation in 0..6 {
        let mut changed = pins.clone();
        match variation {
            0 => changed.native_event_hash = [99; 32],
            1 => changed.context_key = vec![99; 32],
            2 => changed.source_binding_hash = [99; 32],
            3 => changed.publication_hash = [99; 32],
            4 => changed.public_policy_hash = [99; 32],
            _ => changed.recipient_policy_hash = [99; 32],
        }
        assert!(
            crate::records::bind_opened_response(&locator, &changed, &record, &opened).is_err()
        );
    }
    let mut changed = opened.clone();
    changed[0] = b'[';
    assert!(crate::records::bind_opened_response(&locator, &pins, &record, &changed).is_err());
    let mut changed = record.clone();
    changed.push(0);
    assert!(crate::records::bind_opened_response(&locator, &pins, &changed, &opened).is_err());
}

#[test]
fn protected_response_codec_rejects_ciphertext_metadata_and_identity_substitution() {
    let (mut locator, mut pins, record, opened) = opened_fixture();
    let mut value = trellis_types::decode_cbor_value(&record).unwrap();
    let map = value.as_map_mut().unwrap();
    *field(map, "ciphertext") = Value::Bytes(vec![11; opened.len() + 16]);
    let changed = encoded(&value);
    locator.record_hash = trellis_types::sha256_bytes(&changed);
    pins.record_hash = locator.record_hash;
    assert!(crate::records::bind_opened_response(&locator, &pins, &changed, &opened).is_err());
    let (mut locator, mut pins, record, opened) = opened_fixture();
    let mut value = trellis_types::decode_cbor_value(&record).unwrap();
    let map = value.as_map_mut().unwrap();
    let metadata = field(map, "locator").as_map_mut().unwrap();
    *field(metadata, "nonce") = Value::Bytes(vec![99; 12]);
    let changed = encoded(&value);
    locator.record_hash = trellis_types::sha256_bytes(&changed);
    pins.record_hash = locator.record_hash;
    assert!(crate::records::bind_opened_response(&locator, &pins, &changed, &opened).is_err());
    let (mut locator, mut pins, _, opened) = opened_fixture();
    locator.response_id = "foreign-response-id".into();
    pins.response_id = locator.response_id.clone();
    let cipher = vec![10; opened.len() + 16];
    let changed = encoded(&Value::Map(vec![
        (Value::Text("locator".into()), locator.to_value(false)),
        (Value::Text("ciphertext".into()), Value::Bytes(cipher)),
    ]));
    locator.record_hash = trellis_types::sha256_bytes(&changed);
    pins.record_hash = locator.record_hash;
    assert!(crate::records::bind_opened_response(&locator, &pins, &changed, &opened).is_err());
}

fn export_fixture(
    bytes: &[u8],
) -> (
    Vec<DomainEvent>,
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, Vec<u8>>,
) {
    let payload = Value::Map(vec![
        (
            Value::Text("event".into()),
            Value::Text(crate::event_types::wos_intake_accepted_event_type().to_owned()),
        ),
        (
            Value::Text("outputs".into()),
            Value::Array(vec![Value::Text("case-1".into())]),
        ),
        (
            Value::Text("data".into()),
            Value::Map(vec![
                (Value::Text("caseRef".into()), Value::Text("case-1".into())),
                (
                    Value::Text("intakeId".into()),
                    Value::Text("handoff-1".into()),
                ),
                (
                    Value::Text("caseIntent".into()),
                    Value::Text("attachToExistingCase".into()),
                ),
                (
                    Value::Text("caseDisposition".into()),
                    Value::Text("attachToExistingCase".into()),
                ),
            ]),
        ),
    ]);
    let events = vec![event(
        &crate::event_types::wos_intake_accepted_event_type(),
        1,
        Some(encoded(&payload)),
    )];
    let mut members = BTreeMap::new();
    members.insert("063-intake-handoffs.cbor".into(), bytes.to_vec());
    let digest = encoded(&Value::Map(vec![(
        Value::Text("intake_catalog_digest".into()),
        Value::Bytes(trellis_types::sha256_bytes(bytes).to_vec()),
    )]));
    let mut extensions = BTreeMap::new();
    extensions.insert(crate::event_types::INTAKE_EXPORT_EXTENSION.into(), digest);
    (events, members, extensions)
}
fn workflow_catalog() -> Value {
    let mut value = catalog_value();
    let handoff = field(row(&mut value), "handoff").as_map_mut().unwrap();
    *field(handoff, "initiationMode") = Value::Text("workflowInitiated".into());
    handoff.push((Value::Text("caseRef".into()), Value::Text("case-1".into())));
    value
}

#[test]
fn protected_response_native_anchor_is_checked_and_unavailable_cannot_succeed() {
    let bytes = encoded(&workflow_catalog());
    let (events, members, extensions) = export_fixture(&bytes);
    let export = DomainExport {
        events: &events,
        members: &members,
        manifest_extensions: &extensions,
    };
    let findings = crate::catalog::validate_catalogs(&export);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "protected_response_unavailable");
    let mut value = workflow_catalog();
    let locator = field(row(&mut value), "protected_response")
        .as_map_mut()
        .unwrap();
    *field(locator, "native_event_hash") = Value::Bytes(vec![99; 32]);
    let bytes = encoded(&value);
    let (events, members, extensions) = export_fixture(&bytes);
    let findings = crate::catalog::validate_catalogs(&DomainExport {
        events: &events,
        members: &members,
        manifest_extensions: &extensions,
    });
    assert!(
        findings
            .iter()
            .any(|f| f.kind == "protected_response_native_binding_mismatch")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind == "protected_response_unavailable")
    );
}

#[test]
fn protected_response_required_profile_rejects_legacy_missing_content() {
    let mut value = workflow_catalog();
    let row = row(&mut value);
    row.retain(|(key, _)| key.as_text() != Some("protected_response"));
    let response = b"retained original";
    row.push((
        Value::Text("response_bytes".into()),
        Value::Bytes(response.to_vec()),
    ));
    let handoff = field(row, "handoff").as_map_mut().unwrap();
    *field(handoff, "responseHash") = Value::Text(format!(
        "sha256:{}",
        crate::records::hex_string(&trellis_types::sha256_bytes(response))
    ));
    let bytes = encoded(&value);
    let (events, members, extensions) = export_fixture(&bytes);
    let export = DomainExport {
        events: &events,
        members: &members,
        manifest_extensions: &extensions,
    };
    assert!(crate::catalog::validate_catalogs(&export).is_empty());
    let required = std::collections::BTreeSet::from([[1; 32]]);
    let findings = crate::catalog::validate_required_response_catalogs(
        &export,
        &required,
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "required_protected_response_missing");
}

fn signature_catalog_value() -> Value {
    let strings = [
        ("signer_id", "signer-1"),
        ("role_id", "reviewer"),
        ("role", "reviewer"),
        ("document_id", "document-1"),
        ("document_hash", DOC_HASH),
        ("document_hash_algorithm", "sha-256"),
        ("signed_at", "2026-05-15T12:00:00Z"),
        ("signature_provider", "formspec"),
        ("ceremony_id", "ceremony-1"),
        ("formspec_response_ref", NATIVE_RESPONSE_REF),
        ("signing_act_id", "act-1"),
        ("presentation_hash", PRESENTATION_HASH),
    ];
    let mut rows = strings
        .into_iter()
        .map(|(key, value)| (Value::Text(key.into()), Value::Text(value.into())))
        .collect::<Vec<_>>();
    rows.push((
        Value::Text("canonical_event_hash".into()),
        Value::Bytes(vec![1; 32]),
    ));
    rows.push((Value::Text("identity_binding".into()), Value::Map(vec![])));
    rows.push((Value::Text("consent_reference".into()), Value::Map(vec![])));
    Value::Array(vec![Value::Map(rows)])
}

#[test]
fn protected_response_signature_catalog_preserves_legacy_and_rejects_null_locator() {
    let mut value = signature_catalog_value();
    assert!(
        crate::records::parse_signature_manifest_entries(&encoded(&value)).unwrap()[0]
            .protected_response
            .is_none()
    );
    let mut source = catalog_value();
    let locator = field(row(&mut source), "protected_response").clone();
    row(&mut value).push((Value::Text("protected_response".into()), locator));
    assert!(
        crate::records::parse_signature_manifest_entries(&encoded(&value)).unwrap()[0]
            .protected_response
            .is_some()
    );
    *field(row(&mut value), "protected_response") = Value::Null;
    assert!(crate::records::parse_signature_manifest_entries(&encoded(&value)).is_err());
}

fn protected_signature_catalog() -> Value {
    let mut value = signature_catalog_value();
    let mut source = catalog_value();
    let locator = field(row(&mut source), "protected_response").clone();
    row(&mut value).push((Value::Text("protected_response".into()), locator));
    value
}

#[test]
fn protected_response_outer_selectors_are_unique_with_legacy_unknown_tolerance() {
    for name in ["protected_response", "response_bytes"] {
        let mut value = catalog_value();
        let entry = row(&mut value);
        if name == "response_bytes" {
            entry.retain(|(key, _)| key.as_text() != Some("protected_response"));
            entry.push((Value::Text(name.into()), Value::Bytes(vec![])));
        }
        let duplicate = field(entry, name).clone();
        entry.push((Value::Text(name.into()), duplicate));
        let malformed = trellis_types::encode_cbor_value(&value).unwrap();
        assert!(crate::records::parse_intake_manifest_entries(&malformed).is_err());
    }
    let mut value = protected_signature_catalog();
    let entry = row(&mut value);
    let duplicate = field(entry, "protected_response").clone();
    entry.push((Value::Text("protected_response".into()), duplicate));
    assert!(
        crate::records::parse_signature_manifest_entries(
            &trellis_types::encode_cbor_value(&value).unwrap()
        )
        .is_err()
    );
    let mut value = catalog_value();
    row(&mut value).push((Value::Text("legacy_extension".into()), Value::Bool(true)));
    assert!(crate::records::parse_intake_manifest_entries(&encoded(&value)).is_ok());
    let mut value = signature_catalog_value();
    row(&mut value).push((Value::Text("legacy_extension".into()), Value::Bool(true)));
    assert!(crate::records::parse_signature_manifest_entries(&encoded(&value)).is_ok());
}

fn signature_export_fixture(
    bytes: &[u8],
) -> (
    Vec<DomainEvent>,
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, Vec<u8>>,
) {
    let value = signature_catalog_value();
    let fields = value.as_array().unwrap()[0].as_map().unwrap();
    let mut data = Vec::new();
    for (catalog, native) in [
        ("signer_id", "signerId"),
        ("role_id", "roleId"),
        ("role", "role"),
        ("document_id", "documentId"),
        ("document_hash", "documentHash"),
        ("document_hash_algorithm", "documentHashAlgorithm"),
        ("signed_at", "signedAt"),
        ("identity_binding", "identityBinding"),
        ("consent_reference", "consentReference"),
        ("signature_provider", "signatureProvider"),
        ("ceremony_id", "ceremonyId"),
        ("formspec_response_ref", "sourceResponseRef"),
        ("signing_act_id", "signingActId"),
        ("presentation_hash", "presentationHash"),
    ] {
        data.push((
            Value::Text(native.into()),
            trellis_types::map_lookup_optional_value(fields, catalog)
                .unwrap()
                .clone(),
        ));
    }
    let events = vec![event(
        &wos_signature_affirmation_event_type(),
        1,
        Some(encode_record(&wos_signature_affirmation_event_type(), data)),
    )];
    let mut members = BTreeMap::new();
    members.insert("062-signature-affirmations.cbor".into(), bytes.to_vec());
    let digest = encoded(&Value::Map(vec![(
        Value::Text("signature_catalog_digest".into()),
        Value::Bytes(trellis_types::sha256_bytes(bytes).to_vec()),
    )]));
    let mut extensions = BTreeMap::new();
    extensions.insert(
        crate::event_types::SIGNATURE_EXPORT_EXTENSION.into(),
        digest,
    );
    (events, members, extensions)
}

#[test]
fn protected_response_required_catalogs_need_manifest_binding_in_both_families() {
    let required = std::collections::BTreeSet::from([[1; 32]]);
    let empty = std::collections::BTreeSet::new();
    for signature in [false, true] {
        let bytes = if signature {
            encoded(&protected_signature_catalog())
        } else {
            encoded(&workflow_catalog())
        };
        let (events, members, extensions) = if signature {
            signature_export_fixture(&bytes)
        } else {
            export_fixture(&bytes)
        };
        let intact = crate::catalog::validate_required_response_catalogs(
            &DomainExport {
                events: &events,
                members: &members,
                manifest_extensions: &extensions,
            },
            if signature { &empty } else { &required },
            if signature { &required } else { &empty },
        );
        assert_eq!(intact.len(), 1);
        assert_eq!(intact[0].kind, "protected_response_unavailable");
        for corrupt in [false, true] {
            let mut changed = extensions.clone();
            let extension = if signature {
                crate::event_types::SIGNATURE_EXPORT_EXTENSION
            } else {
                crate::event_types::INTAKE_EXPORT_EXTENSION
            };
            if corrupt {
                let key = if signature {
                    "signature_catalog_digest"
                } else {
                    "intake_catalog_digest"
                };
                changed.insert(
                    extension.into(),
                    encoded(&Value::Map(vec![(
                        Value::Text(key.into()),
                        Value::Bytes(vec![99; 32]),
                    )])),
                );
            } else {
                changed.remove(extension);
            }
            let findings = crate::catalog::validate_required_response_catalogs(
                &DomainExport {
                    events: &events,
                    members: &members,
                    manifest_extensions: &changed,
                },
                if signature { &empty } else { &required },
                if signature { &required } else { &empty },
            );
            assert!(
                findings
                    .iter()
                    .any(|item| item.kind == "required_response_catalog_unbound")
            );
            assert!(
                findings
                    .iter()
                    .any(|item| item.kind == "protected_response_unavailable")
            );
            let mut foreign = events.clone();
            foreign[0].canonical_event_hash = [99; 32];
            let findings = crate::catalog::validate_required_response_catalogs(
                &DomainExport {
                    events: &foreign,
                    members: &members,
                    manifest_extensions: &changed,
                },
                if signature { &empty } else { &required },
                if signature { &required } else { &empty },
            );
            let unresolved = if signature {
                "signature_catalog_event_unresolved"
            } else {
                "intake_event_unresolved"
            };
            assert!(findings.iter().any(|item| item.kind == unresolved));
        }
    }
}
