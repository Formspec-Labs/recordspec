// Rust guideline compliant 2026-02-21
//! Exercises the genuine accepted-operation descriptor at the admission boundary.

use trellis_admission_formspec::FormspecAppendAdmissionPolicy;
use trellis_admission_formspec::accepted_attachment::{
    ATTACHMENT_BINDING_EXTENSION, AcceptedAttachmentDescriptor, AttachmentLimits,
    admit_accepted_attachment_descriptor,
};
use trellis_server_ports::{AdmissionEvent, DirectSubmitPolicy, EventAdmissionPolicy};

fn descriptor() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "responseId": "response_original",
        "responseHash": format!("sha256:{}", "12".repeat(32)),
        "sourceId": "urn:formspec:source:neutral",
        "serviceBindingId": "binding_original",
        "acceptedActorRef": "actor:human:original",
        "formId": "form_original",
        "subjectRef": "subject_original",
        "fieldPath": "/photo",
        "uploadId": "upload_original",
        "acceptedAttachmentId": "attachment_occurrence",
        "bindingAttachmentId": "attachment_logical_slot",
        "filename": "photo.jpg",
        "mediaType": "image/jpeg",
        "byteLength": 4,
        "attachmentSha256": format!("sha256:{}", "34".repeat(32)),
        "objectUri": "urn:object:original",
        "priorBindingHash": null
    })
}

#[tokio::test]
async fn accepts_closed_accepted_attachment_operation() {
    let payload = serde_json::to_vec(&descriptor()).unwrap();
    let admitted = admit_accepted_attachment_descriptor(&payload)
        .expect("committed accepted attachment descriptor must have typed admission");
    assert_eq!(
        admitted.event_family.as_str(),
        "formspec.accepted_attachment"
    );
    assert_eq!(admitted.direct_submit, DirectSubmitPolicy::ServiceOnly);
}

#[tokio::test]
async fn ordinary_append_cannot_publish_attachment_with_null_extensions() {
    let payload = serde_json::to_vec(&descriptor()).unwrap();
    assert!(
        FormspecAppendAdmissionPolicy::new()
            .admit(&AdmissionEvent {
                scope: b"source_scope",
                event_type: "substrate.append.accepted_attachment_binding",
                payload: &payload,
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_unknown_accepted_descriptor_fields() {
    let mut descriptor = descriptor();
    descriptor["inventedUploader"] = "unknown".into();
    let payload = serde_json::to_vec(&descriptor).unwrap();
    assert!(admit_accepted_attachment_descriptor(&payload).is_err());
}

fn limits() -> AttachmentLimits {
    AttachmentLimits {
        original_bytes: 64,
        ciphertext_bytes: 64,
        prior_events: 8,
        prior_event_bytes: 8192,
    }
}

fn original_descriptor() -> AcceptedAttachmentDescriptor {
    let mut value = descriptor();
    value["attachmentSha256"] = stack_common_hash::sha256_prefixed(b"JPEG").into();
    AcceptedAttachmentDescriptor::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn prior_event(binding: integrity_cbor::Value) -> trellis_types::StoredEvent {
    use integrity_cbor::Value;
    let entries = vec![
        ("ledger_scope", Value::Bytes(b"source_scope".to_vec())),
        ("sequence", Value::Integer(0.into())),
        ("prev_hash", Value::Null),
        ("author_event_hash", Value::Bytes(vec![7; 32])),
        ("idempotency_key", Value::Bytes(b"prior".to_vec())),
        ("content_hash", Value::Bytes(vec![8; 32])),
        (
            "extensions",
            Value::Map(vec![(
                Value::Text(ATTACHMENT_BINDING_EXTENSION.into()),
                binding,
            )]),
        ),
    ];
    let canonical = integrity_cbor::encode_canonical_cbor_value(&Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    ))
    .unwrap();
    let hash = integrity_cbor::domain_separated_sha256(
        trellis_types::EVENT_DOMAIN,
        &trellis_cddl::canonical_event_hash_preimage(b"source_scope", &canonical),
    );
    trellis_types::StoredEvent::new(b"source_scope".to_vec(), 0, canonical, vec![])
        .with_canonical_event_hash(Some(hash))
}

fn actual_prior() -> trellis_types::StoredEvent {
    let binding = serde_json::json!({
        "attachment_id":"attachment_logical_slot", "slot_path":"/photo", "media_type":"image/jpeg",
        "byte_length":4, "attachment_sha256":stack_common_hash::sha256_prefixed(b"old!"),
        "payload_content_hash":format!("sha256:{}", "08".repeat(32)), "filename":null, "prior_binding_hash":null,
    });
    prior_event(integrity_cbor::json_to_cbor_value(&binding, &[]).unwrap())
}

fn hash_text(event: &trellis_types::StoredEvent) -> String {
    format!(
        "sha256:{}",
        event
            .canonical_event_hash()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn continuation(first: &trellis_types::StoredEvent, linked: bool) -> trellis_types::StoredEvent {
    use integrity_cbor::Value;
    let Value::Map(mut fields) =
        integrity_cbor::decode_cbor_value(first.canonical_event()).unwrap()
    else {
        panic!("event map")
    };
    for (key, value) in &mut fields {
        match key {
            Value::Text(name) if name == "sequence" => *value = Value::Integer(1.into()),
            Value::Text(name) if name == "prev_hash" => {
                *value = Value::Bytes(if linked {
                    first.canonical_event_hash().unwrap().to_vec()
                } else {
                    vec![0; 32]
                })
            }
            _ => {}
        }
    }
    let canonical = integrity_cbor::encode_canonical_cbor_value(&Value::Map(fields)).unwrap();
    let hash = integrity_cbor::domain_separated_sha256(
        trellis_types::EVENT_DOMAIN,
        &trellis_cddl::canonical_event_hash_preimage(b"source_scope", &canonical),
    );
    trellis_types::StoredEvent::new(b"source_scope".to_vec(), 1, canonical, vec![])
        .with_canonical_event_hash(Some(hash))
}

#[test]
fn selects_latest_binding_and_refuses_broken_link() {
    let first = actual_prior();
    let second = continuation(&first, true);
    let mut descriptor = original_descriptor();
    descriptor.prior_binding_hash = Some(hash_text(&first));
    assert!(
        descriptor
            .clone()
            .prepare(
                b"source_scope",
                b"JPEG",
                b"protected",
                &[first.clone(), second.clone()],
                limits()
            )
            .is_err()
    );
    descriptor.prior_binding_hash = Some(hash_text(&second));
    assert!(
        descriptor
            .clone()
            .prepare(
                b"source_scope",
                b"JPEG",
                b"protected",
                &[first.clone(), second],
                limits()
            )
            .is_ok()
    );
    let broken = continuation(&first, false);
    descriptor.prior_binding_hash = Some(hash_text(&broken));
    assert!(
        descriptor
            .prepare(
                b"source_scope",
                b"JPEG",
                b"protected",
                &[first, broken],
                limits()
            )
            .is_err()
    );
}

#[test]
fn maintained_attachment_fixture_uses_canonical_ordering() {
    let canonical = include_bytes!(
        "../../../fixtures/vectors/append/018-attachment-bound/expected-event-payload.cbor"
    );
    let value = integrity_cbor::decode_cbor_value(canonical).unwrap();
    assert_eq!(
        integrity_cbor::encode_canonical_cbor_value(&value).unwrap(),
        canonical
    );
    assert!(trellis_cddl::parse_canonical_event(canonical).is_ok());
}

#[test]
fn binds_original_and_ciphertext_with_distinct_hashes() {
    let prepared = original_descriptor()
        .prepare(b"source_scope", b"JPEG", b"protected", &[], limits())
        .unwrap();
    assert_eq!(prepared.ciphertext(), b"protected");
    assert_eq!(
        prepared.content_hash(),
        integrity_cbor::domain_separated_sha256(trellis_types::CONTENT_DOMAIN, b"protected")
    );
    let extension =
        integrity_cbor::decode_cbor_value(&prepared.extensions_cbor().unwrap()).unwrap();
    let binding =
        integrity_cbor::map_lookup_value(extension.as_map().unwrap(), ATTACHMENT_BINDING_EXTENSION)
            .unwrap();
    assert_eq!(
        integrity_cbor::map_lookup_text(binding.as_map().unwrap(), "attachment_id").unwrap(),
        "attachment_logical_slot"
    );
    assert_ne!(
        prepared.descriptor().accepted_attachment_id,
        prepared.descriptor().binding_attachment_id
    );
}

#[test]
fn rejects_changed_original_and_excessive_binary_inputs() {
    assert!(
        original_descriptor()
            .prepare(b"source_scope", b"FAKE", b"protected", &[], limits())
            .is_err()
    );
    let mut bound = limits();
    bound.ciphertext_bytes = 2;
    assert!(
        original_descriptor()
            .prepare(b"source_scope", b"JPEG", b"protected", &[], bound)
            .is_err()
    );
}

#[test]
fn descriptor_change_conflicts_even_when_original_bytes_match() {
    let first = original_descriptor()
        .prepare(b"source_scope", b"JPEG", b"protected", &[], limits())
        .unwrap();
    let mut changed = original_descriptor();
    changed.accepted_actor_ref = "actor:human:other".into();
    let next = changed
        .prepare(b"source_scope", b"JPEG", b"protected", &[], limits())
        .unwrap();
    assert_ne!(first.replay_digest(), next.replay_digest());
}

#[test]
fn actual_replacement_preserves_logical_slot_and_requires_prior_hash() {
    let prior = actual_prior();
    assert!(
        original_descriptor()
            .prepare(
                b"source_scope",
                b"JPEG",
                b"protected",
                std::slice::from_ref(&prior),
                limits()
            )
            .is_err()
    );
    let mut replacement = original_descriptor();
    replacement.accepted_attachment_id = "attachment_new_occurrence".into();
    replacement.prior_binding_hash = Some(format!(
        "sha256:{}",
        prior
            .canonical_event_hash()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let prepared = replacement
        .clone()
        .prepare(
            b"source_scope",
            b"JPEG",
            b"protected",
            std::slice::from_ref(&prior),
            limits(),
        )
        .unwrap();
    assert_eq!(
        prepared.descriptor().binding_attachment_id,
        "attachment_logical_slot"
    );
    replacement.field_path = "/other".into();
    assert!(
        replacement
            .prepare(b"source_scope", b"JPEG", b"protected", &[prior], limits())
            .is_err()
    );
}

#[test]
fn refuses_fabricated_prior_and_foreign_prefix() {
    let mut replacement = original_descriptor();
    replacement.prior_binding_hash = Some(format!("sha256:{}", "ff".repeat(32)));
    assert!(
        replacement
            .prepare(b"source_scope", b"JPEG", b"protected", &[], limits())
            .is_err()
    );
    assert!(
        original_descriptor()
            .prepare(
                b"other_scope",
                b"JPEG",
                b"protected",
                &[actual_prior()],
                limits()
            )
            .is_err()
    );
}

#[test]
fn refuses_malformed_same_slot_prior_binding() {
    let prior = prior_event(
        integrity_cbor::json_to_cbor_value(
            &serde_json::json!({
                "attachment_id":"attachment_logical_slot", "slot_path":"/photo"
            }),
            &[],
        )
        .unwrap(),
    );
    let mut replacement = original_descriptor();
    replacement.prior_binding_hash = Some(format!(
        "sha256:{}",
        prior
            .canonical_event_hash()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    assert!(
        replacement
            .prepare(b"source_scope", b"JPEG", b"protected", &[prior], limits())
            .is_err()
    );
}

#[test]
fn refuses_unsupported_version_missing_nullable_and_bad_media_type() {
    for field in ["filename", "priorBindingHash"] {
        let mut value = descriptor();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            AcceptedAttachmentDescriptor::decode(&serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
    let mut value = descriptor();
    value["version"] = 2.into();
    assert!(AcceptedAttachmentDescriptor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["version"] = 1.into();
    value["mediaType"] = "image/".into();
    assert!(AcceptedAttachmentDescriptor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}
