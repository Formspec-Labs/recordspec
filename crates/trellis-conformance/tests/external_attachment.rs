// Rust guideline compliant 2026-02-21
//! Byte-exact producer, native signed author and independent recipient tests.
use integrity_hpke::external_attachment::*;
use integrity_seam::SecureRandom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use trellis_core::external_attachment::*;
use trellis_store_memory::external_attachment::MemoryExternalAttachments;
use trellis_types::{
    CONTENT_DOMAIN, Value, decode_cbor_value, domain_separated_sha256, encode_canonical_cbor_value,
};
struct FixtureEntropy(AtomicU8);
impl SecureRandom for FixtureEntropy {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        out.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}
fn map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn sha_text(hash: &[u8; 32]) -> String {
    format!(
        "sha256:{}",
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn limits() -> ProtectionLimits {
    ProtectionLimits {
        original_bytes: 4096,
        recipients: 4,
        recipient_id_bytes: 64,
    }
}
fn request() -> (ExternalAttachmentAppend, Vec<u8>) {
    let original = b"native external attachment original\n".to_vec();
    let digest = integrity_cbor::sha256_bytes(&original);
    let key = b"native-external-047".to_vec();
    let context = AttachmentContext {
        idempotency_key: &key,
        original_sha256: digest,
        original_byte_length: original.len() as u64,
    };
    let private = x25519_dalek::StaticSecret::from([17; 32]);
    let public = x25519_dalek::PublicKey::from(&private);
    let output = protect_external_attachment(
        &FixtureEntropy(AtomicU8::new(71)),
        context,
        &original,
        &[Recipient {
            id: b"fixture-reader",
            public_key: public.to_bytes(),
        }],
        limits(),
    )
    .unwrap();
    let content = domain_separated_sha256(CONTENT_DOMAIN, &output.ciphertext);
    let binding = map(vec![
        ("attachment_id", Value::Text("logical-slot-047".into())),
        ("slot_path", Value::Text("/file".into())),
        ("media_type", Value::Text("application/octet-stream".into())),
        (
            "byte_length",
            Value::Integer((original.len() as u64).into()),
        ),
        ("attachment_sha256", Value::Text(sha_text(&digest))),
        ("payload_content_hash", Value::Text(sha_text(&content))),
        ("filename", Value::Null),
        ("prior_binding_hash", Value::Null),
    ]);
    let entries = output
        .key_bag
        .iter()
        .map(|w| {
            map(vec![
                ("recipient", Value::Bytes(w.recipient.clone())),
                ("suite", Value::Integer(w.suite.into())),
                (
                    "ephemeral_pubkey",
                    Value::Bytes(w.ephemeral_pubkey.to_vec()),
                ),
                ("wrapped_dek", Value::Bytes(w.wrapped_dek.clone())),
            ])
        })
        .collect();
    (
        ExternalAttachmentAppend {
            scope: b"native_external_047".to_vec(),
            idempotency_key: key,
            header: ExternalAttachmentHeader {
                event_type: "substrate.append.accepted_attachment_binding".into(),
                authored_at_seconds: 1791633600,
                authored_at_nanos: 0,
                classification: "x-trellis-service/private-attachment".into(),
                retention_tier: 0,
            },
            extensions: map(vec![("trellis.evidence-attachment-binding.v1", binding)]),
            key_bag: map(vec![("entries", Value::Array(entries))]),
            ciphertext: output.ciphertext,
            nonce: output.nonce,
            original_sha256: digest,
            original_byte_length: original.len() as u64,
            preparation_identity: [9; 32],
            expected_head: None,
            limits: ExternalAppendLimits {
                ciphertext_bytes: 8192,
                events: 8,
                metadata_bytes: 8192,
            },
        },
        original,
    )
}
fn signing_key() -> trellis_core::SigningKeyMaterial {
    trellis_core::SigningKeyMaterial::new(
        include_bytes!("../../../fixtures/vectors/_keys/issuer-001.cose_key").to_vec(),
    )
}
fn authenticated_open(
    retained: &RetainedExternalAttachment,
    private: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let public = trellis_cddl::parse_ed25519_cose_key(signing_key().as_bytes())
        .unwrap()
        .public_key;
    let report =
        integrity_verify::trellis::verify_single_event(public, retained.event().signed_event())
            .map_err(|e| e.to_string())?;
    if !report.integrity_verified || !report.structure_verified {
        return Err(format!(
            "event not authenticated: {:?}",
            report.event_failures
        ));
    }
    open_native_external_attachment(
        public,
        retained.event().signed_event(),
        body,
        b"fixture-reader",
        private,
        limits(),
        8192,
    )
    .map_err(|e| e.to_string())
}
#[test]
fn producer_signed_event_and_independent_recipient_match_exact_fixture() {
    let (request, original) = request();
    let mut store = MemoryExternalAttachments::default();
    let retained = append_external_attachment(&mut store, &signing_key(), request).unwrap();
    assert_eq!(
        authenticated_open(&retained, &[17; 32], retained.ciphertext()).unwrap(),
        original
    );
    assert!(authenticated_open(&retained, &[18; 32], retained.ciphertext()).is_err());
    let mut changed = retained.ciphertext().to_vec();
    changed[0] ^= 1;
    assert!(authenticated_open(&retained, &[17; 32], &changed).is_err());
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/append/047-native-external-attachment");
    let canonical = retained.event().canonical_event();
    let Value::Map(fields) = decode_cbor_value(canonical).unwrap() else {
        panic!("canonical map")
    };
    let author_hash = fields
        .iter()
        .find(|(k, _)| k.as_text() == Some("author_event_hash"))
        .unwrap()
        .1
        .as_bytes()
        .unwrap()
        .clone();
    let append_head = trellis_cddl::append_head_bytes(
        retained.event().scope(),
        retained.event().sequence(),
        *retained.event().canonical_event_hash().unwrap(),
    );
    let authored = encode_canonical_cbor_value(&Value::Map(
        fields
            .into_iter()
            .filter(|(k, _)| k.as_text() != Some("author_event_hash"))
            .collect(),
    ))
    .unwrap();
    let cose = integrity_cose::decode_cose_sign1(retained.event().signed_event()).unwrap();
    let signature_structure =
        integrity_cose::sig_structure_bytes(cose.protected_header(), canonical);
    let bytes = [
        ("sig-structure.bin", signature_structure),
        ("author-event-hash.bin", author_hash),
        ("expected-append-head.cbor", append_head),
        ("input-original.bin", original),
        ("input-author-event-hash-preimage.cbor", authored),
        ("expected-event-payload.cbor", canonical.to_vec()),
        (
            "expected-event.cbor",
            retained.event().signed_event().to_vec(),
        ),
        (
            "input-attachment-ciphertext.bin",
            retained.ciphertext().to_vec(),
        ),
        ("nonce.bin", retained.nonce().to_vec()),
    ];
    if std::env::var_os("TRELLIS_WRITE_EXTERNAL_ATTACHMENT_FIXTURE").is_some() {
        std::fs::create_dir_all(&fixture).unwrap();
        for (name, body) in bytes {
            std::fs::write(fixture.join(name), body).unwrap();
        }
    } else {
        for (name, body) in bytes {
            assert_eq!(std::fs::read(fixture.join(name)).unwrap(), body, "{name}");
        }
    }
}
#[test]
fn retained_output_replay_and_changed_metadata_refusal() {
    let (request, _) = request();
    let mut store = MemoryExternalAttachments::default();
    let first = append_external_attachment(&mut store, &signing_key(), request.clone()).unwrap();
    let mut retry = request.clone();
    retry.header.authored_at_seconds += 1;
    assert_eq!(
        append_external_attachment(&mut store, &signing_key(), retry).unwrap(),
        first
    );
    for change in 0..5 {
        let mut next = request.clone();
        match change {
            0 => next.nonce[0] ^= 1,
            1 => next.preparation_identity[0] ^= 1,
            2 => next.ciphertext[0] ^= 1,
            3 => {
                if let Value::Map(bag) = &mut next.key_bag {
                    if let Value::Array(entries) = &mut bag[0].1 {
                        if let Value::Map(row) = &mut entries[0] {
                            for (k, v) in row {
                                if k.as_text() == Some("wrapped_dek") {
                                    if let Value::Bytes(b) = v {
                                        b[0] ^= 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => next.header.classification = "x-changed".into(),
        }
        assert!(append_external_attachment(&mut store, &signing_key(), next).is_err());
    }
    assert_eq!(store.attachments().len(), 1);
}
#[test]
fn malformed_header_and_absent_protection_refuse_before_retention() {
    let (request, _) = request();
    let mut store = MemoryExternalAttachments::default();
    for change in 0..3 {
        let mut next = request.clone();
        match change {
            0 => next.header.event_type.clear(),
            1 => next.header.authored_at_nanos = 1_000_000_000,
            _ => next.key_bag = map(vec![("entries", Value::Array(vec![]))]),
        };
        assert!(append_external_attachment(&mut store, &signing_key(), next).is_err());
    }
    assert!(store.attachments().is_empty());
}

#[test]
fn modified_wrapped_key_refuses_original_open() {
    let (request, _) = request();
    let mut store = MemoryExternalAttachments::default();
    let retained = append_external_attachment(&mut store, &signing_key(), request).unwrap();
    let parsed =
        trellis_cddl::parse_external_attachment_profile(retained.event().canonical_event())
            .unwrap()
            .unwrap();
    let w = &parsed.key_bag_entries[0];
    let mut wrapped = WrappedPayloadKey {
        recipient: w.recipient.clone(),
        suite: 1,
        ephemeral_pubkey: w.ephemeral_pubkey,
        wrapped_dek: w.wrapped_dek.to_vec(),
    };
    wrapped.wrapped_dek[0] ^= 1;
    assert!(
        open_external_attachment(
            AttachmentContext {
                idempotency_key: &parsed.idempotency_key,
                original_sha256: parsed.original_sha256,
                original_byte_length: parsed.original_byte_length
            },
            retained.ciphertext(),
            &wrapped,
            &[17; 32],
            limits()
        )
        .is_err()
    );
}

#[test]
fn failed_atomic_commit_retains_neither_event_nor_body() {
    struct Refuse {
        inner: MemoryExternalAttachments,
    }
    impl ExternalAttachmentStore for Refuse {
        type Error = std::io::Error;
        fn scope_events(&self, _: &[u8]) -> Result<Vec<trellis_types::StoredEvent>, Self::Error> {
            Ok(vec![])
        }
        fn retained(
            &self,
            _: &[u8],
            _: &[u8],
        ) -> Result<Option<RetainedExternalAttachment>, Self::Error> {
            Ok(None)
        }
        fn commit(&mut self, _: RetainedExternalAttachment) -> Result<(), Self::Error> {
            Err(std::io::Error::other("controlled commit refusal"))
        }
    }
    let mut store = Refuse {
        inner: MemoryExternalAttachments::default(),
    };
    assert!(append_external_attachment(&mut store, &signing_key(), request().0).is_err());
    assert!(store.inner.attachments().is_empty());
}

#[test]
fn stale_preparation_and_ordinary_predecessor_ephemeral_reuse_refuse() {
    use trellis_types::{EVENT_DOMAIN, StoredEvent};
    struct Prior {
        event: StoredEvent,
    }
    impl ExternalAttachmentStore for Prior {
        type Error = std::io::Error;
        fn scope_events(&self, _: &[u8]) -> Result<Vec<StoredEvent>, Self::Error> {
            Ok(vec![self.event.clone()])
        }
        fn retained(
            &self,
            _: &[u8],
            _: &[u8],
        ) -> Result<Option<RetainedExternalAttachment>, Self::Error> {
            Ok(None)
        }
        fn commit(&mut self, _: RetainedExternalAttachment) -> Result<(), Self::Error> {
            panic!("refused before commit")
        }
    }
    let canonical = include_bytes!(
        "../../../fixtures/vectors/append/004-hpke-wrapped-inline/expected-event-payload.cbor"
    )
    .to_vec();
    let parsed = trellis_cddl::parse_canonical_event(&canonical).unwrap();
    let hash = domain_separated_sha256(
        EVENT_DOMAIN,
        &trellis_cddl::canonical_event_hash_preimage(&parsed.ledger_scope, &canonical),
    );
    let event = StoredEvent::with_idempotency_key(
        parsed.ledger_scope.clone(),
        0,
        canonical.clone(),
        vec![],
        parsed.idempotency_key,
    )
    .with_canonical_event_hash(Some(hash));
    let Value::Map(fields) = decode_cbor_value(&canonical).unwrap() else {
        panic!("map")
    };
    let bag = trellis_types::map_lookup_map(&fields, "key_bag").unwrap();
    let Value::Array(rows) = trellis_types::map_lookup_value(bag, "entries").unwrap() else {
        panic!("wraps")
    };
    let old =
        trellis_types::map_lookup_bytes(rows[0].as_map().unwrap(), "ephemeral_pubkey").unwrap();
    let mut next = request().0;
    next.scope = parsed.ledger_scope;
    next.expected_head = Some(hash);
    if let Value::Map(bag) = &mut next.key_bag {
        if let Value::Array(rows) = &mut bag[0].1 {
            if let Value::Map(row) = &mut rows[0] {
                for (k, v) in row {
                    if k.as_text() == Some("ephemeral_pubkey") {
                        *v = Value::Bytes(old.clone());
                    }
                }
            }
        }
    }
    let mut store = Prior { event };
    assert!(
        append_external_attachment(&mut store, &signing_key(), next.clone())
            .unwrap_err()
            .to_string()
            .contains("ephemeral key reused")
    );
    next.expected_head = None;
    assert!(
        append_external_attachment(&mut store, &signing_key(), next)
            .unwrap_err()
            .to_string()
            .contains("preparation head changed")
    );
}

#[test]
fn tampered_signature_and_wrong_signing_key_refuse_before_open() {
    let (input, _) = request();
    let retained = append_external_attachment(
        &mut MemoryExternalAttachments::default(),
        &signing_key(),
        input,
    )
    .unwrap();
    let public = trellis_cddl::parse_ed25519_cose_key(signing_key().as_bytes())
        .unwrap()
        .public_key;
    let mut signed = retained.event().signed_event().to_vec();
    let last = signed.len() - 1;
    signed[last] ^= 1;
    assert!(
        open_native_external_attachment(
            public,
            &signed,
            retained.ciphertext(),
            b"fixture-reader",
            &[17; 32],
            limits(),
            8192
        )
        .is_err()
    );
    assert!(
        open_native_external_attachment(
            [8; 32],
            retained.event().signed_event(),
            retained.ciphertext(),
            b"fixture-reader",
            &[17; 32],
            limits(),
            8192
        )
        .is_err()
    );
}

#[test]
fn regenerating_fresh_protection_for_same_operation_conflicts() {
    let (input, original) = request();
    let mut store = MemoryExternalAttachments::default();
    let first = append_external_attachment(&mut store, &signing_key(), input.clone()).unwrap();
    let private = x25519_dalek::StaticSecret::from([17; 32]);
    let public = x25519_dalek::PublicKey::from(&private);
    let output = protect_external_attachment(
        &FixtureEntropy(AtomicU8::new(81)),
        AttachmentContext {
            idempotency_key: &input.idempotency_key,
            original_sha256: input.original_sha256,
            original_byte_length: input.original_byte_length,
        },
        &original,
        &[Recipient {
            id: b"fixture-reader",
            public_key: public.to_bytes(),
        }],
        limits(),
    )
    .unwrap();
    assert_eq!(output.nonce, input.nonce);
    assert_ne!(output.ciphertext, input.ciphertext);
    let mut next = input;
    next.ciphertext = output.ciphertext;
    next.key_bag = map(vec![(
        "entries",
        Value::Array(
            output
                .key_bag
                .iter()
                .map(|w| {
                    map(vec![
                        ("recipient", Value::Bytes(w.recipient.clone())),
                        ("suite", Value::Integer(1.into())),
                        (
                            "ephemeral_pubkey",
                            Value::Bytes(w.ephemeral_pubkey.to_vec()),
                        ),
                        ("wrapped_dek", Value::Bytes(w.wrapped_dek.clone())),
                    ])
                })
                .collect(),
        ),
    )]);
    let hash = domain_separated_sha256(CONTENT_DOMAIN, &next.ciphertext);
    if let Value::Map(extensions) = &mut next.extensions {
        if let Value::Map(binding) = &mut extensions[0].1 {
            for (k, v) in binding {
                if k.as_text() == Some("payload_content_hash") {
                    *v = Value::Text(sha_text(&hash));
                }
            }
        }
    }
    assert!(
        append_external_attachment(&mut store, &signing_key(), next)
            .unwrap_err()
            .to_string()
            .contains("idempotency conflict")
    );
    assert_eq!(store.attachments()[0], first);
}

#[test]
fn generic_verifier_refuses_signed_unknown_marker_and_missing_binding() {
    let original = include_bytes!(
        "../../../fixtures/vectors/append/047-native-external-attachment/input-author-event-hash-preimage.cbor"
    );
    let public = trellis_cddl::parse_ed25519_cose_key(signing_key().as_bytes())
        .unwrap()
        .public_key;
    for missing_binding in [false, true] {
        let Value::Map(mut fields) = decode_cbor_value(original).unwrap() else {
            panic!("authored map")
        };
        for (key, value) in &mut fields {
            if key.as_text() == Some("extensions") {
                let Value::Map(extensions) = value else {
                    panic!("extensions")
                };
                if missing_binding {
                    extensions.retain(|(k, _)| {
                        k.as_text() != Some("trellis.evidence-attachment-binding.v1")
                    });
                } else {
                    for (k, v) in extensions {
                        if k.as_text() == Some(trellis_cddl::PROFILE_EXTENSION) {
                            *v = Value::Text("unsupported-external-profile".into());
                        }
                    }
                }
            }
        }
        let authored = encode_canonical_cbor_value(&Value::Map(fields)).unwrap();
        let artifacts = trellis_core::append_event(
            &mut trellis_store_memory::MemoryStore::new(),
            &signing_key(),
            &trellis_core::AuthoredEvent::new(authored),
        )
        .unwrap();
        match integrity_verify::trellis::verify_single_event(public, &artifacts.signed_event) {
            Err(_) => {}
            Ok(report) => assert!(
                !report.structure_verified || !report.integrity_verified,
                "generic verifier accepted malformed profile, missing_binding={missing_binding}"
            ),
        }
    }
}
