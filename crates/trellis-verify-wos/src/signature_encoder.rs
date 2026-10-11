// Rust guideline compliant 2026-02-21
//! Derives signature catalogs from actual repository event prefixes.

use crate::catalog::signature_entry_matches_record;
use crate::event_types::wos_signature_affirmation_event_type;
use crate::records::{parse_signature_affirmation_record, parse_signature_manifest_entries};
use ciborium::Value;
use std::collections::BTreeSet;
use std::fmt;
use trellis_cddl::canonical_event_hash_preimage;
use trellis_types::{
    CONTENT_DOMAIN, EVENT_DOMAIN, StoredEvent, decode_cbor_value, domain_separated_sha256,
    encode_canonical_cbor_value, map_lookup_bytes, map_lookup_map, map_lookup_text, map_lookup_u64,
};

/// Reports invalid event identity, unreadable records, or finite limit failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCatalogError {
    /// Input or output exceeds the selected finite count or byte limits.
    Limit,
    /// Stored identity disagrees with the canonical same-scope contiguous prefix.
    EventIdentity,
    /// An affirmation cannot be read or represented by the maintained schema.
    Record,
    /// Canonical encoding or independent parser/matcher validation failed.
    Encoding,
}
impl fmt::Display for SignatureCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "signature catalog limit exceeded",
            Self::EventIdentity => "signature prefix identity refused",
            Self::Record => "signature affirmation record refused",
            Self::Encoding => "signature catalog encoding refused",
        })
    }
}
impl std::error::Error for SignatureCatalogError {}

/// Encodes062 from a contiguous actual event prefix, retaining all earlier rows.
///
/// No caller-selected rows or hashes are accepted. Recomputes event hashes and
/// copies actual readable affirmation fields, including nested values and
/// optional null presence. This validates associations, not signatures, Source
/// custody, original signed text or completeness of a case export. Bounds cover
/// encoded input/output bytes, not the codec's total heap allocation.
///
/// # Errors
/// Refuses empty/foreign/noncontiguous prefixes, missing or conflicting hashes,
/// unreadable affirmation payloads, malformed records and count/byte limits.
pub fn encode_signature_affirmations_v1(
    events: &[&StoredEvent],
    max_events: usize,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SignatureCatalogError> {
    use SignatureCatalogError as E;
    if events.is_empty() || events.len() > max_events || max_bytes == 0 {
        return Err(E::Limit);
    }
    let scope = events[0].scope();
    if scope.is_empty() {
        return Err(E::EventIdentity);
    }
    let mut total = 0usize;
    for event in events {
        total = total
            .checked_add(event.canonical_event().len())
            .ok_or(E::Limit)?;
        if total > max_bytes {
            return Err(E::Limit);
        }
    }
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event.scope() != scope || event.sequence() != index as u64 {
            return Err(E::EventIdentity);
        }
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &canonical_event_hash_preimage(scope, event.canonical_event()),
        );
        if event.canonical_event_hash() != Some(&hash) || !seen.insert(hash) {
            return Err(E::EventIdentity);
        }
        let canonical = decode_cbor_value(event.canonical_event()).map_err(|_| E::EventIdentity)?;
        let map = canonical.as_map().ok_or(E::EventIdentity)?;
        if map_lookup_bytes(map, "ledger_scope").map_err(|_| E::EventIdentity)? != scope
            || map_lookup_u64(map, "sequence").map_err(|_| E::EventIdentity)? != event.sequence()
        {
            return Err(E::EventIdentity);
        }
        let header = map_lookup_map(map, "header").map_err(|_| E::EventIdentity)?;
        let literal = map_lookup_bytes(header, "event_type").map_err(|_| E::EventIdentity)?;
        if literal != wos_signature_affirmation_event_type().as_bytes() {
            continue;
        }
        let reference = map_lookup_map(map, "payload_ref").map_err(|_| E::Record)?;
        if map_lookup_text(reference, "ref_type").map_err(|_| E::Record)? != "inline" {
            return Err(E::Record);
        }
        let payload = map_lookup_bytes(reference, "ciphertext").map_err(|_| E::Record)?;
        let content = domain_separated_sha256(CONTENT_DOMAIN, &payload);
        if map_lookup_bytes(map, "content_hash").map_err(|_| E::Record)? != content {
            return Err(E::Record);
        }
        let record =
            parse_signature_affirmation_record(&payload, wos_signature_affirmation_event_type())
                .map_err(|_| E::Record)?;
        // The maintained catalog requires a genuine signing-act ID; never synthesize one.
        if record.signing_act_id.is_none() {
            return Err(E::Record);
        }
        let value = decode_cbor_value(&payload).map_err(|_| E::Record)?;
        let data =
            map_lookup_map(value.as_map().ok_or(E::Record)?, "data").map_err(|_| E::Record)?;
        let mut row = vec![(
            Value::Text("canonical_event_hash".into()),
            Value::Bytes(hash.to_vec()),
        )];
        for (source, target) in FIELDS {
            if let Some((_, value)) = data
                .iter()
                .find(|(key, _)| key == &Value::Text((*source).into()))
            {
                row.push((Value::Text((*target).into()), value.clone()));
            }
        }
        // The maintained parser accepts this historical field alias. Emit one canonical name.
        row.push((
            Value::Text("formspec_response_ref".into()),
            Value::Text(record.formspec_response_ref.clone()),
        ));
        let encoded = encode_canonical_cbor_value(&Value::Array(vec![Value::Map(row.clone())]))
            .map_err(|_| E::Encoding)?;
        let parsed = parse_signature_manifest_entries(&encoded).map_err(|_| E::Encoding)?;
        if parsed.len() != 1 || !signature_entry_matches_record(&parsed[0], &record) {
            return Err(E::Encoding);
        }
        rows.push(Value::Map(row));
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let bytes = encode_canonical_cbor_value(&Value::Array(rows)).map_err(|_| E::Encoding)?;
    if bytes.len() > max_bytes {
        return Err(E::Limit);
    }
    Ok(Some(bytes))
}

const FIELDS: &[(&str, &str)] = &[
    ("signerId", "signer_id"),
    ("roleId", "role_id"),
    ("role", "role"),
    ("documentId", "document_id"),
    ("documentHash", "document_hash"),
    ("documentHashAlgorithm", "document_hash_algorithm"),
    ("signedAt", "signed_at"),
    ("identityBinding", "identity_binding"),
    ("consentReference", "consent_reference"),
    ("signatureProvider", "signature_provider"),
    ("ceremonyId", "ceremony_id"),
    ("sourceSignatureSystem", "source_signature_system"),
    ("sourceSignatureId", "source_signature_id"),
    ("signedPayloadDigest", "signed_payload_digest"),
    (
        "signedPayloadDigestAlgorithm",
        "signed_payload_digest_algorithm",
    ),
    ("signingIntent", "signing_intent"),
    ("profileRef", "profile_ref"),
    ("profileKey", "profile_key"),
    ("signingActId", "signing_act_id"),
    ("presentationHash", "presentation_hash"),
    ("witnessedSignatureRef", "witnessed_signature_ref"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use integrity_cbor::json_to_dcbor_bytes;
    use serde_json::{Value as Json, json};

    fn payload(id: &str) -> Json {
        json!({"event":wos_signature_affirmation_event_type(),"data":{
            "signerId":"person","roleId":"selected-role","role":"selected",
            "documentId":"original-document","documentHash":"retained-document-digest",
            "documentHashAlgorithm":"selected-algorithm","signedAt":"2026-10-10T00:00:00Z",
            "identityBinding":{"nested":[{"exact":true},null,3]},
            "consentReference":{"text":"original consent","nested":[1,2]},
            "signatureProvider":"controlled-provider","ceremonyId":id,
            "formspecResponseRef":"urn:controlled:response","signingActId":id,
            "presentationHash":"retained-presentation-digest",
            "sourceSignatureId":null,"profileKey":"exact-profile"}})
    }
    // These structural events exercise association logic, not signature verification.
    fn event(scope: &[u8], sequence: u64, payload: Json, external: bool) -> StoredEvent {
        let bytes = json_to_dcbor_bytes(&payload, &[]).unwrap();
        let t = |s: &str| Value::Text(s.into());
        let canonical = encode_canonical_cbor_value(&Value::Map(vec![
            (t("ledger_scope"), Value::Bytes(scope.to_vec())),
            (t("sequence"), Value::Integer(sequence.into())),
            (
                t("header"),
                Value::Map(vec![(
                    t("event_type"),
                    Value::Bytes(payload["event"].as_str().unwrap().as_bytes().to_vec()),
                )]),
            ),
            (
                t("content_hash"),
                Value::Bytes(domain_separated_sha256(CONTENT_DOMAIN, &bytes).to_vec()),
            ),
            (
                t("payload_ref"),
                Value::Map(vec![
                    (
                        t("ref_type"),
                        t(if external { "external" } else { "inline" }),
                    ),
                    (t("ciphertext"), Value::Bytes(bytes)),
                ]),
            ),
        ]))
        .unwrap();
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &canonical_event_hash_preimage(scope, &canonical),
        );
        StoredEvent::new(scope.to_vec(), sequence, canonical, vec![])
            .with_canonical_event_hash(Some(hash))
    }
    fn encode(events: &[&StoredEvent]) -> Result<Option<Vec<u8>>, SignatureCatalogError> {
        encode_signature_affirmations_v1(events, 256, 1024 * 1024)
    }
    #[test]
    fn retains_multiple_affirmations_across_nonaffirmation_continuation() {
        let a = event(b"scope", 0, payload("first"), false);
        let b = event(b"scope", 1, payload("second"), false);
        let later = event(
            b"scope",
            2,
            json!({"event":"wos.kernel.note_added","data":{}}),
            false,
        );
        let before = encode(&[&a, &b]).unwrap().unwrap();
        assert_eq!(encode(&[&a, &b, &later]).unwrap().unwrap(), before);
        let rows = parse_signature_manifest_entries(&before).unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r.canonical_event_hash)
                .collect::<Vec<_>>(),
            vec![
                *a.canonical_event_hash().unwrap(),
                *b.canonical_event_hash().unwrap()
            ]
        );
        assert_eq!(rows[0].signing_act_id, "first");
        assert_eq!(rows[1].signing_act_id, "second");
    }
    #[test]
    fn preserves_nested_values_and_optional_absent_null_and_present_fields() {
        let original = payload("act");
        let a = event(b"scope", 0, original.clone(), false);
        let bytes = encode(&[&a]).unwrap().unwrap();
        let value = decode_cbor_value(&bytes).unwrap();
        let row = value.as_array().unwrap()[0].as_map().unwrap();
        let get = |key: &str| {
            row.iter()
                .find(|(k, _)| k == &Value::Text(key.into()))
                .map(|(_, v)| v)
        };
        assert_eq!(
            get("identity_binding"),
            Some(
                &decode_cbor_value(
                    &json_to_dcbor_bytes(&original["data"]["identityBinding"], &[]).unwrap()
                )
                .unwrap()
            )
        );
        assert_eq!(
            get("consent_reference"),
            Some(
                &decode_cbor_value(
                    &json_to_dcbor_bytes(&original["data"]["consentReference"], &[]).unwrap()
                )
                .unwrap()
            )
        );
        assert_eq!(get("source_signature_id"), Some(&Value::Null));
        assert_eq!(
            get("profile_key"),
            Some(&Value::Text("exact-profile".into()))
        );
        assert!(get("profile_ref").is_none());
        assert_eq!(encode(&[&a]).unwrap().unwrap(), bytes);
    }
    #[test]
    fn refuses_hash_foreign_scope_missing_hash_duplicate_and_sequence_gap() {
        let a = event(b"scope", 0, payload("act"), false);
        let bad = a.clone().with_canonical_event_hash(Some([1; 32]));
        assert_eq!(encode(&[&bad]), Err(SignatureCatalogError::EventIdentity));
        let missing = a.clone().with_canonical_event_hash(None);
        assert_eq!(
            encode(&[&missing]),
            Err(SignatureCatalogError::EventIdentity)
        );
        let foreign = event(b"foreign", 1, payload("other"), false);
        assert_eq!(
            encode(&[&a, &foreign]),
            Err(SignatureCatalogError::EventIdentity)
        );
        assert_eq!(encode(&[&a, &a]), Err(SignatureCatalogError::EventIdentity));
        let gap = event(b"scope", 2, payload("other"), false);
        assert_eq!(
            encode(&[&a, &gap]),
            Err(SignatureCatalogError::EventIdentity)
        );
    }
    #[test]
    fn refuses_missing_act_malformed_field_and_unreadable_affirmation() {
        let mut missing = payload("act");
        missing["data"]
            .as_object_mut()
            .unwrap()
            .remove("signingActId");
        assert_eq!(
            encode(&[&event(b"scope", 0, missing, false)]),
            Err(SignatureCatalogError::Record)
        );
        let mut malformed = payload("act");
        malformed["data"]["profileKey"] = json!(7);
        assert_eq!(
            encode(&[&event(b"scope", 0, malformed, false)]),
            Err(SignatureCatalogError::Record)
        );
        assert_eq!(
            encode(&[&event(b"scope", 0, payload("act"), true)]),
            Err(SignatureCatalogError::Record)
        );
    }
    #[test]
    fn refuses_content_digest_mismatch_even_with_actual_recomputed_event_hash() {
        let original = event(b"scope", 0, payload("act"), false);
        let mut decoded = decode_cbor_value(original.canonical_event()).unwrap();
        let Value::Map(map) = &mut decoded else {
            panic!("map fixture");
        };
        map.iter_mut()
            .find(|(key, _)| key == &Value::Text("content_hash".into()))
            .unwrap()
            .1 = Value::Bytes(vec![0; 32]);
        let canonical = encode_canonical_cbor_value(&decoded).unwrap();
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &canonical_event_hash_preimage(b"scope", &canonical),
        );
        let changed = StoredEvent::new(b"scope".to_vec(), 0, canonical, vec![])
            .with_canonical_event_hash(Some(hash));
        assert_eq!(encode(&[&changed]), Err(SignatureCatalogError::Record));
    }

    #[test]
    fn omits_absent_catalog_and_checks_input_count_and_output_bounds() {
        let ordinary = event(b"scope", 0, json!({"event":"wos.kernel.note_added"}), false);
        assert_eq!(encode(&[&ordinary]).unwrap(), None);
        let a = event(b"scope", 0, payload("act"), false);
        assert_eq!(
            encode_signature_affirmations_v1(&[&a], 0, 1024 * 1024),
            Err(SignatureCatalogError::Limit)
        );
        assert_eq!(
            encode_signature_affirmations_v1(&[&a], 1, a.canonical_event().len() - 1),
            Err(SignatureCatalogError::Limit)
        );
        assert_eq!(
            encode_signature_affirmations_v1(&[&a], 1, 0),
            Err(SignatureCatalogError::Limit)
        );
    }
}
