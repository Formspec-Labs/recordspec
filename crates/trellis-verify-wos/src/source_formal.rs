// Rust guideline compliant 2026-02-21
//! Matches selected formal obligations to already verified certificate events.
use integrity_cbor::{Value, decode_cbor_value, map_lookup_optional_value};
use integrity_verify::trellis::{
    CertificateAttestationAuthorityStatus, CertificateOfCompletionOutcome,
};

pub(crate) fn selected_certificate_covers(
    zip: &[u8],
    outcomes: &[CertificateOfCompletionOutcome],
    required: &[[u8; 32]],
) -> bool {
    let Ok(entries) = integrity_bundle::read_stored_zip(zip) else {
        return false;
    };
    let members = entries
        .iter()
        .filter(|e| e.path().ends_with("/010-events.cbor"))
        .collect::<Vec<_>>();
    let [member] = members.as_slice() else {
        return false;
    };
    let Ok(events) = integrity_cose::decode_cose_sign1_array(member.bytes()) else {
        return false;
    };
    outcomes.iter().any(|outcome| {
        outcome.attestation_authority == CertificateAttestationAuthorityStatus::Verified
            && outcome.attachment_resolved
            && outcome.all_signing_events_resolved
            && outcome.chain_summary_consistent
            && outcome.failures.is_empty()
            && usize::try_from(outcome.event_index)
                .ok()
                .and_then(|i| events.get(i))
                .and_then(|event| event.payload())
                .is_some_and(|payload| payload_covers(payload, &outcome.certificate_id, required))
    })
}

fn payload_covers(payload: &[u8], certificate_id: &str, required: &[[u8; 32]]) -> bool {
    if required.is_empty() {
        return false;
    }
    let Ok(value) = decode_cbor_value(payload) else {
        return false;
    };
    let Some(root) = value.as_map() else {
        return false;
    };
    let Some(extensions) = map_lookup_optional_value(root, "extensions").and_then(Value::as_map)
    else {
        return false;
    };
    let certificates = [
        "trellis.certificate-of-completion.v1",
        "trellis.certificate-of-completion.v2",
    ]
    .iter()
    .flat_map(|literal| {
        extensions
            .iter()
            .filter(move |(key, _)| key.as_text() == Some(*literal))
    })
    .collect::<Vec<_>>();
    let [(_, certificate)] = certificates.as_slice() else {
        return false;
    };
    let Some(certificate) = certificate.as_map() else {
        return false;
    };
    if map_lookup_optional_value(certificate, "certificate_id").and_then(Value::as_text)
        != Some(certificate_id)
    {
        return false;
    }
    let Some(signing) =
        map_lookup_optional_value(certificate, "signing_events").and_then(Value::as_array)
    else {
        return false;
    };
    // The owning verifier validates the complete certificate shape and all signing
    // acts. This additional selection check cannot substitute for that outcome.
    required.iter().all(|hash| {
        signing.iter().any(|value| {
            value
                .as_bytes()
                .is_some_and(|bytes| bytes.as_slice() == hash.as_slice())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(id: &str, hashes: &[[u8; 32]]) -> Vec<u8> {
        let value = Value::Map(vec![(
            Value::Text("extensions".into()),
            Value::Map(vec![(
                Value::Text("trellis.certificate-of-completion.v2".into()),
                Value::Map(vec![
                    (Value::Text("certificate_id".into()), Value::Text(id.into())),
                    (
                        Value::Text("signing_events".into()),
                        Value::Array(hashes.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
                    ),
                ]),
            )]),
        )]);
        integrity_cbor::encode_canonical_cbor_value(&value).unwrap()
    }
    #[test]
    fn source_formal_selection_requires_exact_certificate_and_signing_coverage() {
        let bytes = payload("selected", &[[1; 32], [2; 32]]);
        assert!(payload_covers(&bytes, "selected", &[[1; 32], [2; 32]]));
        assert!(!payload_covers(&bytes, "other", &[[1; 32]]));
        assert!(!payload_covers(&bytes, "selected", &[[3; 32]]));
        assert!(!payload_covers(&bytes, "selected", &[]));
        assert!(!payload_covers(
            &payload("selected", &[[1; 32]]),
            "selected",
            &[[1; 32], [2; 32]]
        ));
    }
    #[test]
    fn source_formal_selection_never_substitutes_for_trusted_outcome() {
        assert!(!selected_certificate_covers(&[], &[], &[[1; 32]]));
        assert!(!payload_covers(b"malformed", "selected", &[[1; 32]]));
    }
    #[test]
    fn source_formal_actual_trusted_v2_export_binds_id_index_and_required_hashes() {
        use integrity_verify::trellis::{
            CertificateAuthorityRegistry, TrellisTimestamp, TrustedCertificateAuthority,
        };
        let zip = include_bytes!(
            "../../../fixtures/vectors/export/015-certificate-v2-distinct-responses/expected-export.zip"
        );
        let key = decode_cbor_value(include_bytes!(
            "../../../fixtures/vectors/_keys/issuer-001.cose_key"
        ))
        .unwrap();
        let public = key
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_integer().is_some_and(|n| i128::from(n) == -2))
            .unwrap()
            .1
            .as_bytes()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let authorities = CertificateAuthorityRegistry::from([(
            "urn:test:operator".into(),
            TrustedCertificateAuthority {
                public_key: public,
                authority_class: "new".into(),
                allowed_purpose: "trellis.certificate-of-completion.v2".into(),
                valid_from: TrellisTimestamp {
                    seconds: 0,
                    nanos: 0,
                },
                valid_until: TrellisTimestamp {
                    seconds: 1_900_000_000,
                    nanos: 0,
                },
            },
        )]);
        let report = crate::verify_export_zip_with_certificate_authorities(zip, &authorities);
        assert!(report.trellis.integrity_verified, "{report:?}");
        assert_eq!(report.trellis.certificates_of_completion.len(), 1);
        let outcomes = &report.trellis.certificates_of_completion;
        assert_eq!(
            outcomes[0].attestation_authority,
            CertificateAttestationAuthorityStatus::Verified
        );
        let entries = integrity_bundle::read_stored_zip(zip).unwrap();
        let member = entries
            .iter()
            .find(|e| e.path().ends_with("/010-events.cbor"))
            .unwrap();
        let events = integrity_cose::decode_cose_sign1_array(member.bytes()).unwrap();
        let value =
            decode_cbor_value(events[outcomes[0].event_index as usize].payload().unwrap()).unwrap();
        let extensions = map_lookup_optional_value(value.as_map().unwrap(), "extensions")
            .unwrap()
            .as_map()
            .unwrap();
        let certificate =
            map_lookup_optional_value(extensions, "trellis.certificate-of-completion.v2")
                .unwrap()
                .as_map()
                .unwrap();
        let required = map_lookup_optional_value(certificate, "signing_events")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_bytes().unwrap().as_slice().try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();
        assert_eq!(required.len(), 2);
        assert!(selected_certificate_covers(zip, outcomes, &required));
        let mut changed = outcomes.clone();
        changed[0].certificate_id = "unrelated".into();
        assert!(!selected_certificate_covers(zip, &changed, &required));
        changed = outcomes.clone();
        changed[0].event_index = 0;
        assert!(!selected_certificate_covers(zip, &changed, &required));
        changed = outcomes.clone();
        changed[0].attestation_authority = CertificateAttestationAuthorityStatus::Unchecked;
        assert!(!selected_certificate_covers(zip, &changed, &required));
        let mut missing = required.clone();
        missing.push([99; 32]);
        assert!(!selected_certificate_covers(zip, outcomes, &missing));
        assert!(!selected_certificate_covers(zip, &[], &required));
        let unchecked = crate::verify_export_zip(zip);
        assert!(!selected_certificate_covers(
            zip,
            &unchecked.trellis.certificates_of_completion,
            &required
        ));
    }
}
