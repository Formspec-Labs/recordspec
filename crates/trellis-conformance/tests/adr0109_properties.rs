// Rust guideline compliant 2026-02-21

use integrity_cose::{
    COSE_LABEL_ALG, COSE_LABEL_KID, decode_protected_header, encode_cose_suite_id_label,
    substrate_protected_header,
};
use proptest::prelude::*;
use trellis_types::{ArtifactType, SUITE_ID_PHASE_1};

fn unknown_artifact_type() -> impl Strategy<Value = String> {
    "[A-Za-z0-9:@._/-]{0,64}".prop_filter(
        "not one of the Trellis substrate artifact_type values",
        |value| !matches!(value.as_str(), "event" | "checkpoint" | "manifest"),
    )
}

fn retired_dispatch_header(kid: [u8; 16], value: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40);
    bytes.push(0xa4);
    bytes.push(COSE_LABEL_ALG as u8);
    bytes.push(0x27);
    bytes.push(COSE_LABEL_KID as u8);
    bytes.push(0x50);
    bytes.extend_from_slice(&kid);
    bytes.extend_from_slice(&encode_cose_suite_id_label());
    bytes.push(SUITE_ID_PHASE_1 as u8);
    // Retired ADR 0109 dispatch label -65539: CBOR negative-int magnitude
    // 65538 encoded as 0x3a_00010002.
    bytes.extend_from_slice(&[0x3a, 0x00, 0x01, 0x00, 0x02]);
    bytes.push(value);
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn unknown_artifact_type_values_reject_with_named_error(value in unknown_artifact_type()) {
        let protected = substrate_protected_header(-8, &[0x11; 16], SUITE_ID_PHASE_1, &value);
        let header = decode_protected_header(&protected)
            .expect("unknown artifact_type remains structurally inspectable");
        prop_assert_eq!(header.artifact_type.as_deref(), Some(value.as_str()));

        let error = ArtifactType::from_cose_value(&value)
            .expect_err("unknown artifact_type must reject");
        prop_assert_eq!(error.value(), value.as_str());
        prop_assert!(
            error.to_string().contains("unknown artifact_type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn retired_dispatch_label_rejects_with_named_error(kid in any::<[u8; 16]>(), value in 0u8..=23) {
        let protected = retired_dispatch_header(kid, value);
        let error = decode_protected_header(&protected)
            .expect_err("retired dispatch label must reject");
        prop_assert!(
            error.to_string().contains("RetiredDispatchLabelPresent"),
            "unexpected error: {error}"
        );
    }
}
