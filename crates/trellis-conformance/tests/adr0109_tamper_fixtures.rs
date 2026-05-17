// Rust guideline compliant 2026-02-21

use std::{
    fs,
    path::{Path, PathBuf},
};

use integrity_verify::trellis::{VerificationFailureKind, verify_tampered_ledger};

fn tamper_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors/tamper")
}

fn assert_adr0109_tamper_vector(vector: &str, reason: &str) {
    let root = tamper_root().join(vector);
    let registry = fs::read(root.join("input-signing-key-registry.cbor"))
        .expect("read signing key registry fixture");
    let ledger =
        fs::read(root.join("input-tampered-ledger.cbor")).expect("read tampered ledger fixture");

    let report =
        verify_tampered_ledger(&registry, &ledger, None, None).expect("verification report");

    assert!(!report.structure_verified, "{report:?}");
    assert!(!report.integrity_verified, "{report:?}");
    assert!(!report.readability_verified, "{report:?}");
    assert!(
        report
            .event_failures
            .iter()
            .any(|failure| failure.kind == VerificationFailureKind::MalformedCose),
        "expected malformed_cose failure, got {report:?}"
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains(reason)),
        "expected warning to contain {reason}, got {report:?}"
    );
}

#[test]
fn unknown_artifact_type_tamper_fixture_rejects_with_named_reason() {
    assert_adr0109_tamper_vector("053-unknown-artifact-type", "ArtifactTypeUnknown");
}

#[test]
fn retired_dispatch_label_tamper_fixture_rejects_with_named_reason() {
    assert_adr0109_tamper_vector("054-retired-dispatch-label", "RetiredDispatchLabelPresent");
}
