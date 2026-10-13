//! Publication-phase failures remain distinct from Source verification.
// Rust guideline compliant 2026-02-21

#[test]
fn source_content_publication_rejects_unreadable_archive() {
    let report = crate::verify_source_content_publication(b"not a ZIP", None);
    assert!(!report.publication_admitted());
    assert!(!report.substrate().structure_verified);
}

#[test]
fn source_content_publication_preserves_tampered_catalog_failure() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../fixtures/vectors/verify/014-export-006-signature-row-mismatch/input-export.zip",
    );
    let bytes = std::fs::read(path).unwrap();
    let ordinary = crate::verify_export_zip(&bytes);
    let publication = crate::verify_source_content_publication(&bytes, None);
    assert!(!publication.publication_admitted());
    assert_eq!(publication.substrate(), &ordinary.trellis);
    assert_eq!(publication.findings(), ordinary.wos_findings.as_slice());
}
