// Rust guideline compliant 2026-05-15
//! G-7 Trellis consumer: walks the shared seven-bundle cross-stack corpus via
//! `integrity-bundle-fixtures` (fixture bytes at `formspec/tests/fixtures/cross-stack/`).

use std::path::{Path, PathBuf};

use integrity_bundle_fixtures::{
    FixtureBundle, all_manifest_schema_paths, discover_bundles, validate_manifest_schema,
};
use integrity_verify::trellis::verify_export_zip;

const EXPECTED_BUNDLE_IDS: [&str; 7] = ["001", "002", "003", "004", "005", "006", "007"];

fn cross_stack_root() -> PathBuf {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../formspec/tests/fixtures/cross-stack");
    assert!(
        root.join("manifest.schema.json").is_file(),
        "cross-stack fixture root missing at {} (repo layout may have moved)",
        root.display()
    );
    root
}

fn bundle_is_byte_populated(bundle: &FixtureBundle) -> bool {
    bundle.dir.join("formspec-response.json").is_file()
}

#[test]
fn given_cross_stack_fixture_root_when_discovering_bundles_then_exactly_seven_ids_001_through_007()
{
    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    assert_eq!(
        bundles.len(),
        7,
        "expected exactly seven cross-stack fixture bundles"
    );
    let ids: Vec<_> = bundles.iter().map(|bundle| bundle.id.as_str()).collect();
    assert_eq!(ids, EXPECTED_BUNDLE_IDS);
}

#[test]
fn given_each_cross_stack_manifest_when_validating_schema_then_validation_succeeds() {
    let root = cross_stack_root();
    let manifest_paths = all_manifest_schema_paths(root.to_str().unwrap()).expect("manifest paths");
    assert_eq!(
        manifest_paths.len(),
        7,
        "expected seven manifest.toml files"
    );
    for manifest_path in manifest_paths {
        validate_manifest_schema(&manifest_path).unwrap_or_else(|error| {
            panic!(
                "manifest {:?} failed schema validation: {error}",
                manifest_path
            );
        });
    }
}

#[test]
fn given_byte_populated_bundle_when_trellis_artifacts_required_then_files_exist_on_disk() {
    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    for bundle in &bundles {
        if !bundle_is_byte_populated(bundle) {
            continue;
        }
        let required = &bundle.manifest.required_files;
        if required.trellis_events {
            let path = bundle.dir.join("trellis-events.cbor");
            assert!(
                path.is_file(),
                "bundle {} requires trellis-events.cbor at {}",
                bundle.id,
                path.display()
            );
        }
        if required.trellis_export {
            let path = bundle.dir.join("trellis-export.zip");
            assert!(
                path.is_file(),
                "bundle {} requires trellis-export.zip at {}",
                bundle.id,
                path.display()
            );
        }
        if let Some(trellis) = bundle.manifest.expected_outcomes.trellis.as_ref() {
            if trellis.present == Some(true) {
                assert!(
                    required.trellis_events || required.trellis_export,
                    "bundle {} declares trellis present but no trellis artifact flags",
                    bundle.id
                );
            }
        }
    }
}

#[test]
fn given_cross_stack_bundle_with_trellis_export_zip_when_verifying_then_structure_passes() {
    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    for bundle in &bundles {
        let path = bundle.dir.join("trellis-export.zip");
        if !path.is_file() {
            continue;
        }
        let export_zip = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "bundle {} trellis-export.zip must be readable: {error}",
                bundle.id
            );
        });
        let report = verify_export_zip(&export_zip);
        assert!(
            report.structure_verified,
            "bundle {} export ZIP failed structure verification: {report:?}",
            bundle.id
        );
        assert!(
            report.integrity_verified,
            "bundle {} export ZIP failed integrity verification: {report:?}",
            bundle.id
        );
    }
}

#[test]
fn given_skeleton_bundle_when_no_bytes_then_consumer_skips_artifact_verify() {
    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    for bundle in &bundles {
        if bundle_is_byte_populated(bundle) {
            continue;
        }
        assert!(
            !bundle.dir.join("trellis-export.zip").is_file(),
            "skeleton bundle {} must not ship trellis-export.zip until bytes land",
            bundle.id
        );
    }
}
