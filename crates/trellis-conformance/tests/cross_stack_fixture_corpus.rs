// Rust guideline compliant 2026-05-15
//! G-7 Trellis consumer: walks the shared cross-stack fixture corpus via
//! `integrity-bundle-fixtures` (fixture bytes at `formspec/tests/fixtures/cross-stack/`).

use std::path::{Path, PathBuf};

use integrity_bundle_fixtures::{
    FixtureBundle, all_manifest_schema_paths, discover_bundles, validate_manifest_schema,
};
use integrity_verify::trellis::verify_export_zip;

const EXPECTED_BUNDLE_IDS: [&str; 8] = ["001", "002", "003", "004", "005", "006", "007", "008"];

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
fn given_cross_stack_fixture_root_when_discovering_bundles_then_expected_ids_are_present() {
    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    assert_eq!(
        bundles.len(),
        EXPECTED_BUNDLE_IDS.len(),
        "expected exactly {} cross-stack fixture bundles",
        EXPECTED_BUNDLE_IDS.len()
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
        EXPECTED_BUNDLE_IDS.len(),
        "expected {} manifest.toml files",
        EXPECTED_BUNDLE_IDS.len()
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

#[tokio::test]
async fn given_shared_cross_stack_bundle_when_replaying_adr0073_vectors_then_trellis_admission_passes() {
    use trellis_admission_wos::WosEventAdmissionPolicy;
    use trellis_server_ports::{AdmissionEvent, EventAdmissionPolicy};
    use trellis_types::ArtifactType;

    let bundles = discover_bundles(cross_stack_root()).expect("discover cross-stack bundles");
    let admission = WosEventAdmissionPolicy::new();

    // 1. Workflow-initiated attach vector from shared bundle 002 ("wos-governed-verified")
    let b002 = bundles.iter().find(|b| b.id == "002").expect("bundle 002 must exist");
    assert!(bundle_is_byte_populated(b002));
    let b002_events_bytes = std::fs::read(b002.dir.join("trellis-events.cbor"))
        .expect("bundle 002 trellis-events.cbor");
    let b002_bundle: serde_json::Value = ciborium::from_reader(&b002_events_bytes[..])
        .expect("parse bundle 002 trellis events");
    assert_eq!(b002_bundle["$trellisEventsBundle"], "1.0");
    let b002_events = b002_bundle["events"].as_array().expect("bundle 002 events");
    assert!(!b002_events.is_empty(), "bundle 002 must have trellis events");

    for ev in b002_events {
        let event_kind = ev["eventKind"].as_str().expect("eventKind present");
        let payload = serde_json::to_vec(&serde_json::json!({
            "id": "prov-002-attach",
            "actorId": "applicant",
            "timestamp": "2026-05-08T17:42:00Z",
            "recordKind": "signatureAffirmation",
            "event": event_kind,
            "data": ev["data"]
        })).unwrap();

        let admitted = admission
            .admit(&AdmissionEvent {
                scope: b"case-cross-stack-002",
                event_type: event_kind,
                payload: &payload,
            })
            .await
            .expect("workflow-attach event in shared bundle 002 must admit");

        assert_eq!(admitted.event_type, event_kind);
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
        assert_eq!(admitted.artifact_type, ArtifactType::Event);
    }

    // Verify bundle 002 cross-layer invariants declared in manifest
    assert_eq!(
        b002.manifest.cross_layer_byte_equality.formspec_signed_payload_digest_equals_wos,
        Some(true)
    );
    assert_eq!(
        b002.manifest.cross_layer_byte_equality.verification_receipt_bytes_identical,
        Some(true)
    );

    // 2. Public-intake refusal vector from shared bundle 003 ("unsupported-method-rejected")
    let b003 = bundles.iter().find(|b| b.id == "003").expect("bundle 003 must exist");
    assert!(bundle_is_byte_populated(b003));
    let b003_events_bytes = std::fs::read(b003.dir.join("trellis-events.cbor"))
        .expect("bundle 003 trellis-events.cbor");
    let b003_bundle: serde_json::Value = ciborium::from_reader(&b003_events_bytes[..])
        .expect("parse bundle 003");
    let b003_events = b003_bundle["events"].as_array().expect("bundle 003 events");

    for ev in b003_events {
        let event_kind = ev["eventKind"].as_str().expect("eventKind present");
        assert_eq!(event_kind, "wos.kernel.signature_admission_failed");
        let payload = serde_json::to_vec(&serde_json::json!({
            "id": "prov-003-refusal",
            "actorId": "system",
            "timestamp": "2026-05-08T17:42:00Z",
            "recordKind": "signatureAdmissionFailed",
            "event": event_kind,
            "data": ev["data"]
        })).unwrap();

        let admitted = admission
            .admit(&AdmissionEvent {
                scope: b"case-cross-stack-003",
                event_type: event_kind,
                payload: &payload,
            })
            .await
            .expect("signature_admission_failed in shared bundle 003 must admit");

        assert_eq!(admitted.event_type, "wos.kernel.signature_admission_failed");
        assert_eq!(admitted.event_family.as_str(), "wos.kernel");
    }

    // 3. Deferred-intake vector from shared bundle 006 ("deferred-pending-helper")
    let b006 = bundles.iter().find(|b| b.id == "006").expect("bundle 006 must exist");
    assert!(bundle_is_byte_populated(b006));
    let b006_events_bytes = std::fs::read(b006.dir.join("trellis-events.cbor"))
        .expect("bundle 006 trellis-events.cbor");
    let b006_bundle: serde_json::Value = ciborium::from_reader(&b006_events_bytes[..])
        .expect("parse bundle 006");
    let b006_events = b006_bundle["events"].as_array().expect("bundle 006 events");
    assert!(!b006_events.is_empty());
}

#[tokio::test]
async fn given_adr0073_append_vectors_when_replaying_then_workflow_attach_and_public_intake_succeed() {
    use trellis_admission_wos::WosEventAdmissionPolicy;
    use trellis_server_ports::{AdmissionEvent, EventAdmissionPolicy};
    use trellis_types::ArtifactType;

    let admission = WosEventAdmissionPolicy::new();
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors/append");

    // Replay 020: workflow-initiated attach
    let dir_020 = fixtures_root.join("020-wos-intake-accepted-workflow-attach");
    let record_020_bytes = std::fs::read(dir_020.join("input-wos-record.dcbor")).expect("020 record");
    let record_020: serde_json::Value = ciborium::from_reader(&record_020_bytes[..]).expect("020 cbor");
    assert_eq!(record_020["data"]["caseDisposition"], "attachToExistingCase");
    assert_eq!(record_020["event"], "wos.kernel.intake_accepted");
    let payload_020 = serde_json::to_vec(&serde_json::json!({
        "id": record_020["id"],
        "actorId": record_020["actorId"],
        "timestamp": record_020["timestamp"],
        "recordKind": "intakeAccepted",
        "event": "wos.kernel.intake_accepted",
        "data": record_020["data"],
    })).unwrap();
    let admitted_020 = admission
        .admit(&AdmissionEvent {
            scope: b"case-workflow-attach",
            event_type: "wos.kernel.intake_accepted",
            payload: &payload_020,
        })
        .await
        .expect("020 workflow-attach must admit");
    assert_eq!(admitted_020.event_type, "wos.kernel.intake_accepted");
    assert_eq!(admitted_020.artifact_type, ArtifactType::Event);

    // Replay 021: public intake create
    let dir_021 = fixtures_root.join("021-wos-intake-accepted-public-create");
    let record_021_bytes = std::fs::read(dir_021.join("input-wos-record.dcbor")).expect("021 record");
    let record_021: serde_json::Value = ciborium::from_reader(&record_021_bytes[..]).expect("021 cbor");
    assert_eq!(record_021["data"]["caseDisposition"], "createGovernedCase");
    assert_eq!(record_021["event"], "wos.kernel.intake_accepted");
    let payload_021 = serde_json::to_vec(&serde_json::json!({
        "id": record_021["id"],
        "actorId": record_021["actorId"],
        "timestamp": record_021["timestamp"],
        "recordKind": "intakeAccepted",
        "event": "wos.kernel.intake_accepted",
        "data": record_021["data"],
    })).unwrap();
    let admitted_021 = admission
        .admit(&AdmissionEvent {
            scope: b"case-public-create",
            event_type: "wos.kernel.intake_accepted",
            payload: &payload_021,
        })
        .await
        .expect("021 public-create must admit");
    assert_eq!(admitted_021.event_type, "wos.kernel.intake_accepted");

    // Replay 022: public intake case created
    let dir_022 = fixtures_root.join("022-wos-case-created-public-intake");
    let record_022_bytes = std::fs::read(dir_022.join("input-wos-record.dcbor")).expect("022 record");
    let record_022: serde_json::Value = ciborium::from_reader(&record_022_bytes[..]).expect("022 cbor");
    assert_eq!(record_022["event"], "wos.kernel.case_created");
    let payload_022 = serde_json::to_vec(&serde_json::json!({
        "id": record_022["id"],
        "actorId": record_022["actorId"],
        "timestamp": record_022["timestamp"],
        "recordKind": "caseCreated",
        "event": "wos.kernel.case_created",
        "data": record_022["data"],
    })).unwrap();
    let admitted_022 = admission
        .admit(&AdmissionEvent {
            scope: b"case-public-create",
            event_type: "wos.kernel.case_created",
            payload: &payload_022,
        })
        .await
        .expect("022 case-created must admit");
    assert_eq!(admitted_022.event_type, "wos.kernel.case_created");
}


