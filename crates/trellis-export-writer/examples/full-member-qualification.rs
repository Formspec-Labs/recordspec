// Rust guideline compliant 2026-02-21
//! Probes existing writer carriage using committed synthetic native records.
//!
//! Reuses separate export/006, 007 and 010 native chains and registered
//! manifest extensions. This is not D1 history or a second writer.
//! Run with `--features fixture-inputs`; the output directory receives a
//! controlled ZIP and public JSON diagnostics. Missing required native members
//! return a nonzero exit status for the retained RED qualification receipt.

use std::error::Error;
use std::path::{Path, PathBuf};

use integrity_cbor::{Value, decode_cbor_value, encode_cbor_value, map_lookup_u64};
use integrity_cose::decode_cose_sign1;
use trellis_export_writer::{
    ExportEvidenceMember, PolicyClosureMember, RegistrySnapshot, SignedActsCatalogMember,
    SignedActsManifestMember, TrellisTimestamp, export_001_writer_input, issue_checkpoints,
    write_export,
};
use trellis_types::StoredEvent;

fn fixture_value(path: &Path) -> Result<Value, Box<dyn Error>> {
    Ok(decode_cbor_value(&std::fs::read(path)?)?)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .as_map()
        .and_then(|items| items.iter().find(|(key, _)| key.as_text() == Some(name)))
        .map(|(_, value)| value)
        .ok_or_else(|| format!("fixture field missing: {name}").into())
}

fn timestamp(value: &Value) -> Result<TrellisTimestamp, Box<dyn Error>> {
    let items = value
        .as_array()
        .ok_or("fixture timestamp is not an array")?;
    let seconds = u64::try_from(
        items
            .first()
            .ok_or("timestamp seconds missing")?
            .as_integer()
            .ok_or("timestamp seconds not integer")?,
    )?;
    let nanos = u32::try_from(
        items
            .get(1)
            .ok_or("timestamp nanos missing")?
            .as_integer()
            .ok_or("timestamp nanos not integer")?,
    )?;
    Ok(TrellisTimestamp::new(seconds, nanos)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("provide controlled output directory")?,
    );
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors");
    let fixture_name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "010-certificate-of-completion-inline".to_string());
    if ![
        "010-certificate-of-completion-inline",
        "006-signature-affirmations-inline",
        "007-intake-handoffs-public-create",
    ]
    .contains(&fixture_name.as_str())
    {
        return Err("choose one of the three qualified native fixture sources".into());
    }
    let fixture = vectors.join("export").join(&fixture_name);
    let original_bytes = std::fs::read(fixture.join("expected-export.zip"))?;
    let original = trellis_verify_wos::verify_export_zip(&original_bytes);
    if !original.trellis.structure_verified || !original.trellis.integrity_verified {
        return Err(
            "committed source fixture is not valid; stop before writer qualification".into(),
        );
    }
    let manifest = decode_cose_sign1(&std::fs::read(fixture.join("000-manifest.cbor"))?)?;
    let manifest_value = decode_cbor_value(manifest.payload().ok_or("manifest payload absent")?)?;
    let scope = field(&manifest_value, "scope")?
        .as_bytes()
        .ok_or("scope not bytes")?
        .clone();
    // The maintained fixture utility supplies the same committed issuer-001
    // signing material. Replace its ledger data with exact export/010 records.
    let mut input = export_001_writer_input(&vectors);
    input.scope = scope.clone();
    input.events.clear();
    let mut checkpoint_timestamps = Vec::new();
    let events = fixture_value(&fixture.join("010-events.cbor"))?;
    if encode_cbor_value(&events)? != std::fs::read(fixture.join("010-events.cbor"))? {
        return Err("fixture event re-encoding changed source bytes".into());
    }
    for event in events.as_array().ok_or("events not array")? {
        let signed = encode_cbor_value(event)?;
        let envelope = decode_cose_sign1(&signed)?;
        let payload = envelope.payload().ok_or("event payload absent")?.to_vec();
        let value = decode_cbor_value(&payload)?;
        let sequence = map_lookup_u64(value.as_map().ok_or("event not map")?, "sequence")?;
        checkpoint_timestamps.push(timestamp(field(field(&value, "header")?, "authored_at")?)?);
        input
            .events
            .push(StoredEvent::new(scope.clone(), sequence, payload, signed));
    }
    // The writer emits one checkpoint per event. Native fixtures may retain
    // only the head. Keep authored timestamps for intermediate checkpoints and
    // use the exact retained head timestamp for the final checkpoint.
    let checkpoints = fixture_value(&fixture.join("040-checkpoints.cbor"))?;
    let head = checkpoints
        .as_array()
        .ok_or("checkpoints not array")?
        .last()
        .ok_or("fixture checkpoint absent")?;
    let head = decode_cose_sign1(&encode_cbor_value(head)?)?;
    let head_value = decode_cbor_value(head.payload().ok_or("checkpoint payload absent")?)?;
    *checkpoint_timestamps
        .last_mut()
        .ok_or("fixture events absent")? = timestamp(field(&head_value, "timestamp")?)?;
    input.checkpoints = issue_checkpoints(
        &scope,
        &input.events,
        &std::fs::read(vectors.join("_keys/issuer-001.cose_key"))?,
        &checkpoint_timestamps,
    );
    input.generated_at = timestamp(field(&manifest_value, "generated_at")?)?;
    input.extensions = Some(field(&manifest_value, "extensions")?.clone());
    let binding = field(&manifest_value, "registry_bindings")?
        .as_array()
        .ok_or("registry_bindings not array")?
        .first()
        .ok_or("registry binding absent")?;
    let registry_file = std::fs::read_dir(fixture.join("050-registries"))?
        .next()
        .ok_or("registry file absent")??;
    input.registries = vec![RegistrySnapshot {
        bytes: std::fs::read(registry_file.path())?,
        registry_format: 1,
        registry_version: field(binding, "registry_version")?
            .as_text()
            .ok_or("registry version not text")?
            .to_string(),
        bound_at_sequence: 0,
    }];
    let mut required = Vec::new();
    if fixture.join("060-payloads").is_dir() {
        for entry in std::fs::read_dir(fixture.join("060-payloads"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let hash_text = name
                .strip_suffix(".bin")
                .ok_or("payload extension invalid")?;
            if hash_text.len() != 64 {
                return Err("payload hash length invalid".into());
            }
            let mut content_hash = [0; 32];
            for (i, byte) in content_hash.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hash_text[i * 2..i * 2 + 2], 16)?;
            }
            input.evidence_members.push(ExportEvidenceMember::Payload {
                content_hash,
                bytes: std::fs::read(entry.path())?,
            });
            required.push(format!("060-payloads/{name}"));
        }
    }
    for member in [
        "061-attachments.cbor",
        "062-signature-affirmations.cbor",
        "063-intake-handoffs.cbor",
        "065-certificates-of-completion.cbor",
    ] {
        if !fixture.join(member).exists() {
            continue;
        }
        let bytes = std::fs::read(fixture.join(member))?;
        input.evidence_members.push(match member {
            "061-attachments.cbor" => ExportEvidenceMember::Attachments {
                bytes,
                inline_attachments: true,
            },
            "062-signature-affirmations.cbor" => {
                ExportEvidenceMember::SignatureAffirmations { bytes }
            }
            "063-intake-handoffs.cbor" => ExportEvidenceMember::IntakeHandoffs { bytes },
            _ => ExportEvidenceMember::CertificatesOfCompletion { bytes },
        });
        required.push(member.to_string());
    }
    let extensions = field(&manifest_value, "extensions")?;
    for (member, extension, metadata) in [
        (
            "066-signed-acts.cbor",
            "trellis.export.signed-acts.v1",
            "derivation_rule",
        ),
        (
            "068-signed-acts-manifest.cbor",
            "trellis.export.signed-acts.manifest.v1",
            "derivation_rule",
        ),
        (
            "067-policy-closure.cbor",
            "trellis.export.policy-closure.v1",
            "closure_version",
        ),
    ] {
        if !fixture.join(member).exists() {
            continue;
        }
        let bytes = std::fs::read(fixture.join(member))?;
        let value = field(field(extensions, extension)?, metadata)?
            .as_text()
            .ok_or("catalog metadata not text")?
            .to_string();
        match member {
            "066-signed-acts.cbor" => {
                input.signed_acts_catalog = Some(SignedActsCatalogMember {
                    bytes,
                    derivation_rule: value,
                })
            }
            "068-signed-acts-manifest.cbor" => {
                input.signed_acts_manifest = Some(SignedActsManifestMember {
                    bytes,
                    derivation_rule: value,
                })
            }
            _ => {
                input.policy_closure = Some(PolicyClosureMember {
                    bytes,
                    closure_version: value,
                })
            }
        }
        required.push(member.to_string());
    }
    input.generator = "x-trellis-test/full-member-qualification".to_string();
    input.readme_title =
        format!("Controlled native writer qualification; synthetic {fixture_name}");
    // Each fixture retains its own sealed history. The original RED remains
    // pinned at commit 5326fe5; this run supplies its actual native member bytes.
    // The explicit negative mode retains the inlining assertion but withholds
    // payload bytes so the composed verifier must refuse the incomplete archive.
    if std::env::args().nth(3).as_deref() == Some("--omit-payloads") {
        input
            .evidence_members
            .retain(|member| !matches!(member, ExportEvidenceMember::Payload { .. }));
    }
    let package = write_export(input)?;
    required.sort();
    let missing: Vec<_> = required
        .iter()
        .filter(|member| package.member_bytes(member).is_none())
        .collect();
    let mismatched: Vec<_> = required
        .iter()
        .filter(|member| {
            package.member_bytes(member).is_some_and(|bytes| {
                bytes != std::fs::read(fixture.join(member)).expect("retained native member")
            })
        })
        .collect();
    let report = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
    std::fs::create_dir_all(&output)?;
    std::fs::write(
        output.join("controlled-writer-output.zip"),
        &package.zip_bytes,
    )?;
    let diagnostic = serde_json::json!({
        "qualification": "Synthetic committed native fixture; not actual D1 history/certificate",
        "writerEventFailures": format!("{:?}", report.trellis.event_failures),
        "fixture": format!("export/{fixture_name}"),
        "originalStructureVerified": original.trellis.structure_verified,
        "originalIntegrityVerified": original.trellis.integrity_verified,
        "fullD1DesiredMemberFamilies": ["060-payloads/", "061-attachments.cbor", "062-signature-affirmations.cbor", "063-intake-handoffs.cbor", "065-certificates-of-completion.cbor", "066-signed-acts.cbor", "067-policy-closure.cbor", "068-signed-acts-manifest.cbor", "open-clocks.json"],
        "fullD1ConstructionStopped": true,
        "requiredNativeMembers": required,
        "missingNativeMembers": missing,
        "mismatchedNativeMembers": mismatched,
        "emittedMembers": package.entries.iter().map(|entry| entry.path()).collect::<Vec<_>>(),
        "writerStructureVerified": report.trellis.structure_verified,
        "writerIntegrityVerified": report.trellis.integrity_verified,
        "headCheckpointDigest": package.head_checkpoint_digest,
        "manifestDigest": package.manifest_digest,
    });
    std::fs::write(
        output.join("controlled-writer-output.json"),
        serde_json::to_vec_pretty(&diagnostic)?,
    )?;
    println!("{diagnostic}");
    if !missing.is_empty() {
        return Err(format!("native writer missing required member: {}", missing[0]).into());
    }
    if !mismatched.is_empty() {
        return Err("native member byte identity changed".into());
    }
    if !report.trellis.structure_verified || !report.trellis.integrity_verified {
        return Err("native writer output failed verification".into());
    }
    Ok(())
}
