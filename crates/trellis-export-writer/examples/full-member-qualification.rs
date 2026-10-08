// Rust guideline compliant 2026-02-21
//! Probes existing writer carriage using committed synthetic native records.
//!
//! Reuses export/010's three-event attachment/signature/certificate chain and
//! registered manifest extensions. This is not D1 history or a second writer.
//! Run with `--features fixture-inputs`; the output directory receives a
//! controlled ZIP and public JSON diagnostics. Missing required native members
//! return a nonzero exit status for the retained RED qualification receipt.

use std::error::Error;
use std::path::{Path, PathBuf};

use integrity_cbor::{Value, decode_cbor_value, encode_cbor_value, map_lookup_u64};
use integrity_cose::decode_cose_sign1;
use trellis_export_writer::{
    RegistrySnapshot, TrellisTimestamp, export_001_writer_input, write_export,
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
    let fixture = vectors.join("export/010-certificate-of-completion-inline");
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
    input.checkpoint_timestamps.clear();
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
        input
            .checkpoint_timestamps
            .push(timestamp(field(field(&value, "header")?, "authored_at")?)?);
        input
            .events
            .push(StoredEvent::new(scope.clone(), sequence, payload, signed));
    }
    // The writer emits one checkpoint per event. Native fixture 010 stores
    // only its head, so use each signed authored_at as the server does and
    // require the resulting final timestamp to match the committed head.
    let checkpoints = fixture_value(&fixture.join("040-checkpoints.cbor"))?;
    let head = checkpoints
        .as_array()
        .ok_or("checkpoints not array")?
        .last()
        .ok_or("fixture checkpoint absent")?;
    let head = decode_cose_sign1(&encode_cbor_value(head)?)?;
    let head_value = decode_cbor_value(head.payload().ok_or("checkpoint payload absent")?)?;
    if input.checkpoint_timestamps.last().copied()
        != Some(timestamp(field(&head_value, "timestamp")?)?)
    {
        return Err("fixture event timestamp differs from committed head".into());
    }
    input.generated_at = timestamp(field(&manifest_value, "generated_at")?)?;
    input.extensions = Some(field(&manifest_value, "extensions")?.clone());
    input.registries = vec![RegistrySnapshot {
        bytes: std::fs::read(fixture.join(
            "050-registries/a0c9f644dffed45242002257c27e050c8f012cede3509a1b4b2d5f2f27408878.cbor",
        ))?,
        registry_format: 1,
        registry_version: "x-trellis-test/registry-cert-export-010-v1".to_string(),
        bound_at_sequence: 0,
    }];
    input.generator = "x-trellis-test/full-member-qualification".to_string();
    input.readme_title =
        "Controlled native writer qualification; synthetic fixture 010".to_string();
    // The full frozen D1 candidate additionally requests 062/063/066/067/068
    // and open clocks when applicable. This minimal valid chain already needs
    // the three native carriers below; stop at their first actual failure.
    let package = write_export(input)?;
    let original_members = std::fs::read_dir(fixture.join("060-payloads"))?
        .map(|entry| {
            entry.map(|entry| format!("060-payloads/{}", entry.file_name().to_string_lossy()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut required = vec![
        "061-attachments.cbor".to_string(),
        "065-certificates-of-completion.cbor".to_string(),
    ];
    required.extend(original_members);
    required.sort();
    let missing: Vec<_> = required
        .iter()
        .filter(|member| package.member_bytes(member).is_none())
        .collect();
    let report = trellis_verify_wos::verify_export_zip(&package.zip_bytes);
    std::fs::create_dir_all(&output)?;
    std::fs::write(
        output.join("controlled-writer-output.zip"),
        &package.zip_bytes,
    )?;
    let diagnostic = serde_json::json!({
        "qualification": "Synthetic committed native fixture; not actual D1 history/certificate",
        "fixture": "export/010-certificate-of-completion-inline",
        "originalStructureVerified": original.trellis.structure_verified,
        "originalIntegrityVerified": original.trellis.integrity_verified,
        "fullD1DesiredMemberFamilies": ["060-payloads/", "061-attachments.cbor", "062-signature-affirmations.cbor", "063-intake-handoffs.cbor", "065-certificates-of-completion.cbor", "066-signed-acts.cbor", "067-policy-closure.cbor", "068-signed-acts-manifest.cbor", "open-clocks.json"],
        "fullD1ConstructionStopped": true,
        "requiredNativeMembers": required,
        "missingNativeMembers": missing,
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
    if !report.trellis.structure_verified || !report.trellis.integrity_verified {
        return Err("native writer output failed verification".into());
    }
    Ok(())
}
