// Rust guideline compliant 2026-02-21
//! Extracts retained HTML after full verification, without rendering new bytes.
use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, map_lookup_bytes, map_lookup_map,
    map_lookup_optional_value, map_lookup_text, map_lookup_u64, sha256_bytes,
};
use integrity_verify::trellis::{
    CertificateAttestationAuthorityStatus, CertificateAuthorityRegistry, Severity,
};

/// Exact certificate bytes and independently selected operator-verification status.
pub struct CertificateHtml {
    pub bytes: Vec<u8>,
    pub operator_authority: CertificateAttestationAuthorityStatus,
}

/// Verifies the archive and extracts the exact bound HTML for one certificate.
///
/// This does not open protected originals or establish current case permission.
/// Missing external operator trust remains explicitly unchecked in the result.
/// # Errors
/// Refuses archive/domain failure, missing or ambiguous certificates/bindings,
/// protected presentations, or mismatched raw/content/presentation hashes and lengths.
pub fn certificate_html_from_export(
    zip: &[u8],
    certificate_id: &str,
    authorities: Option<&CertificateAuthorityRegistry>,
) -> Result<CertificateHtml, String> {
    if zip.len() > 16 * 1024 * 1024 || certificate_id.is_empty() || certificate_id.len() > 1024 {
        return Err("certificate extraction input exceeds bounds".into());
    }
    let report = match authorities {
        Some(registry) => crate::verify_export_zip_with_certificate_authorities(zip, registry),
        None => crate::verify_export_zip(zip),
    };
    if !report.trellis.structure_verified
        || !report.trellis.integrity_verified
        || report
            .wos_findings
            .iter()
            .any(|finding| finding.severity == Severity::Failure)
    {
        return Err("certificate archive verification failed".into());
    }
    let outcomes = report
        .trellis
        .certificates_of_completion
        .iter()
        .filter(|certificate| certificate.certificate_id == certificate_id)
        .collect::<Vec<_>>();
    if outcomes.len() != 1 {
        return Err("certificate ID absent or ambiguous".into());
    }
    let entries = integrity_bundle::read_stored_zip(zip).map_err(|e| e.to_string())?;
    let event_members = entries
        .iter()
        .filter(|e| e.path().ends_with("/010-events.cbor"))
        .collect::<Vec<_>>();
    if event_members.len() != 1 {
        return Err("certificate event member absent or ambiguous".into());
    }
    let events = integrity_cose::decode_cose_sign1_array(event_members[0].bytes())
        .map_err(|e| e.to_string())?;
    let mut presentations = Vec::new();
    let mut bindings = Vec::new();
    for event in events {
        let value = decode_cbor_value(event.payload().ok_or("certificate signed payload absent")?)
            .map_err(|e| e.to_string())?;
        let root = value
            .as_map()
            .ok_or("certificate signed payload malformed")?;
        let Some(extensions) =
            map_lookup_optional_value(root, "extensions").and_then(Value::as_map)
        else {
            continue;
        };
        for literal in [
            "trellis.certificate-of-completion.v1",
            "trellis.certificate-of-completion.v2",
        ] {
            if let Some(certificate) =
                map_lookup_optional_value(extensions, literal).and_then(Value::as_map)
            {
                if map_lookup_text(certificate, "certificate_id").map_err(|e| e.to_string())?
                    == certificate_id
                {
                    presentations.push(
                        map_lookup_map(certificate, "presentation_artifact")
                            .map_err(|e| e.to_string())?
                            .to_vec(),
                    );
                }
            }
        }
        if let Some(binding) =
            map_lookup_optional_value(extensions, "trellis.evidence-attachment-binding.v1")
                .and_then(Value::as_map)
        {
            bindings.push(binding.to_vec());
        }
    }
    if presentations.len() != 1 {
        return Err("certificate presentation absent or ambiguous".into());
    }
    let presentation = &presentations[0];
    if map_lookup_text(presentation, "media_type").map_err(|e| e.to_string())? != "text/html" {
        return Err("certificate presentation is not HTML".into());
    }
    let id = map_lookup_text(presentation, "attachment_id").map_err(|e| e.to_string())?;
    let matching = bindings
        .iter()
        .filter(|binding| map_lookup_text(binding, "attachment_id").is_ok_and(|v| v == id))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err("certificate attachment binding absent or ambiguous".into());
    }
    let binding = matching[0];
    let digest = map_lookup_text(binding, "payload_content_hash").map_err(|e| e.to_string())?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or("certificate payload digest malformed")?;
    let suffix = format!("/060-payloads/{hex}.bin");
    let payloads = entries
        .iter()
        .filter(|entry| entry.path().ends_with(&suffix))
        .collect::<Vec<_>>();
    if payloads.len() != 1 {
        return Err("certificate retained HTML absent or ambiguous".into());
    }
    let bytes = payloads[0].bytes();
    let raw_hash = format!("sha256:{}", hex::encode(sha256_bytes(bytes)));
    let content_hash = format!(
        "sha256:{}",
        hex::encode(domain_separated_sha256("trellis-content-v1", bytes))
    );
    if bytes.len() > 1024 * 1024
        || map_lookup_text(binding, "media_type").map_err(|e| e.to_string())? != "text/html"
        || map_lookup_text(binding, "attachment_sha256").map_err(|e| e.to_string())? != raw_hash
        || digest != content_hash
        || map_lookup_u64(binding, "byte_length").map_err(|e| e.to_string())? != bytes.len() as u64
        || map_lookup_u64(presentation, "byte_length").map_err(|e| e.to_string())?
            != bytes.len() as u64
        || map_lookup_bytes(presentation, "content_hash").map_err(|e| e.to_string())?
            != domain_separated_sha256("trellis-presentation-artifact-v1", bytes)
    {
        return Err("certificate retained HTML binding differs".into());
    }
    Ok(CertificateHtml {
        bytes: bytes.to_vec(),
        operator_authority: outcomes[0].attestation_authority,
    })
}
