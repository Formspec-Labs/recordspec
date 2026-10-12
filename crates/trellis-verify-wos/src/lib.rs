// Rust guideline compliant 2026-02-21
//! WOS-aware verification composed on Trellis integrity verification.
//!
//! Verification proves Trellis bundle structure, checkpoints, and signatures, then applies WOS-domain rules through
//! [`WosRecordValidator`]. The validator installs [`WosFormspecResolver`] so Formspec intake digest material carried
//! inside WOS-shaped provenance still participates in certificate / response-hash checks on the same export bundle
//! bytes (TWREF-025). Formspec producers append under `substrate.append.*` while WOS producers append under `wos.*`,
//! but both land in one ledger and one export ZIP interchange; this entry therefore remains the correct verifier for
//! Formspec-origin bundles unless a future split introduces a Formspec-only `RecordValidator` with different domain
//! findings. Operational `chain_hash` fields maintained inside `wos-server` projections are a separate diagnostic
//! surface from the Trellis proof chain this crate audits; documentation and APIs must not present them as
//! interchangeable legal-grade proof (TWREF-037).

#![forbid(unsafe_code)]

mod catalog;
mod certificate_html;
mod certificate_resolver;
mod clock_semantics;
mod completion_selection;
mod event_types;
mod findings;
mod policy_closure;
mod records;
mod rescission;
mod signature_encoder;
mod signed_acts;
mod validator;

#[cfg(test)]
mod tests;

pub use certificate_html::{certificate_html_from_export, CertificateHtml};
pub use certificate_resolver::WosFormspecResolver;
#[doc(inline)]
pub use completion_selection::{
    completion_record_bindings, validate_completion_prefix, CompletionRecord,
};
pub use findings::{
    WosDomainReport, WosFinding, WosLayeredVerificationReport, WosRelyingPartyVerdict,
    WosVerificationReport,
};
#[doc(inline)]
pub use signature_encoder::{encode_signature_affirmations_v1, SignatureCatalogError};
pub use signed_acts::{derive_signed_acts_manifest_v1, encode_signed_acts_manifest_v1};
pub use validator::WosRecordValidator;

/// Verifies a Trellis export ZIP using structural Trellis checks plus WOS-domain validation.
///
/// Callers pass raw ZIP bytes as emitted by `trellis-export-writer`. The report bundles structural failures with
/// WOS-specific findings from [`WosRecordValidator`], including Formspec response digest resolution for applicable
/// payloads (TWREF-025). This is the verifier entry for stacks that delegate proof to Trellis: it does not consult
/// `wos-server` operational chain hashes, which track projection convenience rather than independent cryptographic
/// proof (TWREF-037).
#[must_use]
pub fn verify_export_zip(zip: &[u8]) -> WosVerificationReport {
    integrity_verify::trellis::verify_export_zip_with_validator(zip, &WosRecordValidator).into()
}

/// Verifies all existing WOS checks plus externally selected operator authority.
#[must_use]
pub fn verify_export_zip_with_certificate_authorities(
    zip: &[u8],
    authorities: &integrity_verify::trellis::CertificateAuthorityRegistry,
) -> WosVerificationReport {
    integrity_verify::trellis::verify_export_zip_with_validator(
        zip,
        &validator::TrustedWosRecordValidator(authorities),
    )
    .into()
}

/// Loads a closed external public registry. This file must be independently trusted.
///
/// Each row identifies the exact authority URI, public key, class, purpose and
/// inclusive completed_at interval. Keys embedded in the export do not establish trust.
/// # Errors
/// Refuses malformed, duplicate, unknown-purpose or unbounded authority rows.
pub fn certificate_authorities_from_json(
    bytes: &[u8],
) -> Result<integrity_verify::trellis::CertificateAuthorityRegistry, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Row {
        authority: String,
        public_key: [u8; 32],
        authority_class: String,
        allowed_purpose: String,
        valid_from: (u64, u32),
        valid_until: (u64, u32),
    }
    if bytes.len() > 32 * 1024 {
        return Err("certificate authority registry exceeds limit".into());
    }
    let rows: Vec<Row> = serde_json::from_slice(bytes)
        .map_err(|e| format!("invalid certificate authority registry: {e}"))?;
    if rows.len() > 8 {
        return Err("certificate authority registry exceeds row limit".into());
    }
    let mut registry = integrity_verify::trellis::CertificateAuthorityRegistry::new();
    for row in rows {
        if row.authority.trim().is_empty()
            || row.authority.len() > 1024
            || !matches!(row.authority_class.as_str(), "prior" | "new")
            || !matches!(
                row.allowed_purpose.as_str(),
                "trellis.certificate-of-completion.v1" | "trellis.certificate-of-completion.v2"
            )
            || row.valid_from.1 >= 1_000_000_000
            || row.valid_until.1 >= 1_000_000_000
            || row.valid_from >= row.valid_until
        {
            return Err("invalid certificate authority binding".into());
        }
        let value = integrity_verify::trellis::TrustedCertificateAuthority {
            public_key: row.public_key,
            authority_class: row.authority_class,
            allowed_purpose: row.allowed_purpose,
            valid_from: integrity_verify::trellis::TrellisTimestamp {
                seconds: row.valid_from.0,
                nanos: row.valid_from.1,
            },
            valid_until: integrity_verify::trellis::TrellisTimestamp {
                seconds: row.valid_until.0,
                nanos: row.valid_until.1,
            },
        };
        if registry.insert(row.authority, value).is_some() {
            return Err("duplicate certificate authority".into());
        }
    }
    Ok(registry)
}

/// Verifies one WOS event.
///
/// # Errors
/// Returns an error when the signed bytes do not decode as a COSE_Sign1 item.
pub fn verify_single_event(
    public_key: [u8; 32],
    signed_event: &[u8],
) -> Result<WosVerificationReport, integrity_verify::trellis::VerifyError> {
    integrity_verify::trellis::verify_single_event_with_validator(
        public_key,
        signed_event,
        &WosRecordValidator,
    )
    .map(Into::into)
}

/// Verifies a WOS tamper-fixture ledger.
///
/// # Errors
/// Returns an error when the registry bytes cannot be decoded.
pub fn verify_tampered_ledger(
    signing_key_registry: &[u8],
    ledger: &[u8],
    initial_posture_declaration: Option<&[u8]>,
    posture_declaration: Option<&[u8]>,
) -> Result<WosVerificationReport, integrity_verify::trellis::VerifyError> {
    integrity_verify::trellis::verify_tampered_ledger_with_validator(
        signing_key_registry,
        ledger,
        initial_posture_declaration,
        posture_declaration,
        &WosRecordValidator,
    )
    .map(Into::into)
}
