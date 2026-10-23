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
mod event_types;
mod findings;
mod native_provenance;
mod policy_closure;
mod records;
#[doc(inline)]
pub use records::ProtectedResponseOpeningV1;
mod rescission;
mod signature_encoder;
mod signed_acts;
mod source_formal;
mod source_original;
pub mod source_proof_package;
mod source_signed_task;
pub mod pin_semantics;
pub use pin_semantics::*;
mod validator;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod source_publication_tests;

pub use certificate_html::{CertificateHtml, certificate_html_from_export};
pub use certificate_resolver::WosFormspecResolver;
pub use findings::{
    WosDomainReport, WosFinding, WosLayeredVerificationReport, WosRelyingPartyVerdict,
    WosVerificationReport,
};
#[doc(inline)]
pub use signature_encoder::{
    SignatureCatalogError, encode_signature_affirmations_v1, signature_catalog_row,
};
pub use signed_acts::{derive_signed_acts_manifest_v1, encode_signed_acts_manifest_v1};
#[doc(inline)]
pub use source_proof_package::{
    OriginalContextProofV1, ProtectedSourceProofPackageLocatorV1,
    ProtectedSourceProofPackageOpeningV1,
};
#[doc(inline)]
pub use source_signed_task::{
    NativeSigningObligation, SourceSignedCompletedTaskFieldsV1, SourceSignedCompletedTaskV1,
    SourceTaskContentProfileV1, SourceTaskContentVerifier, SourceTaskFamily,
    SourceTaskNativeBindings, SourceTaskProofDescriptorV1, SourceTaskRequirementV1,
    SourceTaskResponsePinsV1, VerifiedSourceTaskContent, encode_source_signed_task_catalog,
    source_signed_tasks_from_catalog,
};
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

/// Reports protected-content publication admission, never final Source readiness.
///
/// This phase retains substrate and WOS structural findings. It does not open
/// protected records or verify their Source signatures. An independently selected
/// Source-content publication path must separately admit its complete census and
/// provider pins, and final readers must use the full owning Source verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceContentPublicationReport {
    report: WosVerificationReport,
}

impl SourceContentPublicationReport {
    /// Returns whether all publication-phase obligations passed.
    #[must_use]
    pub fn publication_admitted(&self) -> bool {
        self.report.relying_party_valid()
    }

    /// Returns all substrate findings and verification details unchanged.
    #[must_use]
    pub fn substrate(&self) -> &integrity_verify::trellis::VerificationReport {
        &self.report.trellis
    }

    /// Returns every WOS publication-phase finding without filtering.
    #[must_use]
    pub fn findings(&self) -> &[WosFinding] {
        &self.report.wos_findings
    }

    /// Returns the verifier's blocking reasons plus each domain finding's kind and
    /// message; empty when admitted.
    #[must_use]
    pub fn blocking_reasons(&self) -> Vec<String> {
        let mut reasons = self.report.verdict().blocking_reasons;
        reasons.extend(
            self.report
                .wos_findings
                .iter()
                .map(|finding| format!("{}: {}", finding.kind, finding.message)),
        );
        reasons
    }
}

/// Checks publication structure before independent protected Source verification.
///
/// Select only for an explicitly admitted Source-content publication. Default and
/// full Source verifiers remain unchanged. Existing formal certificate checks,
/// operator authority, native joins, catalogs, clocks and policy checks still run.
#[must_use]
pub fn verify_source_content_publication(
    zip: &[u8],
    authorities: Option<&integrity_verify::trellis::CertificateAuthorityRegistry>,
) -> SourceContentPublicationReport {
    SourceContentPublicationReport {
        report: integrity_verify::trellis::verify_export_zip_with_validator(
            zip,
            &validator::SourceContentPublicationValidator { authorities },
        )
        .into(),
    }
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

/// Verifies selected Source task content without relaxing existing formal certificate checks.
///
/// The profile and proof adapter must be admitted independently of the archive.
/// No Source family or missing certificate selects ordinary native obligations.
#[must_use]
pub fn verify_export_zip_with_source_task_content<V: SourceTaskContentVerifier>(
    zip: &[u8],
    profile: &SourceTaskContentProfileV1,
    verifier: &V,
    authorities: Option<&integrity_verify::trellis::CertificateAuthorityRegistry>,
) -> WosVerificationReport {
    let report = integrity_verify::trellis::verify_export_zip_with_validator(
        zip,
        &validator::SourceContentWosRecordValidator {
            profile,
            verifier,
            authorities,
            archive_sha256: trellis_types::sha256_bytes(zip),
        },
    )
    .into();
    require_selected_formal_certificate(report, profile, zip)
}

#[doc(inline)]
pub use source_original::{
    ProtectedIntakeResponseV1, SourceIntakeContentVerifier, SourceIntakeNativeBindings,
    SourceIntakeRequirementV1, VerifiedSourceIntakeContent,
    protected_intake_responses_from_catalog,
};

/// Verifies all selected original/task content with independent owning proof adapters.
///
/// Missing proofs or selected formal requirements remain failures; no findings are filtered.
#[must_use]
pub fn verify_export_zip_with_source_content<
    T: SourceTaskContentVerifier,
    I: SourceIntakeContentVerifier,
>(
    zip: &[u8],
    profile: &SourceTaskContentProfileV1,
    tasks: &T,
    intakes: &I,
    authorities: Option<&integrity_verify::trellis::CertificateAuthorityRegistry>,
) -> WosVerificationReport {
    let report = integrity_verify::trellis::verify_export_zip_with_validator(
        zip,
        &validator::CompleteSourceWosRecordValidator {
            profile,
            tasks,
            intakes,
            authorities,
            archive_sha256: trellis_types::sha256_bytes(zip),
        },
    )
    .into();
    require_selected_formal_certificate(report, profile, zip)
}

fn require_selected_formal_certificate(
    mut report: WosVerificationReport,
    profile: &SourceTaskContentProfileV1,
    zip: &[u8],
) -> WosVerificationReport {
    for requirement in &profile.required_tasks {
        let NativeSigningObligation::SourceContentAndFormalKernel {
            affirmation_event_hashes,
        } = &requirement.obligation
        else {
            continue;
        };
        if !source_formal::selected_certificate_covers(
            zip,
            &report.trellis.certificates_of_completion,
            affirmation_event_hashes,
        ) {
            report.wos_findings.push(integrity_verify::trellis::DomainFinding::new(
                "source_task_formal_certificate_required",Some(requirement.task_completed_event_hash),integrity_verify::trellis::Severity::Failure,
                "Selected native formal obligation requires a trusted certificate covering its actual signing events"));
        }
    }
    report
}
