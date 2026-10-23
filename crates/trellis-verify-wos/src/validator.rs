// Rust guideline compliant 2026-02-21
//! WOS record-validator implementation.

#![forbid(unsafe_code)]

use integrity_verify::trellis::certificate_proof::ResponseProofResolver;
use integrity_verify::trellis::{DomainEvent, DomainExport, DomainFinding, RecordValidator};

use crate::certificate_resolver::WosFormspecResolver;

/// WOS domain validator.
#[derive(Clone, Copy, Debug, Default)]
pub struct WosRecordValidator;

const WOS_FORMSPEC_RESOLVER: WosFormspecResolver = WosFormspecResolver::new();

impl RecordValidator for WosRecordValidator {
    fn admits_identity_attestation_event_type(&self, event_type: &str) -> bool {
        event_type == crate::event_types::wos_identity_attestation_event_type()
    }

    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        let mut findings = crate::rescission::validate_rescission_terminality(events);
        findings.extend(crate::clock_semantics::validate_clock_semantics(events));
        findings.extend(crate::native_provenance::validate_native_provenance(events));
        findings.extend(crate::pin_semantics::validate_pin_semantics(events));
        findings
    }

    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        let mut findings = crate::catalog::validate_catalogs(&export);
        findings.extend(crate::clock_semantics::validate_open_clock_export(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_projection(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_manifest_extension(
            &export,
        ));
        findings.extend(crate::policy_closure::validate_policy_closure(&export));
        findings
    }

    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        &WOS_FORMSPEC_RESOLVER
    }
}

/// WOS checks with an explicitly selected external operator trust registry.
pub(crate) struct TrustedWosRecordValidator<'a>(
    pub(crate) &'a integrity_verify::trellis::CertificateAuthorityRegistry,
);

/// Publication checks; final Source opening and cryptography remain separate.
pub(crate) struct SourceContentPublicationValidator<'a> {
    pub(crate) authorities: Option<&'a integrity_verify::trellis::CertificateAuthorityRegistry>,
}

impl RecordValidator for SourceContentPublicationValidator<'_> {
    fn certificate_authority_registry(
        &self,
    ) -> Option<&integrity_verify::trellis::CertificateAuthorityRegistry> {
        self.authorities
    }

    fn admits_identity_attestation_event_type(&self, event_type: &str) -> bool {
        WosRecordValidator.admits_identity_attestation_event_type(event_type)
    }

    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        WosRecordValidator.validate_events(events)
    }

    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        let mut findings = crate::catalog::validate_source_content_publication_catalogs(&export);
        findings.extend(crate::clock_semantics::validate_open_clock_export(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_projection(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_manifest_extension(
            &export,
        ));
        findings.extend(crate::policy_closure::validate_policy_closure(&export));
        findings
    }

    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        WosRecordValidator.response_proof_resolver()
    }
}
impl RecordValidator for TrustedWosRecordValidator<'_> {
    fn certificate_authority_registry(
        &self,
    ) -> Option<&integrity_verify::trellis::CertificateAuthorityRegistry> {
        Some(self.0)
    }
    fn admits_identity_attestation_event_type(&self, event_type: &str) -> bool {
        WosRecordValidator.admits_identity_attestation_event_type(event_type)
    }
    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        WosRecordValidator.validate_events(events)
    }
    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        WosRecordValidator.validate_export(export)
    }
    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        WosRecordValidator.response_proof_resolver()
    }
}

pub(crate) struct SourceContentWosRecordValidator<'a, V> {
    pub(crate) profile: &'a crate::SourceTaskContentProfileV1,
    pub(crate) verifier: &'a V,
    pub(crate) authorities: Option<&'a integrity_verify::trellis::CertificateAuthorityRegistry>,
    pub(crate) archive_sha256: [u8; 32],
}
impl<V: crate::SourceTaskContentVerifier> RecordValidator
    for SourceContentWosRecordValidator<'_, V>
{
    fn certificate_authority_registry(
        &self,
    ) -> Option<&integrity_verify::trellis::CertificateAuthorityRegistry> {
        self.authorities
    }
    fn admits_identity_attestation_event_type(&self, event_type: &str) -> bool {
        WosRecordValidator.admits_identity_attestation_event_type(event_type)
    }
    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        WosRecordValidator.validate_events(events)
    }
    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        let mut findings = crate::catalog::validate_catalogs_with_source_content(
            &export,
            self.archive_sha256,
            self.profile,
            self.verifier,
        );
        findings.extend(crate::clock_semantics::validate_open_clock_export(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_projection(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_manifest_extension(
            &export,
        ));
        findings.extend(crate::policy_closure::validate_policy_closure(&export));
        findings
    }
    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        WosRecordValidator.response_proof_resolver()
    }
}

pub(crate) struct CompleteSourceWosRecordValidator<'a, T, I> {
    pub(crate) profile: &'a crate::SourceTaskContentProfileV1,
    pub(crate) tasks: &'a T,
    pub(crate) intakes: &'a I,
    pub(crate) authorities: Option<&'a integrity_verify::trellis::CertificateAuthorityRegistry>,
    pub(crate) archive_sha256: [u8; 32],
}
impl<T: crate::SourceTaskContentVerifier, I: crate::SourceIntakeContentVerifier> RecordValidator
    for CompleteSourceWosRecordValidator<'_, T, I>
{
    fn certificate_authority_registry(
        &self,
    ) -> Option<&integrity_verify::trellis::CertificateAuthorityRegistry> {
        self.authorities
    }
    fn admits_identity_attestation_event_type(&self, t: &str) -> bool {
        WosRecordValidator.admits_identity_attestation_event_type(t)
    }
    fn validate_events(&self, e: &[DomainEvent]) -> Vec<DomainFinding> {
        WosRecordValidator.validate_events(e)
    }
    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        let mut findings = crate::catalog::validate_catalogs_with_all_source_content(
            &export,
            self.archive_sha256,
            self.profile,
            self.tasks,
            self.intakes,
        );
        findings.extend(crate::clock_semantics::validate_open_clock_export(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_projection(&export));
        findings.extend(crate::signed_acts::validate_signed_acts_manifest_extension(
            &export,
        ));
        findings.extend(crate::policy_closure::validate_policy_closure(&export));
        findings
    }
    fn response_proof_resolver(&self) -> &dyn ResponseProofResolver {
        WosRecordValidator.response_proof_resolver()
    }
}
