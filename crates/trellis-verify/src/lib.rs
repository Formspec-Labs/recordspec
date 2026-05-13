// Rust guideline compliant 2026-02-21
//! Compatibility facade for the Trellis verifier.
//!
//! UWU-3 moved the implementation into `integrity-verify` so the universal
//! verifier owns the active envelope, chain, bundle, and report projection
//! path. This crate remains as the Trellis workspace compatibility surface.

#![forbid(unsafe_code)]

pub use integrity_verify::trellis::certificate_proof;
pub use integrity_verify::trellis::validator;
pub use integrity_verify::trellis::{
    DomainEvent, DomainExport, DomainFinding, RecordValidator, Severity, TrellisTimestamp,
    VerificationFailure, VerificationFailureKind, VerificationReport, VerificationWithDomain,
    VerifyError, VerifyErrorKind, certificate_proof::CertificateResponseProof,
    certificate_proof::ResolverError, certificate_proof::ResponseProofResolver, verify_export_zip,
    verify_export_zip_with_validator, verify_single_event, verify_single_event_with_validator,
    verify_tampered_ledger, verify_tampered_ledger_with_validator,
};
pub use integrity_verify::{
    BundleEntryView as UniversalBundleEntryView, BundleStructuralCheck as UniversalBundleCheck,
    CanonicalCheck as UniversalCanonicalCheck,
    CanonicalDigestCheck as UniversalCanonicalDigestCheck, ChainContinuityCheck,
    ChainEventView as UniversalChainEventView, CoseEnvelopeCheck, ProfileRegistry,
    ProfileVerificationResult, ProfileVerifier, UniversalFailureKind,
    VerificationReport as UniversalVerificationReport, VerifyBundleInput as UniversalVerifyInput,
    VerifyEvent as UniversalVerifyEvent, verify_universal,
};
