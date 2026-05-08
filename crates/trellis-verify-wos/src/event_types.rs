// Rust guideline compliant 2026-02-21
//! WOS event and export extension identifiers.

#![forbid(unsafe_code)]

pub(crate) const SIGNATURE_EXPORT_EXTENSION: &str = "trellis.export.signature-affirmations.v1";
pub(crate) const INTAKE_EXPORT_EXTENSION: &str = "trellis.export.intake-handoffs.v1";
pub(crate) const OPEN_CLOCKS_EXPORT_EXTENSION: &str = "trellis.export.open-clocks.v1";

pub(crate) const WOS_SIGNATURE_AFFIRMATION_EVENT_TYPE: &str = "wos.kernel.signatureAffirmation";
pub(crate) const WOS_INTAKE_ACCEPTED_EVENT_TYPE: &str = "wos.kernel.intakeAccepted";
pub(crate) const WOS_CASE_CREATED_EVENT_TYPE: &str = "wos.kernel.caseCreated";
pub(crate) const WOS_IDENTITY_ATTESTATION_EVENT_TYPE: &str = "wos.identity.identityAttestation";
pub(crate) const WOS_GOVERNANCE_DETERMINATION_PREFIX: &str = "wos.governance.determination";
pub(crate) const WOS_GOVERNANCE_DETERMINATION_RESCINDED_EVENT_TYPE: &str =
    "wos.governance.determinationRescinded";
pub(crate) const WOS_GOVERNANCE_REINSTATED_EVENT_TYPE: &str = "wos.governance.reinstated";
