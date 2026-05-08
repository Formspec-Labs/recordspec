// Rust guideline compliant 2026-02-21
//! WOS record-validator implementation.

#![forbid(unsafe_code)]

use trellis_verify::{DomainEvent, DomainExport, DomainFinding, RecordValidator};

/// WOS domain validator.
#[derive(Clone, Copy, Debug, Default)]
pub struct WosRecordValidator;

impl RecordValidator for WosRecordValidator {
    fn admits_identity_attestation_event_type(&self, event_type: &str) -> bool {
        event_type == crate::event_types::WOS_IDENTITY_ATTESTATION_EVENT_TYPE
    }

    fn validate_events(&self, events: &[DomainEvent]) -> Vec<DomainFinding> {
        let mut findings = crate::rescission::validate_rescission_terminality(events);
        findings.extend(crate::clock_semantics::validate_clock_semantics(events));
        findings
    }

    fn validate_export(&self, export: DomainExport<'_>) -> Vec<DomainFinding> {
        let mut findings = crate::catalog::validate_catalogs(&export);
        findings.extend(crate::clock_semantics::validate_open_clock_export(&export));
        findings
    }
}
