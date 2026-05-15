// Rust guideline compliant 2026-02-21
//! WOS rescission terminality checks.

#![forbid(unsafe_code)]

use integrity_verify::trellis::{DomainEvent, DomainFinding, Severity};
use wos_events::GOVERNANCE_DETERMINATION_WIRE_EVENT_PREFIX;

use crate::event_types::{
    wos_governance_determination_rescinded_event_type, wos_governance_reinstated_event_type,
};

pub(crate) fn validate_rescission_terminality(events: &[DomainEvent]) -> Vec<DomainFinding> {
    let mut terminal = false;
    let mut findings = Vec::new();
    for event in events {
        if event.event_type == wos_governance_determination_rescinded_event_type() {
            terminal = true;
        } else if event.event_type == wos_governance_reinstated_event_type() {
            terminal = false;
        } else if terminal
            && event
                .event_type
                .starts_with(GOVERNANCE_DETERMINATION_WIRE_EVENT_PREFIX)
        {
            findings.push(DomainFinding::new(
                "rescission_terminality_violation",
                Some(event.canonical_event_hash),
                Severity::Failure,
                "determination event appears after rescission without reinstatement",
            ));
        }
    }
    findings
}
