// Rust guideline compliant 2026-02-21
//! WOS event and export extension identifiers.
//!
//! Canonical `wos.*` event-type strings resolve through [`wos_events::ProvenanceKind`]
//! so `trellis-verify-wos` cannot drift from [`wos_events::SUBSTRATE_CANONICAL_EVENT_LITERALS`].

#![forbid(unsafe_code)]

use wos_events::ProvenanceKind;
pub(crate) const SIGNATURE_EXPORT_EXTENSION: &str = "trellis.export.signature-affirmations.v1";
pub(crate) const INTAKE_EXPORT_EXTENSION: &str = "trellis.export.intake-handoffs.v1";
pub(crate) const OPEN_CLOCKS_EXPORT_EXTENSION: &str = "trellis.export.open-clocks.v1";

macro_rules! substrate_canonical_event {
    ($fn_name:ident, $kind:ident) => {
        #[inline]
        pub(crate) fn $fn_name() -> &'static str {
            ProvenanceKind::$kind
                .canonical_event_literal()
                .expect(concat!(
                    stringify!($kind),
                    " must carry a substrate canonical event literal"
                ))
        }
    };
}

substrate_canonical_event!(wos_signature_affirmation_event_type, SignatureAffirmation);
substrate_canonical_event!(wos_intake_accepted_event_type, IntakeAccepted);
substrate_canonical_event!(wos_case_created_event_type, CaseCreated);
substrate_canonical_event!(wos_identity_attestation_event_type, IdentityAttestation);
substrate_canonical_event!(
    wos_governance_determination_rescinded_event_type,
    DeterminationRescinded
);
substrate_canonical_event!(wos_governance_reinstated_event_type, Reinstated);
substrate_canonical_event!(wos_governance_clock_started_event_type, ClockStarted);
substrate_canonical_event!(wos_governance_clock_resolved_event_type, ClockResolved);

/// Provenance kinds whose canonical literals `trellis-verify-wos` dereferences on hot paths.
#[cfg(test)]
#[inline]
pub(crate) fn verify_wos_tracked_substrate_kinds() -> &'static [ProvenanceKind] {
    &[
        ProvenanceKind::SignatureAffirmation,
        ProvenanceKind::IntakeAccepted,
        ProvenanceKind::CaseCreated,
        ProvenanceKind::IdentityAttestation,
        ProvenanceKind::DeterminationRescinded,
        ProvenanceKind::Reinstated,
        ProvenanceKind::ClockStarted,
        ProvenanceKind::ClockResolved,
    ]
}
