// Rust guideline compliant 2026-02-21
//! Port for the domain export profile the generic server publishes through.
//!
//! `trellis-export-writer` binds opaque member bytes and stays substrate-only.
//! A profile adapter (for example `trellis-export-profile-wos`) derives the
//! verifier-facing members from the closed event snapshot and judges the
//! finished bundle; the composition root installs it.

use stack_common_error::StackError;
use trellis_export_writer::{
    ExportEvidenceMember, PolicyClosureMember, SignedActsCatalogMember, SignedActsManifestMember,
    TrellisTimestamp,
};
use trellis_types::StoredEvent;

/// Optional export-profile members supplied to `trellis-export-writer`.
#[derive(Debug, Default)]
pub struct ExportProfileMembers {
    pub signed_acts_catalog: Option<SignedActsCatalogMember>,
    pub signed_acts_manifest: Option<SignedActsManifestMember>,
    pub policy_closure: Option<PolicyClosureMember>,
}

impl ExportProfileMembers {
    /// Returns true when domain verification must run before publication.
    #[must_use]
    pub fn requires_profile_validation(&self) -> bool {
        self.signed_acts_catalog.is_some()
            || self.signed_acts_manifest.is_some()
            || self.policy_closure.is_some()
    }
}

/// Consumer-owned signing facts resolved from one actual signature event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningFact {
    pub principal: String,
    pub response_hash: [u8; 32],
    pub authored_at: TrellisTimestamp,
}

/// Domain export profile: member derivation, bundle verification and signing facts.
pub trait ExportProfile: Send + Sync {
    /// Derives evidence members from actual admitted events (empty when none apply).
    ///
    /// # Errors
    /// Refuses unreadable events and finite aggregate limits.
    fn evidence_members(
        &self,
        scope: &[u8],
        events: &[&StoredEvent],
    ) -> Result<Vec<ExportEvidenceMember>, StackError>;

    /// Derives optional profile members for a closed event snapshot.
    ///
    /// # Errors
    /// Returns an error if a source event is unreadable or malformed.
    fn profile_members(
        &self,
        scope: &[u8],
        events: &[StoredEvent],
        generated_at: TrellisTimestamp,
    ) -> Result<ExportProfileMembers, StackError>;

    /// True when the export ZIP passes independent substrate verification.
    fn substrate_verified(&self, zip: &[u8]) -> bool;

    /// True when a profile-bearing export passes domain verification.
    fn profile_verified(&self, zip: &[u8]) -> bool;

    /// Resolves signing facts for the selected signature events.
    ///
    /// # Errors
    /// Refuses unreadable or unqualified signing evidence.
    fn signing_facts(
        &self,
        events: &[StoredEvent],
        selected: &[[u8; 32]],
    ) -> Result<Vec<SigningFact>, StackError>;
}
