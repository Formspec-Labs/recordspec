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

/// Consumer-owned signing facts resolved from one actual signature event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningFact {
    pub principal: String,
    pub response_hash: [u8; 32],
    pub authored_at: TrellisTimestamp,
}

/// Domain export profile: member derivation, the append-time fold and signing facts.
pub trait ExportProfile: Send + Sync {
    /// Folds one appended event into the profile's running state for its scope.
    ///
    /// The state is opaque to the server: it stores the returned bytes with the event's
    /// checkpoint and hands them back, unread, to the next append. Folding event `n` into the state
    /// of events `0..n` MUST accept exactly when [`Self::evidence_members`] accepts events `0..=n`,
    /// and cost the same whatever `n` is. That equivalence is what lets an append check the
    /// profile's finite export limits without reading the prefix.
    ///
    /// `prior` is `None` for the first event of a scope; `tree_size` counts the events including
    /// this one.
    ///
    /// # Errors
    /// Refuses an unreadable event, a corrupt `prior`, or a prefix that would exceed the profile's
    /// finite limits.
    fn fold_append(
        &self,
        scope: &[u8],
        prior: Option<&[u8]>,
        event: &StoredEvent,
        tree_size: u64,
    ) -> Result<Vec<u8>, StackError>;

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
