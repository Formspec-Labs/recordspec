// Rust guideline compliant 2026-02-21
//! Port for the domain's native closeout records.
//!
//! The generic server selects Source content around a closeout record without
//! naming the producer that defines it or reading its fields. A domain adapter
//! (for example `trellis-admission-wos`) owns the pinned rule document, decodes
//! the record and validates it; the composition root installs it.

use stack_common_error::StackError;
use trellis_service_client::SubstrateAppendBody;
use trellis_service_client::source_content::SourceContentIdentityV1;
use trellis_types::StoredEvent;

/// Where a closeout candidate comes from.
#[derive(Clone, Copy, Debug)]
pub enum CloseoutSource<'a> {
    /// A pending append request.
    Append(&'a SubstrateAppendBody),
    /// An event already in the ledger.
    Stored(&'a StoredEvent),
}

/// Domain adapter for native closeout records.
pub trait NativeCloseout: Send + Sync + std::fmt::Debug {
    /// Validates the owner's pinned closeout rule document, which is opaque to the server.
    ///
    /// # Errors
    /// Refuses a malformed rule or one naming a record kind the domain does not define.
    fn validate_rule(&self, rule: &serde_json::Value) -> Result<(), StackError>;

    /// Reserved record id when `source` carries a native record matching `rule`, else `None`.
    ///
    /// # Errors
    /// Refuses a native payload that does not decode or a matching record without an id.
    fn matching_record_id(
        &self,
        rule: &serde_json::Value,
        source: CloseoutSource<'_>,
    ) -> Result<Option<String>, StackError>;

    /// Checks the closeout against the selected reserved identity.
    ///
    /// # Errors
    /// Refuses a malformed payload or any identity change.
    fn validate(
        &self,
        source: CloseoutSource<'_>,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError>;
}
