// Rust guideline compliant 2026-02-21
//! Port for the domain's native closeout records.
//!
//! The generic server selects Source content around a closeout record without
//! naming the producer that defines it. A domain adapter (for example
//! `trellis-admission-wos`) decodes and validates the record; the composition
//! root installs it.

use stack_common_error::StackError;
use trellis_service_client::SubstrateAppendBody;
use trellis_service_client::source_content::SourceContentIdentityV1;
use trellis_types::StoredEvent;

/// Domain adapter for native closeout records.
pub trait NativeCloseout: Send + Sync + std::fmt::Debug {
    /// Validates the record kind named by a closeout rule.
    ///
    /// # Errors
    /// Refuses a kind the domain does not define.
    fn validate_rule_kind(&self, kind: &str) -> Result<(), StackError>;

    /// Native record carried by a pending append, or `None` for any other event type.
    ///
    /// # Errors
    /// Refuses a native payload that does not decode.
    fn record_from_append(
        &self,
        body: &SubstrateAppendBody,
    ) -> Result<Option<serde_json::Value>, StackError>;

    /// Native record carried by a stored event, or `None` for any other event type.
    ///
    /// # Errors
    /// Refuses a native payload that does not decode.
    fn record_from_stored(
        &self,
        event: &StoredEvent,
    ) -> Result<Option<serde_json::Value>, StackError>;

    /// Checks a pending closeout append against the selected reserved identity.
    ///
    /// # Errors
    /// Refuses a malformed payload or any identity change.
    fn validate_append(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError>;

    /// Checks a stored closeout event against the selected reserved identity.
    ///
    /// # Errors
    /// Refuses a malformed payload or any identity change.
    fn validate_stored(
        &self,
        event: &StoredEvent,
        selected: &SourceContentIdentityV1,
    ) -> Result<(), StackError>;
}
