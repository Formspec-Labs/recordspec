//! Neutral port for owner-prepared protected attachments.
//!
//! The generic server retains and exports native external attachments without
//! naming the producer that defines the descriptor. A domain adapter (for
//! example `trellis-admission-formspec`) implements these traits and the
//! composition root installs it.

use std::any::Any;

use stack_common_error::StackError;
use trellis_types::StoredEvent;

/// Deployment-selected finite input bounds for preparing an attachment binding.
#[derive(Clone, Copy, Debug)]
pub struct AttachmentLimits {
    pub original_bytes: usize,
    pub ciphertext_bytes: usize,
    pub prior_events: usize,
    pub prior_event_bytes: usize,
}

/// Domain adapter that admits a wire descriptor for one protected-attachment event type.
pub trait ExternalAttachmentAdmission: Send + Sync {
    /// Event type signed for this attachment family.
    fn event_type(&self) -> &'static str;

    /// Strictly decodes and validates a bounded closed descriptor.
    ///
    /// # Errors
    /// Refuses unknown or duplicate fields, malformed identity or excessive metadata.
    fn admit(&self, descriptor_json: &str) -> Result<Box<dyn AdmittedAttachment>, StackError>;
}

/// A validated descriptor, before any protected bytes are bound to it.
pub trait AdmittedAttachment: Send + Sync {
    /// JSON payload the authorizer and replay identity see for this descriptor.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be encoded.
    fn payload(&self) -> Result<serde_json::Value, StackError>;

    /// Declared length of the unchanged original bytes.
    fn byte_length(&self) -> u64;

    /// Declared `sha256:`-prefixed digest of the unchanged original bytes.
    fn attachment_sha256(&self) -> &str;

    /// Binds the descriptor to actual original bytes, ciphertext and prior ledger prefix.
    ///
    /// # Errors
    /// Refuses changed bytes, excessive inputs, foreign prefixes and stale replacements.
    fn prepare<'a>(
        &self,
        scope: &[u8],
        original: &[u8],
        ciphertext: &'a [u8],
        prior: &[StoredEvent],
        limits: AttachmentLimits,
    ) -> Result<Box<dyn PreparedAttachment + 'a>, StackError>;

    /// Lets the adapter's own selectors recover the concrete descriptor.
    fn as_any(&self) -> &dyn Any;
}

/// Validated binding and exact borrowed ciphertext, ready for native append.
pub trait PreparedAttachment {
    /// Event type the prepared binding is signed under.
    fn event_type(&self) -> &str;

    /// JSON payload matching [`AdmittedAttachment::payload`].
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be encoded.
    fn payload(&self) -> Result<serde_json::Value, StackError>;

    /// Ledger scope the binding was prepared against.
    fn scope(&self) -> &[u8];

    /// Validated head of the preparation prefix.
    fn expected_head(&self) -> Option<[u8; 32]>;

    /// Preparation identity for full-descriptor replay comparison.
    fn replay_digest(&self) -> [u8; 32];

    /// Exact protected bytes, without another payload copy.
    fn ciphertext(&self) -> &[u8];

    /// Canonical CBOR of the outer event extensions this binding contributes.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    fn extensions_cbor(&self) -> Result<Vec<u8>, StackError>;
}
