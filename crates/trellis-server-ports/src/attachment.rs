//! Neutral port for owner-prepared protected attachments.
//!
//! The generic server retains and exports native external attachments without
//! naming the producer that defines the descriptor. A domain adapter (for
//! example `trellis-admission-formspec`) implements [`ExternalAttachmentAdmission`]
//! and the composition root installs it.

use stack_common_error::StackError;
use trellis_types::StoredEvent;

/// Deployment-selected finite input bounds for binding an attachment.
#[derive(Clone, Copy, Debug)]
pub struct AttachmentLimits {
    pub original_bytes: usize,
    pub ciphertext_bytes: usize,
    pub prior_events: usize,
    pub prior_event_bytes: usize,
}

/// A validated descriptor and the facts the transport checks against the original bytes.
#[derive(Clone, Debug)]
pub struct AdmittedDescriptor {
    /// JSON the authorizer, recipient selector and replay identity see.
    pub payload: serde_json::Value,
    /// Declared length of the unchanged original bytes.
    pub byte_length: u64,
    /// Declared `sha256:`-prefixed digest of the unchanged original bytes.
    pub attachment_sha256: String,
}

/// What the owner's binding contributes to one native attachment append.
#[derive(Clone, Debug)]
pub struct AttachmentBinding {
    /// Canonical CBOR of the outer event extensions.
    pub extensions_cbor: Vec<u8>,
    /// Preparation identity for full-descriptor replay comparison.
    pub replay_digest: [u8; 32],
    /// Validated head of the preparation prefix.
    pub expected_head: Option<[u8; 32]>,
}

/// Domain adapter for one protected-attachment event type.
pub trait ExternalAttachmentAdmission: Send + Sync {
    /// Event type signed for this attachment family.
    fn event_type(&self) -> &'static str;

    /// Strictly decodes and validates a bounded closed descriptor.
    ///
    /// # Errors
    /// Refuses unknown or duplicate fields, malformed identity or excessive metadata.
    fn admit(&self, descriptor_json: &str) -> Result<AdmittedDescriptor, StackError>;

    /// Binds an admitted payload to actual original bytes, ciphertext and prior prefix.
    ///
    /// # Errors
    /// Refuses changed bytes, excessive inputs, foreign prefixes and stale replacements.
    fn bind(
        &self,
        payload: &serde_json::Value,
        scope: &[u8],
        original: &[u8],
        ciphertext: &[u8],
        prior: &[StoredEvent],
        limits: AttachmentLimits,
    ) -> Result<AttachmentBinding, StackError>;
}
