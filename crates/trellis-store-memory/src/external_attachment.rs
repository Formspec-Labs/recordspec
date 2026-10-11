// Rust guideline compliant 2026-02-21
//! Atomic in-memory adapter for retained native external attachments.
use trellis_core::external_attachment::{ExternalAttachmentStore, RetainedExternalAttachment};
use trellis_types::{StoredEvent, Value, decode_cbor_value, map_lookup_optional_value};

/// Stores exact signed events and protection outputs together for local composition.
#[derive(Debug, Default)]
pub struct MemoryExternalAttachments {
    attachments: Vec<RetainedExternalAttachment>,
}
/// Refuses conflicting operations or a stale append position.
#[derive(Debug)]
pub struct ExternalAttachmentConflict;
impl std::fmt::Display for ExternalAttachmentConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("external attachment commit conflict")
    }
}
impl std::error::Error for ExternalAttachmentConflict {}
impl MemoryExternalAttachments {
    /// Returns the exact retained records.
    pub fn attachments(&self) -> &[RetainedExternalAttachment] {
        &self.attachments
    }
}
impl ExternalAttachmentStore for MemoryExternalAttachments {
    type Error = ExternalAttachmentConflict;
    fn scope_events(&self, scope: &[u8]) -> Result<Vec<StoredEvent>, Self::Error> {
        Ok(self
            .attachments
            .iter()
            .filter(|a| a.event().scope() == scope)
            .map(|a| a.event().clone())
            .collect())
    }
    fn retained(
        &self,
        scope: &[u8],
        key: &[u8],
    ) -> Result<Option<RetainedExternalAttachment>, Self::Error> {
        Ok(self
            .attachments
            .iter()
            .find(|a| a.event().scope() == scope && a.event().idempotency_key() == Some(key))
            .cloned())
    }
    fn commit(&mut self, next: RetainedExternalAttachment) -> Result<(), Self::Error> {
        if self
            .retained(
                next.event().scope(),
                next.event()
                    .idempotency_key()
                    .ok_or(ExternalAttachmentConflict)?,
            )?
            .is_some()
        {
            return Err(ExternalAttachmentConflict);
        }
        let profile =
            trellis_cddl::parse_external_attachment_profile(next.event().canonical_event())
                .map_err(|_| ExternalAttachmentConflict)?
                .ok_or(ExternalAttachmentConflict)?;
        let hash = trellis_types::domain_separated_sha256(
            trellis_types::EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(
                next.event().scope(),
                next.event().canonical_event(),
            ),
        );
        if next.event().canonical_event_hash() != Some(&hash)
            || profile.idempotency_key.as_slice()
                != next
                    .event()
                    .idempotency_key()
                    .ok_or(ExternalAttachmentConflict)?
            || profile.content_hash
                != trellis_types::domain_separated_sha256(
                    trellis_types::CONTENT_DOMAIN,
                    next.ciphertext(),
                )
        {
            return Err(ExternalAttachmentConflict);
        }
        for old in &self.attachments {
            if old.event().scope() == next.event().scope() {
                let prior =
                    trellis_cddl::parse_external_attachment_profile(old.event().canonical_event())
                        .map_err(|_| ExternalAttachmentConflict)?
                        .ok_or(ExternalAttachmentConflict)?;
                if profile.key_bag_entries.iter().any(|n| {
                    prior
                        .key_bag_entries
                        .iter()
                        .any(|p| n.ephemeral_pubkey == p.ephemeral_pubkey)
                }) {
                    return Err(ExternalAttachmentConflict);
                }
            }
        }
        let prefix = self.scope_events(next.event().scope())?;
        if next.event().sequence() != prefix.len() as u64 {
            return Err(ExternalAttachmentConflict);
        }
        let value = decode_cbor_value(next.event().canonical_event())
            .map_err(|_| ExternalAttachmentConflict)?;
        let fields = value.as_map().ok_or(ExternalAttachmentConflict)?;
        let expected = match prefix.last() {
            None => Value::Null,
            Some(event) => Value::Bytes(
                event
                    .canonical_event_hash()
                    .ok_or(ExternalAttachmentConflict)?
                    .to_vec(),
            ),
        };
        if map_lookup_optional_value(fields, "prev_hash") != Some(&expected) {
            return Err(ExternalAttachmentConflict);
        }
        self.attachments.push(next);
        Ok(())
    }
}
