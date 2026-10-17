// Rust guideline compliant 2026-02-21
//! Async Postgres plumber for Trellis stored events.
//!
//! This crate does not construct Trellis ledger bytes. Callers pass
//! [`trellis_types::StoredEvent`] values whose canonical bytes were already
//! produced by `trellis-core`, and this crate writes those bytes through
//! `sqlx` transactions.

#![forbid(unsafe_code)]

mod attachments;
mod ledger;
mod migrations;
mod pool;

#[doc(inline)]
pub use attachments::{
    AttachmentRow, attachment_by_content_hash, attachment_by_key, insert_attachment,
};
#[doc(inline)]
pub use ledger::{
    AppendError, ReadError, SourceContentBinding, append_checkpointed_in_tx, begin_scope,
    checkpoint_at, checkpoint_by_digest, checkpoints_through, event_by_key, events_before,
    head_checkpoint, insert_source_content, last_event, source_content,
};
#[doc(inline)]
pub use migrations::{MigrationError, run_migrations};
#[doc(inline)]
pub use pool::{PoolError, build_pool};
