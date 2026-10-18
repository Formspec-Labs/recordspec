// Rust guideline compliant 2026-02-21
//! Trellis's Postgres adapter: every SQL statement Trellis runs, behind the sqlx fence.
//!
//! This crate does not construct Trellis ledger bytes. Callers pass
//! [`trellis_types::StoredEvent`] values whose canonical bytes were already produced by
//! `trellis-core`, and this crate writes those bytes. Every statement runs in a
//! [`stack_common_postgres::ScopedTx`], so the scope key it binds comes from the scope the
//! deployment issued (ADR 0168 §1.3); [`PgLedgers`] is the [`trellis_server_ports::Ledgers`]
//! port the server holds. Only this crate and the composition root depend on `sqlx`
//! (`deny.toml`).

#![forbid(unsafe_code)]

mod attachments;
mod ledger;
mod migrations;
mod scoped;
#[doc(hidden)]
pub mod statements;

#[doc(inline)]
pub use attachments::{AttachmentRow, attachment_by_key, attachments_within, insert_attachment};
#[doc(inline)]
pub use ledger::{
    AppendError, ReadError, SourceContentBinding, append_checkpointed, checkpoint_at,
    checkpoint_by_digest, checkpoints_through, event_by_key, events_before, head_checkpoint,
    insert_source_content, last_event, lock_ledger, prefix, source_content,
};
#[doc(inline)]
pub use migrations::{SCHEMA, TABLES, TRELLIS_MIGRATIONS};
#[doc(inline)]
pub use scoped::PgLedgers;
