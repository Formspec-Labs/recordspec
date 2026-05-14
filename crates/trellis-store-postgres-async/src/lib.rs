// Rust guideline compliant 2026-02-21
//! Async Postgres plumber for Trellis stored events.
//!
//! This crate does not construct Trellis ledger bytes. Callers pass
//! [`trellis_types::StoredEvent`] values whose canonical bytes were already
//! produced by `trellis-core`, and this crate writes those bytes through
//! `sqlx` transactions.

#![forbid(unsafe_code)]

mod append;
mod migrations;
mod pool;

#[doc(inline)]
pub use append::{AppendError, append_event_in_tx};
#[doc(inline)]
pub use migrations::{MigrationError, run_migrations};
#[doc(inline)]
pub use pool::{PoolError, build_pool};
