// Rust guideline compliant 2026-02-21
//! The ledger store port: one scope's ledgers, scope-locked units of work and point reads.
//!
//! ADR 0168. A request reaches ledgers only through the [`ScopedLedgers`] its admitted scope's
//! handle carries; the deployment's [`Ledgers`] issues one per scope and is held only by the
//! deployment. Every ledger is named by a [`LedgerScope`] (owned by `trellis-service-client`, the
//! wire's one definition), `<scope key hex>.<ledger id>` (ADR 0168 §1.6), which can only be made
//! under a [`Scope`], so a ledger name always says which scope owns it and the store refuses one
//! that is not its own.
//!
//! An append is one [`LedgerTx`]: [`ScopedLedgers::begin`] takes the ledger's lock before it reads
//! anything, the caller reads the head checkpoint and the last event, writes the new event with
//! its checkpoint, and commits. Everything else is a point read or an index range.

use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use stack_common_scope::Scope;
pub use trellis_service_client::{LedgerScope, validate_ledger_id};
use trellis_types::{StoredCheckpoint, StoredEvent};

/// The checkpoint an export ends at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportAt {
    /// The ledger's head checkpoint.
    Head,
    /// The checkpoint with this digest.
    Digest([u8; 32]),
}

/// The most attachment body bytes one export carries (Core §18 evidence members).
pub const MAX_EXPORT_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;

/// The most events a ledger with attachments may export.
pub const MAX_ATTACHMENT_EXPORT_EVENTS: u64 = 256;

/// Everything one export reads, in one transaction: the checkpoint it ends at (`tree_size`
/// events), events `0..tree_size`, the checkpoints for tree sizes `1..=tree_size`, the
/// attachments retained for those events, and the Source batch copy bound to the last event.
///
/// Attachments are read in sequence order only until their bodies first exceed
/// [`MAX_EXPORT_ATTACHMENT_BYTES`] or their count exceeds [`MAX_ATTACHMENT_EXPORT_EVENTS`]: the
/// row that crosses is included, so assembly refuses the export, and no ledger's bodies are
/// loaded past the bound.
#[derive(Debug)]
pub struct ExportRows {
    pub head: StoredCheckpoint,
    pub events: Vec<StoredEvent>,
    pub checkpoints: Vec<StoredCheckpoint>,
    /// Ascending by sequence.
    pub attachments: Vec<AttachmentRow>,
    pub source_content: Option<SourceContentBinding>,
}

/// One retained attachment row and its committed event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentRow {
    pub event: StoredEvent,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub replay_identity: Vec<u8>,
    pub content_hash: Vec<u8>,
    pub idempotency_key: Vec<u8>,
    /// The custody disclosure the body was retained under, as JSON text.
    pub compute_json: String,
}

/// Trellis's own copy of a Source closeout's admitted batch: where it lives, not the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceContentBinding {
    /// SHA-256 of the stored batch; the object name is derived from it.
    pub batch_hash: [u8; 32],
    /// Byte length of the stored batch.
    pub size: u64,
    /// The key the scope's object store returned for the batch object.
    pub artifact_ref: String,
}

/// A unit of work holding one ledger's lock until it commits or is dropped (which rolls back).
#[async_trait]
pub trait LedgerTx: Send {
    /// The head checkpoint: the highest tree size. One row.
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The most recent event. One row.
    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError>;

    /// The event committed under an idempotency key, if any. At most one row.
    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError>;

    /// The checkpoint at exactly `tree_size`. One row.
    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The first `limit` events, ascending: a bounded read for the flows that validate a whole
    /// small ledger (the completion seal, accepted attachments, a Source closeout).
    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError>;

    /// The protected attachment retained under an idempotency key, if any.
    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError>;

    /// Writes one event and the checkpoint for the tree it produced.
    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError>;

    /// Retains the body of the attachment whose event was just inserted.
    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError>;

    /// Binds the closeout event just inserted to Trellis's own copy of its Source batch.
    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError>;

    /// Makes every write durable at once.
    async fn commit(self: Box<Self>) -> Result<(), StackError>;
}

/// One scope's ledgers. Every method refuses a [`LedgerScope`] of another scope as not found.
#[async_trait]
pub trait ScopedLedgers: Send + Sync {
    /// Opens a [`LedgerTx`], taking the ledger's lock before any read.
    ///
    /// # Errors
    /// [`StackError::unavailable`] when the store cannot open the unit of work.
    async fn begin(&self, ledger: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError>;

    /// The head checkpoint of `ledger`, if it has events. One row.
    async fn head_checkpoint(
        &self,
        ledger: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The checkpoint at exactly `tree_size`. One row.
    async fn checkpoint_at(
        &self,
        ledger: &LedgerScope,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The checkpoint whose digest is `digest` within `ledger`. One row.
    async fn checkpoint_by_digest(
        &self,
        ledger: &LedgerScope,
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The most recent event of `ledger`. One row.
    async fn last_event(&self, ledger: &LedgerScope) -> Result<Option<StoredEvent>, StackError>;

    /// The first `limit` events of `ledger`, ascending.
    async fn prefix(
        &self,
        ledger: &LedgerScope,
        limit: u64,
    ) -> Result<Vec<StoredEvent>, StackError>;

    /// The rows of the export ending at `at`, read in one transaction; `None` when the ledger
    /// has no events or no checkpoint with that digest.
    ///
    /// # Errors
    /// An internal error when the store holds fewer rows than the checkpoint claims.
    async fn export(
        &self,
        ledger: &LedgerScope,
        at: ExportAt,
    ) -> Result<Option<ExportRows>, StackError>;
}

/// The deployment's ledgers: issues one scope's [`ScopedLedgers`] at a time.
///
/// Only the deployment's store holds it (ADR 0168 §1.1); handlers see the scoped half.
pub trait Ledgers: Send + Sync + 'static {
    /// Returns `scope`'s ledgers.
    fn scoped(&self, scope: &Scope) -> Arc<dyn ScopedLedgers>;
}

/// The refusal a scoped store gives a ledger of another scope.
#[must_use]
pub fn foreign_ledger() -> StackError {
    StackError::not_found("no such ledger in this scope")
}
