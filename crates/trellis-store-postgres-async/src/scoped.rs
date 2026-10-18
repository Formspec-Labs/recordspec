// Rust guideline compliant 2026-02-21
//! [`PgLedgers`]: the [`Ledgers`] port over the deployment's [`ScopedPool`].
//!
//! The deployment's store holds one `PgLedgers`; each request's handle holds the
//! [`ScopedLedgers`] it issues for the request's scope. Every read and every unit of work opens a
//! [`ScopedTx`] for that scope, so `scope_key` is bound from the scope, never from the caller, and
//! a [`LedgerScope`] of another scope is refused before any SQL runs.

use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use stack_common_postgres::{ScopedPool, ScopedTx};
use stack_common_scope::Scope;
use trellis_server_ports::{
    AttachmentRow, ExportAt, ExportRows, LedgerScope, LedgerTx, Ledgers,
    MAX_ATTACHMENT_EXPORT_EVENTS, MAX_EXPORT_ATTACHMENT_BYTES, ScopedLedgers, SourceContentBinding,
    foreign_ledger,
};
use trellis_types::{StoredCheckpoint, StoredEvent};

use crate::ledger::{AppendError, ReadError};
use crate::{attachments, ledger};

/// The deployment's Postgres ledgers. Only the deployment's store holds it.
#[derive(Clone, Debug)]
pub struct PgLedgers {
    pool: ScopedPool,
}

impl PgLedgers {
    /// Ledgers over the deployment's pool, which the composition root opened.
    #[must_use]
    pub const fn new(pool: ScopedPool) -> Self {
        Self { pool }
    }
}

impl Ledgers for PgLedgers {
    fn scoped(&self, scope: &Scope) -> Arc<dyn ScopedLedgers> {
        Arc::new(PgScopedLedgers {
            pool: self.pool.clone(),
            scope: scope.clone(),
        })
    }
}

/// One scope's Postgres ledgers.
struct PgScopedLedgers {
    pool: ScopedPool,
    scope: Scope,
}

impl PgScopedLedgers {
    /// A transaction for this scope, refusing a ledger of another scope first.
    async fn tx(&self, ledger: &LedgerScope) -> Result<ScopedTx, StackError> {
        if !ledger.belongs_to(&self.scope) {
            return Err(foreign_ledger());
        }
        self.pool.begin(&self.scope).await.map_err(sql_error)
    }
}

fn read_error(error: ReadError) -> StackError {
    StackError::unavailable(format!("trellis ledger read failed: {error}"))
}

fn sql_error(error: sqlx::Error) -> StackError {
    StackError::unavailable(format!("trellis ledger transaction failed: {error}"))
}

/// A taken unique key is a race lost, not a client fault: the HTTP idempotency layer caches every
/// non-5xx response, so a 409 here would pin the loser's key forever.
fn append_error(error: AppendError) -> StackError {
    match error {
        AppendError::Conflict(key) => StackError::unavailable(format!(
            "trellis append lost a race on {key}; retry the same key"
        )),
        AppendError::Sqlx(error) => {
            StackError::unavailable(format!("trellis append failed: {error}"))
        }
        other => StackError::internal(format!("trellis append refused: {other}")),
    }
}

/// Runs one read in its own scoped transaction and commits it.
macro_rules! read_once {
    ($self:ident, $ledger:ident, |$tx:ident| $read:expr) => {{
        let mut $tx = $self.tx($ledger).await?;
        let value = $read.await.map_err(read_error)?;
        $tx.commit().await.map_err(sql_error)?;
        Ok(value)
    }};
}

#[async_trait]
impl ScopedLedgers for PgScopedLedgers {
    async fn begin(&self, ledger: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError> {
        let mut tx = self.tx(ledger).await?;
        ledger::lock_ledger(&mut tx, ledger.as_bytes())
            .await
            .map_err(sql_error)?;
        Ok(Box::new(PgLedgerTx {
            tx,
            ledger: ledger.clone(),
        }))
    }

    async fn head_checkpoint(
        &self,
        ledger: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        read_once!(self, ledger, |tx| ledger::head_checkpoint(
            &mut tx,
            ledger.as_bytes()
        ))
    }

    async fn checkpoint_at(
        &self,
        ledger: &LedgerScope,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        read_once!(self, ledger, |tx| ledger::checkpoint_at(
            &mut tx,
            ledger.as_bytes(),
            tree_size
        ))
    }

    async fn checkpoint_by_digest(
        &self,
        ledger: &LedgerScope,
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        read_once!(self, ledger, |tx| ledger::checkpoint_by_digest(
            &mut tx,
            ledger.as_bytes(),
            digest
        ))
    }

    async fn last_event(&self, ledger: &LedgerScope) -> Result<Option<StoredEvent>, StackError> {
        read_once!(self, ledger, |tx| ledger::last_event(
            &mut tx,
            ledger.as_bytes()
        ))
    }

    async fn prefix(
        &self,
        ledger: &LedgerScope,
        limit: u64,
    ) -> Result<Vec<StoredEvent>, StackError> {
        read_once!(self, ledger, |tx| ledger::prefix(
            &mut tx,
            ledger.as_bytes(),
            limit
        ))
    }

    /// Every row one export reads, in one transaction: one `BEGIN` and one `COMMIT`. Rows are
    /// append-only, so reads at READ COMMITTED below a committed checkpoint see a fixed prefix.
    async fn export(
        &self,
        ledger: &LedgerScope,
        at: ExportAt,
    ) -> Result<Option<ExportRows>, StackError> {
        let mut tx = self.tx(ledger).await?;
        let scope = ledger.as_bytes();
        let head = match at {
            ExportAt::Head => ledger::head_checkpoint(&mut tx, scope).await,
            ExportAt::Digest(digest) => ledger::checkpoint_by_digest(&mut tx, scope, &digest).await,
        }
        .map_err(read_error)?;
        let Some(head) = head else {
            tx.commit().await.map_err(sql_error)?;
            return Ok(None);
        };
        let tree_size = head.tree_size;
        let events = ledger::events_before(&mut tx, scope, tree_size)
            .await
            .map_err(read_error)?;
        let checkpoints = ledger::checkpoints_through(&mut tx, scope, tree_size)
            .await
            .map_err(read_error)?;
        let attachments = attachments::attachments_within(
            &mut tx,
            scope,
            tree_size,
            MAX_EXPORT_ATTACHMENT_BYTES,
            MAX_ATTACHMENT_EXPORT_EVENTS,
        )
        .await
        .map_err(read_error)?;
        let source_content = ledger::source_content(&mut tx, scope, tree_size - 1)
            .await
            .map_err(read_error)?;
        tx.commit().await.map_err(sql_error)?;
        if events.len() as u64 != tree_size || checkpoints.len() as u64 != tree_size {
            return Err(StackError::internal(
                "trellis ledger rows are fewer than the checkpoint claims",
            ));
        }
        Ok(Some(ExportRows {
            head,
            events,
            checkpoints,
            attachments,
            source_content,
        }))
    }
}

/// One ledger's unit of work: its lock is held until commit or drop.
struct PgLedgerTx {
    tx: ScopedTx,
    ledger: LedgerScope,
}

impl PgLedgerTx {
    /// An event or attachment row must belong to the ledger this unit of work locked.
    fn own(&self, scope: &[u8]) -> Result<(), StackError> {
        if scope == self.ledger.as_bytes() {
            Ok(())
        } else {
            Err(StackError::internal(
                "trellis append refused: the row names another ledger than the one locked",
            ))
        }
    }
}

#[async_trait]
impl LedgerTx for PgLedgerTx {
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError> {
        ledger::head_checkpoint(&mut self.tx, self.ledger.as_bytes())
            .await
            .map_err(read_error)
    }

    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError> {
        ledger::last_event(&mut self.tx, self.ledger.as_bytes())
            .await
            .map_err(read_error)
    }

    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        ledger::event_by_key(&mut self.tx, self.ledger.as_bytes(), key)
            .await
            .map_err(read_error)
    }

    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        ledger::checkpoint_at(&mut self.tx, self.ledger.as_bytes(), tree_size)
            .await
            .map_err(read_error)
    }

    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        ledger::prefix(&mut self.tx, self.ledger.as_bytes(), limit)
            .await
            .map_err(read_error)
    }

    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError> {
        attachments::attachment_by_key(&mut self.tx, self.ledger.as_bytes(), key)
            .await
            .map_err(read_error)
    }

    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError> {
        self.own(event.scope())?;
        ledger::append_checkpointed(&mut self.tx, event, checkpoint)
            .await
            .map_err(append_error)
    }

    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError> {
        self.own(row.event.scope())?;
        attachments::insert_attachment(&mut self.tx, row)
            .await
            .map_err(append_error)
    }

    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError> {
        ledger::insert_source_content(&mut self.tx, self.ledger.as_bytes(), sequence, binding)
            .await
            .map_err(append_error)
    }

    async fn commit(self: Box<Self>) -> Result<(), StackError> {
        self.tx.commit().await.map_err(sql_error)
    }
}
