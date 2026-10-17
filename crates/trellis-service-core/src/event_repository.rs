// Rust guideline compliant 2026-02-21
//! The event repository port: scope-locked units of work and point reads.
//!
//! An append is one [`ScopeTx`]: [`EventRepository::begin`] takes the scope's lock before it
//! reads anything, the caller reads the head checkpoint and the last event, writes the new event
//! with its checkpoint, and commits. The lock replaces any in-process serialisation, so replicas
//! need no coordination beyond the database. Everything else is a point read or an index range.

use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Transaction};
use stack_common_error::StackError;
use trellis_store_postgres_async as store;
use trellis_types::{StoredCheckpoint, StoredEvent};

pub use store::{AttachmentRow, SourceContentBinding};

mod memory;
pub use memory::InMemoryEventRepository;

/// An export's rows: events `0..tree_size` and the checkpoints for tree sizes `1..=tree_size`.
#[derive(Debug)]
pub struct ExportRows {
    pub events: Vec<StoredEvent>,
    pub checkpoints: Vec<StoredCheckpoint>,
}

/// A unit of work holding one scope's lock until it commits or is dropped (which rolls back).
#[async_trait]
pub trait ScopeTx: Send {
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

/// Durable event store used by the service composition root.
#[async_trait]
pub trait EventRepository: Send + Sync {
    /// Opens a [`ScopeTx`], taking the scope's lock before any read.
    ///
    /// # Errors
    /// [`StackError::unavailable`] when the store cannot open the unit of work.
    async fn begin(&self, scope: &[u8]) -> Result<Box<dyn ScopeTx>, StackError>;

    /// The head checkpoint of `scope`, if it has events. One row.
    async fn head_checkpoint(&self, scope: &[u8]) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The checkpoint at exactly `tree_size`. One row.
    async fn checkpoint_at(
        &self,
        scope: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The checkpoint whose digest is `digest` within `scope`. One row.
    async fn checkpoint_by_digest(
        &self,
        scope: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError>;

    /// The most recent event of `scope`. One row.
    async fn last_event(&self, scope: &[u8]) -> Result<Option<StoredEvent>, StackError>;

    /// The first `limit` events of `scope`, ascending.
    async fn prefix(&self, scope: &[u8], limit: u64) -> Result<Vec<StoredEvent>, StackError>;

    /// The rows of the export whose head is the checkpoint at `tree_size`.
    ///
    /// # Errors
    /// An internal error when the store holds fewer rows than the checkpoint claims.
    async fn export_rows(&self, scope: &[u8], tree_size: u64) -> Result<ExportRows, StackError>;

    /// The earliest retained attachment in `scope` whose ciphertext has `content_hash`.
    async fn attachment_by_content_hash(
        &self,
        scope: &[u8],
        content_hash: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError>;

    /// The Source batch copy bound to the event at `sequence`, if it is a closeout.
    async fn source_content(
        &self,
        scope: &[u8],
        sequence: u64,
    ) -> Result<Option<SourceContentBinding>, StackError>;

    /// Every event of `scope`, ascending. Unbounded: for exports, tests and diagnostics.
    async fn list_scope(&self, scope: &[u8]) -> Result<Vec<StoredEvent>, StackError> {
        match self.head_checkpoint(scope).await? {
            Some(head) => Ok(self.export_rows(scope, head.tree_size).await?.events),
            None => Ok(Vec::new()),
        }
    }
}

fn read_error(error: store::ReadError) -> StackError {
    StackError::unavailable(format!("trellis ledger read failed: {error}"))
}

fn sql_error(error: sqlx::Error) -> StackError {
    StackError::unavailable(format!("trellis ledger transaction failed: {error}"))
}

/// A taken unique key is a race lost, not a client fault: the HTTP idempotency layer caches every
/// non-5xx response, so a 409 here would pin the loser's key forever.
fn append_error(error: store::AppendError) -> StackError {
    match error {
        store::AppendError::Conflict(key) => StackError::unavailable(format!(
            "trellis append lost a race on {key}; retry the same key"
        )),
        store::AppendError::Sqlx(error) => {
            StackError::unavailable(format!("trellis append failed: {error}"))
        }
        other => StackError::internal(format!("trellis append refused: {other}")),
    }
}

/// Postgres repository backed by the Trellis async store schema.
#[derive(Clone)]
pub struct PostgresEventRepository {
    pool: PgPool,
}

impl PostgresEventRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct PostgresTx {
    tx: Transaction<'static, Postgres>,
    scope: Vec<u8>,
}

#[async_trait]
impl ScopeTx for PostgresTx {
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError> {
        store::head_checkpoint(&mut *self.tx, &self.scope)
            .await
            .map_err(read_error)
    }

    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError> {
        store::last_event(&mut *self.tx, &self.scope)
            .await
            .map_err(read_error)
    }

    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        store::event_by_key(&mut *self.tx, &self.scope, key)
            .await
            .map_err(read_error)
    }

    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        store::checkpoint_at(&mut *self.tx, &self.scope, tree_size)
            .await
            .map_err(read_error)
    }

    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        store::events_before(&mut *self.tx, &self.scope, i64::MAX as u64, limit)
            .await
            .map_err(read_error)
    }

    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError> {
        store::attachment_by_key(&mut *self.tx, &self.scope, key)
            .await
            .map_err(read_error)
    }

    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError> {
        store::append_checkpointed_in_tx(&mut self.tx, event, checkpoint)
            .await
            .map_err(append_error)
    }

    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError> {
        store::insert_attachment(&mut self.tx, row)
            .await
            .map_err(append_error)
    }

    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError> {
        store::insert_source_content(&mut self.tx, &self.scope, sequence, binding)
            .await
            .map_err(append_error)
    }

    async fn commit(self: Box<Self>) -> Result<(), StackError> {
        self.tx.commit().await.map_err(sql_error)
    }
}

#[async_trait]
impl EventRepository for PostgresEventRepository {
    async fn begin(&self, scope: &[u8]) -> Result<Box<dyn ScopeTx>, StackError> {
        let tx = store::begin_scope(&self.pool, scope)
            .await
            .map_err(sql_error)?;
        Ok(Box::new(PostgresTx {
            tx,
            scope: scope.to_vec(),
        }))
    }

    async fn head_checkpoint(&self, scope: &[u8]) -> Result<Option<StoredCheckpoint>, StackError> {
        store::head_checkpoint(&self.pool, scope)
            .await
            .map_err(read_error)
    }

    async fn checkpoint_at(
        &self,
        scope: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        store::checkpoint_at(&self.pool, scope, tree_size)
            .await
            .map_err(read_error)
    }

    async fn checkpoint_by_digest(
        &self,
        scope: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        store::checkpoint_by_digest(&self.pool, scope, digest)
            .await
            .map_err(read_error)
    }

    async fn last_event(&self, scope: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        store::last_event(&self.pool, scope)
            .await
            .map_err(read_error)
    }

    async fn prefix(&self, scope: &[u8], limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        store::events_before(&self.pool, scope, i64::MAX as u64, limit)
            .await
            .map_err(read_error)
    }

    async fn export_rows(&self, scope: &[u8], tree_size: u64) -> Result<ExportRows, StackError> {
        let events = store::events_before(&self.pool, scope, tree_size, tree_size)
            .await
            .map_err(read_error)?;
        let checkpoints = store::checkpoints_through(&self.pool, scope, tree_size)
            .await
            .map_err(read_error)?;
        if events.len() as u64 != tree_size || checkpoints.len() as u64 != tree_size {
            return Err(StackError::internal(
                "trellis ledger rows are fewer than the checkpoint claims",
            ));
        }
        Ok(ExportRows {
            events,
            checkpoints,
        })
    }

    async fn attachment_by_content_hash(
        &self,
        scope: &[u8],
        content_hash: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError> {
        store::attachment_by_content_hash(&self.pool, scope, content_hash)
            .await
            .map_err(read_error)
    }

    async fn source_content(
        &self,
        scope: &[u8],
        sequence: u64,
    ) -> Result<Option<SourceContentBinding>, StackError> {
        store::source_content(&self.pool, scope, sequence)
            .await
            .map_err(read_error)
    }
}
