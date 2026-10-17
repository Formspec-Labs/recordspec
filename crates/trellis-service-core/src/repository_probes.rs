// Rust guideline compliant 2026-02-21
//! Test decorators over [`EventRepository`]: what a unit of work touched, and how it fails.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use stack_common_error::StackError;
use trellis_server_ports::{ArtifactRef, ArtifactStore};
use trellis_types::{StoredCheckpoint, StoredEvent};

use crate::event_repository::{
    AttachmentRow, EventRepository, ExportRows, ScopeTx, SourceContentBinding,
};

/// What the repository and artifact store were asked to read and write.
#[derive(Default)]
pub(crate) struct Counts {
    /// Rows returned by reads.
    pub(crate) rows_read: AtomicU64,
    /// Rows written (an event and its checkpoint are two).
    pub(crate) rows_written: AtomicU64,
    /// Stored bytes of everything written to the repository.
    pub(crate) db_bytes: AtomicU64,
    /// Bytes written to the artifact store.
    pub(crate) object_bytes: AtomicU64,
}

impl Counts {
    pub(crate) fn snapshot(&self) -> [u64; 4] {
        [
            self.rows_read.load(Ordering::SeqCst),
            self.rows_written.load(Ordering::SeqCst),
            self.db_bytes.load(Ordering::SeqCst),
            self.object_bytes.load(Ordering::SeqCst),
        ]
    }
}

/// Counts the rows a unit of work reads and writes, then delegates.
pub(crate) struct CountingRepository {
    pub(crate) inner: Arc<dyn EventRepository>,
    pub(crate) counts: Arc<Counts>,
}

struct CountingTx {
    inner: Box<dyn ScopeTx>,
    counts: Arc<Counts>,
}

impl CountingTx {
    fn read<T>(&self, rows: usize, value: T) -> T {
        self.counts
            .rows_read
            .fetch_add(rows as u64, Ordering::SeqCst);
        value
    }
}

#[async_trait]
impl ScopeTx for CountingTx {
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError> {
        let head = self.inner.head().await?;
        Ok(self.read(usize::from(head.is_some()), head))
    }

    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError> {
        let last = self.inner.last_event().await?;
        Ok(self.read(usize::from(last.is_some()), last))
    }

    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        let found = self.inner.event_by_key(key).await?;
        Ok(self.read(usize::from(found.is_some()), found))
    }

    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        let found = self.inner.checkpoint_at(tree_size).await?;
        Ok(self.read(usize::from(found.is_some()), found))
    }

    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        let events = self.inner.prefix(limit).await?;
        Ok(self.read(events.len(), events))
    }

    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError> {
        let found = self.inner.attachment_by_key(key).await?;
        Ok(self.read(usize::from(found.is_some()), found))
    }

    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError> {
        self.inner.insert(event, checkpoint).await?;
        self.counts.rows_written.fetch_add(2, Ordering::SeqCst);
        let bytes = event.canonical_event().len()
            + event.signed_event().len()
            + checkpoint.checkpoint.len()
            + checkpoint.frontier.len()
            + checkpoint.profile_state.len();
        self.counts
            .db_bytes
            .fetch_add(bytes as u64, Ordering::SeqCst);
        Ok(())
    }

    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError> {
        self.inner.insert_attachment(row).await?;
        self.counts.rows_written.fetch_add(1, Ordering::SeqCst);
        self.counts
            .db_bytes
            .fetch_add(row.ciphertext.len() as u64, Ordering::SeqCst);
        Ok(())
    }

    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError> {
        self.inner.insert_source_content(sequence, binding).await?;
        self.counts.rows_written.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), StackError> {
        self.inner.commit().await
    }
}

#[async_trait]
impl EventRepository for CountingRepository {
    async fn begin(&self, scope: &[u8]) -> Result<Box<dyn ScopeTx>, StackError> {
        Ok(Box::new(CountingTx {
            inner: self.inner.begin(scope).await?,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn head_checkpoint(&self, scope: &[u8]) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.head_checkpoint(scope).await
    }

    async fn checkpoint_at(
        &self,
        scope: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_at(scope, tree_size).await
    }

    async fn checkpoint_by_digest(
        &self,
        scope: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_by_digest(scope, digest).await
    }

    async fn last_event(&self, scope: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        self.inner.last_event(scope).await
    }

    async fn prefix(&self, scope: &[u8], limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        self.inner.prefix(scope, limit).await
    }

    async fn export_rows(&self, scope: &[u8], tree_size: u64) -> Result<ExportRows, StackError> {
        self.inner.export_rows(scope, tree_size).await
    }

    async fn attachment_by_content_hash(
        &self,
        scope: &[u8],
        content_hash: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError> {
        self.inner
            .attachment_by_content_hash(scope, content_hash)
            .await
    }

    async fn source_content(
        &self,
        scope: &[u8],
        sequence: u64,
    ) -> Result<Option<SourceContentBinding>, StackError> {
        self.inner.source_content(scope, sequence).await
    }
}

/// Counts the bytes written to the artifact store, then delegates.
pub(crate) struct CountingArtifactStore {
    pub(crate) inner: Arc<dyn ArtifactStore<Error = StackError>>,
    pub(crate) counts: Arc<Counts>,
}

#[async_trait]
impl ArtifactStore for CountingArtifactStore {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        self.counts
            .object_bytes
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.inner.put(key, bytes).await
    }

    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        self.counts
            .object_bytes
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.inner.put_immutable(key, bytes).await
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.get(artifact_ref).await
    }
}

/// How a unit of work fails: its first commits, or every insert.
pub(crate) enum Fault {
    /// The first `n` commits fail as an unavailable store would, writing nothing.
    FirstCommits(AtomicUsize),
    /// While armed, every insert reports a taken unique key: a lost race that the lock should have
    /// prevented. Disarmed, inserts go through.
    LostRace(std::sync::atomic::AtomicBool),
    /// Reports no checkpoint at any size, as a store that lost them would.
    HideCheckpoints,
    /// Runs the hook after every export read, as a change of authority mid-request would.
    AfterExportRows(Box<dyn Fn() + Send + Sync>),
}

/// Fails units of work as configured, then delegates.
pub(crate) struct FaultyRepository {
    pub(crate) inner: Arc<dyn EventRepository>,
    pub(crate) fault: Arc<Fault>,
}

struct FaultyTx {
    inner: Box<dyn ScopeTx>,
    fault: Arc<Fault>,
}

#[async_trait]
impl ScopeTx for FaultyTx {
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.head().await
    }

    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError> {
        self.inner.last_event().await
    }

    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        self.inner.event_by_key(key).await
    }

    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        if matches!(&*self.fault, Fault::HideCheckpoints) {
            return Ok(None);
        }
        self.inner.checkpoint_at(tree_size).await
    }

    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        self.inner.prefix(limit).await
    }

    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError> {
        self.inner.attachment_by_key(key).await
    }

    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError> {
        if matches!(&*self.fault, Fault::LostRace(armed) if armed.load(Ordering::SeqCst)) {
            return Err(StackError::unavailable(
                "trellis append lost a race on (scope, sequence); retry the same key",
            ));
        }
        self.inner.insert(event, checkpoint).await
    }

    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError> {
        self.inner.insert_attachment(row).await
    }

    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError> {
        self.inner.insert_source_content(sequence, binding).await
    }

    async fn commit(self: Box<Self>) -> Result<(), StackError> {
        if let Fault::FirstCommits(remaining) = &*self.fault
            && remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Err(StackError::unavailable("injected commit failure"));
        }
        self.inner.commit().await
    }
}

#[async_trait]
impl EventRepository for FaultyRepository {
    async fn begin(&self, scope: &[u8]) -> Result<Box<dyn ScopeTx>, StackError> {
        Ok(Box::new(FaultyTx {
            inner: self.inner.begin(scope).await?,
            fault: Arc::clone(&self.fault),
        }))
    }

    async fn head_checkpoint(&self, scope: &[u8]) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.head_checkpoint(scope).await
    }

    async fn checkpoint_at(
        &self,
        scope: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_at(scope, tree_size).await
    }

    async fn checkpoint_by_digest(
        &self,
        scope: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_by_digest(scope, digest).await
    }

    async fn last_event(&self, scope: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        self.inner.last_event(scope).await
    }

    async fn prefix(&self, scope: &[u8], limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        self.inner.prefix(scope, limit).await
    }

    async fn export_rows(&self, scope: &[u8], tree_size: u64) -> Result<ExportRows, StackError> {
        let rows = self.inner.export_rows(scope, tree_size).await?;
        if let Fault::AfterExportRows(hook) = &*self.fault {
            hook();
        }
        Ok(rows)
    }

    async fn attachment_by_content_hash(
        &self,
        scope: &[u8],
        content_hash: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError> {
        self.inner
            .attachment_by_content_hash(scope, content_hash)
            .await
    }

    async fn source_content(
        &self,
        scope: &[u8],
        sequence: u64,
    ) -> Result<Option<SourceContentBinding>, StackError> {
        self.inner.source_content(scope, sequence).await
    }
}

/// A repository whose every operation fails as an unreachable database would.
pub(crate) struct UnreachableRepository;

fn unreachable_store() -> StackError {
    StackError::unavailable("repository unreachable for test probe")
}

#[async_trait]
impl EventRepository for UnreachableRepository {
    async fn begin(&self, _: &[u8]) -> Result<Box<dyn ScopeTx>, StackError> {
        Err(unreachable_store())
    }
    async fn head_checkpoint(&self, _: &[u8]) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn checkpoint_at(
        &self,
        _: &[u8],
        _: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn checkpoint_by_digest(
        &self,
        _: &[u8],
        _: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn last_event(&self, _: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        Err(unreachable_store())
    }
    async fn prefix(&self, _: &[u8], _: u64) -> Result<Vec<StoredEvent>, StackError> {
        Err(unreachable_store())
    }
    async fn export_rows(&self, _: &[u8], _: u64) -> Result<ExportRows, StackError> {
        Err(unreachable_store())
    }
    async fn attachment_by_content_hash(
        &self,
        _: &[u8],
        _: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError> {
        Err(unreachable_store())
    }
    async fn source_content(
        &self,
        _: &[u8],
        _: u64,
    ) -> Result<Option<SourceContentBinding>, StackError> {
        Err(unreachable_store())
    }
}

/// Fails the first `remaining` immutable puts as a refusing artifact store would, then delegates.
pub(crate) struct FailsFirstImmutablePut {
    pub(crate) remaining: AtomicUsize,
    pub(crate) inner: crate::artifacts::InMemoryArtifactStore,
}

#[async_trait]
impl ArtifactStore for FailsFirstImmutablePut {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        self.inner.put(key, bytes).await
    }

    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StackError::conflict("injected artifact-store fault"));
        }
        self.inner.put_immutable(key, bytes).await
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.get(artifact_ref).await
    }
}
