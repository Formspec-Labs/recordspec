// Rust guideline compliant 2026-02-21
//! Test decorators over the ledger and object ports: what a unit of work touched, and how it fails.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use futures::stream::BoxStream;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMultipartOpts,
    PutOptions, PutPayload, PutResult,
};
use stack_common_error::StackError;
use stack_common_scope::Scope;
use trellis_server_ports::{
    AttachmentRow, ExportAt, ExportRows, LedgerScope, LedgerTx, Ledgers, ScopedLedgers,
    SourceContentBinding,
};
use trellis_types::{StoredCheckpoint, StoredEvent};

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
pub(crate) struct CountingLedgers {
    pub(crate) inner: Arc<dyn Ledgers>,
    pub(crate) counts: Arc<Counts>,
}

impl Ledgers for CountingLedgers {
    fn scoped(&self, scope: &Scope) -> Arc<dyn ScopedLedgers> {
        Arc::new(CountingScoped {
            inner: self.inner.scoped(scope),
            counts: Arc::clone(&self.counts),
        })
    }
}

struct CountingScoped {
    inner: Arc<dyn ScopedLedgers>,
    counts: Arc<Counts>,
}

struct CountingTx {
    inner: Box<dyn LedgerTx>,
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
impl LedgerTx for CountingTx {
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
impl ScopedLedgers for CountingScoped {
    async fn begin(&self, ledger: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError> {
        Ok(Box::new(CountingTx {
            inner: self.inner.begin(ledger).await?,
            counts: Arc::clone(&self.counts),
        }))
    }

    async fn export(
        &self,
        ledger: &LedgerScope,
        at: ExportAt,
    ) -> Result<Option<ExportRows>, StackError> {
        self.inner.export(ledger, at).await
    }

    async fn head_checkpoint(
        &self,
        ledger: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.head_checkpoint(ledger).await
    }

    async fn checkpoint_at(
        &self,
        ledger: &LedgerScope,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_at(ledger, tree_size).await
    }

    async fn checkpoint_by_digest(
        &self,
        ledger: &LedgerScope,
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_by_digest(ledger, digest).await
    }

    async fn last_event(&self, ledger: &LedgerScope) -> Result<Option<StoredEvent>, StackError> {
        self.inner.last_event(ledger).await
    }

    async fn prefix(
        &self,
        ledger: &LedgerScope,
        limit: u64,
    ) -> Result<Vec<StoredEvent>, StackError> {
        self.inner.prefix(ledger, limit).await
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
pub(crate) struct FaultyLedgers {
    pub(crate) inner: Arc<dyn Ledgers>,
    pub(crate) fault: Arc<Fault>,
}

impl Ledgers for FaultyLedgers {
    fn scoped(&self, scope: &Scope) -> Arc<dyn ScopedLedgers> {
        Arc::new(FaultyScoped {
            inner: self.inner.scoped(scope),
            fault: Arc::clone(&self.fault),
        })
    }
}

struct FaultyScoped {
    inner: Arc<dyn ScopedLedgers>,
    fault: Arc<Fault>,
}

struct FaultyTx {
    inner: Box<dyn LedgerTx>,
    fault: Arc<Fault>,
}

#[async_trait]
impl LedgerTx for FaultyTx {
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
impl ScopedLedgers for FaultyScoped {
    async fn begin(&self, ledger: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError> {
        Ok(Box::new(FaultyTx {
            inner: self.inner.begin(ledger).await?,
            fault: Arc::clone(&self.fault),
        }))
    }

    async fn export(
        &self,
        ledger: &LedgerScope,
        at: ExportAt,
    ) -> Result<Option<ExportRows>, StackError> {
        let rows = self.inner.export(ledger, at).await?;
        if let Fault::AfterExportRows(hook) = &*self.fault {
            hook();
        }
        Ok(rows)
    }

    async fn head_checkpoint(
        &self,
        ledger: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.head_checkpoint(ledger).await
    }

    async fn checkpoint_at(
        &self,
        ledger: &LedgerScope,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_at(ledger, tree_size).await
    }

    async fn checkpoint_by_digest(
        &self,
        ledger: &LedgerScope,
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        self.inner.checkpoint_by_digest(ledger, digest).await
    }

    async fn last_event(&self, ledger: &LedgerScope) -> Result<Option<StoredEvent>, StackError> {
        self.inner.last_event(ledger).await
    }

    async fn prefix(
        &self,
        ledger: &LedgerScope,
        limit: u64,
    ) -> Result<Vec<StoredEvent>, StackError> {
        self.inner.prefix(ledger, limit).await
    }
}

/// Ledgers whose every operation fails as an unreachable database would.
pub(crate) struct UnreachableLedgers;

impl Ledgers for UnreachableLedgers {
    fn scoped(&self, _: &Scope) -> Arc<dyn ScopedLedgers> {
        Arc::new(UnreachableLedgers)
    }
}

fn unreachable_store() -> StackError {
    StackError::unavailable("repository unreachable for test probe")
}

#[async_trait]
impl ScopedLedgers for UnreachableLedgers {
    async fn begin(&self, _: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError> {
        Err(unreachable_store())
    }
    async fn head_checkpoint(
        &self,
        _: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn checkpoint_at(
        &self,
        _: &LedgerScope,
        _: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn checkpoint_by_digest(
        &self,
        _: &LedgerScope,
        _: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Err(unreachable_store())
    }
    async fn last_event(&self, _: &LedgerScope) -> Result<Option<StoredEvent>, StackError> {
        Err(unreachable_store())
    }
    async fn prefix(&self, _: &LedgerScope, _: u64) -> Result<Vec<StoredEvent>, StackError> {
        Err(unreachable_store())
    }
    async fn export(&self, _: &LedgerScope, _: ExportAt) -> Result<Option<ExportRows>, StackError> {
        Err(unreachable_store())
    }
}

/// What a [`HookedStore`] does before each object write.
#[async_trait]
pub(crate) trait PutHook: Send + Sync + 'static {
    /// Runs before `bytes` are written at `location`; an error refuses the write.
    async fn before_put(&self, location: &Path, bytes: usize) -> object_store::Result<()>;
}

/// An in-memory object store that runs a hook before every write but the bucket's cell record:
/// counts the bytes, refuses the write, or probes what is locked while it happens.
pub(crate) struct HookedStore {
    inner: InMemory,
    hook: Arc<dyn PutHook>,
}

impl HookedStore {
    pub(crate) fn new(hook: impl PutHook) -> Arc<Self> {
        Arc::new(Self {
            inner: InMemory::new(),
            hook: Arc::new(hook),
        })
    }
}

impl fmt::Debug for HookedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HookedStore")
    }
}

impl fmt::Display for HookedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HookedStore")
    }
}

#[async_trait]
impl ObjectStore for HookedStore {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        if location.as_ref() != "stack-cell" {
            self.hook
                .before_put(location, payload.content_length())
                .await?;
        }
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOpts,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        self.inner.get_opts(location, options).await
    }

    async fn delete(&self, location: &Path) -> object_store::Result<()> {
        self.inner.delete(location).await
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.inner.copy(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.inner.copy_if_not_exists(from, to).await
    }
}

/// Counts the bytes written to the object store.
pub(crate) struct CountObjectBytes(pub(crate) Arc<Counts>);

#[async_trait]
impl PutHook for CountObjectBytes {
    async fn before_put(&self, _: &Path, bytes: usize) -> object_store::Result<()> {
        self.0
            .object_bytes
            .fetch_add(bytes as u64, Ordering::SeqCst);
        Ok(())
    }
}

/// Refuses the first `remaining` writes, as a refusing object store would.
pub(crate) struct RefuseFirstPuts(pub(crate) AtomicUsize);

#[async_trait]
impl PutHook for RefuseFirstPuts {
    async fn before_put(&self, _: &Path, _: usize) -> object_store::Result<()> {
        if self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(object_store::Error::Generic {
                store: "HookedStore",
                source: "injected object-store fault".into(),
            });
        }
        Ok(())
    }
}
