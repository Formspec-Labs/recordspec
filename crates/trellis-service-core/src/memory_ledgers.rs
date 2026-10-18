// Rust guideline compliant 2026-02-21
//! In-memory [`Ledgers`] for tests and explicitly requested local runs.
//!
//! One mutex guards the whole state and a unit of work holds it from `begin` to its end, which is
//! the in-memory form of the Postgres advisory lock. Writes buffer until `commit`, so dropping a
//! unit of work discards them just as a rollback does. Ledgers are keyed by `(scope key, ledger
//! scope)`, as Postgres keys them, and a scope's handle refuses another scope's ledger.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use stack_common_scope::{Scope, ScopeKey};
use tokio::sync::{Mutex, OwnedMutexGuard};
use trellis_server_ports::{
    AttachmentRow, ExportAt, ExportRows, LedgerScope, LedgerTx, Ledgers,
    MAX_ATTACHMENT_EXPORT_EVENTS, MAX_EXPORT_ATTACHMENT_BYTES, ScopedLedgers, SourceContentBinding,
    foreign_ledger,
};
use trellis_types::{StoredCheckpoint, StoredEvent};

#[derive(Default)]
struct Ledger {
    events: Vec<StoredEvent>,
    checkpoints: Vec<StoredCheckpoint>,
    by_key: HashMap<Vec<u8>, usize>,
    attachments: Vec<AttachmentRow>,
    source_contents: HashMap<u64, SourceContentBinding>,
}

/// A ledger's key: the scope key, then the ledger scope.
type LedgerKey = (ScopeKey, Vec<u8>);

#[derive(Default)]
struct State {
    ledgers: HashMap<LedgerKey, Ledger>,
}

/// In-memory [`Ledgers`]; clones share one state.
#[derive(Clone, Default)]
pub struct MemoryLedgers {
    state: Arc<Mutex<State>>,
}

impl MemoryLedgers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Ledgers for MemoryLedgers {
    fn scoped(&self, scope: &Scope) -> Arc<dyn ScopedLedgers> {
        Arc::new(MemoryScopedLedgers {
            state: Arc::clone(&self.state),
            scope: scope.clone(),
        })
    }
}

/// One scope's in-memory ledgers.
struct MemoryScopedLedgers {
    state: Arc<Mutex<State>>,
    scope: Scope,
}

impl MemoryScopedLedgers {
    fn key(&self, ledger: &LedgerScope) -> Result<LedgerKey, StackError> {
        if ledger.belongs_to(&self.scope) {
            Ok((*self.scope.key(), ledger.as_bytes().to_vec()))
        } else {
            Err(foreign_ledger())
        }
    }

    async fn read<T>(
        &self,
        ledger: &LedgerScope,
        read: impl FnOnce(&Ledger) -> T,
    ) -> Result<Option<T>, StackError> {
        let key = self.key(ledger)?;
        Ok(self.state.lock().await.ledgers.get(&key).map(read))
    }
}

#[derive(Default)]
struct Pending {
    write: Option<(StoredEvent, StoredCheckpoint)>,
    attachment: Option<AttachmentRow>,
    source_content: Option<(u64, SourceContentBinding)>,
}

struct MemoryTx {
    guard: OwnedMutexGuard<State>,
    key: LedgerKey,
    pending: Pending,
}

impl MemoryTx {
    fn ledger(&self) -> Option<&Ledger> {
        self.guard.ledgers.get(&self.key)
    }

    /// A row must belong to the ledger this unit of work locked.
    fn own(&self, scope: &[u8]) -> Result<(), StackError> {
        if scope == self.key.1.as_slice() {
            Ok(())
        } else {
            Err(StackError::internal(
                "trellis append refused: the row names another ledger than the one locked",
            ))
        }
    }
}

fn lost_race(what: &str) -> StackError {
    StackError::unavailable(format!(
        "trellis append lost a race on {what}; retry the same key"
    ))
}

#[async_trait]
impl LedgerTx for MemoryTx {
    async fn head(&mut self) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self.ledger().and_then(|l| l.checkpoints.last().cloned()))
    }

    async fn last_event(&mut self) -> Result<Option<StoredEvent>, StackError> {
        Ok(self.ledger().and_then(|l| l.events.last().cloned()))
    }

    async fn event_by_key(&mut self, key: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        Ok(self
            .ledger()
            .and_then(|l| l.by_key.get(key).map(|index| l.events[*index].clone())))
    }

    async fn checkpoint_at(
        &mut self,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self.ledger().and_then(|l| {
            let index = usize::try_from(tree_size.checked_sub(1)?).ok()?;
            l.checkpoints.get(index).cloned()
        }))
    }

    async fn prefix(&mut self, limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .ledger()
            .map(|l| l.events.iter().take(limit).cloned().collect())
            .unwrap_or_default())
    }

    async fn attachment_by_key(&mut self, key: &[u8]) -> Result<Option<AttachmentRow>, StackError> {
        Ok(self.ledger().and_then(|l| {
            l.attachments
                .iter()
                .find(|a| a.idempotency_key == key)
                .cloned()
        }))
    }

    async fn insert(
        &mut self,
        event: &StoredEvent,
        checkpoint: &StoredCheckpoint,
    ) -> Result<(), StackError> {
        self.own(event.scope())?;
        let len = self.ledger().map_or(0, |l| l.events.len() as u64);
        if event.sequence() != len || checkpoint.tree_size != len + 1 {
            return Err(lost_race("(scope, sequence)"));
        }
        if event
            .idempotency_key()
            .is_some_and(|key| self.ledger().is_some_and(|l| l.by_key.contains_key(key)))
        {
            return Err(lost_race("the idempotency key"));
        }
        if event.canonical_event_hash().is_none()
            || checkpoint.frontier.len() != 32 * checkpoint.tree_size.count_ones() as usize
        {
            return Err(StackError::internal(
                "trellis append refused: checkpoint does not describe the event",
            ));
        }
        self.pending.write = Some((event.clone(), checkpoint.clone()));
        Ok(())
    }

    async fn insert_attachment(&mut self, row: &AttachmentRow) -> Result<(), StackError> {
        self.own(row.event.scope())?;
        if self.ledger().is_some_and(|l| {
            l.attachments
                .iter()
                .any(|a| a.idempotency_key == row.idempotency_key)
        }) {
            return Err(lost_race("the attachment key"));
        }
        self.pending.attachment = Some(row.clone());
        Ok(())
    }

    async fn insert_source_content(
        &mut self,
        sequence: u64,
        binding: &SourceContentBinding,
    ) -> Result<(), StackError> {
        self.pending.source_content = Some((sequence, binding.clone()));
        Ok(())
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StackError> {
        let key = self.key.clone();
        let pending = std::mem::take(&mut self.pending);
        let ledger = self.guard.ledgers.entry(key).or_default();
        if let Some((event, checkpoint)) = pending.write {
            if let Some(key) = event.idempotency_key() {
                ledger.by_key.insert(key.to_vec(), ledger.events.len());
            }
            ledger.events.push(event);
            ledger.checkpoints.push(checkpoint);
        }
        ledger.attachments.extend(pending.attachment);
        if let Some((sequence, binding)) = pending.source_content {
            ledger.source_contents.insert(sequence, binding);
        }
        Ok(())
    }
}

/// The attachments below `tree_size` up to and including the one whose body first crosses the
/// export bound, as `ExportRows` documents and Postgres reads them.
fn within_bound(attachments: &[AttachmentRow], tree_size: u64) -> Vec<AttachmentRow> {
    let mut total = 0_u64;
    let mut kept = Vec::new();
    for attachment in attachments
        .iter()
        .filter(|a| a.event.sequence() < tree_size)
    {
        total = total.saturating_add(attachment.ciphertext.len() as u64);
        kept.push(attachment.clone());
        if total > MAX_EXPORT_ATTACHMENT_BYTES || kept.len() as u64 > MAX_ATTACHMENT_EXPORT_EVENTS {
            break;
        }
    }
    kept
}

#[async_trait]
impl ScopedLedgers for MemoryScopedLedgers {
    async fn begin(&self, ledger: &LedgerScope) -> Result<Box<dyn LedgerTx>, StackError> {
        let key = self.key(ledger)?;
        Ok(Box::new(MemoryTx {
            guard: Arc::clone(&self.state).lock_owned().await,
            key,
            pending: Pending::default(),
        }))
    }

    async fn head_checkpoint(
        &self,
        ledger: &LedgerScope,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(ledger, |l| l.checkpoints.last().cloned())
            .await?
            .flatten())
    }

    async fn checkpoint_at(
        &self,
        ledger: &LedgerScope,
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(ledger, |l| {
                let index = usize::try_from(tree_size.checked_sub(1)?).ok()?;
                l.checkpoints.get(index).cloned()
            })
            .await?
            .flatten())
    }

    async fn checkpoint_by_digest(
        &self,
        ledger: &LedgerScope,
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(ledger, |l| {
                l.checkpoints.iter().find(|c| &c.digest == digest).cloned()
            })
            .await?
            .flatten())
    }

    async fn last_event(&self, ledger: &LedgerScope) -> Result<Option<StoredEvent>, StackError> {
        Ok(self
            .read(ledger, |l| l.events.last().cloned())
            .await?
            .flatten())
    }

    async fn prefix(
        &self,
        ledger: &LedgerScope,
        limit: u64,
    ) -> Result<Vec<StoredEvent>, StackError> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .read(ledger, |l| l.events.iter().take(limit).cloned().collect())
            .await?
            .unwrap_or_default())
    }

    async fn export(
        &self,
        ledger: &LedgerScope,
        at: ExportAt,
    ) -> Result<Option<ExportRows>, StackError> {
        let rows = self
            .read(ledger, |l| {
                let head = match at {
                    ExportAt::Head => l.checkpoints.last(),
                    ExportAt::Digest(digest) => l.checkpoints.iter().find(|c| c.digest == digest),
                }?
                .clone();
                let count = usize::try_from(head.tree_size).unwrap_or(usize::MAX);
                if count > l.events.len() || count > l.checkpoints.len() {
                    return Some(Err(StackError::internal(
                        "trellis ledger rows are fewer than the checkpoint claims",
                    )));
                }
                Some(Ok(ExportRows {
                    events: l.events[..count].to_vec(),
                    checkpoints: l.checkpoints[..count].to_vec(),
                    attachments: within_bound(&l.attachments, head.tree_size),
                    source_content: l.source_contents.get(&(head.tree_size - 1)).cloned(),
                    head,
                }))
            })
            .await?
            .flatten();
        rows.transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_types::merkle::{Frontier, TrellisHasher};

    fn a() -> Scope {
        Scope::fixture("acme", "benefits", Some("prod"))
    }

    fn ledger() -> LedgerScope {
        LedgerScope::of(&a(), "s").unwrap()
    }

    fn pair(sequence: u64, key: &[u8]) -> (StoredEvent, StoredCheckpoint) {
        let mut frontier = Frontier::new();
        for i in 0..=sequence {
            frontier.push(&TrellisHasher, &[i as u8; 32]);
        }
        let scope = ledger().as_bytes().to_vec();
        (
            StoredEvent::with_idempotency_key(
                scope.clone(),
                sequence,
                vec![1],
                vec![2],
                key.to_vec(),
            )
            .with_canonical_event_hash(Some([sequence as u8; 32])),
            StoredCheckpoint {
                scope,
                tree_size: sequence + 1,
                digest: [sequence as u8; 32],
                checkpoint: vec![],
                frontier: frontier.to_bytes(),
                profile_state: vec![],
            },
        )
    }

    #[tokio::test]
    async fn a_dropped_unit_of_work_writes_nothing_and_a_committed_one_is_found_by_key_and_digest()
    {
        let repo = MemoryLedgers::new().scoped(&a());
        let (event, checkpoint) = pair(0, b"k0");
        let mut tx = repo.begin(&ledger()).await.unwrap();
        tx.insert(&event, &checkpoint).await.unwrap();
        drop(tx);
        assert!(repo.head_checkpoint(&ledger()).await.unwrap().is_none());

        let mut tx = repo.begin(&ledger()).await.unwrap();
        tx.insert(&event, &checkpoint).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(repo.last_event(&ledger()).await.unwrap(), Some(event));
        assert_eq!(
            repo.checkpoint_by_digest(&ledger(), &checkpoint.digest)
                .await
                .unwrap(),
            Some(checkpoint)
        );
    }

    #[tokio::test]
    async fn a_second_unit_of_work_on_the_ledger_waits_for_the_first_and_then_sees_its_commit() {
        let repo = MemoryLedgers::new().scoped(&a());
        let first = repo.begin(&ledger()).await.unwrap();
        let waiting = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move { repo.begin(&ledger()).await.unwrap().head().await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the lock is held");
        let (event, checkpoint) = pair(0, b"k0");
        let mut first = first;
        first.insert(&event, &checkpoint).await.unwrap();
        first.commit().await.unwrap();
        assert_eq!(waiting.await.unwrap().map(|h| h.tree_size), Some(1));
    }

    #[tokio::test]
    async fn another_scopes_handle_refuses_the_ledger() {
        let ledgers = MemoryLedgers::new();
        let theirs = ledgers.scoped(&Scope::fixture("globex", "benefits", Some("prod")));
        let refused = theirs.head_checkpoint(&ledger()).await.unwrap_err();
        assert_eq!(refused.status().as_u16(), 404);
        assert!(theirs.begin(&ledger()).await.is_err());
    }
}
