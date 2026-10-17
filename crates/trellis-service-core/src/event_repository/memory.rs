// Rust guideline compliant 2026-02-21
//! In-memory repository for tests and explicitly requested local runs.
//!
//! One mutex guards the whole state and a unit of work holds it from `begin` to its end, which is
//! the in-memory form of the Postgres advisory lock. Writes buffer until `commit`, so dropping a
//! unit of work discards them just as a rollback does.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use tokio::sync::{Mutex, OwnedMutexGuard};
use trellis_types::{StoredCheckpoint, StoredEvent};

use super::{AttachmentRow, EventRepository, ExportRows, ScopeTx, SourceContentBinding};

#[derive(Default)]
struct Ledger {
    events: Vec<StoredEvent>,
    checkpoints: Vec<StoredCheckpoint>,
    by_key: HashMap<Vec<u8>, usize>,
    attachments: Vec<AttachmentRow>,
    source_contents: HashMap<u64, SourceContentBinding>,
}

#[derive(Default)]
struct State {
    scopes: HashMap<Vec<u8>, Ledger>,
}

/// In-memory [`EventRepository`].
#[derive(Default)]
pub struct InMemoryEventRepository {
    state: Arc<Mutex<State>>,
}

impl InMemoryEventRepository {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    async fn read<T>(&self, scope: &[u8], read: impl FnOnce(&Ledger) -> T) -> Option<T> {
        self.state.lock().await.scopes.get(scope).map(read)
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
    scope: Vec<u8>,
    pending: Pending,
}

impl MemoryTx {
    fn ledger(&self) -> Option<&Ledger> {
        self.guard.scopes.get(&self.scope)
    }
}

fn lost_race(what: &str) -> StackError {
    StackError::unavailable(format!(
        "trellis append lost a race on {what}; retry the same key"
    ))
}

#[async_trait]
impl ScopeTx for MemoryTx {
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
        let scope = std::mem::take(&mut self.scope);
        let pending = std::mem::take(&mut self.pending);
        let ledger = self.guard.scopes.entry(scope).or_default();
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

#[async_trait]
impl EventRepository for InMemoryEventRepository {
    async fn begin(&self, scope: &[u8]) -> Result<Box<dyn ScopeTx>, StackError> {
        Ok(Box::new(MemoryTx {
            guard: Arc::clone(&self.state).lock_owned().await,
            scope: scope.to_vec(),
            pending: Pending::default(),
        }))
    }

    async fn head_checkpoint(&self, scope: &[u8]) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(scope, |l| l.checkpoints.last().cloned())
            .await
            .flatten())
    }

    async fn checkpoint_at(
        &self,
        scope: &[u8],
        tree_size: u64,
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(scope, |l| {
                let index = usize::try_from(tree_size.checked_sub(1)?).ok()?;
                l.checkpoints.get(index).cloned()
            })
            .await
            .flatten())
    }

    async fn checkpoint_by_digest(
        &self,
        scope: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<StoredCheckpoint>, StackError> {
        Ok(self
            .read(scope, |l| {
                l.checkpoints.iter().find(|c| &c.digest == digest).cloned()
            })
            .await
            .flatten())
    }

    async fn last_event(&self, scope: &[u8]) -> Result<Option<StoredEvent>, StackError> {
        Ok(self
            .read(scope, |l| l.events.last().cloned())
            .await
            .flatten())
    }

    async fn prefix(&self, scope: &[u8], limit: u64) -> Result<Vec<StoredEvent>, StackError> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(self
            .read(scope, |l| l.events.iter().take(limit).cloned().collect())
            .await
            .unwrap_or_default())
    }

    async fn export_rows(&self, scope: &[u8], tree_size: u64) -> Result<ExportRows, StackError> {
        let count = usize::try_from(tree_size).unwrap_or(usize::MAX);
        let rows = self
            .read(scope, |l| {
                (count <= l.events.len()).then(|| ExportRows {
                    events: l.events[..count].to_vec(),
                    checkpoints: l.checkpoints[..count].to_vec(),
                })
            })
            .await
            .flatten();
        rows.ok_or_else(|| {
            StackError::internal("trellis ledger rows are fewer than the checkpoint claims")
        })
    }

    async fn attachment_by_content_hash(
        &self,
        scope: &[u8],
        content_hash: &[u8; 32],
    ) -> Result<Option<AttachmentRow>, StackError> {
        Ok(self
            .read(scope, |l| {
                l.attachments
                    .iter()
                    .find(|a| a.content_hash == content_hash)
                    .cloned()
            })
            .await
            .flatten())
    }

    async fn source_content(
        &self,
        scope: &[u8],
        sequence: u64,
    ) -> Result<Option<SourceContentBinding>, StackError> {
        Ok(self
            .read(scope, |l| l.source_contents.get(&sequence).cloned())
            .await
            .flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trellis_types::merkle::{Frontier, TrellisHasher};

    fn pair(sequence: u64, key: &[u8]) -> (StoredEvent, StoredCheckpoint) {
        let mut frontier = Frontier::new();
        for i in 0..=sequence {
            frontier.push(&TrellisHasher, &[i as u8; 32]);
        }
        (
            StoredEvent::with_idempotency_key(
                b"s".to_vec(),
                sequence,
                vec![1],
                vec![2],
                key.to_vec(),
            )
            .with_canonical_event_hash(Some([sequence as u8; 32])),
            StoredCheckpoint {
                scope: b"s".to_vec(),
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
        let repo = InMemoryEventRepository::new();
        let (event, checkpoint) = pair(0, b"k0");
        let mut tx = repo.begin(b"s").await.unwrap();
        tx.insert(&event, &checkpoint).await.unwrap();
        drop(tx);
        assert!(repo.head_checkpoint(b"s").await.unwrap().is_none());

        let mut tx = repo.begin(b"s").await.unwrap();
        tx.insert(&event, &checkpoint).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(repo.last_event(b"s").await.unwrap(), Some(event));
        assert_eq!(
            repo.checkpoint_by_digest(b"s", &checkpoint.digest)
                .await
                .unwrap(),
            Some(checkpoint)
        );
    }

    #[tokio::test]
    async fn a_second_unit_of_work_on_the_scope_waits_for_the_first_and_then_sees_its_commit() {
        let repo = Arc::new(InMemoryEventRepository::new());
        let first = repo.begin(b"s").await.unwrap();
        let waiting = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move { repo.begin(b"s").await.unwrap().head().await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the lock is held");
        let (event, checkpoint) = pair(0, b"k0");
        let mut first = first;
        first.insert(&event, &checkpoint).await.unwrap();
        first.commit().await.unwrap();
        assert_eq!(waiting.await.unwrap().map(|h| h.tree_size), Some(1));
    }
}
