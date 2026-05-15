// Rust guideline compliant 2026-02-21
//! In-memory artifact storage, materialized bundle index, and per-scope append locks.
//!
//! HTTP handlers and [`crate::TrellisServerState`] compose these pieces; append serialization
//! uses [`ScopeLocks`] so concurrent posts to the same scope do not interleave repository reads
//! and commits.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use tokio::sync::{Mutex, OwnedMutexGuard};
use trellis_server_ports::{ArtifactRef, ArtifactStore};

#[derive(Default)]
pub(crate) struct InMemoryArtifactStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl ArtifactStore for InMemoryArtifactStore {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        let uri = format!("memory://trellis/{key}");
        let mut objects = self.objects.lock().await;
        objects.insert(uri.clone(), bytes.to_vec());
        Ok(ArtifactRef::new(uri))
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        let objects = self.objects.lock().await;
        Ok(objects.get(&artifact_ref.uri).cloned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BundleRecord {
    pub(crate) checkpoint_digest: String,
    pub(crate) artifact_ref: ArtifactRef,
}

#[derive(Default)]
pub(crate) struct BundleIndex {
    pub(crate) head: Mutex<HashMap<Vec<u8>, BundleRecord>>,
    pub(crate) by_digest: Mutex<HashMap<(Vec<u8>, String), BundleRecord>>,
}

impl BundleIndex {
    /// Inserts `record` under `(scope, checkpoint_digest)` and optionally updates the scope head.
    pub(crate) async fn insert_published_record(
        &self,
        scope: &[u8],
        record: &BundleRecord,
        update_head: bool,
    ) {
        {
            let mut by_digest = self.by_digest.lock().await;
            by_digest.insert(
                (scope.to_vec(), record.checkpoint_digest.clone()),
                record.clone(),
            );
        }
        if update_head {
            let mut head = self.head.lock().await;
            head.insert(scope.to_vec(), record.clone());
        }
    }
}

#[derive(Default)]
pub(crate) struct ScopeLocks {
    locks: Mutex<HashMap<Vec<u8>, Arc<Mutex<()>>>>,
}

impl ScopeLocks {
    pub(crate) async fn lock(&self, scope: &[u8]) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(scope.to_vec())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Given the default in-memory artifact store, when bytes are written and read back by ref,
    /// then the payload round-trips without loss (guards extraction of [`InMemoryArtifactStore`]).
    #[tokio::test]
    async fn given_in_memory_artifact_store_when_put_get_roundtrip_then_bytes_match() {
        let store = InMemoryArtifactStore::default();
        let artifact_ref = store.put("scope/k", &[7u8, 8, 9]).await.expect("put");
        let got = store.get(&artifact_ref).await.expect("get");
        assert_eq!(got.as_deref(), Some(&[7u8, 8, 9][..]));
    }

    /// Given a bundle index, when a published record is inserted via [`BundleIndex::insert_published_record`],
    /// then head and by-digest maps return the identical record (guards production index wiring).
    #[tokio::test]
    async fn given_bundle_index_when_record_inserted_then_head_and_by_digest_resolve() {
        let idx = BundleIndex::default();
        let scope = b"case_scope";
        let digest = "sha256:deadbeef".to_string();
        let record = BundleRecord {
            checkpoint_digest: digest.clone(),
            artifact_ref: ArtifactRef::new("memory://trellis/case_scope/bundles/deadbeef.zip"),
        };
        idx.insert_published_record(scope, &record, true).await;
        let from_digest = idx
            .by_digest
            .lock()
            .await
            .get(&(scope.to_vec(), digest.clone()))
            .cloned();
        let from_head = idx.head.lock().await.get(scope.as_slice()).cloned();
        assert_eq!(from_digest, Some(record.clone()));
        assert_eq!(from_head, Some(record));
    }

    /// Given per-scope locks, when the same scope is locked twice in sequence,
    /// then the second guard acquires only after the first is dropped (serialization invariant).
    #[tokio::test]
    async fn given_scope_locks_when_same_scope_locked_sequentially_then_second_after_first_drop() {
        let locks = ScopeLocks::default();
        let scope = b"serial_scope";
        {
            let _first = locks.lock(scope).await;
        }
        let _second = locks.lock(scope).await;
    }

    /// Given two concurrent tasks for one scope, when both take the per-scope lock around a critical section,
    /// then at most one task holds the section at a time (append-path serialization).
    #[tokio::test]
    async fn given_scope_locks_when_two_tasks_same_scope_then_critical_section_serializes() {
        let locks = Arc::new(ScopeLocks::default());
        let scope = b"parallel_scope";
        let holders = Arc::new(AtomicUsize::new(0));

        let first = {
            let locks = locks.clone();
            let holders = holders.clone();
            tokio::spawn(async move {
                let _guard = locks.lock(scope).await;
                let prev = holders.fetch_add(1, Ordering::SeqCst);
                assert_eq!(prev, 0, "second task must not enter while first holds lock");
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                holders.fetch_sub(1, Ordering::SeqCst);
            })
        };

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let second = {
            let locks = locks.clone();
            let holders = holders.clone();
            tokio::spawn(async move {
                let _guard = locks.lock(scope).await;
                let prev = holders.fetch_add(1, Ordering::SeqCst);
                assert_eq!(prev, 0, "second task must not enter while first holds lock");
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                holders.fetch_sub(1, Ordering::SeqCst);
            })
        };

        first.await.expect("first task");
        second.await.expect("second task");
    }
}
