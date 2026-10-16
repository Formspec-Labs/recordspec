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
use trellis_server_ports::{ArtifactRef, ArtifactStore, artifact_key_requires_immutable_put};

#[derive(Default)]
pub(crate) struct InMemoryArtifactStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl ArtifactStore for InMemoryArtifactStore {
    type Error = StackError;

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        if artifact_key_requires_immutable_put(key) {
            return Err(StackError::conflict(
                "bundle artifact keys require immutable writes",
            ));
        }
        let uri = format!("memory://trellis/{key}");
        let mut objects = self.objects.lock().await;
        objects.insert(uri.clone(), bytes.to_vec());
        Ok(ArtifactRef::new(uri))
    }

    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<ArtifactRef, Self::Error> {
        let uri = format!("memory://trellis/{key}");
        let mut objects = self.objects.lock().await;
        match objects.get(&uri) {
            Some(existing) if existing == bytes => Ok(ArtifactRef::new(uri)),
            Some(_existing) => Err(StackError::conflict(
                "artifact key already exists with different bytes",
            )),
            None => {
                objects.insert(uri.clone(), bytes.to_vec());
                Ok(ArtifactRef::new(uri))
            }
        }
    }

    async fn get(&self, artifact_ref: &ArtifactRef) -> Result<Option<Vec<u8>>, Self::Error> {
        let objects = self.objects.lock().await;
        Ok(objects.get(&artifact_ref.uri).cloned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BundleRecord {
    pub(crate) checkpoint_digest: String,
    pub(crate) seal_version: u64,
    pub(crate) export_attempt_id: String,
    pub(crate) artifact_ref: ArtifactRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BundleIdentity {
    pub(crate) checkpoint_digest: String,
    pub(crate) seal_version: u64,
    pub(crate) export_attempt_id: String,
}

impl BundleRecord {
    pub(crate) fn identity(&self) -> BundleIdentity {
        BundleIdentity {
            checkpoint_digest: self.checkpoint_digest.clone(),
            seal_version: self.seal_version,
            export_attempt_id: self.export_attempt_id.clone(),
        }
    }
}

#[derive(Default)]
pub(crate) struct BundleIndex {
    records: Mutex<BundleRecords>,
}

#[async_trait]
pub(crate) trait BundleIndexPort: Send + Sync {
    async fn reserve_publishable(
        &self,
        scope: &[u8],
        identity: &BundleIdentity,
    ) -> Result<(), StackError>;

    /// Returns only an already published record for the exact scope/seal.
    async fn get_by_seal(
        &self,
        scope: &[u8],
        seal: u64,
    ) -> Result<Option<BundleRecord>, StackError>;

    async fn get_by_digest(
        &self,
        scope: &[u8],
        checkpoint_digest: &str,
    ) -> Result<Option<BundleRecord>, StackError>;

    async fn insert_published_record(
        &self,
        scope: &[u8],
        record: &BundleRecord,
        update_head: bool,
    ) -> Result<(), StackError>;
}

#[derive(Default)]
struct BundleRecords {
    head: HashMap<Vec<u8>, BundleRecord>,
    by_digest: HashMap<(Vec<u8>, String), BundleRecord>,
    by_seal: HashMap<(Vec<u8>, u64), BundleRecord>,
}

#[async_trait]
impl BundleIndexPort for BundleIndex {
    async fn reserve_publishable(
        &self,
        scope: &[u8],
        identity: &BundleIdentity,
    ) -> Result<(), StackError> {
        let records = self.records.lock().await;
        records.ensure_publishable(scope, identity)
    }

    async fn get_by_seal(
        &self,
        scope: &[u8],
        seal: u64,
    ) -> Result<Option<BundleRecord>, StackError> {
        Ok(self
            .records
            .lock()
            .await
            .by_seal
            .get(&(scope.to_vec(), seal))
            .cloned())
    }

    async fn get_by_digest(
        &self,
        scope: &[u8],
        checkpoint_digest: &str,
    ) -> Result<Option<BundleRecord>, StackError> {
        let records = self.records.lock().await;
        Ok(records
            .by_digest
            .get(&(scope.to_vec(), checkpoint_digest.to_string()))
            .cloned())
    }

    /// Inserts `record` under digest and seal-version indexes, then optionally updates head.
    async fn insert_published_record(
        &self,
        scope: &[u8],
        record: &BundleRecord,
        update_head: bool,
    ) -> Result<(), StackError> {
        let mut records = self.records.lock().await;
        records.ensure_publishable(scope, &record.identity())?;
        records.by_digest.insert(
            (scope.to_vec(), record.checkpoint_digest.clone()),
            record.clone(),
        );
        records
            .by_seal
            .insert((scope.to_vec(), record.seal_version), record.clone());
        if update_head {
            records.head.insert(scope.to_vec(), record.clone());
        }
        Ok(())
    }
}

impl BundleRecords {
    fn ensure_publishable(
        &self,
        scope: &[u8],
        identity: &BundleIdentity,
    ) -> Result<(), StackError> {
        if let Some(existing) = self.by_seal.get(&(scope.to_vec(), identity.seal_version))
            && existing.identity() != *identity
        {
            return Err(StackError::conflict(
                "seal version already published with different bundle identity",
            ));
        }
        if let Some(existing) = self
            .by_digest
            .get(&(scope.to_vec(), identity.checkpoint_digest.clone()))
            && existing.identity() != *identity
        {
            return Err(StackError::conflict(
                "checkpoint digest already published with different bundle identity",
            ));
        }
        Ok(())
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

    /// Given an in-memory artifact store, when an immutable key is written twice with the
    /// same bytes and then different bytes, then the identical write is reused and the
    /// changed write conflicts without replacing the original object.
    #[tokio::test]
    async fn given_in_memory_artifact_store_when_immutable_put_conflicts_then_original_stays() {
        let store = InMemoryArtifactStore::default();
        let first = store
            .put_immutable("scope/export.zip", b"sealed bytes")
            .await
            .expect("first immutable put");
        let second = store
            .put_immutable("scope/export.zip", b"sealed bytes")
            .await
            .expect("second immutable put");
        assert_eq!(first, second);

        let error = store
            .put_immutable("scope/export.zip", b"changed bytes")
            .await
            .expect_err("different immutable bytes must conflict");
        assert_eq!(error.code().as_str(), "INFRA-4090");
        let got = store.get(&first).await.expect("get").expect("object bytes");
        assert_eq!(got, b"sealed bytes");
    }

    /// Given an in-memory artifact store, when a caller uses mutable put for a bundle key,
    /// then the store rejects the write so checkpoint ZIP keys stay on the immutable path.
    #[tokio::test]
    async fn given_in_memory_artifact_store_when_plain_put_for_bundle_key_then_conflict() {
        let store = InMemoryArtifactStore::default();

        let error = store
            .put("scope/bundles/deadbeef.zip", b"sealed bytes")
            .await
            .expect_err("plain put must not write bundle keys");

        assert_eq!(error.code().as_str(), "INFRA-4090");
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
            seal_version: 1,
            export_attempt_id: "sha256:attempt".to_string(),
            artifact_ref: ArtifactRef::new("memory://trellis/case_scope/bundles/deadbeef.zip"),
        };
        idx.insert_published_record(scope, &record, true)
            .await
            .expect("insert bundle record");
        let records = idx.records.lock().await;
        let from_digest = records
            .by_digest
            .get(&(scope.to_vec(), digest.clone()))
            .cloned();
        let from_seal = records.by_seal.get(&(scope.to_vec(), 1)).cloned();
        let from_head = records.head.get(scope.as_slice()).cloned();
        assert_eq!(from_digest, Some(record.clone()));
        assert_eq!(from_seal, Some(record.clone()));
        assert_eq!(from_head, Some(record));
    }

    /// Given a bundle index, when a seal version already points at different bundle identity,
    /// then insertion rejects so retries cannot silently retarget an export identity.
    #[tokio::test]
    async fn given_bundle_index_when_seal_version_conflicts_then_rejects() {
        let idx = BundleIndex::default();
        let scope = b"case_scope";
        let first = BundleRecord {
            checkpoint_digest: "sha256:first".to_string(),
            seal_version: 1,
            export_attempt_id: "sha256:attempt-one".to_string(),
            artifact_ref: ArtifactRef::new("memory://trellis/case_scope/bundles/first.zip"),
        };
        let second = BundleRecord {
            checkpoint_digest: "sha256:second".to_string(),
            seal_version: 1,
            export_attempt_id: "sha256:attempt-two".to_string(),
            artifact_ref: ArtifactRef::new("memory://trellis/case_scope/bundles/second.zip"),
        };

        idx.insert_published_record(scope, &first, true)
            .await
            .expect("first insert");
        let error = idx
            .insert_published_record(scope, &second, true)
            .await
            .expect_err("conflicting seal identity must reject");

        assert_eq!(error.code().as_str(), "INFRA-4090");
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
    #[tokio::test]
    async fn if034_062_memory_published_seal_lookup_uses_exact_scope_and_seal() {
        let index = BundleIndex::default();
        let identity = BundleIdentity {
            checkpoint_digest: "sha256:controlled".into(),
            seal_version: 7,
            export_attempt_id: "sha256:controlled-attempt".into(),
        };
        index
            .reserve_publishable(b"scope", &identity)
            .await
            .unwrap();
        assert!(index.get_by_seal(b"scope", 7).await.unwrap().is_none());
        let record = BundleRecord {
            checkpoint_digest: identity.checkpoint_digest,
            seal_version: 7,
            export_attempt_id: identity.export_attempt_id,
            artifact_ref: ArtifactRef::new("memory://controlled"),
        };
        index
            .insert_published_record(b"scope", &record, true)
            .await
            .unwrap();
        assert_eq!(index.get_by_seal(b"scope", 7).await.unwrap(), Some(record));
        assert!(index.get_by_seal(b"foreign", 7).await.unwrap().is_none());
        assert!(index.get_by_seal(b"scope", 8).await.unwrap().is_none());
    }
}
