// Rust guideline compliant 2026-02-21
//! In-memory artifact storage for tests and explicitly requested local runs.

use std::collections::HashMap;

use async_trait::async_trait;
use stack_common_error::StackError;
use tokio::sync::Mutex;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Given the default in-memory artifact store, when bytes are written and read back by ref,
    /// then the payload round-trips without loss.
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
}
