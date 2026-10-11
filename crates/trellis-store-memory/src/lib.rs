// Rust guideline compliant 2026-02-21
//! In-memory `LedgerStore` for the Phase-1 append scaffold and conformance corpus.
//!
//! Provides a parity surface to the async Postgres adapter: a buffered
//! "transaction" type and an [`append_event_in_tx`] free function so
//! conformance / cross-store parity tests can target both stores through
//! the same composition shape (canonical write + caller-supplied side
//! effects atomically committed or discarded).

#![forbid(unsafe_code)]

use std::convert::Infallible;

use trellis_core::LedgerStore;
use trellis_types::{StoredEvent, idempotency_key_length_in_bound};

pub use trellis_types::IDEMPOTENCY_KEY_MAX_LEN;

/// Stores appended events in memory for conformance tests.
#[derive(Default, Debug)]
pub struct MemoryStore {
    events: Vec<StoredEvent>,
}

impl MemoryStore {
    /// Creates an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all stored events in append order.
    pub fn events(&self) -> &[StoredEvent] {
        &self.events
    }

    /// Begins a buffered "transaction" against this store.
    ///
    /// The returned [`MemoryTransaction`] buffers events; callers issue
    /// [`append_event_in_tx`] against it (and optionally their own side
    /// effects), then call [`MemoryTransaction::commit`] to flush. Drop
    /// without commit discards the buffer — the parity surface for
    /// `trellis_store_postgres_async::append_event_in_tx` rollback semantics.
    pub fn begin(&mut self) -> MemoryTransaction<'_> {
        MemoryTransaction {
            store: self,
            buffered: Vec::new(),
            committed: false,
        }
    }
}

/// Buffered transaction over [`MemoryStore`].
///
/// On [`Self::commit`] the buffered events flush to the store; on drop
/// without commit the buffer discards. Mirrors the rollback-on-drop
/// semantic of `postgres::Transaction`.
pub struct MemoryTransaction<'a> {
    store: &'a mut MemoryStore,
    buffered: Vec<StoredEvent>,
    committed: bool,
}

impl<'a> MemoryTransaction<'a> {
    /// Number of events buffered (not yet committed).
    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    /// Commits buffered events to the underlying store.
    ///
    /// Returns `Result<(), Infallible>` for parity with
    /// `postgres::Transaction::commit() -> Result<(), postgres::Error>`:
    /// cross-store generic test bodies can share `tx.commit()?` across both
    /// adapters. The `Infallible` arm encodes statically that this in-memory
    /// path cannot fail; callers can `.unwrap()` or `?`-chain identically.
    ///
    /// # Errors
    /// Never fails. The `Result` shape is for parity only.
    pub fn commit(mut self) -> Result<(), Infallible> {
        self.store.events.extend(std::mem::take(&mut self.buffered));
        self.committed = true;
        Ok(())
    }
}

impl Drop for MemoryTransaction<'_> {
    fn drop(&mut self) {
        // Uncommitted buffer drops on the floor — explicit rollback semantic.
        if !self.committed {
            self.buffered.clear();
        }
    }
}

/// Appends one event into the supplied buffered transaction.
///
/// Parity counterpart to `trellis_store_postgres_async::append_event_in_tx` so
/// cross-store composition tests can write a single generic body. The
/// `idempotency_key` parameter is accepted for shape parity; memory
/// enforces only the Core §6.1 length bound and reports a duplicate
/// `(scope, key)` collision through [`MemoryAppendError::IdempotencyKeyConflict`].
///
/// # Errors
/// - [`MemoryAppendError::IdempotencyKeyTooLong`] when `key` violates the
///   Core §6.1 `bstr .size (1..64)` bound.
/// - [`MemoryAppendError::IdempotencyKeyConflict`] when `(scope, key)`
///   collides with a previously-committed event in the underlying store
///   or a buffered event in the same transaction.
pub fn append_event_in_tx(
    tx: &mut MemoryTransaction<'_>,
    event: &StoredEvent,
    idempotency_key: Option<&[u8]>,
) -> Result<(), MemoryAppendError> {
    if let Some(key) = idempotency_key {
        if !idempotency_key_length_in_bound(key) {
            return Err(MemoryAppendError::IdempotencyKeyTooLong(key.len()));
        }
        if let Some(existing) = tx
            .store
            .events
            .iter()
            .chain(tx.buffered.iter())
            .find(|stored| stored.scope() == event.scope() && stored_key(stored) == Some(key))
        {
            return resolve_memory_collision(existing, event);
        }
    }

    if event.canonical_event_hash().is_some() && event.sequence() > 0 {
        let predecessor_seq = event.sequence() - 1;
        let has_predecessor = tx
            .store
            .events
            .iter()
            .chain(tx.buffered.iter())
            .any(|stored| stored.scope() == event.scope() && stored.sequence() == predecessor_seq);
        if !has_predecessor {
            return Err(MemoryAppendError::SequenceGap);
        }
    }

    let to_store = match idempotency_key {
        Some(key) => {
            let mut ev = StoredEvent::with_idempotency_key(
                event.scope().to_vec(),
                event.sequence(),
                event.canonical_event().to_vec(),
                event.signed_event().to_vec(),
                key.to_vec(),
            );
            ev = ev.with_canonical_event_hash(event.canonical_event_hash().copied());
            ev
        }
        None => event.clone(),
    };
    tx.buffered.push(to_store);
    Ok(())
}

/// Core §17.3 collision resolution for the in-memory store.
///
/// - Byte-identical payloads → idempotent no-op per §17.3 clauses 1+2.
/// - Different payloads → `IdempotencyKeyConflict` per §17.3 clause 3.
fn resolve_memory_collision(
    existing: &StoredEvent,
    incoming: &StoredEvent,
) -> Result<(), MemoryAppendError> {
    if existing.canonical_event() == incoming.canonical_event()
        && existing.signed_event() == incoming.signed_event()
    {
        Ok(())
    } else {
        Err(MemoryAppendError::IdempotencyKeyConflict)
    }
}

/// Failure cases for [`append_event_in_tx`].
#[derive(Debug, PartialEq, Eq)]
pub enum MemoryAppendError {
    IdempotencyKeyTooLong(usize),
    IdempotencyKeyConflict,
    SequenceGap,
}

impl std::fmt::Display for MemoryAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdempotencyKeyTooLong(n) => {
                write!(
                    f,
                    "idempotency_key length {n} outside Core §6.1 bound 1..=64"
                )
            }
            Self::IdempotencyKeyConflict => write!(
                f,
                "Core §17.3 idempotency-key conflict on (ledger_scope, idempotency_key)"
            ),
            Self::SequenceGap => write!(
                f,
                "sequence gap: no predecessor at sequence - 1 for non-genesis append"
            ),
        }
    }
}

impl std::error::Error for MemoryAppendError {}

/// Reads the Core §6.1 `idempotency_key` from the threaded `StoredEvent`.
fn stored_key(stored: &StoredEvent) -> Option<&[u8]> {
    stored.idempotency_key()
}

impl LedgerStore for MemoryStore {
    type Error = MemoryAppendError;

    fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
        // Compose the `LedgerStore` trait method through the buffered-tx
        // surface so the §6.1 length bound and the §17.3 unique-`(scope,
        // key)` collision check both fire against the same code path
        // exercised by `append_event_in_tx`.
        let key = event.idempotency_key().map(<[u8]>::to_vec);
        let mut tx = self.begin();
        append_event_in_tx(&mut tx, &event, key.as_deref())?;
        // `MemoryTransaction::commit` returns `Result<(), Infallible>`;
        // the `?` here is structurally unreachable but kept for parity with
        // `trellis-store-postgres-async`.
        let _ = tx.commit();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_append_event_path_persists() {
        let mut store = MemoryStore::new();
        store
            .append_event(StoredEvent::new(
                b"scope".to_vec(),
                0,
                vec![0x01],
                vec![0x02],
            ))
            .unwrap();
        assert_eq!(store.events().len(), 1);
    }

    #[test]
    fn buffered_transaction_commits_events() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]),
            None,
        )
        .unwrap();
        assert_eq!(tx.buffered_len(), 1);
        tx.commit().unwrap();
        assert_eq!(store.events().len(), 1);
    }

    #[test]
    fn buffered_transaction_rolls_back_on_drop() {
        let mut store = MemoryStore::new();
        {
            let mut tx = store.begin();
            append_event_in_tx(
                &mut tx,
                &StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]),
                None,
            )
            .unwrap();
            // Drop without commit — events MUST NOT land.
        }
        assert!(store.events().is_empty(), "uncommitted tx leaked events");
    }

    /// Pins the parity rationale for the `Result<(), Infallible>` return:
    /// a generic test body can `?`-chain `tx.commit()` and the shape works
    /// against both this adapter and `trellis-store-postgres-async` whose
    /// `Transaction::commit` returns `Result<(), sqlx::Error>`.
    #[test]
    fn commit_supports_question_mark_chaining() {
        fn drive(store: &mut MemoryStore) -> Result<(), Infallible> {
            let mut tx = store.begin();
            append_event_in_tx(
                &mut tx,
                &StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]),
                None,
            )
            .unwrap();
            tx.commit()?;
            Ok(())
        }

        let mut store = MemoryStore::new();
        drive(&mut store).unwrap();
        assert_eq!(store.events().len(), 1);
    }

    #[test]
    fn idempotency_key_too_long_rejected() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        let oversize = vec![0u8; IDEMPOTENCY_KEY_MAX_LEN + 1];
        let err = append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"s".to_vec(), 0, vec![], vec![]),
            Some(&oversize),
        )
        .unwrap_err();
        assert_eq!(err, MemoryAppendError::IdempotencyKeyTooLong(65));

        let empty: Vec<u8> = Vec::new();
        let err = append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"s".to_vec(), 0, vec![], vec![]),
            Some(&empty),
        )
        .unwrap_err();
        assert_eq!(err, MemoryAppendError::IdempotencyKeyTooLong(0));
    }

    #[test]
    fn idempotency_key_boundary_lengths_accepted() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope-1b".to_vec(), 0, vec![], vec![]),
            Some(&[0xab]),
        )
        .unwrap();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope-64b".to_vec(), 0, vec![], vec![]),
            Some(&[0x55_u8; 64]),
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(store.events().len(), 2);
    }

    /// TR-CORE-159: idempotent replay with byte-identical payload returns Ok(()).
    /// Core §17.3 clauses 1+2 — same canonical reference, no duplicate position.
    #[test]
    fn idempotent_replay_byte_identical_payload_is_noop() {
        let mut store = MemoryStore::new();

        let event = StoredEvent::new(b"scope-replay".to_vec(), 0, vec![0xaa], vec![0xbb]);
        let key = b"replay-key".to_vec();
        let mut tx = store.begin();
        append_event_in_tx(&mut tx, &event, Some(&key)).unwrap();
        tx.commit().unwrap();

        let mut tx2 = store.begin();
        append_event_in_tx(&mut tx2, &event, Some(&key)).unwrap();
        tx2.commit().unwrap();

        assert_eq!(
            store.events().len(),
            1,
            "idempotent replay MUST NOT create a second order position"
        );
    }

    /// TR-CORE-160: idempotent replay with different payload returns
    /// IdempotencyKeyConflict. Core §17.3 clause 3.
    #[test]
    fn idempotent_replay_different_payload_returns_conflict() {
        let mut store = MemoryStore::new();

        let event_a = StoredEvent::new(b"scope-mm".to_vec(), 0, vec![0x01], vec![0x02]);
        let key = b"mm-key".to_vec();
        let mut tx = store.begin();
        append_event_in_tx(&mut tx, &event_a, Some(&key)).unwrap();
        tx.commit().unwrap();

        let event_b = StoredEvent::new(b"scope-mm".to_vec(), 1, vec![0x03], vec![0x04]);
        let mut tx2 = store.begin();
        let err = append_event_in_tx(&mut tx2, &event_b, Some(&key)).unwrap_err();
        assert_eq!(err, MemoryAppendError::IdempotencyKeyConflict);
    }

    #[test]
    fn chain_validation_genesis_succeeds_without_predecessor() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]),
            None,
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(store.events().len(), 1);
    }

    #[test]
    fn chain_validation_rejects_sequence_gap() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        let err = append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope".to_vec(), 5, vec![0x01], vec![0x02])
                .with_canonical_event_hash(Some([0xaa; 32])),
            None,
        )
        .unwrap_err();
        assert_eq!(err, MemoryAppendError::SequenceGap);
    }

    #[test]
    fn chain_validation_contiguous_sequences_succeed() {
        let mut store = MemoryStore::new();
        let mut tx = store.begin();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope".to_vec(), 0, vec![0x01], vec![0x02]),
            None,
        )
        .unwrap();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"scope".to_vec(), 1, vec![0x03], vec![0x04]),
            None,
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(store.events().len(), 2);
    }
}

/// Atomic in-memory native external attachment retention.
pub mod external_attachment;
