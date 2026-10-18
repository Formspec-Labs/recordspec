// Rust guideline compliant 2026-02-21
//! Behaviour of the checkpointed ledger rows against a real Postgres, through the scoped port.

mod support;

use std::sync::Arc;
use std::time::Duration;

use stack_common_scope::Scope;
use trellis_server_ports::{ExportAt, LedgerScope, Ledgers, ScopedLedgers, SourceContentBinding};
use trellis_store_postgres_async::{self as store, AppendError, PgLedgers};
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

fn hash(tag: u8, sequence: u64) -> [u8; 32] {
    let mut out = [tag; 32];
    out[..8].copy_from_slice(&sequence.to_be_bytes());
    out
}

fn ledger(scope: &Scope, id: &str) -> LedgerScope {
    LedgerScope::of(scope, id).unwrap()
}

/// An event and the checkpoint a service would write with it: ledger of `sequence + 1` leaves.
fn pair(ledger: &LedgerScope, sequence: u64, key: &[u8]) -> (StoredEvent, StoredCheckpoint) {
    let mut frontier = Frontier::new();
    for i in 0..=sequence {
        frontier.push(&TrellisHasher, &hash(1, i));
    }
    let event = StoredEvent::with_idempotency_key(
        ledger.as_bytes().to_vec(),
        sequence,
        format!("canonical-{sequence}").into_bytes(),
        format!("signed-{sequence}").into_bytes(),
        key.to_vec(),
    )
    .with_canonical_event_hash(Some(hash(2, sequence)));
    let checkpoint = StoredCheckpoint {
        scope: ledger.as_bytes().to_vec(),
        tree_size: sequence + 1,
        digest: hash(3, sequence),
        checkpoint: format!("sign1-{sequence}").into_bytes(),
        frontier: frontier.to_bytes(),
        profile_state: b"state".to_vec(),
    };
    (event, checkpoint)
}

fn ledgers(db: &support::Database, scope: &Scope) -> Arc<dyn ScopedLedgers> {
    PgLedgers::new(db.scoped.clone()).scoped(scope)
}

async fn commit(ledgers: &dyn ScopedLedgers, event: &StoredEvent, checkpoint: &StoredCheckpoint) {
    let ledger =
        LedgerScope::within(&support::a(), std::str::from_utf8(event.scope()).unwrap()).unwrap();
    let mut tx = ledgers.begin(&ledger).await.unwrap();
    tx.insert(event, checkpoint).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn an_event_and_its_checkpoint_commit_together_and_read_back() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-a");
    let (event, checkpoint) = pair(&one, 0, b"key-0");
    commit(a.as_ref(), &event, &checkpoint).await;

    assert_eq!(a.last_event(&one).await.unwrap(), Some(event.clone()));
    let mut tx = a.begin(&one).await.unwrap();
    assert_eq!(tx.event_by_key(b"key-0").await.unwrap(), Some(event));
    assert_eq!(tx.event_by_key(b"missing").await.unwrap(), None);
    drop(tx);
    assert_eq!(
        a.head_checkpoint(&one).await.unwrap(),
        Some(checkpoint.clone())
    );
    assert_eq!(
        a.checkpoint_at(&one, 1).await.unwrap(),
        Some(checkpoint.clone())
    );
    assert_eq!(
        a.checkpoint_by_digest(&one, &checkpoint.digest)
            .await
            .unwrap(),
        Some(checkpoint)
    );
    assert_eq!(
        a.head_checkpoint(&ledger(&support::a(), "other"))
            .await
            .unwrap(),
        None
    );
}

/// The same ledger id under another scope is another ledger, and a scope's handle refuses a
/// ledger scope minted under another scope before it runs any SQL.
#[tokio::test]
async fn another_scope_neither_sees_nor_reaches_a_scopes_ledger() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let b = ledgers(&db, &support::b());
    let ours = ledger(&support::a(), "case-1");
    let (event, checkpoint) = pair(&ours, 0, b"key-0");
    commit(a.as_ref(), &event, &checkpoint).await;

    let theirs = ledger(&support::b(), "case-1");
    assert_eq!(b.head_checkpoint(&theirs).await.unwrap(), None);
    assert!(b.export(&theirs, ExportAt::Head).await.unwrap().is_none());
    for refused in [
        b.head_checkpoint(&ours).await.map(|_| ()),
        b.last_event(&ours).await.map(|_| ()),
        b.begin(&ours).await.map(|_| ()),
    ] {
        assert_eq!(refused.unwrap_err().status().as_u16(), 404);
    }
}

#[tokio::test]
async fn the_head_is_the_highest_tree_size_and_ranges_come_back_in_order() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let six = ledger(&support::a(), "case-b");
    for i in 0..6 {
        let (event, checkpoint) = pair(&six, i, format!("key-{i}").as_bytes());
        commit(a.as_ref(), &event, &checkpoint).await;
    }
    let other = ledger(&support::a(), "case-c");
    let (event, checkpoint) = pair(&other, 0, b"key-0");
    commit(a.as_ref(), &event, &checkpoint).await;

    let head = a.head_checkpoint(&six).await.unwrap().unwrap();
    assert_eq!(head.tree_size, 6);
    assert_eq!(
        head.frontier().unwrap().size(),
        6,
        "the stored frontier decodes at its tree size"
    );
    assert_eq!(a.last_event(&six).await.unwrap().unwrap().sequence(), 5);
    assert_eq!(
        a.prefix(&six, 2).await.unwrap().len(),
        2,
        "limit bounds the read"
    );

    let at_four = a.checkpoint_at(&six, 4).await.unwrap().unwrap();
    let rows = a
        .export(&six, ExportAt::Digest(at_four.digest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rows.head, at_four);
    assert_eq!(
        rows.events
            .iter()
            .map(StoredEvent::sequence)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(
        rows.checkpoints
            .iter()
            .map(|c| c.tree_size)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(
        a.export(&six, ExportAt::Head)
            .await
            .unwrap()
            .unwrap()
            .head
            .tree_size,
        6
    );
    sqlx::query("DELETE FROM trellis_events WHERE scope = $1 AND sequence = 2")
        .bind(six.as_bytes())
        .execute(&db.owner)
        .await
        .unwrap();
    assert!(
        a.export(&six, ExportAt::Head).await.is_err(),
        "rows the head claims are missing"
    );
}

#[tokio::test]
async fn a_dropped_unit_of_work_leaves_neither_event_nor_checkpoint() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-d");
    let (event, checkpoint) = pair(&one, 0, b"key-0");
    let mut tx = a.begin(&one).await.unwrap();
    tx.insert(&event, &checkpoint).await.unwrap();
    drop(tx);
    assert_eq!(a.last_event(&one).await.unwrap(), None);
    assert_eq!(a.head_checkpoint(&one).await.unwrap(), None);
}

#[tokio::test]
async fn a_taken_sequence_key_or_digest_is_a_retryable_race_that_writes_nothing() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-e");
    let (event, checkpoint) = pair(&one, 0, b"key-0");
    commit(a.as_ref(), &event, &checkpoint).await;

    let (same_key, mut same_key_cp) = pair(&one, 1, b"key-0");
    same_key_cp.digest = hash(9, 1);
    let (same_sequence, same_sequence_cp) = pair(&one, 0, b"key-other");
    let (next, mut same_digest) = pair(&one, 1, b"key-1");
    same_digest.digest = checkpoint.digest;
    for (event, checkpoint) in [
        (same_key, same_key_cp),
        (same_sequence, same_sequence_cp),
        (next, same_digest),
    ] {
        let mut tx = a.begin(&one).await.unwrap();
        let error = tx.insert(&event, &checkpoint).await.unwrap_err();
        assert_eq!(error.status().as_u16(), 503, "{error}");
        assert!(error.to_string().contains("retry the same key"), "{error}");
    }
    assert_eq!(a.last_event(&one).await.unwrap().unwrap().sequence(), 0);
}

#[tokio::test]
async fn a_checkpoint_that_does_not_describe_its_event_is_refused_before_any_write() {
    let db = support::database(4).await;
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    let one = ledger(&support::a(), "case-f");
    let (event, checkpoint) = pair(&one, 2, b"key-2");

    let mut wrong_size = checkpoint.clone();
    wrong_size.tree_size = 9;
    assert!(matches!(
        store::append_checkpointed(&mut tx, &event, &wrong_size).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let mut wrong_frontier = checkpoint.clone();
    wrong_frontier.frontier.truncate(32);
    assert!(matches!(
        store::append_checkpointed(&mut tx, &event, &wrong_frontier).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let unhashed = StoredEvent::with_idempotency_key(
        one.as_bytes().to_vec(),
        2,
        vec![1],
        vec![2],
        b"k".to_vec(),
    );
    assert!(matches!(
        store::append_checkpointed(&mut tx, &unhashed, &checkpoint).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let long_key = StoredEvent::with_idempotency_key(
        one.as_bytes().to_vec(),
        2,
        vec![1],
        vec![2],
        vec![7; 65],
    )
    .with_canonical_event_hash(Some([1; 32]));
    assert!(matches!(
        store::append_checkpointed(&mut tx, &long_key, &checkpoint).await,
        Err(AppendError::IdempotencyKeyTooLong(65))
    ));
}

/// A unit of work writes only the ledger it locked.
#[tokio::test]
async fn a_unit_of_work_refuses_a_row_of_another_ledger() {
    let db = support::database(2).await;
    let a = ledgers(&db, &support::a());
    let locked = ledger(&support::a(), "case-locked");
    let (event, checkpoint) = pair(&ledger(&support::a(), "case-other"), 0, b"key-0");
    let mut tx = a.begin(&locked).await.unwrap();
    assert_eq!(
        tx.insert(&event, &checkpoint)
            .await
            .unwrap_err()
            .status()
            .as_u16(),
        500
    );
}

#[tokio::test]
async fn the_schema_itself_refuses_a_frontier_that_is_not_popcount_hashes() {
    let db = support::database(1).await;
    let error = sqlx::query(
        "INSERT INTO trellis_checkpoints \
         (scope_key, scope, tree_size, digest, checkpoint, frontier, profile_state) \
         VALUES ($1, $2, 3, $3, $4, $5, $6)",
    )
    .bind(support::a().key().as_bytes().as_slice())
    .bind(b"scope-g".as_slice())
    .bind([5u8; 32].as_slice())
    .bind(b"sign1".as_slice())
    .bind([0u8; 32].as_slice())
    .bind(b"".as_slice())
    .execute(&db.owner)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
}

#[tokio::test]
async fn a_second_appender_waits_for_the_ledger_lock_and_then_sees_the_first_commit() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-h");
    let first = tokio::spawn({
        let a = Arc::clone(&a);
        let one = one.clone();
        async move {
            let mut tx = a.begin(&one).await.unwrap();
            let (event, checkpoint) = pair(&one, 0, b"key-0");
            tokio::time::sleep(Duration::from_millis(300)).await;
            tx.insert(&event, &checkpoint).await.unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Begins while the first holds the lock; its first read must already see the commit.
    let mut tx = a.begin(&one).await.unwrap();
    assert_eq!(tx.head().await.unwrap().map(|h| h.tree_size), Some(1));
    drop(tx);
    first.await.unwrap();
}

#[tokio::test]
async fn a_source_content_binding_belongs_to_exactly_one_event() {
    let db = support::database(4).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-i");
    let (event, checkpoint) = pair(&one, 0, b"key-0");
    let binding = SourceContentBinding {
        batch_hash: [8; 32],
        size: 77,
        artifact_ref: "memory://batch".to_owned(),
    };
    let mut tx = a.begin(&one).await.unwrap();
    tx.insert(&event, &checkpoint).await.unwrap();
    tx.insert_source_content(0, &binding).await.unwrap();
    assert_eq!(
        tx.insert_source_content(0, &binding)
            .await
            .unwrap_err()
            .status()
            .as_u16(),
        503
    );
    drop(tx);
    assert!(a.export(&one, ExportAt::Head).await.unwrap().is_none());

    let mut tx = a.begin(&one).await.unwrap();
    tx.insert(&event, &checkpoint).await.unwrap();
    tx.insert_source_content(0, &binding).await.unwrap();
    tx.commit().await.unwrap();
    let first = a.export(&one, ExportAt::Head).await.unwrap().unwrap();
    assert_eq!(first.source_content, Some(binding.clone()));

    // The binding rides only an export that ends at its event.
    let (event, checkpoint) = pair(&one, 1, b"key-1");
    commit(a.as_ref(), &event, &checkpoint).await;
    let head = a.export(&one, ExportAt::Head).await.unwrap().unwrap();
    assert_eq!(head.source_content, None);
    let pinned = a
        .export(&one, ExportAt::Digest(first.head.digest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pinned.source_content, Some(binding));
}

/// A pool whose connections default to `REPEATABLE READ` would let a waiter's first read see the
/// snapshot from before the lock was granted, and an append would miss the head the lock holder
/// just committed. `lock_ledger` overrides the default before the first read.
#[tokio::test]
async fn a_unit_of_work_reads_the_latest_commit_even_when_the_pool_defaults_to_repeatable_read() {
    let db = support::database(2).await;
    // Hold both connections while setting their session default, so the unit of work cannot be
    // handed a fresh, unconfigured one.
    let mut held = vec![
        db.app.acquire().await.unwrap(),
        db.app.acquire().await.unwrap(),
    ];
    for connection in &mut held {
        sqlx::query("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut **connection)
            .await
            .unwrap();
    }
    drop(held);

    let one = ledger(&support::a(), "case-rr");
    let writer = tokio::spawn({
        let scoped = db.scoped.clone();
        let one = one.clone();
        async move {
            let mut tx = scoped.begin(&support::a()).await.unwrap();
            store::lock_ledger(&mut tx, one.as_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let (event, checkpoint) = pair(&one, 0, b"key-0");
            store::append_checkpointed(&mut tx, &event, &checkpoint)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    store::lock_ledger(&mut tx, one.as_bytes()).await.unwrap();
    let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(isolation, "read committed");
    assert_eq!(
        store::head_checkpoint(&mut tx, one.as_bytes())
            .await
            .unwrap()
            .map(|head| head.tree_size),
        Some(1)
    );
    drop(tx);
    writer.await.unwrap();
}

/// An export reads attachment bodies only up to its bound: through the first that crosses the
/// byte cap, or the first past the row cap, and none after; the lengths come first, so the bodies
/// past the bound are never read.
#[tokio::test]
async fn an_exports_attachments_stop_at_the_first_past_its_bound() {
    let db = support::database(2).await;
    let a = ledgers(&db, &support::a());
    let one = ledger(&support::a(), "case-bound");
    for sequence in 0..4 {
        let (event, checkpoint) = pair(&one, sequence, format!("key-{sequence}").as_bytes());
        let attachment = trellis_server_ports::AttachmentRow {
            event: event.clone(),
            ciphertext: vec![sequence as u8; 6],
            nonce: vec![0; 12],
            replay_identity: vec![0; 32],
            content_hash: vec![sequence as u8; 32],
            idempotency_key: format!("attachment-{sequence}").into_bytes(),
            compute_json: "{}".to_owned(),
        };
        let mut tx = a.begin(&one).await.unwrap();
        tx.insert(&event, &checkpoint).await.unwrap();
        tx.insert_attachment(&attachment).await.unwrap();
        tx.commit().await.unwrap();
    }
    let read = |max_bytes: u64, max_rows: u64| {
        let db = &db;
        let one = one.clone();
        async move {
            let mut tx = db.scoped.begin(&support::a()).await.unwrap();
            store::attachments_within(&mut tx, one.as_bytes(), 4, max_bytes, max_rows)
                .await
                .unwrap()
                .iter()
                .map(|row| row.event.sequence())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(read(u64::MAX, 256).await, [0, 1, 2, 3], "within the bound");
    assert_eq!(read(10, 256).await, [0, 1], "6 + 6 bytes crosses 10");
    assert_eq!(
        read(u64::MAX, 2).await,
        [0, 1, 2],
        "the third row is past two"
    );
    assert_eq!(read(u64::MAX, 0).await, [0]);
}
