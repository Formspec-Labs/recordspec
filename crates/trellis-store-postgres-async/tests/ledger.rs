// Rust guideline compliant 2026-02-21
//! Behaviour of the checkpointed ledger rows against a real Postgres.

mod support;

use std::time::Duration;

use sqlx::PgPool;
use stack_common_postgres::testing::EphemeralCluster;
use trellis_store_postgres_async::ledger::{self, AppendError, SourceContentBinding};
use trellis_store_postgres_async::run_migrations;
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

async fn started_pool(max_connections: u32) -> (EphemeralCluster, PgPool) {
    let cluster = EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, max_connections).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

fn hash(tag: u8, sequence: u64) -> [u8; 32] {
    let mut out = [tag; 32];
    out[..8].copy_from_slice(&sequence.to_be_bytes());
    out
}

/// An event and the checkpoint a service would write with it: ledger of `sequence + 1` leaves.
fn pair(scope: &[u8], sequence: u64, key: &[u8]) -> (StoredEvent, StoredCheckpoint) {
    let mut frontier = Frontier::new();
    for i in 0..=sequence {
        frontier.push(&TrellisHasher, &hash(1, i));
    }
    let event = StoredEvent::with_idempotency_key(
        scope.to_vec(),
        sequence,
        format!("canonical-{sequence}").into_bytes(),
        format!("signed-{sequence}").into_bytes(),
        key.to_vec(),
    )
    .with_canonical_event_hash(Some(hash(2, sequence)));
    let checkpoint = StoredCheckpoint {
        scope: scope.to_vec(),
        tree_size: sequence + 1,
        digest: hash(3, sequence),
        checkpoint: format!("sign1-{sequence}").into_bytes(),
        frontier: frontier.to_bytes(),
        profile_state: b"state".to_vec(),
    };
    (event, checkpoint)
}

async fn commit(pool: &PgPool, event: &StoredEvent, checkpoint: &StoredCheckpoint) {
    let mut tx = ledger::begin_scope(pool, event.scope()).await.unwrap();
    ledger::append_checkpointed_in_tx(&mut tx, event, checkpoint)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn an_event_and_its_checkpoint_commit_together_and_read_back() {
    let (_cluster, pool) = started_pool(4).await;
    let (event, checkpoint) = pair(b"scope-a", 0, b"key-0");
    commit(&pool, &event, &checkpoint).await;

    assert_eq!(
        ledger::last_event(&pool, b"scope-a").await.unwrap(),
        Some(event.clone())
    );
    assert_eq!(
        ledger::event_by_key(&pool, b"scope-a", b"key-0")
            .await
            .unwrap(),
        Some(event)
    );
    assert_eq!(
        ledger::head_checkpoint(&pool, b"scope-a").await.unwrap(),
        Some(checkpoint.clone())
    );
    assert_eq!(
        ledger::checkpoint_at(&pool, b"scope-a", 1).await.unwrap(),
        Some(checkpoint.clone())
    );
    assert_eq!(
        ledger::checkpoint_by_digest(&pool, b"scope-a", &checkpoint.digest)
            .await
            .unwrap(),
        Some(checkpoint)
    );
    assert_eq!(
        ledger::head_checkpoint(&pool, b"other").await.unwrap(),
        None
    );
    assert_eq!(
        ledger::event_by_key(&pool, b"scope-a", b"missing")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn the_head_is_the_highest_tree_size_and_ranges_come_back_in_order() {
    let (_cluster, pool) = started_pool(4).await;
    let pairs: Vec<_> = (0..6)
        .map(|i| pair(b"scope-b", i, format!("key-{i}").as_bytes()))
        .collect();
    for (event, checkpoint) in &pairs {
        commit(&pool, event, checkpoint).await;
    }
    commit(
        &pool,
        &pair(b"scope-c", 0, b"key-0").0,
        &pair(b"scope-c", 0, b"key-0").1,
    )
    .await;

    let head = ledger::head_checkpoint(&pool, b"scope-b")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.tree_size, 6);
    assert_eq!(
        head.frontier().unwrap().size(),
        6,
        "the stored frontier decodes at its tree size"
    );
    assert_eq!(
        ledger::last_event(&pool, b"scope-b")
            .await
            .unwrap()
            .unwrap()
            .sequence(),
        5
    );

    let events = ledger::events_before(&pool, b"scope-b", 4, 100)
        .await
        .unwrap();
    assert_eq!(
        events.iter().map(StoredEvent::sequence).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(
        ledger::events_before(&pool, b"scope-b", 100, 2)
            .await
            .unwrap()
            .len(),
        2,
        "limit bounds the read"
    );
    let checkpoints = ledger::checkpoints_through(&pool, b"scope-b", 4)
        .await
        .unwrap();
    assert_eq!(
        checkpoints.iter().map(|c| c.tree_size).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
}

#[tokio::test]
async fn a_rolled_back_append_leaves_neither_event_nor_checkpoint() {
    let (_cluster, pool) = started_pool(4).await;
    let (event, checkpoint) = pair(b"scope-d", 0, b"key-0");
    let mut tx = ledger::begin_scope(&pool, b"scope-d").await.unwrap();
    ledger::append_checkpointed_in_tx(&mut tx, &event, &checkpoint)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(ledger::last_event(&pool, b"scope-d").await.unwrap(), None);
    assert_eq!(
        ledger::head_checkpoint(&pool, b"scope-d").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn a_taken_sequence_key_or_digest_reports_a_conflict_and_writes_nothing() {
    let (_cluster, pool) = started_pool(4).await;
    let (event, checkpoint) = pair(b"scope-e", 0, b"key-0");
    commit(&pool, &event, &checkpoint).await;

    let (mut same_key, mut same_key_cp) = pair(b"scope-e", 1, b"key-0");
    same_key_cp.digest = hash(9, 1);
    let mut tx = ledger::begin_scope(&pool, b"scope-e").await.unwrap();
    let error = ledger::append_checkpointed_in_tx(&mut tx, &same_key, &same_key_cp)
        .await
        .unwrap_err();
    assert!(matches!(error, AppendError::Conflict(_)), "{error}");
    tx.rollback().await.unwrap();

    let (same_sequence, same_sequence_cp) = pair(b"scope-e", 0, b"key-other");
    let mut tx = ledger::begin_scope(&pool, b"scope-e").await.unwrap();
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &same_sequence, &same_sequence_cp).await,
        Err(AppendError::Conflict(_))
    ));
    tx.rollback().await.unwrap();

    same_key = pair(b"scope-e", 1, b"key-1").0;
    let mut same_digest = pair(b"scope-e", 1, b"key-1").1;
    same_digest.digest = checkpoint.digest;
    let mut tx = ledger::begin_scope(&pool, b"scope-e").await.unwrap();
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &same_key, &same_digest).await,
        Err(AppendError::Conflict(_))
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        ledger::last_event(&pool, b"scope-e")
            .await
            .unwrap()
            .unwrap()
            .sequence(),
        0
    );
}

#[tokio::test]
async fn a_checkpoint_that_does_not_describe_its_event_is_refused_before_any_write() {
    let (_cluster, pool) = started_pool(4).await;
    let (event, checkpoint) = pair(b"scope-f", 2, b"key-2");
    let mut tx = ledger::begin_scope(&pool, b"scope-f").await.unwrap();

    let mut wrong_size = checkpoint.clone();
    wrong_size.tree_size = 9;
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &event, &wrong_size).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let mut wrong_frontier = checkpoint.clone();
    wrong_frontier.frontier.truncate(32);
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &event, &wrong_frontier).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let unhashed =
        StoredEvent::with_idempotency_key(b"scope-f".to_vec(), 2, vec![1], vec![2], b"k".to_vec());
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &unhashed, &checkpoint).await,
        Err(AppendError::CheckpointMismatch(_))
    ));
    let long_key =
        StoredEvent::with_idempotency_key(b"scope-f".to_vec(), 2, vec![1], vec![2], vec![7; 65])
            .with_canonical_event_hash(Some([1; 32]));
    assert!(matches!(
        ledger::append_checkpointed_in_tx(&mut tx, &long_key, &checkpoint).await,
        Err(AppendError::IdempotencyKeyTooLong(65))
    ));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn the_schema_itself_refuses_a_frontier_that_is_not_popcount_hashes() {
    let (_cluster, pool) = started_pool(4).await;
    let error = sqlx::query(
        "INSERT INTO trellis_checkpoints (scope, tree_size, digest, checkpoint, frontier, profile_state) \
         VALUES ($1, 3, $2, $3, $4, $5)",
    )
    .bind(b"scope-g".as_slice())
    .bind([5u8; 32].as_slice())
    .bind(b"sign1".as_slice())
    .bind([0u8; 32].as_slice())
    .bind(b"".as_slice())
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
}

#[tokio::test]
async fn a_second_appender_waits_for_the_scope_lock_and_then_sees_the_first_commit() {
    let (_cluster, pool) = started_pool(4).await;
    let first = tokio::spawn({
        let pool = pool.clone();
        async move {
            let mut tx = ledger::begin_scope(&pool, b"scope-h").await.unwrap();
            let (event, checkpoint) = pair(b"scope-h", 0, b"key-0");
            tokio::time::sleep(Duration::from_millis(300)).await;
            ledger::append_checkpointed_in_tx(&mut tx, &event, &checkpoint)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Begins while the first holds the lock; its first read must already see the commit.
    let mut tx = ledger::begin_scope(&pool, b"scope-h").await.unwrap();
    let head = ledger::head_checkpoint(&mut *tx, b"scope-h").await.unwrap();
    assert_eq!(head.map(|h| h.tree_size), Some(1));
    tx.rollback().await.unwrap();
    first.await.unwrap();
}

#[tokio::test]
async fn a_source_content_binding_belongs_to_exactly_one_event() {
    let (_cluster, pool) = started_pool(4).await;
    let (event, checkpoint) = pair(b"scope-i", 0, b"key-0");
    let binding = SourceContentBinding {
        batch_hash: [8; 32],
        size: 77,
    };
    let mut tx = ledger::begin_scope(&pool, b"scope-i").await.unwrap();
    ledger::append_checkpointed_in_tx(&mut tx, &event, &checkpoint)
        .await
        .unwrap();
    ledger::insert_source_content(&mut tx, b"scope-i", 0, &binding)
        .await
        .unwrap();
    assert!(matches!(
        ledger::insert_source_content(&mut tx, b"scope-i", 0, &binding).await,
        Err(AppendError::Conflict(_))
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        ledger::source_content(&pool, b"scope-i", 0).await.unwrap(),
        None
    );

    let mut tx = ledger::begin_scope(&pool, b"scope-i").await.unwrap();
    ledger::append_checkpointed_in_tx(&mut tx, &event, &checkpoint)
        .await
        .unwrap();
    ledger::insert_source_content(&mut tx, b"scope-i", 0, &binding)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        ledger::source_content(&pool, b"scope-i", 0).await.unwrap(),
        Some(binding)
    );
    assert_eq!(
        ledger::source_content(&pool, b"scope-i", 1).await.unwrap(),
        None
    );
}
