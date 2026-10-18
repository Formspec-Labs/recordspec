// Rust guideline compliant 2026-02-21
//! The schema contract and byte fidelity of the stored rows.

mod support;

use sqlx::PgPool;
use trellis_store_postgres_async::{append_checkpointed, head_checkpoint, last_event, lock_ledger};
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

async fn columns(pool: &PgPool, table: &str) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn primary_key(pool: &PgPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT attribute.attname FROM pg_index AS index \
         JOIN pg_class AS table_class ON table_class.oid = index.indrelid \
         JOIN LATERAL unnest(index.indkey) WITH ORDINALITY AS key(attnum, ord) ON true \
         JOIN pg_attribute AS attribute \
           ON attribute.attrelid = table_class.oid AND attribute.attnum = key.attnum \
         WHERE table_class.relname = $1 AND index.indisprimary ORDER BY key.ord",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap()
}

fn col(name: &str, kind: &str, nullable: &str) -> (String, String, String) {
    (name.to_owned(), kind.to_owned(), nullable.to_owned())
}

#[tokio::test]
async fn the_tables_have_the_documented_columns_keys_and_constraints() {
    let db = support::database(1).await;
    let pool = &db.owner;

    assert_eq!(
        columns(pool, "trellis_events").await,
        vec![
            col("scope_key", "bytea", "NO"),
            col("scope", "bytea", "NO"),
            col("sequence", "bigint", "NO"),
            col("canonical_event", "bytea", "NO"),
            col("signed_event", "bytea", "NO"),
            col("idempotency_key", "bytea", "YES"),
            col("canonical_event_hash", "bytea", "NO"),
        ]
    );
    assert_eq!(
        columns(pool, "trellis_checkpoints").await,
        vec![
            col("scope_key", "bytea", "NO"),
            col("scope", "bytea", "NO"),
            col("tree_size", "bigint", "NO"),
            col("digest", "bytea", "NO"),
            col("checkpoint", "bytea", "NO"),
            col("frontier", "bytea", "NO"),
            col("profile_state", "bytea", "NO"),
        ]
    );
    assert_eq!(
        columns(pool, "trellis_source_contents").await,
        vec![
            col("scope_key", "bytea", "NO"),
            col("scope", "bytea", "NO"),
            col("sequence", "bigint", "NO"),
            col("batch_hash", "bytea", "NO"),
            col("size", "bigint", "NO"),
            col("artifact_ref", "text", "NO"),
        ]
    );
    // ADR 0168 §1.3: scope_key leads every key of every table.
    for (table, rest) in [
        ("trellis_events", "sequence"),
        ("trellis_checkpoints", "tree_size"),
        ("trellis_external_attachments", "sequence"),
        ("trellis_source_contents", "sequence"),
    ] {
        assert_eq!(primary_key(pool, table).await, ["scope_key", "scope", rest]);
    }

    let idempotency_index: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' \
         AND tablename = 'trellis_events' AND indexname = 'trellis_events_idempotency_uidx'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(idempotency_index.contains("CREATE UNIQUE INDEX"));
    assert!(idempotency_index.contains("(scope_key, scope, idempotency_key)"));
    assert!(idempotency_index.contains("WHERE (idempotency_key IS NOT NULL)"));

    let digest_index: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' \
         AND tablename = 'trellis_checkpoints' AND indexdef LIKE '%(scope_key, scope, digest)%'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(digest_index.contains("CREATE UNIQUE INDEX"));
}

/// Each scope's first event, so every checkpoint is a one-leaf tree.
fn corpus() -> Vec<(StoredEvent, StoredCheckpoint)> {
    let deterministic = |len: usize, seed: u8| -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add((i % 251) as u8))
            .collect()
    };
    let one = |scope: &[u8], canonical: Vec<u8>, signed: Vec<u8>, key: Option<Vec<u8>>| {
        let mut frontier = Frontier::new();
        frontier.push(&TrellisHasher, &[0x42; 32]);
        let event = match key {
            Some(key) => {
                StoredEvent::with_idempotency_key(scope.to_vec(), 0, canonical, signed, key)
            }
            None => StoredEvent::new(scope.to_vec(), 0, canonical, signed),
        }
        .with_canonical_event_hash(Some([0x42; 32]));
        let checkpoint = StoredCheckpoint {
            scope: scope.to_vec(),
            tree_size: 1,
            digest: [0x77; 32],
            checkpoint: b"sign1".to_vec(),
            frontier: frontier.to_bytes(),
            profile_state: Vec::new(),
        };
        (event, checkpoint)
    };
    vec![
        one(b"corpus-empty", vec![], vec![], Some(b"i".to_vec())),
        one(
            b"corpus-nul-bom",
            vec![0x00, b'a', 0x00, b'z'],
            vec![0xef, 0xbb, 0xbf, b's', b'i', b'g'],
            Some(vec![0x32; 32]),
        ),
        one(
            b"corpus-large",
            deterministic(8 * 1024, 0x13),
            deterministic(8 * 1024, 0x71),
            Some(vec![0x64; 64]),
        ),
        one(
            b"corpus-no-key",
            b"canonical".to_vec(),
            b"signed".to_vec(),
            None,
        ),
    ]
}

#[tokio::test]
async fn byte_authority_corpus_round_trips_without_reconstructing_events() {
    let db = support::database(2).await;
    let corpus = corpus();
    for (event, checkpoint) in &corpus {
        let mut tx = db.scoped.begin(&support::a()).await.unwrap();
        lock_ledger(&mut tx, event.scope()).await.unwrap();
        append_checkpointed(&mut tx, event, checkpoint)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    for (event, checkpoint) in &corpus {
        assert_eq!(
            last_event(&mut tx, event.scope()).await.unwrap().as_ref(),
            Some(event)
        );
        assert_eq!(
            head_checkpoint(&mut tx, event.scope())
                .await
                .unwrap()
                .as_ref(),
            Some(checkpoint)
        );
    }
}
