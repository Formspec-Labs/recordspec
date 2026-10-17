// Rust guideline compliant 2026-02-21
//! The schema contract and byte fidelity of the stored rows.

mod support;

use sqlx::PgPool;
use stack_common_postgres::testing::EphemeralCluster;
use trellis_store_postgres_async::{
    append_checkpointed_in_tx, begin_scope, head_checkpoint, last_event, run_migrations,
};
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

async fn started_pool() -> (EphemeralCluster, PgPool) {
    let cluster = EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, 8).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

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
    let (_cluster, pool) = started_pool().await;

    assert_eq!(
        columns(&pool, "trellis_events").await,
        vec![
            col("scope", "bytea", "NO"),
            col("sequence", "bigint", "NO"),
            col("canonical_event", "bytea", "NO"),
            col("signed_event", "bytea", "NO"),
            col("idempotency_key", "bytea", "YES"),
            col("canonical_event_hash", "bytea", "NO"),
        ]
    );
    assert_eq!(
        primary_key(&pool, "trellis_events").await,
        ["scope", "sequence"]
    );

    assert_eq!(
        columns(&pool, "trellis_checkpoints").await,
        vec![
            col("scope", "bytea", "NO"),
            col("tree_size", "bigint", "NO"),
            col("digest", "bytea", "NO"),
            col("checkpoint", "bytea", "NO"),
            col("frontier", "bytea", "NO"),
            col("profile_state", "bytea", "NO"),
        ]
    );
    assert_eq!(
        primary_key(&pool, "trellis_checkpoints").await,
        ["scope", "tree_size"]
    );

    assert_eq!(
        columns(&pool, "trellis_source_contents").await,
        vec![
            col("scope", "bytea", "NO"),
            col("sequence", "bigint", "NO"),
            col("batch_hash", "bytea", "NO"),
            col("size", "bigint", "NO"),
            col("artifact_ref", "text", "NO"),
        ]
    );

    let idempotency_index: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' \
         AND tablename = 'trellis_events' AND indexname = 'trellis_events_scope_idempotency_uidx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(idempotency_index.contains("CREATE UNIQUE INDEX"));
    assert!(idempotency_index.contains("(scope, idempotency_key)"));
    assert!(idempotency_index.contains("WHERE (idempotency_key IS NOT NULL)"));

    let digest_index: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' \
         AND tablename = 'trellis_checkpoints' AND indexname = 'trellis_checkpoints_scope_digest_key'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(digest_index.contains("CREATE UNIQUE INDEX"));
    assert!(digest_index.contains("(scope, digest)"));

    let bundle_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('trellis_bundle_publications')::text")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        bundle_table, None,
        "nothing is published, so nothing is reserved"
    );
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
    let (_cluster, pool) = started_pool().await;
    let corpus = corpus();
    for (event, checkpoint) in &corpus {
        let mut tx = begin_scope(&pool, event.scope()).await.unwrap();
        append_checkpointed_in_tx(&mut tx, event, checkpoint)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    for (event, checkpoint) in &corpus {
        assert_eq!(
            last_event(&pool, event.scope()).await.unwrap().as_ref(),
            Some(event)
        );
        assert_eq!(
            head_checkpoint(&pool, event.scope())
                .await
                .unwrap()
                .as_ref(),
            Some(checkpoint)
        );
    }
}
