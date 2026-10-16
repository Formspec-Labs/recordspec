// Rust guideline compliant 2026-02-21

mod support;

use sqlx::PgPool;
use stack_common_postgres::testing::EphemeralCluster;
use trellis_store_postgres_async::{AppendError, append_event_in_tx, run_migrations};
use trellis_types::StoredEvent;

fn event(scope: &[u8], sequence: u64, canonical: &[u8], signed: &[u8], idem: &[u8]) -> StoredEvent {
    StoredEvent::with_idempotency_key(
        scope.to_vec(),
        sequence,
        canonical.to_vec(),
        signed.to_vec(),
        idem.to_vec(),
    )
}

async fn started_pool() -> (EphemeralCluster, PgPool) {
    let cluster = EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, 8).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

#[tokio::test]
async fn ddl_matches_shared_migration_contract() {
    let (_cluster, pool) = started_pool().await;

    let applied_versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM trellis_schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(applied_versions, vec![1, 2, 3, 4]);

    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "\
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'trellis_events'
ORDER BY ordinal_position",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        columns,
        vec![
            ("scope".to_owned(), "bytea".to_owned(), "NO".to_owned()),
            ("sequence".to_owned(), "bigint".to_owned(), "NO".to_owned()),
            (
                "canonical_event".to_owned(),
                "bytea".to_owned(),
                "NO".to_owned()
            ),
            (
                "signed_event".to_owned(),
                "bytea".to_owned(),
                "NO".to_owned()
            ),
            (
                "idempotency_key".to_owned(),
                "bytea".to_owned(),
                "YES".to_owned()
            ),
            (
                "canonical_event_hash".to_owned(),
                "bytea".to_owned(),
                "YES".to_owned()
            ),
        ]
    );

    let pk_columns: Vec<String> = sqlx::query_scalar(
        "\
SELECT attribute.attname
FROM pg_index AS index
JOIN pg_class AS table_class ON table_class.oid = index.indrelid
JOIN LATERAL unnest(index.indkey) WITH ORDINALITY AS key(attnum, ord) ON true
JOIN pg_attribute AS attribute
  ON attribute.attrelid = table_class.oid AND attribute.attnum = key.attnum
WHERE table_class.relname = 'trellis_events' AND index.indisprimary
ORDER BY key.ord",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(pk_columns, vec!["scope", "sequence"]);

    let index_def: String = sqlx::query_scalar(
        "\
SELECT indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'trellis_events'
  AND indexname = 'trellis_events_scope_idempotency_uidx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(index_def.contains("CREATE UNIQUE INDEX"));
    assert!(index_def.contains("(scope, idempotency_key)"));
    assert!(index_def.contains("WHERE (idempotency_key IS NOT NULL)"));

    let constraint_def: String = sqlx::query_scalar(
        "\
SELECT pg_get_constraintdef(check_constraint.oid)
FROM pg_constraint AS check_constraint
JOIN pg_class AS table_class ON table_class.oid = check_constraint.conrelid
WHERE table_class.relname = 'trellis_events'
  AND check_constraint.conname = 'trellis_events_idempotency_key_length'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(constraint_def.contains("octet_length(idempotency_key)"));
    assert!(constraint_def.contains("64"));

    let bundle_columns: Vec<(String, String, String)> = sqlx::query_as(
        "\
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'trellis_bundle_publications'
ORDER BY ordinal_position",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        bundle_columns,
        vec![
            ("scope".to_owned(), "bytea".to_owned(), "NO".to_owned()),
            (
                "seal_version".to_owned(),
                "bigint".to_owned(),
                "NO".to_owned()
            ),
            (
                "checkpoint_digest".to_owned(),
                "text".to_owned(),
                "NO".to_owned()
            ),
            (
                "export_attempt_id".to_owned(),
                "text".to_owned(),
                "NO".to_owned()
            ),
            (
                "artifact_ref".to_owned(),
                "text".to_owned(),
                "YES".to_owned()
            ),
            (
                "created_at".to_owned(),
                "timestamp with time zone".to_owned(),
                "NO".to_owned()
            ),
            (
                "published_at".to_owned(),
                "timestamp with time zone".to_owned(),
                "YES".to_owned()
            ),
        ]
    );

    let bundle_pk_columns: Vec<String> = sqlx::query_scalar(
        "\
SELECT attribute.attname
FROM pg_index AS index
JOIN pg_class AS table_class ON table_class.oid = index.indrelid
JOIN LATERAL unnest(index.indkey) WITH ORDINALITY AS key(attnum, ord) ON true
JOIN pg_attribute AS attribute
  ON attribute.attrelid = table_class.oid AND attribute.attnum = key.attnum
WHERE table_class.relname = 'trellis_bundle_publications' AND index.indisprimary
ORDER BY key.ord",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(bundle_pk_columns, vec!["scope", "seal_version"]);

    let checkpoint_index_def: String = sqlx::query_scalar(
        "\
SELECT indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'trellis_bundle_publications'
  AND indexname = 'trellis_bundle_publications_scope_checkpoint_digest_key'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(checkpoint_index_def.contains("CREATE UNIQUE INDEX"));
    assert!(checkpoint_index_def.contains("(scope, checkpoint_digest)"));
}

#[tokio::test]
async fn append_error_variants_are_exercised_without_sync_oracle() {
    let (_cluster, pool) = started_pool().await;

    assert!(matches!(
        append_error(
            &pool,
            event(b"scope-long", 0, b"canonical", b"signed", &[0xab; 65]),
        )
        .await,
        AppendError::IdempotencyKeyTooLong(65)
    ));

    assert!(matches!(
        append_error(
            &pool,
            StoredEvent::new(
                b"scope-domain".to_vec(),
                (i64::MAX as u64) + 1,
                b"canonical".to_vec(),
                b"signed".to_vec(),
            ),
        )
        .await,
        AppendError::DomainViolation(_)
    ));

    assert!(matches!(
        append_error(
            &pool,
            StoredEvent::new(
                b"scope-gap".to_vec(),
                1,
                b"canonical".to_vec(),
                b"signed".to_vec(),
            )
            .with_canonical_event_hash(Some([0xaa; 32])),
        )
        .await,
        AppendError::SequenceGap(0)
    ));

    let ev_a = event(b"scope-idem", 0, b"canonical-a", b"signed-a", b"idem");
    append_ok(&pool, &ev_a).await;
    let ev_b = event(b"scope-idem", 1, b"canonical-b", b"signed-b", b"idem");
    assert!(matches!(
        append_error(&pool, ev_b).await,
        AppendError::IdempotencyKeyPayloadMismatch
    ));

    let pk_a = StoredEvent::new(
        b"scope-pk".to_vec(),
        0,
        b"canonical-a".to_vec(),
        b"signed-a".to_vec(),
    );
    append_ok(&pool, &pk_a).await;
    let pk_b = StoredEvent::new(
        b"scope-pk".to_vec(),
        0,
        b"canonical-b".to_vec(),
        b"signed-b".to_vec(),
    );
    assert!(matches!(
        append_error(&pool, pk_b).await,
        AppendError::PkCollisionMismatch
    ));

    sqlx::query("DROP TABLE trellis_events")
        .execute(&pool)
        .await
        .unwrap();
    let sql_broken = StoredEvent::new(
        b"scope-sql".to_vec(),
        0,
        b"canonical".to_vec(),
        b"signed".to_vec(),
    );
    assert!(matches!(
        append_error(&pool, sql_broken).await,
        AppendError::Sqlx(_)
    ));
}

#[tokio::test]
async fn byte_authority_corpus_round_trips_without_reconstructing_events() {
    let (_cluster, pool) = started_pool().await;
    let events = byte_authority_corpus();

    for event in &events {
        append_ok(&pool, event).await;
    }

    let rows: Vec<(
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    )> = sqlx::query_as(
        "\
SELECT scope, sequence, canonical_event, signed_event, idempotency_key, canonical_event_hash
FROM trellis_events
ORDER BY scope, sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let mut expected = events.iter().collect::<Vec<_>>();
    expected.sort_by(|left, right| {
        left.scope()
            .cmp(right.scope())
            .then_with(|| left.sequence().cmp(&right.sequence()))
    });

    assert_eq!(rows.len(), expected.len());
    for (row, event) in rows.iter().zip(expected) {
        assert_eq!(row.0, event.scope());
        assert_eq!(row.1, i64::try_from(event.sequence()).unwrap());
        assert_eq!(row.2, event.canonical_event());
        assert_eq!(row.3, event.signed_event());
        assert_eq!(row.4.as_deref(), event.idempotency_key());
        assert_eq!(
            row.5.as_deref(),
            event.canonical_event_hash().map(|hash| hash.as_slice())
        );
    }
}

async fn append_ok(pool: &PgPool, event: &StoredEvent) {
    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, event).await.unwrap();
    tx.commit().await.unwrap();
}

async fn append_error(pool: &PgPool, event: StoredEvent) -> AppendError {
    let mut tx = pool.begin().await.unwrap();
    let error = append_event_in_tx(&mut tx, &event).await.unwrap_err();
    tx.rollback().await.unwrap();
    error
}

fn byte_authority_corpus() -> Vec<StoredEvent> {
    vec![
        event(b"corpus-empty", 0, b"", b"", b"i"),
        event(
            b"corpus-nul-bom",
            0,
            &[0x00, b'a', 0x00, b'z'],
            &[0xef, 0xbb, 0xbf, b's', b'i', b'g'],
            &[0x32; 32],
        ),
        event(
            b"corpus-large",
            0,
            &deterministic_bytes(8 * 1024, 0x13),
            &deterministic_bytes(8 * 1024, 0x71),
            &[0x64; 64],
        ),
        StoredEvent::new(
            b"corpus-chain".to_vec(),
            0,
            b"genesis-canonical".to_vec(),
            b"genesis-signed".to_vec(),
        ),
        event(
            b"corpus-chain",
            1,
            b"non-genesis-canonical",
            b"non-genesis-signed",
            b"chain-idem",
        )
        .with_canonical_event_hash(Some([0x42; 32])),
        event(
            b"corpus-i64-max",
            i64::MAX as u64,
            b"max-sequence-canonical",
            b"max-sequence-signed",
            b"m",
        ),
    ]
}

fn deterministic_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}
