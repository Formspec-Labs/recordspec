// Rust guideline compliant 2026-02-21

mod support;

use sqlx::PgPool;
use support::TestCluster;
use trellis_store_postgres::PostgresStoreErrorKind as SyncKind;
use trellis_store_postgres_async::{AppendError, append_event_in_tx, run_migrations};
use trellis_store_postgres_shared::migrations::MIGRATIONS;
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

async fn started_pool() -> (TestCluster, PgPool) {
    let cluster = TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(4).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

#[tokio::test]
async fn ddl_matches_shared_sync_async_contract() {
    let (_cluster, pool) = started_pool().await;

    let applied_versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM trellis_schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let declared_versions = MIGRATIONS
        .iter()
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    assert_eq!(applied_versions, declared_versions);

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
}

#[tokio::test]
async fn async_append_errors_map_to_sync_error_classes() {
    let (_cluster, pool) = started_pool().await;

    assert_eq!(
        sync_class_for(
            &append_error(
                &pool,
                event(b"scope-long", 0, b"canonical", b"signed", &[0xab; 65]),
            )
            .await
        ),
        SyncKind::IdempotencyKeyTooLong
    );

    assert_eq!(
        sync_class_for(
            &append_error(
                &pool,
                StoredEvent::new(
                    b"scope-domain".to_vec(),
                    (i64::MAX as u64) + 1,
                    b"canonical".to_vec(),
                    b"signed".to_vec(),
                ),
            )
            .await
        ),
        SyncKind::DomainViolation
    );

    assert_eq!(
        sync_class_for(
            &append_error(
                &pool,
                StoredEvent::new(
                    b"scope-gap".to_vec(),
                    1,
                    b"canonical".to_vec(),
                    b"signed".to_vec(),
                )
                .with_canonical_event_hash(Some([0xaa; 32])),
            )
            .await
        ),
        SyncKind::SequenceGap
    );

    let ev_a = event(b"scope-idem", 0, b"canonical-a", b"signed-a", b"idem");
    append_ok(&pool, &ev_a).await;
    let ev_b = event(b"scope-idem", 1, b"canonical-b", b"signed-b", b"idem");
    assert_eq!(
        sync_class_for(&append_error(&pool, ev_b).await),
        SyncKind::IdempotencyKeyPayloadMismatch
    );

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
    assert_eq!(
        sync_class_for(&append_error(&pool, pk_b).await),
        SyncKind::IdempotencyKeyPayloadMismatch
    );
}

#[tokio::test]
async fn byte_authority_corpus_round_trips_without_reconstructing_events() {
    let (_cluster, pool) = started_pool().await;
    let scope = b"scope-byte-authority";
    let events = vec![
        event(
            scope,
            0,
            br#"{"amount":9007199254740993,"kind":"int-not-float"}"#,
            &[0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26],
            b"idem-corpus-0",
        )
        .with_canonical_event_hash(Some([0x01; 32])),
        event(
            scope,
            1,
            b"\0{\"unicode\":\"\\u0000 stays escaped\",\"order\":[3,2,1]}",
            b"signature-bytes-with\nembedded-newline",
            b"idem-corpus-1",
        )
        .with_canonical_event_hash(Some([0x02; 32])),
        StoredEvent::new(
            scope.to_vec(),
            2,
            vec![0xff, 0x00, 0x7f, b'{', b'}'],
            vec![0x01, 0x02, 0x03, 0x04],
        )
        .with_canonical_event_hash(Some([0x03; 32])),
    ];

    let mut tx = pool.begin().await.unwrap();
    for event in &events {
        append_event_in_tx(&mut tx, event).await.unwrap();
    }
    tx.commit().await.unwrap();

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
WHERE scope = $1
ORDER BY sequence",
    )
    .bind(scope.as_ref())
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), events.len());
    for (row, event) in rows.iter().zip(events.iter()) {
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

fn sync_class_for(error: &AppendError) -> SyncKind {
    match error {
        AppendError::IdempotencyKeyTooLong(_) => SyncKind::IdempotencyKeyTooLong,
        AppendError::DomainViolation(_) => SyncKind::DomainViolation,
        AppendError::SequenceGap(_) => SyncKind::SequenceGap,
        AppendError::IdempotencyKeyPayloadMismatch | AppendError::PkCollisionMismatch => {
            SyncKind::IdempotencyKeyPayloadMismatch
        }
        AppendError::Sqlx(_) => SyncKind::QueryFailed,
    }
}
