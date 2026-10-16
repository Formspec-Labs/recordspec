//! Neutral isolated TLS store controls; no selected service database or Source fixtures.
// Rust guideline compliant 2026-02-21
#[path = "../../trellis-store-postgres-async/tests/support/mod.rs"]
mod support;

use integrity_cbor::domain_separated_sha256;
use std::time::Duration;
use trellis_service_core::{EventRepository, PostgresEventRepository};
use trellis_store_postgres_async::{append_event_in_tx, run_migrations};
use trellis_types::StoredEvent;

fn event(scope: &[u8], canonical: &[u8]) -> StoredEvent {
    StoredEvent::with_idempotency_key(
        scope.to_vec(),
        0,
        canonical.to_vec(),
        b"neutral-signed".to_vec(),
        b"neutral-key".to_vec(),
    )
}
fn advisory_key(scope: &[u8]) -> i64 {
    // Exact existing append scope-lock derivation; this test only coordinates
    // a deliberately held writer transaction against the public repository.
    let hash = domain_separated_sha256("trellis-append-scope-lock-v1", scope);
    i64::from_be_bytes(hash[..8].try_into().unwrap())
}

#[tokio::test]
async fn reconciliation_snapshot_waits_for_inflight_commit_and_releases_scope_lock() {
    serialized_snapshot(false).await;
}

#[tokio::test]
async fn reconciliation_snapshot_overrides_repeatable_read_pool_default() {
    serialized_snapshot(true).await;
}

async fn serialized_snapshot(repeatable_read_default: bool) {
    let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, 3).await;
    run_migrations(&pool).await.unwrap();
    if repeatable_read_default {
        // Hold every pool connection while setting its session default so the
        // snapshot cannot accidentally use an unconfigured fresh connection.
        let mut connections = Vec::new();
        for _ in 0..3 {
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("SET default_transaction_isolation = 'repeatable read'")
                .execute(&mut *connection)
                .await
                .unwrap();
            let isolation: String = sqlx::query_scalar("SHOW default_transaction_isolation")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            assert_eq!(isolation, "repeatable read");
            connections.push(connection);
        }
        drop(connections);
    }
    let scope = b"neutral-serialized-snapshot";
    let expected = event(scope, b"neutral-canonical");
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(advisory_key(scope))
        .execute(&mut *writer)
        .await
        .unwrap();
    append_event_in_tx(&mut writer, &expected).await.unwrap();
    let repository = PostgresEventRepository::new(pool.clone());
    let mut snapshot = Box::pin(repository.reconciliation_snapshot(scope));
    // Poll the actual snapshot while the commit lock is held; it must wait,
    // rather than report absence from the writer's uncommitted prefix.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), snapshot.as_mut())
            .await
            .is_err()
    );
    writer.commit().await.unwrap();
    let prefix = tokio::time::timeout(Duration::from_secs(2), snapshot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prefix, vec![expected]);
    let mut after = pool.begin().await.unwrap();
    let released: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(advisory_key(scope))
        .fetch_one(&mut *after)
        .await
        .unwrap();
    assert!(
        released,
        "snapshot must release its transaction before artifact work"
    );
    after.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
async fn reconciliation_snapshot_concurrent_same_key_has_one_commit_and_changed_bytes_conflict() {
    let cluster = stack_common_postgres::testing::EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, 4).await;
    run_migrations(&pool).await.unwrap();
    let repository = PostgresEventRepository::new(pool.clone());
    let scope = b"neutral-same-key";
    assert!(
        repository
            .reconciliation_snapshot(scope)
            .await
            .unwrap()
            .is_empty()
    );
    let expected = event(scope, b"neutral-canonical");
    let (first, second) = tokio::join!(
        repository.append_event(expected.clone()),
        repository.append_event(expected.clone())
    );
    assert!(first.is_ok() || second.is_ok());
    // Existing append semantics can refuse a racing caller; uniqueness does
    // not promise that every concurrent request succeeds.
    for error in [first.err(), second.err()].into_iter().flatten() {
        assert!(error.status().is_client_error() || error.status().is_server_error());
    }
    assert_eq!(
        repository.reconciliation_snapshot(scope).await.unwrap(),
        vec![expected.clone()]
    );
    repository.append_event(expected.clone()).await.unwrap();
    let error = repository
        .append_event(event(scope, b"changed-canonical"))
        .await
        .unwrap_err();
    assert_eq!(error.status(), http::StatusCode::CONFLICT);
    assert_eq!(
        repository.reconciliation_snapshot(scope).await.unwrap(),
        vec![expected]
    );
    pool.close().await;
}
