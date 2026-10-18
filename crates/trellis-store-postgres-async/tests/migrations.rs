mod support;

use stack_common_postgres::{MigrateError, migrate};
use stack_common_scope::Cell;
use trellis_store_postgres_async::SCHEMA;

fn cell() -> Cell {
    Cell::parse("cell-a").unwrap()
}

/// Trellis's schema migrates idempotently and its serving role may only read and insert: the
/// ledgers are append-only. (The generic migrate and open rules are stack-common's, tested
/// there.)
#[tokio::test]
async fn migrations_apply_idempotently_and_grant_only_reads_and_inserts() {
    let db = support::database(2).await;

    migrate(&db.owner, support::APP_ROLE, &cell(), &SCHEMA)
        .await
        .unwrap();

    let versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM trellis_schema_migrations ORDER BY version")
            .fetch_all(&db.owner)
            .await
            .unwrap();
    assert_eq!(versions, vec![1, 2]);
    let privileges: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT privilege_type FROM information_schema.role_table_grants \
         WHERE grantee = $1 AND table_name LIKE 'trellis\\_%' \
           AND table_name <> 'trellis_schema_migrations' ORDER BY 1",
    )
    .bind(support::APP_ROLE)
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(privileges, ["INSERT", "SELECT"]);
    let owns_tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE tableowner = $1")
            .bind(support::APP_ROLE)
            .fetch_one(&db.owner)
            .await
            .unwrap();
    assert_eq!(owns_tables, 0);
}

/// A database that records a Trellis migration this binary does not know is refused.
#[tokio::test]
async fn forward_rollback_detected_when_schema_has_unknown_version() {
    let db = support::database(2).await;
    sqlx::query("INSERT INTO trellis_schema_migrations (version) VALUES (99)")
        .execute(&db.owner)
        .await
        .unwrap();

    let error = migrate(&db.owner, support::APP_ROLE, &cell(), &SCHEMA)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            MigrateError::Migration(stack_common_postgres::MigrationError::SchemaAhead {
                applied_version: 99,
                declared_max: 2
            })
        ),
        "{error}"
    );
}
