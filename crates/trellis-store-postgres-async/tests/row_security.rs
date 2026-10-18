// Rust guideline compliant 2026-02-21
//! ADR 0168 §1.3's backstop on Trellis's tables: row security fences raw SQL by scope key.
//!
//! The adapter already binds `scope_key = $1` in every statement; these tests run SQL that does
//! not, through the app role, and show that scope B's transaction reaches none of scope A's rows,
//! and that a connection that set no scope reaches nothing at all.

mod support;

use trellis_server_ports::{AttachmentRow, LedgerScope, Ledgers, SourceContentBinding};
use trellis_store_postgres_async::{PgLedgers, TABLES};
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

/// A's first event, its checkpoint, a retained attachment and a Source binding: one row in every
/// table, committed through the adapter.
async fn seed_a(db: &support::Database) -> LedgerScope {
    let ledger = LedgerScope::of(&support::a(), "case-1").unwrap();
    let mut frontier = Frontier::new();
    frontier.push(&TrellisHasher, &[1; 32]);
    let event = StoredEvent::with_idempotency_key(
        ledger.as_bytes().to_vec(),
        0,
        b"canonical".to_vec(),
        b"signed".to_vec(),
        b"key-0".to_vec(),
    )
    .with_canonical_event_hash(Some([2; 32]));
    let checkpoint = StoredCheckpoint {
        scope: ledger.as_bytes().to_vec(),
        tree_size: 1,
        digest: [3; 32],
        checkpoint: b"sign1".to_vec(),
        frontier: frontier.to_bytes(),
        profile_state: Vec::new(),
    };
    let ledgers = PgLedgers::new(db.scoped.clone()).scoped(&support::a());
    let attachment = AttachmentRow {
        event: event.clone(),
        ciphertext: b"ciphertext".to_vec(),
        nonce: vec![4; 12],
        replay_identity: vec![5; 32],
        content_hash: vec![6; 32],
        idempotency_key: b"attachment-0".to_vec(),
        compute_json: "{}".to_owned(),
    };
    let binding = SourceContentBinding {
        batch_hash: [7; 32],
        size: 1,
        artifact_ref: "batch".to_owned(),
    };
    let mut tx = ledgers.begin(&ledger).await.unwrap();
    tx.insert(&event, &checkpoint).await.unwrap();
    tx.insert_attachment(&attachment).await.unwrap();
    tx.insert_source_content(0, &binding).await.unwrap();
    tx.commit().await.unwrap();
    ledger
}

#[tokio::test]
async fn row_security_is_forced_on_every_table() {
    let db = support::database(1).await;
    for table in TABLES {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
        )
        .bind(table)
        .fetch_one(&db.owner)
        .await
        .unwrap();
        assert!(enabled && forced, "{table}");
    }
}

/// B's transaction, running SQL with no scope filter, cannot select, insert, update or delete
/// A's rows. The app role is granted UPDATE and DELETE here only so the policy, not the missing
/// grant, is what refuses them.
#[tokio::test]
async fn another_scopes_transaction_cannot_select_insert_update_or_delete_a_row() {
    let db = support::database(1).await;
    let ledger = seed_a(&db).await;
    sqlx::raw_sql(&format!(
        "GRANT UPDATE, DELETE ON {} TO {}",
        TABLES.join(", "),
        support::APP_ROLE
    ))
    .execute(&db.owner)
    .await
    .unwrap();

    let mut tx = db.scoped.begin(&support::b()).await.unwrap();
    for table in TABLES {
        let seen: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(tx.conn())
            .await
            .unwrap();
        assert_eq!(seen, 0, "B sees A's {table} rows");
    }
    let updated = sqlx::query("UPDATE trellis_events SET signed_event = 'forged'")
        .execute(tx.conn())
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 0);
    let deleted = sqlx::query("DELETE FROM trellis_checkpoints")
        .execute(tx.conn())
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 0);
    // A row carrying A's key fails the policy's WITH CHECK.
    let forged = sqlx::query(
        "INSERT INTO trellis_events (scope_key, scope, sequence, canonical_event, signed_event, \
         idempotency_key, canonical_event_hash) VALUES ($1, $2, 1, 'c', 's', 'k', $3)",
    )
    .bind(support::a().key().as_bytes().as_slice())
    .bind(ledger.as_bytes())
    .bind([9u8; 32].as_slice())
    .execute(tx.conn())
    .await
    .unwrap_err();
    assert_eq!(
        forged.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "{forged}"
    );
    drop(tx);

    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM trellis_events")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_eq!(events, 1, "A's row is untouched");
    let signed: Vec<u8> = sqlx::query_scalar("SELECT signed_event FROM trellis_events")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_eq!(signed, b"signed");
}

/// A connection that set no scope key (the app role's raw pool) reaches no row.
#[tokio::test]
async fn a_connection_that_set_no_scope_reaches_nothing() {
    let db = support::database(1).await;
    seed_a(&db).await;
    for table in TABLES {
        let seen: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&db.app)
            .await
            .unwrap();
        assert_eq!(seen, 0, "{table}");
    }
    // The zero counts above are not vacuous: A's own transaction sees a row in every table.
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    for table in TABLES {
        let seen: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(tx.conn())
            .await
            .unwrap();
        assert_eq!(seen, 1, "A's own transaction sees its {table} row");
    }
}
