// Rust guideline compliant 2026-02-21
//! Cross-store parity: every `append/*` fixture produces byte-identical
//! stored canonical + signed bytes whether the underlying store is
//! `trellis-store-memory` or `trellis-store-postgres-async`.
//!
//! Conformance-side enforcement of the wos-server commitment that
//! `trellis-store-postgres-async` is a drop-in canonical-side composition
//! partner for the in-memory test oracle (per VISION.md §III + §V -
//! "Trellis IS the database"; the canonical schema is byte-equivalent across
//! adapters).
//!
//! This is also the first-class integration test exercising the
//! transaction-composition surface
//! ([`trellis_store_postgres_async::append_event_in_tx`]) against the full
//! append corpus.

use std::fs;
use std::path::{Path, PathBuf};

use sqlx::PgPool;
use stack_common_postgres::testing::EphemeralCluster;
use trellis_core::{AuthoredEvent, SigningKeyMaterial, append_event};
use trellis_store_memory::MemoryStore;
use trellis_store_postgres_async::{append_event_in_tx, build_pool, run_migrations};
use trellis_types::StoredEvent;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors")
}

fn append_vector_dirs() -> Vec<PathBuf> {
    let mut dirs = fs::read_dir(fixtures_root().join("append"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    dirs.sort();
    dirs
}

fn manifest_for(dir: &Path) -> toml::Value {
    toml::from_str(&fs::read_to_string(dir.join("manifest.toml")).unwrap()).unwrap()
}

fn signing_key_name(inputs: &toml::value::Table) -> &str {
    inputs
        .get("signing_key")
        .and_then(toml::Value::as_str)
        .or_else(|| inputs.get("signing_key_b").and_then(toml::Value::as_str))
        .expect("append manifest must name a signing key")
}

#[tokio::test]
async fn append_corpus_byte_parity_memory_vs_postgres() {
    let (_cluster, pool) = started_pool().await;

    let mut checked = 0usize;
    for dir in append_vector_dirs() {
        let manifest = manifest_for(&dir);
        let inputs = manifest
            .get("inputs")
            .and_then(toml::Value::as_table)
            .expect("manifest.inputs missing");
        let authored_event_path = inputs
            .get("authored_event")
            .and_then(toml::Value::as_str)
            .expect("inputs.authored_event missing");
        let authored_event = fs::read(dir.join(authored_event_path)).unwrap();
        let signing_key = fs::read(dir.join(signing_key_name(inputs))).unwrap();

        // Run the production append pipeline against memory.
        let mut memory_store = MemoryStore::new();
        let memory_artifacts = append_event(
            &mut memory_store,
            &SigningKeyMaterial::new(signing_key.clone()),
            &AuthoredEvent::new(authored_event.clone()),
        )
        .unwrap();

        assert_eq!(memory_store.events().len(), 1);
        let memory_stored = &memory_store.events()[0];

        // Run again, this time persisting into Postgres via the transaction-
        // composition surface that wos-server's EventStore will use.
        let mut runner = MemoryStore::new();
        let postgres_artifacts = append_event(
            &mut runner,
            &SigningKeyMaterial::new(signing_key),
            &AuthoredEvent::new(authored_event),
        )
        .unwrap();
        let runner_stored = &runner.events()[0];

        // The append corpus reuses scopes across fixtures (e.g. multiple
        // `001-`-style minimal events share `ledger_scope` and `sequence`);
        // truncate before each per-fixture round-trip so Postgres sees a
        // fresh write. Byte parity is the assertion under test, not
        // multi-fixture replay (which the wider conformance suite covers). CASCADE because
        // `trellis_external_attachments` references `trellis_events`.
        sqlx::query("TRUNCATE TABLE trellis_events CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        append_event_in_tx(&mut tx, runner_stored).await.unwrap();
        tx.commit().await.unwrap();

        let postgres_stored =
            load_scope_event(&pool, memory_stored.scope(), memory_stored.sequence())
                .await
                .unwrap_or_else(|| panic!("postgres did not persist event for {}", dir.display()));

        // BYTE-EXACT parity contract.
        assert_eq!(
            postgres_stored.canonical_event(),
            memory_stored.canonical_event(),
            "canonical_event byte mismatch memory vs postgres for {}",
            dir.display()
        );
        assert_eq!(
            postgres_stored.signed_event(),
            memory_stored.signed_event(),
            "signed_event byte mismatch memory vs postgres for {}",
            dir.display()
        );
        assert_eq!(
            postgres_stored.idempotency_key(),
            memory_stored.idempotency_key(),
            "idempotency_key mismatch memory vs postgres for {}",
            dir.display()
        );
        assert_eq!(
            postgres_stored.canonical_event_hash(),
            memory_stored.canonical_event_hash(),
            "stored canonical_event_hash mismatch memory vs postgres for {}",
            dir.display()
        );
        assert_eq!(
            postgres_artifacts.canonical_event_hash,
            memory_artifacts.canonical_event_hash,
            "canonical_event_hash divergence for {}",
            dir.display()
        );

        checked += 1;
    }

    assert!(
        checked > 0,
        "no append vectors discovered under fixtures/vectors/append"
    );
}

#[tokio::test]
async fn transaction_composition_atomic_with_caller_projections() {
    // Demonstrate the load-bearing wos-server commitment: a canonical
    // append + a caller-supplied projection update commit atomically OR
    // roll back together. This is the architectural invariant VISION.md
    // §VIII rejection of dual-write rests on.
    let (_cluster, pool) =
        started_pool().await;

    // Composition root would create this kind of table per its own schema; we
    // model the seam with a simple side table.
    sqlx::query("CREATE TABLE projection_demo (case_id TEXT PRIMARY KEY, status TEXT)")
        .execute(&pool)
        .await
        .unwrap();

    // Happy path: canonical + projection commit together.
    {
        let mut tx = pool.begin().await.unwrap();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"case-1".to_vec(), 0, vec![0xab], vec![0xcd]),
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO projection_demo (case_id, status) VALUES ($1, $2)")
            .bind("case-1")
            .bind("open")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(scope_event_count(&pool, b"case-1").await, 1);

    // Sad path: projection write fails -> canonical event MUST roll back.
    {
        let mut tx = pool.begin().await.unwrap();
        append_event_in_tx(
            &mut tx,
            &StoredEvent::new(b"case-2".to_vec(), 0, vec![0xee], vec![0xff]),
        )
        .await
        .unwrap();
        // PK conflict against case-1 row.
        let projection_err =
            sqlx::query("INSERT INTO projection_demo (case_id, status) VALUES ($1, $2)")
                .bind("case-1")
                .bind("duplicate")
                .execute(&mut *tx)
                .await;
        assert!(projection_err.is_err());
        tx.rollback().await.unwrap();
    }
    assert!(
        scope_event_count(&pool, b"case-2").await == 0,
        "rolled-back tx left canonical event visible"
    );
}

async fn started_pool() -> (EphemeralCluster, PgPool) {
    let cluster = EphemeralCluster::start_required();

    cluster.assert_tls_contract().await;
    let pool = build_pool(&cluster.dsn(), 8).await.unwrap();
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

async fn load_scope_event(pool: &PgPool, scope: &[u8], sequence: u64) -> Option<StoredEvent> {
    let sequence = i64::try_from(sequence).unwrap();
    let row: Option<(
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
WHERE scope = $1 AND sequence = $2",
    )
    .bind(scope)
    .bind(sequence)
    .fetch_optional(pool)
    .await
    .unwrap();

    row.map(
        |(scope, sequence, canonical, signed, idempotency_key, canonical_event_hash)| {
            let event = match idempotency_key {
                Some(key) => StoredEvent::with_idempotency_key(
                    scope,
                    u64::try_from(sequence).unwrap(),
                    canonical,
                    signed,
                    key,
                ),
                None => {
                    StoredEvent::new(scope, u64::try_from(sequence).unwrap(), canonical, signed)
                }
            };
            event.with_canonical_event_hash(canonical_event_hash.map(|hash| {
                hash.try_into()
                    .expect("canonical_event_hash column must be 32 bytes")
            }))
        },
    )
}

async fn scope_event_count(pool: &PgPool, scope: &[u8]) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM trellis_events WHERE scope = $1")
        .bind(scope)
        .fetch_one(pool)
        .await
        .unwrap()
}
