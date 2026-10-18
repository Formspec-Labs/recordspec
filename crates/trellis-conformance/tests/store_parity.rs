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
//! ([`trellis_store_postgres_async::append_checkpointed`] in a scope's `ScopedTx`) against the
//! full append corpus, and that the checkpoint stored beside each event is the
//! checkpoint `trellis-core` issued, byte for byte.

use std::fs;
use std::path::{Path, PathBuf};

use sqlx::PgPool;
use trellis_core::checkpoint::{IssuedCheckpoint, PriorCheckpoint, issue_checkpoint};
use trellis_core::{AuthoredEvent, SigningKeyMaterial, append_event};
use trellis_store_memory::MemoryStore;
use trellis_store_postgres_async::{append_checkpointed, checkpoint_at};

mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}
use trellis_types::merkle::{Frontier, TrellisHasher};
use trellis_types::{StoredCheckpoint, StoredEvent};

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
    let db = support::database(8).await;
    let pool = db.owner.clone();

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
            &SigningKeyMaterial::new(signing_key.clone()),
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
        sqlx::query("TRUNCATE TABLE trellis_events, trellis_checkpoints CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        let runner_stored = runner_stored
            .clone()
            .with_canonical_event_hash(Some(postgres_artifacts.canonical_event_hash));
        let issued = issue_checkpoint_for(&runner_stored, &signing_key);
        let stored_checkpoint = issued.stored(runner_stored.scope(), b"profile-state".to_vec());
        let mut tx = db.scoped.begin(&support::a()).await.unwrap();
        append_checkpointed(&mut tx, &runner_stored, &stored_checkpoint)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut tx = db.scoped.begin(&support::a()).await.unwrap();
        let read_back = checkpoint_at(&mut tx, runner_stored.scope(), runner_stored.sequence() + 1)
            .await
            .unwrap()
            .expect("the checkpoint committed with the event");
        drop(tx);
        assert_eq!(
            read_back,
            stored_checkpoint,
            "checkpoint bytes must survive the store unchanged for {}",
            dir.display()
        );
        assert_eq!(read_back.frontier().unwrap(), issued.frontier);

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
            Some(&memory_artifacts.canonical_event_hash),
            "stored canonical_event_hash must be the one core computed for {}",
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
    let db = support::database(8).await;
    let pool = db.owner.clone();

    // Composition root would create this kind of table per its own schema; we
    // model the seam with a simple side table the serving role may write.
    sqlx::raw_sql(&format!(
        "CREATE TABLE projection_demo (case_id TEXT PRIMARY KEY, status TEXT); \
         GRANT SELECT, INSERT ON projection_demo TO {}",
        support::APP_ROLE
    ))
    .execute(&pool)
    .await
    .unwrap();

    // Happy path: canonical + projection commit together.
    {
        let mut tx = db.scoped.begin(&support::a()).await.unwrap();
        let (event, checkpoint) = first_event_and_checkpoint(b"case-1", vec![0xab], vec![0xcd]);
        append_checkpointed(&mut tx, &event, &checkpoint)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projection_demo (case_id, status) VALUES ($1, $2)")
            .bind("case-1")
            .bind("open")
            .execute(tx.conn())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(scope_event_count(&pool, b"case-1").await, 1);

    // Sad path: projection write fails -> canonical event MUST roll back.
    {
        let mut tx = db.scoped.begin(&support::a()).await.unwrap();
        let (event, checkpoint) = first_event_and_checkpoint(b"case-2", vec![0xee], vec![0xff]);
        append_checkpointed(&mut tx, &event, &checkpoint)
            .await
            .unwrap();
        // PK conflict against case-1 row.
        let projection_err =
            sqlx::query("INSERT INTO projection_demo (case_id, status) VALUES ($1, $2)")
                .bind("case-1")
                .bind("duplicate")
                .execute(tx.conn())
                .await;
        assert!(projection_err.is_err());
        drop(tx);
    }
    assert!(
        scope_event_count(&pool, b"case-2").await == 0,
        "rolled-back tx left canonical event visible"
    );
}

/// The checkpoint a service would issue for `event`: a corpus event at sequence `n` follows `n`
/// earlier leaves, which stand in as arbitrary hashes since only this event's bytes are in play.
fn issue_checkpoint_for(event: &StoredEvent, signing_key: &[u8]) -> IssuedCheckpoint {
    let mut earlier = Frontier::new();
    for index in 0..event.sequence() {
        earlier.push(&TrellisHasher, &index.to_be_bytes());
    }
    let prior = (event.sequence() > 0).then_some(PriorCheckpoint {
        digest: [0x5a; 32],
        frontier: &earlier,
    });
    issue_checkpoint(
        &trellis_core::SigningKeyMaterial::new(signing_key.to_vec()),
        event.scope(),
        prior,
        *event.canonical_event_hash().expect("hash set"),
        (1_700_000_000, 0),
    )
    .unwrap()
}

fn first_event_and_checkpoint(
    scope: &[u8],
    canonical: Vec<u8>,
    signed: Vec<u8>,
) -> (StoredEvent, StoredCheckpoint) {
    let event = StoredEvent::new(scope.to_vec(), 0, canonical, signed)
        .with_canonical_event_hash(Some([0x11; 32]));
    let mut frontier = Frontier::new();
    frontier.push(&TrellisHasher, &[0x11; 32]);
    let checkpoint = StoredCheckpoint {
        scope: scope.to_vec(),
        tree_size: 1,
        digest: [0x22; 32],
        checkpoint: b"sign1".to_vec(),
        frontier: frontier.to_bytes(),
        profile_state: Vec::new(),
    };
    (event, checkpoint)
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
