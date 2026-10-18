// Rust guideline compliant 2026-02-21
//! ADR 0168 §5's acceptance on Trellis's hot tables: every read the adapter runs
//! (`statements::READS`, the SQL it sends, not a copy) walks its intended `(scope_key, scope, …)`
//! index in order — no Sort, no Seq Scan, nothing left to a filter — with row security off and
//! on, as the custom plan a first execution gets and as the generic plan a pooled connection
//! settles on after five, through the app role's scoped transaction.
//!
//! Two distributions: a deployment's (most ledgers under one scope, a few under others) and a
//! shared deployment's (every ledger under its own scope). Without the schema's dependency
//! statistics on `(scope_key, scope)`, the second misplanned every point lookup, row security on
//! or off: the planner multiplied the two key columns' selectivities, estimated a ledger at a
//! fraction of a row, and picked among indexes sharing the `(scope_key, scope)` prefix by cost
//! ties (event by key walked the primary key and filtered the idempotency key). With them, point
//! lookups plan exactly in both; a short range read over interleaved rows may take a bitmap scan
//! of the primary key and sort that range, which costs no more than the range itself.

mod support;

use stack_common_postgres::testing::plans;
use trellis_store_postgres_async::TABLES;
use trellis_store_postgres_async::statements::READS;

/// The index each read must walk.
const INDEXES: &[(&str, &[&str])] = &[
    ("head checkpoint", &["trellis_checkpoints_pkey"]),
    ("checkpoint at", &["trellis_checkpoints_pkey"]),
    ("checkpoint by digest", &["trellis_checkpoints_digest_key"]),
    ("checkpoints through", &["trellis_checkpoints_pkey"]),
    ("last event", &["trellis_events_pkey"]),
    ("event by key", &["trellis_events_idempotency_uidx"]),
    ("prefix", &["trellis_events_pkey"]),
    ("events before", &["trellis_events_pkey"]),
    (
        "attachment by key",
        &[
            "trellis_external_attachments_idempotency_key",
            "trellis_events_pkey",
        ],
    ),
    ("attachment lengths", &["trellis_external_attachments_pkey"]),
    (
        "attachments before",
        &["trellis_external_attachments_pkey", "trellis_events_pkey"],
    ),
    ("source content", &["trellis_source_contents_pkey"]),
];

/// `ledgers` ledgers of 2000 events and checkpoints each, every tenth event with an attachment and
/// a Source binding; ledger `i` is under scope `A_KEY` when `i < in_a`, else under its own key.
const FILL: &str = "\
CREATE TEMP TABLE fill AS
SELECT g, g % LEDGERS AS l, g / LEDGERS AS seq,
    CASE WHEN g % LEDGERS < IN_A THEN decode('A_KEY', 'hex')
         ELSE decode(md5((g % LEDGERS)::text) || md5((g % LEDGERS)::text), 'hex') END AS k
FROM generate_series(0, LEDGERS * 2000 - 1) AS g;
INSERT INTO trellis_events (scope_key, scope, sequence, canonical_event, signed_event,
    idempotency_key, canonical_event_hash)
SELECT k, convert_to(encode(k, 'hex') || '.ledger-' || l, 'UTF8'), seq, '\\x01', '\\x02',
    convert_to('key-' || g, 'UTF8'), decode(repeat('ab', 32), 'hex')
FROM fill;
INSERT INTO trellis_checkpoints (scope_key, scope, tree_size, digest, checkpoint, frontier,
    profile_state)
SELECT k, convert_to(encode(k, 'hex') || '.ledger-' || l, 'UTF8'), seq + 1,
    decode(lpad(to_hex(g), 64, '0'), 'hex'), '\\x03',
    decode(repeat('00', (32 * bit_count((seq + 1)::bit(64)))::int), 'hex'), '\\x'
FROM fill;
INSERT INTO trellis_external_attachments (scope_key, scope, sequence, idempotency_key,
    content_hash, ciphertext, nonce, replay_identity, compute_json)
SELECT scope_key, scope, sequence, idempotency_key, decode(md5(sequence::text) ||
    md5(sequence::text), 'hex'), '\\x00', decode(repeat('00', 12), 'hex'),
    decode(repeat('00', 32), 'hex'), '{}'
FROM trellis_events WHERE sequence % 10 = 0;
INSERT INTO trellis_source_contents (scope_key, scope, sequence, batch_hash, size, artifact_ref)
SELECT scope_key, scope, sequence, decode(repeat('cd', 32), 'hex'), 1, 'batch'
FROM trellis_events WHERE sequence % 10 = 0;
ANALYZE trellis_events, trellis_checkpoints, trellis_external_attachments,
    trellis_source_contents;";

/// A's ledger the reads name: ledger 0, under scope A in every distribution.
fn ledger() -> String {
    format!("{}.ledger-0", support::a().key())
}

/// The digest of ledger 0's checkpoint at tree size 3 (row `g = 2 * LEDGERS = 100`).
fn digest() -> [u8; 32] {
    let mut digest = [0_u8; 32];
    digest[31] = 100;
    digest
}

/// The custom plan: the statement with its values bound, as a first execution plans it.
async fn custom(db: &support::Database, name: &str, sql: &str) -> String {
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    let explain = format!("EXPLAIN {sql}");
    let ledger = ledger();
    let query = tx.query_scalar::<String>(&explain).bind(ledger.as_bytes());
    let query = match name {
        "checkpoint at"
        | "checkpoints through"
        | "events before"
        | "attachments before"
        | "source content" => query.bind(30_i64),
        // A bounded prefix of a 2000-event ledger, as the seal and attachment flows read it. (On
        // a ledger of a few hundred events the planner may sort the whole short ledger instead.)
        "prefix" => query.bind(257_i64),
        "attachment lengths" => query.bind(30_i64).bind(257_i64),
        "checkpoint by digest" => query.bind(digest().to_vec()),
        // Row `g = 0`: ledger 0's event 0, which carries an attachment.
        "event by key" | "attachment by key" => query.bind(b"key-0".as_slice()),
        "head checkpoint" | "last event" => query,
        other => panic!("no values for read `{other}`"),
    };
    let lines: Vec<String> = query.fetch_all(tx.conn()).await.unwrap();
    lines.join("\n")
}

/// The generic plan, which a pooled connection's prepared statement settles on.
async fn generic(db: &support::Database, sql: &str) -> String {
    let mut tx = db.scoped.begin(&support::a()).await.unwrap();
    plans::generic(tx.conn(), sql).await
}

/// Every read's plans, custom and generic, as `(label, plan)`.
async fn plans(db: &support::Database, mode: &str) -> Vec<(String, &'static str, String)> {
    let mut found = Vec::new();
    for (name, sql) in READS {
        found.push((
            format!("row security {mode}, {name}, custom"),
            *name,
            custom(db, name, sql).await,
        ));
        found.push((
            format!("row security {mode}, {name}, generic"),
            *name,
            generic(db, sql).await,
        ));
    }
    found
}

/// An export's range reads, whose whole range it needs in order anyway. `prefix` is not one: it
/// reads a bounded prefix of a ledger of any length and must never sort the whole ledger.
const RANGES: &[&str] = &[
    "checkpoints through",
    "events before",
    "attachment lengths",
    "attachments before",
];

/// Fills the tables, plans every read with row security on, then off, and returns what fails.
///
/// With `sorted_ranges`, a range read may sort its own primary-key range.
async fn violations(ledgers: usize, in_a: usize, sorted_ranges: bool) -> Vec<String> {
    let db = support::database(1).await;
    let fill = FILL
        .replace("LEDGERS", &ledgers.to_string())
        .replace("IN_A", &in_a.to_string())
        .replace("A_KEY", &support::a().key().to_string());
    sqlx::raw_sql(&fill).execute(&db.owner).await.unwrap();
    let mut all = plans(&db, "on").await;
    for table in TABLES {
        sqlx::raw_sql(&format!(
            "ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY; \
             ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"
        ))
        .execute(&db.owner)
        .await
        .unwrap();
    }
    all.extend(plans(&db, "off").await);
    let mut failures = Vec::new();
    for (label, name, plan) in all {
        let indexes = INDEXES
            .iter()
            .find(|(read, _)| *read == name)
            .map(|(_, indexes)| *indexes)
            .unwrap_or_else(|| panic!("no expected index for read `{name}`"));
        let wrong = plans::violations(&plan, indexes, sorted_ranges && RANGES.contains(&name));
        if !wrong.is_empty() {
            failures.push(format!("{label}: {}\n{plan}", wrong.join(", ")));
        }
    }
    failures
}

/// A deployment: 47 ledgers under scope A and three under three other scopes.
#[tokio::test]
async fn every_hot_read_walks_its_index_without_a_sort_or_filter_with_row_security_off_and_on() {
    let failures = violations(50, 47, false).await;
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// Fifty ledgers, each under its own scope: the shape a shared deployment of many tenants has.
#[tokio::test]
async fn with_many_scopes_every_point_read_still_walks_its_index_with_row_security_off_and_on() {
    let failures = violations(50, 1, true).await;
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
