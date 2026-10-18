// Rust guideline compliant 2026-02-21
// An append costs the same at any ledger length, and the failure modes of the one transaction
// that makes it durable.

use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::*;
use crate::repository_probes::{
    CountObjectBytes, CountingLedgers, Counts, Fault, FaultyLedgers, HookedStore,
};
use crate::test_support::ledger;
use trellis_server_ports::Ledgers;
use trellis_store_postgres_async::PgLedgers;

const APPENDS: u64 = 1024;

/// Per table: name, sequential scans, index tuples fetched; the growth over one append.
type TableDelta = (String, i64, i64);

fn append_command(scope: &str, key: &str) -> append::AppendCommand {
    let body: SubstrateAppendBody = serde_json::from_slice(&append_body(key)).unwrap();
    append::AppendCommand {
        scope: ledger(scope),
        event_type: body.event_type,
        idempotency_key: body.idempotency_key,
        payload: body.payload,
        client_attestation: body.client_attestation,
    }
}

/// Width in bytes of a CBOR unsigned integer: the only part of a stored row that grows with the
/// sequence number.
fn cbor_uint_len(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

fn counted_state(ledgers: Arc<dyn Ledgers>) -> (Fixture, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let state = Fixture::over(
        TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
        Arc::new(CountingLedgers {
            inner: ledgers,
            counts: counts.clone(),
        }),
        HookedStore::new(CountObjectBytes(counts.clone())),
    );
    (state, counts)
}

/// Appends [`APPENDS`] events to one scope and returns what each append cost.
async fn costs_of_each_append(state: &Fixture, counts: &Counts) -> Vec<[u64; 4]> {
    let mut costs = Vec::new();
    for index in 1..=APPENDS {
        let before = counts.snapshot();
        state
            .append_coordinator()
            .append(append_command("case_flat", &format!("idem-flat-{index:05}")))
            .await
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
        let after = counts.snapshot();
        costs.push(std::array::from_fn(|i| after[i] - before[i]));
    }
    costs
}

/// `costs[0]` is the cost of append number `first_append`; every later append must cost the same
/// as it, plus the frontier's growth.
fn assert_cost_is_flat(costs: &[[u64; 4]], first_append: u64) {
    const READS: usize = 0;
    const WRITES: usize = 1;
    const DB_BYTES: usize = 2;
    const OBJECT_BYTES: usize = 3;
    let baseline = costs[0];
    assert!(
        baseline[READS] <= 3,
        "an append reads at most the head, the last event and the key: {}",
        baseline[READS]
    );
    // What an append stores beyond the frontier's 32 bytes per set bit is constant up to the width
    // of the integers that count events (sequence, tree size) and the clock's nanoseconds. A slack
    // of half a hash cannot hide a single hash of growth per append.
    let fixed = |index: usize| {
        costs[index][DB_BYTES] as i128
            - 32 * i128::from((first_append + index as u64).count_ones())
    };
    for (index, cost) in costs.iter().enumerate() {
        let append = first_append + index as u64;
        assert_eq!(cost[READS], baseline[READS], "rows read by append {append}");
        assert_eq!(cost[WRITES], 2, "rows written by append {append}: event and checkpoint");
        assert_eq!(cost[OBJECT_BYTES], 0, "object-store bytes of append {append}");
        let drift = (fixed(index) - fixed(0)).abs();
        assert!(
            drift <= 16 + 3 * i128::from(cbor_uint_len(append)),
            "stored bytes of append {append} drifted {drift} from append {first_append} \
             beyond the frontier"
        );
    }
}

/// Given one scope growing to 1024 events, when each append is counted at the repository and
/// artifact-store ports, then every append from the second on reads the same few rows, writes
/// exactly the event and its checkpoint, and writes no object bytes.
#[tokio::test]
async fn append_cost_is_flat_in_ledger_length() {
    let (state, counts) = counted_state(Arc::new(MemoryLedgers::new()));
    let costs = costs_of_each_append(&state, &counts).await;
    assert_eq!(costs[0][0], 0, "the first append reads nothing: there is no head");
    assert_eq!(costs[0][1], 2, "the first append writes the event and its checkpoint");
    assert_cost_is_flat(&costs[1..], 2);

    // The 1024-event ledger still exports, and the independent verifier accepts the export.
    let head = state
        .repository
        .head_checkpoint(b"case_flat")
        .await
        .unwrap()
        .expect("head");
    assert_eq!(head.tree_size, APPENDS);
    let zip = crate::test_support::assemble(&state, b"case_flat", &head)
        .await
        .expect("export of the whole ledger");
    assert!(export_bundle_cryptographically_verified(&zip));
}

/// The same loop on Postgres 16, asking the database what it did: no append scans a table, and
/// the index tuples an append fetches do not depend on the ledger's length.
#[tokio::test]
async fn append_cost_is_flat_in_ledger_length_on_postgres() {
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-store-postgres-async/tests/support/mod.rs"
        ));
    }

    // One connection serves the appends and the statistics reads: a backend flushes its own
    // counters only on request, and `pg_stat_force_next_flush` asks from inside that backend.
    let db = support::database(1).await;
    let pool = db.app.clone();
    let (state, counts) = counted_state(Arc::new(PgLedgers::new(db.scoped.clone())));

    // A shared deployment's tables already hold 100 other ledgers of 1000 events, each under its
    // own scope: the spread that misled the planner before the schema's dependency statistics.
    // Tiny tables are scanned by any planner; this one must show that an append stays on the
    // indexes once there is data, with row security on.
    sqlx::raw_sql(
        "CREATE TEMP TABLE filler AS SELECT g, g / 1000 AS l, \
             decode(md5((g / 1000)::text) || md5((g / 1000)::text), 'hex') AS k \
         FROM generate_series(0, 99999) AS g; \
         INSERT INTO trellis_events (scope_key, scope, sequence, canonical_event, signed_event, \
             idempotency_key, canonical_event_hash) \
         SELECT k, convert_to(encode(k, 'hex') || '.filler-' || l, 'UTF8'), g % 1000, \
             '\\x01'::bytea, '\\x02'::bytea, convert_to('k' || g, 'UTF8'), \
             decode(repeat('ab', 32), 'hex') FROM filler; \
         INSERT INTO trellis_checkpoints (scope_key, scope, tree_size, digest, checkpoint, \
             frontier, profile_state) \
         SELECT k, convert_to(encode(k, 'hex') || '.filler-' || l, 'UTF8'), (g % 1000) + 1, \
             decode(lpad(to_hex(g), 64, '0'), 'hex'), '\\x03'::bytea, \
             decode(repeat('00', (32 * bit_count(((g % 1000) + 1)::bit(64)))::int), 'hex'), \
             '\\x'::bytea FROM filler;",
    )
    .execute(&db.owner)
    .await
    .unwrap();
    for index in 0..8 {
        state
            .append_coordinator()
            .append(append_command("case_flat", &format!("idem-warm-{index}")))
            .await
            .unwrap();
    }
    sqlx::query("ANALYZE trellis_events, trellis_checkpoints")
        .execute(&db.owner)
        .await
        .unwrap();
    let stats = || async {
        sqlx::query("SELECT pg_stat_force_next_flush()")
            .execute(&pool)
            .await
            .unwrap();
        let rows: Vec<TableDelta> = sqlx::query_as(
            "SELECT relname::text, seq_scan, COALESCE(idx_tup_fetch, 0)::bigint \
             FROM pg_stat_user_tables \
             WHERE relname IN ('trellis_events', 'trellis_checkpoints') ORDER BY relname",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        rows
    };

    let mut deltas = Vec::new();
    let mut costs = Vec::new();
    for index in 9..=APPENDS {
        let (before, rows_before) = (stats().await, counts.snapshot());
        state
            .append_coordinator()
            .append(append_command("case_flat", &format!("idem-flat-{index:05}")))
            .await
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
        let (after, rows_after) = (stats().await, counts.snapshot());
        deltas.push(
            before
                .iter()
                .zip(&after)
                .map(|(b, a)| (a.0.clone(), a.1 - b.1, a.2 - b.2))
                .collect::<Vec<_>>(),
        );
        costs.push(std::array::from_fn(|i| rows_after[i] - rows_before[i]));
    }
    assert_cost_is_flat(&costs, 9);
    for delta in &deltas {
        for (table, seq_scans, _) in delta {
            assert_eq!(*seq_scans, 0, "an append scanned {table}");
        }
    }
    let mut distinct: Vec<(Vec<TableDelta>, usize)> = Vec::new();
    for delta in &deltas {
        match distinct.iter_mut().find(|(seen, _)| seen == delta) {
            Some((_, count)) => *count += 1,
            None => distinct.push((delta.clone(), 1)),
        }
    }
    assert_eq!(
        distinct.len(),
        1,
        "index tuples fetched per append changed with ledger length: {distinct:?}"
    );
    assert_eq!(
        distinct[0].0,
        [
            ("trellis_checkpoints".to_owned(), 0, 1),
            ("trellis_events".to_owned(), 0, 1)
        ],
        "an append fetches the head checkpoint and the last event, nothing else"
    );
}

/// Given two server replicas over one database, when they append to one scope at the same time,
/// then every append commits at its own sequence and none answers 409.
#[tokio::test]
async fn replicas_racing_one_scope_all_commit_and_none_answers_409() {
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-store-postgres-async/tests/support/mod.rs"
        ));
    }

    let db = support::database(16).await;
    let replica = || {
        Fixture::over(
            TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
            Arc::new(PgLedgers::new(db.scoped.clone())),
            Arc::new(object_store::memory::InMemory::new()),
        )
    };
    let replicas = [replica(), replica()];
    let mut racers = tokio::task::JoinSet::new();
    for index in 0..16usize {
        let state = replicas[index % 2].clone();
        racers.spawn(async move {
            let app = router(state).expect("router");
            let response = app
                .oneshot(post_request(
                    "/v1/scopes/case_race/events",
                    append_body(&format!("idem-race-{index}")),
                ))
                .await
                .expect("race response");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            (status, bytes)
        });
    }
    let mut sequences = Vec::new();
    while let Some(done) = racers.join_next().await {
        let (status, bytes) = done.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&bytes));
        sequences.push(serde_json::from_slice::<SubstrateAppendResult>(&bytes).unwrap().sequence);
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (0..16).collect::<Vec<_>>());
    let head = replicas[0]
        .repository
        .head_checkpoint(b"case_race")
        .await
        .unwrap()
        .unwrap();
    let zip = crate::test_support::assemble(&replicas[1], b"case_race", &head).await.unwrap();
    assert!(
        export_bundle_cryptographically_verified(&zip),
        "the interleaved ledger is one chain"
    );
}

/// Given a unit of work that loses a race on a unique key, when the append is posted, then the
/// answer is a retryable 503 that the HTTP idempotency layer does not cache, and the same request
/// succeeds once the race is gone.
#[tokio::test]
async fn a_lost_race_answers_503_and_is_not_cached() {
    let armed = Fault::LostRace(AtomicBool::new(true));
    let fault = Arc::new(armed);
    let state = test_state().with_ledgers(Arc::new(FaultyLedgers {
        inner: Arc::new(MemoryLedgers::new()),
        fault: fault.clone(),
    }));
    let app = router(state.clone()).expect("router");
    let body = append_body("idem-lost-race");
    let lost = app
        .clone()
        .oneshot(post_request("/v1/scopes/case_lost_race/events", body.clone()))
        .await
        .unwrap();
    assert_eq!(lost.status(), StatusCode::SERVICE_UNAVAILABLE);

    let Fault::LostRace(flag) = &*fault else { unreachable!() };
    flag.store(false, std::sync::atomic::Ordering::SeqCst);
    let retry = app
        .oneshot(post_request("/v1/scopes/case_lost_race/events", body))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CREATED);
    assert!(
        retry.headers().get(IDEMPOTENCY_REPLAY_HEADER).is_none(),
        "the 503 must not have been recorded for replay"
    );
}

/// Given a store whose commit fails, when the append is retried under the same key, then nothing
/// was written by the failed attempts and the retry commits exactly one event.
#[tokio::test]
async fn a_failed_commit_writes_nothing_and_the_retry_commits_once() {
    let state = test_state().with_ledgers(Arc::new(FaultyLedgers {
        inner: Arc::new(MemoryLedgers::new()),
        fault: Arc::new(Fault::FirstCommits(AtomicUsize::new(2))),
    }));
    let app = router(state.clone()).expect("router");
    let path = "/v1/scopes/case_commit_fault/events";
    for attempt in 0..2 {
        let response = app
            .clone()
            .oneshot(post_request(path, append_body("idem-commit-fault")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "attempt {attempt}");
        assert!(
            state.repository.head_checkpoint(b"case_commit_fault").await.unwrap().is_none(),
            "a failed commit leaves no event and no checkpoint"
        );
    }
    let receipt = post_append(&app, path, append_body("idem-commit-fault")).await;
    assert_eq!(receipt.sequence, 0);
    assert_eq!(
        state.repository.list_scope(b"case_commit_fault").await.unwrap().len(),
        1
    );
}

/// Given a ledger of three events, then the export pinned at each receipt's checkpoint is the
/// export of exactly that prefix, and each verifies on its own.
#[tokio::test]
async fn an_export_at_an_earlier_checkpoint_is_the_export_of_that_prefix() {
    let state = test_state();
    let app = router(state.clone()).expect("router");
    let mut receipts = Vec::new();
    for key in ["idem-prefix-1", "idem-prefix-2", "idem-prefix-3"] {
        receipts.push(post_append(&app, "/v1/scopes/case_prefix/events", append_body(key)).await);
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let zip = pinned_zip(&app, "case_prefix", receipt).await;
        assert!(export_bundle_cryptographically_verified(&zip), "prefix {index}");
        assert_eq!(
            manifest_head_checkpoint_digest(&zip),
            checkpoint_digest_of(receipt)
        );
        let manifest = manifest_payload_from_bundle(&zip);
        assert_eq!(
            map_lookup_u64(manifest.as_map().unwrap(), "tree_size").unwrap(),
            index as u64 + 1
        );
        assert!(seen.insert(zip), "each prefix has its own bytes");
    }
}

/// Given the clock reads earlier than the last event, then the new event is stamped with the last
/// event's time, so replicas with skewed clocks still produce an ordered ledger.
#[tokio::test]
async fn a_clock_behind_the_last_event_cannot_order_events_backwards() {
    let state = test_state();
    state
        .append_coordinator()
        .append(append_command("case_clock", "idem-clock"))
        .await
        .unwrap();
    let last = state.repository.last_event(b"case_clock").await.unwrap().unwrap();
    let at = event_timestamp(&last).unwrap();
    let behind = TrellisTimestamp::new(at.unix_secs - 10, 0).unwrap();
    let ahead = TrellisTimestamp::new(at.unix_secs + 10, 5).unwrap();
    assert_eq!(crate::ledger::authored_at_after(Some(&last), behind).unwrap(), at);
    assert_eq!(crate::ledger::authored_at_after(Some(&last), ahead).unwrap(), ahead);
    assert_eq!(crate::ledger::authored_at_after(None, behind).unwrap(), behind);
}

/// Given a ledger whose profile state the next append must continue, then a corrupt stored state
/// stops the append instead of being re-derived from nothing.
#[tokio::test]
async fn a_corrupt_stored_profile_state_refuses_the_next_append() {
    let state = test_state();
    state
        .append_coordinator()
        .append(append_command("case_state", "idem-state-1"))
        .await
        .unwrap();
    let mut head = state.repository.head_checkpoint(b"case_state").await.unwrap().unwrap();
    head.profile_state = vec![0xff; 3];
    let event = state.repository.last_event(b"case_state").await.unwrap().unwrap();
    let error = state
        .checkpointer()
        .after(Some(&head), &event)
        .expect_err("a corrupt state must not be replaced by an empty one");
    assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

fn fixture_key(name: &str) -> ServerSigningKey {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys")
        .join(name);
    ServerSigningKey::from_cose_key_bytes(
        fs::read(path).expect("fixture key"),
        TrellisTimestamp::new(0, 0).unwrap(),
    )
    .expect("signing key")
}

fn public_hex(key: &ServerSigningKey) -> String {
    hex::encode(key.export_key().public_key)
}

/// Public-key history naming `retired` then `current`, in the startup file's JSON shape.
fn history_json(retired: &[(&ServerSigningKey, u64, u64)], current: &ServerSigningKey) -> Vec<u8> {
    let mut rows: Vec<serde_json::Value> = retired
        .iter()
        .map(|(key, from, to)| {
            serde_json::json!({
                "public_key": public_hex(key),
                "valid_from_unix_secs": from,
                "valid_to_unix_secs": to,
            })
        })
        .collect();
    let from = retired.last().map_or(0, |(_, _, to)| *to);
    rows.push(serde_json::json!({
        "public_key": public_hex(current),
        "valid_from_unix_secs": from,
    }));
    serde_json::to_vec(&rows).unwrap()
}

/// Given a ledger written under key A and then continued under key B, then the export at a
/// checkpoint signed by A and the export at a checkpoint signed by B both verify.
#[tokio::test]
async fn exports_before_and_after_a_key_rotation_both_verify() {
    let key_a = fixture_key("issuer-001.cose_key");
    let key_b = fixture_key("issuer-002.cose_key");
    let ledgers: Arc<dyn Ledgers> = Arc::new(MemoryLedgers::new());
    let over = |key: ServerSigningKey| {
        Fixture::over(
            TrellisServerState::new(key, crate::test_adapters::adapters()),
            ledgers.clone(),
            Arc::new(object_store::memory::InMemory::new()),
        )
    };

    let app_a = router(over(key_a.clone())).expect("router");
    let before = post_append(&app_a, "/v1/scopes/case_rotate/events", append_body("idem-rot-1")).await;

    // The rotation instant, a whole second after A's last signature and no later than B's first.
    let rotated_at = now_timestamp().unwrap().unix_secs + 1;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let history = history_json(&[(&key_a, 0, rotated_at)], &key_b);
    let key_b = key_b.with_history_json(&history).expect("history");
    let app_b = router(over(key_b)).expect("router");
    let after = post_append(&app_b, "/v1/scopes/case_rotate/events", append_body("idem-rot-2")).await;

    assert!(export_bundle_cryptographically_verified(
        &pinned_zip(&app_b, "case_rotate", &before).await
    ));
    assert!(export_bundle_cryptographically_verified(
        &pinned_zip(&app_b, "case_rotate", &after).await
    ));
}

/// Given a history file, then startup keeps retired keys retired, each key supersedes the one
/// before, and the registry route publishes every row.
#[test]
fn a_history_publishes_retired_keys_in_a_supersession_chain() {
    let key_a = fixture_key("issuer-001.cose_key");
    let key_b = fixture_key("issuer-002.cose_key");
    let history = history_json(&[(&key_a, 5, 10)], &key_b);
    let rows = key_b
        .clone()
        .with_history_json(&history)
        .expect("history")
        .registry_entries();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].status, trellis_export_writer::SigningKeyStatus::Retired);
    assert_eq!(rows[0].valid_to, Some(TrellisTimestamp::new(10, 0).unwrap()));
    assert_eq!(rows[1].status, trellis_export_writer::SigningKeyStatus::Active);
    assert_eq!(rows[1].supersedes, Some(rows[0].kid));
    assert_eq!(rows[1].kid, key_b.export_key().kid());
}

/// Given a history whose last key is not the configured key, or that is malformed, then startup
/// refuses it.
#[test]
fn a_history_that_does_not_end_at_the_current_key_is_refused() {
    let key_a = fixture_key("issuer-001.cose_key");
    let key_b = fixture_key("issuer-002.cose_key");
    let ends_at_a = history_json(&[(&key_b, 0, 10)], &key_a);
    assert!(key_b.clone().with_history_json(&ends_at_a).is_err());
    assert!(key_b.clone().with_history_json(b"[]").is_err());
    assert!(key_b.clone().with_history_json(b"{}").is_err());
    let repeated = history_json(&[(&key_b, 0, 10)], &key_b);
    assert!(key_b.clone().with_history_json(&repeated).is_err());
    let unretired = serde_json::to_vec(&serde_json::json!([
        {"public_key": public_hex(&key_a), "valid_from_unix_secs": 0},
        {"public_key": public_hex(&key_b), "valid_from_unix_secs": 10},
    ]))
    .unwrap();
    assert!(key_b.with_history_json(&unretired).is_err());
}

/// Given ledgers of five and eight events, then the export assembled at each head verifies with
/// the maintained verifier; with `TRELLIS_ASSEMBLED_EXPORT_VECTOR_DIR` set, the exports are
/// retained as the `export/` vectors `016` (five events) and `017` (eight).
#[tokio::test]
async fn exports_assembled_at_five_and_eight_events_verify() {
    let state = test_state();
    let app = router(state.clone()).expect("router");
    let mut zips = Vec::new();
    for index in 1..=8 {
        let receipt = post_append(
            &app,
            "/v1/scopes/case_assembled/events",
            append_body(&format!("idem-assembled-{index}")),
        )
        .await;
        if index == 5 || index == 8 {
            let zip = pinned_zip(&app, "case_assembled", &receipt).await;
            let report = trellis_verify_wos::verify_export_zip(&zip);
            assert!(report.trellis.integrity_verified, "{index} events: {report:?}");
            zips.push(zip);
        }
    }
    if let Some(directory) = std::env::var_os("TRELLIS_ASSEMBLED_EXPORT_VECTOR_DIR") {
        let directory = std::path::PathBuf::from(directory);
        crate::export_vector::write_export_vector(&directory.join("016-assembled-five-events"), &zips[0]);
        crate::export_vector::write_export_vector(&directory.join("017-assembled-eight-events"), &zips[1]);
    }
}

/// Given a history whose windows run backwards or overlap, then startup refuses it.
#[test]
fn a_history_with_backwards_or_overlapping_windows_is_refused() {
    let key_a = fixture_key("issuer-001.cose_key");
    let key_b = fixture_key("issuer-002.cose_key");
    let rows = |a_from: u64, a_to: u64, b_from: u64| {
        serde_json::to_vec(&serde_json::json!([
            {"public_key": public_hex(&key_a), "valid_from_unix_secs": a_from, "valid_to_unix_secs": a_to},
            {"public_key": public_hex(&key_b), "valid_from_unix_secs": b_from},
        ]))
        .unwrap()
    };
    assert!(key_b.clone().with_history_json(&rows(0, 10, 10)).is_ok());
    assert!(
        key_b.clone().with_history_json(&rows(10, 5, 10)).is_err(),
        "valid_from after valid_to"
    );
    assert!(
        key_b.clone().with_history_json(&rows(0, 10, 9)).is_err(),
        "the next window opens before the last one closed"
    );
}

/// Given a history whose window for the signing key excludes the time of its signatures, then
/// the export is refused rather than shipped for a verifier that would not notice.
#[tokio::test]
async fn an_export_signed_outside_its_keys_window_is_refused() {
    let key_a = fixture_key("issuer-001.cose_key");
    let key_b = fixture_key("issuer-002.cose_key");
    // B is declared to start in the far future, so what it signs now is out of window.
    let history = history_json(&[(&key_a, 0, 4_000_000_000)], &key_b);
    let key_b = key_b.with_history_json(&history).expect("history");
    let app = router(test_state_with_signing_key(key_b)).expect("router");
    let receipt = post_append(&app, "/v1/scopes/case_window/events", append_body("idem-window-1")).await;
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/v1/scopes/case_window/bundles/sha256:{}",
            hex::encode(checkpoint_digest_of(&receipt))
        )))
        .await
        .expect("export response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("outside the validity window"),
        "{body:?}"
    );
}

/// ADR 0169 §1.2: with a Manifest key of its own, the export's manifest cites that key, the
/// registry carries both purposes' keys (each its own chain), and the export verifies.
#[tokio::test]
async fn an_export_signed_by_its_own_manifest_key_verifies_and_carries_both_keys() {
    let manifest = fixture_key("issuer-002.cose_key");
    let state = test_state().map(|state| state.with_manifest_key(manifest.clone()));
    let app = router(state.clone()).expect("router");
    let receipt = post_append(
        &app,
        "/v1/scopes/case_manifest/events",
        append_body("idem-manifest"),
    )
    .await;
    let zip = pinned_zip(&app, "case_manifest", &receipt).await;
    let report = trellis_verify_wos::verify_export_zip(&zip);
    assert!(report.trellis.integrity_verified, "{report:?}");

    let entries = integrity_bundle::read_stored_zip(&zip).unwrap();
    let manifest_bytes = entries
        .iter()
        .find(|entry| entry.path().ends_with("000-manifest.cbor"))
        .expect("manifest member")
        .bytes();
    let signed = integrity_cose::decode_cose_sign1(manifest_bytes).unwrap();
    assert_eq!(
        signed.kid().map(hex::encode),
        Some(manifest.kid_hex()),
        "the manifest cites the Manifest key"
    );
    let registry = state.signing_key_registry();
    assert_eq!(registry.len(), 2);
    assert!(registry.iter().all(|row| row.supersedes.is_none()));
    assert_ne!(state.signing_key.kid_hex(), manifest.kid_hex());
}
