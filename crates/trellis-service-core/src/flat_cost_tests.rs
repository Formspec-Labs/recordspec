// Rust guideline compliant 2026-02-21
// An append costs the same at any ledger length, and the failure modes of the one transaction
// that makes it durable.

use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::*;
use crate::repository_probes::{
    Counts, CountingArtifactStore, CountingRepository, Fault, FaultyRepository,
};

const APPENDS: u64 = 1024;

/// Per table: name, sequential scans, index tuples fetched; the growth over one append.
type TableDelta = (String, i64, i64);

fn append_command(scope: &str, key: &str) -> append::AppendCommand {
    let body: SubstrateAppendBody = serde_json::from_slice(&append_body(key)).unwrap();
    append::AppendCommand {
        scope: scope.to_string(),
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

fn counted_state(
    repository: Arc<dyn EventRepository>,
) -> (TrellisServerState, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let state = TrellisServerState::new(
        Arc::new(CountingRepository {
            inner: repository,
            counts: counts.clone(),
        }),
        test_signing_key(),
        crate::test_adapters::adapters(),
    )
    .with_artifact_store(Arc::new(CountingArtifactStore {
        inner: Arc::new(crate::artifacts::InMemoryArtifactStore::default()),
        counts: counts.clone(),
    }));
    (state, counts)
}

/// Appends [`APPENDS`] events to one scope and returns what each append cost.
async fn costs_of_each_append(state: &TrellisServerState, counts: &Counts) -> Vec<[u64; 4]> {
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
    let (state, counts) = counted_state(Arc::new(InMemoryEventRepository::new()));
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
    let zip = export::assemble(&state, b"case_flat", &head)
        .await
        .expect("export of the whole ledger");
    assert!(export_bundle_cryptographically_verified(&zip));
}

/// The same loop on Postgres 16, asking the database what it did: no append scans a table, and
/// the index tuples an append fetches do not depend on the ledger's length.
#[tokio::test]
async fn append_cost_is_flat_in_ledger_length_on_postgres() {
    use stack_common_postgres::testing::EphemeralCluster;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-store-postgres-async/tests/support/mod.rs"
        ));
    }

    let cluster = EphemeralCluster::start_required();
    // One connection serves the appends and the statistics reads: a backend flushes its own
    // counters only on request, and `pg_stat_force_next_flush` asks from inside that backend.
    let pool = support::tls_pool(&cluster, 1).await;
    trellis_store_postgres_async::run_migrations(&pool).await.unwrap();
    let (state, counts) = counted_state(Arc::new(PostgresEventRepository::new(pool.clone())));

    // A deployment-wide ledger already holds other scopes' rows. Tiny tables are scanned by any
    // planner; this one must show that an append stays on the indexes once there is data.
    sqlx::query(
        "INSERT INTO trellis_events (scope, sequence, canonical_event, signed_event, \
         idempotency_key, canonical_event_hash) \
         SELECT convert_to('filler-' || (g / 1000), 'UTF8'), g % 1000, '\\x01'::bytea, \
         '\\x02'::bytea, convert_to('k' || g, 'UTF8'), decode(repeat('ab', 32), 'hex') \
         FROM generate_series(0, 99999) AS g",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO trellis_checkpoints (scope, tree_size, digest, checkpoint, frontier, \
         profile_state) \
         SELECT convert_to('filler-' || (g / 1000), 'UTF8'), (g % 1000) + 1, \
         decode(lpad(to_hex(g), 64, '0'), 'hex'), '\\x03'::bytea, \
         decode(repeat('00', (32 * bit_count(((g % 1000) + 1)::bit(64)))::int), 'hex'), '\\x'::bytea \
         FROM generate_series(0, 99999) AS g",
    )
    .execute(&pool)
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
        .execute(&pool)
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
    use stack_common_postgres::testing::EphemeralCluster;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../trellis-store-postgres-async/tests/support/mod.rs"
        ));
    }

    let cluster = EphemeralCluster::start_required();
    let pool = support::tls_pool(&cluster, 16).await;
    trellis_store_postgres_async::run_migrations(&pool).await.unwrap();
    let replica = |pool: &sqlx::PgPool| {
        TrellisServerState::new(
            Arc::new(PostgresEventRepository::new(pool.clone())),
            test_signing_key(),
            crate::test_adapters::adapters(),
        )
    };
    let replicas = [replica(&pool), replica(&pool)];
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
    let zip = export::assemble(&replicas[1], b"case_race", &head).await.unwrap();
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
    let state = TrellisServerState::new(
        Arc::new(FaultyRepository {
            inner: Arc::new(InMemoryEventRepository::new()),
            fault: fault.clone(),
        }),
        test_signing_key(),
        crate::test_adapters::adapters(),
    );
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
    let state = TrellisServerState::new(
        Arc::new(FaultyRepository {
            inner: Arc::new(InMemoryEventRepository::new()),
            fault: Arc::new(Fault::FirstCommits(AtomicUsize::new(2))),
        }),
        test_signing_key(),
        crate::test_adapters::adapters(),
    );
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
