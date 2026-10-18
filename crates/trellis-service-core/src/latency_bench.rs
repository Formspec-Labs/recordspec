// Rust guideline compliant 2026-02-21
// ADR 0168 §5: append and export latency with row security on and off, on Trellis's own path.
//
// Not a gate: run it with
//   cargo nextest run --release -p trellis-service-core --run-ignored only \
//       -E 'test(latency_with_row_security_on_and_off)' --no-capture
// Each mode gets a fresh TLS cluster migrated as the owner and served through the app role, a
// shared deployment's table shape (100 other ledgers, each under its own scope), and the composed router
// in process, so a sample is the whole request: gate, scoped transaction, row security, signing
// and export assembly, without a network hop.

use std::time::{Duration, Instant};

use super::*;

mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

/// Appends timed per mode, after a warm-up.
const APPENDS: usize = 600;
const WARM_UP: usize = 50;
/// Exports timed per mode, of a ledger of `EXPORT_EVENTS` events.
const EXPORTS: usize = 200;
const EXPORT_EVENTS: usize = 40;

fn percentile(samples: &mut [Duration], percent: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() * percent / 100).min(samples.len() - 1)]
}

async fn measure(row_security: bool) -> (Vec<Duration>, Vec<Duration>) {
    let db = support::database(8).await;
    // A shared deployment's other ledgers: 100 of 1000 events, each under its own scope.
    sqlx::raw_sql(
        "CREATE TEMP TABLE filler AS SELECT g, g / 1000 AS l, \
             decode(md5((g / 1000)::text) || md5((g / 1000)::text), 'hex') AS k \
         FROM generate_series(0, 99999) AS g; \
         INSERT INTO trellis_events (scope_key, scope, sequence, canonical_event, signed_event, \
             idempotency_key, canonical_event_hash) \
         SELECT k, convert_to(encode(k, 'hex') || '.filler-' || l, 'UTF8'), g % 1000, \
             '\\x01'::bytea, '\\x02'::bytea, convert_to('k' || g, 'UTF8'), \
             decode(repeat('ab', 32), 'hex') FROM filler;",
    )
    .execute(&db.owner)
    .await
    .unwrap();
    sqlx::query("ANALYZE trellis_events")
        .execute(&db.owner)
        .await
        .unwrap();
    if !row_security {
        for table in trellis_store_postgres_async::TABLES {
            sqlx::raw_sql(&format!(
                "ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY; \
                 ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"
            ))
            .execute(&db.owner)
            .await
            .unwrap();
        }
    }
    let fixture = Fixture::over(
        TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
        Arc::new(trellis_store_postgres_async::PgLedgers::new(db.scoped.clone())),
        Arc::new(object_store::memory::InMemory::new()),
    );
    let app = router(fixture).unwrap();

    let mut appends = Vec::with_capacity(APPENDS);
    for index in 0..WARM_UP + APPENDS {
        let request = post_request(
            "/v1/scopes/case_bench/events",
            append_body(&format!("bench-{index:05}")),
        );
        let started = Instant::now();
        let response = app.clone().oneshot(request).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(response.status(), StatusCode::CREATED);
        if index >= WARM_UP {
            appends.push(elapsed);
        }
    }

    for index in 0..EXPORT_EVENTS {
        let response = app
            .clone()
            .oneshot(post_request(
                "/v1/scopes/case_export/events",
                append_body(&format!("export-{index:03}")),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let mut exports = Vec::with_capacity(EXPORTS);
    for index in 0..WARM_UP / 5 + EXPORTS {
        let started = Instant::now();
        let response = app
            .clone()
            .oneshot(get_request("/v1/scopes/case_export/bundles/head"))
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), 64 << 20).await.unwrap();
        let elapsed = started.elapsed();
        assert!(bytes.len() > 100);
        if index >= WARM_UP / 5 {
            exports.push(elapsed);
        }
    }
    (appends, exports)
}

#[tokio::test]
#[ignore = "latency measurement, not a gate; see the module comment"]
async fn latency_with_row_security_on_and_off() {
    let mut lines = Vec::new();
    for row_security in [false, true, false, true] {
        let (mut appends, mut exports) = measure(row_security).await;
        lines.push(format!(
            "row security {:<3}  append p50 {:>7.2} ms  p99 {:>7.2} ms   \
             export ({EXPORT_EVENTS} events) p50 {:>7.2} ms  p99 {:>7.2} ms",
            if row_security { "on" } else { "off" },
            percentile(&mut appends, 50).as_secs_f64() * 1e3,
            percentile(&mut appends, 99).as_secs_f64() * 1e3,
            percentile(&mut exports, 50).as_secs_f64() * 1e3,
            percentile(&mut exports, 99).as_secs_f64() * 1e3,
        ));
    }
    println!(
        "Trellis latency, in process over TLS Postgres 16 through the app role \
         ({APPENDS} appends, {EXPORTS} exports per run):"
    );
    for line in lines {
        println!("  {line}");
    }
}
