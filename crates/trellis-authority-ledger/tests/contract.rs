// Rust guideline compliant 2026-02-21
//! Contract and integration tests for `TrellisAuthorityLedger` against:
//! 1. `stack_common_authz::testing::MemoryLedger` (reference executable contract),
//! 2. the real in-process `trellis-server` router over `MemoryLedgers`, and
//! 3. the real in-process `trellis-server` router over `PgLedgers` on an ephemeral Postgres 16 cluster.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use integrity_cbor::Value as Cbor;
use object_store::memory::InMemory;
use serde_json::{Value, json};
use stack_common_auth::{AccessTokenError, AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_authz::ports::{
    AuthorityLedger, Head, Ledger, LedgerFailure, MAX_LEDGER_KEY_BYTES, MAX_ORDERED_EVENTS,
    Reconcile,
};
use stack_common_authz::projection::{ACTIVATION, DECISION, Fold, FoldSnapshot, GRANT, REVOCATION};
use stack_common_authz::testing::MemoryLedger;
use stack_common_error::StackError;
use stack_common_object_store::ScopedBucket;
use stack_common_ops::HealthRouter;
use stack_common_scope::{Cell, Deployment, Scope, ScopeKey};
use tokio::net::TcpListener;
use trellis_authority_ledger::TrellisAuthorityLedger;
use trellis_core::{AuthoredEvent, LedgerStore, SigningKeyMaterial};
use trellis_export_writer::TrellisTimestamp;
use trellis_server::test_harness::{multi_producer_memory_state, one_scope};
use trellis_server::{MemoryLedgers, TrellisServerState, TrellisStore, router};
use trellis_server_ports::{
    AuthorizedScope, Ledgers, ScopeAction, ScopeAuthorization, ScopeAuthorizer,
};
use trellis_service_client::{
    TrellisServiceClient, TrellisServiceClientConfig, canonical_append_content,
};
use trellis_types::{StoredCheckpoint, StoredEvent};

mod pg {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

fn scope_a() -> Scope {
    Scope::fixture("acme", "benefits", Some("prod"))
}

fn scope_b() -> Scope {
    Scope::fixture("globex", "benefits", Some("prod"))
}

fn authority_cases() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../fixtures/conformance/authority-events.json"
    ))
    .expect("conformance fixture")
}

fn grant_payload(contract: &str, object: &str, command: &str) -> Value {
    json!({
        "contract": contract,
        "tuple": {
            "subject": format!("user:{}", "1".repeat(64)),
            "relation": "viewer",
            "object": object,
        },
        "actor": format!("user:{}", "2".repeat(64)),
        "reason": "Contract test grant",
        "command": command,
    })
}

fn revocation_payload(contract: &str, object: &str, command: &str) -> Value {
    json!({
        "contract": contract,
        "tuple": {
            "subject": format!("user:{}", "1".repeat(64)),
            "relation": "viewer",
            "object": object,
        },
        "actor": format!("user:{}", "2".repeat(64)),
        "reason": "Contract test revocation",
        "command": command,
    })
}

fn activation_payload(contract: &str, built_at: &Head) -> Value {
    let content = "<\\\"escaped\npolicy\">";
    let sha = format!(
        "sha256:{}",
        hex::encode(integrity_cbor::sha256_bytes(content.as_bytes()))
    );
    json!({
        "contract": contract,
        "policy": {
            "digest": format!("sha256:{}", "a".repeat(64)),
            "profileSet": format!("sha256:{}", "b".repeat(64)),
            "revision": 1,
        },
        "builtAt": {
            "treeSize": built_at.tree_size,
            "treeHeadHash": built_at.tree_head_hash,
        },
        "actor": format!("service:{}", "3".repeat(64)),
        "configuration": format!("sha256:{}", "c".repeat(64)),
        "artifacts": [{
            "path": "policy.cedar",
            "sha256": sha,
            "content": content,
        }],
    })
}

fn decision_payload(contract: &str, attempt: &str, prefix: &Head) -> Value {
    let mut payload = authority_cases()[3]["payload"].clone();
    payload["contract"] = contract.into();
    payload["attempt"] = attempt.into();
    payload["authorityPrefix"] = json!({
        "treeSize": prefix.tree_size,
        "treeHeadHash": prefix.tree_head_hash,
    });
    payload
}

fn genesis_payload_for(scope: &Scope) -> Value {
    let mut payload = authority_cases()[4]["payload"].clone();
    payload["tuple"]["object"] = format!("space:{}", scope.key()).into();
    payload
}

struct RunningServer {
    endpoint: String,
    ledgers: Arc<dyn Ledgers>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn provisioned_memory_bucket() -> ScopedBucket {
    let store = Arc::new(InMemory::new());
    let cell = Cell::parse("cell-a").expect("cell");
    stack_common_object_store::record_bucket_cell(store.as_ref(), &cell)
        .await
        .expect("record cell");
    ScopedBucket::open(store, &cell).await.expect("open bucket")
}

async fn spawn_server(state: TrellisServerState, ledgers: Arc<dyn Ledgers>) -> RunningServer {
    let bucket = provisioned_memory_bucket().await;
    let store = TrellisStore::new(Arc::clone(&ledgers), bucket);
    let deployment = Arc::new(
        Deployment::new(&one_scope("acme", "benefits", "prod"), store).expect("deployment"),
    );
    let built = router(state, deployment, HealthRouter::new()).expect("trellis router");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, built.into_make_service()).await;
    });
    RunningServer {
        endpoint: format!("http://{addr}"),
        ledgers,
        handle,
    }
}

async fn spawn_memory_server() -> RunningServer {
    spawn_server(
        multi_producer_memory_state(),
        Arc::new(MemoryLedgers::new()),
    )
    .await
}

async fn spawn_postgres_server(max_connections: u32) -> (pg::Database, RunningServer) {
    let db = pg::database(max_connections).await;
    let ledgers: Arc<dyn Ledgers> = Arc::new(trellis_store_postgres_async::PgLedgers::new(
        db.scoped.clone(),
    ));
    let server = spawn_server(multi_producer_memory_state(), ledgers).await;
    (db, server)
}

fn adapter_for(endpoint: &str, actor: &str, token: Option<&str>) -> TrellisAuthorityLedger {
    let mut cfg = TrellisServiceClientConfig::new(endpoint).with_timeout(Duration::from_secs(5));
    if let Some(token) = token {
        cfg = cfg.with_service_bearer_token(token);
    }
    let client = TrellisServiceClient::new(cfg).expect("trellis client");
    TrellisAuthorityLedger::new(client, actor).expect("authority ledger adapter")
}

/// Seeds an OC-124 erased authority grant row directly into the store:
/// `idempotency_key` and `content_hash` (computed from `original_payload`) are preserved in the
/// signed canonical event and checkpoint, while the plaintext payload is cleared (`ref_type:
/// "external"`, `availability: "erased"`, no grant JSON stored).
async fn seed_erased_authority_grant(
    ledgers: &Arc<dyn Ledgers>,
    scope: &Scope,
    key: &str,
    original_payload: &Value,
) -> Head {
    seed_external_authority_grant(ledgers, scope, key, original_payload, "erased").await
}

async fn seed_external_authority_grant(
    ledgers: &Arc<dyn Ledgers>,
    scope: &Scope,
    key: &str,
    original_payload: &Value,
    availability: &str,
) -> Head {
    #[derive(Default)]
    struct Capture(Option<StoredEvent>);
    impl LedgerStore for Capture {
        type Error = StackError;
        fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
            self.0 = Some(event);
            Ok(())
        }
    }

    let ledger_scope = TrellisAuthorityLedger::ledger_scope(scope, Ledger::Authority);
    let content = canonical_append_content(original_payload).expect("canonical content hash");

    let key_bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/_keys/issuer-001.cose_key"),
    )
    .expect("read fixture signing key");
    let signing_key = SigningKeyMaterial::new(key_bytes);

    let scoped = ledgers.scoped(scope);
    let mut tx = scoped.begin(&ledger_scope).await.expect("begin tx");
    let prior_head = tx.head().await.expect("head");
    let prior_event = tx.last_event().await.expect("last event");
    let sequence = prior_head.as_ref().map_or(0, |h| h.tree_size);
    let prev_hash = prior_event
        .as_ref()
        .and_then(|e| e.canonical_event_hash().copied());

    let map = |pairs: Vec<(&str, Cbor)>| {
        Cbor::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Cbor::Text(k.to_owned()), v))
                .collect(),
        )
    };
    let ts = TrellisTimestamp::new(1_760_000_000 + sequence, 0).expect("timestamp");
    let header = map(vec![
        ("event_type", Cbor::Bytes(GRANT.as_bytes().to_vec())),
        (
            "authored_at",
            Cbor::Array(vec![
                Cbor::Integer(ts.unix_secs.into()),
                Cbor::Integer(u64::from(ts.subsec_nanos).into()),
            ]),
        ),
        ("retention_tier", Cbor::Integer(0.into())),
        (
            "classification",
            Cbor::Bytes(b"x-trellis-service/public-metadata".to_vec()),
        ),
        ("outcome_commitment", Cbor::Null),
        ("subject_ref_commitment", Cbor::Null),
        ("tag_commitment", Cbor::Null),
        ("witness_ref", Cbor::Null),
        ("extensions", Cbor::Null),
    ]);
    // Payload cleared per OC-124 while retaining `content_hash` and `idempotency_key`.
    let payload_ref = map(vec![
        ("ref_type", Cbor::Text("external".to_owned())),
        ("content_hash", Cbor::Bytes(content.content_hash.to_vec())),
        ("availability", Cbor::Text(availability.to_owned())),
        ("retrieval_hint", Cbor::Null),
    ]);
    let key_bag = map(vec![("entries", Cbor::Array(Vec::new()))]);
    let authored = map(vec![
        ("version", Cbor::Integer(1.into())),
        (
            "ledger_scope",
            Cbor::Bytes(ledger_scope.as_bytes().to_vec()),
        ),
        ("sequence", Cbor::Integer(sequence.into())),
        (
            "prev_hash",
            prev_hash.map_or(Cbor::Null, |h| Cbor::Bytes(h.to_vec())),
        ),
        ("causal_deps", Cbor::Null),
        ("content_hash", Cbor::Bytes(content.content_hash.to_vec())),
        ("header", header),
        ("commitments", Cbor::Null),
        ("payload_ref", payload_ref),
        ("key_bag", key_bag),
        ("idempotency_key", Cbor::Bytes(key.as_bytes().to_vec())),
        ("extensions", Cbor::Null),
    ]);
    let authored_bytes =
        integrity_cbor::encode_canonical_cbor_value(&authored).expect("encode authored cbor");
    let mut capture = Capture::default();
    let proof = trellis_core::append_event(
        &mut capture,
        &signing_key,
        &AuthoredEvent::new(authored_bytes),
    )
    .expect("core append");
    let stored_event = capture
        .0
        .expect("captured event")
        .with_canonical_event_hash(Some(proof.canonical_event_hash));

    let prior_frontier = prior_head
        .as_ref()
        .map(StoredCheckpoint::frontier)
        .transpose()
        .expect("frontier");
    let prior = prior_head
        .as_ref()
        .zip(prior_frontier.as_ref())
        .map(
            |(head, frontier)| trellis_core::checkpoint::PriorCheckpoint {
                digest: head.digest,
                frontier,
            },
        );
    let issued = trellis_core::checkpoint::issue_checkpoint(
        &signing_key,
        ledger_scope.as_bytes(),
        prior,
        proof.canonical_event_hash,
        (ts.unix_secs, ts.subsec_nanos),
    )
    .expect("issue checkpoint");
    let profile_state = trellis_server::composition::adapters()
        .export_profile
        .fold_append(
            ledger_scope.as_bytes(),
            prior_head.as_ref().map(|h| h.profile_state.as_slice()),
            &stored_event,
            issued.tree_size,
        )
        .expect("fold export profile state");
    let checkpoint = issued.stored(ledger_scope.as_bytes(), profile_state);
    tx.insert(&stored_event, &checkpoint)
        .await
        .expect("insert erased event");
    tx.commit().await.expect("commit erased event");

    Head {
        tree_size: issued.tree_size,
        tree_head_hash: format!("sha256:{}", hex::encode(issued.tree_head_hash)),
        checkpoint_ref: Some(format!("sha256:{}", hex::encode(issued.digest))),
        last_event_hash: Some(format!(
            "sha256:{}",
            hex::encode(proof.canonical_event_hash)
        )),
    }
}

/// Core shared contract suite verified identically against `MemoryLedger`,
/// `TrellisAuthorityLedger` (in-memory server), and `TrellisAuthorityLedger` (Postgres 16 server).
async fn run_core_port_contract(ledger: &dyn AuthorityLedger, scope: &Scope) {
    // 1. Empty ledgers report Head::empty() and prefix-only read_after(0, 0).
    for kind in [Ledger::Authority, Ledger::Decisions] {
        assert_eq!(ledger.head(scope, kind).await.unwrap(), Head::empty());
        let origin = ledger.read_after(scope, kind, 0, 0).await.unwrap();
        assert_eq!(origin.start, Head::empty());
        assert!(origin.entries.is_empty());

        let empty_page = ledger.read_after(scope, kind, 0, 5).await.unwrap();
        assert_eq!(empty_page.start, Head::empty());
        assert!(empty_page.entries.is_empty());

        assert_eq!(
            ledger.read_after(scope, kind, 1, 0).await.unwrap_err(),
            LedgerFailure::HeadMoved
        );
        assert_eq!(
            ledger.read_after(scope, kind, 1, 5).await.unwrap_err(),
            LedgerFailure::HeadMoved
        );
    }

    // 2. Local key bounds validation on encoded_append_size, reconcile, append.
    let g0 = grant_payload("wos", "record:1", "cmd-0");
    let oversize_key = "k".repeat(MAX_LEDGER_KEY_BYTES + 1);
    for bad_key in ["", oversize_key.as_str()] {
        assert!(matches!(
            ledger.encoded_append_size(scope, Ledger::Authority, bad_key, GRANT, &g0, Some(0)),
            Err(LedgerFailure::Rejected(_))
        ));
        assert!(matches!(
            ledger
                .reconcile(scope, Ledger::Authority, bad_key, GRANT, &g0)
                .await,
            Err(LedgerFailure::Rejected(_))
        ));
        assert!(matches!(
            ledger
                .append(scope, Ledger::Authority, bad_key, GRANT, &g0, Some(0))
                .await,
            Err(LedgerFailure::Rejected(_))
        ));
    }

    // 3. Reconcile Absent does not write.
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", GRANT, &g0)
            .await
            .unwrap(),
        Reconcile::Absent
    );
    assert_eq!(
        ledger.head(scope, Ledger::Authority).await.unwrap(),
        Head::empty()
    );

    // 4. Conditional append fails with HeadMoved when expected_size != 0 without reserving key.
    assert_eq!(
        ledger
            .append(scope, Ledger::Authority, "key-0", GRANT, &g0, Some(1))
            .await
            .unwrap_err(),
        LedgerFailure::HeadMoved
    );
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", GRANT, &g0)
            .await
            .unwrap(),
        Reconcile::Absent
    );

    // 5. Same key succeeds once expected_size matches 0.
    let h1 = ledger
        .append(scope, Ledger::Authority, "key-0", GRANT, &g0, Some(0))
        .await
        .unwrap();
    assert_eq!(h1.tree_size, 1);
    assert!(
        h1.checkpoint_ref
            .as_deref()
            .is_some_and(|d| d.starts_with("sha256:"))
    );
    assert!(
        h1.last_event_hash
            .as_deref()
            .is_some_and(|d| d.starts_with("sha256:"))
    );
    assert_eq!(ledger.head(scope, Ledger::Authority).await.unwrap(), h1);

    // 6. Reconcile Committed returns the EXACT same Head, and Conflict detects changed payload/type.
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", GRANT, &g0)
            .await
            .unwrap(),
        Reconcile::Committed(h1.clone())
    );
    let mut changed_payload = g0.clone();
    changed_payload["reason"] = "Different reason".into();
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", GRANT, &changed_payload)
            .await
            .unwrap(),
        Reconcile::Conflict
    );
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", REVOCATION, &g0)
            .await
            .unwrap(),
        Reconcile::Conflict
    );

    // 7. Reusing a committed key with changed payload or event type fails with KeyConflict (not HeadMoved).
    assert_eq!(
        ledger
            .append(
                scope,
                Ledger::Authority,
                "key-0",
                GRANT,
                &changed_payload,
                Some(0)
            )
            .await
            .unwrap_err(),
        LedgerFailure::KeyConflict
    );
    assert_eq!(
        ledger
            .append(scope, Ledger::Authority, "key-0", REVOCATION, &g0, Some(1))
            .await
            .unwrap_err(),
        LedgerFailure::KeyConflict
    );

    // 8. Multi-contract events (formspec, genesis, activation, revocation) on the ONE shared ledger.
    let g1 = grant_payload("formspec", "record:2", "cmd-1");
    let h2 = ledger
        .append(scope, Ledger::Authority, "key-1", GRANT, &g1, Some(1))
        .await
        .unwrap();
    assert_eq!(h2.tree_size, 2);

    let genesis = genesis_payload_for(scope);
    let h3 = ledger
        .append(
            scope,
            Ledger::Authority,
            "key-genesis",
            GRANT,
            &genesis,
            Some(2),
        )
        .await
        .unwrap();
    assert_eq!(h3.tree_size, 3);

    let act = activation_payload("wos", &h3);
    let h4 = ledger
        .append(
            scope,
            Ledger::Authority,
            "key-act",
            ACTIVATION,
            &act,
            Some(3),
        )
        .await
        .unwrap();
    assert_eq!(h4.tree_size, 4);

    let rev = revocation_payload("wos", "record:1", "cmd-rev");
    let h5 = ledger
        .append(
            scope,
            Ledger::Authority,
            "key-rev",
            REVOCATION,
            &rev,
            Some(4),
        )
        .await
        .unwrap();
    assert_eq!(h5.tree_size, 5);

    // 9. Committed replay with a STALE expected_size still returns the original position!
    assert_eq!(
        ledger
            .append(scope, Ledger::Authority, "key-0", GRANT, &g0, Some(99))
            .await
            .unwrap(),
        h1
    );
    assert_eq!(
        ledger
            .append(scope, Ledger::Authority, "key-1", GRANT, &g1, None)
            .await
            .unwrap(),
        h2
    );
    assert_eq!(ledger.head(scope, Ledger::Authority).await.unwrap(), h5);

    // 10. Reconciling historical positions still returns exact original Heads.
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-0", GRANT, &g0)
            .await
            .unwrap(),
        Reconcile::Committed(h1.clone())
    );
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Authority, "key-act", ACTIVATION, &act)
            .await
            .unwrap(),
        Reconcile::Committed(h4.clone())
    );

    // 11. Prefix-only read_after(N, 0) and slice reads match exact Heads and hash links.
    let prefix_2 = ledger
        .read_after(scope, Ledger::Authority, 2, 0)
        .await
        .unwrap();
    assert_eq!(prefix_2.start, h2);
    assert!(prefix_2.entries.is_empty());

    let from_2 = ledger
        .read_after(scope, Ledger::Authority, 2, 2)
        .await
        .unwrap();
    assert_eq!(from_2.start, h2);
    assert_eq!(from_2.entries.len(), 2);
    assert_eq!(from_2.entries[0].head, h3);
    assert_eq!(from_2.entries[0].prior_event_hash, h2.last_event_hash);
    assert_eq!(from_2.entries[0].event_type, GRANT);
    assert_eq!(from_2.entries[0].payload.as_ref(), Some(&genesis));
    assert_eq!(from_2.entries[1].head, h4);
    assert_eq!(from_2.entries[1].prior_event_hash, h3.last_event_hash);
    assert_eq!(from_2.entries[1].event_type, ACTIVATION);

    let at_head = ledger
        .read_after(scope, Ledger::Authority, 5, 5)
        .await
        .unwrap();
    assert_eq!(at_head.start, h5);
    assert!(at_head.entries.is_empty());

    assert_eq!(
        ledger
            .read_after(scope, Ledger::Authority, 6, 0)
            .await
            .unwrap_err(),
        LedgerFailure::HeadMoved
    );

    // 12. Full Fold + FoldSnapshot round-trip compatibility with stack-common-authz.
    let all = ledger
        .read_after(scope, Ledger::Authority, 0, 10)
        .await
        .unwrap();
    assert_eq!(all.start, Head::empty());
    assert_eq!(all.entries.len(), 5);
    let mut fold = Fold::empty(all.start).unwrap();
    fold.extend(scope.key(), &all.entries).unwrap();
    assert_eq!(fold.head, h5);
    assert_eq!(fold.tuples.len(), 2); // record:2 grant + genesis authority_admin (record:1 was revoked)
    let snapshot = FoldSnapshot::build(
        scope,
        &fold,
        DateTime::from_timestamp(1_760_000_100, 0).unwrap(),
    )
    .expect("FoldSnapshot::build must accept Heads from AuthorityLedger");
    assert_eq!(snapshot.open(scope).expect("FoldSnapshot::open"), fold);

    // 13. Decisions ledger (`authority-decisions`) stays completely independent from `authority`.
    let d0 = decision_payload("wos", "attempt-1", &h5);
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Decisions, "dec-1", DECISION, &d0)
            .await
            .unwrap(),
        Reconcile::Absent
    );
    let dh1 = ledger
        .append(scope, Ledger::Decisions, "dec-1", DECISION, &d0, None)
        .await
        .unwrap();
    assert_eq!(dh1.tree_size, 1);
    assert_eq!(ledger.head(scope, Ledger::Decisions).await.unwrap(), dh1);
    assert_eq!(ledger.head(scope, Ledger::Authority).await.unwrap(), h5);
    assert_eq!(
        ledger
            .reconcile(scope, Ledger::Decisions, "dec-1", DECISION, &d0)
            .await
            .unwrap(),
        Reconcile::Committed(dh1.clone())
    );
    let d1 = decision_payload("formspec", "attempt-2", &h5);
    assert_eq!(
        ledger
            .append(scope, Ledger::Decisions, "dec-2", DECISION, &d1, Some(0))
            .await
            .unwrap_err(),
        LedgerFailure::HeadMoved
    );
    let dh2 = ledger
        .append(scope, Ledger::Decisions, "dec-2", DECISION, &d1, Some(1))
        .await
        .unwrap();
    assert_eq!(dh2.tree_size, 2);
    let dec_page = ledger
        .read_after(scope, Ledger::Decisions, 0, 10)
        .await
        .unwrap();
    assert_eq!(dec_page.start, Head::empty());
    assert_eq!(dec_page.entries.len(), 2);
    assert_eq!(dec_page.entries[0].head, dh1);
    assert_eq!(dec_page.entries[1].head, dh2);

    // 14. Cross-ledger event rejection (decision on authority, grant on decisions).
    assert!(matches!(
        ledger
            .append(scope, Ledger::Authority, "cross-1", DECISION, &d0, None)
            .await,
        Err(LedgerFailure::Rejected(_))
    ));
    assert!(matches!(
        ledger
            .append(scope, Ledger::Decisions, "cross-2", GRANT, &g0, None)
            .await,
        Err(LedgerFailure::Rejected(_))
    ));
}

async fn run_pagination_and_race_contract(server: &RunningServer, scope: &Scope) {
    let adapter = adapter_for(&server.endpoint, "wos-server", None);

    // 1. Concurrent conditional append race under writer lock: exactly one commits, other gets HeadMoved.
    let ledger_scope = TrellisAuthorityLedger::ledger_scope(scope, Ledger::Authority);
    let scoped = server.ledgers.scoped(scope);
    let lock = scoped
        .begin(&ledger_scope)
        .await
        .expect("acquire writer lock");

    let a1 = adapter.clone();
    let a2 = adapter.clone();
    let s1 = scope.clone();
    let s2 = scope.clone();
    let p1 = grant_payload("wos", "record:race-1", "race-1");
    let p2 = grant_payload("formspec", "record:race-2", "race-2");
    let p2_retry = p2.clone();

    let mut t1 = tokio::spawn(async move {
        a1.append(&s1, Ledger::Authority, "race-key-1", GRANT, &p1, Some(0))
            .await
    });
    let mut t2 = tokio::spawn(async move {
        a2.append(&s2, Ledger::Authority, "race-key-2", GRANT, &p2, Some(0))
            .await
    });
    // Both must block behind the writer lock rather than racing ahead.
    assert!(
        tokio::time::timeout(Duration::from_millis(60), &mut t1)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(60), &mut t2)
            .await
            .is_err()
    );
    drop(lock);

    let (r1, r2) = tokio::join!(t1, t2);
    let (r1, r2) = (r1.unwrap(), r2.unwrap());
    let (winner_head, loser_key, loser_payload) = match (&r1, &r2) {
        (Ok(head), Err(LedgerFailure::HeadMoved)) => (head.clone(), "race-key-2", p2_retry),
        (Err(LedgerFailure::HeadMoved), Ok(head)) => (
            head.clone(),
            "race-key-1",
            grant_payload("wos", "record:race-1", "race-1"),
        ),
        other => panic!("expected exactly one commit and one HeadMoved, got {other:?}"),
    };
    assert_eq!(winner_head.tree_size, 1);
    assert_eq!(
        adapter.head(scope, Ledger::Authority).await.unwrap(),
        winner_head
    );

    // Retrying the loser with the same key at tree_size=1 commits cleanly.
    let second_head = adapter
        .append(
            scope,
            Ledger::Authority,
            loser_key,
            GRANT,
            &loser_payload,
            Some(1),
        )
        .await
        .unwrap();
    assert_eq!(second_head.tree_size, 2);

    // 2. Append through 70 total events (> 2 * MAX_ORDERED_EVENTS = 64) and test multi-page read_after!
    let mut heads = vec![winner_head, second_head];
    for i in 2..70_u64 {
        let payload = grant_payload(
            if i % 2 == 0 { "wos" } else { "formspec" },
            &format!("record:item-{i}"),
            &format!("cmd-page-{i}"),
        );
        let head = adapter
            .append(
                scope,
                Ledger::Authority,
                &format!("page-key-{i}"),
                GRANT,
                &payload,
                Some(i),
            )
            .await
            .unwrap();
        assert_eq!(head.tree_size, i + 1);
        heads.push(head);
    }

    // Read all 70 from 0 in one call (loops across pages of <= 32).
    let full = adapter
        .read_after(scope, Ledger::Authority, 0, 70)
        .await
        .unwrap();
    assert_eq!(full.start, Head::empty());
    assert_eq!(full.entries.len(), 70);
    for (idx, entry) in full.entries.iter().enumerate() {
        assert_eq!(entry.head, heads[idx], "entry {idx}");
        let expected_prior = if idx == 0 {
            None
        } else {
            heads[idx - 1].last_event_hash.clone()
        };
        assert_eq!(entry.prior_event_hash, expected_prior, "prior {idx}");
    }

    // Read exactly 32 from nonzero tree_size=5 (needs 2 RPCs: anchor+31 + 1).
    let page_32 = adapter
        .read_after(scope, Ledger::Authority, 5, MAX_ORDERED_EVENTS)
        .await
        .unwrap();
    assert_eq!(page_32.start, heads[4]);
    assert_eq!(page_32.entries.len(), 32);
    for (offset, entry) in page_32.entries.iter().enumerate() {
        assert_eq!(entry.head, heads[5 + offset]);
    }

    // Read 70 from tree_size=5 (only 65 remain -> stops cleanly at head across 3 RPCs).
    let tail = adapter
        .read_after(scope, Ledger::Authority, 5, 70)
        .await
        .unwrap();
    assert_eq!(tail.start, heads[4]);
    assert_eq!(tail.entries.len(), 65);
    assert_eq!(tail.entries.last().unwrap().head, *heads.last().unwrap());
}

async fn run_erased_entry_reconcile_contract(server: &RunningServer, scope: &Scope) {
    let adapter = adapter_for(&server.endpoint, "wos-server", None);
    let original = grant_payload("wos", "record:erased", "cmd-erased");

    // Seed an OC-124 erased entry at seq 0 (preserving idempotency_key + content_hash, clearing payload).
    let erased_head =
        seed_erased_authority_grant(&server.ledgers, scope, "erased-key-0", &original).await;

    // Reconcile when erased entry is at head -> Committed(exact original Head)!
    assert_eq!(
        adapter
            .reconcile(scope, Ledger::Authority, "erased-key-0", GRANT, &original)
            .await
            .unwrap(),
        Reconcile::Committed(erased_head.clone())
    );

    // Reconcile with a different payload under the same key -> Conflict!
    let mut different = original.clone();
    different["reason"] = "Reused key after erasure".into();
    assert_eq!(
        adapter
            .reconcile(scope, Ledger::Authority, "erased-key-0", GRANT, &different)
            .await
            .unwrap(),
        Reconcile::Conflict
    );

    // Append retry of the erased entry replays the original position and does NOT append a new grant.
    assert_eq!(
        adapter
            .append(
                scope,
                Ledger::Authority,
                "erased-key-0",
                GRANT,
                &original,
                Some(0)
            )
            .await
            .unwrap(),
        erased_head
    );
    assert_eq!(
        adapter.head(scope, Ledger::Authority).await.unwrap(),
        erased_head
    );

    // Append a normal subsequent event at seq 1, then reconcile the historical erased entry at seq 0!
    let next_grant = grant_payload("formspec", "record:after-erased", "cmd-after-erased");
    let h2 = adapter
        .append(
            scope,
            Ledger::Authority,
            "after-erased-1",
            GRANT,
            &next_grant,
            Some(1),
        )
        .await
        .unwrap();
    assert_eq!(h2.tree_size, 2);
    assert_eq!(
        adapter
            .reconcile(scope, Ledger::Authority, "erased-key-0", GRANT, &original)
            .await
            .unwrap(),
        Reconcile::Committed(erased_head.clone())
    );

    // OC-124 rebuild & anchor reads over real Trellis HTTP: erased entry yields `payload: None`
    // while preserving canonical event hash, chain continuity, and checkpoint proofs.
    let full = adapter
        .read_after(scope, Ledger::Authority, 0, 10)
        .await
        .expect("read_after across OC-124 erased entry must succeed");
    assert_eq!(full.start, Head::empty());
    assert_eq!(full.entries.len(), 2);
    assert_eq!(full.entries[0].head.tree_size, 1);
    assert_eq!(full.entries[0].event_type, GRANT);
    assert_eq!(full.entries[0].payload, None);
    assert_eq!(full.entries[0].head, erased_head);
    assert_eq!(full.entries[1].head.tree_size, 2);
    assert_eq!(full.entries[1].event_type, GRANT);
    assert_eq!(full.entries[1].payload.as_ref(), Some(&next_grant));
    assert_eq!(full.entries[1].head, h2);

    // Anchor read starting directly at the erased seq 0 (tree_size = 1) must also succeed.
    let tail = adapter
        .read_after(scope, Ledger::Authority, 1, 10)
        .await
        .expect("read_after anchored on OC-124 erased entry must succeed");
    assert_eq!(tail.start, erased_head);
    assert_eq!(tail.entries.len(), 1);
    assert_eq!(tail.entries[0].payload.as_ref(), Some(&next_grant));
    assert_eq!(tail.entries[0].head, h2);

    // Zero-limit prefix confirmation anchored on the erased seq 0 must succeed.
    let prefix = adapter
        .read_after(scope, Ledger::Authority, 1, 0)
        .await
        .expect("zero-limit prefix check anchored on OC-124 erased entry must succeed");
    assert_eq!(prefix.start, erased_head);
    assert!(prefix.entries.is_empty());
}

#[tokio::test]
async fn contract_in_memory_server_non_erased_external_authority_row_fails_closed() {
    let server = spawn_memory_server().await;
    let scope = scope_a();
    let adapter = adapter_for(&server.endpoint, "wos-server", None);
    let original = grant_payload("wos", "record:corrupt", "cmd-corrupt");
    seed_external_authority_grant(&server.ledgers, &scope, "corrupt-key-0", &original, "available")
        .await;
    let err = adapter
        .read_after(&scope, Ledger::Authority, 0, 10)
        .await
        .expect_err("non-erased external authority payload must fail closed");
    assert!(
        matches!(err, LedgerFailure::Unavailable(_)),
        "expected Unavailable on non-erased unreadable authority payload, got {err:?}"
    );
}

#[tokio::test]
async fn contract_parity_memory_ledger_reference() {
    let ledger = MemoryLedger::default();
    run_core_port_contract(&ledger, &scope_a()).await;
}

#[tokio::test]
async fn contract_in_memory_server_core_operations() {
    let server = spawn_memory_server().await;
    let adapter = adapter_for(&server.endpoint, "wos-server", None);
    run_core_port_contract(&adapter, &scope_a()).await;
}

#[tokio::test]
async fn contract_in_memory_server_race_and_pagination_over_32() {
    let server = spawn_memory_server().await;
    run_pagination_and_race_contract(&server, &scope_a()).await;
}

#[tokio::test]
async fn contract_in_memory_server_oc124_erased_entry_reconcile() {
    let server = spawn_memory_server().await;
    run_erased_entry_reconcile_contract(&server, &scope_a()).await;
}

#[tokio::test]
async fn contract_postgres_server_core_operations() {
    let (_db, server) = spawn_postgres_server(8).await;
    let adapter = adapter_for(&server.endpoint, "wos-server", None);
    run_core_port_contract(&adapter, &scope_a()).await;
}

#[tokio::test]
async fn contract_postgres_server_race_and_pagination_over_32() {
    let (_db, server) = spawn_postgres_server(16).await;
    run_pagination_and_race_contract(&server, &scope_a()).await;
}

#[tokio::test]
async fn contract_postgres_server_oc124_erased_entry_reconcile() {
    let (_db, server) = spawn_postgres_server(8).await;
    run_erased_entry_reconcile_contract(&server, &scope_a()).await;
}

#[tokio::test]
async fn encoded_append_size_matches_exact_wire_http_body_bytes() {
    let server = spawn_memory_server().await;
    let observed_body_len = Arc::new(Mutex::new(Vec::<usize>::new()));
    let observed_queries = Arc::new(Mutex::new(Vec::<String>::new()));

    // Lightweight loopback HTTP proxy forwarding to real trellis-server while recording exact
    // body byte counts and query strings.
    let upstream = server.endpoint.clone();
    let lengths = Arc::clone(&observed_body_len);
    let queries = Arc::clone(&observed_queries);
    let proxy_router = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let upstream = upstream.clone();
        let lengths = Arc::clone(&lengths);
        let queries = Arc::clone(&queries);
        async move {
            let method = req.method().clone();
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str().to_owned())
                .unwrap_or_default();
            if path_and_query.contains("/events/ordered") {
                queries.lock().unwrap().push(path_and_query.clone());
            }
            let headers = req.headers().clone();
            let body = axum::body::to_bytes(req.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap();
            if method == axum::http::Method::POST && path_and_query.ends_with("/events") {
                lengths.lock().unwrap().push(body.len());
            }
            let client = reqwest::Client::new();
            let mut out = client.request(
                reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
                format!("{upstream}{path_and_query}"),
            );
            for (name, value) in &headers {
                if name != axum::http::header::HOST && name != axum::http::header::CONTENT_LENGTH {
                    out = out.header(name.as_str(), value.as_bytes());
                }
            }
            let resp = out.body(body.to_vec()).send().await.unwrap();
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16()).unwrap();
            let resp_headers = resp.headers().clone();
            let resp_bytes = resp.bytes().await.unwrap();
            let mut builder = axum::http::Response::builder().status(status);
            for (name, value) in &resp_headers {
                if name != axum::http::header::CONTENT_LENGTH
                    && name != axum::http::header::TRANSFER_ENCODING
                {
                    builder = builder.header(name.as_str(), value.as_bytes());
                }
            }
            builder.body(axum::body::Body::from(resp_bytes)).unwrap()
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, proxy_router).await;
    });

    let adapter = adapter_for(&format!("http://{proxy_addr}"), "wos-server", None);
    let scope = scope_a();

    // Verify exact byte-count match for grant (with expected_size=Some(0)),
    // activation with escaped JSON characters (expected_size=Some(1)), and decision (None).
    let grant = grant_payload("wos", "record:size-test", "cmd-size-0");
    let expected_grant_len = adapter
        .encoded_append_size(&scope, Ledger::Authority, "size-0", GRANT, &grant, Some(0))
        .unwrap();
    let h1 = adapter
        .append(&scope, Ledger::Authority, "size-0", GRANT, &grant, Some(0))
        .await
        .unwrap();

    let act = activation_payload("wos", &h1);
    let expected_act_len = adapter
        .encoded_append_size(
            &scope,
            Ledger::Authority,
            "size-1",
            ACTIVATION,
            &act,
            Some(1),
        )
        .unwrap();
    let h2 = adapter
        .append(
            &scope,
            Ledger::Authority,
            "size-1",
            ACTIVATION,
            &act,
            Some(1),
        )
        .await
        .unwrap();

    let dec = decision_payload("wos", "attempt-size", &h2);
    let expected_dec_len = adapter
        .encoded_append_size(&scope, Ledger::Decisions, "size-dec", DECISION, &dec, None)
        .unwrap();
    adapter
        .append(&scope, Ledger::Decisions, "size-dec", DECISION, &dec, None)
        .await
        .unwrap();

    assert_eq!(
        *observed_body_len.lock().unwrap(),
        vec![expected_grant_len, expected_act_len, expected_dec_len],
        "encoded_append_size must match exact HTTP request body bytes"
    );

    // Append 38 more events (40 total) and verify EVERY `/events/ordered` query has 1 <= limit <= 32.
    for i in 2..40_u64 {
        let p = grant_payload("wos", &format!("record:q-{i}"), &format!("cmd-q-{i}"));
        adapter
            .append(
                &scope,
                Ledger::Authority,
                &format!("q-{i}"),
                GRANT,
                &p,
                Some(i),
            )
            .await
            .unwrap();
    }
    observed_queries.lock().unwrap().clear();
    let page = adapter
        .read_after(&scope, Ledger::Authority, 3, 40)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 37);
    let recorded = observed_queries.lock().unwrap().clone();
    assert!(recorded.len() >= 2, "must paginate across multiple RPCs");
    for query in &recorded {
        let limit: u32 = query
            .split("limit=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            (1..=32).contains(&limit),
            "RPC query exceeded MAX_ORDERED_EVENTS=32 or used limit=0: {query}"
        );
    }
    proxy_handle.abort();
}

#[tokio::test]
async fn strict_auth_missing_grant_and_foreign_scope_are_refused() {
    struct StaticVerifier;
    #[async_trait]
    impl AccessTokenVerifier for StaticVerifier {
        async fn verify(&self, token: &str) -> Result<VerifiedAccessIdentity, AccessTokenError> {
            if token != "valid-service-token" {
                return Err(AccessTokenError::rejected());
            }
            Ok(VerifiedAccessIdentity {
                issuer: "https://issuer.example".into(),
                subject: "wos-service".into(),
                client_id: Some("wos-client".into()),
                scopes: BTreeSet::new(),
                expires_at: i64::MAX,
                token_id: None,
            })
        }
    }

    struct ToggleAuthorizer {
        allow_read: Arc<AtomicBool>,
        allow_append: Arc<AtomicBool>,
        bound_scope: ScopeKey,
    }
    #[async_trait]
    impl ScopeAuthorizer for ToggleAuthorizer {
        type Error = StackError;
        fn bound_scopes(
            &self,
            _identity: Option<&VerifiedAccessIdentity>,
        ) -> Result<Option<Vec<ScopeKey>>, StackError> {
            Ok(Some(vec![self.bound_scope]))
        }
        async fn authorize(
            &self,
            request: &ScopeAuthorization<'_>,
        ) -> Result<AuthorizedScope, StackError> {
            let allowed = match request.action {
                ScopeAction::Read => self.allow_read.load(Ordering::SeqCst),
                ScopeAction::Append => self.allow_append.load(Ordering::SeqCst),
                ScopeAction::Administer => false,
            };
            if !allowed {
                return Err(StackError::new(
                    stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
                    axum::http::StatusCode::FORBIDDEN,
                    "missing RecordsSpec grant",
                ));
            }
            Ok(AuthorizedScope {
                principal: "wos-server".into(),
                scope: request.scope.clone(),
                action: request.action,
            })
        }
    }

    let allow_read = Arc::new(AtomicBool::new(true));
    let allow_append = Arc::new(AtomicBool::new(true));
    let state = multi_producer_memory_state()
        .with_access_token_verifier(Arc::new(StaticVerifier))
        .with_scope_authorizer(Arc::new(ToggleAuthorizer {
            allow_read: Arc::clone(&allow_read),
            allow_append: Arc::clone(&allow_append),
            bound_scope: *scope_a().key(),
        }))
        .with_production_like_scope_posture(true);
    let server = spawn_server(state, Arc::new(MemoryLedgers::new())).await;

    let scope = scope_a();
    let foreign = scope_b();
    let grant = grant_payload("wos", "record:auth", "cmd-auth");

    // 1. Unauthenticated (401) -> Rejected with INFRA-4010 on every method.
    let unauth = adapter_for(&server.endpoint, "wos-server", Some("bad-token"));
    for err in [
        unauth.head(&scope, Ledger::Authority).await.unwrap_err(),
        unauth
            .read_after(&scope, Ledger::Authority, 0, 5)
            .await
            .unwrap_err(),
        unauth
            .reconcile(&scope, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap_err(),
        unauth
            .append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(&err, LedgerFailure::Rejected(msg) if msg.contains("INFRA-4010")),
            "expected Rejected(INFRA-4010), got {err:?}"
        );
    }

    // 2. Missing RecordsSpec grant (403) -> Rejected with INFRA-4030 on every method.
    let authed = adapter_for(&server.endpoint, "wos-server", Some("valid-service-token"));
    allow_read.store(false, Ordering::SeqCst);
    allow_append.store(false, Ordering::SeqCst);
    for err in [
        authed.head(&scope, Ledger::Authority).await.unwrap_err(),
        authed
            .read_after(&scope, Ledger::Authority, 0, 5)
            .await
            .unwrap_err(),
        authed
            .reconcile(&scope, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap_err(),
        authed
            .append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(&err, LedgerFailure::Rejected(msg) if msg.contains("INFRA-4030")),
            "expected Rejected(INFRA-4030), got {err:?}"
        );
    }

    // 3. Foreign scope (404) -> Rejected with INFRA-4040 on every method (NEVER HeadMoved!).
    allow_read.store(true, Ordering::SeqCst);
    allow_append.store(true, Ordering::SeqCst);
    for err in [
        authed.head(&foreign, Ledger::Authority).await.unwrap_err(),
        authed
            .read_after(&foreign, Ledger::Authority, 0, 0)
            .await
            .unwrap_err(),
        authed
            .read_after(&foreign, Ledger::Authority, 0, 5)
            .await
            .unwrap_err(),
        authed
            .read_after(&foreign, Ledger::Authority, 5, 0)
            .await
            .unwrap_err(),
        authed
            .read_after(&foreign, Ledger::Authority, 5, 5)
            .await
            .unwrap_err(),
        authed
            .reconcile(&foreign, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap_err(),
        authed
            .append(&foreign, Ledger::Authority, "k1", GRANT, &grant, Some(0))
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(&err, LedgerFailure::Rejected(msg) if msg.contains("INFRA-4040")),
            "foreign scope must return Rejected(INFRA-4040), never HeadMoved; got {err:?}"
        );
    }

    // 4. Valid scope + valid token + valid grants succeeds, and invalid payload preserves INFRA-4000.
    let head = authed
        .append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
        .await
        .unwrap();
    assert_eq!(head.tree_size, 1);

    let invalid_grant = json!({"contract": "genesis", "bad": true});
    let err = authed
        .append(
            &scope,
            Ledger::Authority,
            "k2",
            GRANT,
            &invalid_grant,
            Some(1),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, LedgerFailure::Rejected(msg) if msg.contains("INFRA-4000")),
        "expected Rejected(INFRA-4000), got {err:?}"
    );
}

#[tokio::test]
async fn reconcile_unknown_and_no_retries_on_stopped_erroring_and_slow_servers() {
    let scope = scope_a();
    let grant = grant_payload("wos", "record:u", "cmd-u");

    // 1. Stopped / unreachable server -> reconcile returns Ok(Reconcile::Unknown) (NEVER Absent),
    //    head/read_after return Unavailable, append returns OutcomeUnknown.
    let dead_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let dead_endpoint = format!("http://{}", dead_listener.local_addr().unwrap());
    drop(dead_listener);
    let dead = adapter_for(&dead_endpoint, "wos-server", None);
    assert_eq!(
        dead.reconcile(&scope, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap(),
        Reconcile::Unknown
    );
    assert!(matches!(
        dead.head(&scope, Ledger::Authority).await,
        Err(LedgerFailure::Unavailable(_))
    ));
    assert!(matches!(
        dead.read_after(&scope, Ledger::Authority, 0, 5).await,
        Err(LedgerFailure::Unavailable(_))
    ));
    assert!(matches!(
        dead.append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
            .await,
        Err(LedgerFailure::OutcomeUnknown(_))
    ));

    // 2. Server returning 503 -> reconcile returns Ok(Reconcile::Unknown) with zero retries.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let err_endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server_thread = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"error_code":"INFRA-5030","title":"SECRET_PROVIDER_TEXT"}"#;
            let resp = format!(
                "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/problem+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let erroring = adapter_for(&err_endpoint, "wos-server", None);
    assert_eq!(
        erroring
            .reconcile(&scope, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap(),
        Reconcile::Unknown
    );
    let append_err = erroring
        .append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
        .await
        .unwrap_err();
    assert!(matches!(append_err, LedgerFailure::OutcomeUnknown(_)));
    assert!(
        !format!("{append_err:?}").contains("SECRET_PROVIDER_TEXT"),
        "private provider text must never leak into LedgerFailure"
    );
    server_thread.join().unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "adapter must never retry internally"
    );

    // 3. Server returning AppendReconciliation::Unknown (missing checkpoint fault) -> Reconcile::Unknown.
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let unknown_endpoint = format!("http://{}", listener.local_addr().unwrap());
    let unknown_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"status":"unknown","reason":"receiptUnavailable"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    });
    let unknown_adapter = adapter_for(&unknown_endpoint, "wos-server", None);
    assert_eq!(
        unknown_adapter
            .reconcile(&scope, Ledger::Authority, "k1", GRANT, &grant)
            .await
            .unwrap(),
        Reconcile::Unknown
    );
    unknown_thread.join().unwrap();

    // 4. Non-INFRA-4094 HTTP 409 with unrecognized error_code must NOT map to HeadMoved.
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let conflict_endpoint = format!("http://{}", listener.local_addr().unwrap());
    let conflict_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"error_code":"CUSTOM-CONFLICT","title":"PRIVATE_CONFLICT"}"#;
        let resp = format!(
            "HTTP/1.1 409 Conflict\r\ncontent-type: application/problem+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    });
    let conflict_adapter = adapter_for(&conflict_endpoint, "wos-server", None);
    let err = conflict_adapter
        .append(&scope, Ledger::Authority, "k1", GRANT, &grant, Some(0))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LedgerFailure::Rejected(_)),
        "non-INFRA-4094 unknown 409 must map to Rejected, never HeadMoved: {err:?}"
    );
    assert!(!format!("{err:?}").contains("PRIVATE_CONFLICT"));
    conflict_thread.join().unwrap();
}

#[tokio::test]
async fn read_after_preserves_null_payload_and_constructor_validates_service_actor() {
    let client =
        TrellisServiceClient::new(TrellisServiceClientConfig::new("http://127.0.0.1:1")).unwrap();
    for bad_actor in ["", "   ", " wos-server", "wos-server ", "wos\nserver"] {
        assert!(
            matches!(
                TrellisAuthorityLedger::new(client.clone(), bad_actor),
                Err(LedgerFailure::Rejected(_))
            ),
            "must reject invalid service actor {bad_actor:?}"
        );
    }

    // Verify read_after preserves `payload: null` (erased entry on the wire).
    let scope = scope_a();
    let ledger_scope = TrellisAuthorityLedger::ledger_scope(&scope, Ledger::Authority);
    let cp_digest = format!("sha256:{}", "d".repeat(64));
    let ev_hash = format!("sha256:{}", "e".repeat(64));
    let tree_hash = format!("sha256:{}", "f".repeat(64));
    let body = json!({
        "startTreeHeadHash": Head::empty().tree_head_hash,
        "events": [{
            "sequence": 0,
            "eventType": GRANT,
            "payload": null,
            "canonicalEventHash": ev_hash,
            "priorEventHash": null,
            "checkpointRef": format!("trellis://{ledger_scope}/checkpoints/{cp_digest}"),
            "treeHeadHash": tree_hash,
        }]
    })
    .to_string();
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let _ = stream.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    });
    let adapter = adapter_for(&endpoint, "wos-server", None);
    let page = adapter
        .read_after(&scope, Ledger::Authority, 0, 1)
        .await
        .unwrap();
    assert_eq!(page.start, Head::empty());
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].payload, None);
    assert_eq!(page.entries[0].head.tree_size, 1);
    assert_eq!(
        page.entries[0].head.checkpoint_ref.as_deref(),
        Some(cp_digest.as_str())
    );
    server_thread.join().unwrap();
}

#[tokio::test]
async fn read_after_rejects_cross_page_hash_divergence_and_honors_caller_deadline() {
    let scope = scope_a();
    let ledger_scope = TrellisAuthorityLedger::ledger_scope(&scope, Ledger::Authority);

    // 1. Page 2 returns a different startTreeHeadHash than page 1's last event -> fail closed.
    let mut events_page_1 = Vec::new();
    let mut prior: Option<String> = None;
    for seq in 0..32_u64 {
        let ev_hash = format!("sha256:{seq:064x}");
        let cp_digest = format!("sha256:{:064x}", seq + 100);
        let tree_hash = format!("sha256:{:064x}", seq + 200);
        events_page_1.push(json!({
            "sequence": seq,
            "eventType": GRANT,
            "payload": grant_payload("wos", &format!("record:div-{seq}"), &format!("cmd-div-{seq}")),
            "canonicalEventHash": ev_hash,
            "priorEventHash": prior,
            "checkpointRef": format!("trellis://{ledger_scope}/checkpoints/{cp_digest}"),
            "treeHeadHash": tree_hash,
        }));
        prior = Some(ev_hash);
    }
    let page1_body = json!({
        "startTreeHeadHash": Head::empty().tree_head_hash,
        "events": events_page_1,
    })
    .to_string();
    let page2_body = json!({
        "startTreeHeadHash": format!("sha256:{}", "f".repeat(64)),
        "events": [],
    })
    .to_string();
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server_thread = std::thread::spawn(move || {
        for body in [page1_body, page2_body] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let adapter = adapter_for(&endpoint, "wos-server", None);
    let err = adapter
        .read_after(&scope, Ledger::Authority, 0, 40)
        .await
        .unwrap_err();
    assert!(
        matches!(err, LedgerFailure::Unavailable(_)),
        "diverged page boundary must fail closed as Unavailable, got {err:?}"
    );
    server_thread.join().unwrap();

    // 2. Unresponsive listener honors caller deadline immediately (and client timeout maps to Unknown/Unavailable).
    let hanging = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let hanging_endpoint = format!("http://{}", hanging.local_addr().unwrap());
    let slow_adapter = adapter_for(&hanging_endpoint, "wos-server", None);
    let timed_out = tokio::time::timeout(
        Duration::from_millis(50),
        slow_adapter.head(&scope, Ledger::Authority),
    )
    .await;
    assert!(
        timed_out.is_err(),
        "caller deadline must cancel in-flight read"
    );

    let short_client = TrellisServiceClient::new(
        TrellisServiceClientConfig::new(&hanging_endpoint).with_timeout(Duration::from_millis(40)),
    )
    .unwrap();
    let short_adapter = TrellisAuthorityLedger::new(short_client, "wos-server").unwrap();
    assert_eq!(
        short_adapter
            .reconcile(
                &scope,
                Ledger::Authority,
                "k-timeout",
                GRANT,
                &grant_payload("wos", "record:t", "cmd-t"),
            )
            .await
            .unwrap(),
        Reconcile::Unknown
    );
    drop(hanging);
}
