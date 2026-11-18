use super::*;

const EMPTY_TREE_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async fn get(app: &App, path: &str) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(get_request(path)).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

#[tokio::test]
async fn t1_ledger_feed_is_empty_and_reports_its_read_limit() {
    let app = router(test_state()).unwrap();
    let (status, head) = get(&app, "/v1/scopes/case_123/head").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head, serde_json::json!({"head": null}));
    let (status, ordered) =
        get(&app, "/v1/scopes/case_123/events/ordered?after=0&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ordered, serde_json::json!({"startTreeHeadHash": EMPTY_TREE_HASH, "events": []}));
    let (status, page) = get(&app, "/v1/scopes/case_123/events/ordered?after=0").await;
    assert_eq!((status, page), (StatusCode::OK, serde_json::json!({"startTreeHeadHash": EMPTY_TREE_HASH, "events": []})));
    for limit in [0, 33] {
        let (status, _) = get(
            &app,
            &format!("/v1/scopes/case_123/events/ordered?after=0&limit={limit}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn t1_ledger_feed_requires_a_current_read_grant() {
    let (fixture, controls) = auth_boundary_tests::external_state();
    controls.grants.store(false, std::sync::atomic::Ordering::SeqCst);
    let app = router(fixture).unwrap();
    for path in ["/v1/scopes/case_123/head", "/v1/scopes/case_123/events/ordered?after=0&limit=2"] {
        let request = crate::test_support::scoped_request("GET", path)
            .header("authorization", "Bearer controlled-current-token")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

mod pg {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

pub(super) fn authority_cases() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!(
        "../../../fixtures/conformance/authority-events.json"
    ))
    .unwrap()
}

pub(super) fn body_for(case: &serde_json::Value, key: &str) -> serde_json::Value {
    serde_json::json!({
        "eventType": case["eventType"],
        "idempotencyKey": key,
        "actor": {"kind": "service", "subject": "authority-producer"},
        "payload": case["payload"],
        "computeContext": {"declarationId": "compute:authority-producer:publicMetadata",
            "actor": "authority-producer", "sensitivity": "publicMetadata"}
    })
}

#[tokio::test]
async fn t1_authority_replays_original_and_refuses_changed_payload() {
    let fixture = test_state();
    let app = router(fixture.clone()).unwrap();
    for (index, case) in authority_cases().iter().enumerate() {
        let path = format!("/v1/scopes/{}/events", case["ledger"].as_str().unwrap());
        let mut body = body_for(case, &format!("authority-replay-{index}"));
        let bytes = serde_json::to_vec(&body).unwrap();
        let first = post_append(&app, &path, bytes.clone()).await;
        assert_eq!(post_append(&app, &path, bytes.clone()).await, first);
        let (status, page) = get(
            &app,
            &format!("{path}/ordered?after={}&limit=1", first.sequence),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["events"][0]["payload"], case["payload"]);
        // A fresh HTTP replay cache must still resolve the canonical append.
        let fresh = || {
            let mut fixture = fixture.clone();
            fixture.state.replay_store =
                Arc::new(stack_common_idempotency::InMemoryHttpReplayStore::new());
            router(fixture).unwrap()
        };
        assert_eq!(post_append(&fresh(), &path, bytes).await, first);
        let field = match case["eventType"].as_str().unwrap() {
            "trellis.authority.grant.v1" | "trellis.authority.revocation.v1" => "reason",
            "trellis.authority.activation.v1" => "actor",
            _ => "point",
        };
        body["payload"][field] = "person:changed".into();
        let response = fresh().oneshot(post_request(&path, serde_json::to_vec(&body).unwrap())).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}

async fn check_feed(fixture: Fixture) {
    let app = router(fixture.clone()).unwrap();
    let ledger = crate::test_support::ledger("authority");
    let path = "/v1/scopes/authority";
    let head_path = format!("{path}/head");
    let feed = |after, limit| format!("{path}/events/ordered?after={after}&limit={limit}");
    assert_eq!(get(&app, &head_path).await, (StatusCode::OK, serde_json::json!({"head":null})));

    let grant = authority_cases().remove(0);
    let make_body = |id: u64| {
        let mut body = body_for(&grant, &format!("concurrent-{id}"));
        body["payload"]["command"] = format!("cmd-{id}").into();
        body
    };
    let first_body = make_body(0);
    let first = post_append(
        &app, &format!("{path}/events"), serde_json::to_vec(&first_body).unwrap(),
    ).await;
    let (status, head) = get(&app, &head_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head["head"]["treeSize"], 1);
    assert_eq!(head["head"]["lastEventHash"], first.canonical_event_hash);
    assert_eq!(head["head"]["checkpointDigest"], first.checkpoint_ref.rsplit('/').next().unwrap());

    // Keep an append transaction open while reading. A feed that takes the
    // writer lock cannot finish this read. Other writers queue behind it.
    let ledgers = fixture.ledgers.scoped(&crate::test_support::a());
    let mut lock = ledgers.begin(&ledger).await.unwrap();
    let pending = StoredEvent::new(
        ledger.as_bytes().to_vec(), 1, b"uncommitted".to_vec(), Vec::new(),
    ).with_canonical_event_hash(Some([0xab; 32]));
    let mut pending_checkpoint = lock.head().await.unwrap().unwrap();
    pending_checkpoint.tree_size = 2;
    pending_checkpoint.digest = [0xab; 32];
    lock.insert(&pending, &pending_checkpoint).await.unwrap();
    let mut writers = tokio::task::JoinSet::new();
    for id in 1..=12 {
        let body = serde_json::to_vec(&make_body(id)).unwrap();
        let app = app.clone();
        writers.spawn(async move {
            (id, post_append(&app, "/v1/scopes/authority/events", body).await)
        });
    }
    let (status, page) = tokio::time::timeout(
        std::time::Duration::from_secs(3), async { get(&app, &feed(0, 3)).await },
    ).await.expect("reader does not wait for the append lock");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["startTreeHeadHash"], EMPTY_TREE_HASH);
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    let (status, uncommitted) = get(&app, &feed(2, 3)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{uncommitted}");
    let (status, locked_head) = tokio::time::timeout(
        std::time::Duration::from_secs(3), get(&app, &head_path),
    ).await.expect("head does not wait for the append lock");
    assert_eq!((status, locked_head), (StatusCode::OK, head));
    drop(lock);

    let seen = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut seen = Vec::new();
        while seen.len() < 13 {
            let (status, page) = get(&app, &feed(seen.len(), 3)).await;
            assert_eq!(status, StatusCode::OK);
            let page = page["events"].as_array().unwrap();
            assert!(page.len() <= 3);
            for row in page {
                assert_eq!(row["sequence"], seen.len());
                seen.push(row.clone());
            }
            tokio::task::yield_now().await;
        }
        seen
    }).await.expect("reader eventually sees every committed event");
    while let Some(completed) = writers.join_next().await {
        let (id, receipt) = completed.unwrap();
        let row = &seen[receipt.sequence as usize];
        assert_eq!(row["payload"], make_body(id)["payload"]);
        assert_eq!(row["canonicalEventHash"], receipt.canonical_event_hash);
        assert_eq!(row["checkpointRef"], receipt.checkpoint_ref);
    }
    let mut prior = serde_json::Value::Null;
    let mut last = serde_json::Value::Null;
    for after in [0, 3, 6, 9, 12] {
        let (status, page) = get(&app, &feed(after, 3)).await;
        assert_eq!(status, StatusCode::OK);
        let expected_start = if after == 0 {
            serde_json::json!(EMPTY_TREE_HASH)
        } else {
            seen[after - 1]["treeHeadHash"].clone()
        };
        assert_eq!(page["startTreeHeadHash"], expected_start);
        let page = page["events"].as_array().unwrap();
        assert_eq!(page.len(), (13 - after).min(3));
        for (offset, row) in page.iter().enumerate() {
            assert_eq!(row["sequence"], after + offset);
            assert_eq!(row["eventType"], grant["eventType"]);
            let id = row["payload"]["command"].as_str().unwrap().strip_prefix("cmd-").unwrap().parse().unwrap();
            assert_eq!(row["payload"], make_body(id)["payload"]);
            assert_eq!(row["priorEventHash"], prior);
            prior = row["canonicalEventHash"].clone();
            let checkpoint = ledgers.checkpoint_at(&ledger, (after + offset + 1) as u64).await.unwrap().unwrap();
            let expected = trellis_types::CheckpointPayload::from_sign1(&checkpoint.checkpoint).unwrap();
            assert_eq!(row["treeHeadHash"], format!("sha256:{}", hex::encode(expected.tree_head_hash)));
            assert_eq!(row["checkpointRef"], crate::ledger::checkpoint_ref(ledger.as_str(), &checkpoint));
            last = row.clone();
        }
    }
    let (status, head) = get(&app, &head_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head["head"]["treeSize"], 13);
    assert_eq!(head["head"]["lastEventHash"], last["canonicalEventHash"]);
    assert_eq!(head["head"]["treeHeadHash"], last["treeHeadHash"]);
    assert_eq!(get(&app, &feed(13, 3)).await.1, serde_json::json!({"startTreeHeadHash": last["treeHeadHash"], "events":[]}));
}

#[tokio::test]
async fn t1_gap_free_feed_memory() {
    check_feed(test_state()).await;
}

#[tokio::test]
async fn t1_gap_free_feed_postgres() {
    // Leave a connection for the reads while all appenders queue on the writer.
    let db = pg::database(16).await;
    let fixture = Fixture::over(
        TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
        Arc::new(trellis_store_postgres_async::PgLedgers::new(db.scoped.clone())),
        Arc::new(object_store::memory::InMemory::new()),
    );
    check_feed(fixture).await;
}

#[tokio::test]
async fn t1_activation_admits_a_realistic_package_and_refuses_oversize() {
    let app = router(test_state()).unwrap();
    let case = authority_cases().remove(2);
    let mut body = body_for(&case, "large-activation");
    let model = "<\\\"\n>".repeat((256 * 1024) / 5);
    let artifact = |path, content: &str| serde_json::json!({
        "path":path, "content":content,
        "sha256":format!("sha256:{}", hex::encode(integrity_cbor::sha256_bytes(content.as_bytes()))),
    });
    body["payload"]["artifacts"] = serde_json::json!([
        artifact("model.txt", &model),
        artifact("policy.txt", &"policy\n".repeat(1000)),
        artifact("vocabulary.json", "{}"),
    ]);
    let path = "/v1/scopes/authority/events";
    post_append(&app, path, serde_json::to_vec(&body).unwrap()).await;
    body["idempotencyKey"] = "oversize-activation".into();
    body["payload"]["artifacts"][0] = artifact("model.txt", &"x".repeat(1800 * 1024));
    let response = app.oneshot(post_request(path, serde_json::to_vec(&body).unwrap())).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn t1_conditional_append_refuses_moved_heads_and_uses_canonical_replay() {
    let cases = authority_cases();
    for (ledger, first_case, second_case, change_field) in [
        ("authority", &cases[0], &cases[2], "reason"),
        ("authority-decisions", &cases[3], &cases[3], "point"),
    ] {
        let app = router(test_state()).unwrap();
        let path = format!("/v1/scopes/{ledger}/events");
        let mut first = body_for(first_case, &format!("first-conditional-{ledger}"));
        first["expectedTreeSize"] = 0.into();
        let receipt = post_append(&app, &path, serde_json::to_vec(&first).unwrap()).await;
        let mut second = body_for(second_case, &format!("second-conditional-{ledger}"));
        second["expectedTreeSize"] = 0.into();
        let response = app
            .clone()
            .oneshot(post_request(&path, serde_json::to_vec(&second).unwrap()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{ledger}");
        let problem: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(problem["error_code"], "INFRA-4094", "{ledger}");
        second["expectedTreeSize"] = 1.into();
        assert_eq!(
            post_append(&app, &path, serde_json::to_vec(&second).unwrap())
                .await
                .sequence,
            1,
            "{ledger}: same key must commit once expectedTreeSize is corrected"
        );

        first["expectedTreeSize"] = 1.into();
        assert_eq!(
            post_append(&app, &path, serde_json::to_vec(&first).unwrap()).await,
            receipt,
            "{ledger}: committed replay accepts stale expectedTreeSize"
        );
        first["payload"][change_field] = "person:changed".into();
        let response = app
            .clone()
            .oneshot(post_request(&path, serde_json::to_vec(&first).unwrap()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{ledger}");
        let problem: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_ne!(problem["error_code"], "INFRA-4094", "{ledger}");
        assert_eq!(
            get(&app, &format!("/v1/scopes/{ledger}/head")).await.1["head"]["treeSize"],
            2,
            "{ledger}"
        );
    }
}

async fn concurrent_conditionals(fixture: Fixture) {
    let scoped = fixture.ledgers.scoped(&crate::test_support::a());
    let lock = scoped.begin(&crate::test_support::ledger("authority")).await.unwrap();
    let app = router(fixture).unwrap();
    let grant = authority_cases().remove(0);
    let path = "/v1/scopes/authority/events";
    let request = |key| {
        let mut body = body_for(&grant, key);
        body["expectedTreeSize"] = 0.into();
        post_request(path, serde_json::to_vec(&body).unwrap())
    };
    let mut first = std::pin::pin!(app.clone().oneshot(request("parallel-one")));
    let mut second = std::pin::pin!(app.clone().oneshot(request("parallel-two")));
    // Advance both requests while the ledger remains empty and its writer lock is held.
    let blocked = std::time::Duration::from_millis(50);
    assert!(tokio::time::timeout(blocked, first.as_mut()).await.is_err());
    assert!(tokio::time::timeout(blocked, second.as_mut()).await.is_err());
    drop(lock);
    let (first, second) = tokio::join!(first, second);
    let mut statuses = [first.unwrap().status(), second.unwrap().status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::CREATED, StatusCode::CONFLICT]);
    assert_eq!(get(&app, "/v1/scopes/authority/head").await.1["head"]["treeSize"], 1);
}

#[tokio::test]
async fn t1_concurrent_conditional_appends_memory() {
    concurrent_conditionals(test_state()).await;
}

#[tokio::test]
async fn t1_concurrent_conditional_appends_postgres() {
    let db = pg::database(4).await;
    concurrent_conditionals(Fixture::over(
        TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
        Arc::new(trellis_store_postgres_async::PgLedgers::new(db.scoped.clone())),
        Arc::new(object_store::memory::InMemory::new()),
    )).await;
}

#[tokio::test]
async fn t1_committed_authority_replay_after_signer_expires() {
    let mut fixture = test_state();
    let app = router(fixture.clone()).unwrap();
    let path = "/v1/scopes/authority/events";
    let mut body = body_for(&authority_cases()[0], "review-replay");
    body["expectedTreeSize"] = 0.into();
    let bytes = serde_json::to_vec(&body).unwrap();
    let original = post_append(&app, path, bytes.clone()).await;
    let expired = test_signing_key().with_valid_to(Some(TrellisTimestamp::new(1, 0).unwrap()));
    fixture.state = TrellisServerState::new(expired, crate::test_adapters::adapters());
    let app = router(fixture).unwrap();
    assert_eq!(post_append(&app, path, bytes).await, original);
    body["idempotencyKey"] = "new-after-expiry".into();
    body["expectedTreeSize"] = 1.into();
    let refusal = app.clone().oneshot(post_request(path, serde_json::to_vec(&body).unwrap())).await.unwrap();
    assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(refusal.into_body(), 4096).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("signing key inactive"));
    assert_eq!(get(&app, "/v1/scopes/authority/head").await.1["head"]["treeSize"], 1);
}

fn validate_http_response(
    operation_id: &str,
    status: serde_json::Value,
    response: &serde_json::Value,
) {
    use serde_json::{Value, json};
    let http: Value = serde_json::from_str(include_str!("../../../specs/trellis-http-api.schema.json")).unwrap();
    let operation = http["x-trellis-http-api"]["operations"].as_array().unwrap().iter()
        .find(|op| op["operationId"] == operation_id).unwrap();
    let schema_ref = operation["responses"].as_array().unwrap().iter()
        .find(|entry| entry["status"] == status).unwrap()["schemaRef"].as_str().unwrap();
    let live = crate::tests::documents_of_test_state().stack;
    let native: Value = serde_json::from_str(include_str!(
        "../../../../work-spec/schemas/wos-native-provenance-event.schema.json"
    )).unwrap();
    let authority: Value = serde_json::from_str(include_str!(
        "../../../specs/authority-events.schema.json"
    )).unwrap();
    let registry = jsonschema::Registry::new()
        .add(native["$id"].as_str().unwrap().to_owned(), jsonschema::Resource::from_contents(native))
        .unwrap()
        .add(authority["$id"].as_str().unwrap().to_owned(), jsonschema::Resource::from_contents(authority))
        .unwrap()
        .add(
            "https://specs.formspec.dev/trellis/trellis-server.openapi.json",
            jsonschema::Resource::from_contents(live.clone()),
        )
        .unwrap().prepare().unwrap();
    let validator = jsonschema::options().with_registry(&registry);
    let schema = json!({"$schema": http["$schema"], "$id": http["$id"], "$defs": http["$defs"], "$ref": schema_ref});
    validator.build(&schema).unwrap().validate(response).unwrap();
    validator.build(&http).unwrap().validate(response).unwrap();
    let operation = &live["paths"][operation["path"].as_str().unwrap()]["get"];
    let (status, media) = if status == 200 { ("200", "application/json") } else { ("400", "application/problem+json") };
    let openapi_response = &operation["responses"][status]["content"][media]["schema"];
    assert!(openapi_response.is_object());
    let schema = json!({
        "$schema": http["$schema"], "components": live["components"],
        "$ref": openapi_response["$ref"]
    });
    validator.build(&schema).unwrap().validate(response).unwrap();
}

#[tokio::test]
async fn t1_invalid_ordered_query_returns_declared_problem_json() {
    let app = router(test_state()).unwrap();
    for query in ["after=abc", "limit=2", "after=0&limit=33"] {
        let path = format!("/v1/scopes/authority/events/ordered?{query}");
        let response = app.clone().oneshot(get_request(&path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(response.headers()["content-type"], "application/problem+json", "{query}");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let problem = serde_json::from_slice(&bytes).unwrap();
        validate_http_response("getOrderedEvents", serde_json::json!("4xx/5xx"), &problem);
    }
}

#[tokio::test]
async fn t1_ledger_successes_validate_against_the_normative_http_schema() {
    let app = router(test_state()).unwrap();
    let path = "/v1/scopes/authority";
    let (status, head) = get(&app, &format!("{path}/head")).await;
    assert_eq!(status, StatusCode::OK);
    validate_http_response("getLedgerHead", serde_json::json!(200), &head);
    let body = body_for(&authority_cases()[0], "published-schema");
    post_append(&app, &format!("{path}/events"), serde_json::to_vec(&body).unwrap()).await;
    for (id, suffix) in [("getLedgerHead", "/head"), ("getOrderedEvents", "/events/ordered?after=0")] {
        let (status, result) = get(&app, &format!("{path}{suffix}")).await;
        assert_eq!(status, StatusCode::OK);
        validate_http_response(id, serde_json::json!(200), &result);
    }
}

#[tokio::test]
async fn t1_read_rejects_event_hash_that_disagrees_with_the_canonical_bytes() {
    let fixture = test_state();
    let app = router(fixture.clone()).unwrap();
    let body = body_for(&authority_cases()[0], "review-row");
    post_append(&app, "/v1/scopes/authority/events", serde_json::to_vec(&body).unwrap()).await;
    let ledger = crate::test_support::ledger("authority");
    let ledgers = fixture.ledgers.scoped(&crate::test_support::a());
    let mut page = ledgers.events_after(&ledger, 0, 1).await.unwrap().unwrap();
    let mut row = page.events.remove(0);
    assert!(crate::ledger_read::event(&ledger, row.clone(), &fixture.state.admission_policy).is_ok());
    row.canonical_event_hash[0] ^= 1;
    assert!(crate::ledger_read::event(&ledger, row, &fixture.state.admission_policy).is_err(), "reader reported a canonical hash inconsistent with its own retained bytes");
}

#[tokio::test]
async fn t1_read_rejects_checkpoint_digest_that_disagrees_with_the_signed_payload() {
    let fixture = test_state();
    let app = router(fixture.clone()).unwrap();
    let body = body_for(&authority_cases()[0], "checkpoint-digest");
    post_append(&app, "/v1/scopes/authority/events", serde_json::to_vec(&body).unwrap()).await;
    let ledger = crate::test_support::ledger("authority");
    let ledgers = fixture.ledgers.scoped(&crate::test_support::a());
    let mut row = ledgers.events_after(&ledger, 0, 1).await.unwrap().unwrap().events.remove(0);
    row.checkpoint.digest[0] ^= 1;
    assert!(crate::ledger_read::event(&ledger, row, &fixture.state.admission_policy).is_err());
}

#[tokio::test]
async fn t1_default_ordered_page_stops_at_32_with_one_event_left() {
    let app = router(test_state()).unwrap();
    let case = &authority_cases()[0];
    for i in 0..33 {
        let body = body_for(case, &format!("default-page-{i}"));
        post_append(
            &app,
            "/v1/scopes/authority/events",
            serde_json::to_vec(&body).unwrap(),
        ).await;
    }
    let path = "/v1/scopes/authority/events/ordered";
    let (status, first) = get(&app, &format!("{path}?after=0")).await;
    assert_eq!(status, StatusCode::OK);
    let rows = first["events"].as_array().unwrap();
    assert_eq!(rows.len(), 32);
    assert_eq!(rows[31]["sequence"], 31);
    let (status, rest) = get(&app, &format!("{path}?after=32")).await;
    assert_eq!(status, StatusCode::OK);
    let rows = rest["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["sequence"], 32);
}

#[tokio::test]
async fn t1_head_reauthorizes_after_the_store_returns() {
    check_read_reauthorization("/v1/scopes/case_123/head").await;
}

#[tokio::test]
async fn t1_ordered_page_reauthorizes_after_the_store_returns() {
    check_read_reauthorization("/v1/scopes/case_123/events/ordered?after=0").await;
}

async fn check_read_reauthorization(path: &str) {
    use crate::repository_probes::{Fault, FaultyLedgers};

    let (fixture, controls) = auth_boundary_tests::external_state();
    let grants = Arc::clone(&controls.grants);
    let ledgers = FaultyLedgers {
        inner: Arc::clone(&fixture.ledgers),
        fault: Arc::new(Fault::AfterLedgerRead(Box::new(move || {
            assert!(grants.swap(false, Ordering::SeqCst));
        }))),
    };
    let app = router(fixture.with_ledgers(Arc::new(ledgers))).unwrap();
    let response = app.oneshot(
        crate::test_support::scoped_request("GET", path)
            .header("authorization", "Bearer controlled-current-token")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert!(!controls.grants.load(Ordering::SeqCst), "store read must happen first");
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
}

#[tokio::test]
async fn t1_budget_review_matches_fields_disclosed_by_each_authority_payload() {
    let app = router(test_state()).unwrap();
    let specs = trellis_admission_authority::authority_event_type_specs().collect::<Vec<_>>();
    for (i, case) in authority_cases().iter().enumerate() {
        let path = format!("/v1/scopes/{}/events", case["ledger"].as_str().unwrap());
        let mut request = body_for(case, &format!("inventory-{i}"));
        if request["payload"].get("detail").is_some() {
            request["payload"]["representedParty"] = serde_json::json!("person:represented");
            request["payload"]["instance"] = serde_json::json!("job-1");
        }
        let bytes = serde_json::to_vec(&request).unwrap();
        let receipt = post_append(&app, &path, bytes).await;
        let (_, page) = get(&app, &format!("{path}/ordered?after={}&limit=1", receipt.sequence)).await;
        let payload = page["events"][0]["payload"].as_object().unwrap();
        let spec = specs.iter().find(|spec| spec.event_type == case["eventType"]).unwrap();
        let disclosed: std::collections::BTreeSet<_> = payload.keys().map(String::as_str).collect();
        let inventory: std::collections::BTreeSet<_> = spec.budget_review.plaintext_fields.iter().map(String::as_str).collect();
        assert!(disclosed.is_subset(&inventory), "unreviewed fields in {}: {:?}", spec.event_type, disclosed.difference(&inventory));
    }
}

async fn seed_non_json_row(fixture: &Fixture, ledger_name: &str, event_type: &str) {
    use crate::append::{AuthoredEventInput, EventContent, build_authored_event};
    use integrity_cbor::{Value, domain_separated_sha256};
    use trellis_types::CONTENT_DOMAIN;

    #[derive(Default)]
    struct Capture(Option<StoredEvent>);
    impl trellis_core::LedgerStore for Capture {
        type Error = StackError;
        fn append_event(&mut self, event: StoredEvent) -> Result<(), Self::Error> {
            self.0 = Some(event);
            Ok(())
        }
    }

    let ledger = crate::test_support::ledger(ledger_name);
    let key = b"non-json";
    let payload_bytes = crate::encode_value(&Value::Map(vec![(crate::uint(1), Value::Null)])).unwrap();
    let authored = build_authored_event(AuthoredEventInput {
        scope: ledger.as_bytes(),
        sequence: 0,
        prev_hash: None,
        event_type,
        idempotency_key: key,
        authored_at: TrellisTimestamp::new(1, 0).unwrap(),
        content: EventContent {
            content_hash: domain_separated_sha256(CONTENT_DOMAIN, &payload_bytes),
            nonce: crate::append::derive_payload_inline_nonce(key, &payload_bytes).unwrap(),
            payload_bytes,
        },
        extensions: Value::Null,
    }).unwrap();
    let mut capture = Capture::default();
    let proof = trellis_core::append_event(&mut capture, &test_signing_key().core_key(), &authored).unwrap();
    let event = capture.0.unwrap().with_canonical_event_hash(Some(proof.canonical_event_hash));
    let (event, checkpoint) = fixture.state.checkpointer().after(None, &event).unwrap();
    let ledgers = fixture.ledgers.scoped(&crate::test_support::a());
    let mut tx = ledgers.begin(&ledger).await.unwrap();
    tx.insert(&event, &checkpoint).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn t1_ordered_page_keeps_non_json_event_and_the_next_readable_event() {
    let fixture = test_state();
    seed_non_json_row(
        &fixture,
        "case_123",
        crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED,
    )
    .await;

    let app = router(fixture).unwrap();
    let mut body = body_for(&authority_cases()[0], "next-json");
    body["eventType"] = crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED.into();
    body["payload"] = serde_json::json!({"aggregateType":"t","aggregateId":"i","payload":{"ok":true}});
    post_append(&app, "/v1/scopes/case_123/events", serde_json::to_vec(&body).unwrap()).await;
    let (status, page) = get(&app, "/v1/scopes/case_123/events/ordered?after=0").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let rows = page["events"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["sequence"], 0);
    assert_eq!(rows[0]["payload"], serde_json::Value::Null);
    assert_eq!(rows[1]["sequence"], 1);
    assert_eq!(rows[1]["payload"], body["payload"]);
    assert_eq!(rows[1]["priorEventHash"], rows[0]["canonicalEventHash"]);
}

#[tokio::test]
async fn t1_ordered_page_refuses_unreadable_authority_rows() {
    for (ledger_name, event_type) in [
        ("authority", "trellis.authority.grant.v1"),
        ("authority-decisions", "trellis.authority.decision.v1"),
    ] {
        let fixture = test_state();
        seed_non_json_row(&fixture, ledger_name, event_type).await;
        let app = router(fixture).unwrap();
        let path = format!("/v1/scopes/{ledger_name}/events/ordered?after=0");
        let response = app.oneshot(get_request(&path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "{ledger_name}");
        let problem: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(problem["error_code"], "INFRA-5000", "{ledger_name}");
        assert_eq!(
            problem["title"],
            "stored authority payload is not readable JSON",
            "{ledger_name}"
        );
    }
}

#[tokio::test]
async fn t1_payload_policy_cannot_relabel_a_reserved_event() {
    use trellis_server_ports::{AdmissionEvent, AdmittedEvent, EventAdmissionPolicy};

    struct RelabelsEvent;

    #[async_trait::async_trait]
    impl EventAdmissionPolicy for RelabelsEvent {
        type Error = StackError;

        async fn admit(&self, event: &AdmissionEvent<'_>) -> Result<AdmittedEvent, StackError> {
            let mut admitted = trellis_admission_authority::AuthorityAdmissionPolicy
                .admit(event)
                .await?;
            admitted.event_type = crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED.into();
            Ok(admitted)
        }
    }

    let app = router(test_state().with_admission_policy(Arc::new(RelabelsEvent))).unwrap();
    let path = "/v1/scopes/authority";
    let request = body_for(&authority_cases()[0], "relabelled-event");
    let response = app.clone().oneshot(post_request(
        &format!("{path}/events"),
        serde_json::to_vec(&request).unwrap(),
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(get(&app, &format!("{path}/head")).await.1["head"], serde_json::Value::Null);
}

#[tokio::test]
async fn t1_shared_ledgers_admit_multiple_contracts_and_genesis_and_refuse_cross_ledger() {
    let fixture = test_state();
    let admission = &fixture.state.admission_policy;
    assert!(admission.uses_canonical_append_replay(crate::test_support::ledger("authority").as_bytes()));
    assert!(admission.uses_canonical_append_replay(crate::test_support::ledger("authority-decisions").as_bytes()));
    assert!(!admission.uses_canonical_append_replay(crate::test_support::ledger("authority-sample").as_bytes()));
    assert!(!admission.uses_canonical_append_replay(crate::test_support::ledger("authority-decisions-sample").as_bytes()));
    assert!(!admission.uses_canonical_append_replay(crate::test_support::ledger("case_123").as_bytes()));
    assert!(!admission.uses_canonical_append_replay(b"authority"));
    assert!(!admission.uses_canonical_append_replay(b"authority-decisions"));
    for event_type in [
        "trellis.authority.grant.v1",
        "trellis.authority.revocation.v1",
        "trellis.authority.activation.v1",
        "trellis.authority.decision.v1",
    ] {
        assert!(admission.is_contract_event(event_type), "{event_type}");
    }
    assert!(!admission.is_contract_event("wos.kernel.case_created"));
    assert!(!admission.is_contract_event(crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED));

    let app = router(fixture).unwrap();
    let cases = authority_cases();
    for (seq, contract) in ["wos", "formspec", "genesis", "decisions"].into_iter().enumerate() {
        let mut body = body_for(&cases[0], &format!("shared-auth-{seq}"));
        body["expectedTreeSize"] = (seq as u64).into();
        body["payload"]["contract"] = contract.into();
        if contract == "genesis" {
            body["payload"] = cases[4]["payload"].clone();
        }
        let receipt = post_append(&app, "/v1/scopes/authority/events", serde_json::to_vec(&body).unwrap()).await;
        assert_eq!(receipt.sequence, seq as u64);
    }
    let (status, auth_page) = get(&app, "/v1/scopes/authority/events/ordered?after=0").await;
    assert_eq!(status, StatusCode::OK);
    let auth_events = auth_page["events"].as_array().unwrap();
    assert_eq!(auth_events.len(), 4);
    assert_eq!(auth_events[0]["payload"]["contract"], "wos");
    assert_eq!(auth_events[1]["payload"]["contract"], "formspec");
    assert_eq!(auth_events[2]["payload"]["contract"], "genesis");
    assert_eq!(auth_events[3]["payload"]["contract"], "decisions");

    for (seq, contract) in ["wos", "formspec"].into_iter().enumerate() {
        let mut body = body_for(&cases[3], &format!("shared-decision-{seq}"));
        body["expectedTreeSize"] = (seq as u64).into();
        body["payload"]["contract"] = contract.into();
        let receipt = post_append(
            &app,
            "/v1/scopes/authority-decisions/events",
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        assert_eq!(receipt.sequence, seq as u64);
    }
    let (status, dec_page) = get(&app, "/v1/scopes/authority-decisions/events/ordered?after=0").await;
    assert_eq!(status, StatusCode::OK);
    let dec_events = dec_page["events"].as_array().unwrap();
    assert_eq!(dec_events.len(), 2);
    assert_eq!(dec_events[0]["payload"]["contract"], "wos");
    assert_eq!(dec_events[1]["payload"]["contract"], "formspec");

    let mut stale_decision = body_for(&cases[3], "stale-shared-decision");
    stale_decision["expectedTreeSize"] = 1.into();
    let stale_response = app
        .clone()
        .oneshot(post_request(
            "/v1/scopes/authority-decisions/events",
            serde_json::to_vec(&stale_decision).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(stale_response.status(), StatusCode::CONFLICT);
    let problem: serde_json::Value =
        serde_json::from_slice(&to_bytes(stale_response.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(problem["error_code"], "INFRA-4094");
    stale_decision["expectedTreeSize"] = 2.into();
    let retried_decision = post_append(
        &app,
        "/v1/scopes/authority-decisions/events",
        serde_json::to_vec(&stale_decision).unwrap(),
    )
    .await;
    assert_eq!(retried_decision.sequence, 2);
    assert_eq!(
        get(&app, "/v1/scopes/authority-decisions/head").await.1["head"]["treeSize"],
        3
    );

    // Cross-ledger and cross-family writes are refused.
    let decision_body = body_for(&cases[3], "cross-decision-on-authority");
    assert_eq!(
        app.clone()
            .oneshot(post_request("/v1/scopes/authority/events", serde_json::to_vec(&decision_body).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let grant_body = body_for(&cases[0], "cross-grant-on-decisions");
    assert_eq!(
        app.clone()
            .oneshot(post_request("/v1/scopes/authority-decisions/events", serde_json::to_vec(&grant_body).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    for legacy_path in ["/v1/scopes/authority-sample/events", "/v1/scopes/case_123/events"] {
        assert_eq!(
            app.clone()
                .oneshot(post_request(legacy_path, serde_json::to_vec(&grant_body).unwrap()))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST,
            "{legacy_path}"
        );
    }
    let mut legacy_with_expected = body_for(&cases[0], "expected-on-legacy");
    legacy_with_expected["eventType"] = crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED.into();
    legacy_with_expected["payload"] = serde_json::json!({"aggregateType":"t","aggregateId":"i","payload":{}});
    legacy_with_expected["expectedTreeSize"] = 0.into();
    assert_eq!(
        app.clone()
            .oneshot(post_request("/v1/scopes/authority-sample/events", serde_json::to_vec(&legacy_with_expected).unwrap()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    for ledger in ["authority", "authority-decisions"] {
        let mut formspec_body = body_for(&cases[0], &format!("formspec-on-{ledger}"));
        formspec_body["eventType"] = crate::test_adapters::FORMSPEC_RESPONSE_SUBMITTED.into();
        formspec_body["payload"] = serde_json::json!({"aggregateType":"t","aggregateId":"i","payload":{}});
        assert_eq!(
            app.clone()
                .oneshot(post_request(&format!("/v1/scopes/{ledger}/events"), serde_json::to_vec(&formspec_body).unwrap()))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn t1_attachment_route_rejects_mismatched_adapter_and_uses_single_validated_literal() {
    use base64::Engine as _;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use trellis_admission_formspec::accepted_attachment::FormspecAttachmentAdmission;
    use trellis_server_ports::{
        AdmittedDescriptor, AttachmentBinding, AttachmentLimits, AuthorizedScope,
        ExternalAttachmentAdmission, ScopeAuthorization, ScopeAuthorizer,
    };
    use trellis_service_client::{
        ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL, AcceptedAttachmentAppendBody, AppendActor,
    };

    struct SwitchingAttachmentAdmission {
        inner: FormspecAttachmentAdmission,
        mismatch: &'static str,
        use_mismatch: Arc<AtomicBool>,
    }

    impl ExternalAttachmentAdmission for SwitchingAttachmentAdmission {
        fn event_type(&self) -> &'static str {
            if self.use_mismatch.load(Ordering::SeqCst) {
                self.mismatch
            } else {
                ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL
            }
        }

        fn admit(&self, descriptor_json: &str) -> Result<AdmittedDescriptor, StackError> {
            self.inner.admit(descriptor_json)
        }

        fn bind(
            &self,
            payload: &serde_json::Value,
            scope: &[u8],
            original: &[u8],
            ciphertext: &[u8],
            prior: &[StoredEvent],
            limits: AttachmentLimits,
        ) -> Result<AttachmentBinding, StackError> {
            self.inner
                .bind(payload, scope, original, ciphertext, prior, limits)
        }
    }

    struct RecordingAuthorizer {
        recorded: Arc<Mutex<Vec<String>>>,
        flip_after_authorize: Option<Arc<AtomicBool>>,
    }

    #[async_trait::async_trait]
    impl ScopeAuthorizer for RecordingAuthorizer {
        type Error = StackError;

        fn bound_scopes(
            &self,
            _identity: Option<&stack_common_auth::VerifiedAccessIdentity>,
        ) -> Result<Option<Vec<stack_common_scope::ScopeKey>>, StackError> {
            Ok(None)
        }

        async fn authorize(
            &self,
            request: &ScopeAuthorization<'_>,
        ) -> Result<AuthorizedScope, StackError> {
            if let Some(body) = request.append_body {
                self.recorded
                    .lock()
                    .unwrap()
                    .push(body.event_type.clone());
                if let Some(flag) = &self.flip_after_authorize {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            Ok(AuthorizedScope {
                principal: "attachment-test-producer".into(),
                scope: request.scope.clone(),
                action: request.action,
            })
        }
    }

    struct TestRecipients;

    #[async_trait::async_trait]
    impl crate::ExternalAttachmentRecipientSelector for TestRecipients {
        async fn select(
            &self,
            _permit: &AuthorizedScope,
            _descriptor: &serde_json::Value,
        ) -> Result<Vec<crate::ExternalAttachmentRecipient>, StackError> {
            let public_key: [u8; 32] =
                hex::decode("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13")
                    .unwrap()
                    .try_into()
                    .unwrap();
            Ok(vec![crate::ExternalAttachmentRecipient {
                id: b"fixture-reader".to_vec(),
                public_key,
                operator_held: false,
            }])
        }
    }

    let attachment_body = |key: &str| {
        let (descriptor, _, original) = super::external_attachment_tests::external_fixture_input();
        let body = AcceptedAttachmentAppendBody {
            expected_prefix: None,
            idempotency_key: key.into(),
            actor: AppendActor::service("formspec-server"),
            descriptor: serde_json::to_value(descriptor).unwrap(),
            original_bytes: base64::engine::general_purpose::STANDARD.encode(original),
        };
        serde_json::to_vec(&body).unwrap()
    };

    // Static mismatch is refused at router, OpenAPI documents, and direct admission.
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut mismatch_fixture = test_state();
    mismatch_fixture.state.external_attachment_admission = Arc::new(SwitchingAttachmentAdmission {
        inner: FormspecAttachmentAdmission,
        mismatch: "trellis.authority.grant.v1",
        use_mismatch: Arc::new(AtomicBool::new(true)),
    });
    mismatch_fixture.state.external_attachment_recipients = Some(Arc::new(TestRecipients));
    mismatch_fixture.state.authorizer = Arc::new(RecordingAuthorizer {
        recorded: recorded.clone(),
        flip_after_authorize: None,
    });
    assert!(router(mismatch_fixture.clone()).is_err());
    assert!(crate::test_support::documents(&mismatch_fixture).is_err());
    let mut direct_req = post_request("/v1/scopes/case_123/accepted-attachments", attachment_body("direct-mismatch"));
    assert!(
        crate::external_transport::admit(
            &mismatch_fixture.state,
            &crate::state::AuthenticatedRequest::Anonymous,
            crate::test_support::ledger("case_123"),
            &mut direct_req,
        )
        .await
        .is_err()
    );
    assert!(recorded.lock().unwrap().is_empty());

    // AdmissionRouter cannot reserve the closed attachment literal onto a contract ledger.
    let mut reserved_fixture = test_state();
    reserved_fixture.state.admission_policy = reserved_fixture
        .state
        .admission_policy
        .clone()
        .reserve_ledger(
            "authority",
            Arc::new(trellis_admission_authority::AuthorityAdmissionPolicy),
            [ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL],
        );
    assert!(router(reserved_fixture.clone()).is_err());
    assert!(crate::test_support::documents(&reserved_fixture).is_err());

    // Adapter flipping after startup is rejected on HTTP admission without authorizing or appending.
    let use_mismatch = Arc::new(AtomicBool::new(false));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut post_startup_fixture = test_state();
    post_startup_fixture.state.external_attachment_admission =
        Arc::new(SwitchingAttachmentAdmission {
            inner: FormspecAttachmentAdmission,
            mismatch: "trellis.authority.grant.v1",
            use_mismatch: use_mismatch.clone(),
        });
    post_startup_fixture.state.external_attachment_recipients = Some(Arc::new(TestRecipients));
    post_startup_fixture.state.authorizer = Arc::new(RecordingAuthorizer {
        recorded: recorded.clone(),
        flip_after_authorize: None,
    });
    let app = router(post_startup_fixture).unwrap();
    use_mismatch.store(true, Ordering::SeqCst);
    let response = app
        .clone()
        .oneshot(post_request(
            "/v1/scopes/case_123/accepted-attachments",
            attachment_body("flip-before-admit"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(recorded.lock().unwrap().is_empty());
    assert_eq!(get(&app, "/v1/scopes/case_123/head").await.1["head"], serde_json::Value::Null);

    // Adapter flipping after authorize cannot relabel the signed canonical header.
    let flip_after = Arc::new(AtomicBool::new(false));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut mid_request_fixture = test_state();
    mid_request_fixture.state.external_attachment_admission =
        Arc::new(SwitchingAttachmentAdmission {
            inner: FormspecAttachmentAdmission,
            mismatch: "trellis.authority.grant.v1",
            use_mismatch: flip_after.clone(),
        });
    mid_request_fixture.state.external_attachment_recipients = Some(Arc::new(TestRecipients));
    mid_request_fixture.state.authorizer = Arc::new(RecordingAuthorizer {
        recorded: recorded.clone(),
        flip_after_authorize: Some(flip_after),
    });
    let app = router(mid_request_fixture).unwrap();
    // Targetting a reserved authority ledger is refused before admission or authorization.
    let authority_response = app
        .clone()
        .oneshot(post_request(
            "/v1/scopes/authority/accepted-attachments",
            attachment_body("authority-attachment-refused"),
        ))
        .await
        .unwrap();
    assert_eq!(authority_response.status(), StatusCode::BAD_REQUEST);
    assert!(recorded.lock().unwrap().is_empty());
    assert_eq!(get(&app, "/v1/scopes/authority/head").await.1["head"], serde_json::Value::Null);

    let ok_response = app
        .clone()
        .oneshot(post_request(
            "/v1/scopes/case_123/accepted-attachments",
            attachment_body("single-validated-literal"),
        ))
        .await
        .unwrap();
    let ok_status = ok_response.status();
    let ok_bytes = to_bytes(ok_response.into_body(), 4096).await.unwrap();
    assert_eq!(ok_status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&ok_bytes));
    assert_eq!(
        recorded.lock().unwrap().as_slice(),
        &[ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL]
    );
    let (status, page) = get(&app, "/v1/scopes/case_123/events/ordered?after=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["events"][0]["eventType"],
        ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL,
        "signed header event_type must remain the single validated route literal"
    );
}
