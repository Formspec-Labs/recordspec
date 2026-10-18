// Rust guideline compliant 2026-02-21
// ADR 0168 §1.8: GOAL.md's isolation gate against the composed Trellis server on Postgres.
//
// Each pair is a deployment serving scope A (acme/benefits/prod, seeded with canaries) and a
// scope B that differs as the pair names; B's principal is bound to B alone. The harness probes
// every operation of the stack document, the fallback, the health probes and the public document
// as B, with A's ledger scope and checkpoint, and fails on any A canary in a response or any
// change to A's rows and objects. It runs with row security off and then on (§1.8 order). Two
// controls must fail it: a grant that binds B's principal to A, and a route that reads a ledger by
// raw SQL ignoring the scope key, which row security alone then fences.

use object_store::ObjectStore;
use stack_common_auth::{AccessTokenError, AccessTokenVerifier, VerifiedAccessIdentity};
use stack_common_http_testkit::cross_scope::{self, Operation, Pair, World, Worlds};
use stack_common_scope::{Scope, ScopeConfig, ScopeKey};
use axum::http::HeaderMap;
use trellis_server_ports::{AuthorizedScope, LedgerScope, ScopeAuthorization, ScopeAuthorizer};

use super::*;

mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../trellis-store-postgres-async/tests/support/mod.rs"
    ));
}

/// Strings planted in A's events and objects that must never reach B.
const CANARIES: [&str; 2] = ["canary-a-ledger-7f3e1c", "canary-a-object-29bd04"];

/// The id of A's seeded ledger.
const A_LEDGER: &str = "acme_case_canary";

/// The raw-SQL control's ledger under B, and the string its event carries.
const B_LEDGER: &str = "b_case_marker";
const B_MARKER: &str = "b-own-row-5e81";

fn config(tenant: &str, workspace: &str, environment: Option<&str>) -> ScopeConfig {
    ScopeConfig {
        tenant: tenant.into(),
        workspace: workspace.into(),
        environment: environment.map(Into::into),
    }
}

/// Scope B for each pair; A is the fixture's scope A, acme/benefits/prod.
fn forbidden(message: &str) -> StackError {
    StackError::new(
        stack_common_error::ErrorCode::new("INFRA-4030").unwrap(),
        StatusCode::FORBIDDEN,
        message,
    )
}

fn b_of(pair: Pair) -> ScopeConfig {
    match pair {
        Pair::OtherTenant => config("globex", "benefits", Some("prod")),
        Pair::OtherWorkspace => config("acme", "payroll", Some("prod")),
        Pair::OtherEnvironment => config("acme", "benefits", Some("staging")),
        Pair::BoundAgainstUnbound => config("acme", "benefits", None),
    }
}

fn scope_of(config: &ScopeConfig) -> Scope {
    Scope::fixture(
        &config.tenant,
        &config.workspace,
        config.environment.as_deref(),
    )
}

/// Bearer `token-a` is A's principal and `token-b` is B's.
struct Tokens;

#[async_trait]
impl AccessTokenVerifier for Tokens {
    async fn verify(&self, token: &str) -> Result<VerifiedAccessIdentity, AccessTokenError> {
        let subject = match token {
            "token-a" => "principal-a",
            "token-b" => "principal-b",
            _ => return Err(AccessTokenError::rejected()),
        };
        Ok(VerifiedAccessIdentity {
            issuer: "https://cross-scope.example".into(),
            subject: subject.into(),
            client_id: Some("cross-scope-client".into()),
            scopes: Default::default(),
            expires_at: i64::MAX,
            token_id: None,
        })
    }
}

/// Each principal is bound to one scope and may do anything there; nothing elsewhere.
struct Bindings {
    a: ScopeKey,
    b: ScopeKey,
}

impl Bindings {
    fn of(&self, identity: Option<&VerifiedAccessIdentity>) -> Result<ScopeKey, StackError> {
        match identity.map(|identity| identity.subject.as_str()) {
            Some("principal-a") => Ok(self.a),
            Some("principal-b") => Ok(self.b),
            _ => Err(forbidden("unknown principal")),
        }
    }
}

#[async_trait]
impl ScopeAuthorizer for Bindings {
    type Error = StackError;

    fn bound_scopes(
        &self,
        identity: Option<&VerifiedAccessIdentity>,
    ) -> Result<Option<Vec<ScopeKey>>, StackError> {
        Ok(Some(vec![self.of(identity)?]))
    }

    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, StackError> {
        let bound = self.of(request.identity)?;
        if request.scope.key() != &bound {
            return Err(forbidden("not this principal's scope"));
        }
        Ok(AuthorizedScope {
            principal: request.identity.map(|i| i.subject.clone()).unwrap_or_default(),
            scope: request.scope.clone(),
            action: request.action,
        })
    }
}

/// The path of the raw-SQL control's route (§1.8): inside B's admitted transaction, it reads a
/// ledger's events by ledger name alone, leaving out `scope_key = $1` as a buggy handler would,
/// and answers 404 when it sees none.
const RAW_ROUTE: &str = "/v1/scopes/{scope}/raw-events";

/// The served router, plus the raw-SQL control's route when the world carries one.
#[derive(Clone)]
struct ControlApp {
    app: crate::test_support::App,
    /// The deployment's pool and the scope the raw route's transaction is opened for (B's).
    raw: Option<(stack_common_postgres::ScopedPool, Scope)>,
}

impl tower::Service<Request<Body>> for ControlApp {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let ledger = request
            .uri()
            .path()
            .strip_prefix("/v1/scopes/")
            .and_then(|rest| rest.strip_suffix("/raw-events"))
            .map(str::to_owned);
        if let (Some((pool, scope)), Some(ledger)) = (self.raw.clone(), ledger) {
            return Box::pin(async move {
                let read = async {
                    let mut tx = pool.begin(&scope).await?;
                    sqlx::query_scalar::<_, Vec<u8>>(
                        "SELECT canonical_event FROM trellis_events WHERE scope = $1",
                    )
                    .bind(ledger.as_bytes())
                    .fetch_all(tx.conn())
                    .await
                };
                Ok(match read.await {
                    Err(_) => axum::response::IntoResponse::into_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ),
                    Ok(rows) if rows.is_empty() => {
                        axum::response::IntoResponse::into_response(StatusCode::NOT_FOUND)
                    }
                    Ok(rows) => axum::response::IntoResponse::into_response(rows.concat()),
                })
            });
        }
        let mut app = self.app.clone();
        Box::pin(async move { tower::Service::call(&mut app, request).await })
    }
}

/// One pair's deployment on its own Postgres cluster, with A seeded.
struct TrellisWorld {
    db: support::Database,
    app: ControlApp,
    document: serde_json::Value,
    artifacts: Arc<object_store::memory::InMemory>,
    a_key: ScopeKey,
    a_head_digest: String,
}

/// Every pair's world, built before the run: row security on or off, and which control, if any. (Building inside the `Send` trait future trips the compiler's higher-ranked
/// `Send` inference on sqlx's executors, so the worlds are made first and handed out.)
struct TrellisWorlds {
    worlds: std::sync::Mutex<Vec<(Pair, TrellisWorld)>>,
}

/// A control the harness must catch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Control {
    None,
    /// B's principal is bound to A's scope.
    MisbindBToA,
    /// The router also serves `RAW_ROUTE`.
    RawSqlRoute,
}

impl TrellisWorlds {
    async fn build(row_security: bool, control: Control) -> Self {
        let mut worlds = Vec::new();
        for pair in Pair::ALL {
            worlds.push((pair, build_world(row_security, control, pair).await));
        }
        Self {
            worlds: std::sync::Mutex::new(worlds),
        }
    }
}

#[async_trait]
impl Worlds for TrellisWorlds {
    type World = TrellisWorld;

    async fn world(&self, pair: Pair) -> TrellisWorld {
        let mut worlds = self.worlds.lock().unwrap();
        let index = worlds
            .iter()
            .position(|(built, _)| *built == pair)
            .expect("every pair was built");
        worlds.remove(index).1
    }
}

async fn build_world(row_security: bool, control: Control, pair: Pair) -> TrellisWorld {
    {
        let db = support::database(8).await;
        if !row_security {
            disable_row_security(&db).await;
        }
        let b_config = b_of(pair);
        let a = crate::test_support::a();
        let b = scope_of(&b_config);
        let artifacts = Arc::new(object_store::memory::InMemory::new());
        let fixture = Fixture::over(
            TrellisServerState::new(test_signing_key(), crate::test_adapters::adapters()),
            Arc::new(trellis_store_postgres_async::PgLedgers::new(db.scoped.clone())),
            artifacts.clone(),
        )
        .serving(b_config)
        .with_access_token_verifier(Arc::new(Tokens))
        .with_scope_authorizer(Arc::new(Bindings {
            a: *a.key(),
            b: if control == Control::MisbindBToA {
                *a.key()
            } else {
                *b.key()
            },
        }))
        .with_production_like_scope_posture(true);

        // A's data: two events whose payloads carry a canary, and an object that is one.
        let ledger = LedgerScope::of(&a, A_LEDGER).unwrap();
        for (key, note) in [("seed-1", CANARIES[0]), ("seed-2", CANARIES[0])] {
            let mut record =
                ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::CaseCreated);
            record.id = format!("prov-{key}");
            record.data = Some(serde_json::json!({ "note": note }));
            fixture
                .append_coordinator()
                .append(append::AppendCommand {
                    scope: ledger.clone(),
                    event_type: "wos.kernel.case_created".into(),
                    idempotency_key: key.into(),
                    payload: serde_json::to_value(record).unwrap(),
                    client_attestation: None,
                })
                .await
                .expect("A's seed appends");
        }
        fixture
            .scoped()
            .artifacts()
            .write_once("notes/canary", CANARIES[1].as_bytes())
            .await
            .unwrap();
        if control == Control::RawSqlRoute {
            // B's own ledger, so the raw route's answer to B is not vacuous.
            let mut record =
                ProvenanceRecord::blank(&fixture_minter(), ProvenanceKind::CaseCreated);
            record.id = "prov-b-seed".into();
            record.data = Some(serde_json::json!({ "note": B_MARKER }));
            fixture
                .state
                .append_coordinator(&fixture.scoped_for(&b))
                .append(append::AppendCommand {
                    scope: LedgerScope::of(&b, B_LEDGER).unwrap(),
                    event_type: "wos.kernel.case_created".into(),
                    idempotency_key: "b-seed".into(),
                    payload: serde_json::to_value(record).unwrap(),
                    client_attestation: None,
                })
                .await
                .expect("B's seed append");
        }
        let head = fixture
            .repository
            .head_checkpoint(ledger.as_bytes())
            .await
            .unwrap()
            .unwrap();
        let mut document = crate::test_support::documents(&fixture).unwrap().stack;
        let raw = (control == Control::RawSqlRoute).then(|| {
            // Declared like the head-bundle read, so the harness probes it with A's ledger.
            let read = document["paths"]["/v1/scopes/{scope}/bundles/head"]["get"].clone();
            let mut operation = serde_json::json!({
                "operationId": "rawEvents",
                "parameters": read["parameters"].clone(),
                "x-access": read["x-access"].clone(),
                "responses": {"200": {"description": "raw rows"}},
            });
            operation["security"] = read["security"].clone();
            document["paths"][RAW_ROUTE] = serde_json::json!({ "get": operation });
            (db.scoped.clone(), b.clone())
        });
        let app = ControlApp {
            app: router(fixture).unwrap(),
            raw,
        };
        TrellisWorld {
            db,
            app,
            document,
            artifacts,
            a_key: *a.key(),
            a_head_digest: format!("sha256:{}", hex::encode(head.digest)),
        }
    }
}

/// Row security off for the §1.8 order's first run: the owner turns it off on every table.
async fn disable_row_security(db: &support::Database) {
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

impl TrellisWorld {
    fn a_ledger(&self) -> String {
        format!("{}.{A_LEDGER}", self.a_key)
    }
}

#[async_trait]
impl World for TrellisWorld {
    type App = ControlApp;

    fn app(&self) -> Self::App {
        self.app.clone()
    }

    fn document(&self) -> &serde_json::Value {
        &self.document
    }

    fn undeclared(&self) -> Vec<String> {
        vec!["/healthz".into(), "/readyz".into(), "/openapi.json".into()]
    }

    fn as_b(&self, _operation: &Operation) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token-b".parse().unwrap());
        headers
    }

    fn a_id(&self, family: &str) -> Option<String> {
        // Every ledger route's `{scope}` is documented as this family, so the harness fills it
        // with A's ledger and requires 404 or 401.
        (family == trellis_service_client::endpoints::LEDGER_SCOPE_FAMILY).then(|| self.a_ledger().into())
    }

    fn fixture(&self, operation: &Operation, name: &str) -> Option<serde_json::Value> {
        let probe = "cross-scope-probe";
        let body = |kind: &str| -> serde_json::Value {
            match kind {
                "events" => serde_json::json!({
                    "eventType": "wos.kernel.case_created",
                    "idempotencyKey": probe,
                    "actor": {"kind": "service", "subject": "wos-server"},
                    "payload": {},
                    "computeContext": {"declarationId": "compute:none", "actor": "wos-server",
                        "sensitivity": "publicMetadata"}
                }),
                "reconcile" => serde_json::json!({
                    "eventType": "wos.kernel.case_created",
                    "idempotencyKey": "seed-1",
                    "contentHash": null,
                    "certificateId": null
                }),
                _ => serde_json::json!({"idempotencyKey": probe}),
            }
        };
        match name {
            "checkpointDigest" => Some(self.a_head_digest.clone().into()),
            "body" => Some(if operation.path.ends_with("/reconcile") {
                body("reconcile")
            } else if operation.path.ends_with("/events") {
                body("events")
            } else {
                body("other")
            }),
            _ => None,
        }
    }

    fn canaries(&self) -> Vec<String> {
        CANARIES.iter().map(|canary| (*canary).to_owned()).collect()
    }

    async fn a_digest(&self) -> Vec<u8> {
        let mut digest = Vec::new();
        let key = self.a_key.as_bytes().to_vec();
        for table in trellis_store_postgres_async::TABLES {
            let rows: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT md5(t::text) FROM {table} t WHERE scope_key = $1 ORDER BY 1"
            ))
            .bind(&key)
            .fetch_all(&self.db.owner)
            .await
            .unwrap();
            digest.extend(table.bytes());
            for row in rows {
                digest.extend(row.bytes());
            }
        }
        let prefix = object_store::path::Path::from(self.a_key.to_string());
        let mut objects = futures::StreamExt::collect::<Vec<_>>(self.artifacts.list(Some(&prefix)))
            .await
            .into_iter()
            .map(|meta| meta.unwrap())
            .collect::<Vec<_>>();
        objects.sort_by(|x, y| x.location.cmp(&y.location));
        for meta in objects {
            let bytes = self.artifacts.get(&meta.location).await.unwrap().bytes().await.unwrap();
            digest.extend(meta.location.as_ref().bytes());
            digest.extend(bytes);
        }
        integrity_cbor::sha256_bytes(&digest).to_vec()
    }

    fn surfaces(&self) -> Vec<String> {
        // Trellis starts no runner and declares no Socket.IO event: its only surface is HTTP,
        // which the harness covers from the stack document of this same router.
        Vec::new()
    }

    async fn probe(&self, _surface: &str) -> Option<Vec<String>> {
        None
    }
}

/// A's own principal reads its seeded export, and the canary is in it: the leak checks can see.
async fn a_reads_its_canary(world: &TrellisWorld) {
    let request = Request::builder()
        .uri(format!("/v1/scopes/{}/bundles/head", world.a_ledger()))
        .header("authorization", "Bearer token-a")
        .body(Body::empty())
        .unwrap();
    let response = world.app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 32 << 20).await.unwrap();
    assert!(
        bytes
            .windows(CANARIES[0].len())
            .any(|window| window == CANARIES[0].as_bytes()),
        "A's export carries its canary, so a leak to B would show"
    );
}

#[tokio::test]
async fn b_reaches_nothing_of_a_with_row_security_off_then_on() {
    for row_security in [false, true] {
        a_reads_its_canary(&build_world(row_security, Control::None, Pair::OtherTenant).await)
            .await;
        let worlds = TrellisWorlds::build(row_security, Control::None).await;
        if let Err(report) = cross_scope::run(&worlds).await {
            panic!("row security {row_security}: {report}");
        }
    }
}

/// The control: a grant that binds B's principal to A's scope must fail the harness, by route.
#[tokio::test]
async fn a_principal_bound_to_the_wrong_scope_fails_the_harness() {
    let worlds = TrellisWorlds::build(true, Control::MisbindBToA).await;
    let report = cross_scope::run(&worlds)
        .await
        .expect_err("B bound to A reaches A");
    assert!(
        report
            .failures()
            .iter()
            .any(|failure| failure.contains("GET /v1/scopes/{scope}/bundles/head")
                && failure.contains("canary")),
        "{report}"
    );
}

/// The raw-SQL control (§1.8): a route that reads a ledger by name inside B's admitted
/// transaction, leaving out the scope key, leaks A's rows to B with row security off, and the
/// harness catches it by canary; with row security on, the same route still answers B with B's
/// own rows but sees none of A's, and the harness passes.
#[tokio::test]
async fn a_raw_sql_route_fails_the_harness_until_row_security_is_on() {
    let worlds = TrellisWorlds::build(false, Control::RawSqlRoute).await;
    let report = cross_scope::run(&worlds)
        .await
        .expect_err("raw SQL reaches A's rows without row security");
    assert!(
        report
            .failures()
            .iter()
            .any(|failure| failure.contains(RAW_ROUTE) && failure.contains("canary")),
        "{report}"
    );
    let worlds = TrellisWorlds::build(true, Control::RawSqlRoute).await;
    if let Err(report) = cross_scope::run(&worlds).await {
        panic!("row security on: {report}");
    }
    let world = build_world(true, Control::RawSqlRoute, Pair::OtherTenant).await;
    let b = scope_of(&b_of(Pair::OtherTenant));
    let request = Request::builder()
        .uri(format!("/v1/scopes/{}.{B_LEDGER}/raw-events", b.key()))
        .header("authorization", "Bearer token-b")
        .body(Body::empty())
        .unwrap();
    let response = world.app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert!(
        bytes
            .windows(B_MARKER.len())
            .any(|window| window == B_MARKER.as_bytes()),
        "the raw route reads B's own rows under row security"
    );
}
