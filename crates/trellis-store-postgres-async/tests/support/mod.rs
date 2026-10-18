// Shared harness lives in `stack_common_postgres::testing`; this file adds the production shape
// every Trellis Postgres test starts from: migrated by the owner, served through `trellis_app`, a
// login role that is not a superuser, owns no table and cannot bypass row security. Other crates
// `include!` it, and each uses a different part, hence the `dead_code` allowances.

use sqlx::PgPool;
use sqlx::postgres::{PgPoolOptions, PgSslMode};
use stack_common_postgres::ScopedPool;
use stack_common_postgres::testing::EphemeralCluster;
use stack_common_scope::{Cell, Scope};

/// The serving role the tests connect as.
pub const APP_ROLE: &str = "trellis_app";

/// A migrated cluster: the owner's pool, the app role's raw pool and the scoped pool over it.
#[allow(dead_code, reason = "each includer reads a different part")]
pub struct Database {
    pub cluster: EphemeralCluster,
    pub owner: PgPool,
    /// The app role's pool without the scoped wrapper: the raw-SQL side door controls use.
    pub app: PgPool,
    pub scoped: ScopedPool,
}

/// Starts a TLS-required cluster, migrates it as the owner and opens it for cell `cell-a`.
pub async fn database(max_connections: u32) -> Database {
    let cluster = EphemeralCluster::start_required();
    cluster.assert_tls_contract().await;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(cluster.connect_options(PgSslMode::Require))
        .await
        .expect("owner pool");
    sqlx::raw_sql(&format!("CREATE ROLE {APP_ROLE} LOGIN"))
        .execute(&owner)
        .await
        .expect("app role");
    stack_common_postgres::migrate(
        &owner,
        APP_ROLE,
        &Cell::parse("cell-a").unwrap(),
        &trellis_store_postgres_async::SCHEMA,
    )
    .await
    .expect("migrations");
    let app = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(
            cluster
                .connect_options(PgSslMode::Require)
                .username(APP_ROLE),
        )
        .await
        .expect("app pool");
    let scoped = ScopedPool::open(
        app.clone(),
        &Cell::parse("cell-a").unwrap(),
        &trellis_store_postgres_async::SCHEMA,
    )
    .await
    .expect("open for cell-a");
    Database {
        cluster,
        owner,
        app,
        scoped,
    }
}

/// Scope A of the tests.
#[allow(dead_code, reason = "not every includer names a scope")]
pub fn a() -> Scope {
    Scope::fixture("acme", "benefits", Some("prod"))
}

/// Scope B: another tenant.
#[allow(dead_code, reason = "not every includer names a scope")]
pub fn b() -> Scope {
    Scope::fixture("globex", "benefits", Some("prod"))
}
