// Rust guideline compliant 2026-02-21
//! Trellis server binary: the composition root (ADR 0168 §1.2).
//!
//! The only Trellis crate that enables `composition-root`.
//!
//! - `trellis-server migrate` runs as the schema owner (`TRELLIS_MIGRATION_DATABASE_URL`): it
//!   applies the stack and Trellis migrations, refusing a database recorded for another cell
//!   before any Trellis DDL, and grants the serving role named by `TRELLIS_APP_ROLE`. It holds
//!   no serving credential, and serving holds no owner credential.
//! - `trellis-server` (or `trellis-server serve`) holds only the serving role's credential: it
//!   checks the schema is migrated and row-secured, opens the pool and buckets for its cell
//!   (refusing another cell's, and a role that bypasses or owns row security), builds the
//!   `Deployment` and serves it.
//! - `trellis-server bootstrap` records the deployment's cell marker in Trellis's artifacts
//!   bucket (`TRELLIS_ARTIFACT_BUCKET` / `TRELLIS_ARTIFACT_PREFIX`) and verifies it opens for that
//!   cell, without writing to `source_content` (which Source owns).
//! - `trellis-server config-check` reads the serving configuration, applies the posture rules
//!   `serve` applies (the signing-purpose rule among them), and prints each scope's key, without
//!   opening anything.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use object_store::ObjectStore;
use object_store::memory::InMemory;
use object_store::prefix::PrefixStore;
use sqlx::PgPool;
use stack_common_object_store::ScopedBucket;
use stack_common_ops::HealthRouter;
use stack_common_postgres::{PgHealthProbe, PoolConfig, ScopedPool};
use stack_common_scope::{Cell, Deployment, Scope, Store};
use tokio::net::TcpListener;
use trellis_server::composition;
use trellis_server::{MemoryLedgers, ObjectStoreConfig, StorageConfig, TrellisStore};
use trellis_server_ports::Ledgers;
use trellis_store_postgres_async::PgLedgers;

#[tokio::main]
async fn main() -> ExitCode {
    stack_common_ops::tracing_init();
    let command = env::args().nth(1);
    let result = match command.as_deref() {
        None | Some("serve") => serve().await,
        Some("migrate") => migrate().await,
        Some("bootstrap") => bootstrap().await,
        Some("config-check") => config_check(),
        Some(other) => Err(format!(
            "unknown command `{other}`; use serve, migrate, bootstrap or config-check"
        )
        .into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("trellis-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let startup = trellis_server::startup_from_env(composition::adapters())?;
    let cell = Cell::parse(&startup.deployment.cell)?;
    let (store, health) = open_store(&startup.storage, &cell).await?;
    let deployment = Arc::new(Deployment::new(&startup.deployment, store)?);
    let app = trellis_server::router(startup.state, deployment, health)?;
    let bind_addr = env::var("TRELLIS_BIND_ADDR")
        .unwrap_or_else(|_| trellis_server::default_bind_addr().to_string());
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(bind_addr = %bind_addr, "trellis server listening");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Migrates as the schema owner and grants the serving role; serving holds neither credential.
async fn migrate() -> Result<(), Box<dyn Error>> {
    let deployment = trellis_server::deployment_from_env()?;
    let cell = Cell::parse(&deployment.cell)?;
    let required = |name: &str| env::var(name).map_err(|_| format!("{name} is required"));
    let app_role = required("TRELLIS_APP_ROLE")?;
    let owner = pool(&required("TRELLIS_MIGRATION_DATABASE_URL")?, 2).await?;
    stack_common_postgres::migrate(
        &owner,
        &app_role,
        &cell,
        &trellis_store_postgres_async::SCHEMA,
    )
    .await?;
    owner.close().await;
    println!("trellis migrated for cell {cell}; serving role {app_role}");
    Ok(())
}

/// A store that is never opened: `config-check` builds the deployment only for its checks.
struct Unopened;

impl Store for Unopened {
    type Scoped = Scope;

    fn scoped(&self, scope: &Scope) -> Scope {
        scope.clone()
    }
}

/// Records the deployment's cell marker in Trellis's artifacts bucket (`TRELLIS_ARTIFACT_BUCKET` /
/// `TRELLIS_ARTIFACT_PREFIX`), refusing a prefix recorded for another cell and verifying that the
/// bucket opens for `cell`. Never writes to `source_content`, which Source owns.
async fn bootstrap() -> Result<(), Box<dyn Error>> {
    let startup = trellis_server::startup_from_env(composition::adapters())?;
    let cell = Cell::parse(&startup.deployment.cell)?;
    let _deployment = Deployment::new(&startup.deployment, Unopened)?;
    if let Some(artifacts) = &startup.storage.artifacts {
        let store = s3_store(artifacts)?;
        stack_common_object_store::record_bucket_cell(store.as_ref(), &cell).await?;
        let _opened = ScopedBucket::open(store, &cell).await?;
    }
    println!("trellis bootstrap ok for cell {cell}");
    Ok(())
}

fn config_check() -> Result<(), Box<dyn Error>> {
    let startup = trellis_server::startup_from_env(composition::adapters())?;
    let deployment = Deployment::new(&startup.deployment, Unopened)?;
    println!("cell {}", deployment.cell());
    for scope in deployment.scopes() {
        println!("scope {scope} {}", scope.key());
    }
    println!("trellis config: ok");
    Ok(())
}

/// Opens the deployment's ledgers and buckets for `cell`, with the probes `/readyz` runs.
async fn open_store(
    storage: &StorageConfig,
    cell: &Cell,
) -> Result<(TrellisStore, HealthRouter), Box<dyn Error>> {
    let mut health = HealthRouter::new();
    let ledgers: Arc<dyn Ledgers> = match &storage.database {
        None => Arc::new(MemoryLedgers::new()),
        Some(database) => {
            let app = pool(&database.url, 10).await?;
            health = health.with_probe(PgHealthProbe::new(app.clone(), "trellis-postgres"));
            // Refuses a role that bypasses, could lift or owns row security, and a database the
            // migrate job has not migrated, row-secured and granted.
            let scoped = ScopedPool::open(app, cell, &trellis_store_postgres_async::SCHEMA).await?;
            Arc::new(PgLedgers::new(scoped))
        }
    };
    let artifacts = bucket(storage.artifacts.as_ref(), cell).await?;
    // Trellis writes certificates and Source batch copies to its own bucket.
    health = health.with_probe(artifacts.health_probe("trellis-artifacts", true));
    let mut store = TrellisStore::new(ledgers, artifacts);
    if let Some(source) = &storage.source_content {
        let source = bucket(Some(source), cell).await?;
        // WOS's Source bucket, which Trellis only reads.
        health = health.with_probe(source.health_probe("trellis-source-content", false));
        store = store.with_source_content(source);
    }
    Ok((store, health))
}

async fn pool(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the composition root builds the deployment's pools (ADR 0168 §1.2)"
    )]
    let pool = stack_common_postgres::build_sqlx_pool_with_acquire_timeout(
        &PoolConfig::programmatic(url, max_connections),
        Duration::from_secs(10),
    )
    .await;
    pool
}

fn s3_store(config: &ObjectStoreConfig) -> Result<Arc<dyn ObjectStore + Send + Sync>, Box<dyn Error>> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the composition root builds the deployment's bucket clients (ADR 0168 §1.2)"
    )]
    let s3 = stack_common_object_store::build_s3_store(&config.s3)?;
    Ok(match config.prefix.trim_matches('/') {
        "" => Arc::new(s3),
        prefix => Arc::new(PrefixStore::new(s3, prefix)),
    })
}

/// The configured bucket under its prefix, which `bootstrap` (or provisioning) recorded for `cell`,
/// or an in-memory one, which this process provisions itself; opened for `cell` without writing.
async fn bucket(
    config: Option<&ObjectStoreConfig>,
    cell: &Cell,
) -> Result<ScopedBucket, Box<dyn Error>> {
    let store: Arc<dyn ObjectStore + Send + Sync> = match config {
        None => {
            let memory: Arc<dyn ObjectStore + Send + Sync> = Arc::new(InMemory::new());
            stack_common_object_store::record_bucket_cell(memory.as_ref(), cell).await?;
            memory
        }
        Some(config) => s3_store(config)?,
    };
    Ok(ScopedBucket::open(store, cell).await?)
}
