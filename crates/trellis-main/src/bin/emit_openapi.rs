// Rust guideline compliant 2026-02-21
//! Emit the Trellis substrate OpenAPI document.
//!
//! Builds the router's route declarations over the fixture-backed state and a one-scope
//! in-memory deployment, so an annotation that disagrees with its endpoint fails here as it
//! fails the server.

use std::process::ExitCode;
use std::sync::Arc;

use object_store::ObjectStore;
use object_store::memory::InMemory;
use stack_common_object_store::ScopedBucket;
use stack_common_scope::{Cell, Deployment};
use trellis_server::test_harness::{memory_store, multi_producer_memory_state, one_scope};

#[tokio::main]
async fn main() -> ExitCode {
    let deployment = async {
        let cell = Cell::parse("cell-a")?;
        let store: Arc<dyn ObjectStore + Send + Sync> = Arc::new(InMemory::new());
        stack_common_object_store::record_bucket_cell(store.as_ref(), &cell).await?;
        let bucket = ScopedBucket::open(store, &cell).await?;
        let config = one_scope("trellis", "openapi", "emit");
        Ok::<_, Box<dyn std::error::Error>>(Deployment::new(&config, memory_store(bucket))?)
    }
    .await;
    let documents = match deployment.map(|deployment| {
        trellis_server::documents(multi_producer_memory_state(), Arc::new(deployment))
    }) {
        Ok(Ok(documents)) => documents,
        Ok(Err(error)) => {
            eprintln!("emit-openapi: {error}");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("emit-openapi: {error}");
            return ExitCode::from(1);
        }
    };
    match serde_json::to_string_pretty(&documents.stack) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("emit-openapi: OpenAPI serialization failed: {error}");
            ExitCode::from(1)
        }
    }
}
