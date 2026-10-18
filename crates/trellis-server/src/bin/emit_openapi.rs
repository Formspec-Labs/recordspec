// Rust guideline compliant 2026-02-21
//! Emit the Trellis substrate OpenAPI document.
//!
//! Builds the router's route declarations over the fixture-backed in-memory state, so an
//! annotation that disagrees with its endpoint fails here as it fails the server.

use std::process::ExitCode;

use trellis_server::test_harness::multi_producer_memory_state;

fn main() -> ExitCode {
    let documents = match trellis_server::documents(multi_producer_memory_state()) {
        Ok(documents) => documents,
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
