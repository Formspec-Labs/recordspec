// Rust guideline compliant 2026-05-15
//! Trellis server binary entrypoint.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;

use tokio::net::TcpListener;
use trellis_server::composition;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    stack_common_ops::tracing_init();
    let adapters = composition::adapters(composition::tenant_headers_from_env()?);
    let state = trellis_service_core::state_from_env(adapters).await?;
    let bind_addr = env::var("TRELLIS_BIND_ADDR")
        .unwrap_or_else(|_| trellis_service_core::default_bind_addr().to_string());
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(bind_addr = %bind_addr, "trellis server listening");
    axum::serve(listener, trellis_service_core::router(state)?).await?;
    Ok(())
}
