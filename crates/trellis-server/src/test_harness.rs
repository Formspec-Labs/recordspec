// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed `trellis-server` in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server` from a dev-dependency only.
//! This keeps production dependency graphs free of fixture-loaded signing keys.

#![forbid(unsafe_code)]

use std::fs;
use std::sync::Arc;

use trellis_export_writer::TrellisTimestamp;

use crate::{InMemoryEventRepository, ServerSigningKey, TenantHeaderMode, TrellisServerState};

/// In-memory substrate state with mixed WOS/Formspec tenant headers (compose default).
///
/// # Panics
///
/// Panics when the repo `fixtures/vectors/_keys/issuer-001.cose_key` file is missing
/// relative to this crate (same oracle as `trellis-server` unit tests).
#[must_use]
pub fn multi_producer_memory_state() -> TrellisServerState {
    TrellisServerState::new(
        Arc::new(InMemoryEventRepository::new()),
        fixture_issuer_signing_key(),
        TenantHeaderMode::MultiProducer,
    )
}

#[must_use]
fn fixture_issuer_signing_key() -> ServerSigningKey {
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
    let key = fs::read(key_path).expect("read issuer-001.cose_key");
    ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).expect("timestamp"))
        .expect("fixture COSE signing key")
}
