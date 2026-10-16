// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed the composed server in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server` from a
//! dev-dependency only. This keeps production dependency graphs free of
//! fixture-loaded signing keys.

use std::fs;

use integrity_verify::trellis::CertificateAuthorityRegistry;
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use trellis_export_writer::TrellisTimestamp;
use trellis_service_client::TrellisServiceClient;
use trellis_service_core::{
    ServerSigningKey, SourceContentComposition, TrellisServerState,
    source_content_composition_from_configuration as compose_source_content,
};

use crate::composition;

fn fixture_issuer_signing_key() -> ServerSigningKey {
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
    let key = fs::read(key_path).expect("read issuer-001.cose_key");
    ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).expect("timestamp"))
        .expect("fixture COSE signing key")
}

/// In-memory substrate state with mixed WOS/Formspec tenant headers (compose default).
///
/// # Panics
///
/// Panics when the repo `fixtures/vectors/_keys/issuer-001.cose_key` file is missing
/// relative to this crate.
#[must_use]
pub fn multi_producer_memory_state() -> TrellisServerState {
    TrellisServerState::in_memory(
        fixture_issuer_signing_key(),
        composition::adapters(composition::mixed_tenant_headers()),
    )
}

/// Encodes the existing fixture issuer's public signing-key registry.
///
/// Select this registry before effects in feature-gated consumer tests. The
/// helper uses the same fixture issuer as [`multi_producer_memory_state`] and the
/// maintained registry encoder; it creates no independent trust or key material.
///
/// # Errors
///
/// Returns the maintained registry encoder's error if encoding fails.
///
/// # Panics
///
/// Panics when the existing fixture issuer key is missing or invalid.
pub fn fixture_signing_key_registry_cbor() -> Result<Vec<u8>, StackError> {
    fixture_issuer_signing_key().public_key_registry_cbor()
}

/// Composes configured Source-only ports through the maintained startup loader.
///
/// See [`trellis_service_core::source_content_composition_from_configuration`]; this
/// binds the shipped WOS adapters.
///
/// # Errors
///
/// Refuses unknown or malformed configuration fields, unsafe private files,
/// changed native-policy digest, or an unsupported native closeout rule.
pub fn source_content_composition_from_configuration(
    configuration: &[u8],
    service_profile: &std::path::Path,
    client: TrellisServiceClient,
    tenant: TenantScope,
    authorities: Option<CertificateAuthorityRegistry>,
) -> Result<SourceContentComposition, StackError> {
    compose_source_content(
        configuration,
        service_profile,
        client,
        tenant,
        authorities,
        &composition::adapters(composition::mixed_tenant_headers()),
    )
}
