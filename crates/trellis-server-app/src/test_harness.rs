// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed a composed server in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server-app` from a
//! dev-dependency only. This keeps production dependency graphs free of
//! fixture-loaded signing keys.

use integrity_verify::trellis::CertificateAuthorityRegistry;
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use trellis_server::test_harness::fixture_issuer_signing_key;
use trellis_server::{SourceContentComposition, TrellisServerState};
use trellis_service_client::TrellisServiceClient;

pub use trellis_server::test_harness::fixture_signing_key_registry_cbor;

use crate::composition;

/// In-memory substrate state with mixed WOS/Formspec tenant headers (compose default).
///
/// # Panics
///
/// Panics when the repo `fixtures/vectors/_keys/issuer-001.cose_key` file is missing
/// relative to the `trellis-server` crate.
#[must_use]
pub fn multi_producer_memory_state() -> TrellisServerState {
    TrellisServerState::in_memory(
        fixture_issuer_signing_key(),
        composition::adapters(composition::mixed_tenant_headers()),
    )
}

/// Composes configured Source-only ports through the maintained startup loader.
///
/// See [`trellis_server::test_harness::source_content_composition_from_configuration`];
/// this binds the WOS native closeout codec.
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
    trellis_server::test_harness::source_content_composition_from_configuration(
        configuration,
        service_profile,
        client,
        tenant,
        authorities,
        composition::native_closeout(),
    )
}
