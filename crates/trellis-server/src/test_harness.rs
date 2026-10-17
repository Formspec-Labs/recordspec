// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed the composed server in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server` from a
//! dev-dependency only. This keeps production dependency graphs free of
//! fixture-loaded signing keys.

use std::fs;
use std::sync::Arc;

use integrity_verify::trellis::CertificateAuthorityRegistry;
use stack_common_error::StackError;
use trellis_export_writer::TrellisTimestamp;
use trellis_service_core::{
    InMemoryEventRepository, ServerSigningKey, SourceContentComposition, TrellisServerState,
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

/// Two servers over one ledger, before and after a signing-key rotation.
pub struct KeyRotationStates {
    /// Signs with the fixture issuer `issuer-001`.
    pub before: TrellisServerState,
    /// Signs with `issuer-002`, whose history retires `issuer-001` at the rotation instant.
    pub after: TrellisServerState,
    /// The public key history a relying party pins: the contents of
    /// `TRELLIS_SIGNING_KEY_HISTORY_PATH` after the rotation.
    pub history_json: Vec<u8>,
}

/// In-memory servers sharing one ledger across a rotation at `rotated_at` (unix seconds).
///
/// The first key must stop signing by `rotated_at` and the second start signing no earlier;
/// an export refuses a signature outside its key's window.
///
/// # Panics
///
/// Panics when the fixture issuer keys are missing or invalid.
#[must_use]
pub fn key_rotation_memory_states(rotated_at: u64) -> KeyRotationStates {
    let keys_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors/_keys");
    let load = |name: &str| {
        ServerSigningKey::from_cose_key_bytes(
            fs::read(keys_dir.join(name)).expect("read fixture key"),
            TrellisTimestamp::new(0, 0).expect("timestamp"),
        )
        .expect("fixture COSE signing key")
    };
    let (first, second) = (load("issuer-001.cose_key"), load("issuer-002.cose_key"));
    let public_hex = |key: &ServerSigningKey| {
        key.registry_entries()
            .last()
            .expect("a current key row")
            .public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let history_json = serde_json::to_vec(&serde_json::json!([
        {"public_key": public_hex(&first), "valid_from_unix_secs": 0, "valid_to_unix_secs": rotated_at},
        {"public_key": public_hex(&second), "valid_from_unix_secs": rotated_at},
    ]))
    .expect("history JSON");
    let second = second
        .with_history_json(&history_json)
        .expect("key history");
    let repository: Arc<InMemoryEventRepository> = Arc::new(InMemoryEventRepository::new());
    let state = |key| {
        TrellisServerState::new(
            repository.clone(),
            key,
            composition::adapters(composition::mixed_tenant_headers()),
        )
    };
    KeyRotationStates {
        before: state(first),
        after: state(second),
        history_json,
    }
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
    authorities: Option<CertificateAuthorityRegistry>,
) -> Result<SourceContentComposition, StackError> {
    compose_source_content(
        configuration,
        service_profile,
        authorities,
        &composition::adapters(composition::mixed_tenant_headers()),
    )
}
