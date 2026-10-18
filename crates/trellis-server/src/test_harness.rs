// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed the composed server in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server` from a
//! dev-dependency only. This keeps production dependency graphs free of
//! fixture-loaded signing keys.
//!
//! The harness opens nothing and makes no scope: a test opens its bucket
//! (`ScopedBucket::open`) and builds its `Deployment` with the `composition-root` features its
//! own dev-dependencies enable (ADR 0168 §1.2), then serves it:
//!
//! ```ignore
//! let bucket = ScopedBucket::open(Arc::new(InMemory::new()), &Cell::parse("cell-a")?).await?;
//! let deployment = Deployment::new(&one_scope("acme", "benefits", "prod"), memory_store(bucket))?;
//! let app = trellis_server::router(multi_producer_memory_state(), Arc::new(deployment),
//!     HealthRouter::new())?;
//! ```

use std::fs;
use std::sync::Arc;

use integrity_verify::trellis::CertificateAuthorityRegistry;
use stack_common_error::StackError;
use stack_common_object_store::ScopedBucket;
use stack_common_scope::{DeploymentConfig, ScopeConfig};
use trellis_export_writer::TrellisTimestamp;
use trellis_service_core::{
    MemoryLedgers, ServerSigningKey, SourceContentComposition, TrellisServerState, TrellisStore,
    source_content_composition_from_configuration as compose_source_content,
};

use crate::composition;

/// A deployment in cell `cell-a` serving the one scope `tenant/workspace/environment`.
#[must_use]
pub fn one_scope(tenant: &str, workspace: &str, environment: &str) -> DeploymentConfig {
    DeploymentConfig {
        cell: "cell-a".into(),
        scopes: vec![ScopeConfig {
            tenant: tenant.into(),
            workspace: workspace.into(),
            environment: Some(environment.into()),
        }],
        public: None,
    }
}

/// In-memory ledgers over the test's bucket, ready for `Deployment::new`.
#[must_use]
pub fn memory_store(bucket: ScopedBucket) -> TrellisStore {
    TrellisStore::new(Arc::new(MemoryLedgers::new()), bucket)
}

fn fixture_issuer_signing_key() -> ServerSigningKey {
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
    let key = fs::read(key_path).expect("read issuer-001.cose_key");
    ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).expect("timestamp"))
        .expect("fixture COSE signing key")
}

/// Substrate state with the shipped WOS and Formspec adapters and the fixture issuer key.
///
/// # Panics
///
/// Panics when the repo `fixtures/vectors/_keys/issuer-001.cose_key` file is missing
/// relative to this crate.
#[must_use]
pub fn multi_producer_memory_state() -> TrellisServerState {
    TrellisServerState::new(fixture_issuer_signing_key(), composition::adapters())
}

/// Two servers' states, before and after a signing-key rotation. Serve both over one
/// deployment so they share its ledgers.
pub struct KeyRotationStates {
    /// Signs with the fixture issuer `issuer-001`.
    pub before: TrellisServerState,
    /// Signs with `issuer-002`, whose history retires `issuer-001` at the rotation instant.
    pub after: TrellisServerState,
    /// The public key history a relying party pins: the contents of
    /// `TRELLIS_SIGNING_KEY_HISTORY_PATH` after the rotation.
    pub history_json: Vec<u8>,
}

/// Server states across a rotation at `rotated_at` (unix seconds).
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
    let state = |key| TrellisServerState::new(key, composition::adapters());
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
        &composition::adapters(),
    )
}
