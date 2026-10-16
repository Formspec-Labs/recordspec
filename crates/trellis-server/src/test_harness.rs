// Rust guideline compliant 2026-02-21
//! Cross-crate integration helpers for consumers that embed `trellis-server` in tests.
//!
//! Enable the **`test-harness`** Cargo feature on `trellis-server` from a dev-dependency only.
//! This keeps production dependency graphs free of fixture-loaded signing keys.

#![forbid(unsafe_code)]

use std::fs;
use trellis_export_writer::TrellisTimestamp;

use crate::ServerSigningKey;

/// The fixture issuer's signing key.
///
/// # Panics
///
/// Panics when the repo `fixtures/vectors/_keys/issuer-001.cose_key` file is missing
/// relative to this crate (same oracle as `trellis-server` unit tests).
#[must_use]
pub fn fixture_issuer_signing_key() -> ServerSigningKey {
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vectors/_keys/issuer-001.cose_key");
    let key = fs::read(key_path).expect("read issuer-001.cose_key");
    ServerSigningKey::from_cose_key_bytes(key, TrellisTimestamp::new(0, 0).expect("timestamp"))
        .expect("fixture COSE signing key")
}

/// Encodes the existing fixture issuer's public signing-key registry.
///
/// Select this registry before effects in feature-gated consumer tests. The
/// helper uses the same fixture issuer as [`fixture_issuer_signing_key`] and the
/// maintained registry encoder; it creates no independent trust or key material.
///
/// # Errors
///
/// Returns the maintained registry encoder's error if encoding fails.
///
/// # Panics
///
/// Panics when the existing fixture issuer key is missing or invalid.
pub fn fixture_signing_key_registry_cbor() -> Result<Vec<u8>, stack_common_error::StackError> {
    crate::signing_key_registry_cbor(&fixture_issuer_signing_key().export_key())
}

/// Composes configured Source-only ports through the maintained startup loader.
///
/// Pass the independently selected client, tenant, Source/native/recipient pins,
/// private native-policy file and the domain's native closeout codec through the
/// existing closed configuration.
/// SourceContentOnly callers may pass `None` for formal certificate authorities.
/// This helper supplies the real reader, native guard and publication verifier;
/// it grants no Source authority or final reader readiness and sends no requests.
///
/// # Errors
///
/// Refuses unknown or malformed configuration fields, unsafe private files,
/// changed native-policy digest, or an unsupported native closeout rule.
pub fn source_content_composition_from_configuration(
    configuration: &[u8],
    service_profile: &std::path::Path,
    client: trellis_service_client::TrellisServiceClient,
    tenant: stack_common_http::tenant::TenantScope,
    authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
    closeout: std::sync::Arc<dyn trellis_server_ports::NativeCloseout>,
) -> Result<crate::SourceContentComposition, stack_common_error::StackError> {
    let selected: crate::source_content_startup::SourceContentStartupConfiguration =
        serde_json::from_slice(configuration).map_err(|_| {
            stack_common_error::StackError::bad_request(
                "Source content startup configuration invalid",
            )
        })?;
    let guard = selected.load(service_profile, closeout)?;
    Ok(selected.compose(guard, client, tenant, authorities))
}

#[cfg(all(test, unix))]
mod source_content_configuration_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn inputs(
        directory: &std::path::Path,
        rule: serde_json::Value,
    ) -> (Vec<u8>, std::path::PathBuf) {
        let bytes = serde_json::to_vec(&serde_json::json!({"closeoutRecord":rule})).unwrap();
        let native = directory.join("native.json");
        fs::write(&native, &bytes).unwrap();
        fs::set_permissions(&native, fs::Permissions::from_mode(0o600)).unwrap();
        let configuration = serde_json::to_vec(&serde_json::json!({
            "pins":{"providerSelectionHash":vec![1u8;32],"nativePolicyHash":vec![2u8;32],"recipientPolicyHash":vec![3u8;32]},
            "nativeHostSelectionFile":"native.json",
            "nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&bytes)
        })).unwrap();
        (configuration, directory.join("service-profile.json"))
    }
    fn rule() -> serde_json::Value {
        serde_json::json!({
            "recordKind":serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap(),
            "event":"neutral.closeout",
            "tests":[{"test":"equals","pointer":"/data/closed","value":true}]
        })
    }
    fn compose(
        configuration: &[u8],
        profile: &std::path::Path,
    ) -> Result<crate::SourceContentComposition, stack_common_error::StackError> {
        // No server or credential authority is mocked. These tests exercise only
        // inactive configuration admission; the real client performs no request.
        let client = trellis_service_client::TrellisServiceClient::new(
            trellis_service_client::TrellisServiceClientConfig::new(
                "http://127.0.0.1:1",
                stack_common_http::tenant::HeaderConfig::wos(),
            ),
        )
        .unwrap();
        let tenant = stack_common_http::tenant::TenantScope {
            tenant: "tenant".into(),
            workspace: "workspace".into(),
            environment: "test".into(),
            cell: "cell".into(),
        };
        source_content_composition_from_configuration(
            configuration,
            profile,
            client,
            tenant,
            None,
            std::sync::Arc::new(trellis_admission_wos::WosNativeCloseout),
        )
    }
    #[test]
    fn source_content_harness_uses_real_configuration_without_formal_authority() {
        let directory = tempfile::tempdir().unwrap();
        let (configuration, profile) = inputs(directory.path(), rule());
        let composition = compose(&configuration, &profile).unwrap();
        assert!(matches!(
            composition
                .final_prefix_guard
                .classify(b"neutral-scope", &[])
                .unwrap(),
            crate::SourceContentPrefixClass::Ordinary
        ));
    }
    #[test]
    fn source_content_harness_refuses_unknown_configuration_field() {
        let directory = tempfile::tempdir().unwrap();
        let (configuration, profile) = inputs(directory.path(), rule());
        let mut changed: serde_json::Value = serde_json::from_slice(&configuration).unwrap();
        changed["foreignPolicy"] = serde_json::json!(true);
        let error = compose(&serde_json::to_vec(&changed).unwrap(), &profile).unwrap_err();
        assert_eq!(
            error.title(),
            "Source content startup configuration invalid"
        );
    }
    #[test]
    fn source_content_harness_refuses_changed_private_native_file_digest() {
        let directory = tempfile::tempdir().unwrap();
        let (configuration, profile) = inputs(directory.path(), rule());
        fs::write(directory.path().join("native.json"), b"{}").unwrap();
        let error = compose(&configuration, &profile).unwrap_err();
        assert_eq!(
            error.title(),
            "Source owning native selection digest differs"
        );
    }
    #[test]
    fn source_content_harness_refuses_invalid_native_closeout_rule() {
        let directory = tempfile::tempdir().unwrap();
        let mut invalid = rule();
        invalid["foreignPolicy"] = serde_json::json!(true);
        let (configuration, profile) = inputs(directory.path(), invalid);
        let error = compose(&configuration, &profile).unwrap_err();
        assert_eq!(error.title(), "Source native closeout rule invalid");
    }
}
