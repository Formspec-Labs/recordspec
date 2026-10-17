//! Binds Source-content admission to its configured publisher, pins, object store and owning policy.
// Rust guideline compliant 2026-02-21

use serde::Deserialize;
use stack_common_error::StackError;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use trellis_server_ports::{NativeCloseout, S3CompatibleArtifactStore, S3ObjectConfig};

use crate::ServerAdapters;
use crate::source_content::{
    ConfiguredNativeCloseoutGuard, ConfiguredSourceContentPins, SourceContentComposition,
    SourceContentFactory, SourceContentInputs, StoreSourceContentReader,
};

/// Optional additive composition in the existing private completion service profile.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceContentStartupConfiguration {
    pins: ConfiguredSourceContentPins,
    /// The one principal allowed to append a Source closeout (the WOS machine).
    publisher: String,
    /// Where WOS writes prepared batches. The read credential is the launcher's
    /// process credential, as for WOS's archive read store; Trellis only ever reads.
    object_store: SourceContentObjectStore,
    native_host_selection_file: PathBuf,
    native_host_selection_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceContentObjectStore {
    bucket: String,
    endpoint: Option<String>,
    region: Option<String>,
    prefix: String,
}

impl SourceContentStartupConfiguration {
    pub(crate) fn load(
        &self,
        service_profile: &Path,
        closeout: Arc<dyn NativeCloseout>,
    ) -> Result<ConfiguredNativeCloseoutGuard, StackError> {
        if self.publisher.trim().is_empty() || self.object_store.bucket.trim().is_empty() {
            return Err(StackError::bad_request(
                "Source content startup configuration invalid",
            ));
        }
        let parent = service_profile.parent().unwrap_or_else(|| Path::new("."));
        let bytes =
            crate::oidc_startup::read_private(&parent.join(&self.native_host_selection_file))?;
        if stack_common_hash::sha256_prefixed(&bytes) != self.native_host_selection_sha256 {
            return Err(StackError::bad_request(
                "Source owning native selection digest differs",
            ));
        }
        // The owner defines and validates this whole pinned document. This host passes it
        // unchanged to the NativeCloseout adapter and defines no policy.
        let owning: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| StackError::bad_request("Source owning native selection invalid"))?;
        ConfiguredNativeCloseoutGuard::new(closeout, self.pins.native_policy_hash, owning)
    }

    pub(crate) fn compose(
        &self,
        guard: ConfiguredNativeCloseoutGuard,
        factory: &SourceContentFactory,
        authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
    ) -> SourceContentComposition {
        let parts = factory(SourceContentInputs { authorities });
        let store = S3CompatibleArtifactStore::new(
            S3ObjectConfig {
                bucket: self.object_store.bucket.clone(),
                endpoint: self.object_store.endpoint.clone(),
                region: self.object_store.region.clone(),
            },
            self.object_store.prefix.clone(),
        );
        SourceContentComposition {
            object_reader: Arc::new(StoreSourceContentReader::new(store)),
            batch_checker: parts.batch_checker,
            final_prefix_guard: Arc::new(guard),
            structural: parts.structural,
            pins: self.pins.clone(),
            publisher: self.publisher.clone(),
        }
    }
}

/// Composes configured Source-only ports through the maintained startup loader.
///
/// Pass the Source publisher, Source/native/recipient pins, object store and
/// private native-policy file through the closed configuration.
/// SourceContentOnly callers may pass `None` for formal certificate authorities.
/// This supplies the adapters' real reader, native guard and publication verifier;
/// it grants no Source authority or final reader readiness and sends no requests.
///
/// # Errors
/// Refuses unknown or malformed configuration fields, unsafe private files,
/// changed native-policy digest, or an unsupported native closeout rule.
pub fn source_content_composition_from_configuration(
    configuration: &[u8],
    service_profile: &Path,
    authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
    adapters: &ServerAdapters,
) -> Result<SourceContentComposition, StackError> {
    let selected: SourceContentStartupConfiguration = serde_json::from_slice(configuration)
        .map_err(|_| StackError::bad_request("Source content startup configuration invalid"))?;
    let guard = selected.load(service_profile, adapters.native_closeout.clone())?;
    Ok(selected.compose(guard, &adapters.source_content, authorities))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn startup_source_guard_uses_exact_private_owning_rule_and_refuses_changed_digest() {
        let directory = tempfile::tempdir().unwrap();
        let owning = directory.path().join("owning.json");
        let rule = serde_json::json!({"closeoutRecord":{"recordKind":serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap(),"event":"neutral.closeout",
            "tests":[{"test":"equals","pointer":"/data/closed","value":true}]}});
        let bytes = serde_json::to_vec(&rule).unwrap();
        std::fs::write(&owning, &bytes).unwrap();
        std::fs::set_permissions(&owning, std::fs::Permissions::from_mode(0o600)).unwrap();
        let value = serde_json::json!({"pins":{"providerSelectionHash":vec![1u8;32],"nativePolicyHash":vec![2u8;32],"recipientPolicyHash":vec![3u8;32]},
            "publisher":"wos-machine","objectStore":{"bucket":"b","endpoint":null,"region":null,"prefix":"p"},
            "nativeHostSelectionFile":"owning.json","nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&bytes)});
        let configuration: SourceContentStartupConfiguration =
            serde_json::from_value(value.clone()).unwrap();
        assert!(
            configuration
                .load(
                    &directory.path().join("service.json"),
                    crate::test_adapters::closeout()
                )
                .is_ok()
        );
        std::fs::write(&owning, b"{}").unwrap();
        assert!(
            configuration
                .load(
                    &directory.path().join("service.json"),
                    crate::test_adapters::closeout()
                )
                .is_err()
        );
        let mut unknown = value;
        unknown["callerSelectedRule"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SourceContentStartupConfiguration>(unknown).is_err());
    }
}

#[cfg(all(test, unix))]
mod source_content_configuration_tests {
    use super::*;
    use std::fs;
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
            "publisher":"wos-machine","objectStore":{"bucket":"b","endpoint":null,"region":null,"prefix":"p"},
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
    ) -> Result<SourceContentComposition, stack_common_error::StackError> {
        source_content_composition_from_configuration(
            configuration,
            profile,
            None,
            &crate::test_adapters::adapters(),
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
