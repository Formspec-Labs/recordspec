//! Binds Source-only reads to existing selected completion client and owning policy.
// Rust guideline compliant 2026-02-21

use serde::Deserialize;
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::source_content::{
    ConfiguredNativeCloseoutGuard, ConfiguredSourceContentPins, NativeCloseoutRecordRule,
    SourceContentComposition, WosSourceContentContributor, WosSourcePublicationVerifier,
};

/// Optional additive composition in the existing private completion service profile.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceContentStartupConfiguration {
    pins: ConfiguredSourceContentPins,
    native_host_selection_file: PathBuf,
    native_host_selection_sha256: String,
}

impl SourceContentStartupConfiguration {
    pub(crate) fn load(
        &self,
        service_profile: &Path,
    ) -> Result<ConfiguredNativeCloseoutGuard, StackError> {
        let parent = service_profile.parent().unwrap_or_else(|| Path::new("."));
        let bytes =
            crate::oidc_startup::read_private(&parent.join(&self.native_host_selection_file))?;
        if stack_common_hash::sha256_prefixed(&bytes) != self.native_host_selection_sha256 {
            return Err(StackError::bad_request(
                "Source owning native selection digest differs",
            ));
        }
        // WOS owns and validates this whole pinned document. This host consumes
        // its unchanged closeoutRecord rule; it does not define another policy.
        let owning: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| StackError::bad_request("Source owning native selection invalid"))?;
        let rule: NativeCloseoutRecordRule = serde_json::from_value(
            owning
                .get("closeoutRecord")
                .cloned()
                .ok_or_else(|| StackError::bad_request("Source native closeout rule absent"))?,
        )
        .map_err(|_| StackError::bad_request("Source native closeout rule invalid"))?;
        ConfiguredNativeCloseoutGuard::new(self.pins.native_policy_hash, rule)
    }

    pub(crate) fn compose(
        &self,
        guard: ConfiguredNativeCloseoutGuard,
        client: trellis_service_client::TrellisServiceClient,
        tenant: TenantScope,
        authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
    ) -> SourceContentComposition {
        let reader = Arc::new(WosSourceContentContributor::for_tenant(
            client,
            tenant,
            self.pins.clone(),
        ));
        SourceContentComposition {
            selection_resolver: reader.clone(),
            contributor: reader,
            final_prefix_guard: Arc::new(guard),
            structural: Arc::new(WosSourcePublicationVerifier::new(authorities)),
        }
    }
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
            "nativeHostSelectionFile":"owning.json","nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&bytes)});
        let configuration: SourceContentStartupConfiguration =
            serde_json::from_value(value.clone()).unwrap();
        assert!(
            configuration
                .load(&directory.path().join("service.json"))
                .is_ok()
        );
        std::fs::write(&owning, b"{}").unwrap();
        assert!(
            configuration
                .load(&directory.path().join("service.json"))
                .is_err()
        );
        let mut unknown = value;
        unknown["callerSelectedRule"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SourceContentStartupConfiguration>(unknown).is_err());
    }
}
