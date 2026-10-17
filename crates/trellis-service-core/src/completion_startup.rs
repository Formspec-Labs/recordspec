// Rust guideline compliant 2026-02-21
//! Loads the completion operator signing keys and the Source-content configuration.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use serde::Deserialize;
use stack_common_error::StackError;
use trellis_export_writer::TrellisTimestamp;

use crate::{
    ServerAdapters, TrellisServerState,
    completion::{CompletionAttestor, CompletionSigner, CoseCompletionSigner},
    oidc_startup::read_private,
    source_content_startup::SourceContentStartupConfiguration,
};

const OPERATOR_CONFIG: &str = "TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE";
const SOURCE_CONTENT_CONFIG: &str = "TRELLIS_SOURCE_CONTENT_CONFIG_FILE";

pub(crate) struct StartupCompletion {
    signer: Option<OperatorSigners>,
    source_content: Option<crate::SourceContentComposition>,
}

impl StartupCompletion {
    /// Reads the two optional private configuration files named by the environment.
    pub(crate) fn from_env(adapters: &ServerAdapters) -> Result<Option<Self>, StackError> {
        let path = |name: &str| match std::env::var_os(name) {
            None => Ok(None),
            Some(value) if value.is_empty() => Err(invalid()),
            Some(value) => Ok(Some(PathBuf::from(value))),
        };
        let (operator, source) = (path(OPERATOR_CONFIG)?, path(SOURCE_CONTENT_CONFIG)?);
        if operator.is_none() && source.is_none() {
            return Ok(None);
        }
        // File problems surface as one fixed refusal, never as the file reader's message.
        Self::load(source.as_deref(), operator.as_deref(), adapters)
            .map(Some)
            .map_err(|_| invalid())
    }

    fn load(
        source: Option<&Path>,
        operator: Option<&Path>,
        adapters: &ServerAdapters,
    ) -> Result<Self, StackError> {
        let rows: Vec<OperatorProfile> = match operator {
            Some(path) => serde_json::from_slice(&read_private(path)?).map_err(|_| invalid())?,
            None => Vec::new(),
        };
        // The operator key signs whatever selection the caller sent, so the seal needs the one
        // configured publisher, which the Source-content file names.
        if (operator.is_some() && (rows.is_empty() || source.is_none())) || rows.len() > 8 {
            return Err(invalid());
        }
        let mut authorities = BTreeSet::new();
        let mut signers = Vec::with_capacity(rows.len());
        let mut trusted = integrity_verify::trellis::CertificateAuthorityRegistry::new();
        for row in rows {
            text(&row.authority)?;
            if !authorities.insert(row.authority.clone()) {
                return Err(invalid());
            }
            let authority = CompletionAttestor {
                authority: row.authority,
                authority_class: match row.authority_class {
                    AuthorityClass::Prior => "prior".into(),
                    AuthorityClass::New => "new".into(),
                },
                public_key: row.public_key,
            };
            let key_path = operator
                .ok_or_else(invalid)?
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(row.cose_key_file);
            let signer = CoseCompletionSigner::from_cose_key_bytes(
                authority.clone(),
                TrellisTimestamp::new(row.valid_from.0, row.valid_from.1).map_err(|_| invalid())?,
                TrellisTimestamp::new(row.valid_until.0, row.valid_until.1)
                    .map_err(|_| invalid())?,
                &read_private(&key_path)?,
            )
            .map_err(|_| invalid())?;
            trusted.insert(
                authority.authority.clone(),
                integrity_verify::trellis::TrustedCertificateAuthority {
                    public_key: authority.public_key,
                    authority_class: authority.authority_class.clone(),
                    allowed_purpose: trellis_service_client::COMPLETION_EVENT.into(),
                    valid_from: integrity_verify::trellis::TrellisTimestamp {
                        seconds: row.valid_from.0,
                        nanos: row.valid_from.1,
                    },
                    valid_until: integrity_verify::trellis::TrellisTimestamp {
                        seconds: row.valid_until.0,
                        nanos: row.valid_until.1,
                    },
                },
            );
            signers.push((authority, signer));
        }
        let source_content = source
            .map(|path| {
                let configuration: SourceContentStartupConfiguration =
                    serde_json::from_slice(&read_private(path)?).map_err(|_| invalid())?;
                let guard = configuration.load(path, adapters.native_closeout.clone())?;
                Ok::<_, StackError>(configuration.compose(
                    guard,
                    &adapters.source_content,
                    operator.map(|_| trusted),
                ))
            })
            .transpose()?;
        Ok(Self {
            signer: operator.map(|_| OperatorSigners(signers)),
            source_content,
        })
    }

    pub(crate) fn apply(self, state: TrellisServerState) -> TrellisServerState {
        let state = match self.signer {
            Some(signer) => match self.source_content.as_ref() {
                // `load` refused an operator file without the Source-content file naming it.
                Some(source) => state.with_completion(Arc::new(signer), source.publisher.clone()),
                None => state,
            },
            None => state,
        };
        match self.source_content {
            Some(composition) => state.with_source_content(composition),
            None => state,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperatorProfile {
    authority: String,
    authority_class: AuthorityClass,
    public_key: [u8; 32],
    valid_from: (u64, u32),
    valid_until: (u64, u32),
    cose_key_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum AuthorityClass {
    Prior,
    New,
}

struct OperatorSigners(Vec<(CompletionAttestor, CoseCompletionSigner)>);
#[async_trait]
impl CompletionSigner for OperatorSigners {
    async fn sign(
        &self,
        authority: &CompletionAttestor,
        preimage: &[u8],
    ) -> Result<[u8; 64], StackError> {
        let signer = self
            .0
            .iter()
            .find(|(selected, _)| selected == authority)
            .map(|(_, signer)| signer)
            .ok_or_else(invalid)?;
        signer.sign(authority, preimage).await
    }
}

fn text(value: &str) -> Result<(), StackError> {
    if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn invalid() -> StackError {
    StackError::bad_request("completion startup configuration is invalid")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;

    fn private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn adapters() -> ServerAdapters {
        crate::test_adapters::adapters()
    }
    /// A valid Source-content file naming the publisher the seal pins.
    fn source_file(directory: &Path) -> PathBuf {
        let source = directory.join("source.json");
        let owning = serde_json::to_vec(&json!({"closeoutRecord":{"recordKind":serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap(),"event":"neutral.closeout","tests":[]}})).unwrap();
        private(&directory.join("owning.json"), &owning);
        private(
            &source,
            &serde_json::to_vec(&json!({
                "pins":{"providerSelectionHash":vec![1u8;32],"nativePolicyHash":vec![2u8;32],"recipientPolicyHash":vec![3u8;32]},
                "publisher":"wos-machine",
                "objectStore":{"bucket":"b","endpoint":null,"region":null,"prefix":"p"},
                "nativeHostSelectionFile":"owning.json",
                "nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&owning)
            }))
            .unwrap(),
        );
        source
    }

    #[test]
    fn completion_startup_loads_only_explicit_valid_operator_keys() {
        let directory = tempfile::tempdir().unwrap();
        let operator = directory.path().join("operator.json");
        let key = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/vectors/_keys/issuer-001.cose_key"),
        )
        .unwrap();
        let public = trellis_cddl::parse_ed25519_cose_key(&key)
            .unwrap()
            .public_key;
        private(&directory.path().join("key.cose"), &key);
        let row = json!({"authority":"test-operator", "authorityClass":"prior", "publicKey":public, "validFrom":[0,0], "validUntil":[20000,0], "coseKeyFile":"key.cose"});
        let source = source_file(directory.path());
        let loads = |rows: Value| {
            private(&operator, &serde_json::to_vec(&rows).unwrap());
            StartupCompletion::load(Some(&source), Some(&operator), &adapters())
        };
        assert!(loads(json!([row.clone()])).unwrap().signer.is_some());
        assert!(loads(json!([row.clone(), row.clone()])).is_err());
        let mut mismatch = row.clone();
        mismatch["publicKey"] = json!(vec![0u8; 32]);
        assert!(loads(json!([mismatch])).is_err());
        let mut interval = row.clone();
        interval["validUntil"] = json!([0, 0]);
        assert!(loads(json!([interval])).is_err());
        assert!(loads(json!([])).is_err());
        // The operator key signs whatever the caller selected: no publisher, no seal.
        private(&operator, &serde_json::to_vec(&json!([row])).unwrap());
        assert!(StartupCompletion::load(None, Some(&operator), &adapters()).is_err());
    }

    #[test]
    fn source_content_startup_needs_no_operator_key_and_no_outgoing_client() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        let owning = serde_json::to_vec(&json!({"closeoutRecord":{"recordKind":serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap(),"event":"neutral.closeout","tests":[]}})).unwrap();
        private(&directory.path().join("owning.json"), &owning);
        private(
            &source,
            &serde_json::to_vec(&json!({
                "pins":{"providerSelectionHash":vec![1u8;32],"nativePolicyHash":vec![2u8;32],"recipientPolicyHash":vec![3u8;32]},
                "publisher":"wos-machine",
                "objectStore":{"bucket":"b","endpoint":null,"region":null,"prefix":"p"},
                "nativeHostSelectionFile":"owning.json",
                "nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&owning)
            }))
            .unwrap(),
        );
        let loaded = StartupCompletion::load(Some(&source), None, &adapters()).unwrap();
        assert!(loaded.signer.is_none());
        let composition = loaded.source_content.unwrap();
        assert_eq!(composition.publisher, "wos-machine");
        assert_eq!(composition.pins.native_policy_hash, [2; 32]);
        // An outgoing-client profile is no longer a configuration shape.
        private(
            &source,
            &serde_json::to_vec(&json!({"origin":"https://wos.example","clientId":"c"})).unwrap(),
        );
        assert!(StartupCompletion::load(Some(&source), None, &adapters()).is_err());
    }

    #[tokio::test]
    async fn operator_selection_requires_exact_authority_class_and_key() {
        let key = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/vectors/_keys/issuer-001.cose_key"),
        )
        .unwrap();
        let authority = CompletionAttestor {
            authority: "test-operator".into(),
            authority_class: "prior".into(),
            public_key: trellis_cddl::parse_ed25519_cose_key(&key)
                .unwrap()
                .public_key,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signer = CoseCompletionSigner::from_cose_key_bytes(
            authority.clone(),
            TrellisTimestamp::new(now - 60, 0).unwrap(),
            TrellisTimestamp::new(now + 3600, 0).unwrap(),
            &key,
        )
        .unwrap();
        let operators = OperatorSigners(vec![(authority.clone(), signer)]);
        let preimage =
            trellis_cddl::certificate_attestation_preimage("test-certificate", now, 0, "prior")
                .unwrap();
        let signature = operators.sign(&authority, &preimage).await.unwrap();
        assert!(integrity_cose::verify_ed25519_signature(
            authority.public_key,
            &preimage,
            signature
        ));
        let mut class = authority.clone();
        class.authority_class = "new".into();
        assert!(operators.sign(&class, &preimage).await.is_err());
        let mut key = authority.clone();
        key.public_key = [0; 32];
        assert!(operators.sign(&key, &preimage).await.is_err());
        let mut name = authority;
        name.authority = "unselected".into();
        assert!(operators.sign(&name, &preimage).await.is_err());
    }
}
