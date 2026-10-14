// Rust guideline compliant 2026-02-21
//! Loads independently selected completion service credentials and operator keys.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use serde::Deserialize;
use stack_common_auth::oidc::{
    AccessTokenProfile, ClientAuthenticationMethod, ClientCredentialsConfig,
    OidcAccessTokenVerifier, OidcClientCredentials, OidcDependencies, OidcTrust,
    ReqwestAuthHttpClient, StaticClientSecret, SystemAuthClock, TransportPolicy, WorkloadAssurance,
};
use stack_common_error::StackError;
use stack_common_http::tenant::{HeaderConfig, TenantScope};
use trellis_export_writer::TrellisTimestamp;
use trellis_service_client::{
    TrellisServiceClient, TrellisServiceClientConfig, completion_selection::CompletionTenant,
};

use crate::{
    TrellisServerState,
    completion::{
        CompletionAttestor, CompletionSigner, CoseCompletionSigner, WosCompletionSelector,
    },
    oidc_startup::read_private,
};

pub(crate) struct StartupCompletion {
    selector: Option<WosCompletionSelector>,
    signer: Option<OperatorSigners>,
    source_content: Option<crate::SourceContentComposition>,
}

impl StartupCompletion {
    pub(crate) fn from_env(tenant: &TenantScope) -> Result<Option<Self>, StackError> {
        match (
            std::env::var_os("TRELLIS_WOS_COMPLETION_CONFIG_FILE"),
            std::env::var_os("TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE"),
        ) {
            (None, None) => Ok(None),
            (Some(service), Some(operator)) if !service.is_empty() && !operator.is_empty() => {
                Self::load(Path::new(&service), Path::new(&operator), tenant).map(Some)
            }
            (Some(service), None) if !service.is_empty() => {
                Self::load_selected(Path::new(&service), None, tenant)
                    .map_err(|_| invalid())
                    .map(Some)
            }
            _ => Err(invalid()),
        }
    }

    fn load(service: &Path, operator: &Path, tenant: &TenantScope) -> Result<Self, StackError> {
        Self::load_selected(service, Some(operator), tenant)
    }

    fn load_selected(
        service: &Path,
        operator: Option<&Path>,
        tenant: &TenantScope,
    ) -> Result<Self, StackError> {
        let profile: ServiceProfile =
            serde_json::from_slice(&read_private(service)?).map_err(|_| invalid())?;
        profile.validate(tenant)?;
        let native_guard = profile
            .source_content
            .as_ref()
            .map(|configuration| configuration.load(service))
            .transpose()?;
        if operator.is_none() && native_guard.is_none() {
            return Err(invalid());
        }
        let secret_path = service
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&profile.client_secret_file);
        let secret = String::from_utf8(read_private(&secret_path)?).map_err(|_| invalid())?;
        let credentials = StaticClientSecret::new(
            profile.client_id.clone(),
            secret.trim_end_matches(['\r', '\n']).to_owned(),
        )
        .map_err(|_| invalid())?;
        let verifier = OidcAccessTokenVerifier::new(
            OidcTrust {
                issuer: profile.issuer,
                audience: profile.audience,
                required_scopes: profile.required_scopes.into_iter().collect(),
                allowed_clients: profile.allowed_clients.into_iter().collect(),
                profile: match profile.profile {
                    ClaimProfile::Keycloak => AccessTokenProfile::Keycloak,
                    ClaimProfile::OktaCustomAuthorizationServer => {
                        AccessTokenProfile::OktaCustomAuthorizationServer
                    }
                    ClaimProfile::Rfc9068 => AccessTokenProfile::Rfc9068,
                },
                transport: if profile.allow_development_loopback_http {
                    TransportPolicy::DevelopmentLiteralLoopback
                } else {
                    TransportPolicy::HttpsOnly
                },
            },
            OidcDependencies {
                http: Arc::new(ReqwestAuthHttpClient::new().map_err(|_| invalid())?),
                clock: Arc::new(SystemAuthClock),
            },
        )
        .map_err(|_| invalid())?;
        let provider = OidcClientCredentials::new(
            ClientCredentialsConfig {
                client_id: profile.client_id,
                scopes: profile.scopes.into_iter().collect(),
                method: ClientAuthenticationMethod::ClientSecretBasic,
                assurance: WorkloadAssurance::RegisteredClient,
            },
            verifier,
            Arc::new(credentials),
        )
        .map_err(|_| invalid())?;
        let client_configuration =
            TrellisServiceClientConfig::new(profile.origin, HeaderConfig::wos());
        let client_configuration = if profile.source_content.is_some() {
            client_configuration.with_timeout(
                trellis_service_client::source_content::DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT,
            )
        } else {
            client_configuration
        };
        let client = TrellisServiceClient::new(client_configuration)
            .map_err(|_| invalid())?
            .with_token_provider(Arc::new(provider))
            .map_err(|_| invalid())?;

        let rows: Vec<OperatorProfile> = match operator {
            Some(path) => serde_json::from_slice(&read_private(path)?).map_err(|_| invalid())?,
            None => Vec::new(),
        };
        if (operator.is_some() && rows.is_empty()) || rows.len() > 8 {
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
        let source_content = match (profile.source_content, native_guard) {
            (Some(configuration), Some(guard)) => Some(configuration.compose(
                guard,
                client.clone(),
                tenant.clone(),
                if operator.is_some() {
                    Some(trusted)
                } else {
                    None
                },
            )),
            (None, None) => None,
            _ => return Err(invalid()),
        };
        Ok(Self {
            selector: operator.map(|_| WosCompletionSelector::for_tenant(client, tenant.clone())),
            signer: operator.map(|_| OperatorSigners(signers)),
            source_content,
        })
    }

    pub(crate) fn apply(self, state: TrellisServerState) -> TrellisServerState {
        let state = match (self.selector, self.signer) {
            (Some(selector), Some(signer)) => {
                state.with_completion(Arc::new(selector), Arc::new(signer))
            }
            (None, None) => state,
            _ => unreachable!("startup constructs paired formal dependencies"),
        };
        match self.source_content {
            Some(composition) => state.with_source_content(composition),
            None => state,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceProfile {
    origin: String,
    tenant_scope: CompletionTenant,
    issuer: String,
    audience: String,
    required_scopes: Vec<String>,
    allowed_clients: Vec<String>,
    profile: ClaimProfile,
    #[serde(default)]
    allow_development_loopback_http: bool,
    client_id: String,
    scopes: Vec<String>,
    authentication: Authentication,
    assurance: Assurance,
    client_secret_file: PathBuf,
    #[serde(default)]
    source_content: Option<crate::source_content_startup::SourceContentStartupConfiguration>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum ClaimProfile {
    Keycloak,
    OktaCustomAuthorizationServer,
    Rfc9068,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Authentication {
    ClientSecretBasic,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Assurance {
    RegisteredClient,
}

impl ServiceProfile {
    fn validate(&self, tenant: &TenantScope) -> Result<(), StackError> {
        let _ = (&self.authentication, &self.assurance);
        if self.tenant_scope != CompletionTenant::from(tenant)
            || self.allowed_clients != [self.client_id.clone()]
        {
            return Err(invalid());
        }
        for field in [
            &self.tenant_scope.tenant,
            &self.tenant_scope.workspace,
            &self.tenant_scope.environment,
            &self.tenant_scope.cell,
            &self.issuer,
            &self.audience,
            &self.client_id,
        ] {
            text(field)?;
        }
        let requested = scope_set(&self.scopes)?;
        if requested != scope_set(&self.required_scopes)? {
            return Err(invalid());
        }
        if self.client_secret_file.as_os_str().is_empty() {
            return Err(invalid());
        }
        text(&self.origin)?;
        // http::Uri discards fragments; refuse them before parsing.
        if self.origin.contains('#') {
            return Err(invalid());
        }
        let uri: axum::http::Uri = self.origin.parse().map_err(|_| invalid())?;
        let authority = uri.authority().ok_or_else(invalid)?;
        if authority.as_str().contains('@') || uri.path() != "/" || uri.query().is_some() {
            return Err(invalid());
        }
        match uri.scheme_str() {
            Some("https") => (),
            Some("http") if self.allow_development_loopback_http => {
                let host = uri
                    .host()
                    .ok_or_else(invalid)?
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                if !host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

fn scope_set(values: &[String]) -> Result<BTreeSet<String>, StackError> {
    if values.is_empty() || values.len() > 64 {
        return Err(invalid());
    }
    let mut result = BTreeSet::new();
    for value in values {
        text(value)?;
        if value.chars().any(char::is_whitespace) || !result.insert(value.clone()) {
            return Err(invalid());
        }
    }
    Ok(result)
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

    fn tenant() -> TenantScope {
        TenantScope {
            tenant: "tenant-a".into(),
            workspace: "workspace-a".into(),
            environment: "environment-a".into(),
            cell: "cell-a".into(),
        }
    }
    fn profile() -> Value {
        json!({"origin":"https://wos.example", "tenantScope":{"tenant":"tenant-a","workspace":"workspace-a","environment":"environment-a","cell":"cell-a"},
            "issuer":"https://issuer.example/realm", "audience":"wos-audience", "requiredScopes":["completion.read"], "allowedClients":["completion-client"],
            "profile":"keycloak", "clientId":"completion-client", "scopes":["completion.read"], "authentication":"clientSecretBasic", "assurance":"registeredClient", "clientSecretFile":"secret"})
    }
    fn validate(value: Value) -> bool {
        serde_json::from_value::<ServiceProfile>(value)
            .is_ok_and(|profile| profile.validate(&tenant()).is_ok())
    }
    fn private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn completion_profile_requires_exact_tenant_client_and_scopes() {
        assert!(validate(profile()));
        let mut value = profile();
        value["tenantScope"]["cell"] = json!("other-cell");
        assert!(!validate(value));
        let mut value = profile();
        value["allowedClients"] = json!(["another-client"]);
        assert!(!validate(value));
        let mut value = profile();
        value["requiredScopes"] = json!(["another.scope"]);
        assert!(!validate(value));
        let mut value = profile();
        value["scopes"] = json!(["completion.read", "completion.read"]);
        assert!(!validate(value));
    }

    #[test]
    fn completion_profile_refuses_origin_redirection_and_implicit_development() {
        for origin in [
            "http://127.0.0.1:1",
            "https://user:secret@wos.example",
            "https://wos.example/path",
            "https://wos.example/?token=secret",
            "https://wos.example/#fragment",
        ] {
            let mut value = profile();
            value["origin"] = json!(origin);
            assert!(!validate(value), "{origin}");
        }
        for origin in ["http://127.0.0.1:1", "http://[::1]:1"] {
            let mut value = profile();
            value["origin"] = json!(origin);
            value["allowDevelopmentLoopbackHttp"] = json!(true);
            assert!(validate(value), "{origin}");
        }
        for origin in ["http://localhost:1", "http://192.0.2.1:1"] {
            let mut value = profile();
            value["origin"] = json!(origin);
            value["allowDevelopmentLoopbackHttp"] = json!(true);
            assert!(!validate(value));
        }
    }

    #[test]
    fn completion_profile_is_closed_and_requires_supported_credentials() {
        for (field, value) in [
            ("authentication", json!("privateKeyJwt")),
            ("assurance", json!("workloadAttested")),
            ("profile", json!("unknown")),
            ("staticToken", json!("secret")),
        ] {
            let mut selected = profile();
            selected[field] = value;
            assert!(!validate(selected));
        }
    }

    #[test]
    fn completion_startup_loads_only_explicit_valid_operator_keys() {
        let directory = tempfile::tempdir().unwrap();
        let service = directory.path().join("service.json");
        let operator = directory.path().join("operator.json");
        private(&service, &serde_json::to_vec(&profile()).unwrap());
        private(
            &directory.path().join("secret"),
            b"private-test-only-secret",
        );
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
        private(
            &operator,
            &serde_json::to_vec(&json!([row.clone()])).unwrap(),
        );
        assert!(StartupCompletion::load(&service, &operator, &tenant()).is_ok());
        private(
            &operator,
            &serde_json::to_vec(&json!([row.clone(), row.clone()])).unwrap(),
        );
        assert!(StartupCompletion::load(&service, &operator, &tenant()).is_err());
        let mut mismatch = row.clone();
        mismatch["publicKey"] = json!(vec![0u8; 32]);
        private(&operator, &serde_json::to_vec(&json!([mismatch])).unwrap());
        assert!(StartupCompletion::load(&service, &operator, &tenant()).is_err());
        let mut interval = row;
        interval["validUntil"] = json!([0, 0]);
        private(&operator, &serde_json::to_vec(&json!([interval])).unwrap());
        assert!(StartupCompletion::load(&service, &operator, &tenant()).is_err());
    }

    #[test]
    fn source_content_normal_startup_needs_no_formal_operator_or_signing_key() {
        let directory = tempfile::tempdir().unwrap();
        let service = directory.path().join("service.json");
        private(
            &directory.path().join("secret"),
            b"private-test-only-secret",
        );
        let owning = serde_json::to_vec(&json!({"closeoutRecord":{"recordKind":serde_json::to_value(wos_events::ProvenanceKind::OnEntry).unwrap(),"event":"neutral.closeout","tests":[]}})).unwrap();
        private(&directory.path().join("owning.json"), &owning);
        let mut selected = profile();
        selected["sourceContent"] = json!({"pins":{"providerSelectionHash":vec![1u8;32],"nativePolicyHash":vec![2u8;32],"recipientPolicyHash":vec![3u8;32]},
            "nativeHostSelectionFile":"owning.json","nativeHostSelectionSha256":stack_common_hash::sha256_prefixed(&owning)});
        private(&service, &serde_json::to_vec(&selected).unwrap());
        let loaded = StartupCompletion::load_selected(&service, None, &tenant()).unwrap();
        assert!(loaded.selector.is_none());
        assert!(loaded.signer.is_none());
        assert!(loaded.source_content.is_some());
        // An unrelated formal profile retains its required operator dependency.
        private(&service, &serde_json::to_vec(&profile()).unwrap());
        assert!(StartupCompletion::load_selected(&service, None, &tenant()).is_err());
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
