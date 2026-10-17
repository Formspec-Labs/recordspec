//! Composes current provider verification and exact deployment resource grants.
// Rust guideline compliant 2026-02-21

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use axum::http::StatusCode;
use serde::Deserialize;
use stack_common_auth::{
    AccessTokenVerifier,
    oidc::{
        AccessTokenProfile, OidcAccessTokenVerifier, OidcCurrentAuthority, OidcDependencies,
        OidcTrust, ReqwestAuthHttpClient, StaticClientSecret, SystemAuthClock, TransportPolicy,
    },
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_http::tenant::TenantScope;
use trellis_server_ports::{AuthorizedScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer};

use crate::TrellisServerState;

// Operator profiles and grants are small. Bound reads, including files growing after metadata.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) struct StartupAuth {
    verifier: Arc<dyn AccessTokenVerifier>,
    authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    attachment_recipients: Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>,
}

impl StartupAuth {
    pub(crate) fn from_env() -> Result<Self, StackError> {
        let path = std::env::var_os("TRELLIS_OIDC_CONFIG_FILE")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StackError::bad_request("TRELLIS_OIDC_CONFIG_FILE is required"))?;
        if std::env::var_os("TRELLIS_JWT_HS256_SECRET").is_some()
            || std::env::var_os("TRELLIS_PERMISSIVE_SCOPE_AUTH").is_some()
        {
            return Err(StackError::bad_request(
                "OIDC startup refuses legacy authentication settings",
            ));
        }
        Self::load(
            Path::new(&path),
            OidcDependencies {
                http: Arc::new(ReqwestAuthHttpClient::new().map_err(|_| invalid())?),
                clock: Arc::new(SystemAuthClock),
            },
        )
    }

    pub(crate) fn load(path: &Path, dependencies: OidcDependencies) -> Result<Self, StackError> {
        let profile: Profile = serde_json::from_slice(&read_private(path)?).map_err(|error| {
            if error
                .to_string()
                .contains("accepted-attachment recipient selection invalid")
            {
                attachment_invalid()
            } else {
                invalid()
            }
        })?;
        profile.validate()?;
        let attachment_recipients = profile.attachment_selector()?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let secret = String::from_utf8(read_private(
            &parent.join(&profile.introspection_client_secret_file),
        )?)
        .map_err(|_| invalid())?;
        let credentials = StaticClientSecret::new(
            profile.introspection_client_id.clone(),
            secret.trim_end_matches(['\r', '\n']).to_owned(),
        )
        .map_err(|_| invalid())?;
        let verifier = OidcAccessTokenVerifier::new(
            OidcTrust {
                issuer: profile.issuer.clone(),
                audience: profile.audience.clone(),
                required_scopes: profile.required_scopes.iter().cloned().collect(),
                allowed_clients: profile.allowed_clients.iter().cloned().collect(),
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
            dependencies,
        )
        .map_err(|_| invalid())?;
        let verifier = OidcCurrentAuthority::new(
            verifier,
            profile.introspection_endpoint.clone(),
            profile.introspection_client_id.clone(),
            Arc::new(credentials),
        )
        .map_err(|_| invalid())?;
        let authorizer = CurrentGrants {
            path: parent.join(&profile.grants_file),
            profile,
        };
        authorizer.load_grants()?;
        Ok(Self {
            verifier: Arc::new(verifier),
            authorizer: Arc::new(authorizer),
            attachment_recipients,
        })
    }

    pub(crate) fn apply(self, state: TrellisServerState) -> TrellisServerState {
        let state = state
            .with_access_token_verifier(self.verifier)
            .with_scope_authorizer(self.authorizer)
            .with_production_like_scope_posture(true);
        match self.attachment_recipients {
            Some(selector) => state.with_external_attachment_recipients(selector),
            None => state,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    issuer: String,
    audience: String,
    required_scopes: Vec<String>,
    allowed_clients: Vec<String>,
    profile: ClaimProfile,
    #[serde(default)]
    allow_development_loopback_http: bool,
    introspection_endpoint: String,
    introspection_client_id: String,
    introspection_client_secret_file: PathBuf,
    grants_file: PathBuf,
    tenant_scope: Deployment,
    identities: Vec<Identity>,
    action_scopes: ActionScopes,
    #[serde(default, deserialize_with = "deserialize_attachment_selection")]
    accepted_attachment_recipients: Option<Vec<AttachmentSelection>>,
}

// Selected custody shares the OIDC deployment tuple and admitted principal registry.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentSelection {
    principal: String,
    scope: String,
    recipients: Vec<AttachmentRecipient>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentRecipient {
    id: String,
    public_key: [u8; 32],
    operator_held: bool,
}

struct ScopedAttachmentRecipients {
    tenant_scope: TenantScope,
    rows: Vec<(String, Vec<u8>, Vec<crate::ExternalAttachmentRecipient>)>,
}

#[async_trait]
impl crate::ExternalAttachmentRecipientSelector for ScopedAttachmentRecipients {
    async fn select(
        &self,
        permit: &AuthorizedScope,
        _descriptor: &serde_json::Value,
    ) -> Result<Vec<crate::ExternalAttachmentRecipient>, StackError> {
        if permit.action != ScopeAction::Append || permit.tenant_scope != self.tenant_scope {
            return Err(attachment_denied());
        }
        self.rows
            .iter()
            .find(|(principal, scope, _)| principal == &permit.principal && scope == &permit.scope)
            .map(|(_, _, recipients)| recipients.clone())
            .ok_or_else(attachment_denied)
    }
}

fn deserialize_attachment_selection<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<AttachmentSelection>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<AttachmentSelection>::deserialize(deserializer)
        .map(Some)
        .map_err(|_| serde::de::Error::custom("accepted-attachment recipient selection invalid"))
}

fn attachment_invalid() -> StackError {
    StackError::bad_request("accepted-attachment recipient selection invalid")
}

fn attachment_denied() -> StackError {
    StackError::new(
        ErrorCode::new("INFRA-4030").expect("static error code is valid"),
        StatusCode::FORBIDDEN,
        "accepted-attachment recipient selection required for admitted resource",
    )
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ClaimProfile {
    Keycloak,
    OktaCustomAuthorizationServer,
    Rfc9068,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Deployment {
    tenant: String,
    workspace: String,
    environment: String,
    cell: String,
}

impl Deployment {
    fn tuple(&self) -> TenantScope {
        TenantScope {
            tenant: self.tenant.clone(),
            workspace: self.workspace.clone(),
            environment: self.environment.clone(),
            cell: self.cell.clone(),
        }
    }
    fn validate(&self) -> Result<(), StackError> {
        for value in [&self.tenant, &self.workspace, &self.environment, &self.cell] {
            nonempty(value)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    issuer: String,
    subject: String,
    client_id: String,
    principal: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActionScopes {
    read: String,
    append: String,
    administer: String,
}

impl Profile {
    fn attachment_selector(
        &self,
    ) -> Result<Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>, StackError> {
        let Some(selections) = &self.accepted_attachment_recipients else {
            return Ok(None);
        };
        // Operator profiles fit the existing 1 MiB private-file bound; cap row work too.
        if selections.is_empty() || selections.len() > 1024 {
            return Err(attachment_invalid());
        }
        let mut row_ids = BTreeSet::new();
        let mut rows = Vec::with_capacity(selections.len());
        for selection in selections {
            if !self
                .identities
                .iter()
                .any(|identity| identity.principal == selection.principal)
                || nonempty(&selection.scope).is_err()
                || crate::http::validate_scope(&selection.scope).is_err()
                || !row_ids.insert((&selection.principal, &selection.scope))
                || selection.recipients.is_empty()
                || selection.recipients.len() > 64
            {
                return Err(attachment_invalid());
            }
            let mut ids = BTreeSet::new();
            let mut keys = BTreeSet::new();
            let mut recipients = Vec::with_capacity(selection.recipients.len());
            for recipient in &selection.recipients {
                // Match the owning transport's recipient bounds before storage opens.
                if recipient.id.trim().is_empty()
                    || recipient.id.len() > 256
                    || recipient.id.chars().any(char::is_control)
                    || recipient.public_key == [0; 32]
                    || !ids.insert(&recipient.id)
                    || !keys.insert(recipient.public_key)
                {
                    return Err(attachment_invalid());
                }
                recipients.push(crate::ExternalAttachmentRecipient {
                    id: recipient.id.as_bytes().to_vec(),
                    public_key: recipient.public_key,
                    operator_held: recipient.operator_held,
                });
            }
            if recipients.iter().all(|recipient| recipient.operator_held) {
                return Err(attachment_invalid());
            }
            rows.push((
                selection.principal.clone(),
                selection.scope.as_bytes().to_vec(),
                recipients,
            ));
        }
        Ok(Some(Arc::new(ScopedAttachmentRecipients {
            tenant_scope: self.tenant_scope.tuple(),
            rows,
        })))
    }

    fn validate(&self) -> Result<(), StackError> {
        self.tenant_scope.validate()?;
        unique_nonempty(&self.required_scopes)?;
        unique_nonempty(&self.allowed_clients)?;
        for value in [
            &self.issuer,
            &self.audience,
            &self.introspection_endpoint,
            &self.introspection_client_id,
            &self.action_scopes.read,
            &self.action_scopes.append,
            &self.action_scopes.administer,
        ] {
            nonempty(value)?;
        }
        for value in self.required_scopes.iter().chain([
            &self.action_scopes.read,
            &self.action_scopes.append,
            &self.action_scopes.administer,
        ]) {
            if value
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || matches!(byte, b'\"' | b'\\'))
            {
                return Err(invalid());
            }
        }
        if self.introspection_client_secret_file.as_os_str().is_empty()
            || self.grants_file.as_os_str().is_empty()
            || self.identities.is_empty()
        {
            return Err(invalid());
        }
        let mut identities = BTreeSet::new();
        for identity in &self.identities {
            for value in [&identity.subject, &identity.client_id, &identity.principal] {
                nonempty(value)?;
            }
            if identity.issuer != self.issuer
                || !self.allowed_clients.contains(&identity.client_id)
                || !identities.insert((&identity.issuer, &identity.subject, &identity.client_id))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantFile {
    tenant_scope: Deployment,
    grants: Vec<Grant>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Action {
    Read,
    Append,
    Administer,
}

impl Action {
    fn port(self) -> ScopeAction {
        match self {
            Self::Read => ScopeAction::Read,
            Self::Append => ScopeAction::Append,
            Self::Administer => ScopeAction::Administer,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    principal: String,
    /// Exactly one of `scope` (one ledger) and `scopePrefix` (every ledger the prefix starts).
    #[serde(default)]
    scope: Option<String>,
    /// A prefix ending in `.` or `_`, so it stops at a component boundary of a ledger name
    /// (`<scope key>.<namespace>_<type>_<id>`) and cannot match half a component.
    #[serde(default)]
    scope_prefix: Option<String>,
    action: Action,
    #[serde(default)]
    actors: Vec<Actor>,
    #[serde(default)]
    payload_actors: Vec<PayloadActor>,
}

impl Grant {
    /// The grant's exact scope or prefix, tagged so the two never collide in the uniqueness set.
    fn selector(&self) -> Result<(bool, &str), StackError> {
        match (&self.scope, &self.scope_prefix) {
            (Some(scope), None) => Ok((false, scope)),
            (None, Some(prefix)) if prefix.ends_with(['.', '_']) => Ok((true, prefix)),
            _ => Err(invalid()),
        }
    }

    fn admits(&self, scope: &str) -> bool {
        match (&self.scope, &self.scope_prefix) {
            (Some(exact), _) => exact == scope,
            (None, Some(prefix)) => scope.starts_with(prefix.as_str()),
            (None, None) => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Actor {
    kind: String,
    subject: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayloadActor {
    pointer: String,
    required: bool,
    subjects: Vec<String>,
}

struct CurrentGrants {
    path: PathBuf,
    profile: Profile,
}

impl CurrentGrants {
    fn load_grants(&self) -> Result<GrantFile, StackError> {
        let file: GrantFile =
            serde_json::from_slice(&read_private(&self.path)?).map_err(|_| invalid())?;
        self.validate_current(&file)?;
        Ok(file)
    }

    fn validate_current(&self, file: &GrantFile) -> Result<(), StackError> {
        if file.tenant_scope != self.profile.tenant_scope {
            return Err(invalid());
        }
        let mut rows = BTreeSet::new();
        for grant in &file.grants {
            let (is_prefix, selector) = grant.selector()?;
            nonempty(selector)?;
            crate::http::validate_scope(selector).map_err(|_| invalid())?;
            if !self
                .profile
                .identities
                .iter()
                .any(|identity| identity.principal == grant.principal)
                || !rows.insert((&grant.principal, is_prefix, selector, grant.action))
            {
                return Err(invalid());
            }
            if grant.action != Action::Append {
                if !grant.actors.is_empty() || !grant.payload_actors.is_empty() {
                    return Err(invalid());
                }
                continue;
            }
            if grant.actors.is_empty() {
                return Err(invalid());
            }
            let mut actors = BTreeSet::new();
            for actor in &grant.actors {
                nonempty(&actor.kind)?;
                nonempty(&actor.subject)?;
                if !actors.insert((&actor.kind, &actor.subject)) {
                    return Err(invalid());
                }
            }
            let mut pointers = BTreeSet::new();
            for actor in &grant.payload_actors {
                validate_pointer(&actor.pointer)?;
                unique_nonempty(&actor.subjects)?;
                if !pointers.insert(&actor.pointer) {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ScopeAuthorizer for CurrentGrants {
    type Error = StackError;
    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, StackError> {
        let identity = request.identity.ok_or_else(denied)?;
        if request.tenant_scope != &self.profile.tenant_scope.tuple() {
            return Err(denied());
        }
        let principal = self
            .profile
            .identities
            .iter()
            .find(|binding| {
                binding.issuer == identity.issuer
                    && binding.subject == identity.subject
                    && Some(binding.client_id.as_str()) == identity.client_id.as_deref()
            })
            .ok_or_else(denied)?;
        let required_scope = match request.action {
            ScopeAction::Read => &self.profile.action_scopes.read,
            ScopeAction::Append => &self.profile.action_scopes.append,
            ScopeAction::Administer => &self.profile.action_scopes.administer,
        };
        if !identity.scopes.contains(required_scope) {
            return Err(denied());
        }
        let scope = std::str::from_utf8(request.scope).map_err(|_| denied())?;
        // File reads never block the async worker. No admitted grants survive this request.
        let path = self.path.clone();
        let bytes = tokio::task::spawn_blocking(move || read_private(&path))
            .await
            .map_err(|_| StackError::unavailable("current resource authority unavailable"))?
            .map_err(|_| StackError::unavailable("current resource authority unavailable"))?;
        // Validate the complete current file before selecting a grant.
        let file: GrantFile = serde_json::from_slice(&bytes)
            .map_err(|_| StackError::unavailable("current resource authority unavailable"))?;
        self.validate_current(&file)
            .map_err(|_| StackError::unavailable("current resource authority unavailable"))?;
        let grant = file
            .grants
            .iter()
            .find(|grant| {
                grant.principal == principal.principal
                    && grant.admits(scope)
                    && grant.action.port() == request.action
            })
            .ok_or_else(denied)?;
        if request.action == ScopeAction::Append {
            let body = request.append_body.ok_or_else(denied)?;
            if !grant
                .actors
                .iter()
                .any(|actor| actor.kind == body.actor.kind && actor.subject == body.actor.subject)
            {
                return Err(denied());
            }
            for actor in &grant.payload_actors {
                match body.payload.pointer(&actor.pointer) {
                    None if !actor.required => {}
                    Some(value)
                        if value.as_str().is_some_and(|subject| {
                            actor.subjects.iter().any(|allowed| allowed == subject)
                        }) => {}
                    _ => return Err(denied()),
                }
            }
        }
        Ok(AuthorizedScope {
            principal: principal.principal.clone(),
            tenant_scope: request.tenant_scope.clone(),
            scope: request.scope.to_vec(),
            action: request.action,
        })
    }
}

/// Reads one private startup file through the stack-wide reader (descriptor-checked, no symlink or FIFO stall).
pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>, StackError> {
    stack_common_private_file::read_private_file(
        path,
        MAX_FILE_BYTES,
        stack_common_private_file::PrivateAccess::OwnerOnly,
    )
    .map_err(|_| invalid())
}

fn nonempty(value: &str) -> Result<(), StackError> {
    if value.trim().is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}

fn unique_nonempty(values: &[String]) -> Result<(), StackError> {
    if values.is_empty() {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for value in values {
        nonempty(value)?;
        if !seen.insert(value) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_pointer(pointer: &str) -> Result<(), StackError> {
    nonempty(pointer)?;
    if !pointer.starts_with('/') {
        return Err(invalid());
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> StackError {
    StackError::bad_request("invalid Trellis OIDC configuration or current grants")
}
fn denied() -> StackError {
    StackError::new(
        ErrorCode::new("INFRA-4030").expect("static error code is valid"),
        StatusCode::FORBIDDEN,
        "current Trellis resource grant required",
    )
}
