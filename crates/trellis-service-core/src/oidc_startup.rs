//! Composes current provider verification and exact deployment resource grants.
//!
//! Grants are `(principal, scope, ledger or ledger prefix, action)` (ADR 0168 §1.6). They are
//! read and validated once at startup and held in memory, indexed so a request finds its grant
//! in O(log G) per candidate prefix rather than re-reading and re-validating the whole file on
//! every call (audit #25). A grant change is a file change and a restart, as a new scope is
//! (ADR 0168 §3.3). A prefix grant names a ledger prefix inside one scope, so it can never reach
//! another tenant's ledgers: the scope key is part of every ledger scope it admits.
// Rust guideline compliant 2026-02-21

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use axum::http::StatusCode;
use serde::Deserialize;
use stack_common_auth::VerifiedAccessIdentity;
use stack_common_auth::{
    AccessTokenVerifier,
    oidc::{
        AccessTokenProfile, OidcAccessTokenVerifier, OidcCurrentAuthority, OidcDependencies,
        OidcTrust, ReqwestAuthHttpClient, StaticClientSecret, SystemAuthClock, TransportPolicy,
    },
};
use stack_common_error::{ErrorCode, StackError};
use stack_common_scope::{DeploymentConfig, ScopeConfig, ScopeKey};
use trellis_server_ports::{
    AuthorizedScope, LedgerScope, ScopeAction, ScopeAuthorization, ScopeAuthorizer,
    validate_ledger_id,
};

use crate::TrellisServerState;

// Operator profiles and grants are small. Bound reads, including files growing after metadata.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) struct StartupAuth {
    verifier: Arc<dyn AccessTokenVerifier>,
    authorizer: Arc<dyn ScopeAuthorizer<Error = StackError>>,
    attachment_recipients: Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>,
}

impl StartupAuth {
    pub(crate) fn from_env(deployment: &DeploymentConfig) -> Result<Self, StackError> {
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
            deployment,
        )
    }

    pub(crate) fn load(
        path: &Path,
        dependencies: OidcDependencies,
        deployment: &DeploymentConfig,
    ) -> Result<Self, StackError> {
        let served = crate::state::deployment_keys(deployment)?;
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
        let attachment_recipients = profile.attachment_selector(&served)?;
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
        let grants: GrantFile =
            serde_json::from_slice(&read_private(&parent.join(&profile.grants_file))?)
                .map_err(|_| invalid())?;
        let authorizer = CurrentGrants::index(profile, &grants, &served)?;
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
    identities: Vec<Identity>,
    action_scopes: ActionScopes,
    #[serde(default, deserialize_with = "deserialize_attachment_selection")]
    accepted_attachment_recipients: Option<Vec<AttachmentSelection>>,
}

// Selected custody names a served scope, a ledger in it and an admitted principal.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentSelection {
    principal: String,
    /// The deployment scope the ledger lives under.
    scope: ScopeConfig,
    /// The ledger id within that scope.
    ledger: String,
    recipients: Vec<AttachmentRecipient>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentRecipient {
    id: String,
    public_key: [u8; 32],
    operator_held: bool,
}

/// Recipients by `(principal, ledger)`.
struct ScopedAttachmentRecipients {
    rows: BTreeMap<(String, LedgerScope), Vec<crate::ExternalAttachmentRecipient>>,
}

#[async_trait]
impl crate::ExternalAttachmentRecipientSelector for ScopedAttachmentRecipients {
    async fn select(
        &self,
        permit: &AuthorizedScope,
        _descriptor: &serde_json::Value,
    ) -> Result<Vec<crate::ExternalAttachmentRecipient>, StackError> {
        if permit.action != ScopeAction::Append {
            return Err(attachment_denied());
        }
        self.rows
            .get(&(permit.principal.clone(), permit.scope.clone()))
            .cloned()
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
        served: &[ScopeKey],
    ) -> Result<Option<Arc<dyn crate::ExternalAttachmentRecipientSelector>>, StackError> {
        let Some(selections) = &self.accepted_attachment_recipients else {
            return Ok(None);
        };
        // Operator profiles fit the existing 1 MiB private-file bound; cap row work too.
        if selections.is_empty() || selections.len() > 1024 {
            return Err(attachment_invalid());
        }
        let mut rows = BTreeMap::new();
        for selection in selections {
            let scope_key =
                served_key(&selection.scope, served).map_err(|_| attachment_invalid())?;
            let ledger = LedgerScope::under(scope_key, &selection.ledger)
                .map_err(|_| attachment_invalid())?;
            let row = (selection.principal.clone(), ledger);
            if !self
                .identities
                .iter()
                .any(|identity| identity.principal == selection.principal)
                || rows.contains_key(&row)
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
            rows.insert(row, recipients);
        }
        Ok(Some(Arc::new(ScopedAttachmentRecipients { rows })))
    }

    fn validate(&self) -> Result<(), StackError> {
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
    grants: Vec<Grant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Action {
    Read,
    Append,
    Administer,
}

impl Action {
    fn of(action: ScopeAction) -> Self {
        match action {
            ScopeAction::Read => Self::Read,
            ScopeAction::Append => Self::Append,
            ScopeAction::Administer => Self::Administer,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    principal: String,
    /// The deployment scope the grant holds in; every ledger it admits lies under it.
    scope: ScopeConfig,
    /// Exactly one of `ledger` (one ledger id) and `ledgerPrefix` (every ledger id it starts).
    #[serde(default)]
    ledger: Option<String>,
    /// A ledger-id prefix ending in `.` or `_`, so it stops at a component boundary of a ledger
    /// id (`<namespace>_<type>_<id>`) and cannot match half a component.
    #[serde(default)]
    ledger_prefix: Option<String>,
    action: Action,
    #[serde(default)]
    actors: Vec<Actor>,
    #[serde(default)]
    payload_actors: Vec<PayloadActor>,
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

/// What an admitting grant further requires of an append body.
#[derive(Default)]
struct Rule {
    actors: BTreeSet<(String, String)>,
    payload_actors: Vec<PayloadActor>,
}

/// One principal's grants for one scope and action.
#[derive(Default)]
struct Selectors {
    exact: BTreeMap<String, Rule>,
    prefixes: BTreeMap<String, Rule>,
}

impl Selectors {
    /// The most specific rule admitting `ledger_id`: its exact grant, else its longest prefix
    /// grant. A prefix ends in `.` or `_`, so only those positions are looked up: O(k log G) for
    /// k boundaries in the id.
    fn admitting(&self, ledger_id: &str) -> Option<&Rule> {
        self.exact.get(ledger_id).or_else(|| {
            ledger_id
                .char_indices()
                .rev()
                .filter(|(_, c)| matches!(c, '.' | '_'))
                .find_map(|(index, _)| self.prefixes.get(&ledger_id[..=index]))
        })
    }
}

/// The deployment's grants, validated once at startup and held in memory.
struct CurrentGrants {
    profile: Profile,
    /// `(issuer, subject, client) → principal`.
    principals: BTreeMap<(String, String, String), String>,
    /// Each principal's bound scopes, sorted: what `VerifiedBinding::select` chooses among.
    bound: BTreeMap<String, Vec<ScopeKey>>,
    /// `(scope key, action) → principal → selectors`.
    rules: BTreeMap<(ScopeKey, Action), BTreeMap<String, Selectors>>,
}

/// The key of a configured scope the deployment serves.
fn served_key(scope: &ScopeConfig, served: &[ScopeKey]) -> Result<ScopeKey, StackError> {
    let key = scope.key().map_err(|_| invalid())?;
    served
        .binary_search(&key)
        .map(|_| key)
        .map_err(|_| invalid())
}

impl CurrentGrants {
    fn index(profile: Profile, file: &GrantFile, served: &[ScopeKey]) -> Result<Self, StackError> {
        let principals = profile
            .identities
            .iter()
            .map(|identity| {
                (
                    (
                        identity.issuer.clone(),
                        identity.subject.clone(),
                        identity.client_id.clone(),
                    ),
                    identity.principal.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let known: BTreeSet<&str> = profile
            .identities
            .iter()
            .map(|identity| identity.principal.as_str())
            .collect();
        let mut bound: BTreeMap<String, Vec<ScopeKey>> = BTreeMap::new();
        let mut rules: BTreeMap<(ScopeKey, Action), BTreeMap<String, Selectors>> = BTreeMap::new();
        for grant in &file.grants {
            if !known.contains(grant.principal.as_str()) {
                return Err(invalid());
            }
            let scope_key = served_key(&grant.scope, served)?;
            let rule = Self::rule(grant)?;
            let selectors = rules
                .entry((scope_key, grant.action))
                .or_default()
                .entry(grant.principal.clone())
                .or_default();
            let fresh = match (&grant.ledger, &grant.ledger_prefix) {
                (Some(ledger), None) => {
                    validate_ledger_id(ledger).map_err(|_| invalid())?;
                    selectors.exact.insert(ledger.clone(), rule).is_none()
                }
                (None, Some(prefix)) if prefix.ends_with(['.', '_']) => {
                    validate_ledger_id(prefix).map_err(|_| invalid())?;
                    selectors.prefixes.insert(prefix.clone(), rule).is_none()
                }
                _ => return Err(invalid()),
            };
            // A selector granted twice for one principal, scope and action is ambiguous.
            if !fresh {
                return Err(invalid());
            }
            bound
                .entry(grant.principal.clone())
                .or_default()
                .push(scope_key);
        }
        for keys in bound.values_mut() {
            keys.sort();
            keys.dedup();
        }
        Ok(Self {
            profile,
            principals,
            bound,
            rules,
        })
    }

    fn rule(grant: &Grant) -> Result<Rule, StackError> {
        if grant.action != Action::Append {
            if !grant.actors.is_empty() || !grant.payload_actors.is_empty() {
                return Err(invalid());
            }
            return Ok(Rule::default());
        }
        if grant.actors.is_empty() {
            return Err(invalid());
        }
        let mut actors = BTreeSet::new();
        for actor in &grant.actors {
            nonempty(&actor.kind)?;
            nonempty(&actor.subject)?;
            if !actors.insert((actor.kind.clone(), actor.subject.clone())) {
                return Err(invalid());
            }
        }
        let mut pointers = BTreeSet::new();
        let mut payload_actors = Vec::with_capacity(grant.payload_actors.len());
        for actor in &grant.payload_actors {
            validate_pointer(&actor.pointer)?;
            unique_nonempty(&actor.subjects)?;
            if !pointers.insert(&actor.pointer) {
                return Err(invalid());
            }
            payload_actors.push(PayloadActor {
                pointer: actor.pointer.clone(),
                required: actor.required,
                subjects: actor.subjects.clone(),
            });
        }
        Ok(Rule {
            actors,
            payload_actors,
        })
    }

    fn principal(&self, identity: &VerifiedAccessIdentity) -> Result<&str, StackError> {
        let client = identity.client_id.clone().ok_or_else(denied)?;
        self.principals
            .get(&(identity.issuer.clone(), identity.subject.clone(), client))
            .map(String::as_str)
            .ok_or_else(denied)
    }
}

#[async_trait]
impl ScopeAuthorizer for CurrentGrants {
    type Error = StackError;

    fn bound_scopes(
        &self,
        identity: Option<&VerifiedAccessIdentity>,
    ) -> Result<Option<Vec<ScopeKey>>, StackError> {
        let principal = self.principal(identity.ok_or_else(denied)?)?;
        Ok(Some(self.bound.get(principal).cloned().unwrap_or_default()))
    }

    async fn authorize(
        &self,
        request: &ScopeAuthorization<'_>,
    ) -> Result<AuthorizedScope, StackError> {
        let identity = request.identity.ok_or_else(denied)?;
        let principal = self.principal(identity)?;
        let required_scope = match request.action {
            ScopeAction::Read => &self.profile.action_scopes.read,
            ScopeAction::Append => &self.profile.action_scopes.append,
            ScopeAction::Administer => &self.profile.action_scopes.administer,
        };
        if !identity.scopes.contains(required_scope) {
            return Err(denied());
        }
        let rule = self
            .rules
            .get(&(*request.scope.key(), Action::of(request.action)))
            .and_then(|principals| principals.get(principal))
            .and_then(|selectors| selectors.admitting(request.scope.ledger_id()))
            .ok_or_else(denied)?;
        if request.action == ScopeAction::Append {
            let body = request.append_body.ok_or_else(denied)?;
            if !rule
                .actors
                .contains(&(body.actor.kind.clone(), body.actor.subject.clone()))
            {
                return Err(denied());
            }
            for actor in &rule.payload_actors {
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
            principal: principal.to_owned(),
            scope: request.scope.clone(),
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
