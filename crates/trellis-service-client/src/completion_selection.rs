// Rust guideline compliant 2026-02-21
//! Closed completion selection messages for an independently authorized owning service.
//!
//! These messages contain no caller-selected case, principal, bearer, or grant.
//! The owning service derives the case and checks current permissions. Echoed
//! byte bindings protect correspondence; they establish no signature authority.

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use trellis_types::{StoredEvent, completion_selection::completion_selection_prefix_digest};

use crate::CompletionRequest;

/// Maximum encoded selection request, including JSON byte-array expansion.
pub const MAX_SELECTION_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Maximum complete selection response before deserialization.
pub const MAX_SELECTION_RESPONSE_BYTES: usize = 64 * 1024;

/// Closed deployment tuple repeated in the protected request and reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionTenant {
    pub tenant: String,
    pub workspace: String,
    pub environment: String,
    pub cell: String,
}

impl From<&TenantScope> for CompletionTenant {
    fn from(value: &TenantScope) -> Self {
        Self {
            tenant: value.tenant.clone(),
            workspace: value.workspace.clone(),
            environment: value.environment.clone(),
            cell: value.cell.clone(),
        }
    }
}

fn validate_tenant_fields(tenant: [&str; 4]) -> Result<(), StackError> {
    if tenant
        .iter()
        .any(|value| value.trim().is_empty() || value.len() > 1024)
    {
        return Err(StackError::bad_request(
            "completion selection tenant is invalid",
        ));
    }
    Ok(())
}

/// Exact protected event bytes in their retained order.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionPrefixRow {
    pub sequence: u64,
    pub canonical_event: Vec<u8>,
    pub signed_event: Vec<u8>,
}

impl std::fmt::Debug for CompletionPrefixRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionPrefixRow")
            .finish_non_exhaustive()
    }
}

/// Finite selection trigger and exact protected prefix, without credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSelectionRequest {
    pub version: u8,
    pub tenant: CompletionTenant,
    pub ledger_scope: String,
    pub trigger: CompletionRequest,
    pub prefix: Vec<CompletionPrefixRow>,
    pub prefix_digest: [u8; 32],
}

impl std::fmt::Debug for CompletionSelectionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionSelectionRequest")
            .finish_non_exhaustive()
    }
}

impl CompletionSelectionRequest {
    /// Constructs a bounded request from retained bytes and the admitted tenant.
    ///
    /// Structural event validation and archive authority remain independent checks.
    ///
    /// # Errors
    /// Refuses invalid triggers, deployment fields, scopes, or prefix budgets.
    pub fn from_prefix(
        tenant: &TenantScope,
        ledger_scope: &str,
        trigger: &CompletionRequest,
        prefix: &[StoredEvent],
    ) -> Result<Self, StackError> {
        trigger.validate()?;
        validate_tenant_fields([
            &tenant.tenant,
            &tenant.workspace,
            &tenant.environment,
            &tenant.cell,
        ])?;
        let prefix_digest = completion_selection_prefix_digest(ledger_scope.as_bytes(), prefix)
            .map_err(|_| StackError::bad_request("completion selection prefix is invalid"))?;
        Ok(Self {
            version: 1,
            tenant: tenant.into(),
            ledger_scope: ledger_scope.into(),
            trigger: trigger.clone(),
            prefix_digest,
            prefix: prefix
                .iter()
                .map(|event| CompletionPrefixRow {
                    sequence: event.sequence(),
                    canonical_event: event.canonical_event().to_vec(),
                    signed_event: event.signed_event().to_vec(),
                })
                .collect(),
        })
    }

    /// Encodes the closed request within the agreed transport budget.
    ///
    /// # Errors
    /// Refuses changed bindings, unsupported versions, or excessive JSON size.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, StackError> {
        if self.version != 1 {
            return Err(invalid());
        }
        self.trigger.validate()?;
        validate_tenant_fields([
            &self.tenant.tenant,
            &self.tenant.workspace,
            &self.tenant.environment,
            &self.tenant.cell,
        ])?;
        trellis_types::completion_selection::completion_scope_bounds(self.ledger_scope.as_bytes())
            .map_err(|_| invalid())?;
        trellis_types::completion_selection::completion_prefix_byte_bounds(
            self.prefix
                .iter()
                .map(|row| (row.canonical_event.as_slice(), row.signed_event.as_slice())),
        )
        .map_err(|_| invalid())?;
        let events = self
            .prefix
            .iter()
            .map(|row| {
                StoredEvent::new(
                    self.ledger_scope.as_bytes().to_vec(),
                    row.sequence,
                    row.canonical_event.clone(),
                    row.signed_event.clone(),
                )
            })
            .collect::<Vec<_>>();
        let tenant = TenantScope {
            tenant: self.tenant.tenant.clone(),
            workspace: self.tenant.workspace.clone(),
            environment: self.tenant.environment.clone(),
            cell: self.tenant.cell.clone(),
        };
        let checked = Self::from_prefix(&tenant, &self.ledger_scope, &self.trigger, &events)?;
        if checked.prefix_digest != self.prefix_digest {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > MAX_SELECTION_REQUEST_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
}

fn invalid() -> StackError {
    StackError::bad_request("completion selection request is invalid")
}

/// Owning disclosure label for one retained signing event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectionSignerLabel {
    pub signing_event: [u8; 32],
    pub display_name: String,
    pub display_role: Option<String>,
}

/// Independently selected public operator authority required by the owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectionAttestor {
    pub authority: String,
    pub authority_class: String,
    pub public_key: [u8; 32],
}

/// Owning facts from one current, complete, consistently read case snapshot.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSelection {
    pub selection_revision: [u8; 32],
    pub case_ref: String,
    pub workflow_ref: String,
    pub workflow_status: String,
    pub completed_at: (u64, u32),
    pub impact_level: Option<String>,
    pub signer_labels: Vec<SelectionSignerLabel>,
    pub required_attestors: Vec<SelectionAttestor>,
}

/// Exact request binding plus a case derived by the independently trusted owner.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSelectionResponse {
    pub version: u8,
    pub tenant: CompletionTenant,
    pub ledger_scope: String,
    pub trigger: CompletionRequest,
    pub prefix_digest: [u8; 32],
    pub case_ledger_id: String,
    pub selected: CompletionSelection,
}

impl std::fmt::Debug for SelectionSignerLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionSignerLabel")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for CompletionSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionSelection")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for CompletionSelectionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionSelectionResponse")
            .finish_non_exhaustive()
    }
}

impl CompletionSelectionResponse {
    /// Checks exact request echoes and the owner's raw case identity relationship.
    ///
    /// The configured owner establishes legal case association and current grants.
    /// This check alone does not authenticate a response from an arbitrary server.
    ///
    /// # Errors
    /// Refuses changed request echoes, case identities, timestamps, or disclosure fields.
    pub fn validate_for_request(
        &self,
        request: &CompletionSelectionRequest,
    ) -> Result<(), StackError> {
        let fail = || StackError::unavailable("completion selection response refused");
        if self.version != 1
            || self.tenant != request.tenant
            || self.ledger_scope != request.ledger_scope
            || self.prefix_digest != request.prefix_digest
            || self.trigger.idempotency_key != request.trigger.idempotency_key
            || self.trigger.certificate_id != request.trigger.certificate_id
            || self.trigger.expected_head != request.trigger.expected_head
            || self.trigger.signing_events != request.trigger.signing_events
            || self.case_ledger_id.trim().is_empty()
            || self.case_ledger_id.len() > 1024
            || self.selected.case_ref != self.case_ledger_id
            || self.selected.completed_at.1 >= 1_000_000_000
            || self.selected.workflow_ref.trim().is_empty()
            || self.selected.workflow_ref.len() > 1024
            || self.selected.workflow_status.trim().is_empty()
            || self.selected.workflow_status.len() > 1024
            || self.selected.signer_labels.len() != request.trigger.signing_events.len()
            || self.selected.required_attestors.is_empty()
            || self.selected.required_attestors.len() > 8
            || self
                .selected
                .impact_level
                .as_ref()
                .is_some_and(|v| v.trim().is_empty() || v.len() > 1024)
        {
            return Err(fail());
        }
        let mut labels = std::collections::BTreeSet::new();
        for (row, signing_event) in self
            .selected
            .signer_labels
            .iter()
            .zip(&request.trigger.signing_events)
        {
            if &row.signing_event != signing_event
                || !labels.insert(row.signing_event)
                || row.display_name.trim().is_empty()
                || row.display_name.len() > 1024
                || row
                    .display_role
                    .as_ref()
                    .is_some_and(|v| v.trim().is_empty() || v.len() > 1024)
            {
                return Err(fail());
            }
        }
        let mut authorities = std::collections::BTreeSet::new();
        for row in &self.selected.required_attestors {
            if row.authority.trim().is_empty()
                || row.authority.len() > 1024
                || !matches!(row.authority_class.as_str(), "prior" | "new")
                || !authorities.insert(&row.authority)
            {
                return Err(fail());
            }
        }
        Ok(())
    }
}

impl crate::TrellisServiceClient {
    pub(crate) fn validate_current_completion_origin(&self) -> Result<(), StackError> {
        let origin = reqwest::Url::parse(&self.config.endpoint).map_err(|_| {
            StackError::unavailable("completion selection origin or provider is invalid")
        })?;
        let local = origin
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if self.token_provider.is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !(origin.scheme() == "https" || (origin.scheme() == "http" && local))
        {
            return Err(StackError::unavailable(
                "completion selection origin or provider is invalid",
            ));
        }
        Ok(())
    }
}

impl crate::TrellisServiceClient {
    /// Requests selection from the fixed configured owning-service origin.
    ///
    /// Requires the independently configured current machine provider. The person
    /// credential is borrowed only for this request, never serialized or retained.
    /// The five-second total deadline includes token acquisition and streamed reply.
    ///
    /// # Errors
    /// Refuses unsupported origins, invalid or oversized messages, missing providers,
    /// redirects, timeouts, upstream refusal, or any changed reply binding.
    pub async fn completion_selection(
        &self,
        body: &CompletionSelectionRequest,
        person_authorization: &str,
    ) -> Result<CompletionSelectionResponse, StackError> {
        crate::validate_completion_caller_authorization(person_authorization)?;
        self.validate_current_completion_origin()?;
        let bytes = body.to_json_bytes()?;
        let tenant = TenantScope {
            tenant: body.tenant.tenant.clone(),
            workspace: body.tenant.workspace.clone(),
            environment: body.tenant.environment.clone(),
            cell: body.tenant.cell.clone(),
        };
        let fail = || StackError::unavailable("completion selection response refused");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut person =
                reqwest::header::HeaderValue::from_str(person_authorization).map_err(|_| fail())?;
            person.set_sensitive(true);
            let request = self
                .request(
                    reqwest::Method::POST,
                    "/api/v1/completion/selections",
                    &tenant,
                )
                .await
                .map_err(|_| fail())?;
            let mut request = request
                .header(crate::COMPLETION_CALLER_AUTHORIZATION_HEADER, person)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes)
                .build()
                .map_err(|_| fail())?;
            // WOS derives its fixed workspace/environment from authenticated deployment;
            // even matching override headers are refused by TenantBinding::derive.
            request.headers_mut().remove("x-wos-workspace-id");
            request.headers_mut().remove("x-wos-environment-id");
            let mut response = self.http.execute(request).await.map_err(|_| fail())?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .content_length()
                    .is_some_and(|n| n > MAX_SELECTION_RESPONSE_BYTES as u64)
            {
                return Err(fail());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| fail())? {
                if chunk.len() > MAX_SELECTION_RESPONSE_BYTES - bytes.len() {
                    return Err(fail());
                }
                bytes.extend_from_slice(&chunk);
            }
            let selected: CompletionSelectionResponse =
                serde_json::from_slice(&bytes).map_err(|_| fail())?;
            selected.validate_for_request(body)?;
            Ok(selected)
        })
        .await
        .map_err(|_| fail())?
    }
}
