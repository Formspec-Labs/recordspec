//! Reads existing prepared Source bytes with current selected completion credentials.
// Rust guideline compliant 2026-02-21

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;

use crate::TrellisServiceClient;

/// Already committed protected content returned by the independently selected owner.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceContentBatchV1 {
    pub version: u8,
    pub selection: SourceContentIdentityV1,
    pub records: Vec<PreparedSourceContentRecordV1>,
    pub intake_handoffs: Vec<u8>,
    pub source_signed_tasks: Vec<u8>,
}

/// Exact native and independently selected provider identity for a committed batch.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentIdentityV1 {
    pub case_ledger_id: String,
    pub process_id: String,
    pub native_prefix_digest: [u8; 32],
    pub reserved_closeout_record_id: String,
    pub reserved_native_closeout_record_sha256: [u8; 32],
    pub provider_selection_hash: [u8; 32],
    pub native_policy_hash: [u8; 32],
    pub recipient_policy_hash: [u8; 32],
    pub workflow_url: String,
    pub workflow_version: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub environment_id: String,
    pub cell_id: String,
    pub source_id: String,
    pub service_binding_id: String,
}

/// Owning content family within the retained batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceContentRoleV1 {
    OriginalResponse,
    CorrectionResponse,
    TaskProofPackage,
}

/// Public Source occurrence selected by its owner before protection.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentOccurrenceV1 {
    pub role: SourceContentRoleV1,
    pub occurrence_event_hash: [u8; 32],
    pub response_id: Option<String>,
    pub publication_hash: [u8; 32],
    pub public_signing_policy_hash: [u8; 32],
    pub evaluation_registration_hash: [u8; 32],
}

/// First complete encrypted bytes and their admitted public associations.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceContentRecordV1 {
    pub occurrence: SourceContentOccurrenceV1,
    pub record_sha256: [u8; 32],
    pub member_content_hash: [u8; 32],
    pub protected_record_bytes: Vec<u8>,
    pub locator_cbor: Vec<u8>,
}

/// Independently admitted selection, never decoded from the returned batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentSelection {
    pub preparation_key: String,
    pub identity: SourceContentIdentityV1,
    /// Exact ordered N-1 native anchors, followed only by the selected suffix.
    pub native_prefix_event_hashes: Vec<[u8; 32]>,
    #[serde(rename = "orderedPhotoEventHashes")]
    pub photo_event_hashes: Vec<[u8; 32]>,
    pub intake_catalog_sha256: [u8; 32],
    pub task_catalog_sha256: [u8; 32],
    /// Exact public inventory admitted by the existing owning selection.
    pub record_pins: Vec<SourceContentRecordPins>,
}

/// Independently admitted public identity for one protected record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentRecordPins {
    pub role: SourceContentRoleV1,
    pub occurrence_event_hash: [u8; 32],
    pub response_id: Option<String>,
    pub source_publication_hash: [u8; 32],
    pub public_signing_policy_hash: [u8; 32],
    pub evaluation_registration_hash: [u8; 32],
    pub record_sha256: [u8; 32],
    pub member_content_hash: [u8; 32],
    pub locator_sha256: [u8; 32],
}

/// Read-response ceiling shared with the owning encoded prepared batch.
pub const MAX_PREPARED_SOURCE_CONTENT_BYTES: usize = 16 * 1024 * 1024;

impl TrellisServiceClient {
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

    /// Reads only the already committed batch from the fixed owning service.
    ///
    /// The caller supplies a locator, never provider URL, authority, or recipient
    /// assertions. The server owner must decode and independently admit the closed
    /// response. This method performs no preparation or object publication.
    ///
    /// # Errors
    /// Refuses invalid origin, absent current provider, invalid caller credential,
    /// non-success responses, redirects, timeout, or encoded response overflow.
    pub async fn prepared_source_content_bytes(
        &self,
        tenant: &TenantScope,
        case_ledger_id: &str,
        preparation_key: &str,
        person_authorization: &str,
    ) -> Result<Vec<u8>, StackError> {
        crate::validate_completion_caller_authorization(person_authorization)?;
        self.validate_current_completion_origin()?;
        if [case_ledger_id, preparation_key]
            .iter()
            .any(|text| text.is_empty() || text.len() > 256 || text.chars().any(char::is_control))
        {
            return Err(StackError::bad_request("prepared Source locator invalid"));
        }
        let path = format!(
            "/api/v1/internal/completion-export-content/{}/{}",
            crate::encode_path_segment(case_ledger_id),
            crate::encode_path_segment(preparation_key)
        );
        let fail = || StackError::unavailable("prepared Source content GET refused");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut person =
                reqwest::header::HeaderValue::from_str(person_authorization).map_err(|_| fail())?;
            person.set_sensitive(true);
            let mut request = self
                .request(reqwest::Method::GET, &path, tenant)
                .await
                .map_err(|_| fail())?
                .header(crate::COMPLETION_CALLER_AUTHORIZATION_HEADER, person)
                .build()
                .map_err(|_| fail())?;
            request.headers_mut().remove("x-wos-workspace-id");
            request.headers_mut().remove("x-wos-environment-id");
            let mut response = self.http.execute(request).await.map_err(|_| fail())?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .content_length()
                    .is_some_and(|size| size > MAX_PREPARED_SOURCE_CONTENT_BYTES as u64)
            {
                return Err(fail());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| fail())? {
                if chunk.len() > MAX_PREPARED_SOURCE_CONTENT_BYTES - bytes.len() {
                    return Err(fail());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| fail())?
    }
}

/// Actual prefix and original closeout body for the owning Source-only callback.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentOnlySelectionRequest {
    pub version: u8,
    pub tenant: crate::completion_selection::CompletionTenant,
    pub ledger_scope: String,
    pub preparation_key: String,
    pub prefix: Vec<crate::completion_selection::CompletionPrefixRow>,
    pub append_body: crate::SubstrateAppendBody,
}
impl std::fmt::Debug for SourceContentOnlySelectionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceContentOnlySelectionRequest")
            .finish_non_exhaustive()
    }
}
impl SourceContentOnlySelectionRequest {
    /// Constructs the bounded Source-only branch without formal completion or trust pins.
    ///
    /// # Errors
    /// Refuses invalid scope, locator, closeout body, or protected prefix budget.
    pub fn from_prefix(
        tenant: &TenantScope,
        scope: &str,
        key: &str,
        append_body: &crate::SubstrateAppendBody,
        prefix: &[trellis_types::StoredEvent],
    ) -> Result<Self, StackError> {
        append_body.validate()?;
        trellis_types::completion_selection::completion_selection_prefix_digest(
            scope.as_bytes(),
            prefix,
        )
        .map_err(|_| StackError::bad_request("Source selection prefix invalid"))?;
        if key.is_empty()
            || key.len() > 256
            || !key.is_ascii()
            || key
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(StackError::bad_request(
                "Source preparation locator invalid",
            ));
        }
        for field in [
            &tenant.tenant,
            &tenant.workspace,
            &tenant.environment,
            &tenant.cell,
        ] {
            if field.trim().is_empty() || field.len() > 1024 {
                return Err(StackError::bad_request("Source selection tenant invalid"));
            }
        }
        Ok(Self {
            version: 1,
            tenant: tenant.into(),
            ledger_scope: scope.into(),
            preparation_key: key.into(),
            append_body: append_body.clone(),
            prefix: prefix
                .iter()
                .map(|event| crate::completion_selection::CompletionPrefixRow {
                    sequence: event.sequence(),
                    canonical_event: event.canonical_event().to_vec(),
                    signed_event: event.signed_event().to_vec(),
                })
                .collect(),
        })
    }

    /// Reconstructs the exact transported prefix within maintained bounds.
    ///
    /// # Errors
    /// Refuses unsupported versions or prefix byte/count/scope bounds.
    pub fn prefix_events(&self) -> Result<Vec<trellis_types::StoredEvent>, StackError> {
        if self.version != 1 {
            return Err(StackError::bad_request(
                "Source selection request version invalid",
            ));
        }
        trellis_types::completion_selection::completion_scope_bounds(self.ledger_scope.as_bytes())
            .map_err(|_| StackError::bad_request("Source selection scope invalid"))?;
        trellis_types::completion_selection::completion_prefix_byte_bounds(
            self.prefix
                .iter()
                .map(|row| (row.canonical_event.as_slice(), row.signed_event.as_slice())),
        )
        .map_err(|_| StackError::bad_request("Source selection prefix bounds invalid"))?;
        Ok(self
            .prefix
            .iter()
            .map(|row| {
                trellis_types::StoredEvent::new(
                    self.ledger_scope.as_bytes().to_vec(),
                    row.sequence,
                    row.canonical_event.clone(),
                    row.signed_event.clone(),
                )
            })
            .collect())
    }

    /// Checks complete request bindings before allocating encoded transport bytes.
    ///
    /// # Errors
    /// Refuses malformed fields or encoded overflow.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, StackError> {
        let tenant = TenantScope {
            tenant: self.tenant.tenant.clone(),
            workspace: self.tenant.workspace.clone(),
            environment: self.tenant.environment.clone(),
            cell: self.tenant.cell.clone(),
        };
        Self::from_prefix(
            &tenant,
            &self.ledger_scope,
            &self.preparation_key,
            &self.append_body,
            &self.prefix_events()?,
        )?;
        struct Bound(usize);
        impl std::io::Write for Bound {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|n| *n <= crate::completion_selection::MAX_SELECTION_REQUEST_BYTES)
                    .ok_or_else(|| std::io::Error::other("Source selection encoded limit"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(&mut Bound(0), self)
            .map_err(|_| StackError::bad_request("Source selection encoded limit"))?;
        serde_json::to_vec(self)
            .map_err(|_| StackError::bad_request("Source selection encoding invalid"))
    }
}

/// Current owning selection with exact request correspondence and no credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentOnlySelectionResponse {
    pub version: u8,
    pub tenant: crate::completion_selection::CompletionTenant,
    pub ledger_scope: String,
    pub preparation_key: String,
    pub prefix_digest: [u8; 32],
    pub selected: SourceContentSelection,
}
impl SourceContentOnlySelectionResponse {
    /// Binds the reply to this actual prefix and scoped locator without granting authority.
    ///
    /// # Errors
    /// Refuses substituted tenant, scope, prefix or locator.
    pub fn validate_for_request(
        &self,
        request: &SourceContentOnlySelectionRequest,
    ) -> Result<(), StackError> {
        let digest = trellis_types::completion_selection::completion_selection_prefix_digest(
            request.ledger_scope.as_bytes(),
            &request.prefix_events()?,
        )
        .map_err(|_| StackError::bad_request("Source selection prefix invalid"))?;
        if self.version != 1
            || self.tenant != request.tenant
            || self.ledger_scope != request.ledger_scope
            || self.preparation_key != request.preparation_key
            || self.prefix_digest != digest
            || self.selected.preparation_key != request.preparation_key
        {
            return Err(StackError::conflict(
                "Source owning selection reply differs",
            ));
        }
        Ok(())
    }
}

/// Shared owning selection name used by the WOS read-only callback.
pub type SourceContentSelectionV1 = SourceContentSelection;
/// Existing internal callback selected by the owning WOS service.
pub const SOURCE_CONTENT_SELECTION_PATH: &str =
    "/api/v1/internal/completion-source-content-selection";
/// Request-local prepared locator; this header grants no authority.
pub const SOURCE_CONTENT_PREPARATION_KEY_HEADER: &str = "x-wos-source-content-preparation-key";
