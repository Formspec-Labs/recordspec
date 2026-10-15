//! Reads existing prepared Source bytes with current selected completion credentials.
// Rust guideline compliant 2026-02-21

use serde::{Deserialize, Serialize};
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;

use crate::TrellisServiceClient;

/// Encodes byte payloads as standard base64 text. JSON number arrays expand
/// protected ciphertext about 3.6x, which pushed real batches past the 16 MiB bound.
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Already committed protected content returned by the independently selected owner.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceContentBatchV1 {
    pub version: u8,
    pub selection: SourceContentIdentityV1,
    pub records: Vec<PreparedSourceContentRecordV1>,
    #[serde(with = "base64_bytes")]
    pub intake_handoffs: Vec<u8>,
    #[serde(with = "base64_bytes")]
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
    /// WOS-derived digest of the canonical sorted actual recipient IDs and public keys.
    ///
    /// This required identity field distinguishes key rotation under the same
    /// recipient policy. Trellis carries and compares the owning digest; it
    /// neither computes the recipient-set algorithm nor grants read authority.
    pub recipient_set_sha256: [u8; 32],
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
    #[serde(with = "base64_bytes")]
    pub protected_record_bytes: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub locator_cbor: Vec<u8>,
}

/// Independently admitted selection, never decoded from the returned batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceContentSelection {
    pub preparation_key: String,
    pub identity: SourceContentIdentityV1,
    /// Complete ordered authenticated prefix before selected photos and closeout.
    /// Includes independently bound WOS and Source events in their original order.
    /// `identity.native_prefix_digest` binds this entire prefix; the selected photo
    /// events and reserved closeout follow it.
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

/// Inner bound for each owning WOS Source callback handler (selection and read).
///
/// Sized from a real-size D1 case: each callback reads the full case snapshot
/// twice (~5.5 s each) and validates the retained batch once. The handler bound
/// stays below the callback transport bound so the owner's refusal arrives first.
pub const SOURCE_CONTENT_OWNER_HANDLER_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(45);

/// Default transport budget for independently selected Source callbacks.
///
/// The selected callback client uses this bound for both HTTP and its complete
/// callback wait, including current-token acquisition and decoding.
pub const DEFAULT_SOURCE_CONTENT_CALLBACK_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Default whole-append budget selected by the owning Source export caller.
///
/// Reserves two callbacks plus ten seconds for admission and publication.
/// Configure the caller through existing TrellisServiceClientConfig::with_timeout;
/// ordinary defaults remain unchanged.
pub const DEFAULT_SOURCE_CONTENT_APPEND_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(130);

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
        tokio::time::timeout(self.config.timeout, async {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(payload: usize) -> PreparedSourceContentBatchV1 {
        let identity = SourceContentIdentityV1 {
            case_ledger_id: "case".into(),
            process_id: "process".into(),
            native_prefix_digest: [1; 32],
            reserved_closeout_record_id: "closeout".into(),
            reserved_native_closeout_record_sha256: [2; 32],
            provider_selection_hash: [3; 32],
            native_policy_hash: [4; 32],
            recipient_policy_hash: [5; 32],
            recipient_set_sha256: [6; 32],
            workflow_url: "urn:test:workflow".into(),
            workflow_version: "1".into(),
            tenant_id: "tenant".into(),
            workspace_id: "workspace".into(),
            environment_id: "environment".into(),
            cell_id: "cell".into(),
            source_id: "source".into(),
            service_binding_id: "binding".into(),
        };
        PreparedSourceContentBatchV1 {
            version: 1,
            selection: identity,
            records: vec![PreparedSourceContentRecordV1 {
                occurrence: SourceContentOccurrenceV1 {
                    role: SourceContentRoleV1::TaskProofPackage,
                    occurrence_event_hash: [7; 32],
                    response_id: None,
                    publication_hash: [8; 32],
                    public_signing_policy_hash: [9; 32],
                    evaluation_registration_hash: [10; 32],
                },
                record_sha256: [11; 32],
                member_content_hash: [12; 32],
                protected_record_bytes: (0..payload).map(|i| (i * 131 % 256) as u8).collect(),
                locator_cbor: vec![0xa0],
            }],
            intake_handoffs: vec![0x80],
            source_signed_tasks: vec![0x80],
        }
    }

    #[test]
    fn byte_fields_round_trip_as_compact_base64_text() {
        let original = batch(8 * 1024 * 1024);
        let encoded = serde_json::to_vec(&original).unwrap();
        // Ciphertext near the 8 MiB package bound must fit the 16 MiB batch bound.
        assert!(encoded.len() < MAX_PREPARED_SOURCE_CONTENT_BYTES);
        assert_eq!(serde_json::from_slice::<PreparedSourceContentBatchV1>(&encoded).unwrap(), original);
        let value = serde_json::to_value(&original).unwrap();
        assert!(value["records"][0]["protectedRecordBytes"].is_string());
        assert_eq!(serde_json::from_value::<PreparedSourceContentBatchV1>(value).unwrap(), original);
    }

    #[test]
    fn non_base64_byte_text_is_refused() {
        let mut value = serde_json::to_value(batch(4)).unwrap();
        value["intakeHandoffs"] = serde_json::json!("not base64!");
        assert!(serde_json::from_value::<PreparedSourceContentBatchV1>(value).is_err());
    }
}
