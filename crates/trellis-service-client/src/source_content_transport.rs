//! Current-purpose transport for the owning Source-only selection callback.
// Rust guideline compliant 2026-02-21

use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;

use crate::{
    TrellisServiceClient,
    source_content::{
        SOURCE_CONTENT_SELECTION_PATH, SourceContentOnlySelectionRequest,
        SourceContentOnlySelectionResponse,
    },
};

// Supports all 32 occurrence pin sets and 256 native anchors without raising
// the existing formal completion response limit or the prepared-batch ceiling.
const MAX_SOURCE_SELECTION_RESPONSE_BYTES: usize = 1024 * 1024;

impl TrellisServiceClient {
    /// Selects current native and Source pins from the fixed owning callback.
    ///
    /// Credentials remain headers. The closed body includes no public policy,
    /// provider URL, recipient assertion, or formal CompletionRequest.
    ///
    /// # Errors
    /// Refuses invalid origin/provider, changed request, missing current authority,
    /// redirect, timeout, oversized response, or an unbound reply.
    pub async fn source_content_selection(
        &self,
        body: &SourceContentOnlySelectionRequest,
        person_authorization: &str,
    ) -> Result<SourceContentOnlySelectionResponse, StackError> {
        crate::validate_completion_caller_authorization(person_authorization)?;
        self.validate_current_completion_origin()?;
        let bytes = body.to_json_bytes()?;
        let tenant = TenantScope {
            tenant: body.tenant.tenant.clone(),
            workspace: body.tenant.workspace.clone(),
            environment: body.tenant.environment.clone(),
            cell: body.tenant.cell.clone(),
        };
        let fail = || StackError::unavailable("Source owning selection response refused");
        tokio::time::timeout(self.config.timeout, async {
            let mut person =
                reqwest::header::HeaderValue::from_str(person_authorization).map_err(|_| fail())?;
            person.set_sensitive(true);
            let mut request = self
                .request(
                    reqwest::Method::POST,
                    SOURCE_CONTENT_SELECTION_PATH,
                    &tenant,
                )
                .await
                .map_err(|_| fail())?
                .header(crate::COMPLETION_CALLER_AUTHORIZATION_HEADER, person)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes)
                .build()
                .map_err(|_| fail())?;
            request.headers_mut().remove("x-wos-workspace-id");
            request.headers_mut().remove("x-wos-environment-id");
            let mut response = self.http.execute(request).await.map_err(|_| fail())?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .content_length()
                    .is_some_and(|size| size > MAX_SOURCE_SELECTION_RESPONSE_BYTES as u64)
            {
                return Err(fail());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| fail())? {
                if chunk.len() > MAX_SOURCE_SELECTION_RESPONSE_BYTES - bytes.len() {
                    return Err(fail());
                }
                bytes.extend_from_slice(&chunk);
            }
            let selected: SourceContentOnlySelectionResponse =
                serde_json::from_slice(&bytes).map_err(|_| fail())?;
            selected.validate_for_request(body)?;
            Ok(selected)
        })
        .await
        .map_err(|_| fail())?
    }
}
