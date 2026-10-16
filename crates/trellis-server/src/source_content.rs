// Rust guideline compliant 2026-02-21
//! WOS Source-content owner adapter: reads prepared batches from the owning service and
//! checks them with the WOS catalog parsers and structural publication verifier.

use std::sync::Arc;

use async_trait::async_trait;
use stack_common_error::StackError;
use stack_common_http::tenant::TenantScope;
use trellis_export_profile_wos::{check_source_content_batch, verify_source_content_export};
use trellis_server_ports::{CloseoutSource, NativeCloseout};
use trellis_service_client::TrellisServiceClient;
use trellis_service_core::{
    ConfiguredSourceContentPins, PreparedSourceContentBatchV1, SourceContentContributor,
    SourceContentInputs, SourceContentParts, SourceContentRequest, SourceContentSelection,
    SourceContentSelectionRequest, SourceContentSelectionResolver,
    StructuralSourcePublicationVerifier, source_content_batch_key,
};

fn refused() -> StackError {
    StackError::conflict("committed Source content selection differs")
}

/// Builds the WOS owner adapter for one configured Source-content composition.
#[must_use]
pub fn source_content_parts(inputs: SourceContentInputs) -> SourceContentParts {
    let reader = Arc::new(WosSourceContentContributor {
        client: inputs.client,
        tenant: inputs.tenant,
        pins: inputs.pins,
        closeout: inputs.closeout,
    });
    SourceContentParts {
        selection_resolver: reader.clone(),
        contributor: reader,
        structural: Arc::new(WosSourcePublicationVerifier {
            authorities: inputs.authorities,
        }),
    }
}

/// Configured owning GET adapter using maintained current read credentials.
#[derive(Clone)]
struct WosSourceContentContributor {
    client: TrellisServiceClient,
    tenant: TenantScope,
    pins: ConfiguredSourceContentPins,
    closeout: Arc<dyn NativeCloseout>,
}

impl std::fmt::Debug for WosSourceContentContributor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WosSourceContentContributor")
            .field("tenant", &self.tenant)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SourceContentContributor for WosSourceContentContributor {
    async fn read(
        &self,
        request: &SourceContentRequest<'_>,
    ) -> Result<PreparedSourceContentBatchV1, StackError> {
        let selected = &request.selection.identity;
        if selected.provider_selection_hash != self.pins.provider_selection_hash
            || selected.native_policy_hash != self.pins.native_policy_hash
            || selected.recipient_policy_hash != self.pins.recipient_policy_hash
        {
            return Err(StackError::conflict(
                "configured Source provider pins differ",
            ));
        }
        let person = request
            .caller
            .person_authorization()
            .ok_or_else(|| StackError::unavailable("qualified Source content caller is absent"))?;
        let bytes = self
            .client
            .prepared_source_content_bytes(
                &self.tenant,
                &selected.case_ledger_id,
                &request.selection.preparation_key,
                person,
            )
            .await?;
        let batch: PreparedSourceContentBatchV1 = serde_json::from_slice(&bytes)
            .map_err(|_| StackError::unavailable("closed prepared Source response refused"))?;
        if batch.selection != *selected
            || source_content_batch_key(&batch)? != request.selection.preparation_key
        {
            return Err(refused());
        }
        Ok(batch)
    }

    fn check_batch(
        &self,
        selected: &SourceContentSelection,
        batch: &PreparedSourceContentBatchV1,
    ) -> Result<(), StackError> {
        check_source_content_batch(selected, batch)
    }
}

#[async_trait]
impl SourceContentSelectionResolver for WosSourceContentContributor {
    async fn select(
        &self,
        request: &SourceContentSelectionRequest<'_>,
    ) -> Result<SourceContentSelection, StackError> {
        if request.tenant != &self.tenant {
            return Err(StackError::conflict("configured Source tenant differs"));
        }
        let person = request
            .caller
            .person_authorization()
            .ok_or_else(|| StackError::unavailable("qualified Source content caller is absent"))?;
        let body =
            trellis_service_client::source_content::SourceContentOnlySelectionRequest::from_prefix(
                &self.tenant,
                request.scope,
                request.preparation_key,
                request.append_body,
                request.prefix,
            )?;
        let reply = self.client.source_content_selection(&body, person).await?;
        let selected = reply.selected;
        if selected.identity.provider_selection_hash != self.pins.provider_selection_hash
            || selected.identity.native_policy_hash != self.pins.native_policy_hash
            || selected.identity.recipient_policy_hash != self.pins.recipient_policy_hash
        {
            return Err(StackError::conflict(
                "configured Source provider pins differ",
            ));
        }
        self.closeout.validate(
            CloseoutSource::Append(request.append_body),
            &selected.identity,
        )?;
        Ok(selected)
    }
}

/// Uses the maintained explicit publication phase without claiming Source opening.
#[derive(Clone, Debug)]
struct WosSourcePublicationVerifier {
    authorities: Option<integrity_verify::trellis::CertificateAuthorityRegistry>,
}

impl StructuralSourcePublicationVerifier for WosSourcePublicationVerifier {
    fn verify(&self, zip: &[u8]) -> Result<(), StackError> {
        verify_source_content_export(zip, self.authorities.as_ref())
    }
}
