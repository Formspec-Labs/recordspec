// Rust guideline compliant 2026-02-21
//! WOS Source-content owner adapter: checks prepared batches with the WOS catalog parsers and
//! verifies final publication with the structural export verifier.

use std::sync::Arc;

use stack_common_error::StackError;
use trellis_export_profile_wos::{check_source_content_batch, verify_source_content_export};
use trellis_service_core::{
    PreparedSourceContentBatchV1, SourceContentBatchChecker, SourceContentInputs,
    SourceContentParts, SourceContentSelection, StructuralSourcePublicationVerifier,
};

/// Builds the WOS owner adapter for one configured Source-content composition.
#[must_use]
pub fn source_content_parts(inputs: SourceContentInputs) -> SourceContentParts {
    SourceContentParts {
        batch_checker: Arc::new(WosBatchChecker),
        structural: Arc::new(WosSourcePublicationVerifier {
            authorities: inputs.authorities,
        }),
    }
}

/// Cross-checks a batch with the WOS catalog parsers.
#[derive(Clone, Debug)]
struct WosBatchChecker;

impl SourceContentBatchChecker for WosBatchChecker {
    fn check_batch(
        &self,
        selected: &SourceContentSelection,
        batch: &PreparedSourceContentBatchV1,
    ) -> Result<(), StackError> {
        check_source_content_batch(selected, batch)
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
