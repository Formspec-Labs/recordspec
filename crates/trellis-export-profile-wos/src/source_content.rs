// Rust guideline compliant 2026-02-21
//! WOS Source-content publication checks: owner catalog parsing for returned batches and
//! the structural publication verifier.

use std::collections::BTreeSet;

use stack_common_error::StackError;
use trellis_service_client::source_content::{
    PreparedSourceContentBatchV1, SourceContentRoleV1, SourceContentSelection,
};

fn refused() -> StackError {
    StackError::conflict("committed Source content selection differs")
}

/// Cross-checks a prepared batch's catalogs and every record with the WOS parsers.
///
/// # Errors
/// Refuses any catalog, inventory, locator or opening that differs from the selection.
pub fn check_source_content_batch(
    selected: &SourceContentSelection,
    batch: &PreparedSourceContentBatchV1,
) -> Result<(), StackError> {
    // Parse the complete catalogs with their owners before any record is admitted.
    let originals =
        trellis_verify_wos::protected_intake_responses_from_catalog(&batch.intake_handoffs)
            .map_err(|_| refused())?;
    let tasks = trellis_verify_wos::source_signed_tasks_from_catalog(&batch.source_signed_tasks)
        .map_err(|_| refused())?;
    // Admit the complete catalog inventory before creating any writer member.
    let mut expected_inventory = BTreeSet::new();
    for row in &originals {
        expected_inventory.insert((
            SourceContentRoleV1::OriginalResponse,
            row.intake_event_hash(),
        ));
        if !tasks.is_empty() {
            row.validate_original_context_proof(&tasks)
                .map_err(|_| refused())?;
        }
    }
    for row in &tasks {
        row.protected_package_locator_cbor()
            .map_err(|_| refused())?;
        expected_inventory.insert((
            SourceContentRoleV1::CorrectionResponse,
            row.fields().canonical_event_hash,
        ));
        expected_inventory.insert((
            SourceContentRoleV1::TaskProofPackage,
            row.fields().canonical_event_hash,
        ));
    }
    let actual_inventory = batch
        .records
        .iter()
        .map(|record| {
            (
                record.occurrence.role,
                record.occurrence.occurrence_event_hash,
            )
        })
        .collect::<BTreeSet<_>>();
    if actual_inventory != expected_inventory || actual_inventory.len() != batch.records.len() {
        return Err(refused());
    }
    for record in &batch.records {
        match record.occurrence.role {
            SourceContentRoleV1::OriginalResponse => {
                let mut matches = originals.iter().filter(|row| {
                    row.intake_event_hash() == record.occurrence.occurrence_event_hash
                });
                let row = matches.next().ok_or_else(refused)?;
                if matches.next().is_some()
                    || row.protected_locator_cbor().map_err(|_| refused())? != record.locator_cbor
                {
                    return Err(refused());
                }
                let opening = row
                    .protected_response_opening(&record.protected_record_bytes)
                    .map_err(|_| refused())?;
                if Some(row.response_id()) != record.occurrence.response_id.as_deref()
                    || opening.publication_hash() != record.occurrence.publication_hash
                    || opening.public_policy_hash() != record.occurrence.public_signing_policy_hash
                    || opening.recipient_policy_hash() != selected.identity.recipient_policy_hash
                {
                    return Err(refused());
                }
            }
            SourceContentRoleV1::CorrectionResponse => {
                let mut matches = tasks.iter().filter(|row| {
                    row.fields().canonical_event_hash == record.occurrence.occurrence_event_hash
                });
                let row = matches.next().ok_or_else(refused)?;
                if matches.next().is_some()
                    || row.protected_locator_cbor().map_err(|_| refused())? != record.locator_cbor
                {
                    return Err(refused());
                }
                let opening = row
                    .protected_response_opening(&record.protected_record_bytes)
                    .map_err(|_| refused())?;
                if Some(row.fields().response_id.as_str())
                    != record.occurrence.response_id.as_deref()
                    || opening.publication_hash() != record.occurrence.publication_hash
                    || opening.public_policy_hash() != record.occurrence.public_signing_policy_hash
                    || opening.recipient_policy_hash() != selected.identity.recipient_policy_hash
                {
                    return Err(refused());
                }
            }
            SourceContentRoleV1::TaskProofPackage => {
                let mut matches = tasks.iter().filter(|row| {
                    row.fields().canonical_event_hash == record.occurrence.occurrence_event_hash
                });
                let row = matches.next().ok_or_else(refused)?;
                if matches.next().is_some()
                    || row
                        .protected_package_locator_cbor()
                        .map_err(|_| refused())?
                        != record.locator_cbor
                {
                    return Err(refused());
                }
                let opening = row
                    .protected_package_opening(&record.protected_record_bytes)
                    .map_err(|_| refused())?;
                if opening.current_publication_hash() != record.occurrence.publication_hash
                    || opening.public_policy_hash() != record.occurrence.public_signing_policy_hash
                    || opening.recipient_policy_hash() != selected.identity.recipient_policy_hash
                {
                    return Err(refused());
                }
            }
        }
    }
    Ok(())
}

/// Admits a complete export for protected-member publication, never final Source readiness.
///
/// # Errors
/// Refuses any native, registry, checkpoint, or member identity failure.
pub fn verify_source_content_export(
    zip: &[u8],
    authorities: Option<&integrity_verify::trellis::CertificateAuthorityRegistry>,
) -> Result<(), StackError> {
    let report = trellis_verify_wos::verify_source_content_publication(zip, authorities);
    if !report.publication_admitted() {
        return Err(StackError::conflict(format!(
            "protected Source publication structural admission refused: {}",
            report.blocking_reasons().join("; ")
        )));
    }
    Ok(())
}
