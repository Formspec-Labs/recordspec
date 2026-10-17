// Rust guideline compliant 2026-02-21
//! Core §18 exports, assembled on request at a stored checkpoint.
//!
//! Nothing is published at append time: an export is the events and checkpoints already stored,
//! plus one manifest signature. The bytes are a function of the ledger prefix alone, so the same
//! checkpoint always yields the same ZIP.

use integrity_cbor::domain_separated_sha256;
use stack_common_error::StackError;
use trellis_export_writer::{
    ExportSealFence, ExportWriterInput, RegistrySnapshot as ExportRegistrySnapshot, write_export,
};
use trellis_types::StoredCheckpoint;

use crate::{
    EVENT_TYPE_REGISTRY_VERSION, TrellisServerState, append, encode_value, event_hash,
    event_timestamp, event_type_registry_cbor, external_attachment, reconciliation, source_content,
    text_map, uint,
};

const EXPORT_ATTEMPT_DOMAIN: &str = "trellis-export-attempt-v1";

/// The ZIP for the prefix whose head is `head`.
///
/// Reads `head.tree_size` event rows and as many checkpoint rows; builds the proofs from an
/// in-memory tree (`O(k log k)`); signs only the manifest.
///
/// # Errors
/// Unavailable when a row the checkpoint implies is missing; a conflict when stored rows contradict
/// themselves or a Source closeout's retained batch.
pub(crate) async fn assemble(
    state: &TrellisServerState,
    scope: &[u8],
    head: &StoredCheckpoint,
) -> Result<Vec<u8>, StackError> {
    let rows = state.repository.export_rows(scope, head.tree_size).await?;
    let events = reconciliation::checked_prefix(scope, rows.events)?;
    let last = events
        .last()
        .ok_or_else(|| StackError::internal("export of an empty prefix"))?;
    let generated_at = event_timestamp(last)?;
    let seal_version = head.tree_size;
    let high_water_event_hash = event_hash(scope, last)?;
    let export_attempt_id =
        export_attempt_id(scope, seal_version, last.sequence(), high_water_event_hash)?;

    // A final Source closeout is never served bare: its members come from the batch Trellis kept.
    let source_members = match &state.source_content {
        Some(composition) => match composition.final_prefix_guard.classify(scope, &events)? {
            crate::SourceContentPrefixClass::Ordinary => None,
            crate::SourceContentPrefixClass::FinalCloseout { .. } => {
                Some(source_content::stored_members(state, scope, last.sequence()).await?)
            }
        },
        None => None,
    };

    let compute = external_attachment::export_compute(
        state,
        scope,
        &events,
        &append::default_public_compute_context(),
    )
    .await?;
    let mut evidence_members = state
        .export_profile
        .evidence_members(scope, &events.iter().collect::<Vec<_>>())?;
    evidence_members.extend(external_attachment::evidence_members(state, scope, &events).await?);
    if let Some(members) = &source_members {
        evidence_members = source_content::merge_source_members(evidence_members, members)?;
    }
    let export_profile = state
        .export_profile
        .profile_members(scope, &events, generated_at)?;
    let package = write_export(ExportWriterInput {
        scope: scope.to_vec(),
        events,
        registries: vec![ExportRegistrySnapshot {
            bytes: event_type_registry_cbor(state.event_type_catalog.as_ref())?,
            registry_format: 1,
            registry_version: EVENT_TYPE_REGISTRY_VERSION.to_string(),
            bound_at_sequence: 0,
        }],
        signing_key: state.signing_key.export_key(),
        generator: "trellis-server".to_string(),
        generated_at,
        checkpoints: rows.checkpoints,
        posture_declaration: append::export_posture_from_compute(&compute),
        omitted_payload_checks: Vec::new(),
        readme_title: format!("Trellis export for {}", String::from_utf8_lossy(scope)),
        root_dir_override: None,
        external_anchors: Vec::new(),
        extensions: None,
        seal_fence: Some(ExportSealFence {
            bundle_scope: scope.to_vec(),
            export_attempt_id,
            seal_version,
            event_count: seal_version,
            high_water_sequence: head.tree_size - 1,
        }),
        witness_key_registry: None,
        signed_acts_catalog: export_profile.signed_acts_catalog,
        signed_acts_manifest: export_profile.signed_acts_manifest,
        policy_closure: export_profile.policy_closure,
        evidence_members,
    })?;
    if source_members.is_some() {
        source_content::archive_bound(&package.zip_bytes)?;
        if let Some(composition) = &state.source_content {
            composition.verify_structural(&package.zip_bytes)?;
        }
    }
    Ok(package.zip_bytes)
}

pub(crate) fn export_attempt_id(
    scope: &[u8],
    seal_version: u64,
    high_water_sequence: u64,
    high_water_event_hash: [u8; 32],
) -> Result<String, StackError> {
    let material = text_map(vec![
        ("bundle_scope", integrity_cbor::Value::Bytes(scope.to_vec())),
        ("seal_version", uint(seal_version)),
        ("high_water_sequence", uint(high_water_sequence)),
        (
            "high_water_event_hash",
            integrity_cbor::Value::Bytes(high_water_event_hash.to_vec()),
        ),
    ])?;
    let digest = domain_separated_sha256(EXPORT_ATTEMPT_DOMAIN, &encode_value(&material)?);
    Ok(format!("sha256:{}", hex::encode(digest)))
}
