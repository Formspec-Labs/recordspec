// Rust guideline compliant 2026-02-21
//! What every append commits with its event: the next checkpoint.
//!
//! A [`Checkpointer`] turns "this event follows that head" into the signed checkpoint, the Merkle
//! frontier and the export profile's running state that are stored beside the event. It reads
//! nothing but the head it is handed, so the cost of an append does not depend on the ledger's
//! length.

use stack_common_error::StackError;
use trellis_core::SigningKeyMaterial;
use trellis_core::checkpoint::{PriorCheckpoint, issue_checkpoint};
use trellis_export_writer::TrellisTimestamp;
use trellis_server_ports::ExportProfile;
use trellis_service_client::SubstrateAppendResult;
use trellis_types::{StoredCheckpoint, StoredEvent};

use crate::{event_hash, event_timestamp};

/// Issues the checkpoint that follows a head.
pub(crate) struct Checkpointer<'a> {
    pub(crate) signing_key: SigningKeyMaterial,
    pub(crate) purpose: integrity_seam::Purpose,
    pub(crate) export_profile: &'a dyn ExportProfile,
}

impl Checkpointer<'_> {
    /// The checkpoint for `event` appended after `head`, and `event` with its canonical hash set.
    ///
    /// # Errors
    /// Refuses an event that does not extend `head`, a corrupt stored frontier, a profile whose
    /// limits the new prefix exceeds, or a signing failure.
    pub(crate) fn after(
        &self,
        head: Option<&StoredCheckpoint>,
        event: &StoredEvent,
    ) -> Result<(StoredEvent, StoredCheckpoint), StackError> {
        if self.purpose != integrity_seam::Purpose::Ledger {
            return Err(StackError::internal(
                "Checkpointer must sign checkpoints with a Purpose::Ledger key",
            ));
        }
        let scope = event.scope();
        let hash = event_hash(scope, event)?;
        let event = event.clone().with_canonical_event_hash(Some(hash));
        if event.sequence() != head.map_or(0, |head| head.tree_size) {
            return Err(StackError::internal(
                "event does not extend the head checkpoint",
            ));
        }
        let frontier = head
            .map(StoredCheckpoint::frontier)
            .transpose()
            .map_err(|error| StackError::internal(format!("stored frontier invalid: {error}")))?;
        let prior = head
            .zip(frontier.as_ref())
            .map(|(head, frontier)| PriorCheckpoint {
                digest: head.digest,
                frontier,
            });
        let authored_at = event_timestamp(&event)?;
        let issued = issue_checkpoint(
            &self.signing_key,
            scope,
            prior,
            hash,
            (authored_at.unix_secs, authored_at.subsec_nanos),
        )
        .map_err(|error| StackError::internal(format!("checkpoint issuance failed: {error}")))?;
        let profile_state = self.export_profile.fold_append(
            scope,
            head.map(|head| head.profile_state.as_slice()),
            &event,
            issued.tree_size,
        )?;
        let checkpoint = issued.stored(scope, profile_state);
        Ok((event, checkpoint))
    }
}

/// `authored_at` for a new event: the clock, but never before the last event.
///
/// Verifiers order events by `authored_at` (Core §19 step 4.h), so replicas whose clocks differ by
/// a few milliseconds must not produce a ledger that fails its own verification.
///
/// # Errors
/// Refuses a last event whose header is unreadable.
pub(crate) fn authored_at_after(
    last: Option<&StoredEvent>,
    now: TrellisTimestamp,
) -> Result<TrellisTimestamp, StackError> {
    let Some(last) = last else { return Ok(now) };
    let last = event_timestamp(last)?;
    Ok(
        if (last.unix_secs, last.subsec_nanos) > (now.unix_secs, now.subsec_nanos) {
            last
        } else {
            now
        },
    )
}

/// The `prev_hash` a stored event commits to: the hash of its predecessor, if it has one.
///
/// # Errors
/// Refuses an event whose canonical bytes are not an event map with a well-formed `prev_hash`.
pub(crate) fn prior_event_hash(event: &StoredEvent) -> Result<Option<[u8; 32]>, StackError> {
    let value = integrity_cbor::decode_cbor_value(event.canonical_event())
        .map_err(|error| StackError::internal(format!("stored event unreadable: {error}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| StackError::internal("stored event is not a map"))?;
    match integrity_cbor::map_lookup_optional_value(map, "prev_hash") {
        None | Some(integrity_cbor::Value::Null) => Ok(None),
        Some(integrity_cbor::Value::Bytes(bytes)) => bytes
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| StackError::internal("stored prev_hash is not 32 bytes")),
        Some(_) => Err(StackError::internal("stored prev_hash is malformed")),
    }
}

/// The URI naming a stored checkpoint.
pub(crate) fn checkpoint_ref(scope: &str, checkpoint: &StoredCheckpoint) -> String {
    format!(
        "trellis://{scope}/checkpoints/sha256:{}",
        hex::encode(checkpoint.digest)
    )
}

/// The append response: the event's identity and the checkpoint that commits to it.
///
/// # Errors
/// Refuses a checkpoint that is not the one at `event.sequence() + 1`.
pub(crate) fn append_result(
    scope: &str,
    event: &StoredEvent,
    prior_event_hash: Option<[u8; 32]>,
    checkpoint: &StoredCheckpoint,
) -> Result<SubstrateAppendResult, StackError> {
    if checkpoint.tree_size != event.sequence() + 1 {
        return Err(StackError::internal(
            "append receipt checkpoint is not the one at sequence + 1",
        ));
    }
    let canonical_hash = event_hash(scope.as_bytes(), event)?;
    let hash_hex = hex::encode(canonical_hash);
    Ok(SubstrateAppendResult {
        event_id: format!("evt_{}", &hash_hex[..16]),
        sequence: event.sequence(),
        prior_event_hash: prior_event_hash.map(|hash| format!("sha256:{}", hex::encode(hash))),
        canonical_event_hash: format!("sha256:{hash_hex}"),
        checkpoint_ref: checkpoint_ref(scope, checkpoint),
    })
}
