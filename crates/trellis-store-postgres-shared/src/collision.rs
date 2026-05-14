//! Idempotency collision decisions shared by Postgres adapters.

/// Decision returned after comparing existing and incoming payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionDecision<'a> {
    /// Existing bytes are identical and the append is a replay.
    Replay(&'a [u8]),
    /// Existing bytes differ and the append conflicts with prior state.
    Conflict {
        /// Stable reason token for logs and adapter-specific errors.
        reason: &'static str,
    },
}

/// Resolves byte equality for one collision payload component.
#[must_use]
pub fn resolve_collision<'a>(
    existing_payload: &'a [u8],
    new_payload: &[u8],
) -> CollisionDecision<'a> {
    if existing_payload == new_payload {
        CollisionDecision::Replay(existing_payload)
    } else {
        CollisionDecision::Conflict {
            reason: "IdempotencyKeyPayloadMismatch",
        }
    }
}
