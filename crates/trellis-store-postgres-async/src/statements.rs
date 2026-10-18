// Rust guideline compliant 2026-02-21
//! Every read statement the adapter runs, named once, so the EXPLAIN acceptance test plans the
//! SQL the adapter sends rather than a copy of it.
//!
//! Each runs in a `ScopedTx`: `$1` is the scope key (the transaction binds it) and `$2` the ledger
//! scope, so every read is `WHERE scope_key = $1 AND scope = $2 …` on a `(scope_key, scope, …)`
//! key.

macro_rules! events {
    ($where:literal) => {
        concat!(
            "SELECT scope, sequence, canonical_event, signed_event, idempotency_key, ",
            "canonical_event_hash FROM trellis_events ",
            $where
        )
    };
}

macro_rules! checkpoints {
    ($where:literal) => {
        concat!(
            "SELECT scope, tree_size, digest, checkpoint, frontier, profile_state ",
            "FROM trellis_checkpoints ",
            $where
        )
    };
}

macro_rules! attachments {
    ($where:literal) => {
        concat!(
            "SELECT e.scope, e.sequence, e.canonical_event, e.signed_event, e.idempotency_key, ",
            "e.canonical_event_hash, a.ciphertext, a.nonce, a.replay_identity, a.content_hash, ",
            "a.idempotency_key, a.compute_json FROM trellis_external_attachments a ",
            "JOIN trellis_events e ",
            "ON e.scope_key = a.scope_key AND e.scope = a.scope AND e.sequence = a.sequence ",
            $where
        )
    };
}

/// The head checkpoint: a backward walk of the primary key. `$2` ledger.
pub const HEAD_CHECKPOINT: &str =
    checkpoints!("WHERE scope_key = $1 AND scope = $2 ORDER BY tree_size DESC LIMIT 1");
/// The checkpoint at `$3` (tree size).
pub const CHECKPOINT_AT: &str =
    checkpoints!("WHERE scope_key = $1 AND scope = $2 AND tree_size = $3");
/// The checkpoint with digest `$3`.
pub const CHECKPOINT_BY_DIGEST: &str =
    checkpoints!("WHERE scope_key = $1 AND scope = $2 AND digest = $3");
/// Checkpoints with tree size `<= $3`, ascending.
pub const CHECKPOINTS_THROUGH: &str =
    checkpoints!("WHERE scope_key = $1 AND scope = $2 AND tree_size <= $3 ORDER BY tree_size");
/// The most recent event.
pub const LAST_EVENT: &str =
    events!("WHERE scope_key = $1 AND scope = $2 ORDER BY sequence DESC LIMIT 1");
/// The event under idempotency key `$3`.
pub const EVENT_BY_KEY: &str =
    events!("WHERE scope_key = $1 AND scope = $2 AND idempotency_key = $3");
/// The first `$3` events, ascending: a bounded prefix of a ledger of any length.
pub const PREFIX: &str = events!("WHERE scope_key = $1 AND scope = $2 ORDER BY sequence LIMIT $3");
/// Events with sequence `< $3`, ascending: an export's events.
pub const EVENTS_BEFORE: &str =
    events!("WHERE scope_key = $1 AND scope = $2 AND sequence < $3 ORDER BY sequence");
/// The attachment under idempotency key `$3`, with its event.
pub const ATTACHMENT_BY_KEY: &str =
    attachments!("WHERE a.scope_key = $1 AND a.scope = $2 AND a.idempotency_key = $3");
/// The body length of each attachment for events with sequence `< $3`, ascending, at most `$4`:
/// read before the bodies, so an export stops at its byte bound.
pub const ATTACHMENT_LENGTHS: &str = "SELECT sequence, octet_length(ciphertext)::bigint FROM \
     trellis_external_attachments WHERE scope_key = $1 AND scope = $2 AND sequence < $3 \
     ORDER BY sequence LIMIT $4";
/// Attachments for events with sequence `< $3`, ascending, with their events.
pub const ATTACHMENTS_BEFORE: &str =
    attachments!("WHERE a.scope_key = $1 AND a.scope = $2 AND a.sequence < $3 ORDER BY a.sequence");
/// The Source batch copy bound to the event at `$3`.
pub const SOURCE_CONTENT: &str = "SELECT batch_hash, size, artifact_ref FROM \
     trellis_source_contents WHERE scope_key = $1 AND scope = $2 AND sequence = $3";

/// Every read, named, for the EXPLAIN acceptance test.
pub const READS: &[(&str, &str)] = &[
    ("head checkpoint", HEAD_CHECKPOINT),
    ("checkpoint at", CHECKPOINT_AT),
    ("checkpoint by digest", CHECKPOINT_BY_DIGEST),
    ("checkpoints through", CHECKPOINTS_THROUGH),
    ("last event", LAST_EVENT),
    ("event by key", EVENT_BY_KEY),
    ("prefix", PREFIX),
    ("events before", EVENTS_BEFORE),
    ("attachment by key", ATTACHMENT_BY_KEY),
    ("attachment lengths", ATTACHMENT_LENGTHS),
    ("attachments before", ATTACHMENTS_BEFORE),
    ("source content", SOURCE_CONTENT),
];
