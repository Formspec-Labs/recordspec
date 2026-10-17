// Rust guideline compliant 2026-02-21
//! Bounded byte binding for a completion or Source-content prefix.
//!
//! The digest binds ordered transport bytes. It establishes neither signature
//! authority nor checkpoint inclusion; callers must verify those independently.

use crate::{domain_separated_sha256, encode_canonical_cbor_value, StoredEvent, Value};

/// Maximum events in an independently checked completion prefix.
pub const MAX_COMPLETION_EVENTS: usize = 256;
/// Maximum canonical bytes in the agreed completion transport budget.
pub const MAX_COMPLETION_CANONICAL_BYTES: usize = 1024 * 1024;
/// Maximum combined canonical and signed bytes before decoding or hashing.
pub const MAX_COMPLETION_PREFIX_BYTES: usize = 3 * 1024 * 1024;

/// Checks the bounded ledger scope used by prefix checks.
///
/// # Errors
/// Refuses blank, non-ASCII, slash-containing, or oversized scope bytes.
pub fn completion_scope_bounds(scope: &[u8]) -> Result<(), String> {
    if scope.is_empty()
        || scope.len() > 1024
        || !scope.is_ascii()
        || scope.contains(&b'/')
        || scope.iter().all(u8::is_ascii_whitespace)
    {
        return Err("completion prefix scope differs".into());
    }
    Ok(())
}

/// Checks prefix byte budgets without decoding protected event contents.
///
/// # Errors
/// Refuses empty, oversized, or overflowing prefixes.
pub fn completion_prefix_bounds(events: &[StoredEvent]) -> Result<(), String> {
    completion_prefix_byte_bounds(
        events
            .iter()
            .map(|event| (event.canonical_event(), event.signed_event())),
    )
}

/// Checks borrowed canonical and signed byte slices without allocating copies.
///
/// # Errors
/// Refuses empty, oversized, or overflowing prefixes.
pub fn completion_prefix_byte_bounds<'a>(
    events: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), String> {
    let mut canonical = 0usize;
    let mut combined = 0usize;
    let mut count = 0usize;
    for (canonical_bytes, signed_bytes) in events {
        count += 1;
        if count > MAX_COMPLETION_EVENTS {
            return Err("completion prefix exceeds bounds".into());
        }
        canonical = canonical
            .checked_add(canonical_bytes.len())
            .ok_or("completion prefix exceeds bounds")?;
        combined = combined
            .checked_add(canonical_bytes.len())
            .and_then(|n| n.checked_add(signed_bytes.len()))
            .ok_or("completion prefix exceeds bounds")?;
        if canonical > MAX_COMPLETION_CANONICAL_BYTES || combined > MAX_COMPLETION_PREFIX_BYTES {
            return Err("completion prefix exceeds bounds".into());
        }
    }
    if count == 0 {
        return Err("completion prefix exceeds bounds".into());
    }
    Ok(())
}

/// Binds exact ordered canonical and signed bytes to one ledger scope.
///
/// Uses the maintained canonical CBOR and domain-separated hash helpers. This
/// transport digest grants no permission and proves no signature authority.
///
/// # Errors
/// Refuses invalid scope bytes, mismatched event scopes, or excessive byte budgets.
pub fn completion_selection_prefix_digest(
    scope: &[u8],
    events: &[StoredEvent],
) -> Result<[u8; 32], String> {
    completion_prefix_bounds(events)?;
    completion_scope_bounds(scope)?;
    if events.iter().any(|e| e.scope() != scope) {
        return Err("completion prefix scope differs".into());
    }
    let rows = events
        .iter()
        .map(|event| {
            Value::Array(vec![
                Value::Integer(event.sequence().into()),
                Value::Bytes(event.canonical_event().to_vec()),
                Value::Bytes(event.signed_event().to_vec()),
            ])
        })
        .collect();
    let bytes = encode_canonical_cbor_value(&Value::Array(vec![
        Value::Bytes(scope.to_vec()),
        Value::Array(rows),
    ]))
    .map_err(|_| "completion prefix encoding failed")?;
    Ok(domain_separated_sha256(
        "trellis-completion-selection-prefix-v1",
        &bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_scope_sequence_order_and_both_byte_sets() {
        let event = |scope: &[u8], sequence, canonical, signed| {
            StoredEvent::new(scope.to_vec(), sequence, vec![canonical], vec![signed])
        };
        let baseline = completion_selection_prefix_digest(b"a", &[event(b"a", 0, 1, 2)]).unwrap();
        for altered in [
            event(b"a", 1, 1, 2),
            event(b"a", 0, 3, 2),
            event(b"a", 0, 1, 3),
        ] {
            assert_ne!(
                baseline,
                completion_selection_prefix_digest(b"a", &[altered]).unwrap()
            );
        }
        assert_ne!(
            baseline,
            completion_selection_prefix_digest(b"b", &[event(b"b", 0, 1, 2)]).unwrap()
        );
        let first = event(b"a", 0, 1, 2);
        let second = event(b"a", 1, 3, 4);
        assert_ne!(
            completion_selection_prefix_digest(b"a", &[first.clone(), second.clone()]).unwrap(),
            completion_selection_prefix_digest(b"a", &[second, first]).unwrap()
        );
        assert!(completion_selection_prefix_digest(b"a", &[event(b"b", 0, 1, 2)]).is_err());
    }

    #[test]
    fn budgets_refuse_before_decoding() {
        assert!(completion_prefix_bounds(&[]).is_err());
        let oversized = StoredEvent::new(
            b"a".to_vec(),
            0,
            vec![0; MAX_COMPLETION_CANONICAL_BYTES + 1],
            vec![],
        );
        assert!(completion_prefix_bounds(&[oversized]).is_err());
        let oversized = StoredEvent::new(
            b"a".to_vec(),
            0,
            vec![0],
            vec![0; MAX_COMPLETION_PREFIX_BYTES],
        );
        assert!(completion_prefix_bounds(&[oversized]).is_err());
    }
}
