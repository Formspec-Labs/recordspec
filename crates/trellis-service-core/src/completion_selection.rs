// Rust guideline compliant 2026-02-21
//! Checks structural correspondence between a complete census and native events.
//!
//! Callers independently establish archive signatures, checkpoint inclusion,
//! current authority, and completeness of the owning census. These functions
//! cannot authenticate supplied signed bytes or a caller's chosen event list.

use integrity_cbor::{
    Value, decode_cbor_value, domain_separated_sha256, map_lookup_bytes, map_lookup_map,
    map_lookup_optional_value, map_lookup_text,
};
use std::collections::BTreeSet;
use trellis_types::{
    CONTENT_DOMAIN, EVENT_DOMAIN, StoredEvent,
    completion_selection::{
        MAX_COMPLETION_CANONICAL_BYTES, MAX_COMPLETION_EVENTS, completion_prefix_bounds,
        completion_scope_bounds,
    },
};

/// Exact opaque owning record expected in the selected complete snapshot.
pub struct CompletionRecord {
    /// Owning event vocabulary member.
    pub event_type: String,
    /// Exact retained inline payload bytes.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for CompletionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionRecord").finish_non_exhaustive()
    }
}

fn invalid() -> String {
    "completion native prefix or census differs".into()
}

/// Checks exact event scope, sequence, recomputed hashes, and structural links.
///
/// Supplied materialized hashes are checked when present, never trusted as the
/// hash source. This does not verify COSE signatures or checkpoint inclusion.
///
/// # Errors
/// Refuses excessive budgets, malformed events, mismatched scope or sequence,
/// inconsistent materialized hashes, or broken previous-event links.
pub fn validate_completion_prefix(events: &[StoredEvent], scope: &[u8]) -> Result<(), String> {
    completion_prefix_bounds(events)?;
    completion_scope_bounds(scope)?;
    if events.iter().any(|event| event.scope() != scope) {
        return Err(invalid());
    }
    let mut prior = Value::Null;
    for (index, event) in events.iter().enumerate() {
        let parsed =
            trellis_cddl::parse_canonical_event(event.canonical_event()).map_err(|_| invalid())?;
        let value = decode_cbor_value(event.canonical_event()).map_err(|_| invalid())?;
        // Preserve the maintained native map order, including appended author hash.
        // Canonicalization checks duplicate keys recursively without rewriting it.
        trellis_types::canonicalize_cbor_value(&value).map_err(|_| invalid())?;
        if trellis_types::encode_cbor_value(&value).map_err(|_| invalid())?
            != event.canonical_event()
        {
            return Err(invalid());
        }
        let root = value.as_map().ok_or_else(invalid)?;
        if parsed.ledger_scope != scope
            || event.sequence() != index as u64
            || parsed.sequence != event.sequence()
            || map_lookup_optional_value(root, "prev_hash") != Some(&prior)
        {
            return Err(invalid());
        }
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(scope, event.canonical_event()),
        );
        if event
            .canonical_event_hash()
            .is_some_and(|stored| stored != &hash)
        {
            return Err(invalid());
        }
        prior = Value::Bytes(hash.to_vec());
    }
    Ok(())
}

/// Binds a complete owning census to exact readable native event bytes.
///
/// The owner supplies its entire relevant vocabulary and complete census. The
/// one-to-one match proves correspondence only, not that business census's completeness.
///
/// # Errors
/// Refuses missing, duplicate, extra relevant, unreadable, oversized, or changed records.
pub fn completion_record_bindings(
    prefix: &[StoredEvent],
    records: &[CompletionRecord],
    relevant_event_types: &[String],
) -> Result<Vec<[u8; 32]>, String> {
    let scope = prefix.first().ok_or_else(invalid)?.scope();
    validate_completion_prefix(prefix, scope)?;
    if records.is_empty()
        || records.len() > MAX_COMPLETION_EVENTS
        || relevant_event_types.is_empty()
        || relevant_event_types.len() > MAX_COMPLETION_EVENTS
    {
        return Err(invalid());
    }
    let payload_bytes = records
        .iter()
        .try_fold(0usize, |total, row| total.checked_add(row.payload.len()))
        .ok_or_else(invalid)?;
    if payload_bytes > MAX_COMPLETION_CANONICAL_BYTES {
        return Err(invalid());
    }
    let relevant = relevant_event_types.iter().collect::<BTreeSet<_>>();
    if relevant.len() != relevant_event_types.len()
        || records
            .iter()
            .any(|record| !relevant.contains(&record.event_type))
    {
        return Err(invalid());
    }
    let mut actual = Vec::new();
    for event in prefix {
        let value = decode_cbor_value(event.canonical_event()).map_err(|_| invalid())?;
        let root = value.as_map().ok_or_else(invalid)?;
        let header = map_lookup_map(root, "header").map_err(|_| invalid())?;
        let event_type =
            String::from_utf8(map_lookup_bytes(header, "event_type").map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        if !relevant.contains(&event_type) {
            continue;
        }
        let reference = map_lookup_map(root, "payload_ref").map_err(|_| invalid())?;
        if map_lookup_text(reference, "ref_type").map_err(|_| invalid())? != "inline" {
            return Err(invalid());
        }
        let payload = map_lookup_bytes(reference, "ciphertext").map_err(|_| invalid())?;
        if map_lookup_bytes(root, "content_hash").map_err(|_| invalid())?
            != domain_separated_sha256(CONTENT_DOMAIN, &payload)
        {
            return Err(invalid());
        }
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(scope, event.canonical_event()),
        );
        actual.push((event_type, payload, hash));
    }
    if actual.len() != records.len() {
        return Err(invalid());
    }
    let mut consumed = BTreeSet::new();
    let mut bindings = Vec::with_capacity(records.len());
    for record in records {
        let mut matches = actual
            .iter()
            .enumerate()
            .filter(|(_, row)| row.0 == record.event_type && row.1 == record.payload);
        let (index, row) = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() || !consumed.insert(index) {
            return Err(invalid());
        }
        bindings.push(row.2);
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal structural maps intentionally establish no signature authority.
    fn event(scope: &[u8], sequence: u64, previous: Value, payload: &[u8]) -> StoredEvent {
        let pair = |key: &str, value| (Value::Text(key.into()), value);
        let value = Value::Map(vec![
            pair("ledger_scope", Value::Bytes(scope.to_vec())),
            pair("sequence", Value::Integer(sequence.into())),
            pair("author_event_hash", Value::Bytes(vec![1; 32])),
            pair("idempotency_key", Value::Bytes(vec![1])),
            pair("prev_hash", previous),
            pair(
                "content_hash",
                Value::Bytes(domain_separated_sha256(CONTENT_DOMAIN, payload).to_vec()),
            ),
            pair(
                "header",
                Value::Map(vec![pair(
                    "event_type",
                    Value::Bytes(b"owner.done".to_vec()),
                )]),
            ),
            pair(
                "payload_ref",
                Value::Map(vec![
                    pair("ref_type", Value::Text("inline".into())),
                    pair("ciphertext", Value::Bytes(payload.to_vec())),
                ]),
            ),
        ]);
        let bytes = trellis_types::encode_canonical_cbor_value(&value).unwrap();
        StoredEvent::new(scope.to_vec(), sequence, bytes, vec![0])
    }

    #[test]
    fn prefix_rederives_hash_and_checks_inner_scope_sequence_and_links() {
        let first = event(b"a", 0, Value::Null, b"first");
        let hash = domain_separated_sha256(
            EVENT_DOMAIN,
            &trellis_cddl::canonical_event_hash_preimage(b"a", first.canonical_event()),
        );
        let second = event(b"a", 1, Value::Bytes(hash.to_vec()), b"second");
        assert!(validate_completion_prefix(&[first.clone(), second], b"a").is_ok());
        assert!(
            validate_completion_prefix(
                &[first.clone().with_canonical_event_hash(Some([0; 32]))],
                b"a"
            )
            .is_err()
        );
        assert!(validate_completion_prefix(&[first], b"b").is_err());
        let inner_foreign = event(b"b", 0, Value::Null, b"first");
        let outer = StoredEvent::new(
            b"a".to_vec(),
            0,
            inner_foreign.canonical_event().to_vec(),
            vec![0],
        );
        assert!(validate_completion_prefix(&[outer], b"a").is_err());
        assert!(
            validate_completion_prefix(&[event(b"a", 1, Value::Null, b"first")], b"a").is_err()
        );
        assert!(
            validate_completion_prefix(
                &[event(b"a", 0, Value::Bytes(vec![0; 32]), b"first")],
                b"a"
            )
            .is_err()
        );
    }

    #[test]
    fn census_refuses_missing_changed_repeated_or_extra_records() {
        let prefix = [event(b"a", 0, Value::Null, b"retained")];
        let record = |payload: &[u8]| CompletionRecord {
            event_type: "owner.done".into(),
            payload: payload.to_vec(),
        };
        let vocabulary = ["owner.done".into()];
        assert_eq!(
            completion_record_bindings(&prefix, &[record(b"retained")], &vocabulary)
                .unwrap()
                .len(),
            1
        );
        assert!(completion_record_bindings(&prefix, &[], &vocabulary).is_err());
        assert!(completion_record_bindings(&prefix, &[record(b"changed")], &vocabulary).is_err());
        assert!(
            completion_record_bindings(
                &prefix,
                &[record(b"retained"), record(b"retained")],
                &vocabulary
            )
            .is_err()
        );
        assert!(
            completion_record_bindings(&prefix, &[record(b"retained")], &["owner.other".into()])
                .is_err()
        );
    }

    #[test]
    fn record_debug_redacts_payload() {
        let record = CompletionRecord {
            event_type: "private-owner-type".into(),
            payload: b"private-payload".to_vec(),
        };
        assert_eq!(format!("{record:?}"), "CompletionRecord { .. }");
    }

    #[test]
    fn oversized_or_invalid_scope_refuses_before_cbor_decoding() {
        let bytes = [0xff];
        for scope in [
            vec![b'a'; 1025],
            b"bad/scope".to_vec(),
            b" ".to_vec(),
            vec![0xff],
        ] {
            let event = StoredEvent::new(scope.clone(), 0, bytes.to_vec(), vec![]);
            assert_eq!(
                validate_completion_prefix(&[event], &scope).unwrap_err(),
                "completion prefix scope differs"
            );
        }
        let outer = StoredEvent::new(vec![b'a'; 1025], 0, bytes.to_vec(), vec![]);
        assert_eq!(
            validate_completion_prefix(&[outer], b"a").unwrap_err(),
            "completion native prefix or census differs"
        );
    }

    #[test]
    fn prefix_refuses_trailing_bytes_duplicate_keys_and_indefinite_encoding() {
        let baseline = event(b"a", 0, Value::Null, b"retained");
        let mut trailing = baseline.canonical_event().to_vec();
        trailing.push(0);
        let value = decode_cbor_value(baseline.canonical_event()).unwrap();
        let mut duplicate = value.clone();
        if let Value::Map(ref mut entries) = duplicate {
            entries.push(entries[0].clone());
        }
        let duplicate = trellis_types::encode_cbor_value(&duplicate).unwrap();
        let mut indefinite = baseline.canonical_event().to_vec();
        assert_eq!(indefinite[0], 0xa8);
        indefinite[0] = 0xbf;
        indefinite.push(0xff);
        for bytes in [trailing, duplicate, indefinite] {
            let altered = StoredEvent::new(b"a".to_vec(), 0, bytes, vec![0]);
            assert!(validate_completion_prefix(&[altered], b"a").is_err());
        }
    }
}
