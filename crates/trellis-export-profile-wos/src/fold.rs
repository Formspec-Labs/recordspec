// Rust guideline compliant 2026-02-21
//! The append-time fold of the signature export's finite limits.
//!
//! [`crate::signature_evidence_members`] judges a whole prefix: with any signature affirmation
//! present, the prefix must hold at most [`MAX_MEMBERS`] events, the events, the 062 catalog and
//! the distinct original payloads together must fit [`MAX_BYTES`], and there may be at most
//! `MAX_MEMBERS - 1` distinct originals. Every one of those is a function of seven running
//! quantities, so an append carries them forward with its checkpoint instead of re-reading the
//! prefix. The fold accepts exactly when the whole-prefix judgement accepts (the property test in
//! this module holds the two together).
//!
//! Two originals with the same `trellis-content-v1` hash are the same bytes unless SHA-256
//! collides; the fold relies on that where the whole-prefix judgement compares the bytes.

use std::collections::BTreeSet;

use integrity_cbor::{
    decode_cbor_value, domain_separated_sha256, encode_canonical_cbor_value, map_lookup_bytes,
    map_lookup_map,
};
use stack_common_error::StackError;
use trellis_server_ports::event_codec::{cbor_bad_request, event_summary};
use trellis_types::StoredEvent;

use crate::{MAX_BYTES, MAX_MEMBERS, wos_signature_affirmation_event_type};

const STATE_VERSION: u8 = 1;
const FIXED_LEN: usize = 1 + 4 * 8 + 4;

/// Running quantities of the signature export limits for one scope's prefix.
#[derive(Debug, Default, PartialEq, Eq)]
struct SignatureExportState {
    /// Sum of every event's canonical bytes.
    event_bytes: u64,
    /// Signature affirmations seen.
    affirmations: u64,
    /// Sum of the canonical encodings of the 062 catalog rows.
    catalog_row_bytes: u64,
    /// Sum of the distinct original payloads' lengths.
    original_bytes: u64,
    /// Content hashes of the distinct original payloads.
    originals: BTreeSet<[u8; 32]>,
}

impl SignatureExportState {
    fn decode(bytes: &[u8]) -> Result<Self, StackError> {
        let corrupt = || StackError::internal("signature export fold state corrupt");
        if bytes.len() < FIXED_LEN || bytes[0] != STATE_VERSION {
            return Err(corrupt());
        }
        let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let count = u32::from_be_bytes(bytes[33..37].try_into().expect("4 bytes")) as usize;
        if bytes.len() != FIXED_LEN + 32 * count || count >= MAX_MEMBERS {
            return Err(corrupt());
        }
        let originals = bytes[FIXED_LEN..]
            .chunks_exact(32)
            .map(|chunk| <[u8; 32]>::try_from(chunk).expect("32 bytes"))
            .collect::<BTreeSet<_>>();
        if originals.len() != count {
            return Err(corrupt());
        }
        Ok(Self {
            event_bytes: word(1),
            affirmations: word(9),
            catalog_row_bytes: word(17),
            original_bytes: word(25),
            originals,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN + 32 * self.originals.len());
        out.push(STATE_VERSION);
        for word in [
            self.event_bytes,
            self.affirmations,
            self.catalog_row_bytes,
            self.original_bytes,
        ] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(&(self.originals.len() as u32).to_be_bytes());
        for hash in &self.originals {
            out.extend_from_slice(hash);
        }
        out
    }
}

/// Encoded length of a CBOR array header for `count` items.
fn array_header_len(count: u64) -> u64 {
    match count {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

pub(crate) fn fold_append(
    scope: &[u8],
    prior: Option<&[u8]>,
    event: &StoredEvent,
    tree_size: u64,
) -> Result<Vec<u8>, StackError> {
    let mut state = prior.map_or_else(
        || Ok(SignatureExportState::default()),
        SignatureExportState::decode,
    )?;
    let summary = event_summary(event)?;
    state.event_bytes = state
        .event_bytes
        .checked_add(event.canonical_event().len() as u64)
        .ok_or_else(|| StackError::bad_request("signature evidence aggregate byte limit"))?;
    if summary.event_type == wos_signature_affirmation_event_type() {
        if event.scope() != scope {
            return Err(StackError::bad_request("signature export scope mismatch"));
        }
        let row = trellis_verify_wos::signature_catalog_row(scope, tree_size - 1, event)
            .map_err(|_| StackError::bad_request("actual signature affirmation inventory refused"))?
            .ok_or_else(|| StackError::internal("actual affirmation catalog row absent"))?;
        state.catalog_row_bytes += encode_canonical_cbor_value(&row)
            .map_err(|_| StackError::bad_request("actual signature affirmation inventory refused"))?
            .len() as u64;
        state.affirmations += 1;
        let canonical = decode_cbor_value(event.canonical_event()).map_err(cbor_bad_request)?;
        let map = canonical
            .as_map()
            .ok_or_else(|| StackError::bad_request("invalid actual signature event"))?;
        let reference = map_lookup_map(map, "payload_ref").map_err(cbor_bad_request)?;
        let original = map_lookup_bytes(reference, "ciphertext").map_err(cbor_bad_request)?;
        let hash = domain_separated_sha256(trellis_types::CONTENT_DOMAIN, &original);
        if summary.content_hash != hash {
            return Err(StackError::bad_request(
                "signature payload content hash mismatch",
            ));
        }
        if state.originals.insert(hash) {
            state.original_bytes += original.len() as u64;
            if state.originals.len() >= MAX_MEMBERS {
                return Err(StackError::bad_request("signature evidence member limit"));
            }
        }
    }
    if state.affirmations > 0 {
        let catalog = array_header_len(state.affirmations) + state.catalog_row_bytes;
        if tree_size > MAX_MEMBERS as u64 {
            return Err(StackError::bad_request(
                "signature prefix event count limit",
            ));
        }
        if state.event_bytes + catalog + state.original_bytes > MAX_BYTES as u64 {
            return Err(StackError::bad_request(
                "signature evidence aggregate byte limit",
            ));
        }
    }
    Ok(state.encode())
}

#[cfg(test)]
mod tests;
