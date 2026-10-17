// Rust guideline compliant 2026-02-21
//! Checkpoint issuance (Core §11): the signed commitment to the tree an append produced.
//!
//! One checkpoint exists per tree size. [`issue_checkpoint`] derives the next one from the prior
//! checkpoint's digest and [`Frontier`] alone, so issuing costs `O(log n)` hashes and one
//! signature whatever the ledger's length. An export is assembled from the stored checkpoints;
//! nothing re-signs a prefix.

use integrity_cose::{
    SUITE_ID_PHASE_1, derive_kid, sig_structure_bytes, sign_ed25519, sign1_bytes,
    substrate_protected_header,
};
use trellis_cddl::parse_ed25519_cose_key;
use trellis_types::merkle::{Frontier, MerkleHasher, TrellisHasher};
use trellis_types::{ArtifactType, CheckpointPayload, checkpoint_digest};

use crate::{AppendError, SigningKeyMaterial};

/// COSE EdDSA algorithm identifier used by Trellis Phase 1.
const ALG_EDDSA: i32 = -8;

/// What the next checkpoint continues from.
#[derive(Clone, Copy, Debug)]
pub struct PriorCheckpoint<'a> {
    /// Digest of the prior checkpoint (`prev_checkpoint_hash` of the next one).
    pub digest: [u8; 32],
    /// The tree after the prior append.
    pub frontier: &'a Frontier,
}

/// A signed checkpoint plus the state the following append continues from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCheckpoint {
    pub tree_size: u64,
    pub tree_head_hash: [u8; 32],
    /// Core §11.2 digest of the payload; the next checkpoint's `prev_checkpoint_hash`.
    pub digest: [u8; 32],
    /// Tagged COSE_Sign1, exactly as `040-checkpoints.cbor` carries it.
    pub sign1: Vec<u8>,
    /// The tree including the appended leaf.
    pub frontier: Frontier,
}

/// Issues the checkpoint that commits to the tree after appending `canonical_event_hash`.
///
/// `timestamp` is the event's `authored_at`, which is what keeps checkpoint bytes a function of
/// the ledger alone (Core §11.2). `prior` is `None` for the first event of a scope.
///
/// # Errors
/// Returns an error when the signing key cannot be parsed or the payload cannot be encoded.
pub fn issue_checkpoint(
    signing_key: &SigningKeyMaterial,
    scope: &[u8],
    prior: Option<PriorCheckpoint<'_>>,
    canonical_event_hash: [u8; 32],
    timestamp: (u64, u32),
) -> Result<IssuedCheckpoint, AppendError> {
    let key = parse_ed25519_cose_key(signing_key.as_bytes())
        .map_err(|error| AppendError::new(error.to_string()))?;
    let hasher = TrellisHasher;
    let mut frontier = prior.map_or_else(Frontier::new, |prior| prior.frontier.clone());
    frontier.push(&hasher, &canonical_event_hash);
    let tree_head_hash = frontier
        .root(&hasher)
        .ok_or_else(|| AppendError::new("a pushed leaf makes the tree non-empty"))?;
    let payload = CheckpointPayload {
        scope: scope.to_vec(),
        tree_size: frontier.size(),
        tree_head_hash,
        timestamp,
        prev_checkpoint_hash: prior.map(|prior| prior.digest),
    }
    .encode()
    .map_err(|error| AppendError::new(error.to_string()))?;
    let protected_header = substrate_protected_header(
        ALG_EDDSA,
        &derive_kid(SUITE_ID_PHASE_1, key.public_key),
        SUITE_ID_PHASE_1,
        ArtifactType::Checkpoint.cose_value(),
    );
    let signature = sign_ed25519(
        key.private_seed,
        &sig_structure_bytes(&protected_header, &payload),
    );
    Ok(IssuedCheckpoint {
        tree_size: frontier.size(),
        tree_head_hash,
        digest: checkpoint_digest(scope, &payload),
        sign1: sign1_bytes(&protected_header, &payload, signature),
        frontier,
    })
}

/// The Merkle leaf hash of an event: Core §11.3 domain separation over its canonical event hash.
#[must_use]
pub fn event_leaf_hash(canonical_event_hash: &[u8; 32]) -> [u8; 32] {
    TrellisHasher.leaf(canonical_event_hash)
}

#[cfg(test)]
mod tests {
    use trellis_types::merkle::{MerkleTree, TrellisHasher};

    use super::*;

    fn key() -> SigningKeyMaterial {
        SigningKeyMaterial::new(
            include_bytes!("../../../fixtures/vectors/_keys/issuer-001.cose_key").to_vec(),
        )
    }

    fn event_hash(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn each_checkpoint_commits_to_the_tree_and_chains_to_the_one_before() {
        let hasher = TrellisHasher;
        let mut prior: Option<IssuedCheckpoint> = None;
        let mut leaves = Vec::new();
        for i in 0..20u8 {
            leaves.push(event_leaf_hash(&event_hash(i)));
            let issued = issue_checkpoint(
                &key(),
                b"scope",
                prior.as_ref().map(|p| PriorCheckpoint {
                    digest: p.digest,
                    frontier: &p.frontier,
                }),
                event_hash(i),
                (1_700_000_000 + u64::from(i), 0),
            )
            .unwrap();
            let payload = CheckpointPayload::from_sign1(&issued.sign1).unwrap();
            assert_eq!(payload.tree_size, u64::from(i) + 1);
            assert_eq!(
                payload.tree_head_hash,
                MerkleTree::from_leaf_hashes(&hasher, leaves.clone())
                    .root(leaves.len() as u64)
                    .unwrap()
            );
            assert_eq!(
                payload.prev_checkpoint_hash,
                prior.as_ref().map(|p| p.digest)
            );
            assert_eq!(payload.timestamp, (1_700_000_000 + u64::from(i), 0));
            assert_eq!(
                issued.digest,
                checkpoint_digest(b"scope", &payload.encode().unwrap())
            );
            prior = Some(issued);
        }
    }

    #[test]
    fn issuing_twice_from_the_same_prior_gives_identical_bytes() {
        let first = issue_checkpoint(&key(), b"scope", None, event_hash(1), (5, 6)).unwrap();
        let again = issue_checkpoint(&key(), b"scope", None, event_hash(1), (5, 6)).unwrap();
        assert_eq!(first, again, "Ed25519 signatures are deterministic");
    }
}
