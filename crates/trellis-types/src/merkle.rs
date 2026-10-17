// Rust guideline compliant 2026-02-21
//! RFC 9162 Merkle tree over a caller-supplied hasher (Core §11.3).
//!
//! Core §11.3 fixes the *shape* of the ledger tree: the RFC 6962/9162 tree, where a tree of `n`
//! leaves splits at the largest power of two below `n`. Only the two hash functions are
//! Trellis-specific (domain-separated SHA-256, [`TrellisHasher`]). Everything here is generic over
//! [`MerkleHasher`], so the same code runs under the RFC 6962 hasher in the oracle tests.
//!
//! Three structures cover every consumer:
//!
//! - [`Frontier`] is the compact range (RFC 9162's "perfect subtrees of the binary
//!   decomposition", Trillian `compact.Range`): `popcount(n)` hashes. An append pushes one leaf and
//!   reads the root in `O(log n)` hashes and `O(log n)` stored bytes, with no history.
//! - [`MerkleTree`] holds every perfect subtree of a closed leaf list and serves inclusion and
//!   consistency proofs in `O(log n)` each after one `O(n)` build.
//! - [`root_from_inclusion_proof`] and [`root_from_consistency_proof`] are the verifier side,
//!   ported from transparency-dev/merkle.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use crate::domain_separated_sha256;

/// One Merkle node.
pub type Hash = [u8; 32];

/// Domain tag for the hash of a leaf (Core §11.3).
pub const MERKLE_LEAF_DOMAIN: &str = "trellis-merkle-leaf-v1";

/// Domain tag for the hash of an interior node (Core §11.3).
pub const MERKLE_INTERIOR_DOMAIN: &str = "trellis-merkle-interior-v1";

/// The two hash functions that distinguish one RFC 9162-shaped tree from another.
pub trait MerkleHasher {
    /// Hashes the data of one leaf.
    fn leaf(&self, data: &[u8]) -> Hash;

    /// Hashes two children into their parent.
    fn node(&self, left: &Hash, right: &Hash) -> Hash;
}

/// Core §11.3 hashing: `trellis-merkle-leaf-v1` over the canonical event hash, and
/// `trellis-merkle-interior-v1` over the concatenated children.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrellisHasher;

impl MerkleHasher for TrellisHasher {
    fn leaf(&self, data: &[u8]) -> Hash {
        domain_separated_sha256(MERKLE_LEAF_DOMAIN, data)
    }

    fn node(&self, left: &Hash, right: &Hash) -> Hash {
        let mut joined = [0u8; 64];
        joined[..32].copy_from_slice(left);
        joined[32..].copy_from_slice(right);
        domain_separated_sha256(MERKLE_INTERIOR_DOMAIN, &joined)
    }
}

/// A malformed frontier, size, index or proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// A frontier does not hold `popcount(size)` hashes.
    FrontierShape,
    /// An index or size is outside the tree.
    OutOfRange,
    /// A proof has the wrong number of hashes for its sizes.
    ProofShape,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FrontierShape => "Merkle frontier does not hold popcount(size) hashes",
            Self::OutOfRange => "Merkle index or size is outside the tree",
            Self::ProofShape => "Merkle proof has the wrong number of hashes",
        })
    }
}

impl std::error::Error for MerkleError {}

/// The compact range of a tree: the roots of its perfect subtrees, largest first.
///
/// A tree of `n` leaves decomposes along the set bits of `n`; the frontier keeps one hash per set
/// bit. [`Self::root`] folds them right to left, which is the RFC 9162 root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    nodes: Vec<Hash>,
}

impl Frontier {
    /// The frontier of the empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Perfect-subtree roots, largest first.
    #[must_use]
    pub fn nodes(&self) -> &[Hash] {
        &self.nodes
    }

    /// Rebuilds a frontier read from storage.
    ///
    /// # Errors
    /// [`MerkleError::FrontierShape`] unless `nodes` holds exactly `popcount(size)` hashes.
    pub fn from_nodes(size: u64, nodes: Vec<Hash>) -> Result<Self, MerkleError> {
        if nodes.len() != size.count_ones() as usize {
            return Err(MerkleError::FrontierShape);
        }
        Ok(Self { size, nodes })
    }

    /// Rebuilds a frontier from the concatenated hashes [`Self::to_bytes`] wrote.
    ///
    /// # Errors
    /// [`MerkleError::FrontierShape`] unless `bytes` is exactly `popcount(size)` hashes.
    pub fn from_bytes(size: u64, bytes: &[u8]) -> Result<Self, MerkleError> {
        if !bytes.len().is_multiple_of(32) {
            return Err(MerkleError::FrontierShape);
        }
        let nodes = bytes
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().expect("chunks_exact(32)"))
            .collect();
        Self::from_nodes(size, nodes)
    }

    /// The hashes, concatenated largest first. `popcount(size) * 32` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.nodes.concat()
    }

    /// Adds a leaf whose hash is already computed. Costs `trailing_ones(size)` node hashes.
    pub fn push_leaf_hash<H: MerkleHasher>(&mut self, hasher: &H, leaf_hash: Hash) {
        let mut carry = leaf_hash;
        for _ in 0..self.size.trailing_ones() {
            let left = self.nodes.pop().expect("one node per set bit");
            carry = hasher.node(&left, &carry);
        }
        self.nodes.push(carry);
        self.size += 1;
    }

    /// Hashes `data` as a leaf and adds it.
    pub fn push<H: MerkleHasher>(&mut self, hasher: &H, data: &[u8]) {
        self.push_leaf_hash(hasher, hasher.leaf(data));
    }

    /// RFC 9162 root; `None` for the empty tree. Costs `popcount(size) - 1` node hashes.
    #[must_use]
    pub fn root<H: MerkleHasher>(&self, hasher: &H) -> Option<Hash> {
        let (last, rest) = self.nodes.split_last()?;
        Some(
            rest.iter()
                .rev()
                .fold(*last, |right, left| hasher.node(left, &right)),
        )
    }
}

/// Roots of every prefix of `leaf_hashes`: element `i` is the root of the first `i + 1` leaves.
/// One frontier pass, `O(n log n)` hashes.
#[must_use]
pub fn prefix_roots<H: MerkleHasher>(hasher: &H, leaf_hashes: &[Hash]) -> Vec<Hash> {
    let mut frontier = Frontier::new();
    leaf_hashes
        .iter()
        .map(|leaf| {
            frontier.push_leaf_hash(hasher, *leaf);
            frontier
                .root(hasher)
                .expect("a pushed leaf makes the tree non-empty")
        })
        .collect()
}

/// Largest power of two strictly below `n` (`n > 1`): the RFC 9162 split point.
fn split_point(n: u64) -> u64 {
    debug_assert!(n > 1);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Every perfect subtree of a closed leaf list, for proofs.
///
/// `levels[l][i]` is the root of leaves `[i * 2^l, (i + 1) * 2^l)`. The roots of imperfect ranges
/// that proofs need (all of them end at a tree size) are derived from the perfect ones and
/// memoised, so a proof costs `O(log n)` after the `O(n)` build.
pub struct MerkleTree<'h, H: MerkleHasher> {
    hasher: &'h H,
    levels: Vec<Vec<Hash>>,
    imperfect: RefCell<HashMap<(u64, u64), Hash>>,
}

impl<'h, H: MerkleHasher> MerkleTree<'h, H> {
    /// Builds the tree over `leaf_hashes`. `leaf_hashes.len() - 1` node hashes.
    #[must_use]
    pub fn from_leaf_hashes(hasher: &'h H, leaf_hashes: Vec<Hash>) -> Self {
        let mut levels = vec![leaf_hashes];
        while levels.last().is_some_and(|level| level.len() > 1) {
            let below = levels.last().expect("checked");
            let above = below
                .chunks_exact(2)
                .map(|pair| hasher.node(&pair[0], &pair[1]))
                .collect();
            levels.push(above);
        }
        Self {
            hasher,
            levels,
            imperfect: RefCell::default(),
        }
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Root of the first `size` leaves.
    ///
    /// # Errors
    /// [`MerkleError::OutOfRange`] for `size` of zero or beyond the tree.
    pub fn root(&self, size: u64) -> Result<Hash, MerkleError> {
        if size == 0 || size > self.size() {
            return Err(MerkleError::OutOfRange);
        }
        Ok(self.range_root(0, size))
    }

    /// RFC 9162 `MTH(D[a:b])`, `0 <= a < b <= size`.
    fn range_root(&self, a: u64, b: u64) -> Hash {
        let len = b - a;
        if len.is_power_of_two() && a.is_multiple_of(len) {
            return self.levels[len.trailing_zeros() as usize][(a / len) as usize];
        }
        if let Some(root) = self.imperfect.borrow().get(&(a, b)) {
            return *root;
        }
        let k = split_point(len);
        let root = self
            .hasher
            .node(&self.range_root(a, a + k), &self.range_root(a + k, b));
        self.imperfect.borrow_mut().insert((a, b), root);
        root
    }

    /// RFC 9162 §2.1.3.1 audit path of leaf `index` in the first `size` leaves.
    ///
    /// # Errors
    /// [`MerkleError::OutOfRange`] unless `index < size <= self.size()`.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>, MerkleError> {
        if index >= size || size > self.size() {
            return Err(MerkleError::OutOfRange);
        }
        let (mut m, mut a, mut b) = (index, 0, size);
        let mut path = Vec::new();
        while b - a > 1 {
            let k = split_point(b - a);
            if m < k {
                path.push(self.range_root(a + k, b));
                b = a + k;
            } else {
                path.push(self.range_root(a, a + k));
                m -= k;
                a += k;
            }
        }
        path.reverse();
        Ok(path)
    }

    /// RFC 9162 §2.1.4.1 consistency proof from the first `from` leaves to the first `to`.
    ///
    /// # Errors
    /// [`MerkleError::OutOfRange`] unless `0 < from <= to <= self.size()`.
    pub fn consistency_proof(&self, from: u64, to: u64) -> Result<Vec<Hash>, MerkleError> {
        if from == 0 || from > to || to > self.size() {
            return Err(MerkleError::OutOfRange);
        }
        let (mut m, mut a, b) = (from, 0, to);
        let mut b = b;
        let mut complete = true;
        let mut path = Vec::new();
        while m != b - a {
            let k = split_point(b - a);
            if m <= k {
                path.push(self.range_root(a + k, b));
                b = a + k;
            } else {
                path.push(self.range_root(a, a + k));
                m -= k;
                a += k;
                complete = false;
            }
        }
        if !complete {
            path.push(self.range_root(a, b));
        }
        path.reverse();
        Ok(path)
    }
}

fn inner_proof_size(index: u64, size: u64) -> usize {
    let xor = index ^ (size - 1);
    (u64::BITS - xor.leading_zeros()) as usize
}

fn decomp_inclusion_proof(index: u64, size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    let border = (index >> inner).count_ones() as usize;
    (inner, border)
}

fn chain_inner<H: MerkleHasher>(hasher: &H, mut seed: Hash, proof: &[Hash], index: u64) -> Hash {
    for (i, sibling) in proof.iter().enumerate() {
        seed = if (index >> i) & 1 == 0 {
            hasher.node(&seed, sibling)
        } else {
            hasher.node(sibling, &seed)
        };
    }
    seed
}

fn chain_inner_right<H: MerkleHasher>(
    hasher: &H,
    mut seed: Hash,
    proof: &[Hash],
    index: u64,
) -> Hash {
    for (i, sibling) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            seed = hasher.node(sibling, &seed);
        }
    }
    seed
}

fn chain_border_right<H: MerkleHasher>(hasher: &H, mut seed: Hash, proof: &[Hash]) -> Hash {
    for sibling in proof {
        seed = hasher.node(sibling, &seed);
    }
    seed
}

/// Root implied by an inclusion proof (RFC 9162 §2.1.3.2).
///
/// # Errors
/// [`MerkleError::OutOfRange`] unless `leaf_index < tree_size`, [`MerkleError::ProofShape`] unless
/// the proof has exactly the hashes those two numbers imply.
pub fn root_from_inclusion_proof<H: MerkleHasher>(
    hasher: &H,
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: Hash,
    proof: &[Hash],
) -> Result<Hash, MerkleError> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(MerkleError::OutOfRange);
    }
    let (inner, border) = decomp_inclusion_proof(leaf_index, tree_size);
    if proof.len() != inner + border {
        return Err(MerkleError::ProofShape);
    }
    let node = chain_inner(hasher, leaf_hash, &proof[..inner], leaf_index);
    Ok(chain_border_right(hasher, node, &proof[inner..]))
}

/// Root of the larger tree implied by a consistency proof, after checking that the proof also
/// reproduces `root1` (RFC 9162 §2.1.4.2).
///
/// # Errors
/// [`MerkleError::OutOfRange`] for impossible sizes, [`MerkleError::ProofShape`] for a proof of the
/// wrong length or one that does not reproduce `root1`.
pub fn root_from_consistency_proof<H: MerkleHasher>(
    hasher: &H,
    size1: u64,
    size2: u64,
    root1: Hash,
    proof: &[Hash],
) -> Result<Hash, MerkleError> {
    if size2 < size1 || size1 == 0 {
        return Err(MerkleError::OutOfRange);
    }
    if size1 == size2 {
        return if proof.is_empty() {
            Ok(root1)
        } else {
            Err(MerkleError::ProofShape)
        };
    }
    if proof.is_empty() {
        return Err(MerkleError::ProofShape);
    }
    let (mut inner, border) = decomp_inclusion_proof(size1 - 1, size2);
    let shift = size1.trailing_zeros() as usize;
    if inner < shift {
        return Err(MerkleError::ProofShape);
    }
    inner -= shift;
    let (seed, start) = if size1 == 1u64 << shift {
        (root1, 0)
    } else {
        (proof[0], 1)
    };
    if proof.len() != start + inner + border {
        return Err(MerkleError::ProofShape);
    }
    let suffix = &proof[start..];
    let mask = (size1 - 1) >> shift;
    let hash1 = chain_inner_right(hasher, seed, &suffix[..inner], mask);
    let hash1 = chain_border_right(hasher, hash1, &suffix[inner..]);
    if hash1 != root1 {
        return Err(MerkleError::ProofShape);
    }
    let hash2 = chain_inner(hasher, seed, &suffix[..inner], mask);
    Ok(chain_border_right(hasher, hash2, &suffix[inner..]))
}

#[cfg(test)]
mod tests;
