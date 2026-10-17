//! Behaviour of the RFC 9162 tree: roots and proofs against the RFC's own recursive definition
//! and against `ct-merkle`, cost per append, and the verifier side against the generator side.

use std::cell::Cell;

use sha2::{Digest, Sha256};

use super::*;

/// RFC 6962 hashing: `SHA-256(0x00 || data)` and `SHA-256(0x01 || left || right)`.
struct Rfc6962;

impl MerkleHasher for Rfc6962 {
    fn leaf(&self, data: &[u8]) -> Hash {
        Sha256::new()
            .chain_update([0u8])
            .chain_update(data)
            .finalize()
            .into()
    }

    fn node(&self, left: &Hash, right: &Hash) -> Hash {
        Sha256::new()
            .chain_update([1u8])
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }
}

/// Counts node and leaf hashes of an inner hasher.
struct Counting<'a, H> {
    inner: &'a H,
    hashes: Cell<u64>,
}

impl<H: MerkleHasher> MerkleHasher for Counting<'_, H> {
    fn leaf(&self, data: &[u8]) -> Hash {
        self.hashes.set(self.hashes.get() + 1);
        self.inner.leaf(data)
    }

    fn node(&self, left: &Hash, right: &Hash) -> Hash {
        self.hashes.set(self.hashes.get() + 1);
        self.inner.node(left, right)
    }
}

fn leaf_hashes(hasher: &impl MerkleHasher, n: u64) -> Vec<Hash> {
    (0..n).map(|i| hasher.leaf(&i.to_be_bytes())).collect()
}

/// RFC 9162 §2.1.1 `MTH`, transcribed from the definition.
fn mth(hasher: &impl MerkleHasher, leaves: &[Hash]) -> Hash {
    match leaves.len() {
        1 => leaves[0],
        n => {
            let k = split_point(n as u64) as usize;
            hasher.node(&mth(hasher, &leaves[..k]), &mth(hasher, &leaves[k..]))
        }
    }
}

/// RFC 9162 §2.1.3.1 `PATH`, transcribed from the definition.
fn path(hasher: &impl MerkleHasher, m: usize, leaves: &[Hash]) -> Vec<Hash> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let k = split_point(leaves.len() as u64) as usize;
    if m < k {
        let mut proof = path(hasher, m, &leaves[..k]);
        proof.push(mth(hasher, &leaves[k..]));
        proof
    } else {
        let mut proof = path(hasher, m - k, &leaves[k..]);
        proof.push(mth(hasher, &leaves[..k]));
        proof
    }
}

/// RFC 9162 §2.1.4.1 `SUBPROOF`, transcribed from the definition.
fn subproof(hasher: &impl MerkleHasher, m: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    if m == leaves.len() {
        return if complete {
            Vec::new()
        } else {
            vec![mth(hasher, leaves)]
        };
    }
    let k = split_point(leaves.len() as u64) as usize;
    if m <= k {
        let mut proof = subproof(hasher, m, &leaves[..k], complete);
        proof.push(mth(hasher, &leaves[k..]));
        proof
    } else {
        let mut proof = subproof(hasher, m - k, &leaves[k..], false);
        proof.push(mth(hasher, &leaves[..k]));
        proof
    }
}

#[test]
fn frontier_and_tree_roots_equal_the_rfc_9162_root_for_every_size_up_to_1024() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 1024);
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves.clone());
    let mut frontier = Frontier::new();
    for (i, leaf) in leaves.iter().enumerate() {
        frontier.push_leaf_hash(&hasher, *leaf);
        let size = i + 1;
        let expected = mth(&hasher, &leaves[..size]);
        assert_eq!(
            frontier.root(&hasher),
            Some(expected),
            "frontier, size {size}"
        );
        assert_eq!(tree.root(size as u64), Ok(expected), "tree, size {size}");
    }
    assert_eq!(
        prefix_roots(&hasher, &leaves).last(),
        tree.root(1024).as_ref().ok()
    );
}

#[test]
fn proofs_equal_the_rfc_9162_definitions_for_every_index_and_size_up_to_67() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 67);
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves.clone());
    for size in 1..=67usize {
        for index in 0..size {
            assert_eq!(
                tree.inclusion_proof(index as u64, size as u64).unwrap(),
                path(&hasher, index, &leaves[..size]),
                "inclusion {index} of {size}"
            );
        }
        for from in 1..=size {
            assert_eq!(
                tree.consistency_proof(from as u64, size as u64).unwrap(),
                subproof(&hasher, from, &leaves[..size], true),
                "consistency {from} to {size}"
            );
        }
    }
}

#[test]
fn proofs_of_a_1024_leaf_tree_equal_the_definitions_at_sampled_positions() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 1024);
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves.clone());
    for size in [1023usize, 1024] {
        for index in (0..size).step_by(37).chain([size - 1]) {
            assert_eq!(
                tree.inclusion_proof(index as u64, size as u64).unwrap(),
                path(&hasher, index, &leaves[..size])
            );
        }
        for from in (1..=size).step_by(41).chain([size - 1, size]) {
            assert_eq!(
                tree.consistency_proof(from as u64, size as u64).unwrap(),
                subproof(&hasher, from, &leaves[..size], true)
            );
        }
    }
}

#[test]
fn the_verifier_algorithm_accepts_every_generated_proof_and_reproduces_both_roots() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 70);
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves.clone());
    for size in 1..=70u64 {
        let root = tree.root(size).unwrap();
        for index in 0..size {
            let proof = tree.inclusion_proof(index, size).unwrap();
            assert_eq!(
                root_from_inclusion_proof(&hasher, index, size, leaves[index as usize], &proof),
                Ok(root)
            );
        }
        for from in 1..=size {
            let proof = tree.consistency_proof(from, size).unwrap();
            assert_eq!(
                root_from_consistency_proof(&hasher, from, size, tree.root(from).unwrap(), &proof),
                Ok(root),
                "{from} to {size}"
            );
        }
    }
}

#[test]
fn the_verifier_algorithm_refuses_a_tampered_or_misshapen_proof() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 13);
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves.clone());
    let root = tree.root(13).unwrap();
    let mut proof = tree.inclusion_proof(5, 13).unwrap();
    proof[0][0] ^= 1;
    assert_ne!(
        root_from_inclusion_proof(&hasher, 5, 13, leaves[5], &proof),
        Ok(root)
    );
    proof.pop();
    assert_eq!(
        root_from_inclusion_proof(&hasher, 5, 13, leaves[5], &proof),
        Err(MerkleError::ProofShape)
    );
    let mut consistency = tree.consistency_proof(6, 13).unwrap();
    consistency[1][0] ^= 1;
    assert_ne!(
        root_from_consistency_proof(&hasher, 6, 13, tree.root(6).unwrap(), &consistency),
        Ok(root),
        "a tampered node may only change the implied new root, never reproduce the real one"
    );
    consistency[0][0] ^= 1;
    assert!(
        root_from_consistency_proof(&hasher, 6, 13, tree.root(6).unwrap(), &consistency).is_err(),
        "a tampered node under the old root fails the old-root check"
    );
    assert_eq!(
        tree.inclusion_proof(13, 13),
        Err(MerkleError::OutOfRange),
        "an index equal to the size is outside the tree"
    );
}

#[test]
fn one_push_and_one_root_cost_at_most_twice_the_log_of_the_tree_size_up_to_65536() {
    let base = TrellisHasher;
    let counting = Counting {
        inner: &base,
        hashes: Cell::new(0),
    };
    let mut frontier = Frontier::new();
    for n in 1..=65_536u64 {
        let leaf = base.leaf(&n.to_be_bytes());
        let before = counting.hashes.get();
        frontier.push_leaf_hash(&counting, leaf);
        assert!(frontier.root(&counting).is_some());
        let spent = counting.hashes.get() - before;
        let bound = 2 * u64::from(n.next_power_of_two().trailing_zeros()).max(1);
        assert!(
            spent <= bound,
            "size {n}: {spent} hashes exceed 2*ceil(log2 n) = {bound}"
        );
        assert!(
            frontier.nodes().len() <= 64,
            "the frontier is at most 64 hashes"
        );
    }
}

#[test]
fn a_frontier_survives_storage_and_keeps_appending_to_the_same_roots() {
    let hasher = TrellisHasher;
    let leaves = leaf_hashes(&hasher, 300);
    let mut live = Frontier::new();
    let mut restored = Frontier::new();
    for leaf in &leaves {
        live.push_leaf_hash(&hasher, *leaf);
        restored = Frontier::from_bytes(restored.size(), &restored.to_bytes()).unwrap();
        restored.push_leaf_hash(&hasher, *leaf);
        assert_eq!(live, restored);
        assert_eq!(
            restored.to_bytes().len(),
            32 * restored.size().count_ones() as usize
        );
    }
    assert_eq!(
        Frontier::from_bytes(5, &[0u8; 32]),
        Err(MerkleError::FrontierShape),
        "five leaves need two stored hashes"
    );
}

#[test]
fn roots_and_proofs_equal_ct_merkle_under_the_rfc_6962_hasher() {
    use ct_merkle::mem_backed_tree::MemoryBackedTree;

    let hasher = Rfc6962;
    let items: Vec<Vec<u8>> = (0..130u64).map(|i| i.to_be_bytes().to_vec()).collect();
    let leaves: Vec<Hash> = items.iter().map(|item| hasher.leaf(item)).collect();
    let tree = MerkleTree::from_leaf_hashes(&hasher, leaves);
    for size in 1..=items.len() {
        let mut oracle = MemoryBackedTree::<Sha256, Vec<u8>>::new();
        for item in &items[..size] {
            oracle.push(item.clone());
        }
        let size64 = size as u64;
        assert_eq!(
            tree.root(size64).unwrap().as_slice(),
            oracle.root().as_bytes().as_slice(),
            "root of {size}"
        );
        for index in 0..size {
            assert_eq!(
                tree.inclusion_proof(index as u64, size64).unwrap().concat(),
                oracle.prove_inclusion(index).as_bytes(),
                "inclusion {index} of {size}"
            );
        }
        for from in 1..size {
            assert_eq!(
                tree.consistency_proof(from as u64, size64)
                    .unwrap()
                    .concat(),
                oracle.prove_consistency(size - from).as_bytes(),
                "consistency {from} to {size}"
            );
        }
    }
}
