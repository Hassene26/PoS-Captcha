use crate::block_generation::utils::FRAGMENT_SIZE;
use crate::merkle_tree::structs::*;
use log::debug;

/// Recompute the Merkle root hash from a proof and a self_fragment.
/// Ported from thesis — used by the Verifier to validate inclusion proofs.
pub fn get_root_hash(
    proof: &Proof,
    self_fragment: [u8; FRAGMENT_SIZE],
) -> [u8; 32] {
    let mut hash_final = blake3::hash(&self_fragment);
    for sibling in &proof.siblings {
        let sibling_hash = &sibling.hash;
        match sibling.direction {
            Direction::Left => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(sibling_hash);
                hasher.update(hash_final.as_bytes());
                hash_final = hasher.finalize();
            }
            Direction::Right => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(hash_final.as_bytes());
                hasher.update(sibling_hash);
                hash_final = hasher.finalize();
            }
        }
    }
    debug!("Computed root hash: {:?}", hash_final.as_bytes());
    *hash_final.as_bytes()
}
