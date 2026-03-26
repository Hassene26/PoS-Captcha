use log::debug;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::block_generation::utils::{
    NUM_BYTES_IN_BLOCK, NUM_BYTES_IN_BLOCK_GROUP,
};

/// Deterministic random path generator.
/// Given a seed and iteration, produces the next (block_id, position, new_seed).
/// This function MUST produce identical results on both Prover and Verifier.
/// Ported as-is from the thesis.
pub fn random_path_generator(seed: u8, iteration: u64, num_block_groups: u64) -> (u32, u32, u8) {
    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();
    let mut hasher_seed = DefaultHasher::new();

    seed.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % num_block_groups;

    seed.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK_GROUP as u64;

    new_id.hash(&mut hasher_seed);
    new_p.hash(&mut hasher_seed);
    iteration.hash(&mut hasher_seed);
    let new_seed = hasher_seed.finish() % u8::MAX as u64;

    debug!("path_gen: block_id={}, pos={}, new_seed={}", new_id, new_p, new_seed);
    (
        new_id.try_into().unwrap(),
        new_p.try_into().unwrap(),
        new_seed.try_into().unwrap(),
    )
}
