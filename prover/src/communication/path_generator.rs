use log::debug;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::block_generation::utils::{
    NUM_BYTES_IN_BLOCK, NUM_BYTES_IN_BLOCK_GROUP,
};

/// Deterministic path generator.
/// Given a seed and iteration, produces the next (block_id, position).
/// The seed MUST be rolled by the caller via `derive_next_seed` using the byte
/// actually read at (block_id, position), so that target i+1 cannot be
/// computed without first reading the plot byte at target i.
/// Prover and Verifier must use identical hashing.
pub fn random_path_generator(seed: u8, iteration: u64, num_block_groups: u64) -> (u32, u32) {
    let mut hasher_nxt_block = DefaultHasher::new();
    seed.hash(&mut hasher_nxt_block);
    iteration.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % num_block_groups;

    let mut hasher_nxt_pos = DefaultHasher::new();
    seed.hash(&mut hasher_nxt_pos);
    iteration.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK_GROUP as u64;

    debug!("path_gen: block_id={}, pos={}", new_id, new_p);
    (
        new_id.try_into().unwrap(),
        new_p.try_into().unwrap(),
    )
}

/// Mixes the plot byte just read into the seed used for the next iteration.
/// This is what forces sequential disk reads: an attacker without the plot
/// cannot know iteration i+1's target until iteration i's byte has been read.
pub fn derive_next_seed(seed: u8, byte_read: u8, iteration: u64) -> u8 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    byte_read.hash(&mut hasher);
    iteration.hash(&mut hasher);
    (hasher.finish() % u8::MAX as u64) as u8
}
