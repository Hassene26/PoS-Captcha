#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use blake3;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Constants matching the Prover
pub const HASH_BYTES_LEN: usize = 32;
pub const BATCH_SIZE: usize = 70;
pub const NUM_BYTES_IN_BLOCK: u32 = 524_288; // 2^19 bytes — must match Prover
pub const NUM_BYTES_IN_BLOCK_GROUP: usize = 2097152; // 2 MB
pub const VERIFIABLE_RATIO: f32 = 0.01;
pub const TIME_LIMIT: u128 = 2000000; // 2 seconds

#[derive(Clone)]
#[napi(object)]
pub struct PositionTarget {
    pub block_id: u32,
    pub index: u32,
}

#[derive(Clone)]
#[napi(object)]
pub struct SiblingNode {
    pub hash: Buffer,
    pub direction: String, // "Left" or "Right"
}

#[derive(Clone)]
#[napi(object)]
pub struct MerkleProof {
    pub path: Vec<SiblingNode>,
}

/// Replicates Prover's `random_path_generator` — (seed, iteration) -> (block_id, position).
/// Must remain in lockstep with prover/src/communication/path_generator.rs.
fn path_step(seed: u8, iteration: u64, num_block_groups: u64) -> (u32, u32) {
    let mut hasher_nxt_block = DefaultHasher::new();
    seed.hash(&mut hasher_nxt_block);
    iteration.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % num_block_groups;

    let mut hasher_nxt_pos = DefaultHasher::new();
    seed.hash(&mut hasher_nxt_pos);
    iteration.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK_GROUP as u64;

    (new_id as u32, new_p as u32)
}

/// Replicates Prover's `derive_next_seed`.
fn next_seed(seed: u8, byte_read: u8, iteration: u64) -> u8 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    byte_read.hash(&mut hasher);
    iteration.hash(&mut hasher);
    (hasher.finish() % u8::MAX as u64) as u8
}

/// Derives the full chain of targets the Prover traversed, given the initial seed
/// and the byte sequence the Prover returned. Each target i+1 is computed from
/// the seed rolled with byte i — so an attacker without the plot cannot enumerate
/// the targets in advance.
#[napi]
pub fn derive_path_chain(
    seed: u32,
    num_block_groups: u32,
    proof_bytes: Buffer,
) -> Vec<PositionTarget> {
    let mut state = (seed & 0xff) as u8;
    let num_groups = num_block_groups as u64;
    let bytes: &[u8] = &proof_bytes;
    let mut targets = Vec::with_capacity(bytes.len());

    for (i, &byte) in bytes.iter().enumerate() {
        let iteration = i as u64;
        let (block_id, index) = path_step(state, iteration, num_groups);
        targets.push(PositionTarget { block_id, index });
        state = next_seed(state, byte, iteration);
    }

    targets
}

fn get_root_hash(leaf_hash: &[u8; 32], path: &[SiblingNode]) -> [u8; 32] {
    let mut current_hash = *leaf_hash;

    for sibling in path {
        let mut hasher = blake3::Hasher::new();
        if sibling.direction == "Left" {
            hasher.update(&sibling.hash);
            hasher.update(&current_hash);
        } else {
            hasher.update(&current_hash);
            hasher.update(&sibling.hash);
        }
        current_hash = *hasher.finalize().as_bytes();
    }

    current_hash
}

#[napi]
pub fn verify_inclusion_proof(
    self_fragment: Buffer,
    proof_path: Vec<SiblingNode>,
    expected_root_hash: Buffer
) -> bool {
    let mut leaf_hasher = blake3::Hasher::new();
    leaf_hasher.update(&self_fragment);
    let leaf_hash = leaf_hasher.finalize();

    let computed_root = get_root_hash(leaf_hash.as_bytes(), &proof_path);
    
    // Check if the computed root matches the expected root
    let expected_slice: &[u8] = &expected_root_hash;
    computed_root == expected_slice
}

#[napi]
pub fn verify_time_bound(timestamp_diff_ms: i64) -> bool {
    // 2 seconds in micros = 2000000. So we check if diff in ms < 2000
    timestamp_diff_ms < 2000
}
