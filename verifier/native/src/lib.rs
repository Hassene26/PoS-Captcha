#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use blake3;

// Constants matching the Prover
pub const HASH_BYTES_LEN: usize = 32;
pub const BATCH_SIZE: usize = 70;
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

#[napi]
pub fn random_path_generator(
    seed: f64, 
    iterations: u32, 
    num_block_groups: u32
) -> Vec<PositionTarget> {
    // Replicating exactly what the Prover does in path_generator.rs
    // For JS compat, we take seed as f64 but cast to u64
    let mut state = seed as u64;
    let mut targets = Vec::new();

    for i in 0..iterations {
        // A simple deterministic LCG for matching the Prover.
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        
        let block_id = (state % num_block_groups as u64) as u32;
        
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = (state % NUM_BYTES_IN_BLOCK_GROUP as u64) as u32;

        targets.push(PositionTarget {
            block_id,
            index,
        });
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
