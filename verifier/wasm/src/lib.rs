use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ==================== Types ====================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sibling {
    pub hash: Vec<u8>,  // 32 bytes
    pub direction: Direction,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof {
    pub siblings: Vec<Sibling>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InclusionProofEntry {
    pub block_id: u32,
    pub position: u32,
    pub root_hash: Vec<u8>,       // 32 bytes
    pub self_fragment: Vec<u8>,   // 32 bytes
    pub proof: Proof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationResult {
    pub block_id: u32,
    pub position: u32,
    pub valid: bool,
    pub reason: String,
}

// ==================== Constants ====================

const HASH_BYTES_LEN: usize = 32;
const FRAGMENT_SIZE: usize = 32;
const NUM_BYTES_IN_BLOCK: u32 = 524_288;
const NUM_BYTES_IN_BLOCK_GROUP: u32 = 2_097_152;

// ==================== Path Generator ====================
// MUST match the Prover's implementation exactly!

fn random_path_generator(seed: u8, iteration: u64, num_block_groups: u64) -> (u32, u32, u8) {
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

    (
        new_id as u32,
        new_p as u32,
        new_seed as u8,
    )
}

// ==================== Merkle Verification ====================

fn get_root_hash(proof: &Proof, self_fragment: &[u8]) -> [u8; 32] {
    let mut hash_final = blake3::hash(self_fragment);
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
    *hash_final.as_bytes()
}

// ==================== Time Bound Verification ====================

const GOOD_PROOF_AVG_TIMING: u128 = 50;    // microseconds
const BAD_PROOF_AVG_TIMING: u128 = 11_000; // microseconds
const LOWEST_ACCEPTED_STORING_PERCENTAGE: f64 = 0.9;
const TIME_LIMIT: u128 = 2_000_000; // 2 seconds in microseconds
const VERIFIABLE_RATIO: f32 = 0.01;

fn estimate_number_g_and_b(
    n: usize,
    target: u128,
    good_elem: u128,
    bad_elem: u128,
) -> (u128, u128) {
    let mut sum: u128 = 0;
    let mut good_count: u128 = 0;
    let mut bad_count: u128 = 0;
    for _ in 0..n {
        if sum < target {
            sum += bad_elem;
            bad_count += 1;
        } else {
            sum += good_elem;
            good_count += 1;
        }
    }
    if bad_count > 0 && sum >= target + bad_count {
        good_count += 1;
        bad_count -= 1;
    }
    (good_count, bad_count)
}

// ==================== Exported Wasm Functions ====================

/// Generate the list of (block_id, position) pairs that the Verifier expects
/// given a seed and a number of proof iterations. This is used server-side to
/// know which bytes the Prover should have read.
#[wasm_bindgen]
pub fn generate_expected_path(seed: u8, num_iterations: u64, num_block_groups: u64) -> JsValue {
    let mut s = seed;
    let mut pairs: Vec<(u32, u32)> = Vec::new();
    for iteration in 0..num_iterations {
        let (block_id, position, new_seed) = random_path_generator(s, iteration, num_block_groups);
        pairs.push((block_id, position));
        s = new_seed;
    }
    serde_wasm_bindgen::to_value(&pairs).unwrap()
}

/// Verify that the time taken to respond is consistent with actually reading
/// from stored data rather than computing on-the-fly.
/// Returns a JSON string: { "status": "correct" | "incorrect" | "insufficient", "p": f64 }
#[wasm_bindgen]
pub fn verify_time_bound(num_proofs: usize, elapsed_micros: u64) -> JsValue {
    let (good_count, bad_count) = estimate_number_g_and_b(
        num_proofs,
        elapsed_micros as u128,
        GOOD_PROOF_AVG_TIMING,
        BAD_PROOF_AVG_TIMING,
    );
    let total = good_count + bad_count;
    let p = if total > 0 { good_count as f64 / total as f64 } else { 0.0 };
    let std_dev = if num_proofs > 0 {
        (1.0 / (num_proofs as f64).sqrt()) * (p * (1.0 - p)).sqrt()
    } else {
        1.0
    };
    let inf = -2.576 * std_dev + p;
    let sup = 2.576 * std_dev + p;

    let status = if sup - inf < 0.08 && (sup + inf) / 2.0 >= LOWEST_ACCEPTED_STORING_PERCENTAGE {
        "correct"
    } else if elapsed_micros as u128 > TIME_LIMIT {
        "incorrect"
    } else {
        "insufficient"
    };

    serde_wasm_bindgen::to_value(&serde_json::json!({
        "status": status,
        "p": p,
        "inf": inf,
        "sup": sup,
    })).unwrap()
}

/// Verify a single inclusion proof.
/// `committed_root_hash` is the hash the Prover committed to during Phase 1.
/// Returns a JSON VerificationResult.
#[wasm_bindgen]
pub fn verify_inclusion_proof(
    proof_json: &str,
    committed_root_hash_hex: &str,
) -> JsValue {
    let entry: InclusionProofEntry = match serde_json::from_str(proof_json) {
        Ok(e) => e,
        Err(err) => {
            let result = VerificationResult {
                block_id: 0,
                position: 0,
                valid: false,
                reason: format!("Failed to parse proof JSON: {}", err),
            };
            return serde_wasm_bindgen::to_value(&result).unwrap();
        }
    };

    // Decode the committed root hash
    let committed_root: Vec<u8> = hex_decode(committed_root_hash_hex);
    if committed_root.len() != 32 {
        let result = VerificationResult {
            block_id: entry.block_id,
            position: entry.position,
            valid: false,
            reason: "Invalid committed root hash length".to_string(),
        };
        return serde_wasm_bindgen::to_value(&result).unwrap();
    }

    // Step 1: Recompute root hash from the proof path
    let computed_root = get_root_hash(&entry.proof, &entry.self_fragment);

    // Step 2: Check that the computed root matches the root_hash in the proof
    let proof_root_matches = computed_root == entry.root_hash.as_slice();

    // Step 3: Check that the computed root matches the committed root hash
    let commitment_matches = computed_root == committed_root.as_slice();

    let valid = proof_root_matches && commitment_matches;
    let reason = if valid {
        "Inclusion proof verified successfully".to_string()
    } else if !proof_root_matches {
        "Computed Merkle root does not match proof's root_hash".to_string()
    } else {
        "Computed Merkle root does not match committed root hash".to_string()
    };

    let result = VerificationResult {
        block_id: entry.block_id,
        position: entry.position,
        valid,
        reason,
    };
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Select which proofs to request inclusion proofs for (sampling).
/// Returns indices into the proof batch that should be verified for correctness.
#[wasm_bindgen]
pub fn select_verification_targets(
    seed: u8,
    num_proofs: u64,
    num_block_groups: u64,
) -> JsValue {
    let mut s = seed;
    let mut block_ids_pos: Vec<(u32, u32)> = Vec::new();

    for iteration in 0..num_proofs {
        let (block_id, position, new_seed) = random_path_generator(s, iteration, num_block_groups);
        block_ids_pos.push((block_id, position));
        s = new_seed;
    }

    // Sample a subset based on VERIFIABLE_RATIO
    let mut verifiable_ratio = VERIFIABLE_RATIO;
    if verifiable_ratio == 0.0 {
        verifiable_ratio = 0.5;
    }
    let avg_step = (1.0 / verifiable_ratio).floor() as i32;
    let mut targets: Vec<(u32, u32)> = Vec::new();
    let mut i = avg_step.abs();

    while (i as usize) < block_ids_pos.len() {
        targets.push(block_ids_pos[i as usize]);
        i += avg_step;
    }

    serde_wasm_bindgen::to_value(&targets).unwrap()
}

// ==================== Utility ====================

fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = hex.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let hi = chars[i].to_digit(16).unwrap_or(0) as u8;
        let lo = chars[i + 1].to_digit(16).unwrap_or(0) as u8;
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    bytes
}
