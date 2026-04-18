use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use actix_web::{web, HttpResponse};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::block_generation::blockgen::{GROUP_BYTE_SIZE, GROUP_SIZE, N};
use crate::block_generation::encoder::generate_xored_data;
use crate::block_generation::utils::*;
use crate::communication::path_generator::{random_path_generator, derive_next_seed};
use crate::communication::structs::*;
use crate::config::Config;
use crate::merkle_tree::structs::*;

/// Shared application state for all HTTP handlers.
pub struct AppState {
    pub status: Mutex<ServiceStatus>,
    pub output_file: Mutex<File>,
    pub root_hashes: Vec<[u8; HASH_BYTES_LEN]>,
    pub num_block_groups: u64,
    pub config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStatus {
    Ready,
    Plotting,
    Proving,
    Error(String),
}

// ============ /status ============

pub async fn get_status(data: web::Data<AppState>) -> HttpResponse {
    let status = data.status.lock().unwrap().clone();
    let disk_used = {
        let file = data.output_file.lock().unwrap();
        file.metadata().map(|m| m.len() / (1024 * 1024)).unwrap_or(0)
    };

    HttpResponse::Ok().json(serde_json::json!({
        "state": format!("{:?}", status),
        "disk_used_mb": disk_used,
        "plot_progress": 100,
        "num_block_groups": data.num_block_groups,
    }))
}

// ============ /commitment ============

pub async fn get_commitment(data: web::Data<AppState>) -> HttpResponse {
    info!("Commitment requested");
    let response = CommitmentResponse {
        root_hashes: data.root_hashes.clone(),
        num_block_groups: data.num_block_groups,
    };
    HttpResponse::Ok().json(response)
}

// ============ /challenge ============

pub async fn handle_challenge(
    data: web::Data<AppState>,
    body: String,
) -> HttpResponse {
    let decrypted = match crate::crypto::decrypt_aes(&body, &data.config.aes_secret_key) {
        Some(d) => d,
        None => return HttpResponse::BadRequest().body("Invalid encrypted payload"),
    };
    
    let req: ChallengeRequest = match serde_json::from_str(&decrypted) {
        Ok(r) => r,
        Err(_) => return HttpResponse::BadRequest().body("Invalid JSON"),
    };

    info!("Challenge received: seed={}, session={}", req.seed, req.session_id);

    // Set status to Proving
    {
        *data.status.lock().unwrap() = ServiceStatus::Proving;
    }

    let mut seed = req.seed;
    let mut iteration: u64 = 0;
    let mut proof_batch: Vec<u8> = Vec::with_capacity(BATCH_SIZE);

    for _ in 0..BATCH_SIZE {
        let (block_id, position) =
            random_path_generator(seed, iteration, data.num_block_groups);

        let byte_value = read_byte_from_file(&data.output_file, block_id, position);
        proof_batch.push(byte_value);

        // Roll the seed using the byte just read — target i+1 depends on plot byte at target i.
        seed = derive_next_seed(seed, byte_value, iteration);
        iteration += 1;
    }

    // Set status back to Ready
    {
        *data.status.lock().unwrap() = ServiceStatus::Ready;
    }

    let response = ChallengeResponse {
        proof_bytes: proof_batch,
        seed,
        iteration,
    };

    let json_resp = serde_json::to_string(&response).unwrap();
    let encrypted_resp = crate::crypto::encrypt_aes(&json_resp, &data.config.aes_secret_key);

    HttpResponse::Ok().body(encrypted_resp)
}

// ============ /inclusion-proofs ============

pub async fn handle_inclusion_proofs(
    data: web::Data<AppState>,
    body: String,
) -> HttpResponse {
    let decrypted = match crate::crypto::decrypt_aes(&body, &data.config.aes_secret_key) {
        Some(d) => d,
        None => return HttpResponse::BadRequest().body("Invalid encrypted payload"),
    };
    
    let req: InclusionProofRequest = match serde_json::from_str(&decrypted) {
        Ok(r) => r,
        Err(_) => return HttpResponse::BadRequest().body("Invalid JSON"),
    };

    info!("Inclusion proof request: {} targets", req.targets.len());

    let mut proofs: Vec<InclusionProofEntry> = Vec::new();

    for &(block_id, position) in &req.targets {
        let mut buffer = vec![0u8; HASH_BYTES_LEN + NUM_BYTES_IN_BLOCK_GROUP as usize];
        read_hash_and_block(&data.output_file, block_id, &mut buffer);

        // Reconstruct raw data from the encoded block
        let reconstructed = reconstruct_raw_from_buffer(block_id, &buffer, &data.root_hashes);

        // Generate Merkle tree and extract inclusion proof
        let (proof, self_fragment, root_hash) =
            generate_merkle_proof(&reconstructed, block_id, position);

        proofs.push(InclusionProofEntry {
            block_id,
            position,
            root_hash,
            self_fragment,
            proof,
        });
    }

    let response = InclusionProofResponse { proofs };
    let json_resp = serde_json::to_string(&response).unwrap();
    let encrypted_resp = crate::crypto::encrypt_aes(&json_resp, &data.config.aes_secret_key);

    HttpResponse::Ok().body(encrypted_resp)
}

// ============ Helper Functions ============

/// Read a single byte from the output file at the position determined by (block_id, position).
fn read_byte_from_file(
    shared_file: &Mutex<File>,
    block_id: u32,
    position: u32,
) -> u8 {
    let mut file = shared_file.lock().unwrap();
    let index = (block_id as u64 * NUM_BYTES_IN_BLOCK_GROUP as u64)
        + position as u64
        + 8
        + HASH_BYTES_LEN as u64 * (block_id + 1) as u64;

    file.seek(SeekFrom::Start(index)).unwrap();
    let mut buffer = [0u8; 1];
    match file.read_exact(&mut buffer) {
        Ok(_) => {}
        Err(e) => warn!("Error reading file: {:?}", e),
    };
    buffer[0]
}

/// Read the hash and full block data from the output file for a given block_id.
fn read_hash_and_block(
    shared_file: &Mutex<File>,
    block_id: u32,
    buffer: &mut [u8],
) {
    let mut file = shared_file.lock().unwrap();
    let index = (block_id as u64 * NUM_BYTES_IN_BLOCK_GROUP as u64)
        + 8
        + HASH_BYTES_LEN as u64 * block_id as u64;

    file.seek(SeekFrom::Start(index)).unwrap();
    match file.read_exact(buffer) {
        Ok(_) => {}
        Err(e) => warn!("Error reading file: {:?}", e),
    };
}

/// Reconstruct the raw (un-XOR'd) data from an encoded buffer.
/// This reverses the encoding to get back the original block bytes needed for Merkle tree building.
fn reconstruct_raw_from_buffer(
    block_id: u32,
    buffer: &[u8],
    root_hashes: &[[u8; HASH_BYTES_LEN]],
) -> Vec<u8> {
    use crate::block_generation::encoder::generate_pos;
    use std::mem::transmute;

    let root_hash = root_hashes[block_id as usize];
    let group = generate_pos(block_id as u64, root_hash);

    let encoded_data = &buffer[HASH_BYTES_LEN..];
    let mut raw_data = vec![0u8; GROUP_BYTE_SIZE];

    for i in 0..(N * GROUP_SIZE) {
        let mut data_bytes = [0u8; 8];
        for j in 0..8 {
            data_bytes[j] = encoded_data[i * 8 + j];
        }
        let mut data = u64::from_le_bytes(data_bytes);
        data ^= group[i / GROUP_SIZE][i % GROUP_SIZE];
        data_bytes = unsafe { transmute(data.to_le()) };
        for j in 0..8 {
            raw_data[i * 8 + j] = data_bytes[j];
        }
    }

    raw_data
}

/// Generate a Merkle tree for a block and extract the inclusion proof for a given position.
/// Ported from the thesis's `generate_MT_vector`.
fn generate_merkle_proof(
    buffer: &[u8],
    block_id: u32,
    position: u32,
) -> (Proof, [u8; 32], [u8; 32]) {
    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

    let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
    let mut fragment_start_indx = (number_id_fragment) as usize * HASH_BYTES_LEN;

    let mut i = 0;
    while i + HASH_BYTES_LEN < hash_layers.len() {
        let mut first_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        first_fragment.copy_from_slice(&hash_layers[i..i + HASH_BYTES_LEN]);

        let mut second_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        second_fragment
            .copy_from_slice(&hash_layers[i + HASH_BYTES_LEN..i + HASH_BYTES_LEN * 2]);

        if i < buffer.len() {
            first_fragment = *blake3::hash(&first_fragment).as_bytes();
            second_fragment = *blake3::hash(&second_fragment).as_bytes();
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&first_fragment);
        hasher.update(&second_fragment);
        let new_hash = hasher.finalize();

        hash_layers.extend(new_hash.as_bytes());
        i += HASH_BYTES_LEN * 2;
    }

    root_hash.copy_from_slice(&hash_layers[hash_layers.len() - HASH_BYTES_LEN..]);

    // Extract Merkle proof path (siblings)
    let mut layer_len = buffer.len();
    let mut siblings = Vec::new();
    let mut layer_counter = buffer.len();
    let mut self_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
    let mut is_first_iter = true;

    while layer_len / HASH_BYTES_LEN > 1 {
        let mut sibling_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

        let direction;
        if number_id_fragment % 2 == 0 {
            direction = Direction::Right;
            sibling_fragment.copy_from_slice(
                &hash_layers
                    [fragment_start_indx + HASH_BYTES_LEN..fragment_start_indx + HASH_BYTES_LEN * 2],
            );
        } else {
            direction = Direction::Left;
            sibling_fragment.copy_from_slice(
                &hash_layers[(fragment_start_indx - HASH_BYTES_LEN)..fragment_start_indx],
            );
        }

        if is_first_iter {
            sibling_fragment = *blake3::hash(&sibling_fragment).as_bytes();
        }
        siblings.push(Sibling::new(sibling_fragment, direction));

        if is_first_iter {
            is_first_iter = false;
            self_fragment.copy_from_slice(
                &hash_layers[fragment_start_indx..fragment_start_indx + HASH_BYTES_LEN],
            );
        }

        layer_len /= 2;
        number_id_fragment /= 2;
        let count_frag = layer_counter / HASH_BYTES_LEN + number_id_fragment as usize;
        layer_counter += layer_len;
        fragment_start_indx = count_frag * HASH_BYTES_LEN;
    }

    (Proof::new(siblings), self_fragment, root_hash)
}
