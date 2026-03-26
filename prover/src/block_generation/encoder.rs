use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{Read, SeekFrom};
use std::mem::transmute;
use std::time::Instant;

use log::{debug, info};

use crate::block_generation::blockgen::{
    block_gen, InitGroup, BlockGroup, GROUP_BYTE_SIZE, GROUP_SIZE, INIT_SIZE, N,
};
use crate::block_generation::utils::{FRAGMENT_SIZE, HASH_BYTES_LEN, NUM_BYTES_IN_BLOCK_GROUP};

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";

/// Generate a commitment hash (Merkle root) for a given block of raw data.
pub fn generate_commitment_hash(raw_data: &[u8], block_id: u32) -> [u8; 32] {
    let start = (block_id as usize) * NUM_BYTES_IN_BLOCK_GROUP as usize;
    let end = std::cmp::min(start + NUM_BYTES_IN_BLOCK_GROUP as usize, raw_data.len());
    let block_data = &raw_data[start..end];

    let mut buffer = vec![0u8; NUM_BYTES_IN_BLOCK_GROUP as usize];
    buffer[..block_data.len()].copy_from_slice(block_data);

    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

    let mut i = 0;
    while i + HASH_BYTES_LEN < hash_layers.len() {
        let mut first_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        first_fragment.copy_from_slice(&hash_layers[i..i + HASH_BYTES_LEN]);

        let mut second_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        second_fragment.copy_from_slice(&hash_layers[i + HASH_BYTES_LEN..i + HASH_BYTES_LEN * 2]);

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

    root_hash
}

/// Generate the PoS block group for a given block_id and root_hash.
/// Used both during encoding AND during xored_data verification.
pub fn generate_pos(block_id: u64, root_hash: [u8; HASH_BYTES_LEN]) -> BlockGroup {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
    for g in 0..GROUP_SIZE {
        let pos_bytes: [u8; 8] =
            unsafe { transmute(((block_id * GROUP_SIZE as u64) + g as u64).to_le()) };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pos_bytes);
        hasher.update(pub_hash.as_bytes());
        hasher.update(&root_hash);

        let block_hash = hasher.finalize();
        let block_hash = block_hash.as_bytes();
        for i in 0..INIT_SIZE {
            let mut hash_bytes = [0u8; 8];
            for j in 0..8 {
                hash_bytes[j] = block_hash[i * 8 + j]
            }
            inits[i][g] = u64::from_le_bytes(hash_bytes);
        }
    }

    block_gen(inits)
}

/// Encode raw data into the output file.
/// Modified from thesis: takes raw_data bytes directly instead of reading from input.mp4.
pub fn encode(
    raw_data: &[u8],
    output_file: &mut File,
    root_hashes: &mut Vec<[u8; HASH_BYTES_LEN]>,
) -> io::Result<()> {
    let startup = Instant::now();

    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let input_length = raw_data.len() as u64;
    let block_count = ((input_length - 1) / GROUP_BYTE_SIZE as u64) + 1;

    unsafe {
        crate::block_generation::utils::NUM_BLOCK_GROUPS_PER_UNIT = block_count;
    }

    let output_length = 8 + (64 * block_count) + block_count * GROUP_BYTE_SIZE as u64;
    output_file.set_len(output_length)?;

    // Write input data size at the start
    let size_bytes: [u8; 8] = unsafe { transmute(input_length.to_le()) };
    output_file.write_all(&size_bytes)?;

    // Generate commitment hashes
    for i in 0..block_count {
        root_hashes.push(generate_commitment_hash(raw_data, i as u32));
    }
    debug!("Generated {} root hashes", root_hashes.len());

    // Write encoded blocks
    for i in 0..block_count {
        let start = (i as usize) * GROUP_BYTE_SIZE;
        let end = std::cmp::min(start + GROUP_BYTE_SIZE, raw_data.len());
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        input[..end - start].copy_from_slice(&raw_data[start..end]);

        // Compute init vectors
        let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
        for g in 0..GROUP_SIZE {
            let pos_bytes: [u8; 8] =
                unsafe { transmute(((i * GROUP_SIZE as u64) + g as u64).to_le()) };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pos_bytes);
            hasher.update(pub_hash.as_bytes());
            hasher.update(&root_hashes[i as usize]);

            let block_hash = hasher.finalize();
            let block_hash = block_hash.as_bytes();
            for ii in 0..INIT_SIZE {
                let mut hash_bytes = [0u8; 8];
                for j in 0..8 {
                    hash_bytes[j] = block_hash[ii * 8 + j]
                }
                inits[ii][g] = u64::from_le_bytes(hash_bytes);
            }
        }

        let group = block_gen(inits);

        // Output = hash || XOR(input, block_gen output)
        let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
        let input_hash = root_hashes[i as usize];
        for byte in &input_hash {
            output.push(*byte);
        }

        for j in 0..(N * GROUP_SIZE) {
            let mut data_bytes = [0u8; 8];
            for k in 0..8 {
                data_bytes[k] = input[j * 8 + k];
            }
            let mut data = u64::from_le_bytes(data_bytes);
            data ^= group[j / GROUP_SIZE][j % GROUP_SIZE];
            data_bytes = unsafe { transmute(data.to_le()) };
            for byte in &data_bytes {
                output.push(*byte);
            }
        }

        output_file.write_all(&output)?;
    }

    let total = startup.elapsed();
    info!("Encoded the data in {:.1}ms", total.as_micros() as f32 / 1000.0);
    Ok(())
}

/// Generate the XOR'd data for a specific (block_id, position) for inclusion proof verification.
pub fn generate_xored_data(
    block_id: u32,
    position: u32,
    root_hash: [u8; HASH_BYTES_LEN],
    self_fragment: [u8; FRAGMENT_SIZE],
) -> Vec<u8> {
    let group = generate_pos(block_id as u64, root_hash);
    let mut input = vec![0u8; GROUP_BYTE_SIZE];

    let number_id_fragment = position / HASH_BYTES_LEN as u32;
    let indx_start = (number_id_fragment) as usize * HASH_BYTES_LEN;
    let indx_end = indx_start + FRAGMENT_SIZE;

    let mut k = 0;
    for i in indx_start..indx_end {
        input[i] = self_fragment[k];
        k += 1;
    }

    let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
    for byte in &root_hash {
        output.push(*byte);
    }

    for i in 0..(N * GROUP_SIZE) {
        let mut data_bytes = [0u8; 8];
        for j in 0..8 {
            data_bytes[j] = input[i * 8 + j];
        }
        let mut data = u64::from_le_bytes(data_bytes);
        data ^= group[i / GROUP_SIZE][i % GROUP_SIZE];
        data_bytes = unsafe { transmute(data.to_le()) };
        for byte in &data_bytes {
            output.push(*byte);
        }
    }
    output[HASH_BYTES_LEN + indx_start..HASH_BYTES_LEN + indx_end].to_vec()
}
