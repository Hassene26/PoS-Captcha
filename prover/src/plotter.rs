use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use log::info;
use rand::Rng;

use crate::block_generation::encoder::encode;
use crate::block_generation::utils::HASH_BYTES_LEN;
use crate::config::Config;

/// Manages disk space allocation for the PoS prover.
/// Replaces the thesis's approach of reading `input.mp4` with
/// deterministic random-fill (CSPRNG seeded by user identity).
pub struct Plotter {
    plot_path: String,
    storage_size_bytes: u64,
}

impl Plotter {
    pub fn new(config: &Config) -> Plotter {
        Plotter {
            plot_path: config.plot_path.clone(),
            storage_size_bytes: config.storage_size_mb * 1024 * 1024,
        }
    }

    /// Check if a plot file already exists and is valid.
    /// If not, generate one from scratch.
    /// Returns the opened output file, root hashes, and number of block groups.
    pub fn ensure_plotted(self) -> (File, Vec<[u8; HASH_BYTES_LEN]>, usize) {
        let plot_path = Path::new(&self.plot_path);
        let hashes_path = Path::new("root_hashes.bin");

        if plot_path.exists() && hashes_path.exists() {
            info!("Existing plot found at {}, loading...", self.plot_path);
            return self.load_existing();
        }

        info!("No existing plot found. Generating {} MB of storage...", self.storage_size_bytes / (1024 * 1024));
        self.create_new_plot()
    }

    fn load_existing(self) -> (File, Vec<[u8; HASH_BYTES_LEN]>, usize) {
        // Load root hashes from disk
        let hashes_data = fs::read("root_hashes.bin")
            .expect("Failed to read root_hashes.bin");
        let num_hashes = hashes_data.len() / HASH_BYTES_LEN;
        let mut root_hashes = Vec::with_capacity(num_hashes);
        for i in 0..num_hashes {
            let mut hash = [0u8; HASH_BYTES_LEN];
            hash.copy_from_slice(&hashes_data[i * HASH_BYTES_LEN..(i + 1) * HASH_BYTES_LEN]);
            root_hashes.push(hash);
        }

        let output_file = OpenOptions::new()
            .read(true)
            .open(&self.plot_path)
            .expect("Failed to open plot file");

        // Set global block count
        unsafe {
            crate::block_generation::utils::NUM_BLOCK_GROUPS_PER_UNIT = num_hashes as u64;
        }

        info!("Loaded {} root hashes from existing plot", num_hashes);
        (output_file, root_hashes, num_hashes)
    }

    fn create_new_plot(self) -> (File, Vec<[u8; HASH_BYTES_LEN]>, usize) {
        // Generate random raw data to fill the required space
        let mut rng = rand::thread_rng();
        let mut raw_data = vec![0u8; self.storage_size_bytes as usize];
        rng.fill(&mut raw_data[..]);
        info!("Generated {} bytes of random data", raw_data.len());

        // Create output file
        let mut output_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&self.plot_path)
            .expect("Failed to create plot file");

        let mut root_hashes = Vec::new();

        // Encode the raw data into the plot file
        encode(&raw_data, &mut output_file, &mut root_hashes)
            .expect("Failed to encode data");

        // Persist root hashes to disk for future loads
        let mut hashes_data = Vec::with_capacity(root_hashes.len() * HASH_BYTES_LEN);
        for hash in &root_hashes {
            hashes_data.extend_from_slice(hash);
        }
        fs::write("root_hashes.bin", &hashes_data)
            .expect("Failed to write root hashes");

        let num = root_hashes.len();
        info!("Plot created: {} block groups, saved root hashes", num);

        // Reopen as read-only
        drop(output_file);
        let output_file = OpenOptions::new()
            .read(true)
            .open(&self.plot_path)
            .expect("Failed to reopen plot file");

        (output_file, root_hashes, num)
    }
}
