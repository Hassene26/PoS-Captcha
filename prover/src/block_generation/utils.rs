/// Constants for the PoS protocol.
/// Ported from thesis with configurable values for CAPTCHA use-case.

pub const BUFFER_DATA_SIZE: usize = 50_000_000;

pub const NUM_BYTES_IN_BLOCK: u32 = 524_288;       // 2^19 bytes
pub const NUM_BYTES_IN_BLOCK_GROUP: u32 = 2_097_152; // 2^21 bytes

/// Number of block groups in the current plot. Set during plotting.
pub static mut NUM_BLOCK_GROUPS_PER_UNIT: u64 = 0;

pub const INITIAL_BLOCK_ID: u32 = 0;
pub const INITIAL_POSITION: u32 = 0;
pub const VERIFIABLE_RATIO: f32 = 0.01;
pub const NUM_BYTES_PER_BLOCK_ID: usize = 4;
pub const NUM_BYTES_PER_POSITION: usize = 4;
pub const HASH_BYTES_LEN: usize = 32;
pub const FRAGMENT_SIZE: usize = 32;

/// Batch size of proofs sent per challenge round.
pub const BATCH_SIZE: usize = 70;

/// Lowest accepted percentage of blocks stored by the prover.
pub const LOWEST_ACCEPTED_STORING_PERCENTAGE: f64 = 0.9;

/// Time limit for the challenge in microseconds (2 seconds).
pub const TIME_LIMIT: u128 = 2_000_000;

/// Average timing benchmarks (in microseconds) for good/bad proofs.
pub const GOOD_PROOF_AVG_TIMING: u128 = 50;
pub const BAD_PROOF_AVG_TIMING: u128 = 11_000;
