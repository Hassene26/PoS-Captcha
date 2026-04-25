use serde::{Deserialize, Serialize};

/// Possible states of the prover service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceState {
    Idle,
    Plotting,
    Ready,
    Proving,
    Error,
}

/// Status response returned by the prover's /status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub state: ServiceState,
    pub disk_used_mb: u64,
    pub plot_progress: u8,
    pub num_block_groups: u64,
}

/// Challenge request sent by the browser proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub seed: u8,
    pub session_id: String,
}

/// Proof batch response returned after a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub proof_bytes: Vec<u8>,
    pub seed: u8,
    pub iteration: u64,
    /// Milliseconds spent waiting for the user to approve the request in
    /// the browser extension. The verifier subtracts this from the wall-
    /// clock elapsed time so its 2 s disk-read bound is not polluted by
    /// human reaction time.
    #[serde(default)]
    pub consent_wait_ms: u64,
}

/// Request for inclusion proofs from the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofRequest {
    /// List of (block_id, position) pairs to generate proofs for.
    pub targets: Vec<(u32, u32)>,
}

/// A single inclusion proof for a (block_id, position).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofEntry {
    pub block_id: u32,
    pub position: u32,
    pub root_hash: [u8; 32],
    pub self_fragment: [u8; 32],
    pub proof: crate::merkle_tree::structs::Proof,
}

/// Response containing all requested inclusion proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    pub proofs: Vec<InclusionProofEntry>,
}

/// Commitment (root hashes for all block groups).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentResponse {
    pub root_hashes: Vec<[u8; 32]>,
    pub num_block_groups: u64,
}
