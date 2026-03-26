use serde::{Deserialize, Serialize};

/// Direction of a sibling in a Merkle proof path.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Direction {
    Left,
    Right,
}

/// A sibling node in a Merkle inclusion proof.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sibling {
    pub hash: [u8; 32],
    pub direction: Direction,
}

impl Sibling {
    pub fn new(hash: [u8; 32], direction: Direction) -> Sibling {
        Sibling { hash, direction }
    }
}

/// A Merkle inclusion proof consisting of sibling nodes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof {
    pub siblings: Vec<Sibling>,
}

impl Proof {
    pub fn new(siblings: Vec<Sibling>) -> Proof {
        Proof { siblings }
    }
}
