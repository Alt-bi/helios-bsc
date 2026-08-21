use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypesError {
    #[error("unsupported chain id {0} (expected BSC mainnet 56)")]
    UnsupportedChainId(u64),
    #[error("checkpoint sealing set is empty")]
    EmptySealingSet,
    #[error("checkpoint sealing set address is not 20 bytes")]
    BadSealingAddress,
    #[error("checkpoint sealing set has a duplicate address")]
    DuplicateSealingAddress,
    #[error("checkpoint {field} is not a 32-byte hash")]
    BadCheckpointHash { field: &'static str },
    #[error("checkpoint has {keys} BLS vote keys for {validators} sealing addresses")]
    VoteKeyCountMismatch { keys: usize, validators: usize },
    #[error("checkpoint BLS vote key is not 48 bytes")]
    BadVoteKey,
    #[error("checkpoint has a duplicate BLS vote key")]
    DuplicateVoteKey,
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid hex length: expected {expected} bytes, got {got}")]
    InvalidHexLength { expected: usize, got: usize },
}
