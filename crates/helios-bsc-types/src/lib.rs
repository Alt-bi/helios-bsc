//! Shared types for helios-bsc.
//!
//! Normative consensus details live in `docs/design.md` and Phase 0 appendix.
//! Confirmation-depth uses sealing set size `N_seal` (≈21), threshold
//! `floor(2*N/3)+1` (=15 for N=21).

use serde::{Deserialize, Serialize};

pub mod error;
pub mod hexutil;
pub mod rpc_header;
pub mod trust;

pub use error::TypesError;
pub use hexutil::{
    address_from_pubkey_uncompressed, decode_hex, decode_hex_fixed, decode_u64, format_address,
    keccak256,
};
pub use rpc_header::RpcBlockHeader;
pub use trust::TrustClass;

/// BSC mainnet chain id.
pub const BSC_MAINNET_CHAIN_ID: u64 = 56;

/// Hex-encoded 32-byte hash (0x-prefixed preferred in JSON).
pub type HexHash = String;

/// Hex-encoded 20-byte address.
pub type HexAddress = String;

/// Hex-encoded 48-byte BLS12-381 vote key (Parlia Fast Finality).
pub type HexBlsKey = String;

/// Weak-subjectivity style checkpoint — root of trust for light sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub chain_id: u64,
    /// Block number of the trusted header.
    pub number: u64,
    pub hash: HexHash,
    pub parent_hash: HexHash,
    pub state_root: HexHash,
    pub timestamp: u64,
    /// Fork id / hardfork name used to select codec (e.g. "maxwell", "fermi").
    pub fork_id: String,
    /// Sealing validator set active at this checkpoint (N_seal addresses).
    pub sealing_set: Vec<HexAddress>,
    /// BLS vote keys for `sealing_set`, **positionally aligned** with it.
    ///
    /// Optional on purpose: a checkpoint written from `--sealing-set` (operator
    /// addresses) carries none, and neither does any checkpoint written before Fast
    /// Finality existed. Without them the client runs confirmation-depth only until it
    /// ingests and activates an epoch header that carries the keys — it never guesses a
    /// key, and never infers one from an attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vote_keys: Option<Vec<HexBlsKey>>,
    /// Optional human / multi-source attestation notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

impl Checkpoint {
    pub fn validate_basic(&self) -> Result<(), TypesError> {
        if self.chain_id != BSC_MAINNET_CHAIN_ID {
            return Err(TypesError::UnsupportedChainId(self.chain_id));
        }
        if self.sealing_set.is_empty() {
            return Err(TypesError::EmptySealingSet);
        }
        // Current mainnet expectation; config crate may override for tests.
        if self.sealing_set.len() != 21 {
            // Soft warning path — allow other sizes for testnets / governance changes.
            // Callers should log; we only hard-fail empty.
        }
        let mut seen = std::collections::HashSet::with_capacity(self.sealing_set.len());
        for a in &self.sealing_set {
            let addr = decode_hex_fixed::<20>(a).map_err(|_| TypesError::BadSealingAddress)?;
            if !seen.insert(addr) {
                return Err(TypesError::DuplicateSealingAddress);
            }
        }
        for (field, v) in [
            ("hash", self.hash.as_str()),
            ("parentHash", self.parent_hash.as_str()),
            ("stateRoot", self.state_root.as_str()),
        ] {
            decode_hex_fixed::<32>(v).map_err(|_| TypesError::BadCheckpointHash { field })?;
        }
        if let Some(keys) = &self.vote_keys {
            // Positional alignment is the whole contract: a short, long, or reordered
            // list silently pairs an address with someone else's BLS key, and the only
            // symptom is an aggregate signature that fails for the wrong reason.
            if keys.len() != self.sealing_set.len() {
                return Err(TypesError::VoteKeyCountMismatch {
                    keys: keys.len(),
                    validators: self.sealing_set.len(),
                });
            }
            let mut seen_keys = std::collections::HashSet::with_capacity(keys.len());
            for k in keys {
                let key = decode_hex_fixed::<48>(k).map_err(|_| TypesError::BadVoteKey)?;
                if !seen_keys.insert(key) {
                    return Err(TypesError::DuplicateVoteKey);
                }
            }
        }
        Ok(())
    }

    /// Attach BLS vote keys, positionally aligned with `sealing_set`.
    ///
    /// Separate from [`Self::from_rpc_header`] because the two inputs have different
    /// provenance: the addresses may be operator-supplied, while the keys only ever come
    /// from an **activated** epoch header's `extraData`.
    pub fn with_vote_keys(mut self, vote_keys: Vec<HexBlsKey>) -> Self {
        self.vote_keys = Some(vote_keys);
        self
    }

    /// Build a checkpoint from a trusted header + operator-supplied sealing set.
    /// Does **not** invent the set from `miner` fields.
    pub fn from_rpc_header(
        header: &RpcBlockHeader,
        sealing_set: Vec<HexAddress>,
        fork_id: impl Into<String>,
        attestation: Option<String>,
    ) -> Result<Self, TypesError> {
        Ok(Self {
            chain_id: BSC_MAINNET_CHAIN_ID,
            number: decode_u64(&header.number)?,
            hash: header.hash.clone(),
            parent_hash: header.parent_hash.clone(),
            state_root: header.state_root.clone(),
            timestamp: decode_u64(&header.timestamp)?,
            fork_id: fork_id.into(),
            sealing_set,
            vote_keys: None,
            attestation,
        })
    }
}

/// Minimal Parlia header fields needed for light verification (pre-alloy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParliaHeaderLite {
    pub number: u64,
    pub hash: HexHash,
    pub parent_hash: HexHash,
    pub state_root: HexHash,
    pub difficulty: String,
    pub timestamp: u64,
    /// Raw extraData hex (vanity + validators/votes + seal) — codec in config/consensus.
    pub extra_data: String,
    pub miner: HexAddress,
}

/// Safe tip after confirmation-depth (MVP-1 finality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeHead {
    pub number: u64,
    pub hash: HexHash,
    pub state_root: HexHash,
    pub distinct_sealers: u32,
    pub required_sealers: u32,
}

/// Compute >⅔ threshold: `floor(2N/3)+1`.
pub fn min_distinct_sealers(n_seal: u32) -> u32 {
    if n_seal == 0 {
        return 0;
    }
    (2 * n_seal) / 3 + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_n21_is_15() {
        assert_eq!(min_distinct_sealers(21), 15);
    }

    #[test]
    fn threshold_table() {
        // floor(2N/3)+1
        assert_eq!(min_distinct_sealers(22), 15); // 14+1
        assert_eq!(min_distinct_sealers(45), 31); // elected pool — not used for seals
    }

    #[test]
    fn checkpoint_rejects_wrong_chain() {
        let cp = Checkpoint {
            chain_id: 1,
            number: 1,
            hash: "0x00".into(),
            parent_hash: "0x00".into(),
            state_root: "0x00".into(),
            timestamp: 0,
            fork_id: "test".into(),
            sealing_set: vec!["0xabc".into()],
            vote_keys: None,
            attestation: None,
        };
        assert!(matches!(
            cp.validate_basic(),
            Err(TypesError::UnsupportedChainId(1))
        ));
    }

    fn sample_set(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("0x{:040x}", i)).collect()
    }

    #[test]
    fn checkpoint_rejects_bad_or_duplicate_sealer() {
        let mut cp = Checkpoint {
            chain_id: 56,
            number: 1,
            hash: "0x00".into(),
            parent_hash: "0x00".into(),
            state_root: "0x00".into(),
            timestamp: 0,
            fork_id: "fermi".into(),
            sealing_set: vec!["0xabc".into()],
            vote_keys: None,
            attestation: None,
        };
        assert!(matches!(
            cp.validate_basic(),
            Err(TypesError::BadSealingAddress)
        ));
        cp.sealing_set = sample_set(21);
        cp.hash = format!("0x{}", "aa".repeat(32));
        cp.parent_hash = format!("0x{}", "bb".repeat(32));
        cp.state_root = format!("0x{}", "cc".repeat(32));
        cp.validate_basic().unwrap();
        cp.sealing_set[20] = cp.sealing_set[0].clone();
        assert!(matches!(
            cp.validate_basic(),
            Err(TypesError::DuplicateSealingAddress)
        ));
        cp.sealing_set = sample_set(21);
        cp.hash = "0x00".into();
        assert!(matches!(
            cp.validate_basic(),
            Err(TypesError::BadCheckpointHash { field: "hash" })
        ));
    }

    #[test]
    fn checkpoint_rejects_duplicate_sealer_hex_case() {
        let mut cp = Checkpoint {
            chain_id: 56,
            number: 1,
            hash: format!("0x{}", "aa".repeat(32)),
            parent_hash: format!("0x{}", "bb".repeat(32)),
            state_root: format!("0x{}", "cc".repeat(32)),
            timestamp: 0,
            fork_id: "fermi".into(),
            sealing_set: sample_set(21),
            vote_keys: None,
            attestation: None,
        };
        cp.sealing_set[0] = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        cp.sealing_set[20] = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(matches!(
            cp.validate_basic(),
            Err(TypesError::DuplicateSealingAddress)
        ));
    }
}
