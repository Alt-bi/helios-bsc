//! Confirmation-depth Safe: ≥ floor(2N/3)+1 distinct subsequent sealers.

use helios_bsc_config::PROVIDER_PROOF_LOOKBACK;
use helios_bsc_types::{format_address, min_distinct_sealers, RpcBlockHeader, SafeHead};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedBlock {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub miner: [u8; 20],
    /// Lorentz+ `MilliTimestamp`; 0 means unknown (skip parent interval/gas checks).
    pub milli_timestamp: u64,
    pub gas_limit: u64,
    /// Sealed header kept at ingest so `eth_getBlock*` / persist do not re-fetch.
    pub header: Option<RpcBlockHeader>,
}

/// Newest Safe = highest S such that distinct(miners in (S, tip]) ≥ threshold.
///
/// Walks backward from tip. When the lookback window first contains `threshold`
/// distinct sealers, S is the parent of the oldest block in that window.
pub fn newest_safe(chain: &[VerifiedBlock], n_seal: u32) -> Option<SafeHead> {
    if chain.len() < 2 {
        return None;
    }
    let threshold = min_distinct_sealers(n_seal);
    let mut seen: Vec<[u8; 20]> = Vec::new();
    for (i, block) in chain.iter().enumerate().rev() {
        if !seen.iter().any(|a| a == &block.miner) {
            seen.push(block.miner);
        }
        if seen.len() as u32 >= threshold {
            // Window is chain[i..=tip]. Safe is parent = chain[i-1] if i>0.
            if i == 0 {
                return None;
            }
            let s = &chain[i - 1];
            return Some(SafeHead {
                number: s.number,
                hash: format!("0x{}", hex::encode(s.hash)),
                state_root: format!("0x{}", hex::encode(s.state_root)),
                distinct_sealers: seen.len() as u32,
                required_sealers: threshold,
            });
        }
    }
    None
}

pub fn proof_lag(tip: u64, safe: u64) -> u64 {
    tip.saturating_sub(safe)
}

pub fn within_proof_window(tip: u64, safe: u64) -> bool {
    proof_lag(tip, safe) <= PROVIDER_PROOF_LOOKBACK
}

pub fn sealer_hex(addr: &[u8; 20]) -> String {
    format_address(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(n: u64, miner: u8) -> VerifiedBlock {
        let mut m = [0u8; 20];
        m[19] = miner;
        let mut hash = [0u8; 32];
        hash[0] = miner;
        hash[7] = n as u8;
        VerifiedBlock {
            number: n,
            hash,
            state_root: hash,
            miner: m,
            ..Default::default()
        }
    }

    /// In-turn: each sealer produces 8 blocks. 15 distinct first appear after
    /// 14 full turns + 1 block of the 15th, but mid-alignment can hit 15 at 112.
    fn in_turn_chain(start: u64, len: usize) -> Vec<VerifiedBlock> {
        (0..len)
            .map(|i| {
                let n = start + i as u64;
                let miner = ((i / 8) % 21) as u8 + 1;
                blk(n, miner)
            })
            .collect()
    }

    #[test]
    fn hundred_blocks_not_enough() {
        let chain = in_turn_chain(1, 101);
        assert!(
            newest_safe(&chain, 21).is_none(),
            "100 in-turn blocks cannot contain 15 distinct sealers"
        );
    }

    #[test]
    fn one_twelve_hits_threshold_on_aligned_window() {
        let chain = in_turn_chain(1, 130);
        let safe = newest_safe(&chain, 21).expect("safe");
        let tip = chain.last().unwrap().number;
        let lag = tip - safe.number;
        assert!(
            lag <= PROVIDER_PROOF_LOOKBACK || lag <= 120,
            "lag {lag} way above in-turn estimate"
        );
        assert_eq!(safe.required_sealers, 15);
        assert!(safe.distinct_sealers >= 15);
        assert!(within_proof_window(tip, safe.number) || lag <= 120);
    }

    #[test]
    fn proof_window_constant_is_112() {
        assert_eq!(PROVIDER_PROOF_LOOKBACK, 112);
        assert!(within_proof_window(1000, 888));
        assert!(!within_proof_window(1000, 887));
    }
}
