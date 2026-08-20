//! Verified balances vs an independent oracle at the local Safe head.

use crate::upstream::RpcUpstream;
use anyhow::{anyhow, Context, Result};
use helios_bsc_execution::{encode_qty, qty_equal, verify_eth_get_proof, EthAccountProof};
use helios_bsc_types::{decode_hex_fixed, SafeHead};
use std::collections::HashSet;

/// Demo Slice soak set (≥10). Same list as `scripts/soak_vs_oracle.py`.
pub const SOAK_ADDRESSES: &[(&str, &str)] = &[
    ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
    ("USDT", "0x55d398326f99059fF775485246999027B3197955"),
    ("USDC", "0x8AC76a51cc950d9822D68b83fe1Ad97B32Cd580d"),
    ("Cake", "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"),
    ("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"),
    (
        "PancakeRouter",
        "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    ),
    (
        "PancakeFactory",
        "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    ),
    (
        "VenusUnitroller",
        "0xfD36E2c2a6789Db23113685031d7F16329158384",
    ),
    ("VenusVBNB", "0xA07c5b74C9B18179ce657c4d74e5CE8C674C96a3"),
    (
        "VenusTreasury",
        "0xF322942f644A996A617BD29c16bd7d231d9F35E9",
    ),
    ("BinanceHot", "0xe2fc31F816A9b94326492132018C3aEcC4a93aE1"),
    ("TokenHub", "0x0000000000000000000000000000000000001004"),
    ("ETH", "0x2170Ed0880ac9A755fd29B2688956BD959F933F8"),
    ("DAI", "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3"),
    ("XVS", "0xcF6BB5389c92Bdda8a3747Ddb454cB7a64626C63"),
    ("BTCB", "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c"),
    ("ValidatorSet", "0x0000000000000000000000000000000000001000"),
    ("Slash", "0x0000000000000000000000000000000000001001"),
    ("SystemReward", "0x0000000000000000000000000000000000001002"),
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub compared: u32,
    pub matched: u32,
    pub mismatched: u32,
    pub skipped: u32,
}

impl DiffReport {
    pub fn accumulate(&mut self, other: &Self) {
        self.compared += other.compared;
        self.matched += other.matched;
        self.mismatched += other.mismatched;
        self.skipped += other.skipped;
    }
}

/// Lowercase 0x-address key for unique-address soak tracking.
pub fn addr_key(addr: &str) -> String {
    addr.to_ascii_lowercase()
}

/// Duration soak: after every listed address has matched once, later rounds
/// re-diff the full list at the new Safe (idle unique-only rounds are not a soak).
pub fn soak_repeat_full_list(duration_secs: u64, unique: usize, n_addrs: usize) -> bool {
    duration_secs > 0 && n_addrs > 0 && unique >= n_addrs
}

/// Whether a burst counts as empty for `max_empty`.
/// Unique hunt: no new address. Re-diff (`visit_all`): no successful compare
/// (re-matches are progress; do not starve the rest of the list).
pub fn soak_empty_burst(visit_all: bool, gained: u32, compared_this: u32) -> bool {
    if visit_all {
        compared_this == 0
    } else {
        gained == 0
    }
}

/// Addresses not yet matched (case-insensitive).
pub fn unmatched<'a>(
    addrs: &[(&'a str, &'a str)],
    done: &HashSet<String>,
) -> Vec<(&'a str, &'a str)> {
    addrs
        .iter()
        .copied()
        .filter(|(_, a)| !done.contains(&addr_key(a)))
        .collect()
}

/// Move the first `n` items to the back so a skipped burst does not starve later addresses.
pub fn rotate_front<T>(items: &mut [T], n: usize) {
    let n = n.min(items.len());
    if n == 0 || items.len() <= 1 {
        return;
    }
    items.rotate_left(n);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOutcome {
    Match { local: String, remote: String },
    Mismatch { local: String, remote: String },
    SkipProof(String),
    SkipOracle(String),
}

/// Retry after catch-up unless the verifier already rejected the proof (MPT).
/// Window/rate/`eth_getProof` RPC errors must not permanently drop an address.
pub fn proof_error_retryable(err: &str) -> bool {
    let m = err.to_ascii_lowercase();
    let fatal = m.contains("proof path mismatch")
        || m.contains("proof node hash mismatch")
        || m.contains("claimed field mismatch")
        || m.contains("invalid account leaf")
        || m.contains("key leftover")
        || m.contains("extra proof nodes")
        || m.contains("unexpected empty child");
    !fatal
}

/// One address at the Safe head. Skips are retryable (proof window / oracle history).
pub fn diff_one(
    proofs: &dyn RpcUpstream,
    oracle: &dyn RpcUpstream,
    name: &str,
    addr: &str,
    safe: &SafeHead,
) -> DiffOutcome {
    let local = match verified_account(proofs, addr, safe) {
        Ok(a) => a,
        Err(e) => return DiffOutcome::SkipProof(format!("{name}: {e:#}")),
    };
    let remote_bal = match oracle_balance(oracle, addr, safe) {
        Ok(q) => q,
        Err(e) => return DiffOutcome::SkipOracle(format!("{name}: {e:#}")),
    };
    if !qty_equal(&local.balance, &remote_bal) {
        return DiffOutcome::Mismatch {
            local: local.balance,
            remote: remote_bal,
        };
    }
    if let Ok(remote_n) = oracle_nonce(oracle, addr, safe) {
        if !qty_equal(&local.nonce, &remote_n) {
            return DiffOutcome::Mismatch {
                local: format!("nonce {}", local.nonce),
                remote: format!("nonce {remote_n}"),
            };
        }
    }
    DiffOutcome::Match {
        local: local.balance,
        remote: remote_bal,
    }
}

pub struct VerifiedQty {
    pub balance: String,
    pub nonce: String,
}

pub fn verified_account(
    proofs: &dyn RpcUpstream,
    addr: &str,
    safe: &SafeHead,
) -> Result<VerifiedQty> {
    let raw = proofs
        .get_proof_at_safe(addr, &[], &safe.hash, safe.number)
        .context("eth_getProof")?;
    let proof: EthAccountProof = serde_json::from_value(raw).context("decode eth_getProof")?;
    let root = decode_hex_fixed::<32>(&safe.state_root)?;
    let want = decode_hex_fixed::<20>(addr)?;
    let acc = verify_eth_get_proof(&root, &want, &proof)?;
    Ok(VerifiedQty {
        balance: encode_qty(&acc.balance_wei),
        nonce: format!("0x{:x}", acc.nonce),
    })
}

pub fn verified_balance(proofs: &dyn RpcUpstream, addr: &str, safe: &SafeHead) -> Result<String> {
    Ok(verified_account(proofs, addr, safe)?.balance)
}

pub fn oracle_balance(oracle: &dyn RpcUpstream, addr: &str, safe: &SafeHead) -> Result<String> {
    oracle
        .get_balance(addr, &safe.hash)
        .or_else(|_| oracle.get_balance(addr, &format!("0x{:x}", safe.number)))
        .map_err(|e| anyhow!("oracle historical skip: {e}"))
}

pub fn oracle_nonce(oracle: &dyn RpcUpstream, addr: &str, safe: &SafeHead) -> Result<String> {
    oracle
        .get_transaction_count(addr, &safe.hash)
        .or_else(|_| oracle.get_transaction_count(addr, &format!("0x{:x}", safe.number)))
        .map_err(|e| anyhow!("oracle nonce skip: {e}"))
}

/// MPT-verify each address against `proofs`, compare qty to `oracle` at Safe.
pub fn diff_vs_oracle(
    proofs: &dyn RpcUpstream,
    oracle: &dyn RpcUpstream,
    addresses: &[(&str, &str)],
    safe: &SafeHead,
) -> DiffReport {
    let mut r = DiffReport::default();
    for (name, addr) in addresses {
        match diff_one(proofs, oracle, name, addr, safe) {
            DiffOutcome::Match { local, remote } => {
                r.compared += 1;
                r.matched += 1;
                eprintln!("  {name}  local={local}  oracle={remote}  OK");
            }
            DiffOutcome::Mismatch { local, remote } => {
                r.compared += 1;
                r.mismatched += 1;
                eprintln!("  {name}  local={local}  oracle={remote}  MISMATCH");
            }
            DiffOutcome::SkipProof(e) => {
                r.skipped += 1;
                eprintln!("  {name}  SKIP proof: {e}");
            }
            DiffOutcome::SkipOracle(e) => {
                r.skipped += 1;
                eprintln!("  {name}  SKIP oracle: {e}");
            }
        }
    }
    r
}

/// Merge probe address into the soak list (probe first, no dupes).
pub fn soak_list(probe: &str) -> Vec<(&str, &str)> {
    let mut out = vec![("probe", probe)];
    for &(n, a) in SOAK_ADDRESSES {
        if !a.eq_ignore_ascii_case(probe) {
            out.push((n, a));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn duration_soak_repeats_when_unique_full() {
        assert!(!soak_repeat_full_list(0, 19, 19));
        assert!(!soak_repeat_full_list(3600, 10, 19));
        assert!(soak_repeat_full_list(3600, 19, 19));
        assert!(!soak_repeat_full_list(3600, 19, 0));
    }

    #[test]
    fn re_diff_match_is_not_empty_burst() {
        assert!(soak_empty_burst(false, 0, 2));
        assert!(!soak_empty_burst(false, 1, 2));
        assert!(!soak_empty_burst(true, 0, 2));
        assert!(soak_empty_burst(true, 0, 0));
        assert!(!soak_empty_burst(true, 0, 1));
    }

    #[test]
    fn soak_set_is_at_least_ten() {
        assert!(SOAK_ADDRESSES.len() >= 16);
        for (_, a) in SOAK_ADDRESSES {
            let h = a.trim_start_matches("0x");
            assert_eq!(h.len(), 40, "{a}");
        }
    }

    #[test]
    fn mpt_path_mismatch_is_not_retryable() {
        assert!(!proof_error_retryable("USDC: proof path mismatch"));
        assert!(!proof_error_retryable("claimed field mismatch: balance"));
        assert!(proof_error_retryable("historical state not available"));
        assert!(proof_error_retryable("USDT: eth_getProof"));
        assert!(proof_error_retryable("by-number: missing trie node"));
    }

    #[test]
    fn accumulate_sums_rounds() {
        let mut tot = DiffReport {
            compared: 2,
            matched: 2,
            mismatched: 0,
            skipped: 1,
        };
        tot.accumulate(&DiffReport {
            compared: 3,
            matched: 2,
            mismatched: 1,
            skipped: 0,
        });
        assert_eq!(tot.compared, 5);
        assert_eq!(tot.matched, 4);
        assert_eq!(tot.mismatched, 1);
        assert_eq!(tot.skipped, 1);
    }

    #[test]
    fn unmatched_drops_done_case_insensitive() {
        let addrs = [("A", "0xAA"), ("B", "0xBB"), ("C", "0xCC")];
        let mut done = HashSet::new();
        done.insert(addr_key("0xaa"));
        assert_eq!(unmatched(&addrs, &done), vec![("B", "0xBB"), ("C", "0xCC")]);
    }

    #[test]
    fn rotate_front_moves_skipped_burst_to_back() {
        let mut v = vec!["a", "b", "c", "d"];
        rotate_front(&mut v, 2);
        assert_eq!(v, vec!["c", "d", "a", "b"]);
        rotate_front(&mut v, 0);
        assert_eq!(v, vec!["c", "d", "a", "b"]);
        rotate_front(&mut v, 99);
        assert_eq!(v, vec!["c", "d", "a", "b"]);
    }
}
