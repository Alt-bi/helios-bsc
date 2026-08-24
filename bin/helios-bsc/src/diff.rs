//! Verified balances vs an independent oracle at the local Safe head.

use crate::upstream::RpcUpstream;
use anyhow::{anyhow, Context, Result};
use helios_bsc_consensus::VerifiedBlock;
use helios_bsc_execution::{
    encode_qty, eth_call_verified, qty_equal, verify_eth_get_proof, verify_storage_slot, CallTx,
    EthAccountProof,
};
use helios_bsc_types::{decode_hex_fixed, SafeHead};
use std::collections::HashSet;

/// Demo Slice soak set (≥10). Same list as `scripts/soak_vs_oracle.py`.
///
/// Every entry is a **BSC mainnet** address. The token names are symbols, not chains:
/// `PegETH` and `BTCB` are Binance-Peg contracts deployed on BSC (`name()` returns
/// "Ethereum Token" / "BTCB Token"), and `USDT` / `USDC` / `DAI` are likewise the
/// Binance-Peg issues. The rest is BSC-native either way: PancakeSwap, Venus, and the
/// Parlia system contracts at `0x…1000` ValidatorSet, `0x…1001` Slash, `0x…1002`
/// SystemReward and `0x…1004` TokenHub.
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
    // Binance-Peg "Ethereum Token" on BSC — a BEP-20 with the symbol ETH, not the
    // Ethereum chain. Labelled `PegETH` so a soak log cannot be read as cross-chain.
    ("PegETH", "0x2170Ed0880ac9A755fd29B2688956BD959F933F8"),
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
    /// How many comparisons actually reached each sub-check.
    ///
    /// Every sub-check past the balance is best-effort -- an oracle that cannot serve
    /// historical nonces or storage is a skip, not a failure. That is the right
    /// behaviour and a silent one: an oracle that never serves storage would leave the
    /// trie untested while every line still printed OK. Counted so the summary can say
    /// what was actually exercised, the same reason the gate counts `at_fast_head`.
    pub checked_balance: u32,
    pub checked_nonce: u32,
    pub checked_slot0: u32,
    pub checked_call: u32,
    pub checked_finality: u32,
}

impl DiffReport {
    pub fn accumulate(&mut self, other: &Self) {
        self.compared += other.compared;
        self.matched += other.matched;
        self.mismatched += other.mismatched;
        self.skipped += other.skipped;
        self.checked_balance += other.checked_balance;
        self.checked_nonce += other.checked_nonce;
        self.checked_slot0 += other.checked_slot0;
        self.checked_call += other.checked_call;
        self.checked_finality += other.checked_finality;
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
    Match {
        local: String,
        remote: String,
        /// Sub-checks this comparison reached, for the OK line and the tally.
        checks: DiffChecks,
    },
    Mismatch {
        local: String,
        remote: String,
    },
    SkipProof(String),
    SkipOracle(String),
}

/// `totalSupply()` — `keccak256("totalSupply()")[..4]`, the same selector under BEP-20
/// as under ERC-20.
///
/// The one cross-check worth running blind: it is a zero-argument view whose answer is a
/// pure function of verified state, so local and oracle must agree byte for byte at the
/// same block. Anything taking an argument would mean inventing one, and anything reading
/// block context would compare two different instants.
pub const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];

/// Addresses that answer `totalSupply()` — the BEP-20s in [`SOAK_ADDRESSES`].
///
/// BEP-20 is ERC-20 plus optional extras, and BSC runs an EVM, so the selector above is
/// byte-identical on both. The local name is the right one to use here.
///
/// Deliberately a short allow-list rather than "try it everywhere": a router or an EOA
/// reverts, and a soak that logged expected reverts would train its reader to ignore the
/// column that is supposed to mean something.
pub fn call_probe(addr: &str) -> Option<[u8; 4]> {
    const BEP20: &[&str] = &[
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", // WBNB
        "0x55d398326f99059ff775485246999027b3197955", // USDT
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", // USDC
        "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", // Cake
        "0xe9e7cea3dedca5984780bafc599bd69add087d56", // BUSD
        "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3", // DAI
        "0xcf6bb5389c92bdda8a3747ddb454cb7a64626c63", // XVS
        "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c", // BTCB
        "0x2170ed0880ac9a755fd29b2688956bd959f933f8", // Binance-Peg ETH
    ];
    BEP20
        .contains(&addr_key(addr).as_str())
        .then_some(TOTAL_SUPPLY_SELECTOR)
}

/// Cross-check one `eth_call` against the oracle at the same verified block.
///
/// `None` means there is nothing to compare here — no probe for this address, or the
/// Safe head is not a block this client has in `chain`. Neither is a failure.
///
/// This is the only live coverage the **EVM** path gets: `eth_call` executes proven
/// state through revm, and until now the soak never touched it. A wrong answer here is
/// as serious as a wrong balance, because both come back from methods this client calls
/// verified.
pub fn diff_call_one(
    proofs: &dyn RpcUpstream,
    oracle: &dyn RpcUpstream,
    addr: &str,
    safe: &SafeHead,
    chain: &[VerifiedBlock],
) -> Option<DiffOutcome> {
    let selector = call_probe(addr)?;
    let to = decode_hex_fixed::<20>(addr).ok()?;
    let hash = decode_hex_fixed::<32>(&safe.hash).ok()?;
    let local_block = chain
        .iter()
        .find(|b| b.number == safe.number && b.hash == hash)?;
    let block = crate::rpc_server::call_block_from_verified(local_block, chain);
    let tx = CallTx {
        from: [0u8; 20],
        to,
        data: selector.to_vec(),
        value: [0u8; 32],
        gas: None,
        access_list: Vec::new(),
    };

    let prover = crate::rpc_server::UpstreamProve { up: proofs };
    let local = match eth_call_verified(&prover, &block, &tx) {
        Ok(out) => format!("0x{}", hex::encode(out)),
        // Proof-window and budget misses are the same transient conditions the balance
        // path already treats as retryable, and an unsupported precompile is a refusal
        // by design. Never a mismatch.
        Err(e) => return Some(DiffOutcome::SkipProof(format!("eth_call: {e}"))),
    };
    let remote = match oracle_call(oracle, addr, &selector, safe) {
        Ok(v) => v,
        Err(e) => return Some(DiffOutcome::SkipOracle(format!("eth_call: {e}"))),
    };
    if !storage_word_equal(&local, &remote) {
        return Some(DiffOutcome::Mismatch {
            local: format!("totalSupply {local}"),
            remote: format!("totalSupply {remote}"),
        });
    }
    Some(DiffOutcome::Match {
        local,
        remote,
        checks: DiffChecks {
            call: true,
            ..DiffChecks::default()
        },
    })
}

fn oracle_call(
    oracle: &dyn RpcUpstream,
    addr: &str,
    selector: &[u8; 4],
    safe: &SafeHead,
) -> Result<String> {
    let data = format!("0x{}", hex::encode(selector));
    let at = |block: String| {
        oracle
            .unverified_call(
                "eth_call",
                &serde_json::json!([{ "to": addr, "data": data }, block]),
            )
            .and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("eth_call returned {v}"))
            })
    };
    at(safe.hash.clone())
        .or_else(|_| at(format!("0x{:x}", safe.number)))
        .map_err(|e| anyhow!("oracle call skip: {e}"))
}

/// Cross-check this client's BEP-126 heads against geth's own answer at the same block.
///
/// `parlia_getJustifiedNumber` / `parlia_getFinalizedNumber` are defined in v1.7.8
/// `consensus/parlia/api.go` as `snapshot(at that header).Attestation.TargetNumber` and
/// `.SourceNumber` -- word for word what [`Snapshot::justified`] and
/// [`Snapshot::finalized`] return. Both are taken **at a named block**, so this is an
/// exact equality, not a race between two moving tips.
///
/// It is the only direct coverage the attestation path gets. Everything else about
/// BEP-126 here is fixtures plus the indirect evidence that a walk did not wedge -- and
/// both bugs found in it this week (the Fermi ancestor window, the missing
/// `source < target` rule) were found by walking mainnet, not by the suite.
///
/// `None` when this client has no attestation yet. Skips cover an oracle that does not
/// expose the `parlia` namespace at all (most do not) and an oracle that is not on our
/// chain at that height -- neither is evidence of anything.
pub fn diff_finality_one(
    oracle: &dyn RpcUpstream,
    snap_number: u64,
    snap_hash: [u8; 32],
    local: (u64, u64),
) -> Option<DiffOutcome> {
    let (local_justified, local_finalized) = local;
    let block = format!("0x{snap_number:x}");

    // Same height is not the same block. Confirm the oracle is on our chain here before
    // comparing, or a reorg on either side reads as a finality disagreement.
    match oracle.header_by_number(snap_number) {
        Ok(h) => match decode_hex_fixed::<32>(&h.hash) {
            Ok(remote_hash) if remote_hash == snap_hash => {}
            Ok(_) => {
                return Some(DiffOutcome::SkipOracle(
                    "finality: oracle is on another block at this height".into(),
                ))
            }
            Err(e) => return Some(DiffOutcome::SkipOracle(format!("finality: {e}"))),
        },
        Err(e) => return Some(DiffOutcome::SkipOracle(format!("finality: {e}"))),
    }

    let ask = |method: &str| -> Result<u64> {
        let v = oracle.unverified_call(method, &serde_json::json!([block]))?;
        match &v {
            serde_json::Value::Number(n) => {
                n.as_u64().ok_or_else(|| anyhow!("{method} returned {v}"))
            }
            serde_json::Value::String(t) => {
                u64::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .map_err(|e| anyhow!("{method} returned {v}: {e}"))
            }
            _ => Err(anyhow!("{method} returned {v}")),
        }
    };
    let remote_justified = match ask("parlia_getJustifiedNumber") {
        Ok(v) => v,
        Err(e) => return Some(DiffOutcome::SkipOracle(format!("finality: {e}"))),
    };
    let remote_finalized = match ask("parlia_getFinalizedNumber") {
        Ok(v) => v,
        Err(e) => return Some(DiffOutcome::SkipOracle(format!("finality: {e}"))),
    };

    if local_justified != remote_justified || local_finalized != remote_finalized {
        return Some(DiffOutcome::Mismatch {
            local: format!("justified {local_justified} finalized {local_finalized}"),
            remote: format!("justified {remote_justified} finalized {remote_finalized}"),
        });
    }
    Some(DiffOutcome::Match {
        local: format!("justified {local_justified} finalized {local_finalized}"),
        remote: format!("justified {remote_justified} finalized {remote_finalized}"),
        checks: DiffChecks {
            finality: true,
            ..DiffChecks::default()
        },
    })
}

/// Which best-effort sub-checks a matching comparison reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiffChecks {
    pub nonce: bool,
    pub slot0: bool,
    /// An `eth_call` cross-check ran. Tracked separately because it is a whole extra
    /// comparison, not a field of the account one.
    pub call: bool,
    /// A `parlia_*` finality cross-check ran. Also a standalone comparison.
    pub finality: bool,
}

impl DiffChecks {
    /// `balance,nonce,slot0` — the balance is never optional, so it always leads.
    pub fn label(&self) -> String {
        let mut v = vec!["balance"];
        if self.nonce {
            v.push("nonce");
        }
        if self.slot0 {
            v.push("slot0");
        }
        if self.call {
            // A call comparison stands alone; it does not carry a balance.
            return "eth_call".into();
        }
        if self.finality {
            return "parlia_finality".into();
        }
        v.join(",")
    }
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
    let mut checks = DiffChecks::default();
    if let Ok(remote_n) = oracle_nonce(oracle, addr, safe) {
        if !qty_equal(&local.nonce, &remote_n) {
            return DiffOutcome::Mismatch {
                local: format!("nonce {}", local.nonce),
                remote: format!("nonce {remote_n}"),
            };
        }
        checks.nonce = true;
    }
    // An oracle that cannot serve historical storage is a skip, exactly as for the
    // nonce; an oracle that answers and disagrees is a mismatch.
    if let (Some(local_s), Ok(remote_s)) = (&local.slot0, oracle_slot0(oracle, addr, safe)) {
        if !storage_word_equal(local_s, &remote_s) {
            return DiffOutcome::Mismatch {
                local: format!("slot0 {local_s}"),
                remote: format!("slot0 {remote_s}"),
            };
        }
        checks.slot0 = true;
    }
    DiffOutcome::Match {
        local: local.balance,
        remote: remote_bal,
        checks,
    }
}

pub struct VerifiedQty {
    pub balance: String,
    pub nonce: String,
    /// Slot 0, MPT-verified against the account's `storageRoot`.
    ///
    /// `None` when the upstream answered without a `storageProof` entry for it. Not
    /// every provider honours `storageKeys`, and losing the balance comparison over a
    /// missing extra would trade away a check we have for one we merely wanted. An entry
    /// that *is* present and does not verify stays fatal: that is a lying upstream, not
    /// a thin one.
    pub slot0: Option<String>,
}

/// The storage word every soaked address is cross-checked on.
///
/// Slot 0 needs no ABI: it is the first storage word of any contract and simply absent
/// for an EOA, and the trie has to answer both correctly. It rides along on the
/// `eth_getProof` the balance already costs -- one extra key on a request being made
/// anyway -- and it is the only live differential coverage the **storage** trie gets.
/// Balances only ever exercise the account trie.
pub const SOAK_STORAGE_SLOT: [u8; 32] = [0u8; 32];

/// Did the upstream actually answer for this storage key? Keys are compared as
/// quantities: `0x0` and a zero-padded 32-byte word name the same slot.
fn proof_carries_slot(proof: &EthAccountProof, slot_hex: &str) -> bool {
    proof
        .storage_proof
        .iter()
        .any(|e| storage_word_equal(&e.key, slot_hex))
}

fn slot0_hex() -> String {
    format!("0x{}", hex::encode(SOAK_STORAGE_SLOT))
}

/// `eth_getStorageAt` returns a full 32-byte word; `verify_storage_slot` returns the
/// RLP-stripped integer. Compare them as quantities, not as strings.
fn storage_word_equal(local: &str, remote: &str) -> bool {
    fn strip(v: &str) -> String {
        let h = v.trim_start_matches("0x").trim_start_matches("0X");
        let t = h.trim_start_matches('0');
        if t.is_empty() {
            "0".into()
        } else {
            t.to_ascii_lowercase()
        }
    }
    strip(local) == strip(remote)
}

pub fn verified_account(
    proofs: &dyn RpcUpstream,
    addr: &str,
    safe: &SafeHead,
) -> Result<VerifiedQty> {
    let raw = proofs
        .get_proof_at_safe(addr, &[slot0_hex()], &safe.hash, safe.number)
        .context("eth_getProof")?;
    let proof: EthAccountProof = serde_json::from_value(raw).context("decode eth_getProof")?;
    let root = decode_hex_fixed::<32>(&safe.state_root)?;
    let want = decode_hex_fixed::<20>(addr)?;
    let acc = verify_eth_get_proof(&root, &want, &proof)?;
    // Presence is decided before verification so that "the provider did not send it"
    // and "the provider sent something wrong" stay different answers.
    let slot0 = if proof_carries_slot(&proof, &slot0_hex()) {
        let raw = verify_storage_slot(&acc, &SOAK_STORAGE_SLOT, &proof)
            .context("verify storage slot 0")?;
        Some(encode_qty(&raw))
    } else {
        None
    };
    Ok(VerifiedQty {
        balance: encode_qty(&acc.balance_wei),
        nonce: format!("0x{:x}", acc.nonce),
        slot0,
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

pub fn oracle_slot0(oracle: &dyn RpcUpstream, addr: &str, safe: &SafeHead) -> Result<String> {
    let at = |block: String| {
        oracle
            .unverified_call(
                "eth_getStorageAt",
                &serde_json::json!([addr, slot0_hex(), block]),
            )
            .and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("eth_getStorageAt returned {v}"))
            })
    };
    at(safe.hash.clone())
        .or_else(|_| at(format!("0x{:x}", safe.number)))
        .map_err(|e| anyhow!("oracle storage skip: {e}"))
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
            DiffOutcome::Match {
                local,
                remote,
                checks,
            } => {
                r.compared += 1;
                r.matched += 1;
                r.checked_balance += 1;
                r.checked_nonce += u32::from(checks.nonce);
                r.checked_slot0 += u32::from(checks.slot0);
                eprintln!(
                    "  {name}  local={local}  oracle={remote}  OK [{}]",
                    checks.label()
                );
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
        // `..Default::default()` on purpose: this test is about accumulation, and a new
        // counter should not make it fail to compile.
        let mut tot = DiffReport {
            compared: 2,
            matched: 2,
            skipped: 1,
            checked_balance: 2,
            checked_nonce: 2,
            checked_slot0: 1,
            ..DiffReport::default()
        };
        tot.accumulate(&DiffReport {
            compared: 3,
            matched: 2,
            mismatched: 1,
            checked_balance: 3,
            checked_nonce: 3,
            checked_call: 2,
            ..DiffReport::default()
        });
        assert_eq!(tot.compared, 5);
        assert_eq!(tot.matched, 4);
        assert_eq!(tot.mismatched, 1);
        assert_eq!(tot.skipped, 1);
        // The sub-check tallies must accumulate too, or a long soak would report only
        // the last round's coverage.
        assert_eq!(tot.checked_nonce, 5);
        assert_eq!(
            tot.checked_slot0, 1,
            "an oracle that stopped serving storage"
        );
    }

    /// The label is what an operator reads to see a sub-check silently going missing.
    #[test]
    fn check_label_names_what_actually_ran() {
        assert_eq!(DiffChecks::default().label(), "balance");
        assert_eq!(
            DiffChecks {
                nonce: true,
                ..DiffChecks::default()
            }
            .label(),
            "balance,nonce"
        );
        assert_eq!(
            DiffChecks {
                nonce: true,
                slot0: true,
                ..DiffChecks::default()
            }
            .label(),
            "balance,nonce,slot0"
        );
        // A call comparison stands alone -- it never carries a balance, so labelling it
        // `balance,eth_call` would claim a check that did not run.
        assert_eq!(
            DiffChecks {
                call: true,
                ..DiffChecks::default()
            }
            .label(),
            "eth_call"
        );
        assert_eq!(
            DiffChecks {
                finality: true,
                ..DiffChecks::default()
            }
            .label(),
            "parlia_finality"
        );
    }

    /// `eth_getStorageAt` pads to 32 bytes, `verify_storage_slot` returns the stripped
    /// integer. Comparing those as strings would call every slot a mismatch.
    #[test]
    fn storage_words_compare_as_quantities() {
        assert!(storage_word_equal(
            "0x1",
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(storage_word_equal(
            "0x0",
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
        // WBNB slot 0 is the packed `name` string, not a small integer.
        assert!(storage_word_equal(
            "0x5772617070656420424e42000000000000000000000000000000000000000016",
            "0x5772617070656420424E42000000000000000000000000000000000000000016"
        ));
        assert!(!storage_word_equal("0x1", "0x2"));
        assert!(!storage_word_equal("0x0", "0x1"));
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
