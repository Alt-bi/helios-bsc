//! Fork-aware Parlia parameters.
//!
//! Pinned to `bnb-chain/bsc` **v1.7.8**
//! (`cdb7548b5baacfdae92f9f63437d6456411665f3`).
//! Source: `params/config.go` `BSCChainConfig` + `consensus/parlia/{parlia,snapshot}.go`.

use helios_bsc_types::min_distinct_sealers;
use serde::{Deserialize, Serialize};

pub mod extra;

pub use extra::{parse_extra, ExtraError, ParsedExtra, SealingValidator};

/// Exact upstream pin recorded in `docs/hardfork-table.md`.
pub const BSC_UPSTREAM_TAG: &str = "v1.7.8";
pub const BSC_UPSTREAM_COMMIT: &str = "cdb7548b5baacfdae92f9f63437d6456411665f3";

/// Network identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    BscMainnet,
}

/// Mainnet fork times / heights from `BSCChainConfig` (v1.7.8).
pub const LONDON_BLOCK: u64 = 31_302_048;
pub const LUBAN_BLOCK: u64 = 29_020_050;
pub const PLATO_BLOCK: u64 = 30_720_096;
pub const BOHR_TIME: u64 = 1_727_317_200;
pub const LORENTZ_TIME: u64 = 1_745_903_100;
pub const MAXWELL_TIME: u64 = 1_751_250_600;
pub const FERMI_TIME: u64 = 1_768_357_800;
pub const OSAKA_MENDEL_TIME: u64 = 1_777_343_400;
/// Live since 2026-08-25 02:30 UTC. Already in the pinned v1.7.8 tree, and it changes
/// no Parlia rule — see [`fermi_family`] — so activation needed no client change.
pub const PASTEUR_TIME: u64 = 1_787_625_000;

pub const DEFAULT_EPOCH_LENGTH: u64 = 200;
pub const LORENTZ_EPOCH_LENGTH: u64 = 500;
pub const MAXWELL_EPOCH_LENGTH: u64 = 1000;

pub const DEFAULT_BLOCK_INTERVAL_MS: u64 = 3000;
pub const LORENTZ_BLOCK_INTERVAL_MS: u64 = 1500;
pub const MAXWELL_BLOCK_INTERVAL_MS: u64 = 750;
pub const FERMI_BLOCK_INTERVAL_MS: u64 = 450;

pub const EXTRA_VANITY: usize = 32;
pub const EXTRA_SEAL: usize = 65;
pub const NEXT_FORK_HASH_SIZE: usize = 4;
pub const TURN_LENGTH_SIZE: usize = 1;
pub const VALIDATOR_BYTES_BEFORE_LUBAN: usize = 20;
pub const VALIDATOR_BYTES: usize = 68; // 20 addr + 48 BLS
/// Light-client cap on epoch `turnLength` (live=8; source comments mention 16).
/// Not a geth constant — blocks a 255-byte delay bomb in extraData.
pub const MAX_TURN_LENGTH: u8 = 64;
pub const VALIDATOR_NUMBER_SIZE: usize = 1;

pub const DIFF_IN_TURN: u64 = 2;
pub const DIFF_NO_TURN: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkParams {
    pub name: &'static str,
    /// Inclusive activation block if the fork is height-gated.
    pub activation_block: Option<u64>,
    /// Inclusive activation unix time if the fork is time-gated.
    pub activation_time: Option<u64>,
    pub epoch_length: u64,
    pub turn_length: u64,
    /// Nominal block interval milliseconds.
    pub block_interval_ms: u64,
    /// extraData layout family for the light-client codec.
    pub extra_data_version: ExtraDataVersion,
}

/// extraData codec family. Newer forks are supersets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtraDataVersion {
    /// vanity + optional 20-byte validators + seal
    PreLuban,
    /// + n:u8 + (addr20+bls48)*n on epoch + RLP vote attestation
    Luban,
    /// + turnLength:u8 on epoch extra
    Bohr,
}

/// Fermi / Pasteur share epochLength, turnLength, interval, extraData family.
///
/// This is **verified**, not assumed. Pasteur is already present in the pinned
/// `v1.7.8` tree (`params/config.go` sets mainnet `PasteurTime` to the same
/// `PASTEUR_TIME` this crate pins), and `IsPasteur` appears nowhere in
/// `consensus/parlia/{parlia,snapshot,ramanujanfork}.go` -- the fork changes no
/// Parlia rule, so epoch length, turn length, block interval and the extraData
/// layout all carry over from Fermi unchanged. Nor does it touch BSC's blob
/// schedule, which lists only Cancun/Prague/Osaka with the latter two aliased to
/// `DefaultCancunBlobConfig`.
///
/// What Pasteur *does* change is precompile behaviour, at an address set
/// identical to Osaka's: `0x64` and `0x65` become the `Deprecated` variants and
/// `0x67` becomes `cometBFTLightBlockValidatePasteur` (per-byte gas). All three
/// are already refused by `precompile_kind` as chain precompiles the local EVM
/// does not implement, so none of it is reachable from `eth_call`.
fn fermi_family(name: &'static str, activation_time: u64) -> ForkParams {
    ForkParams {
        name,
        activation_block: None,
        activation_time: Some(activation_time),
        epoch_length: MAXWELL_EPOCH_LENGTH,
        // Live value from fixtures/mainnet/header_116664000.json (epoch extraData).
        // Source comments mention 16 as a Maxwell-era possibility; do not assume it.
        turn_length: 8,
        block_interval_ms: FERMI_BLOCK_INTERVAL_MS,
        extra_data_version: ExtraDataVersion::Bohr,
    }
}

/// v1.7.8 `consensus/parlia/parlia.go`:
///
/// ```text
/// kAncestorGenerationDepth = 3
///
/// func (p *Parlia) GetAncestorGenerationDepth(header *types.Header) uint64 {
///     if p.chainConfig.IsFermi(header.Number, header.Time) {
///         return kAncestorGenerationDepth
///     }
///     return 1
/// }
/// ```
pub const K_ANCESTOR_GENERATION_DEPTH: u64 = 3;

/// How many generations back from the parent `verifyVoteAttestation` will look for an
/// attestation's target.
///
/// Before Fermi this is 1 -- the target must be the direct parent. From Fermi on it is
/// [`K_ANCESTOR_GENERATION_DEPTH`], so the target may equally be the parent's parent or
/// its grandparent. Treating the pre-Fermi rule as universal rejects honest mainnet
/// headers: BSC produces them routinely, and one is enough to wedge a client that walks
/// sequentially.
///
/// `IsFermi` is `IsLondon(num) && isTimestampForked(FermiTime, time)`; both halves are
/// kept even though Fermi is far past London, because that is what the source says.
pub fn ancestor_generation_depth(number: u64, timestamp: u64) -> u64 {
    if number >= LONDON_BLOCK && timestamp >= FERMI_TIME {
        K_ANCESTOR_GENERATION_DEPTH
    } else {
        1
    }
}

/// Target block numbers `verifyVoteAttestation` will accept for a header at `number`:
/// the parent, down to [`ancestor_generation_depth`] generations counted from it.
pub fn attestation_target_window(number: u64, timestamp: u64) -> std::ops::RangeInclusive<u64> {
    let parent = number.saturating_sub(1);
    let depth = ancestor_generation_depth(number, timestamp);
    parent.saturating_sub(depth.saturating_sub(1))..=parent
}

/// Pin-date Parlia profile (`v1.7.8`). For a live header use [`params_at`].
pub fn mainnet_current_fork() -> ForkParams {
    fermi_family("fermi", FERMI_TIME)
}

/// Resolve Parlia params at a header's (number, timestamp).
pub fn params_at(number: u64, timestamp: u64) -> ForkParams {
    if timestamp >= PASTEUR_TIME {
        return fermi_family("pasteur", PASTEUR_TIME);
    }
    if timestamp >= FERMI_TIME {
        return fermi_family("fermi", FERMI_TIME);
    }
    if timestamp >= MAXWELL_TIME {
        return ForkParams {
            name: "maxwell",
            activation_block: None,
            activation_time: Some(MAXWELL_TIME),
            epoch_length: MAXWELL_EPOCH_LENGTH,
            turn_length: 8,
            block_interval_ms: MAXWELL_BLOCK_INTERVAL_MS,
            extra_data_version: ExtraDataVersion::Bohr,
        };
    }
    if timestamp >= LORENTZ_TIME {
        return ForkParams {
            name: "lorentz",
            activation_block: None,
            activation_time: Some(LORENTZ_TIME),
            epoch_length: LORENTZ_EPOCH_LENGTH,
            turn_length: 8,
            block_interval_ms: LORENTZ_BLOCK_INTERVAL_MS,
            extra_data_version: ExtraDataVersion::Bohr,
        };
    }
    if timestamp >= BOHR_TIME {
        return ForkParams {
            name: "bohr",
            activation_block: None,
            activation_time: Some(BOHR_TIME),
            epoch_length: DEFAULT_EPOCH_LENGTH,
            turn_length: 4,
            block_interval_ms: DEFAULT_BLOCK_INTERVAL_MS,
            extra_data_version: ExtraDataVersion::Bohr,
        };
    }
    if number >= LUBAN_BLOCK {
        let name = if number >= PLATO_BLOCK {
            "plato"
        } else {
            "luban"
        };
        return ForkParams {
            name,
            activation_block: Some(if number >= PLATO_BLOCK {
                PLATO_BLOCK
            } else {
                LUBAN_BLOCK
            }),
            activation_time: None,
            epoch_length: DEFAULT_EPOCH_LENGTH,
            turn_length: 1,
            block_interval_ms: DEFAULT_BLOCK_INTERVAL_MS,
            extra_data_version: ExtraDataVersion::Luban,
        };
    }
    ForkParams {
        name: "legacy",
        activation_block: Some(0),
        activation_time: None,
        epoch_length: DEFAULT_EPOCH_LENGTH,
        turn_length: 1,
        block_interval_ms: DEFAULT_BLOCK_INTERVAL_MS,
        extra_data_version: ExtraDataVersion::PreLuban,
    }
}

pub fn mainnet_n_seal() -> u32 {
    21
}

/// Design MVP-1 fork choice: accept a reorg only within `N_seal` of the local tip.
pub fn max_reorg_depth() -> u64 {
    u64::from(mainnet_n_seal())
}

pub fn mainnet_min_distinct_sealers() -> u32 {
    min_distinct_sealers(mainnet_n_seal())
}

/// `Snapshot.minerHistoryCheckLen = (N/2+1)*turnLength - 1`.
///
/// Epoch extraData published at `E` activates at `E + miner_history_check_len`.
pub fn miner_history_check_len(n_seal: u32, turn_length: u64) -> u64 {
    if n_seal == 0 || turn_length == 0 {
        return 0;
    }
    (u64::from(n_seal) / 2 + 1) * turn_length - 1
}

/// Rough expected Safe lag in blocks: O(min_distinct * turn_length).
pub fn expected_safe_lag_blocks() -> u64 {
    u64::from(mainnet_min_distinct_sealers()) * mainnet_current_fork().turn_length
}

/// Wall-clock Safe lag for `lag` subsequent blocks at `block_interval_ms`.
pub fn safe_lag_seconds(lag_blocks: u64, block_interval_ms: u64) -> u64 {
    lag_blocks.saturating_mul(block_interval_ms) / 1000
}

/// In-turn upper bound in seconds (`expected_safe_lag_blocks` × interval).
pub fn expected_safe_lag_seconds() -> u64 {
    safe_lag_seconds(
        expected_safe_lag_blocks(),
        mainnet_current_fork().block_interval_ms,
    )
}

/// Safe-lag SLO uses the in-turn upper bound, not a protocol constant.
pub fn slo_safe_lag_blocks_max() -> u64 {
    expected_safe_lag_blocks()
}

pub fn safe_lag_within_slo(lag_blocks: u64) -> bool {
    lag_blocks <= slo_safe_lag_blocks_max()
}

pub fn pasteur_is_live(now_unix: u64) -> bool {
    now_unix >= PASTEUR_TIME
}

/// Operator-facing Pasteur line (no secrets). The pin already contains the fork, and
/// it changes no Parlia rule -- see [`fermi_family`] -- so this reports rather than warns.
pub fn pasteur_status_line(now_unix: u64) -> String {
    if pasteur_is_live(now_unix) {
        format!(
            "pasteur: LIVE (unix {PASTEUR_TIME}) — pin {BSC_UPSTREAM_TAG} already covers it; no Parlia rule changes"
        )
    } else {
        let secs = PASTEUR_TIME.saturating_sub(now_unix);
        let days = secs / 86_400;
        format!(
            "pasteur: in ~{days}d (unix {PASTEUR_TIME} = 2026-08-25 02:30 UTC); pin {BSC_UPSTREAM_TAG}"
        )
    }
}

/// Temporary provider proof window (Ankr free, 2026-08-18).
/// Security is still `min_distinct_sealers`; this only caps how far back we fetch proofs.
/// Swap the key if proofs at newest-Safe start failing.
pub const PROVIDER_PROOF_LOOKBACK: u64 = 112;

/// Headers fetched without `--checkpoint` (must cover newest-Safe ≈ 106–112).
pub const DEFAULT_LOOKBACK: u64 = 130;

/// Max distance from a trusted checkpoint to live tip (~2 h @ 0.45 s).
/// Lookback 130 is only ~1 min — too tight for `run` restart from last-verified.
pub const DEFAULT_MAX_SYNC: u64 = 16_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1000_not_200() {
        assert_eq!(mainnet_current_fork().epoch_length, 1000);
    }

    #[test]
    fn max_sync_outlives_lookback() {
        const { assert!(DEFAULT_MAX_SYNC > DEFAULT_LOOKBACK) };
        const { assert!(DEFAULT_MAX_SYNC > PROVIDER_PROOF_LOOKBACK) };
    }

    #[test]
    fn safe_threshold_15() {
        assert_eq!(mainnet_min_distinct_sealers(), 15);
    }

    #[test]
    fn max_reorg_depth_is_n_seal() {
        assert_eq!(crate::max_reorg_depth(), 21);
        assert_eq!(max_reorg_depth(), u64::from(mainnet_n_seal()));
    }

    #[test]
    fn miner_history_legacy_is_n_over_2() {
        // turnLength=1, N=21 → (10+1)*1 - 1 = 10
        assert_eq!(miner_history_check_len(21, 1), 10);
    }

    #[test]
    fn miner_history_if_turn16_is_175() {
        assert_eq!(miner_history_check_len(21, 16), 175);
    }

    #[test]
    fn miner_history_live_turn8_is_87() {
        assert_eq!(miner_history_check_len(21, 8), 87);
        assert_eq!(
            miner_history_check_len(mainnet_n_seal(), mainnet_current_fork().turn_length),
            87
        );
    }

    #[test]
    fn fermi_profile_at_current_time() {
        let p = params_at(80_000_000, FERMI_TIME + 1);
        assert_eq!(p.name, "fermi");
        assert_eq!(p.epoch_length, 1000);
        assert_eq!(p.turn_length, 8);
        assert_eq!(p.block_interval_ms, 450);
        assert_eq!(p.extra_data_version, ExtraDataVersion::Bohr);
    }

    #[test]
    fn pin_is_v178() {
        assert_eq!(BSC_UPSTREAM_TAG, "v1.7.8");
        assert_eq!(BSC_UPSTREAM_COMMIT.len(), 40);
    }

    #[test]
    fn pasteur_is_named_after_activation() {
        let p = params_at(80_000_000, PASTEUR_TIME);
        assert_eq!(p.name, "pasteur");
        assert_eq!(p.epoch_length, 1000);
        assert_eq!(p.turn_length, 8);
        assert_eq!(p.block_interval_ms, 450);
        assert_eq!(p.extra_data_version, ExtraDataVersion::Bohr);
        let fermi = params_at(80_000_000, PASTEUR_TIME - 1);
        assert_eq!(fermi.name, "fermi");
        assert_eq!(fermi.epoch_length, p.epoch_length);
        assert_eq!(fermi.turn_length, p.turn_length);
        assert_eq!(fermi.block_interval_ms, p.block_interval_ms);
    }

    /// The fork is not an announcement we are tracking -- it is in the pinned tree.
    /// `params/config.go` at `v1.7.8` sets mainnet `PasteurTime: newUint64(1787625000)`,
    /// and `IsPasteur` appears in none of `consensus/parlia/*.go`, so `fermi_family`
    /// inheriting every Parlia parameter is read off the source rather than assumed.
    #[test]
    fn pasteur_time_matches_the_pinned_upstream_config() {
        assert_eq!(PASTEUR_TIME, 1_787_625_000);
        let p = params_at(80_000_000, PASTEUR_TIME);
        let fermi = mainnet_current_fork();
        assert_eq!(p.epoch_length, fermi.epoch_length);
        assert_eq!(p.turn_length, fermi.turn_length);
        assert_eq!(p.block_interval_ms, fermi.block_interval_ms);
        assert_eq!(p.extra_data_version, fermi.extra_data_version);
    }

    /// The case that wedged a live walk on 2026-08-22: header 117425792 carried an
    /// attestation targeting 117425789 while its parent was 117425791. That is legal
    /// from Fermi on -- `kAncestorGenerationDepth = 3` -- and was rejected by the
    /// pre-Fermi "target must be the direct parent" rule, which stopped the walk dead.
    #[test]
    fn attestation_target_window_covers_three_generations_on_fermi() {
        let w = attestation_target_window(117_425_792, FERMI_TIME + 1);
        assert_eq!(*w.end(), 117_425_791, "the parent");
        assert_eq!(*w.start(), 117_425_789, "two generations below it");
        assert!(
            w.contains(&117_425_789),
            "the target that used to be refused"
        );
        assert!(!w.contains(&117_425_788), "one generation too deep");
        assert!(
            !w.contains(&117_425_792),
            "the header is not its own ancestor"
        );
    }

    /// Before Fermi the depth really is 1, so the old rule was right for its era. The
    /// window must not be widened retroactively over pre-Fermi history.
    #[test]
    fn attestation_target_window_is_the_parent_alone_before_fermi() {
        assert_eq!(ancestor_generation_depth(117_425_792, FERMI_TIME - 1), 1);
        assert_eq!(ancestor_generation_depth(117_425_792, FERMI_TIME), 3);
        let w = attestation_target_window(117_425_792, FERMI_TIME - 1);
        assert_eq!(*w.start(), 117_425_791);
        assert_eq!(*w.end(), 117_425_791);
        // `IsFermi` is gated on London too: a block below it is pre-Fermi whatever the
        // clock says.
        assert_eq!(
            ancestor_generation_depth(LONDON_BLOCK - 1, FERMI_TIME + 1),
            1
        );
    }

    #[test]
    fn pin_profile_stays_fermi_until_re_pin() {
        assert_eq!(mainnet_current_fork().name, "fermi");
    }

    #[test]
    fn safe_lag_seconds_live_window() {
        // 108–112 blocks × 450 ms ≈ 48–50 s; in-turn upper 120 × 0.45 = 54 s.
        assert_eq!(safe_lag_seconds(108, FERMI_BLOCK_INTERVAL_MS), 48);
        assert_eq!(safe_lag_seconds(112, FERMI_BLOCK_INTERVAL_MS), 50);
        assert_eq!(expected_safe_lag_seconds(), 54);
        assert!(safe_lag_within_slo(112));
        assert!(safe_lag_within_slo(120));
        assert!(!safe_lag_within_slo(121));
    }

    #[test]
    fn pasteur_status_line_before_and_after() {
        let before = pasteur_status_line(PASTEUR_TIME - 1);
        assert!(before.contains("in ~"), "{before}");
        assert!(before.contains("v1.7.8"), "{before}");
        assert!(!before.contains("LIVE"), "{before}");
        let live = pasteur_status_line(PASTEUR_TIME);
        assert!(live.contains("LIVE"), "{live}");
        assert!(live.contains("v1.7.8"), "{live}");
        assert!(pasteur_is_live(PASTEUR_TIME));
        assert!(!pasteur_is_live(PASTEUR_TIME - 1));
    }
}
