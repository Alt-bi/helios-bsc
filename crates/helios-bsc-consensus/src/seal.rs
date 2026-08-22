//! Parlia ECDSA seal recovery (`types.SealHash` + `ecrecover`).
//!
//! Pinned to `bnb-chain/bsc` v1.7.8 `core/types/block.go` `EncodeSigHeader`.

use crate::rlp_util::{encode_bytes, encode_list, encode_uint};
use helios_bsc_config::{
    params_at, parse_extra, ExtraDataVersion, ExtraError, BOHR_TIME, DIFF_IN_TURN, DIFF_NO_TURN,
    EXTRA_SEAL, EXTRA_VANITY, LORENTZ_TIME, MAX_TURN_LENGTH,
};
use helios_bsc_types::{
    address_from_pubkey_uncompressed, decode_hex, decode_hex_fixed, decode_u64, format_address,
    keccak256, RpcBlockHeader, TypesError, BSC_MAINNET_CHAIN_ID,
};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, SECP256K1};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealError {
    #[error(transparent)]
    Types(#[from] TypesError),
    #[error("extraData too short for vanity+seal")]
    ExtraTooShort,
    #[error("invalid recovery id {0}")]
    BadRecoveryId(u8),
    #[error("secp256k1 recover failed: {0}")]
    Recover(String),
    #[error("coinbase mismatch: recovered {recovered}, miner {miner}")]
    CoinbaseMismatch { recovered: String, miner: String },
    #[error(
        "Parlia difficulty {got} is not {DIFF_NO_TURN} (out-of-turn) or {DIFF_IN_TURN} (in-turn)"
    )]
    BadDifficulty { got: u64 },
    #[error("non-empty uncle hash (Parlia forbids uncles)")]
    InvalidUncles,
    #[error("gasUsed {used} exceeds gasLimit {limit}")]
    InvalidGasUsed { used: u64, limit: u64 },
    #[error("gasLimit {got} exceeds 2^63-1")]
    InvalidGasLimit { got: u64 },
    #[error("invalid mixDigest (Lorentz milliseconds / pre-Lorentz zero)")]
    InvalidMixDigest,
    #[error("invalid parentBeaconRoot (Bohr+ expects the zero hash)")]
    InvalidParentBeaconRoot,
    /// RPC `hash` ≠ keccak256(RLP(header)) (`types.Header.Hash()`).
    #[error("header hash mismatch (geth Header.Hash())")]
    HashMismatch,
    #[error("header extraData exceeds 100KiB")]
    ExtraTooLong,
    #[error("withdrawalsRoot is not the empty trie hash")]
    InvalidWithdrawalsRoot,
    #[error("block MilliTimestamp {got} < parent {parent} + interval {interval}ms")]
    TimestampTooEarly {
        got: u64,
        parent: u64,
        interval: u64,
    },
    #[error(
        "out-of-turn block MilliTimestamp {got} < parent {parent} + interval {interval}ms \
         + backoff {backoff}ms"
    )]
    OutOfTurnTooEarly {
        got: u64,
        parent: u64,
        interval: u64,
        backoff: u64,
    },
    #[error("gasLimit {got} outside parent {parent} ± bound {bound}")]
    GasLimitBound { got: u64, parent: u64, bound: u64 },
    #[error("header timestamp {time} is in the future (now {now})")]
    FutureBlock { time: u64, now: u64 },
    #[error("Parlia nonce must be the empty 8-byte nonce")]
    InvalidNonce,
    #[error(transparent)]
    Extra(#[from] ExtraError),
    #[error("epoch extraData has no validators")]
    MissingEpochExtra,
    #[error("epoch extraData turnLength is out of range 1..={MAX_TURN_LENGTH}")]
    InvalidTurnLength,
    #[error("epoch extraData has a duplicate validator address")]
    DuplicateValidator,
}

/// `keccak256(rlp([]))` — Parlia/Clique empty uncle list.
pub const EMPTY_UNCLE_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];

/// Empty MPT root — Cancun+ `withdrawalsRoot` (geth `EmptyWithdrawalsHash`).
pub const EMPTY_WITHDRAWALS_HASH: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// geth `VerifyUnsealedHeader`: gasLimit ≤ 2^63-1.
const GAS_LIMIT_MAX: u64 = 0x7fff_ffff_ffff_ffff;
/// `params.MinGasLimit`.
const MIN_GAS_LIMIT: u64 = 5_000;
/// Lorentz+ `params.GasLimitBoundDivisor`.
const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;
/// Pre-Lorentz Parlia `gasLimitBoundDivisorBeforeLorentz`.
const GAS_LIMIT_BOUND_DIVISOR_PRE_LORENTZ: u64 = 256;
/// geth `Header.SanityCheck` extra cap.
const EXTRA_MAX: usize = 100 * 1024;

/// `types.SealHash(header, chainId)` — keccak256 of `EncodeSigHeader`.
pub fn seal_hash(header: &RpcBlockHeader, chain_id: u64) -> Result<[u8; 32], SealError> {
    let extra = decode_hex(&header.extra_data)?;
    if extra.len() < EXTRA_VANITY + EXTRA_SEAL {
        return Err(SealError::ExtraTooShort);
    }
    let extra_wo_seal = &extra[..extra.len() - EXTRA_SEAL];

    let parent = decode_hex_fixed::<32>(&header.parent_hash)?;
    let uncle = decode_hex_fixed::<32>(&header.sha3_uncles)?;
    let coinbase = decode_hex_fixed::<20>(&header.miner)?;
    let root = decode_hex_fixed::<32>(&header.state_root)?;
    let tx_hash = decode_hex_fixed::<32>(&header.transactions_root)?;
    let receipt = decode_hex_fixed::<32>(&header.receipts_root)?;
    let bloom = decode_hex(&header.logs_bloom)?;
    let difficulty = decode_u64(&header.difficulty)?;
    let number = decode_u64(&header.number)?;
    let gas_limit = decode_u64(&header.gas_limit)?;
    let gas_used = decode_u64(&header.gas_used)?;
    let time = decode_u64(&header.timestamp)?;
    let mix = decode_hex_fixed::<32>(&header.mix_hash)?;
    let nonce = decode_hex_fixed::<8>(&header.nonce)?;

    let mut items: Vec<Vec<u8>> = vec![
        encode_uint(u128::from(chain_id)),
        encode_bytes(&parent),
        encode_bytes(&uncle),
        encode_bytes(&coinbase),
        encode_bytes(&root),
        encode_bytes(&tx_hash),
        encode_bytes(&receipt),
        encode_bytes(&bloom),
        encode_uint(u128::from(difficulty)),
        encode_uint(u128::from(number)),
        encode_uint(u128::from(gas_limit)),
        encode_uint(u128::from(gas_used)),
        encode_uint(u128::from(time)),
        encode_bytes(extra_wo_seal),
        encode_bytes(&mix),
        encode_bytes(&nonce),
    ];

    // Bohr+ / Cancun+ / Prague: if ParentBeaconRoot is present, append the
    // post-London optional fields exactly as EncodeSigHeader does.
    if header.parent_beacon_block_root.is_some() {
        let base_fee = header
            .base_fee_per_gas
            .as_deref()
            .map(decode_u64)
            .transpose()?
            .unwrap_or(0);
        let withdrawals = header
            .withdrawals_root
            .as_deref()
            .map(decode_hex_fixed::<32>)
            .transpose()?
            .unwrap_or([0u8; 32]);
        let blob_gas = header
            .blob_gas_used
            .as_deref()
            .map(decode_u64)
            .transpose()?
            .unwrap_or(0);
        let excess = header
            .excess_blob_gas
            .as_deref()
            .map(decode_u64)
            .transpose()?
            .unwrap_or(0);
        let beacon = decode_hex_fixed::<32>(
            header
                .parent_beacon_block_root
                .as_deref()
                .expect("checked is_some"),
        )?;
        items.push(encode_uint(u128::from(base_fee)));
        items.push(encode_bytes(&withdrawals));
        items.push(encode_uint(u128::from(blob_gas)));
        items.push(encode_uint(u128::from(excess)));
        items.push(encode_bytes(&beacon));
        if let Some(req) = header.requests_hash.as_deref() {
            items.push(encode_bytes(&decode_hex_fixed::<32>(req)?));
        }
    }

    Ok(keccak256(&encode_list(&items)))
}

/// geth `Header.Hash()`: keccak256(RLP(header)). Not SealHash (no chainId; extra **includes** seal).
///
/// Optional London+ fields follow `core/types/gen_header_rlp.go` (v1.7.8): encode from the
/// first present field through the last; missing intermediates are empty strings (`0x80`).
pub fn header_hash(header: &RpcBlockHeader) -> Result<[u8; 32], SealError> {
    let parent = decode_hex_fixed::<32>(&header.parent_hash)?;
    let uncle = decode_hex_fixed::<32>(&header.sha3_uncles)?;
    let coinbase = decode_hex_fixed::<20>(&header.miner)?;
    let root = decode_hex_fixed::<32>(&header.state_root)?;
    let tx_hash = decode_hex_fixed::<32>(&header.transactions_root)?;
    let receipt = decode_hex_fixed::<32>(&header.receipts_root)?;
    let bloom = decode_hex_fixed::<256>(&header.logs_bloom)?;
    let difficulty = decode_u64(&header.difficulty)?;
    let number = decode_u64(&header.number)?;
    let gas_limit = decode_u64(&header.gas_limit)?;
    let gas_used = decode_u64(&header.gas_used)?;
    let time = decode_u64(&header.timestamp)?;
    let extra = decode_hex(&header.extra_data)?;
    let mix = decode_hex_fixed::<32>(&header.mix_hash)?;
    let nonce = decode_hex_fixed::<8>(&header.nonce)?;

    let mut items: Vec<Vec<u8>> = vec![
        encode_bytes(&parent),
        encode_bytes(&uncle),
        encode_bytes(&coinbase),
        encode_bytes(&root),
        encode_bytes(&tx_hash),
        encode_bytes(&receipt),
        encode_bytes(&bloom),
        encode_uint(u128::from(difficulty)),
        encode_uint(u128::from(number)),
        encode_uint(u128::from(gas_limit)),
        encode_uint(u128::from(gas_used)),
        encode_uint(u128::from(time)),
        encode_bytes(&extra),
        encode_bytes(&mix),
        encode_bytes(&nonce),
    ];

    let has_base = header.base_fee_per_gas.is_some();
    let has_wd = header.withdrawals_root.is_some();
    let has_blob = header.blob_gas_used.is_some();
    let has_excess = header.excess_blob_gas.is_some();
    let has_beacon = header.parent_beacon_block_root.is_some();
    let has_req = header.requests_hash.is_some();
    if has_base || has_wd || has_blob || has_excess || has_beacon || has_req {
        items.push(encode_opt_uint(header.base_fee_per_gas.as_deref())?);
    }
    if has_wd || has_blob || has_excess || has_beacon || has_req {
        items.push(encode_opt_hash(header.withdrawals_root.as_deref())?);
    }
    if has_blob || has_excess || has_beacon || has_req {
        items.push(encode_opt_uint(header.blob_gas_used.as_deref())?);
    }
    if has_excess || has_beacon || has_req {
        items.push(encode_opt_uint(header.excess_blob_gas.as_deref())?);
    }
    if has_beacon || has_req {
        items.push(encode_opt_hash(header.parent_beacon_block_root.as_deref())?);
    }
    if has_req {
        items.push(encode_opt_hash(header.requests_hash.as_deref())?);
    }

    Ok(keccak256(&encode_list(&items)))
}

fn encode_opt_uint(s: Option<&str>) -> Result<Vec<u8>, SealError> {
    match s {
        None => Ok(vec![0x80]),
        Some(x) => Ok(encode_uint(u128::from(decode_u64(x)?))),
    }
}

fn encode_opt_hash(s: Option<&str>) -> Result<Vec<u8>, SealError> {
    match s {
        None => Ok(vec![0x80]),
        Some(x) => Ok(encode_bytes(&decode_hex_fixed::<32>(x)?)),
    }
}

/// Require RPC `hash` == [`header_hash`].
pub fn verify_header_hash(header: &RpcBlockHeader) -> Result<[u8; 32], SealError> {
    let computed = header_hash(header)?;
    let claimed = decode_hex_fixed::<32>(&header.hash)?;
    if computed != claimed {
        return Err(SealError::HashMismatch);
    }
    Ok(computed)
}

pub fn recover_signer(header: &RpcBlockHeader, chain_id: u64) -> Result<[u8; 20], SealError> {
    let extra = decode_hex(&header.extra_data)?;
    if extra.len() < EXTRA_SEAL {
        return Err(SealError::ExtraTooShort);
    }
    let seal = &extra[extra.len() - EXTRA_SEAL..];
    let digest = seal_hash(header, chain_id)?;
    ecrecover(&digest, seal)
}

pub fn ecrecover(digest: &[u8; 32], seal: &[u8]) -> Result<[u8; 20], SealError> {
    if seal.len() != EXTRA_SEAL {
        return Err(SealError::ExtraTooShort);
    }
    let mut v = seal[64];
    if v >= 27 {
        v -= 27;
    }
    let rec_id =
        RecoveryId::try_from(i32::from(v)).map_err(|_| SealError::BadRecoveryId(seal[64]))?;
    let sig = RecoverableSignature::from_compact(&seal[..64], rec_id)
        .map_err(|e| SealError::Recover(e.to_string()))?;
    let msg = Message::from_digest(*digest);
    let pk = SECP256K1
        .recover_ecdsa(&msg, &sig)
        .map_err(|e| SealError::Recover(e.to_string()))?;
    address_from_pubkey_uncompressed(&pk.serialize_uncompressed()).map_err(SealError::from)
}

/// Allowed clock skew vs `header.Time` (geth is strict `> now`; 15s avoids rejecting the tip).
pub const MAX_FUTURE_SKEW_SECS: u64 = 15;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parlia `verifyHeader`: reject `header.Time` more than [`MAX_FUTURE_SKEW_SECS`] ahead of `now`.
pub fn verify_timestamp_not_future(
    header: &RpcBlockHeader,
    now_unix: u64,
) -> Result<(), SealError> {
    let time = decode_u64(&header.timestamp)?;
    if time > now_unix.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(SealError::FutureBlock {
            time,
            now: now_unix,
        });
    }
    Ok(())
}

/// Lorentz+ `Header.MilliTimestamp`: `Time*1000 + MixDigest` last two bytes.
pub fn milli_timestamp(header: &RpcBlockHeader) -> Result<u64, SealError> {
    let time = decode_u64(&header.timestamp)?;
    let mix = decode_hex_fixed::<32>(&header.mix_hash)?;
    if time < LORENTZ_TIME {
        return Ok(time.saturating_mul(1000));
    }
    let ms = u64::from(u16::from_be_bytes([mix[30], mix[31]]));
    Ok(time.saturating_mul(1000).saturating_add(ms))
}

/// Standalone `VerifyUnsealedHeader` checks that do not need the parent snapshot.
pub fn verify_unsealed_fields(header: &RpcBlockHeader) -> Result<(), SealError> {
    let extra = decode_hex(&header.extra_data)?;
    if extra.len() > EXTRA_MAX {
        return Err(SealError::ExtraTooLong);
    }
    let uncles = decode_hex_fixed::<32>(&header.sha3_uncles)?;
    if uncles != EMPTY_UNCLE_HASH {
        return Err(SealError::InvalidUncles);
    }
    let gas_limit = decode_u64(&header.gas_limit)?;
    if gas_limit > GAS_LIMIT_MAX {
        return Err(SealError::InvalidGasLimit { got: gas_limit });
    }
    let gas_used = decode_u64(&header.gas_used)?;
    if gas_used > gas_limit {
        return Err(SealError::InvalidGasUsed {
            used: gas_used,
            limit: gas_limit,
        });
    }
    let time = decode_u64(&header.timestamp)?;
    let mix = decode_hex_fixed::<32>(&header.mix_hash)?;
    if time < LORENTZ_TIME {
        if mix != [0u8; 32] {
            return Err(SealError::InvalidMixDigest);
        }
    } else {
        let milli = milli_timestamp(header)?;
        if milli / 1000 != time {
            return Err(SealError::InvalidMixDigest);
        }
    }
    if time >= BOHR_TIME {
        let Some(root) = header.parent_beacon_block_root.as_deref() else {
            return Err(SealError::InvalidParentBeaconRoot);
        };
        let got = decode_hex_fixed::<32>(root)?;
        if got != [0u8; 32] {
            return Err(SealError::InvalidParentBeaconRoot);
        }
    }
    if let Some(w) = header.withdrawals_root.as_deref() {
        let got = decode_hex_fixed::<32>(w)?;
        if got != EMPTY_WITHDRAWALS_HASH {
            return Err(SealError::InvalidWithdrawalsRoot);
        }
    }
    let nonce = decode_hex_fixed::<8>(&header.nonce)?;
    if nonce != [0u8; 8] {
        return Err(SealError::InvalidNonce);
    }
    verify_timestamp_not_future(header, unix_now())?;
    verify_extra_layout(header)?;
    Ok(())
}

/// Bohr+ extraData: epoch blocks must parse `n` validator records + turnLength > 0.
/// Lookback-only still does **not** check sealing-set membership.
pub fn verify_extra_layout(header: &RpcBlockHeader) -> Result<(), SealError> {
    let extra = decode_hex(&header.extra_data)?;
    let number = decode_u64(&header.number)?;
    let time = decode_u64(&header.timestamp)?;
    let p = params_at(number, time);
    let is_epoch = number % p.epoch_length == 0;
    let parsed = parse_extra(&extra, p.extra_data_version, is_epoch)?;
    if is_epoch {
        if parsed.validators.is_empty() {
            return Err(SealError::MissingEpochExtra);
        }
        let mut seen = std::collections::HashSet::with_capacity(parsed.validators.len());
        for v in &parsed.validators {
            if !seen.insert(v.address) {
                return Err(SealError::DuplicateValidator);
            }
        }
        if matches!(p.extra_data_version, ExtraDataVersion::Bohr) {
            match parsed.turn_length {
                Some(t) if t > 0 && t <= MAX_TURN_LENGTH => {}
                _ => return Err(SealError::InvalidTurnLength),
            }
        }
    }
    Ok(())
}

/// Parent-dependent checks: Ramanujan floor `parent.milli + BlockInterval` and Lorentz+
/// gasLimit bound (`|Δ| < parent/1024`, min 5000).
///
/// This is the whole rule for in-turn headers, where geth's `backOffTime` is `0`. The
/// out-of-turn refinement needs snapshot state and lives in [`verify_out_of_turn_backoff`],
/// which `Snapshot::apply_verified` applies on top of this floor.
///
/// `parent_gas_limit == 0` skips (unknown parent fields, e.g. dummy test genesis).
pub fn verify_cascading_vs_parent(
    parent_milli: u64,
    parent_gas_limit: u64,
    header: &RpcBlockHeader,
) -> Result<(), SealError> {
    if parent_gas_limit == 0 {
        return Ok(());
    }
    let number = decode_u64(&header.number)?;
    let time = decode_u64(&header.timestamp)?;
    let interval = params_at(number, time).block_interval_ms;
    let got_milli = milli_timestamp(header)?;
    let min_milli = parent_milli.saturating_add(interval);
    if got_milli < min_milli {
        return Err(SealError::TimestampTooEarly {
            got: got_milli,
            parent: parent_milli,
            interval,
        });
    }
    let gas = decode_u64(&header.gas_limit)?;
    if gas < MIN_GAS_LIMIT {
        return Err(SealError::InvalidGasLimit { got: gas });
    }
    let divisor = if time >= LORENTZ_TIME {
        GAS_LIMIT_BOUND_DIVISOR
    } else {
        GAS_LIMIT_BOUND_DIVISOR_PRE_LORENTZ
    };
    let bound = parent_gas_limit / divisor;
    let diff = parent_gas_limit.abs_diff(gas);
    if diff >= bound {
        return Err(SealError::GasLimitBound {
            got: gas,
            parent: parent_gas_limit,
            bound,
        });
    }
    Ok(())
}

/// v1.7.8 `consensus/parlia/parlia.go` `wiggleTime` — per-step backoff spacing.
pub const WIGGLE_TIME_MS: u64 = 1000;
/// v1.7.8 `consensus/parlia/parlia.go` `lorentzInitialBackOffTime`.
pub const LORENTZ_INITIAL_BACKOFF_MS: u64 = 2000;
/// v1.7.8 `consensus/parlia/parlia.go` `defaultInitialBackOffTime` (pre-Lorentz parents).
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 1000;

/// Parent-snapshot facts needed to bound `backOffTime` for an out-of-turn header.
///
/// Every field is "what the snapshot at the **parent** knows"; see
/// [`verify_out_of_turn_backoff`] for how each one is used.
#[derive(Debug, Clone, Copy)]
pub struct BackoffContext {
    /// `parent.MilliTimestamp()`.
    pub parent_milli: u64,
    /// False whenever the client cannot reproduce geth's inputs — no sealing set, a
    /// padded set (`enforce_inturn == false`), or a `countRecents` window that was not
    /// fully walked. Makes the whole check a no-op.
    pub known: bool,
    /// `snap.signRecentlyByCounts(snap.inturnValidator(), snap.countRecents())`.
    ///
    /// Must be `true` whenever the client is not certain it is `false`: geth zeroes the
    /// initial backoff in that case, so a wrong `false` here would reject an honest block.
    pub in_turn_signed_recently: bool,
}

/// Out-of-turn backoff floor — the enforceable part of Parlia's `backOffTime`.
///
/// v1.7.8 `consensus/parlia/ramanujanfork.go` `blockTimeVerifyForRamanujanFork` shows this
/// is a **verifier** rule, not just a sealing rule (`verifyCascadingFields` calls it):
///
/// ```text
/// func (p *Parlia) blockTimeVerifyForRamanujanFork(snap *Snapshot, header, parent *types.Header) error {
///     if p.chainConfig.IsRamanujan(header.Number) {
///         if header.MilliTimestamp() < parent.MilliTimestamp()+snap.BlockInterval+p.backOffTime(snap, parent, header, header.Coinbase) {
///             return consensus.ErrFutureBlock
///         }
///     }
///     return nil
/// }
/// ```
///
/// `backOffTime` (v1.7.8 `consensus/parlia/parlia.go`) returns `0` for an in-turn sealer,
/// so for `difficulty == diffInTurn` this collapses to the plain Ramanujan floor already
/// enforced by [`verify_cascading_vs_parent`]. The out-of-turn branch, for a parent past
/// Lorentz (so `IsPlanck` and `IsBohr` also hold — the only combination mainnet runs), is:
///
/// ```text
/// delay := defaultInitialBackOffTime
/// isParerntLorentz := p.chainConfig.IsLorentz(parent.Number, parent.Time)
/// if isParerntLorentz {
///     delay = lorentzInitialBackOffTime
/// }
/// ...
///     inTurnAddr := snap.inturnValidator()
///     if snap.signRecentlyByCounts(inTurnAddr, counts) {
///         delay = 0
///     }
/// ...
/// if delay == 0 && isParerntLorentz {
///     if backOffSteps[idx] == 0 {
///         return 0
///     }
///     return lorentzInitialBackOffTime + (backOffSteps[idx]-1)*wiggleTime
/// }
/// delay += backOffSteps[idx] * wiggleTime
/// return delay
/// ```
///
/// `backOffSteps` is `[0..n)` shuffled by `rand.New(rand.NewSource(randSeed)).Shuffle` —
/// Go's `math/rand` additive lagged-Fibonacci generator, whose state is seeded from a
/// 607-entry table baked into Go's runtime. That term is **not** reproduced here.
///
/// What *is* reproduced is a bound that holds whatever the shuffle produces. `backOffTime`
/// has exactly four `0` returns, and `verifyCascadingFields` has already excluded three of
/// them by the time this runs:
///
/// - `snap.inturn(val)` — excluded: the caller has matched `difficulty` against
///   `snap.inturn`, so a `diffNoTurn` header's sealer is not the in-turn validator.
/// - `snap.signRecentlyByCounts(val, counts)` — excluded: `errRecentlySigned` rejects the
///   header before the timing check.
/// - `idx < 0` — excluded: the sealer is in the set, is not in-turn and has not signed
///   recently, so it survives both exclusion filters and has an index.
/// - `delay == 0 && backOffSteps[idx] == 0` — this is the one that depends on the shuffle,
///   and it is reachable **only** when `delay` was zeroed, i.e. only when the in-turn
///   validator signed recently. [`BackoffContext::in_turn_signed_recently`] gates it.
///
/// So when the in-turn validator has *not* signed recently, `delay` keeps its initial value
/// and the function returns `delay + backOffSteps[idx]*wiggleTime >= delay`. The floor below
/// uses `delay` alone, dropping the non-negative shuffled term. It is therefore a strict
/// **under**-estimate of geth's `backOffTime`: every header geth accepts, this accepts.
///
/// `interval_ms` likewise comes from the header's fork rather than geth's `snap.BlockInterval`
/// (which is the parent's, and never smaller, since intervals only shrink across forks) —
/// again erring low on purpose.
pub fn verify_out_of_turn_backoff(
    ctx: BackoffContext,
    header: &RpcBlockHeader,
) -> Result<(), SealError> {
    // Any uncertainty, or a possibly-zeroed `delay`, means no constraint at all.
    if !ctx.known || ctx.in_turn_signed_recently {
        return Ok(());
    }
    if decode_u64(&header.difficulty)? != DIFF_NO_TURN {
        return Ok(());
    }
    // `IsLorentz(parent.Number, parent.Time)` — deliberately the *parent's* clock, as geth
    // notes: `header.Time` is temporarily `now+1` while mining, so it cannot gate the fork.
    let parent_time = ctx.parent_milli / 1000;
    let backoff = if parent_time >= LORENTZ_TIME {
        LORENTZ_INITIAL_BACKOFF_MS
    } else {
        DEFAULT_INITIAL_BACKOFF_MS
    };

    let number = decode_u64(&header.number)?;
    let time = decode_u64(&header.timestamp)?;
    let interval = params_at(number, time).block_interval_ms;
    let got = milli_timestamp(header)?;
    let floor = ctx
        .parent_milli
        .saturating_add(interval)
        .saturating_add(backoff);
    if got < floor {
        return Err(SealError::OutOfTurnTooEarly {
            got,
            parent: ctx.parent_milli,
            interval,
            backoff,
        });
    }
    Ok(())
}

/// `diffNoTurn=1` / `diffInTurn=2`. Other values are never valid Parlia headers.
pub fn assert_difficulty_range(difficulty: u64) -> Result<(), SealError> {
    if difficulty != DIFF_NO_TURN && difficulty != DIFF_IN_TURN {
        return Err(SealError::BadDifficulty { got: difficulty });
    }
    Ok(())
}

/// Recover signer and require it equals `header.miner` (Parlia `errCoinBaseMisMatch`).
pub fn verify_seal_coinbase(header: &RpcBlockHeader) -> Result<[u8; 20], SealError> {
    verify_unsealed_fields(header)?;
    let difficulty = decode_u64(&header.difficulty)?;
    assert_difficulty_range(difficulty)?;
    let recovered = recover_signer(header, BSC_MAINNET_CHAIN_ID)?;
    let miner = decode_hex_fixed::<20>(&header.miner)?;
    if recovered != miner {
        return Err(SealError::CoinbaseMismatch {
            recovered: format_address(&recovered),
            miner: format_address(&miner),
        });
    }
    verify_header_hash(header)?;
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn load(name: &str) -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet")
            .join(name);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&raw).expect("header json")
    }

    #[test]
    fn fixtures_seal_matches_miner() {
        for name in [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ] {
            let h = load(name);
            verify_seal_coinbase(&h).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn mutated_seal_does_not_match_miner() {
        let mut h = load("header_116664000.json");
        let mut extra = decode_hex(&h.extra_data).unwrap();
        let last = extra.len() - 1;
        extra[last] ^= 0x01;
        h.extra_data = format!("0x{}", hex::encode(extra));
        assert!(verify_seal_coinbase(&h).is_err());
    }

    #[test]
    fn difficulty_outside_1_or_2_rejected() {
        let mut h = load("header_116664000.json");
        h.difficulty = "0x3".into();
        let err = verify_seal_coinbase(&h).unwrap_err();
        assert!(matches!(err, SealError::BadDifficulty { got: 3 }), "{err}");
        h.difficulty = "0x0".into();
        assert!(matches!(
            verify_seal_coinbase(&h).unwrap_err(),
            SealError::BadDifficulty { got: 0 }
        ));
    }

    #[test]
    fn fixtures_pass_unsealed_fields() {
        for name in [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ] {
            let h = load(name);
            verify_unsealed_fields(&h).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn uncle_hash_must_be_empty() {
        let mut h = load("header_116664000.json");
        h.sha3_uncles = format!("0x{}", hex::encode([0x11u8; 32]));
        assert!(matches!(
            verify_unsealed_fields(&h).unwrap_err(),
            SealError::InvalidUncles
        ));
    }

    #[test]
    fn gas_used_cannot_exceed_limit() {
        let mut h = load("header_116664000.json");
        h.gas_used = "0x7fffffffffffffff".into();
        h.gas_limit = "0x1".into();
        assert!(matches!(
            verify_unsealed_fields(&h).unwrap_err(),
            SealError::InvalidGasUsed { .. }
        ));
    }

    #[test]
    fn lorentz_mixdigest_milliseconds_must_fit() {
        let mut h = load("header_116664000.json");
        // 0x03e8 = 1000 ms → MilliTimestamp/1000 != Time
        let mut mix = [0u8; 32];
        mix[30] = 0x03;
        mix[31] = 0xe8;
        h.mix_hash = format!("0x{}", hex::encode(mix));
        assert!(matches!(
            verify_unsealed_fields(&h).unwrap_err(),
            SealError::InvalidMixDigest
        ));
    }

    #[test]
    fn fixtures_header_hash_matches_rpc_field() {
        for name in [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ] {
            let h = load(name);
            verify_header_hash(&h).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn lied_rpc_hash_field_rejected() {
        let mut h = load("header_116664000.json");
        verify_header_hash(&h).unwrap();
        h.hash = format!("0x{}", hex::encode([0x11u8; 32]));
        assert!(matches!(
            verify_seal_coinbase(&h).unwrap_err(),
            SealError::HashMismatch
        ));
    }

    #[test]
    fn fixtures_cascading_milli_is_at_least_interval() {
        let names = [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ];
        let headers: Vec<_> = names.iter().map(|n| load(n)).collect();
        for w in headers.windows(2) {
            let p_milli = milli_timestamp(&w[0]).unwrap();
            let p_gas = decode_u64(&w[0].gas_limit).unwrap();
            verify_cascading_vs_parent(p_milli, p_gas, &w[1])
                .unwrap_or_else(|e| panic!("{} -> {}: {e}", w[0].number, w[1].number));
        }
        let parent = &headers[0];
        let mut early = headers[1].clone();
        // MixDigest ms = 0 with same unix second as parent → below 450ms floor.
        early.timestamp = parent.timestamp.clone();
        early.mix_hash = format!("0x{}", hex::encode([0u8; 32]));
        let p_milli = milli_timestamp(parent).unwrap();
        let p_gas = decode_u64(&parent.gas_limit).unwrap();
        assert!(matches!(
            verify_cascading_vs_parent(p_milli, p_gas, &early).unwrap_err(),
            SealError::TimestampTooEarly { .. }
        ));
        let mut gas = headers[1].clone();
        gas.gas_limit = "0x1".into();
        assert!(matches!(
            verify_cascading_vs_parent(p_milli, p_gas, &gas).unwrap_err(),
            SealError::InvalidGasLimit { got: 1 } | SealError::GasLimitBound { .. }
        ));
    }

    /// Rewrite a header's `MilliTimestamp` (Lorentz+ splits it across `time` and `mixDigest`).
    fn set_milli(h: &mut RpcBlockHeader, milli: u64) {
        h.timestamp = format!("0x{:x}", milli / 1000);
        let mut mix = [0u8; 32];
        let ms = u16::try_from(milli % 1000).unwrap();
        mix[30..32].copy_from_slice(&ms.to_be_bytes());
        h.mix_hash = format!("0x{}", hex::encode(mix));
    }

    fn ctx(parent_milli: u64) -> BackoffContext {
        BackoffContext {
            parent_milli,
            known: true,
            in_turn_signed_recently: false,
        }
    }

    /// Boundary is geth's, not ours: `parent.MilliTimestamp() + snap.BlockInterval +
    /// lorentzInitialBackOffTime`, with the shuffled `backOffSteps[idx]*wiggleTime` term
    /// dropped (it is non-negative, so dropping it can only loosen the check).
    #[test]
    fn out_of_turn_floor_is_interval_plus_initial_backoff() {
        let mut h = load("header_116664001.json");
        h.difficulty = format!("0x{DIFF_NO_TURN:x}");
        // Post-Fermi fixture: snap.BlockInterval = 450ms, parent is well past Lorentz.
        let parent_milli = 1_787_059_567_700u64;
        let interval = params_at(
            decode_u64(&h.number).unwrap(),
            decode_u64(&h.timestamp).unwrap(),
        )
        .block_interval_ms;
        assert_eq!(interval, 450);
        let floor = parent_milli + interval + LORENTZ_INITIAL_BACKOFF_MS;
        assert_eq!(floor, parent_milli + 2450);

        set_milli(&mut h, floor);
        verify_out_of_turn_backoff(ctx(parent_milli), &h).expect("exactly at the floor is legal");

        set_milli(&mut h, floor + WIGGLE_TIME_MS);
        verify_out_of_turn_backoff(ctx(parent_milli), &h).expect("later is always legal");

        set_milli(&mut h, floor - 1);
        let err = verify_out_of_turn_backoff(ctx(parent_milli), &h).unwrap_err();
        assert!(
            matches!(err, SealError::OutOfTurnTooEarly { backoff: 2000, .. }),
            "{err}"
        );

        // The plain Ramanujan floor would have accepted this: the refinement is real.
        set_milli(&mut h, parent_milli + interval);
        let p_gas = decode_u64(&load("header_116664000.json").gas_limit).unwrap();
        verify_cascading_vs_parent(parent_milli, p_gas, &h)
            .expect("one interval clears the Ramanujan floor");
        assert!(verify_out_of_turn_backoff(ctx(parent_milli), &h).is_err());
    }

    /// `isParerntLorentz` reads the *parent's* clock, so a pre-Lorentz parent keeps
    /// `defaultInitialBackOffTime` (1000ms) with the 3000ms pre-Lorentz interval.
    #[test]
    fn pre_lorentz_parent_uses_default_initial_backoff() {
        let mut h = load("header_116664001.json");
        h.difficulty = format!("0x{DIFF_NO_TURN:x}");
        let parent_milli = (LORENTZ_TIME - 10) * 1000;
        let floor = parent_milli + 3000 + DEFAULT_INITIAL_BACKOFF_MS;

        h.timestamp = format!("0x{:x}", floor / 1000);
        assert_eq!(milli_timestamp(&h).unwrap(), floor);
        verify_out_of_turn_backoff(ctx(parent_milli), &h).unwrap();

        h.timestamp = format!("0x{:x}", (floor / 1000) - 1);
        let err = verify_out_of_turn_backoff(ctx(parent_milli), &h).unwrap_err();
        assert!(
            matches!(err, SealError::OutOfTurnTooEarly { backoff: 1000, .. }),
            "{err}"
        );
    }

    /// `backOffTime` returns 0 for an in-turn sealer, so `diffInTurn` headers keep the
    /// plain Ramanujan floor. Every mainnet fixture is in-turn and spaced one interval.
    #[test]
    fn in_turn_fixtures_unaffected_by_backoff_rule() {
        let names = [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ];
        let headers: Vec<_> = names.iter().map(|n| load(n)).collect();
        for w in headers.windows(2) {
            let p_milli = milli_timestamp(&w[0]).unwrap();
            assert_eq!(decode_u64(&w[1].difficulty).unwrap(), DIFF_IN_TURN);
            // Spacing is 450ms — far below the 2450ms out-of-turn floor, so this would
            // fail loudly if the rule ever leaked into the in-turn path.
            assert!(milli_timestamp(&w[1]).unwrap() - p_milli < LORENTZ_INITIAL_BACKOFF_MS);
            verify_out_of_turn_backoff(ctx(p_milli), &w[1])
                .unwrap_or_else(|e| panic!("{} -> {}: {e}", w[0].number, w[1].number));
        }
    }

    /// Both no-op gates: unknown context, and a possibly-zeroed `delay`.
    #[test]
    fn backoff_rule_is_a_noop_without_context() {
        let mut h = load("header_116664001.json");
        h.difficulty = format!("0x{DIFF_NO_TURN:x}");
        let parent_milli = 1_787_059_567_700u64;
        set_milli(&mut h, parent_milli + 450);
        assert!(verify_out_of_turn_backoff(ctx(parent_milli), &h).is_err());

        let unknown = BackoffContext {
            known: false,
            ..ctx(parent_milli)
        };
        verify_out_of_turn_backoff(unknown, &h).expect("no sealing set => no constraint");

        let zeroed = BackoffContext {
            in_turn_signed_recently: true,
            ..ctx(parent_milli)
        };
        verify_out_of_turn_backoff(zeroed, &h)
            .expect("geth zeroes delay, so any backOffSteps[idx] may be 0");
    }

    #[test]
    fn empty_withdrawals_required_when_present() {
        let mut h = load("header_116664000.json");
        h.withdrawals_root = Some(format!("0x{}", hex::encode([0x11u8; 32])));
        assert!(matches!(
            verify_unsealed_fields(&h).unwrap_err(),
            SealError::InvalidWithdrawalsRoot
        ));
    }

    #[test]
    fn parlia_nonce_must_be_empty() {
        let mut h = load("header_116664000.json");
        verify_unsealed_fields(&h).unwrap();
        h.nonce = "0x0000000000000001".into();
        assert!(matches!(
            verify_unsealed_fields(&h).unwrap_err(),
            SealError::InvalidNonce
        ));
    }

    #[test]
    fn future_unix_time_rejected() {
        let h = load("header_116664000.json");
        let now = decode_u64(&h.timestamp).unwrap();
        verify_timestamp_not_future(&h, now).unwrap();
        verify_timestamp_not_future(&h, now.saturating_sub(MAX_FUTURE_SKEW_SECS)).unwrap();
        let mut future = h.clone();
        future.timestamp = format!("0x{:x}", now + MAX_FUTURE_SKEW_SECS + 1);
        assert!(matches!(
            verify_timestamp_not_future(&future, now).unwrap_err(),
            SealError::FutureBlock { .. }
        ));
        let mut wall = h;
        wall.timestamp = format!("0x{:x}", unix_now() + 3600);
        assert!(matches!(
            verify_unsealed_fields(&wall).unwrap_err(),
            SealError::FutureBlock { .. }
        ));
    }

    #[test]
    fn epoch_extra_must_parse_validators() {
        let epoch = load("header_116664000.json");
        verify_extra_layout(&epoch).unwrap();
        let non_epoch = load("header_116664001.json");
        verify_extra_layout(&non_epoch).unwrap();
        let mut stripped = epoch.clone();
        stripped.extra_data = format!("0x{}", hex::encode([0u8; EXTRA_VANITY + EXTRA_SEAL]));
        assert!(matches!(
            verify_unsealed_fields(&stripped).unwrap_err(),
            SealError::Extra(_) | SealError::MissingEpochExtra
        ));

        let mut extra = decode_hex(&epoch.extra_data).unwrap();
        let n = extra[EXTRA_VANITY] as usize;
        assert!(n >= 2);
        let rec = EXTRA_VANITY + 1;
        extra.copy_within(
            rec..rec + helios_bsc_config::VALIDATOR_BYTES,
            rec + helios_bsc_config::VALIDATOR_BYTES,
        );
        let mut dup = epoch.clone();
        dup.extra_data = format!("0x{}", hex::encode(&extra));
        assert!(matches!(
            verify_extra_layout(&dup).unwrap_err(),
            SealError::DuplicateValidator
        ));

        let mut extra_tl = decode_hex(&epoch.extra_data).unwrap();
        let vals_end = rec + n * helios_bsc_config::VALIDATOR_BYTES;
        extra_tl[vals_end] = 255;
        let mut tl = epoch;
        tl.extra_data = format!("0x{}", hex::encode(extra_tl));
        assert!(matches!(
            verify_extra_layout(&tl).unwrap_err(),
            SealError::InvalidTurnLength
        ));
    }
}
