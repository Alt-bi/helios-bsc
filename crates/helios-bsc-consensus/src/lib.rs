//! Parlia light-client consensus (seals, epochs, confirmation-depth).

pub mod finality;
mod rlp_util;
pub mod seal;
pub mod snapshot;

use helios_bsc_config::{
    expected_safe_lag_blocks, mainnet_min_distinct_sealers, miner_history_check_len, params_at,
    parse_extra, ExtraDataVersion, ExtraError, PROVIDER_PROOF_LOOKBACK,
};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, format_address, Checkpoint, RpcBlockHeader, SafeHead,
    TypesError,
};
use thiserror::Error;

pub use finality::{newest_safe, proof_lag, within_proof_window, VerifiedBlock};
pub use seal::{
    header_hash, milli_timestamp, recover_signer, unix_now, verify_cascading_vs_parent,
    verify_extra_layout, verify_header_hash, verify_seal_coinbase, verify_timestamp_not_future,
    verify_unsealed_fields, SealError, MAX_FUTURE_SKEW_SECS,
};
pub use snapshot::{Snapshot, SnapshotError};

pub const CHECKPOINT_WARN_AGE_SECS: u64 = 6 * 3600;
pub const DEFAULT_MAX_CHECKPOINT_AGE_SECS: u64 = 24 * 3600;

/// Operator SLO label for a checkpoint age (`ok` / `warn` / `fail`).
pub fn checkpoint_slo_label(age_secs: u64) -> &'static str {
    if age_secs > DEFAULT_MAX_CHECKPOINT_AGE_SECS {
        "fail"
    } else if age_secs > CHECKPOINT_WARN_AGE_SECS {
        "warn"
    } else {
        "ok"
    }
}

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),
    #[error("checkpoint {field} mismatch vs header")]
    CheckpointMismatch { field: &'static str },
    #[error("checkpoint age {age}s exceeds max {max}s — fail-closed (refresh checkpoint)")]
    CheckpointTooOld { age: u64, max: u64 },
    #[error(
        "checkpoint is {lag} blocks behind tip (limit {limit}) — fail-closed (fresher checkpoint)"
    )]
    CheckpointTooFar { lag: u64, limit: u64 },
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Types(#[from] TypesError),
    #[error("no Safe head yet (need {need} distinct sealers, have {have})")]
    NotSafe { need: u32, have: u32 },
    #[error(
        "Safe lag {lag} exceeds provider proof window {limit} — fail-closed (swap RPC key or wait)"
    )]
    ProofWindowExceeded { lag: u64, limit: u64 },
    #[error("header {number} is not an epoch boundary (epochLength={epoch_length})")]
    NotEpoch { number: u64, epoch_length: u64 },
    #[error("epoch extraData at {0} has no validators")]
    EmptyEpochValidators(u64),
    #[error(
        "epoch extraData at {epoch} is the *next* sealing set; activates at {activate_at} (checkpoint {checkpoint} is too early)"
    )]
    EpochSetNotActivated {
        epoch: u64,
        activate_at: u64,
        checkpoint: u64,
    },
    #[error(transparent)]
    Extra(#[from] ExtraError),
}

pub fn checkpoint_age_secs(timestamp: u64, now: u64) -> u64 {
    now.saturating_sub(timestamp)
}

/// `max_age_secs == 0` disables the check. Returns age on success.
pub fn assert_checkpoint_age(
    timestamp: u64,
    now: u64,
    max_age_secs: u64,
) -> Result<u64, ConsensusError> {
    let age = checkpoint_age_secs(timestamp, now);
    if max_age_secs > 0 && age > max_age_secs {
        return Err(ConsensusError::CheckpointTooOld {
            age,
            max: max_age_secs,
        });
    }
    Ok(age)
}

/// Sealing set from an **activated** epoch header's extraData (the *next* set at that epoch).
///
/// Epoch extraData at `E` activates at `E + minerHistoryCheckLen`. Using it as the
/// set at `checkpoint_number` before that height is fail-closed — this is **not**
/// inferred from `miner` fields.
pub fn sealing_set_from_activated_epoch(
    epoch_header: &RpcBlockHeader,
    checkpoint_number: u64,
) -> Result<Vec<String>, ConsensusError> {
    let number = decode_u64(&epoch_header.number)?;
    let timestamp = decode_u64(&epoch_header.timestamp)?;
    let fork = params_at(number, timestamp);
    if number % fork.epoch_length != 0 {
        return Err(ConsensusError::NotEpoch {
            number,
            epoch_length: fork.epoch_length,
        });
    }
    let extra = decode_hex(&epoch_header.extra_data)?;
    let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, true)?;
    if parsed.validators.is_empty() {
        return Err(ConsensusError::EmptyEpochValidators(number));
    }
    let n = parsed.validators.len() as u32;
    let turn = parsed
        .turn_length
        .map(u64::from)
        .unwrap_or(fork.turn_length);
    let activate_at = number.saturating_add(miner_history_check_len(n, turn));
    if checkpoint_number < activate_at {
        return Err(ConsensusError::EpochSetNotActivated {
            epoch: number,
            activate_at,
            checkpoint: checkpoint_number,
        });
    }
    Ok(parsed
        .validators
        .iter()
        .map(|v| format_address(&v.address))
        .collect())
}

/// Build a checkpoint from the header that matches `snapshot` tip + current sealing set.
pub fn checkpoint_at_snapshot(
    header: &RpcBlockHeader,
    snapshot: &Snapshot,
    fork_id: impl Into<String>,
    attestation: Option<String>,
) -> Result<Checkpoint, ConsensusError> {
    let number = decode_u64(&header.number)?;
    if number != snapshot.number {
        return Err(ConsensusError::CheckpointMismatch { field: "number" });
    }
    let got = crate::seal::header_hash(header)?;
    if got != snapshot.hash {
        return Err(ConsensusError::CheckpointMismatch { field: "hash" });
    }
    let mut header = header.clone();
    header.hash = format!("0x{}", hex::encode(got));
    Ok(Checkpoint::from_rpc_header(
        &header,
        snapshot.sealing_set_hex(),
        fork_id,
        attestation,
    )?)
}

fn hex_eq(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("0x").trim_start_matches("0X");
    let b = b.trim_start_matches("0x").trim_start_matches("0X");
    a.eq_ignore_ascii_case(b)
}

/// Number / hash / parentHash / stateRoot must match the checkpoint (oracle or primary).
pub fn header_matches_checkpoint(
    checkpoint: &Checkpoint,
    header: &RpcBlockHeader,
) -> Result<(), ConsensusError> {
    let number = decode_u64(&header.number)?;
    if number != checkpoint.number {
        return Err(ConsensusError::CheckpointMismatch { field: "number" });
    }
    let computed = crate::seal::header_hash(header)?;
    let want = decode_hex_fixed::<32>(&checkpoint.hash)?;
    if computed != want {
        return Err(ConsensusError::CheckpointMismatch { field: "hash" });
    }
    if !hex_eq(&header.parent_hash, &checkpoint.parent_hash) {
        return Err(ConsensusError::CheckpointMismatch {
            field: "parentHash",
        });
    }
    if !hex_eq(&header.state_root, &checkpoint.state_root) {
        return Err(ConsensusError::CheckpointMismatch { field: "stateRoot" });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct LightEngine {
    pub checkpoint: Checkpoint,
    pub snapshot: Snapshot,
    pub chain: Vec<VerifiedBlock>,
    pub safe: Option<SafeHead>,
    pub proof_lookback: u64,
}

impl LightEngine {
    pub fn from_checkpoint(checkpoint: Checkpoint) -> Result<Self, ConsensusError> {
        checkpoint
            .validate_basic()
            .map_err(|e| ConsensusError::InvalidCheckpoint(e.to_string()))?;
        let snapshot = Snapshot::from_checkpoint(&checkpoint)?;
        let genesis = VerifiedBlock {
            number: checkpoint.number,
            hash: decode_hex_fixed::<32>(&checkpoint.hash)?,
            state_root: decode_hex_fixed::<32>(&checkpoint.state_root)?,
            miner: [0u8; 20],
            ..Default::default()
        };
        Ok(Self {
            checkpoint,
            snapshot,
            chain: vec![genesis],
            safe: None,
            proof_lookback: PROVIDER_PROOF_LOOKBACK,
        })
    }

    /// Checkpoint + matching header (seal recovered so genesis miner is real).
    pub fn from_checkpoint_and_header(
        checkpoint: Checkpoint,
        header: &RpcBlockHeader,
    ) -> Result<Self, ConsensusError> {
        checkpoint
            .validate_basic()
            .map_err(|e| ConsensusError::InvalidCheckpoint(e.to_string()))?;
        header_matches_checkpoint(&checkpoint, header)?;
        let miner = verify_seal_coinbase(header)?;
        let snapshot = Snapshot::from_checkpoint(&checkpoint)?;
        let genesis = VerifiedBlock {
            number: checkpoint.number,
            hash: decode_hex_fixed::<32>(&checkpoint.hash)?,
            state_root: decode_hex_fixed::<32>(&checkpoint.state_root)?,
            miner,
            milli_timestamp: milli_timestamp(header)?,
            gas_limit: decode_u64(&header.gas_limit)?,
            header: Some(header.clone()),
        };
        Ok(Self {
            checkpoint,
            snapshot,
            chain: vec![genesis],
            safe: None,
            proof_lookback: PROVIDER_PROOF_LOOKBACK,
        })
    }

    pub fn apply_headers(&mut self, headers: &[RpcBlockHeader]) -> Result<(), ConsensusError> {
        for h in headers {
            self.apply_header(h)?;
        }
        Ok(())
    }

    /// Checkpoint at the current snapshot tip (last verified header), for restart.
    pub fn last_verified_checkpoint(
        &self,
        header: &RpcBlockHeader,
    ) -> Result<Checkpoint, ConsensusError> {
        checkpoint_at_snapshot(
            header,
            &self.snapshot,
            self.checkpoint.fork_id.clone(),
            Some("helios-bsc last-verified".into()),
        )
    }

    pub fn n_seal(&self) -> u32 {
        self.snapshot.n_seal()
    }

    pub fn required_sealers(&self) -> u32 {
        mainnet_min_distinct_sealers()
    }

    pub fn expected_safe_lag_blocks(&self) -> u64 {
        expected_safe_lag_blocks()
    }

    pub fn tip_number(&self) -> u64 {
        self.snapshot.number
    }

    pub fn apply_header(&mut self, header: &RpcBlockHeader) -> Result<(), ConsensusError> {
        let signer = self.snapshot.apply_header(header)?;
        let number = decode_u64(&header.number)?;
        if let Some(prev) = self.chain.last() {
            verify_cascading_vs_parent(prev.milli_timestamp, prev.gas_limit, header)?;
        }
        self.chain.push(VerifiedBlock {
            number,
            hash: decode_hex_fixed::<32>(&header.hash)?,
            state_root: decode_hex_fixed::<32>(&header.state_root)?,
            miner: signer,
            milli_timestamp: milli_timestamp(header)?,
            gas_limit: decode_u64(&header.gas_limit)?,
            header: Some(header.clone()),
        });
        const KEEP: usize = 512;
        if self.chain.len() > KEEP {
            let drop = self.chain.len() - KEEP;
            self.chain.drain(0..drop);
        }
        self.safe = newest_safe(&self.chain, self.n_seal());
        Ok(())
    }

    /// Apply headers that are already parent-linked. Used by tests without real seals.
    pub fn apply_verified(
        &mut self,
        header: &RpcBlockHeader,
        signer: [u8; 20],
    ) -> Result<(), ConsensusError> {
        self.snapshot.apply_verified(header, signer)?;
        self.chain.push(VerifiedBlock {
            number: decode_u64(&header.number)?,
            hash: decode_hex_fixed::<32>(&header.hash)?,
            state_root: decode_hex_fixed::<32>(&header.state_root)?,
            miner: signer,
            milli_timestamp: milli_timestamp(header)?,
            gas_limit: decode_u64(&header.gas_limit)?,
            header: Some(header.clone()),
        });
        self.safe = newest_safe(&self.chain, self.n_seal());
        Ok(())
    }

    /// Safe head if it exists **and** sits inside the provider proof window.
    pub fn proof_target(&self) -> Result<SafeHead, ConsensusError> {
        let safe = self.safe.clone().ok_or(ConsensusError::NotSafe {
            need: self.required_sealers(),
            have: distinct_tail(&self.chain),
        })?;
        let lag = proof_lag(self.tip_number(), safe.number);
        if lag > self.proof_lookback {
            return Err(ConsensusError::ProofWindowExceeded {
                lag,
                limit: self.proof_lookback,
            });
        }
        Ok(safe)
    }
}

fn distinct_tail(chain: &[VerifiedBlock]) -> u32 {
    let mut s = Vec::new();
    for b in chain.iter().rev() {
        if !s.iter().any(|a| a == &b.miner) {
            s.push(b.miner);
        }
    }
    s.len() as u32
}

pub fn epoch_delay_mainnet() -> u64 {
    miner_history_check_len(21, 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_bsc_types::Checkpoint;

    fn sample_cp() -> Checkpoint {
        Checkpoint {
            chain_id: 56,
            number: 40_000_000,
            hash: "0x".to_string() + &"11".repeat(32),
            parent_hash: "0x".to_string() + &"22".repeat(32),
            state_root: "0x".to_string() + &"33".repeat(32),
            timestamp: 1_768_357_801,
            fork_id: "fermi".into(),
            sealing_set: (0..21).map(|i| format!("0x{:040x}", i + 1)).collect(),
            attestation: Some("test-only".into()),
        }
    }

    #[test]
    fn engine_from_checkpoint() {
        let eng = LightEngine::from_checkpoint(sample_cp()).unwrap();
        assert_eq!(eng.required_sealers(), 15);
        assert_eq!(eng.expected_safe_lag_blocks(), 15 * 8);
        assert_eq!(eng.proof_lookback, 112);
        assert_eq!(epoch_delay_mainnet(), 87);
    }

    #[test]
    fn stale_checkpoint_rejected() {
        let ts = 1_000_000;
        assert_eq!(checkpoint_age_secs(ts, ts + 100), 100);
        assert!(assert_checkpoint_age(ts, ts + 100, 24 * 3600).is_ok());
        let err =
            assert_checkpoint_age(ts, ts + 25 * 3600, DEFAULT_MAX_CHECKPOINT_AGE_SECS).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::CheckpointTooOld { max: 86400, .. }
        ));
        assert!(assert_checkpoint_age(ts, ts + 99_000, 0).is_ok());
        assert_eq!(checkpoint_slo_label(3600), "ok");
        assert_eq!(checkpoint_slo_label(CHECKPOINT_WARN_AGE_SECS + 1), "warn");
        assert_eq!(
            checkpoint_slo_label(DEFAULT_MAX_CHECKPOINT_AGE_SECS + 1),
            "fail"
        );
    }

    #[test]
    fn fixtures_seals_and_epoch_extra() {
        use helios_bsc_config::{parse_extra, ExtraDataVersion, MAXWELL_EPOCH_LENGTH};
        use helios_bsc_types::decode_hex;
        use std::path::PathBuf;

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mainnet");
        let epoch: RpcBlockHeader = serde_json::from_str(
            &std::fs::read_to_string(dir.join("header_116664000.json")).unwrap(),
        )
        .unwrap();
        verify_seal_coinbase(&epoch).unwrap();
        let extra = decode_hex(&epoch.extra_data).unwrap();
        let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, true).unwrap();
        assert_eq!(parsed.validators.len(), 21);
        assert_eq!(parsed.turn_length, Some(8));
        assert_eq!(decode_u64(&epoch.number).unwrap() % MAXWELL_EPOCH_LENGTH, 0);
    }

    #[test]
    fn epoch_extra_set_waits_for_activation_delay() {
        let epoch = load_header("header_116664000.json");
        let n = decode_u64(&epoch.number).unwrap();
        let err = sealing_set_from_activated_epoch(&epoch, n).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::EpochSetNotActivated {
                    epoch: 116_664_000,
                    activate_at: 116_664_087,
                    checkpoint: 116_664_000
                }
            ),
            "{err}"
        );
        let set = sealing_set_from_activated_epoch(&epoch, n + 87).unwrap();
        assert_eq!(set.len(), 21);
        let non_epoch = load_header("header_116664001.json");
        let err = sealing_set_from_activated_epoch(&non_epoch, n + 87).unwrap_err();
        assert!(matches!(err, ConsensusError::NotEpoch { .. }), "{err}");
    }

    fn load_header(name: &str) -> RpcBlockHeader {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn fixture_headers() -> Vec<RpcBlockHeader> {
        [
            "header_116663998.json",
            "header_116663999.json",
            "header_116664000.json",
            "header_116664001.json",
            "header_116664002.json",
        ]
        .into_iter()
        .map(load_header)
        .collect()
    }

    fn padded_set(miners: impl Iterator<Item = String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut set = Vec::new();
        for m in miners {
            if let Ok(addr) = decode_hex_fixed::<20>(&m) {
                if seen.insert(addr) {
                    set.push(format_address(&addr));
                }
            }
        }
        let mut i = 1u8;
        while set.len() < 21 {
            let mut addr = [0u8; 20];
            addr[18] = 0xee;
            addr[19] = i;
            if seen.insert(addr) {
                set.push(format_address(&addr));
            }
            i = i.wrapping_add(1);
            if i == 0 {
                break;
            }
        }
        set
    }

    #[test]
    fn fixture_engine_accepts_authorized_sealers() {
        let headers = fixture_headers();
        let set = padded_set(headers.iter().map(|h| h.miner.clone()));
        let cp =
            Checkpoint::from_rpc_header(&headers[0], set, "fermi", Some("fixture".into())).unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();
        eng.snapshot.enforce_inturn = false;
        eng.apply_headers(&headers[1..]).unwrap();
        assert_eq!(eng.tip_number(), 116_664_002);
        assert_ne!(eng.chain[0].miner, [0u8; 20]);
    }

    #[test]
    fn fixture_engine_rejects_unauthorized_sealer() {
        let headers = fixture_headers();
        let banned = headers[1].miner.clone();
        let set = padded_set(
            headers
                .iter()
                .map(|h| h.miner.clone())
                .filter(|m| !m.eq_ignore_ascii_case(&banned)),
        );
        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None).unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();
        eng.snapshot.enforce_inturn = false;
        let err = eng.apply_header(&headers[1]).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::Snapshot(SnapshotError::Unauthorized(_))
            ),
            "{err}"
        );
    }

    #[test]
    fn checkpoint_header_hash_mismatch() {
        let headers = fixture_headers();
        let set = padded_set(headers.iter().map(|h| h.miner.clone()));
        let mut cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None).unwrap();
        cp.hash = format!("0x{}", "11".repeat(32));
        let err = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::CheckpointMismatch { field: "hash" }
        ));
    }

    #[test]
    fn last_verified_checkpoint_roundtrip() {
        let headers = fixture_headers();
        let set = padded_set(headers.iter().map(|h| h.miner.clone()));
        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None).unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();
        eng.snapshot.enforce_inturn = false;
        eng.apply_headers(&headers[1..]).unwrap();
        let last = headers.last().unwrap();
        let stored = eng.last_verified_checkpoint(last).unwrap();
        assert_eq!(stored.number, 116_664_002);
        assert_eq!(stored.sealing_set.len(), 21);
        let eng2 = LightEngine::from_checkpoint_and_header(stored, last).unwrap();
        assert_eq!(eng2.tip_number(), 116_664_002);
    }
}
