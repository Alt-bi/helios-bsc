//! Parlia light-client consensus (seals, epochs, confirmation-depth).

pub mod finality;
mod rlp_util;
pub mod seal;
pub mod snapshot;
pub mod vote;

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
pub use vote::{
    decode_vote_attestation, min_votes_for_finality, verify_attestation_signature,
    voted_validators, VoteAttestation, VoteData, VoteError, BLS_PUBLIC_KEY_LEN, BLS_SIGNATURE_LEN,
    MAX_ATTESTATION_EXTRA_LEN,
};

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
    Ok(
        validators_from_activated_epoch(epoch_header, checkpoint_number)?
            .iter()
            .map(|v| format_address(&v.address))
            .collect(),
    )
}

/// BLS vote keys from the same activated epoch, in the **same order** as
/// [`sealing_set_from_activated_epoch`].
///
/// Both read one `extraData`, so the two lists stay positionally aligned; deriving them
/// from separate parses would risk pairing an address with another validator's key.
pub fn vote_keys_from_activated_epoch(
    epoch_header: &RpcBlockHeader,
    checkpoint_number: u64,
) -> Result<Vec<String>, ConsensusError> {
    Ok(
        validators_from_activated_epoch(epoch_header, checkpoint_number)?
            .iter()
            .map(|v| format!("0x{}", hex::encode(v.vote_key)))
            .collect(),
    )
}

fn validators_from_activated_epoch(
    epoch_header: &RpcBlockHeader,
    checkpoint_number: u64,
) -> Result<Vec<helios_bsc_config::SealingValidator>, ConsensusError> {
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
    Ok(parsed.validators)
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
    let cp =
        Checkpoint::from_rpc_header(&header, snapshot.sealing_set_hex(), fork_id, attestation)?;
    // Carry the BLS keys across a restart when the snapshot has them: without this a
    // restart would silently drop to confirmation-depth until the next epoch activates.
    Ok(match snapshot.vote_keys_hex() {
        Some(keys) => cp.with_vote_keys(keys),
        None => cp,
    })
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
            vote_keys: None,
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

    /// End-to-end against **real** mainnet consensus data: epoch 116663000 is the
    /// epoch that *governs* the fixture blocks (activates at +87 = 116663087), so its
    /// extraData supplies the genuine 21-validator sealing set. Unlike [`padded_set`],
    /// a real set can satisfy in-turn difficulty, so `enforce_inturn` stays **on** here.
    #[test]
    fn live_epoch_set_verifies_fixtures_with_inturn_enforced() {
        let epoch = load_header("header_116663000.json");
        let headers = fixture_headers();
        let first = decode_u64(&headers[0].number).unwrap();

        let epoch_number = decode_u64(&epoch.number).unwrap();
        assert_eq!(epoch_number, 116_663_000);
        assert!(
            first >= epoch_number + epoch_delay_mainnet(),
            "fixtures must sit at or past the activation height"
        );

        let set = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        assert_eq!(set.len(), 21, "live mainnet sealing set");

        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", Some("live epoch".into()))
            .unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();
        assert!(
            eng.snapshot.enforce_inturn,
            "real set must not need the in-turn escape hatch"
        );
        assert_eq!(eng.snapshot.turn_length, 8);

        eng.apply_headers(&headers[1..]).unwrap();
        assert_eq!(eng.tip_number(), 116_664_002);
        assert_eq!(eng.n_seal(), 21);

        // No vote keys in this checkpoint, so fast finality must stay unavailable
        // rather than fall back to something weaker.
        assert!(!eng.snapshot.fast_finality_available());
        assert_eq!(eng.snapshot.finalized(), None);
    }

    /// Vote keys turn the same walk into real BLS finality: every fixture header's
    /// attestation is checked against the live 21-key set, and the finalized head ends
    /// up 2 blocks behind the tip — the lag `scripts/verify_attestations.py` measures
    /// on mainnet, against 106–112 for confirmation depth.
    #[test]
    fn live_epoch_vote_keys_produce_bls_finality() {
        let epoch = load_header("header_116663000.json");
        let headers = fixture_headers();
        let first = decode_u64(&headers[0].number).unwrap();

        let set = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        let keys = vote_keys_from_activated_epoch(&epoch, first).unwrap();
        assert_eq!(keys.len(), set.len(), "one BLS key per validator");

        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", Some("live epoch".into()))
            .unwrap()
            .with_vote_keys(keys);
        cp.validate_basic().expect("21 unique 48-byte vote keys");

        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();
        assert!(eng.snapshot.fast_finality_available());

        eng.apply_headers(&headers[1..]).unwrap();
        assert_eq!(eng.tip_number(), 116_664_002);

        let (justified, justified_hash) = eng.snapshot.justified().expect("justified block");
        let (finalized, finalized_hash) = eng.snapshot.finalized().expect("finalized block");
        assert_eq!(justified, 116_664_001, "target is the direct parent");
        assert_eq!(finalized, 116_664_000, "source trails the target by one");

        // Both must name blocks this client verified itself, not just hashes an
        // upstream asserted.
        let in_chain = |n: u64, h: [u8; 32]| eng.chain.iter().any(|b| b.number == n && b.hash == h);
        assert!(
            in_chain(justified, justified_hash),
            "justified block is local"
        );
        assert!(
            in_chain(finalized, finalized_hash),
            "finalized block is local"
        );

        assert_eq!(
            eng.tip_number() - finalized,
            2,
            "BLS finality lag on live mainnet data"
        );

        // A restart must not silently drop to confirmation depth: the checkpoint written
        // back at the current tip has to carry the keys, still paired with the right
        // addresses. Re-derive the pairing from the epoch header to check the alignment
        // rather than trusting the order the snapshot happened to emit.
        let restart = eng.last_verified_checkpoint(&headers[4]).unwrap();
        restart.validate_basic().unwrap();
        let carried = restart
            .vote_keys
            .as_ref()
            .expect("vote keys survive restart");
        assert_eq!(carried.len(), 21);

        let epoch_addrs = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        let epoch_keys = vote_keys_from_activated_epoch(&epoch, first).unwrap();
        for (addr, key) in restart.sealing_set.iter().zip(carried) {
            let i = epoch_addrs
                .iter()
                .position(|a| a.eq_ignore_ascii_case(addr))
                .expect("checkpoint address is one of the epoch validators");
            assert!(
                epoch_keys[i].eq_ignore_ascii_case(key),
                "restart checkpoint paired {addr} with the wrong BLS key"
            );
        }

        // And the restarted client really does start in fast-finality mode.
        let resumed = Snapshot::from_checkpoint(&restart).unwrap();
        assert!(resumed.fast_finality_available());
    }

    /// A forged attestation must reject the header rather than quietly downgrade the
    /// client to confirmation depth — otherwise an upstream could feed fake finality.
    #[test]
    fn tampered_attestation_rejects_the_header() {
        let epoch = load_header("header_116663000.json");
        let headers = fixture_headers();
        let first = decode_u64(&headers[0].number).unwrap();
        let set = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        let keys = vote_keys_from_activated_epoch(&epoch, first).unwrap();

        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None)
            .unwrap()
            .with_vote_keys(keys);
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();

        // Flip one bit inside the attestation region of the next header's extraData —
        // far enough from the 32-byte vanity and the trailing 65-byte seal that only the
        // BLS check can catch it.
        let mut forged = headers[1].clone();
        let mut extra = decode_hex(&forged.extra_data).unwrap();
        let flip = extra.len() - 65 - 40;
        extra[flip] ^= 0x01;
        forged.extra_data = format!("0x{}", hex::encode(&extra));

        let err = eng.apply_header(&forged).unwrap_err();
        assert!(
            matches!(err, ConsensusError::Snapshot(_)),
            "forged attestation must be fatal, got {err}"
        );
        assert_eq!(eng.snapshot.finalized(), None, "no finality was adopted");
    }

    /// `difficulty` is inside the sealed header, so an upstream cannot restate it: the
    /// seal breaks before the in-turn rule is consulted. Rejection must still happen.
    #[test]
    fn live_epoch_set_rejects_restated_difficulty_via_seal() {
        let epoch = load_header("header_116663000.json");
        let headers = fixture_headers();
        let first = decode_u64(&headers[0].number).unwrap();
        let set = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None).unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();

        let mut lying = headers[1].clone();
        assert_eq!(lying.difficulty, "0x2", "fixture block is in-turn");
        lying.difficulty = "0x1".into();
        let err = eng.apply_header(&lying).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::Snapshot(SnapshotError::Seal(SealError::CoinbaseMismatch { .. }))
            ),
            "restated difficulty must break the seal, got: {err}"
        );
    }

    /// In-turn expectation on the **real** set: `offset = (parent+1)/turnLength % N`
    /// picks the sealer the chain actually used, and every other member is out-of-turn.
    #[test]
    fn live_epoch_set_inturn_matches_real_sealers() {
        let epoch = load_header("header_116663000.json");
        let headers = fixture_headers();
        let first = decode_u64(&headers[0].number).unwrap();
        let set = sealing_set_from_activated_epoch(&epoch, first).unwrap();
        let cp = Checkpoint::from_rpc_header(&headers[0], set, "fermi", None).unwrap();
        let mut eng = LightEngine::from_checkpoint_and_header(cp, &headers[0]).unwrap();

        for h in &headers[1..] {
            let want = eng.snapshot.inturn_validator().expect("in-turn sealer");
            let miner = decode_hex_fixed::<20>(&h.miner).unwrap();
            assert_eq!(
                format_address(&want),
                format_address(&miner),
                "block {} in-turn sealer",
                h.number
            );
            assert_eq!(eng.snapshot.expected_difficulty(&miner), 2);
            // Any other set member is out-of-turn at this height.
            let other = eng
                .snapshot
                .validators
                .iter()
                .find(|v| **v != miner)
                .copied()
                .expect("set has >1 validator");
            assert_eq!(eng.snapshot.expected_difficulty(&other), 1);
            eng.apply_header(h).unwrap();
        }
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
