//! Sealing-set snapshot + epoch activation (`minerHistoryCheckLen`).

use crate::seal::{verify_seal_coinbase, SealError};
use crate::vote::{decode_vote_attestation, verify_attestation_signature, VoteData, VoteError};
use helios_bsc_config::{
    miner_history_check_len, params_at, parse_extra, ExtraDataVersion, ExtraError,
    SealingValidator, DIFF_IN_TURN, DIFF_NO_TURN, MAXWELL_EPOCH_LENGTH,
};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, format_address, Checkpoint, RpcBlockHeader,
    TypesError,
};
use std::collections::HashMap;
use thiserror::Error;

/// Geth `Recents[epochKey] = {}` sentinel; skipped in `countRecents`.
const RECENT_EPOCH_SENTINEL: [u8; 20] = [0u8; 20];

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error(transparent)]
    Extra(#[from] ExtraError),
    #[error(transparent)]
    Types(#[from] TypesError),
    #[error("header {got} does not follow parent {want}")]
    NumberMismatch { want: u64, got: u64 },
    #[error("parent hash mismatch")]
    ParentHashMismatch,
    #[error("signer {0} not in active sealing set")]
    Unauthorized(String),
    #[error("epoch extraData missing at boundary {0}")]
    MissingEpochExtra(u64),
    #[error("Parlia difficulty {got} is not 1 or 2")]
    BadDifficulty { got: u64 },
    #[error("difficulty {got} does not match in-turn (want {want})")]
    DifficultyMismatch { got: u64, want: u64 },
    #[error("signer {0} signed too recently (seenTimes >= turnLength)")]
    RecentlySigned(String),
    #[error(transparent)]
    Vote(#[from] VoteError),
    #[error("attestation targets block {got} but the parent is {want}")]
    AttestationTarget { want: u64, got: u64 },
    #[error("attestation target hash does not match the parent hash")]
    AttestationTargetHash,
    #[error("attestation source {got} is not the justified block {want}")]
    AttestationSource { want: u64, got: u64 },
    #[error("attestation source hash does not match the justified block")]
    AttestationSourceHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEpoch {
    pub epoch_block: u64,
    pub activate_at: u64,
    pub validators: Vec<[u8; 20]>,
    /// BLS vote keys, positionally aligned with `validators`. Empty when the epoch
    /// layout carries none (pre-Luban), which leaves fast finality unavailable.
    pub vote_keys: Vec<[u8; 48]>,
    pub turn_length: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub number: u64,
    pub hash: [u8; 32],
    pub epoch_length: u64,
    pub turn_length: u64,
    pub validators: Vec<[u8; 20]>,
    pub pending: Option<PendingEpoch>,
    /// When false, only `{1,2}` range is checked (padded test sets cannot match live in-turn).
    pub enforce_inturn: bool,
    /// Block number → sealer. Bohr `SignRecently`: count in `minerHistoryCheckLen` window.
    pub recents: HashMap<u64, [u8; 20]>,
    /// Address + BLS vote key for the active set, in the same sorted order as
    /// `validators`. Empty means the vote keys are simply not known yet — fast finality
    /// is then unavailable, but nothing else changes.
    vote_set: Vec<SealingValidator>,
    /// The set as it stood before the most recent epoch activation.
    ///
    /// geth checks an attestation's bitset against the snapshot at `TargetNumber - 1`,
    /// two blocks below the header being applied. That differs from the current set in
    /// exactly one block per epoch — the activation block — so keeping one generation of
    /// history is enough, and getting it wrong would fail a signature once every 1000
    /// blocks: rare enough to pass a short test run and break in production.
    prev_vote_set: Vec<SealingValidator>,
    /// Block at which `vote_set` last replaced `prev_vote_set`.
    set_changed_at: u64,
    /// Newest attestation accepted so far: its target is the justified block and its
    /// source is the finalized one (`GetJustifiedNumberAndHash` / `GetFinalizedHeader`).
    pub attestation: Option<VoteData>,
}

impl Snapshot {
    pub fn from_checkpoint(cp: &Checkpoint) -> Result<Self, SnapshotError> {
        let mut validators = Vec::with_capacity(cp.sealing_set.len());
        for a in &cp.sealing_set {
            validators.push(decode_hex_fixed::<20>(a)?);
        }

        // The checkpoint lists addresses and keys in operator order; sorting the two
        // independently would pair each address with the wrong key. Sort the pairs.
        let vote_set = match &cp.vote_keys {
            Some(keys) if keys.len() == validators.len() => {
                let mut pairs = Vec::with_capacity(keys.len());
                for (addr, key) in validators.iter().zip(keys) {
                    pairs.push(SealingValidator {
                        address: *addr,
                        vote_key: decode_hex_fixed::<48>(key)?,
                    });
                }
                pairs.sort_by_key(|v| v.address);
                pairs
            }
            // A mismatched length is rejected by `Checkpoint::validate_basic`; treating
            // it as "no keys" here keeps this constructor total for callers that skip it.
            _ => Vec::new(),
        };
        validators.sort();

        let fork = params_at(cp.number, cp.timestamp);
        Ok(Self {
            number: cp.number,
            hash: decode_hex_fixed::<32>(&cp.hash)?,
            epoch_length: fork.epoch_length,
            turn_length: fork.turn_length,
            validators,
            pending: None,
            enforce_inturn: true,
            recents: HashMap::new(),
            vote_set,
            prev_vote_set: Vec::new(),
            // The checkpoint set is the set at the checkpoint, so nothing is "recent".
            set_changed_at: 0,
            attestation: None,
        })
    }

    /// Vote keys in `validators` order, hex-encoded — `None` when they are not known.
    pub fn vote_keys_hex(&self) -> Option<Vec<String>> {
        if self.vote_set.is_empty() {
            return None;
        }
        Some(
            self.vote_set
                .iter()
                .map(|v| format!("0x{}", hex::encode(v.vote_key)))
                .collect(),
        )
    }

    /// True once the snapshot can actually check a BLS attestation.
    pub fn fast_finality_available(&self) -> bool {
        !self.vote_set.is_empty()
    }

    /// Justified block (`GetJustifiedNumberAndHash`): the newest attestation's target.
    pub fn justified(&self) -> Option<(u64, [u8; 32])> {
        self.attestation.map(|a| (a.target_number, a.target_hash))
    }

    /// Finalized block (`GetFinalizedHeader`): the newest attestation's **source**.
    /// Finality therefore trails justification by one justified block.
    pub fn finalized(&self) -> Option<(u64, [u8; 32])> {
        self.attestation.map(|a| (a.source_number, a.source_hash))
    }

    /// Validator set an attestation in header `number` must be checked against.
    ///
    /// geth uses the snapshot at `TargetNumber - 1` = `number - 2`, so the previous
    /// generation applies while an activation is still that recent.
    fn attestation_set(&self, number: u64) -> &[SealingValidator] {
        if self.set_changed_at > number.saturating_sub(2) {
            &self.prev_vote_set
        } else {
            &self.vote_set
        }
    }

    /// Chain-state half of `verifyVoteAttestation`, then the signature half.
    ///
    /// `Ok(None)` means "nothing to adopt": either the header carries no attestation —
    /// normal, and never a reason to reject a header — or the vote keys are not known
    /// yet. `Err` means the header carries an attestation that is actually wrong, which
    /// is fatal: accepting it would let an upstream feed a forged finality signal.
    fn check_attestation(
        &self,
        raw: &[u8],
        number: u64,
        parent_hash: [u8; 32],
    ) -> Result<Option<VoteData>, SnapshotError> {
        let Some(att) = decode_vote_attestation(raw)? else {
            return Ok(None);
        };
        let set = self.attestation_set(number);
        if set.is_empty() {
            return Ok(None);
        }

        // The target must be the direct parent.
        let want_target = number.saturating_sub(1);
        if att.data.target_number != want_target {
            return Err(SnapshotError::AttestationTarget {
                want: want_target,
                got: att.data.target_number,
            });
        }
        if att.data.target_hash != parent_hash {
            return Err(SnapshotError::AttestationTargetHash);
        }

        // The source must be the block this client already considers justified. On the
        // first attestation after a bootstrap there is nothing to compare against — the
        // signature itself is then the evidence, since ≥⅔ of the set signed that source.
        if let Some(justified) = self.attestation {
            if att.data.source_number != justified.target_number {
                return Err(SnapshotError::AttestationSource {
                    want: justified.target_number,
                    got: att.data.source_number,
                });
            }
            if att.data.source_hash != justified.target_hash {
                return Err(SnapshotError::AttestationSourceHash);
            }
        }

        verify_attestation_signature(&att, set)?;
        Ok(Some(att.data))
    }

    pub fn n_seal(&self) -> u32 {
        self.validators.len() as u32
    }

    pub fn delay(&self) -> u64 {
        miner_history_check_len(self.n_seal(), self.turn_length)
    }

    pub fn contains(&self, addr: &[u8; 20]) -> bool {
        self.validators.binary_search(addr).is_ok()
    }

    /// In-turn sealer for the **next** header (`snap.Number` is the parent).
    ///
    /// `offset = (snap.Number + 1) / turnLength % N_seal` (v1.7.8 appendix).
    pub fn inturn_validator(&self) -> Option<[u8; 20]> {
        let n = self.validators.len() as u64;
        if n == 0 || self.turn_length == 0 {
            return None;
        }
        let offset = (self.number.saturating_add(1) / self.turn_length) % n;
        self.validators.get(offset as usize).copied()
    }

    pub fn expected_difficulty(&self, signer: &[u8; 20]) -> u64 {
        match self.inturn_validator() {
            Some(v) if &v == signer => DIFF_IN_TURN,
            _ => DIFF_NO_TURN,
        }
    }

    /// v1.7.8 `Snapshot.SignRecently` (Bohr+): `seenTimes >= turnLength` in the
    /// `minerHistoryCheckLen` window. Recents from *before* the checkpoint are unknown
    /// (walk starts empty). Maxwell BEP-524 prune-to-FF is not applied (no BLS).
    pub fn sign_recently(&self, signer: &[u8; 20]) -> bool {
        let check_len = self.delay();
        let left_bound = self.number.saturating_sub(check_len);
        let mut seen: u8 = 0;
        for (&block, recent) in &self.recents {
            if block <= left_bound || *recent == RECENT_EPOCH_SENTINEL {
                continue;
            }
            if recent == signer {
                seen = seen.saturating_add(1);
                if u64::from(seen) >= self.turn_length {
                    return true;
                }
            }
        }
        false
    }

    pub fn sealing_set_hex(&self) -> Vec<String> {
        self.validators.iter().map(format_address).collect()
    }

    /// Apply a fully verified header (signer already recovered).
    pub fn apply_verified(
        &mut self,
        header: &RpcBlockHeader,
        signer: [u8; 20],
    ) -> Result<(), SnapshotError> {
        let number = decode_u64(&header.number)?;
        let parent = decode_hex_fixed::<32>(&header.parent_hash)?;
        let hash = decode_hex_fixed::<32>(&header.hash)?;

        if number != self.number + 1 {
            return Err(SnapshotError::NumberMismatch {
                want: self.number + 1,
                got: number,
            });
        }
        if parent != self.hash {
            return Err(SnapshotError::ParentHashMismatch);
        }
        if !self.contains(&signer) {
            return Err(SnapshotError::Unauthorized(format_address(&signer)));
        }

        let difficulty = decode_u64(&header.difficulty)?;
        if difficulty != DIFF_NO_TURN && difficulty != DIFF_IN_TURN {
            return Err(SnapshotError::BadDifficulty { got: difficulty });
        }
        if self.enforce_inturn {
            let want = self.expected_difficulty(&signer);
            if difficulty != want {
                return Err(SnapshotError::DifficultyMismatch {
                    got: difficulty,
                    want,
                });
            }
        }

        let limit = self.delay().saturating_add(1);
        if number >= limit {
            self.recents.remove(&(number - limit));
        }
        if self.sign_recently(&signer) {
            return Err(SnapshotError::RecentlySigned(format_address(&signer)));
        }

        let extra = decode_hex(&header.extra_data)?;
        let is_epoch = number % self.epoch_length == 0;
        let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, is_epoch)?;

        // Before any mutation: the attestation is checked against the set as it stands
        // for this header, and a bad one rejects the header outright.
        let adopted = self.check_attestation(&parsed.attestation, number, parent)?;

        if is_epoch {
            if parsed.validators.is_empty() {
                return Err(SnapshotError::MissingEpochExtra(number));
            }
            // Sort the (address, key) pairs together — sorting the two lists separately
            // would pair each validator with someone else's BLS key.
            let mut vals = parsed.validators.clone();
            vals.sort_by_key(|v| v.address);
            let turn = parsed
                .turn_length
                .map(u64::from)
                .unwrap_or(self.turn_length);
            let delay = miner_history_check_len(self.n_seal(), self.turn_length);
            self.pending = Some(PendingEpoch {
                epoch_block: number,
                activate_at: number + delay,
                validators: vals.iter().map(|v| v.address).collect(),
                vote_keys: vals.iter().map(|v| v.vote_key).collect(),
                turn_length: turn,
            });
        }

        self.recents.insert(number, signer);

        if let Some(pending) = self.pending.clone() {
            if number == pending.activate_at {
                self.prev_vote_set = std::mem::take(&mut self.vote_set);
                self.vote_set = if pending.vote_keys.len() == pending.validators.len() {
                    pending
                        .validators
                        .iter()
                        .zip(&pending.vote_keys)
                        .map(|(address, vote_key)| SealingValidator {
                            address: *address,
                            vote_key: *vote_key,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                self.set_changed_at = number;
                self.validators = pending.validators;
                self.turn_length = pending.turn_length;
                self.pending = None;
                // Bohr BEP-404: clear miner history when the set switches.
                self.recents.clear();
                if let Some(epoch) = number.checked_div(self.epoch_length) {
                    let epoch_key = u64::MAX - epoch;
                    self.recents.insert(epoch_key, RECENT_EPOCH_SENTINEL);
                }
            }
        }

        if let Some(data) = adopted {
            self.attestation = Some(data);
        }

        self.number = number;
        self.hash = hash;
        Ok(())
    }

    pub fn apply_header(&mut self, header: &RpcBlockHeader) -> Result<[u8; 20], SnapshotError> {
        let signer = verify_seal_coinbase(header)?;
        self.apply_verified(header, signer)?;
        Ok(signer)
    }
}

/// Mainnet-era helper used by tests and probe: epoch length after Maxwell.
pub fn current_epoch_length() -> u64 {
    MAXWELL_EPOCH_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_bsc_types::Checkpoint;

    fn addr(i: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = i;
        a
    }

    /// keccak256(RLP empty string `0x80`) — empty tx/receipt trie.
    const EMPTY_TRIE_ROOT: [u8; 32] = [
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ];

    fn dummy_header(number: u64, parent: [u8; 32], hash: [u8; 32]) -> RpcBlockHeader {
        RpcBlockHeader {
            hash: format!("0x{}", hex::encode(hash)),
            parent_hash: format!("0x{}", hex::encode(parent)),
            sha3_uncles: format!("0x{}", hex::encode([0u8; 32])),
            miner: format!("0x{}", hex::encode(addr(1))),
            state_root: format!("0x{}", hex::encode([3u8; 32])),
            transactions_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
            receipts_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
            logs_bloom: format!("0x{}", hex::encode([0u8; 256])),
            difficulty: "0x2".into(),
            number: format!("0x{number:x}"),
            gas_limit: "0x1".into(),
            gas_used: "0x0".into(),
            timestamp: "0x1".into(),
            extra_data: format!("0x{}", hex::encode([0u8; 32 + 65])),
            mix_hash: format!("0x{}", hex::encode([0u8; 32])),
            nonce: format!("0x{}", hex::encode([0u8; 8])),
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    fn cp() -> Checkpoint {
        Checkpoint {
            chain_id: 56,
            number: 1000,
            hash: format!("0x{}", hex::encode([1u8; 32])),
            parent_hash: format!("0x{}", hex::encode([0u8; 32])),
            state_root: format!("0x{}", hex::encode([2u8; 32])),
            timestamp: 1_768_357_801,
            fork_id: "fermi".into(),
            sealing_set: (1..=21)
                .map(|i| format!("0x{}", hex::encode(addr(i))))
                .collect(),
            vote_keys: None,
            attestation: None,
        }
    }

    #[test]
    fn epoch_set_activates_after_miner_history_delay() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        assert_eq!(snap.delay(), 87);
        assert_eq!(snap.turn_length, 8);

        let mut parent = snap.hash;
        // Walk 1..86: no activation. Inject pending as if we saw epoch 1000 (checkpoint is 1000).
        snap.pending = Some(PendingEpoch {
            epoch_block: 1000,
            activate_at: 1000 + 87,
            validators: (30..=50).map(addr).collect(),
            // Synthetic set: no BLS keys, so fast finality stays off for this walk.
            vote_keys: Vec::new(),
            turn_length: 8,
        });

        for n in 1001..=1086 {
            let hash = {
                let mut h = [0u8; 32];
                h[0] = (n % 251) as u8;
                h[1] = 7;
                h
            };
            let signer = snap.inturn_validator().expect("inturn");
            let mut h = dummy_header(n, parent, hash);
            h.difficulty = format!("0x{:x}", snap.expected_difficulty(&signer));
            snap.apply_verified(&h, signer).unwrap();
            assert!(
                snap.pending.is_some(),
                "pending should survive until 1087, died at {n}"
            );
            assert_eq!(snap.validators[0], addr(1));
            parent = hash;
        }

        let hash = {
            let mut h = [0u8; 32];
            h[0] = 87;
            h
        };
        let signer = snap.inturn_validator().expect("inturn");
        let mut last = dummy_header(1087, parent, hash);
        last.difficulty = format!("0x{:x}", snap.expected_difficulty(&signer));
        snap.apply_verified(&last, signer).unwrap();
        assert!(snap.pending.is_none());
        assert_eq!(snap.validators.len(), 21);
        assert_eq!(snap.validators[0], addr(30));
        assert_eq!(snap.recents.len(), 1);
        assert!(snap.recents.values().all(|a| *a == RECENT_EPOCH_SENTINEL));
    }

    #[test]
    fn unauthorized_signer_rejected() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        let err = snap
            .apply_verified(&dummy_header(1001, snap.hash, [9u8; 32]), addr(99))
            .unwrap_err();
        assert!(matches!(err, SnapshotError::Unauthorized(_)));
    }

    #[test]
    fn inturn_offset_matches_appendix() {
        let snap = Snapshot::from_checkpoint(&cp()).unwrap();
        assert_eq!(snap.number, 1000);
        assert_eq!(snap.turn_length, 8);
        // offset = (1000+1)/8 % 21 = 125 % 21 = 20 → validators[20] = addr(21)
        assert_eq!(snap.inturn_validator(), Some(addr(21)));
        assert_eq!(snap.expected_difficulty(&addr(21)), 2);
        assert_eq!(snap.expected_difficulty(&addr(1)), 1);
    }

    #[test]
    fn in_turn_wrong_difficulty_rejected() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        let mut h = dummy_header(1001, snap.hash, [9u8; 32]);
        h.difficulty = "0x1".into(); // in-turn signer addr(21) needs 2
        let err = snap.apply_verified(&h, addr(21)).unwrap_err();
        assert!(
            matches!(err, SnapshotError::DifficultyMismatch { got: 1, want: 2 }),
            "{err}"
        );
        h.difficulty = "0x2".into();
        snap.apply_verified(&h, addr(21)).unwrap();
    }

    #[test]
    fn out_of_turn_wrong_difficulty_rejected() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        let mut h = dummy_header(1001, snap.hash, [9u8; 32]);
        h.difficulty = "0x2".into(); // addr(1) is not in-turn
        let err = snap.apply_verified(&h, addr(1)).unwrap_err();
        assert!(
            matches!(err, SnapshotError::DifficultyMismatch { got: 2, want: 1 }),
            "{err}"
        );
        h.difficulty = "0x1".into();
        snap.apply_verified(&h, addr(1)).unwrap();
    }

    #[test]
    fn sign_recently_after_turn_length() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        snap.enforce_inturn = false;
        let mut parent = snap.hash;
        for i in 1..=8 {
            let n = 1000 + i;
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            let mut h = dummy_header(n, parent, hash);
            h.difficulty = "0x1".into();
            snap.apply_verified(&h, addr(1)).unwrap();
            parent = hash;
        }
        let mut h = dummy_header(1009, parent, [9u8; 32]);
        h.difficulty = "0x1".into();
        let err = snap.apply_verified(&h, addr(1)).unwrap_err();
        assert!(matches!(err, SnapshotError::RecentlySigned(_)), "{err}");
        // A different sealer is still allowed.
        snap.apply_verified(&h, addr(2)).unwrap();
    }

    #[test]
    fn seven_seals_under_turn_length_ok() {
        let mut snap = Snapshot::from_checkpoint(&cp()).unwrap();
        snap.enforce_inturn = false;
        let mut parent = snap.hash;
        for i in 1..=7 {
            let n = 1000 + i;
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            let mut h = dummy_header(n, parent, hash);
            h.difficulty = "0x1".into();
            snap.apply_verified(&h, addr(1)).unwrap();
            parent = hash;
        }
        assert!(!snap.sign_recently(&addr(1)));
    }
}
