//! Parlia `extraData` codec (Luban / Bohr layouts).
//!
//! See `docs/consensus-appendix.md` and `consensus/parlia/parlia.go`
//! `getValidatorBytesFromHeader` / `parseTurnLength`.

use crate::{
    ExtraDataVersion, EXTRA_SEAL, EXTRA_VANITY, NEXT_FORK_HASH_SIZE, VALIDATOR_BYTES,
    VALIDATOR_NUMBER_SIZE,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtraError {
    #[error("extraData shorter than vanity+seal ({EXTRA_VANITY}+{EXTRA_SEAL})")]
    TooShort,
    #[error("epoch extraData missing validator count / records")]
    InvalidEpochValidators,
    #[error("epoch extraData missing turnLength byte")]
    MissingTurnLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealingValidator {
    pub address: [u8; 20],
    pub vote_key: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExtra {
    pub vanity: [u8; 32],
    /// Last 4 vanity bytes (`nextForkHash`).
    pub next_fork_hash: [u8; 4],
    pub validators: Vec<SealingValidator>,
    pub turn_length: Option<u8>,
    /// Raw RLP vote attestation (may be empty).
    pub attestation: Vec<u8>,
    pub seal: [u8; 65],
}

/// Parse extraData. `is_epoch` must be `number % epochLength == 0`.
pub fn parse_extra(
    extra: &[u8],
    version: ExtraDataVersion,
    is_epoch: bool,
) -> Result<ParsedExtra, ExtraError> {
    if extra.len() < EXTRA_VANITY + EXTRA_SEAL {
        return Err(ExtraError::TooShort);
    }

    let mut vanity = [0u8; 32];
    vanity.copy_from_slice(&extra[..EXTRA_VANITY]);
    let mut next_fork_hash = [0u8; 4];
    next_fork_hash.copy_from_slice(&vanity[EXTRA_VANITY - NEXT_FORK_HASH_SIZE..]);

    let mut seal = [0u8; 65];
    seal.copy_from_slice(&extra[extra.len() - EXTRA_SEAL..]);

    let mid = &extra[EXTRA_VANITY..extra.len() - EXTRA_SEAL];

    if !is_epoch || matches!(version, ExtraDataVersion::PreLuban) {
        if matches!(version, ExtraDataVersion::PreLuban) && is_epoch {
            return parse_pre_luban_epoch(vanity, next_fork_hash, mid, seal);
        }
        return Ok(ParsedExtra {
            vanity,
            next_fork_hash,
            validators: Vec::new(),
            turn_length: None,
            attestation: mid.to_vec(),
            seal,
        });
    }

    if mid.is_empty() {
        return Err(ExtraError::InvalidEpochValidators);
    }
    let n = mid[0] as usize;
    let start = VALIDATOR_NUMBER_SIZE;
    let vals_end = start + n * VALIDATOR_BYTES;
    let mut need = vals_end;
    if matches!(version, ExtraDataVersion::Bohr) {
        need += 1;
    }
    if n == 0 || mid.len() < need {
        return Err(ExtraError::InvalidEpochValidators);
    }

    let mut validators = Vec::with_capacity(n);
    for i in 0..n {
        let off = start + i * VALIDATOR_BYTES;
        let mut address = [0u8; 20];
        let mut vote_key = [0u8; 48];
        address.copy_from_slice(&mid[off..off + 20]);
        vote_key.copy_from_slice(&mid[off + 20..off + VALIDATOR_BYTES]);
        validators.push(SealingValidator { address, vote_key });
    }

    let (turn_length, att_off) = if matches!(version, ExtraDataVersion::Bohr) {
        (Some(mid[vals_end]), vals_end + 1)
    } else {
        (None, vals_end)
    };

    Ok(ParsedExtra {
        vanity,
        next_fork_hash,
        validators,
        turn_length,
        attestation: mid[att_off..].to_vec(),
        seal,
    })
}

fn parse_pre_luban_epoch(
    vanity: [u8; 32],
    next_fork_hash: [u8; 4],
    mid: &[u8],
    seal: [u8; 65],
) -> Result<ParsedExtra, ExtraError> {
    if !mid.len().is_multiple_of(20) {
        return Err(ExtraError::InvalidEpochValidators);
    }
    let n = mid.len() / 20;
    let mut validators = Vec::with_capacity(n);
    for i in 0..n {
        let mut address = [0u8; 20];
        address.copy_from_slice(&mid[i * 20..(i + 1) * 20]);
        validators.push(SealingValidator {
            address,
            vote_key: [0u8; 48],
        });
    }
    Ok(ParsedExtra {
        vanity,
        next_fork_hash,
        validators,
        turn_length: None,
        attestation: Vec::new(),
        seal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAXWELL_EPOCH_LENGTH;
    use helios_bsc_types::{decode_hex, decode_u64, RpcBlockHeader};
    use std::path::PathBuf;

    fn fixture(name: &str) -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet")
            .join(name);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&raw).expect("header json")
    }

    #[test]
    fn epoch_116664000_has_21_validators_turn8() {
        let h = fixture("header_116664000.json");
        let number = decode_u64(&h.number).unwrap();
        assert_eq!(number % MAXWELL_EPOCH_LENGTH, 0);
        let extra = decode_hex(&h.extra_data).unwrap();
        let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, true).unwrap();
        assert_eq!(parsed.validators.len(), 21);
        assert_eq!(parsed.turn_length, Some(8));
        assert_eq!(parsed.seal.len(), 65);
        assert!(!parsed.attestation.is_empty());
    }

    #[test]
    fn non_epoch_has_no_validators() {
        let h = fixture("header_116664001.json");
        let extra = decode_hex(&h.extra_data).unwrap();
        let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, false).unwrap();
        assert!(parsed.validators.is_empty());
        assert_eq!(parsed.turn_length, None);
        assert!(!parsed.attestation.is_empty());
    }
}
