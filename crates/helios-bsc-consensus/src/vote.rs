//! BSC Fast Finality vote attestations: RLP decoding + aggregated BLS verification.
//!
//! Pinned to `bnb-chain/bsc` v1.7.8 `core/types/vote.go` (`VoteData`, `VoteAttestation`,
//! `ValidatorsBitSet`) and `consensus/parlia/parlia.go` `verifyVoteAttestation`.
//!
//! Scope: this module answers "is this attestation a well-formed, correctly signed
//! super-majority vote by *these* validators?". It deliberately does **not** decide
//! justification/finalization — parent linkage and the justified-source lookup live with
//! the caller that owns chain state.

use crate::rlp_util::{encode_bytes, encode_list, encode_uint};
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;
use helios_bsc_config::SealingValidator;
use helios_bsc_types::keccak256;
use thiserror::Error;

/// `types.BLSPublicKeyLength` — compressed G1 point (min_pk).
pub const BLS_PUBLIC_KEY_LEN: usize = 48;
/// `types.BLSSignatureLength` — compressed G2 point (min_pk).
pub const BLS_SIGNATURE_LEN: usize = 96;
/// `types.MaxAttestationExtraLength`.
pub const MAX_ATTESTATION_EXTRA_LEN: usize = 256;

/// ETH2 proof-of-possession ciphersuite. BSC votes are produced by the prysm BLS
/// wrapper, so the domain tag must match byte-for-byte or every signature "fails".
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A vote attestation is `[u64, str, [..], str]`: exactly two levels of list nesting.
/// Anything deeper is not a vote attestation, so the decoder refuses to walk it.
const MAX_RLP_DEPTH: usize = 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VoteError {
    #[error("malformed vote attestation RLP: {0}")]
    Rlp(&'static str),
    #[error("too large extra length: {len} > {MAX_ATTESTATION_EXTRA_LEN}")]
    ExtraTooLong { len: usize },
    #[error("vote number larger than validators number: {voted} > {validators}")]
    VoteNumberLargerThanValidators { voted: usize, validators: usize },
    #[error("vote address set has bit {index} set but only {validators} validators exist")]
    BitOutOfRange { index: usize, validators: usize },
    #[error("vote address set is empty")]
    NoVotes,
    #[error("not enough validators voted: {got} < {need}")]
    NotEnoughVotes { got: usize, need: usize },
    #[error("validator {index} has an invalid BLS vote key")]
    InvalidVoteKey { index: usize },
    #[error("aggregated signature is not a valid BLS signature")]
    InvalidSignature,
    #[error("BLS public key aggregation failed")]
    AggregateFailed,
    #[error("vote attestation signature verify fail")]
    SignatureVerifyFailed,
}

impl From<&'static str> for VoteError {
    fn from(msg: &'static str) -> Self {
        VoteError::Rlp(msg)
    }
}

/// `types.VoteData` — the message every voter signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteData {
    pub source_number: u64,
    pub source_hash: [u8; 32],
    pub target_number: u64,
    pub target_hash: [u8; 32],
}

impl VoteData {
    /// `VoteData.Hash()` = `rlpHash(d)` — this, not the header hash, is the signed message.
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&encode_list(&[
            encode_uint(u128::from(self.source_number)),
            encode_bytes(&self.source_hash),
            encode_uint(u128::from(self.target_number)),
            encode_bytes(&self.target_hash),
        ]))
    }
}

/// `types.VoteAttestation` as carried in Parlia `extraData` after the validator records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteAttestation {
    /// `ValidatorsBitSet`: bit `i` names the `i`-th validator in snapshot order.
    pub vote_address_set: u64,
    pub agg_signature: [u8; BLS_SIGNATURE_LEN],
    pub data: VoteData,
    pub extra: Vec<u8>,
}

/// `CeilDiv(len(validators)*2, 3)` — the super-majority a vote attestation must carry.
/// 21 mainnet validators ⇒ 14.
pub fn min_votes_for_finality(n: usize) -> usize {
    n.saturating_mul(2).div_ceil(3)
}

/// Decode the raw attestation bytes taken from `ParsedExtra::attestation`.
///
/// Returns `Ok(None)` for an empty slice: most headers simply carry no attestation, and
/// that is a normal chain state rather than a malformed header.
pub fn decode_vote_attestation(raw: &[u8]) -> Result<Option<VoteAttestation>, VoteError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let top = decode_top(raw)?;
    let fields = list_of(&top)?;
    if fields.len() != 4 {
        return Err(VoteError::Rlp("vote attestation must be a 4-item list"));
    }

    let vote_address_set = uint_of(str_of(&fields[0])?)?;
    let agg_signature = fixed_str::<BLS_SIGNATURE_LEN>(
        str_of(&fields[1])?,
        "aggregated signature is not 96 bytes",
    )?;

    let data_fields = list_of(&fields[2])?;
    if data_fields.len() != 4 {
        return Err(VoteError::Rlp("vote data must be a 4-item list"));
    }
    let data = VoteData {
        source_number: uint_of(str_of(&data_fields[0])?)?,
        source_hash: fixed_str::<32>(str_of(&data_fields[1])?, "source hash is not 32 bytes")?,
        target_number: uint_of(str_of(&data_fields[2])?)?,
        target_hash: fixed_str::<32>(str_of(&data_fields[3])?, "target hash is not 32 bytes")?,
    };

    let extra = str_of(&fields[3])?.to_vec();

    Ok(Some(VoteAttestation {
        vote_address_set,
        agg_signature,
        data,
        extra,
    }))
}

/// Addresses named by the bit set, in snapshot order.
///
/// `validators` MUST be in Parlia snapshot order (sorted by address, as
/// `Snapshot::validators` and the epoch `extraData` records are): bit `i` names
/// `validators[i]`, so a mis-ordered slice silently verifies against the wrong keys.
pub fn voted_validators(
    att: &VoteAttestation,
    validators: &[SealingValidator],
) -> Result<Vec<[u8; 20]>, VoteError> {
    Ok(voted_indices(att.vote_address_set, validators.len())?
        .into_iter()
        .map(|i| validators[i].address)
        .collect())
}

/// `verifyVoteAttestation`'s signature half: extra-length bound, bit-set sanity,
/// super-majority count, then `FastAggregateVerify` over `VoteData.Hash()`.
///
/// `validators` MUST be in Parlia snapshot order — see [`voted_validators`].
///
/// The caller still owes the chain-state half of `verifyVoteAttestation`: that the
/// target is the direct parent and that the source is a justified block.
pub fn verify_attestation_signature(
    att: &VoteAttestation,
    validators: &[SealingValidator],
) -> Result<(), VoteError> {
    if att.extra.len() > MAX_ATTESTATION_EXTRA_LEN {
        return Err(VoteError::ExtraTooLong {
            len: att.extra.len(),
        });
    }

    let indices = voted_indices(att.vote_address_set, validators.len())?;
    if indices.is_empty() {
        // prysm's FastAggregateVerify returns false on an empty key list; blst's
        // aggregate would error instead, so reject up front with a real reason.
        return Err(VoteError::NoVotes);
    }

    // `bls.PublicKeyFromBytes` runs KeyValidate (subgroup membership + non-infinity);
    // `key_validate` is blst's equivalent. A bad key is a rejected attestation, not a
    // skipped voter.
    let mut keys = Vec::with_capacity(indices.len());
    for &i in &indices {
        let key = PublicKey::key_validate(&validators[i].vote_key)
            .map_err(|_| VoteError::InvalidVoteKey { index: i })?;
        keys.push(key);
    }

    let need = min_votes_for_finality(validators.len());
    if keys.len() < need {
        return Err(VoteError::NotEnoughVotes {
            got: keys.len(),
            need,
        });
    }

    let refs: Vec<&PublicKey> = keys.iter().collect();
    // `false`: every key was already KeyValidate'd above, so re-checking each subgroup
    // during aggregation would only repeat the work.
    let agg =
        AggregatePublicKey::aggregate(&refs, false).map_err(|_| VoteError::AggregateFailed)?;
    let pk = agg.to_public_key();

    let sig = Signature::sig_validate(&att.agg_signature, true)
        .map_err(|_| VoteError::InvalidSignature)?;
    let msg = att.data.hash();
    match sig.verify(false, &msg, DST, &[], &pk, false) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(VoteError::SignatureVerifyFailed),
    }
}

/// Bit indices of the voters, validated against the validator count.
fn voted_indices(set: u64, n: usize) -> Result<Vec<usize>, VoteError> {
    // geth: `validatorsBitSet.Count() > uint(len(validators))`.
    let voted = set.count_ones() as usize;
    if voted > n {
        return Err(VoteError::VoteNumberLargerThanValidators {
            voted,
            validators: n,
        });
    }

    // Stricter than geth, deliberately: the popcount check above only catches a
    // high bit when it pushes the total over the validator count, so a bit above the
    // range slips through whenever some in-range voter is missing. A bit that names no
    // validator cannot be anything but malformed, and a light client gains nothing by
    // guessing what the proposer meant — fail closed.
    let high = if n >= 64 { 0 } else { set >> n };
    if high != 0 {
        return Err(VoteError::BitOutOfRange {
            index: n + high.trailing_zeros() as usize,
            validators: n,
        });
    }

    Ok((0..n.min(64)).filter(|&i| (set >> i) & 1 == 1).collect())
}

// ---------------------------------------------------------------------------
// Strict RLP decoding.
//
// The crate ships an encoder only, and pulling in the execution crate's decoder would
// invert the dependency graph. Attestations are a fixed, tiny shape, so a strict
// local reader is both cheaper and easier to keep canonical: every non-canonical
// encoding below is a distinct byte string for the same value, i.e. a way to make two
// honest clients disagree about what a header says.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Rlp<'a> {
    Str(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

/// Decode exactly one item and require it to consume the whole buffer.
fn decode_top(buf: &[u8]) -> Result<Rlp<'_>, VoteError> {
    let (item, rest) = decode_item(buf, 0)?;
    if !rest.is_empty() {
        return Err(VoteError::Rlp("trailing bytes after the top-level item"));
    }
    Ok(item)
}

fn decode_item(buf: &[u8], depth: usize) -> Result<(Rlp<'_>, &[u8]), VoteError> {
    let (&prefix, tail) = buf
        .split_first()
        .ok_or(VoteError::Rlp("unexpected end of input"))?;
    match prefix {
        0x00..=0x7f => Ok((Rlp::Str(&buf[..1]), tail)),
        0x80..=0xb7 => {
            let len = usize::from(prefix - 0x80);
            let (payload, rest) = take(tail, len)?;
            if len == 1 && payload[0] < 0x80 {
                return Err(VoteError::Rlp("single byte < 0x80 wrapped as a string"));
            }
            Ok((Rlp::Str(payload), rest))
        }
        0xb8..=0xbf => {
            let (len, rest) = long_len(tail, usize::from(prefix - 0xb7))?;
            let (payload, rest) = take(rest, len)?;
            Ok((Rlp::Str(payload), rest))
        }
        0xc0..=0xf7 => {
            let len = usize::from(prefix - 0xc0);
            let (payload, rest) = take(tail, len)?;
            Ok((Rlp::List(decode_list(payload, depth)?), rest))
        }
        _ => {
            let (len, rest) = long_len(tail, usize::from(prefix - 0xf7))?;
            let (payload, rest) = take(rest, len)?;
            Ok((Rlp::List(decode_list(payload, depth)?), rest))
        }
    }
}

fn decode_list(mut payload: &[u8], depth: usize) -> Result<Vec<Rlp<'_>>, VoteError> {
    if depth >= MAX_RLP_DEPTH {
        return Err(VoteError::Rlp("RLP nested deeper than a vote attestation"));
    }
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = decode_item(payload, depth + 1)?;
        out.push(item);
        payload = rest;
    }
    Ok(out)
}

/// Long-form length header: big-endian, no leading zero, and never used for a payload
/// that the short form could have expressed.
fn long_len(buf: &[u8], len_of_len: usize) -> Result<(usize, &[u8]), VoteError> {
    let (raw, rest) = take(buf, len_of_len)?;
    if raw.first() == Some(&0) {
        return Err(VoteError::Rlp("length prefix has a leading zero byte"));
    }
    let mut len = 0usize;
    for &b in raw {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(b)))
            .ok_or(VoteError::Rlp("length prefix overflows usize"))?;
    }
    if len <= 55 {
        return Err(VoteError::Rlp("long form used where the short form fits"));
    }
    Ok((len, rest))
}

fn take(buf: &[u8], n: usize) -> Result<(&[u8], &[u8]), VoteError> {
    if buf.len() < n {
        return Err(VoteError::Rlp("payload overruns the buffer"));
    }
    Ok(buf.split_at(n))
}

fn str_of<'a>(item: &Rlp<'a>) -> Result<&'a [u8], VoteError> {
    match item {
        Rlp::Str(s) => Ok(s),
        Rlp::List(_) => Err(VoteError::Rlp("expected a string, found a list")),
    }
}

fn list_of<'a, 'b>(item: &'b Rlp<'a>) -> Result<&'b [Rlp<'a>], VoteError> {
    match item {
        Rlp::List(l) => Ok(l),
        Rlp::Str(_) => Err(VoteError::Rlp("expected a list, found a string")),
    }
}

fn uint_of(raw: &[u8]) -> Result<u64, VoteError> {
    if raw.len() > 8 {
        return Err(VoteError::Rlp("integer longer than 8 bytes"));
    }
    if raw.first() == Some(&0) {
        return Err(VoteError::Rlp("integer has a leading zero byte"));
    }
    let mut v = 0u64;
    for &b in raw {
        v = (v << 8) | u64::from(b);
    }
    Ok(v)
}

fn fixed_str<const N: usize>(raw: &[u8], what: &'static str) -> Result<[u8; N], VoteError> {
    raw.try_into().map_err(|_| VoteError::Rlp(what))
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_bsc_config::{parse_extra, ExtraDataVersion};
    use helios_bsc_types::{decode_hex, decode_hex_fixed, decode_u64, RpcBlockHeader};
    use std::path::PathBuf;

    /// Consecutive mainnet headers, each carrying a real vote attestation.
    const FIXTURES: [&str; 5] = [
        "header_116663998.json",
        "header_116663999.json",
        "header_116664000.json",
        "header_116664001.json",
        "header_116664002.json",
    ];

    fn fixture(name: &str) -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet")
            .join(name);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&raw).expect("header json")
    }

    /// The 21 validators from epoch 116663000, which activates at +87 = 116663087 and so
    /// governs every fixture block. Sorted by address: bit `i` names `validators[i]`.
    fn governing_validators() -> Vec<SealingValidator> {
        let h = fixture("header_116663000.json");
        let extra = decode_hex(&h.extra_data).unwrap();
        let mut validators = parse_extra(&extra, ExtraDataVersion::Bohr, true)
            .unwrap()
            .validators;
        validators.sort_by_key(|v| v.address);
        validators
    }

    fn raw_attestation(name: &str) -> Vec<u8> {
        let h = fixture(name);
        let number = decode_u64(&h.number).unwrap();
        let extra = decode_hex(&h.extra_data).unwrap();
        parse_extra(&extra, ExtraDataVersion::Bohr, number % 1000 == 0)
            .unwrap()
            .attestation
    }

    fn attestation(name: &str) -> VoteAttestation {
        decode_vote_attestation(&raw_attestation(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .unwrap_or_else(|| panic!("{name}: no attestation"))
    }

    #[test]
    fn real_mainnet_attestation_verifies() {
        let validators = governing_validators();
        assert_eq!(validators.len(), 21, "live mainnet sealing set");
        for name in FIXTURES {
            let att = attestation(name);
            assert!(
                att.vote_address_set.count_ones() as usize >= min_votes_for_finality(21),
                "{name}: only {} voters",
                att.vote_address_set.count_ones()
            );
            verify_attestation_signature(&att, &validators)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn voted_validators_are_a_subset_of_the_set() {
        let validators = governing_validators();
        let att = attestation("header_116664001.json");
        let voted = voted_validators(&att, &validators).unwrap();
        assert_eq!(voted.len(), att.vote_address_set.count_ones() as usize);
        for a in &voted {
            assert!(validators.iter().any(|v| &v.address == a));
        }
        // Sorted order in, sorted order out.
        assert!(voted.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn attestation_targets_parent_and_chains_sources() {
        let mut prev: Option<VoteData> = None;
        for name in FIXTURES {
            let h = fixture(name);
            let number = decode_u64(&h.number).unwrap();
            let att = attestation(name);
            assert_eq!(att.data.target_number, number - 1, "{name}");
            assert_eq!(
                att.data.target_hash,
                decode_hex_fixed::<32>(&h.parent_hash).unwrap(),
                "{name}"
            );
            if let Some(p) = prev {
                assert_eq!(att.data.source_number, p.target_number, "{name}");
                assert_eq!(att.data.source_hash, p.target_hash, "{name}");
            }
            prev = Some(att.data);
        }
    }

    #[test]
    fn flipped_signature_bit_is_rejected() {
        let validators = governing_validators();
        let mut att = attestation("header_116664001.json");
        att.agg_signature[64] ^= 0x01;
        let err = verify_attestation_signature(&att, &validators).unwrap_err();
        assert!(
            matches!(
                err,
                VoteError::SignatureVerifyFailed | VoteError::InvalidSignature
            ),
            "{err}"
        );
    }

    #[test]
    fn flipped_target_hash_bit_is_rejected() {
        let validators = governing_validators();
        let mut att = attestation("header_116664001.json");
        att.data.target_hash[0] ^= 0x01;
        assert_eq!(
            verify_attestation_signature(&att, &validators).unwrap_err(),
            VoteError::SignatureVerifyFailed
        );
    }

    #[test]
    fn thirteen_of_twentyone_is_not_enough() {
        let validators = governing_validators();
        let mut att = attestation("header_116664001.json");
        while att.vote_address_set.count_ones() > 13 {
            att.vote_address_set &= att.vote_address_set - 1;
        }
        assert_eq!(
            verify_attestation_signature(&att, &validators).unwrap_err(),
            VoteError::NotEnoughVotes { got: 13, need: 14 }
        );
        assert_eq!(min_votes_for_finality(validators.len()), 14);
    }

    #[test]
    fn bit_naming_no_validator_is_rejected() {
        let validators = governing_validators();
        let mut att = attestation("header_116664001.json");
        // Clear a real voter so the popcount stays within range: geth's count check
        // would let this through, ours must not.
        att.vote_address_set &= att.vote_address_set - 1;
        att.vote_address_set |= 1 << 21;
        assert_eq!(
            verify_attestation_signature(&att, &validators).unwrap_err(),
            VoteError::BitOutOfRange {
                index: 21,
                validators: 21
            }
        );
        assert_eq!(
            voted_validators(&att, &validators).unwrap_err(),
            VoteError::BitOutOfRange {
                index: 21,
                validators: 21
            }
        );
    }

    #[test]
    fn popcount_above_validator_count_is_rejected() {
        let validators = governing_validators()[..3].to_vec();
        let att = attestation("header_116664001.json");
        // The real set has far more than 3 voters — geth's own count check catches it.
        assert_eq!(
            verify_attestation_signature(&att, &validators).unwrap_err(),
            VoteError::VoteNumberLargerThanValidators {
                voted: att.vote_address_set.count_ones() as usize,
                validators: 3
            }
        );
        assert_eq!(voted_indices(0b0111, 3).unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn oversized_extra_is_rejected() {
        let validators = governing_validators();
        let mut att = attestation("header_116664001.json");
        att.extra = vec![0u8; MAX_ATTESTATION_EXTRA_LEN + 1];
        assert_eq!(
            verify_attestation_signature(&att, &validators).unwrap_err(),
            VoteError::ExtraTooLong { len: 257 }
        );
        // Exactly at the bound is fine, and `extra` is not covered by `VoteData.Hash()`,
        // so stuffing it does not disturb the signature — only the length bound guards it.
        att.extra = vec![0u8; MAX_ATTESTATION_EXTRA_LEN];
        assert_eq!(verify_attestation_signature(&att, &validators), Ok(()));
    }

    #[test]
    fn empty_attestation_is_absent_not_invalid() {
        assert_eq!(decode_vote_attestation(&[]), Ok(None));
    }

    #[test]
    fn min_votes_is_ceil_two_thirds() {
        assert_eq!(min_votes_for_finality(21), 14);
        assert_eq!(min_votes_for_finality(3), 2);
        assert_eq!(min_votes_for_finality(1), 1);
        assert_eq!(min_votes_for_finality(0), 0);
    }

    // --- RLP decoder ---

    fn sample_fields() -> Vec<Vec<u8>> {
        vec![
            encode_uint(3),
            encode_bytes(&[0x11u8; BLS_SIGNATURE_LEN]),
            encode_list(&[
                encode_uint(1),
                encode_bytes(&[0x22u8; 32]),
                encode_uint(2),
                encode_bytes(&[0x33u8; 32]),
            ]),
            encode_bytes(b"x"),
        ]
    }

    #[test]
    fn synthetic_attestation_round_trips() {
        let att = decode_vote_attestation(&encode_list(&sample_fields()))
            .unwrap()
            .unwrap();
        assert_eq!(att.vote_address_set, 3);
        assert_eq!(att.agg_signature, [0x11u8; BLS_SIGNATURE_LEN]);
        assert_eq!(att.data.source_number, 1);
        assert_eq!(att.data.target_number, 2);
        assert_eq!(att.data.target_hash, [0x33u8; 32]);
        assert_eq!(att.extra, b"x");
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut raw = raw_attestation("header_116664001.json");
        assert!(decode_vote_attestation(&raw).is_ok());
        raw.push(0x00);
        assert_eq!(
            decode_vote_attestation(&raw).unwrap_err(),
            VoteError::Rlp("trailing bytes after the top-level item")
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let raw = raw_attestation("header_116664001.json");
        let short = &raw[..raw.len() - 1];
        assert_eq!(
            decode_vote_attestation(short).unwrap_err(),
            VoteError::Rlp("payload overruns the buffer")
        );
    }

    #[test]
    fn non_canonical_integer_is_rejected() {
        let mut fields = sample_fields();
        fields[0] = vec![0x82, 0x00, 0x03]; // 3 with a leading zero byte
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("integer has a leading zero byte")
        );
    }

    #[test]
    fn single_byte_wrapped_as_string_is_rejected() {
        let mut fields = sample_fields();
        fields[0] = vec![0x81, 0x05];
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("single byte < 0x80 wrapped as a string")
        );
    }

    #[test]
    fn non_canonical_length_prefix_is_rejected() {
        let mut fields = sample_fields();
        // 96-byte signature written as 0xb9 0x00 0x60 instead of 0xb8 0x60.
        let mut sig = vec![0xb9, 0x00, 0x60];
        sig.extend_from_slice(&[0x11u8; BLS_SIGNATURE_LEN]);
        fields[1] = sig;
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("length prefix has a leading zero byte")
        );

        let mut fields = sample_fields();
        // A 1-byte payload emitted in long form (0xb8 0x01) where 0x81 would do.
        fields[3] = vec![0xb8, 0x01, 0x99];
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("long form used where the short form fits")
        );
    }

    #[test]
    fn wrong_item_count_is_rejected() {
        let fields = sample_fields();
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields[..3])).unwrap_err(),
            VoteError::Rlp("vote attestation must be a 4-item list")
        );
        let mut five = fields.clone();
        five.push(encode_uint(9));
        assert_eq!(
            decode_vote_attestation(&encode_list(&five)).unwrap_err(),
            VoteError::Rlp("vote attestation must be a 4-item list")
        );
    }

    #[test]
    fn wrong_inner_list_arity_is_rejected() {
        let mut fields = sample_fields();
        fields[2] = encode_list(&[encode_uint(1), encode_bytes(&[0x22u8; 32]), encode_uint(2)]);
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("vote data must be a 4-item list")
        );
    }

    #[test]
    fn type_confusion_is_rejected() {
        let mut fields = sample_fields();
        fields[2] = encode_bytes(&[0u8; 8]); // vote data as a string
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("expected a list, found a string")
        );

        let mut fields = sample_fields();
        fields[0] = encode_list(&[encode_uint(1)]); // bit set as a list
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("expected a string, found a list")
        );

        let raw = encode_bytes(&[0u8; 8]); // top level is not a list
        assert_eq!(
            decode_vote_attestation(&raw).unwrap_err(),
            VoteError::Rlp("expected a list, found a string")
        );
    }

    #[test]
    fn excessive_nesting_is_rejected() {
        let mut fields = sample_fields();
        fields[2] = encode_list(&[encode_list(&[encode_list(&[encode_uint(1)])])]);
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("RLP nested deeper than a vote attestation")
        );
    }

    #[test]
    fn wrong_fixed_widths_are_rejected() {
        let mut fields = sample_fields();
        fields[1] = encode_bytes(&[0x11u8; BLS_SIGNATURE_LEN - 1]);
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("aggregated signature is not 96 bytes")
        );

        let mut fields = sample_fields();
        fields[2] = encode_list(&[
            encode_uint(1),
            encode_bytes(&[0x22u8; 31]),
            encode_uint(2),
            encode_bytes(&[0x33u8; 32]),
        ]);
        assert_eq!(
            decode_vote_attestation(&encode_list(&fields)).unwrap_err(),
            VoteError::Rlp("source hash is not 32 bytes")
        );
    }
}
