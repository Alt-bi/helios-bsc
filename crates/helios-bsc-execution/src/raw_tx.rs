//! Local checks on `eth_sendRawTransaction` bytes before the untrusted upstream.
//!
//! Broadcast is still unverified (drop / MEV). These checks stop replay of
//! other-chain txs and bind the wallet's returned hash to keccak256(raw).

use crate::rlp::{decode, encode_bytes, encode_list, encode_uint, Rlp, RlpError};
use helios_bsc_types::{keccak256, BSC_MAINNET_CHAIN_ID};
use thiserror::Error;

/// Same cap as the JSON-RPC handler (512 KiB).
pub const MAX_RAW_TX: usize = 512 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RawTxError {
    #[error("raw tx empty")]
    Empty,
    #[error("raw tx too large")]
    TooLarge,
    #[error("raw tx is not RLP")]
    InvalidRlp,
    #[error("raw tx truncated")]
    Truncated,
    #[error("raw tx unsigned")]
    Unsigned,
    #[error("raw tx missing EIP-155 chainId (unprotected)")]
    Unprotected,
    #[error("raw tx unknown type 0x{0:02x}")]
    UnknownType(u8),
    #[error("raw tx chainId is not BSC mainnet 56")]
    WrongChain,
}

/// Decode, require BSC `chainId` 56, return `keccak256(raw)` (the tx hash).
pub fn validate_bsc_raw_tx(bytes: &[u8]) -> Result<[u8; 32], RawTxError> {
    if bytes.is_empty() {
        return Err(RawTxError::Empty);
    }
    if bytes.len() > MAX_RAW_TX {
        return Err(RawTxError::TooLarge);
    }
    let chain_id = parse_chain_id(bytes)?;
    if chain_id != BSC_MAINNET_CHAIN_ID {
        return Err(RawTxError::WrongChain);
    }
    Ok(keccak256(bytes))
}

/// The `to` address of a signed envelope, or `None` for a contract creation.
///
/// Reads one field out of the already-decoded envelope: no signature work, no hashing.
/// Callers must pass bytes that are already bound to a sealed `transactionsRoot` — this
/// function decodes, it does not authenticate.
///
/// Field position is fixed per envelope type, so a truncated or misshaped list is an
/// error rather than a guess at a neighbouring field:
///
/// | Type | Layout up to `to` | Index |
/// |------|-------------------|-------|
/// | legacy | nonce, gasPrice, gasLimit, **to** | 3 |
/// | `0x01` EIP-2930 | chainId, nonce, gasPrice, gasLimit, **to** | 4 |
/// | `0x02` EIP-1559 | chainId, nonce, maxPriorityFee, maxFee, gasLimit, **to** | 5 |
/// | `0x03` EIP-4844 | same prefix as 1559 | 5 |
/// | `0x04` EIP-7702 | same prefix as 1559 | 5 |
pub fn tx_to_address(bytes: &[u8]) -> Result<Option<[u8; 20]>, RawTxError> {
    if bytes.is_empty() {
        return Err(RawTxError::Empty);
    }
    if bytes.len() > MAX_RAW_TX {
        return Err(RawTxError::TooLarge);
    }
    let (items, idx) = match bytes[0] {
        0x01 => (decode_list(&bytes[1..])?, 4usize),
        0x02..=0x04 => (decode_list(&bytes[1..])?, 5usize),
        0x05..=0x7f => return Err(RawTxError::UnknownType(bytes[0])),
        _ => (decode_list(bytes)?, 3usize),
    };
    let item = items.get(idx).ok_or(RawTxError::Truncated)?;
    let b = item.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    match b.len() {
        // Empty string is the canonical encoding of "no recipient" (contract creation).
        0 => Ok(None),
        20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(b);
            Ok(Some(out))
        }
        _ => Err(RawTxError::InvalidRlp),
    }
}

/// Gas-price fields of a signed envelope, as the two shapes EIP-1559 left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxGasPrice {
    /// Legacy and EIP-2930: one `gasPrice`, paid in full.
    Fixed(u128),
    /// EIP-1559 and later: a cap and a tip, resolved against the block's base fee.
    Dynamic { max_priority: u128, max_fee: u128 },
}

impl TxGasPrice {
    /// `effectiveGasPrice` for a block whose base fee is `base_fee`.
    ///
    /// EIP-1559: `base + min(maxPriorityFeePerGas, maxFeePerGas - base)`. On a Parlia
    /// chain `base` is the constant zero, but it is read from the sealed header rather
    /// than assumed, so this stays correct if that ever stops being true.
    pub fn effective(self, base_fee: u128) -> u128 {
        match self {
            TxGasPrice::Fixed(p) => p,
            TxGasPrice::Dynamic {
                max_priority,
                max_fee,
            } => base_fee.saturating_add(max_priority.min(max_fee.saturating_sub(base_fee))),
        }
    }
}

/// Gas-price fields of a signed envelope.
///
/// Refuses values wider than 16 bytes rather than truncating: a gas price that large
/// cannot occur on this chain, and a silently wrapped one would be a plausible wrong
/// number — exactly what deriving the field is meant to eliminate.
pub fn tx_gas_price(bytes: &[u8]) -> Result<TxGasPrice, RawTxError> {
    if bytes.is_empty() {
        return Err(RawTxError::Empty);
    }
    if bytes.len() > MAX_RAW_TX {
        return Err(RawTxError::TooLarge);
    }
    match bytes[0] {
        // EIP-2930: chainId, nonce, gasPrice, ...
        0x01 => {
            let items = decode_list(&bytes[1..])?;
            Ok(TxGasPrice::Fixed(rlp_u128(
                items.get(2).ok_or(RawTxError::Truncated)?,
            )?))
        }
        // 1559 / 4844 / 7702: chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, ...
        0x02..=0x04 => {
            let items = decode_list(&bytes[1..])?;
            Ok(TxGasPrice::Dynamic {
                max_priority: rlp_u128(items.get(2).ok_or(RawTxError::Truncated)?)?,
                max_fee: rlp_u128(items.get(3).ok_or(RawTxError::Truncated)?)?,
            })
        }
        0x05..=0x7f => Err(RawTxError::UnknownType(bytes[0])),
        // Legacy: nonce, gasPrice, ...
        _ => {
            let items = decode_list(bytes)?;
            Ok(TxGasPrice::Fixed(rlp_u128(
                items.get(1).ok_or(RawTxError::Truncated)?,
            )?))
        }
    }
}

fn rlp_u128(item: &Rlp<'_>) -> Result<u128, RawTxError> {
    let b = item.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    if b.len() > 16 {
        return Err(RawTxError::InvalidRlp);
    }
    if b.len() > 1 && b[0] == 0 {
        return Err(RawTxError::InvalidRlp);
    }
    let mut n = 0u128;
    for x in b {
        n = (n << 8) | u128::from(*x);
    }
    Ok(n)
}

/// The `nonce` of a signed envelope. Index 0 on legacy, 1 on every typed envelope
/// (which all put `chainId` first).
pub fn tx_nonce(bytes: &[u8]) -> Result<u64, RawTxError> {
    if bytes.is_empty() {
        return Err(RawTxError::Empty);
    }
    if bytes.len() > MAX_RAW_TX {
        return Err(RawTxError::TooLarge);
    }
    let (items, idx) = match bytes[0] {
        0x01..=0x04 => (decode_list(&bytes[1..])?, 1usize),
        0x05..=0x7f => return Err(RawTxError::UnknownType(bytes[0])),
        _ => (decode_list(bytes)?, 0usize),
    };
    rlp_u64(items.get(idx).ok_or(RawTxError::Truncated)?)
}

/// Address a contract creation lands at: `keccak256(rlp([sender, nonce]))[12..]`.
///
/// Consensus rule, not a convention — the same one geth applies — so it can be computed
/// rather than taken from an upstream, given a sender and nonce that are themselves
/// verified.
pub fn contract_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let items = [encode_bytes(sender), encode_uint(nonce)];
    let digest = keccak256(&encode_list(&items));
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

/// Signing digest and 65-byte `r||s||recid` signature of a signed envelope.
///
/// Feed the digest and signature to the consensus crate's `ecrecover` to get the sender.
/// Callers must pass bytes already bound to a sealed `transactionsRoot`: this decodes, it
/// does not authenticate.
///
/// **The preimage is sliced out of the input, never re-encoded.** The signing payload is a
/// prefix of the envelope's own list payload, so the bytes are copied verbatim and only a
/// fresh list header is put in front. Re-serialising the decoded fields would risk a
/// spelling that differs from the signer's by one byte, which changes the digest and
/// recovers a plausible wrong address — the failure mode worth engineering away rather
/// than testing for.
///
/// EIP-155 legacy is the one case that appends: its signing list is the first six fields
/// plus `chainId, 0, 0`, and those three are emitted canonically.
pub fn tx_signing_hash(bytes: &[u8]) -> Result<([u8; 32], [u8; 65]), RawTxError> {
    if bytes.is_empty() {
        return Err(RawTxError::Empty);
    }
    if bytes.len() > MAX_RAW_TX {
        return Err(RawTxError::TooLarge);
    }
    let typed = matches!(bytes[0], 0x01..=0x04);
    if (0x05..=0x7f).contains(&bytes[0]) {
        return Err(RawTxError::UnknownType(bytes[0]));
    }
    let envelope = if typed { &bytes[1..] } else { bytes };
    // Decode first: this rejects non-canonical spellings, so the span walk below only
    // ever runs over bytes that already round-trip.
    let items = decode_list(envelope)?;
    if items.len() < 9 {
        return Err(RawTxError::Truncated);
    }
    let payload = list_payload(envelope)?;
    let spans = item_offsets(payload, items.len())?;

    let n = items.len();
    let sig_v = rlp_u64(&items[n - 3])?;
    let r = item_bytes32(&items[n - 2])?;
    let sig_s = item_bytes32(&items[n - 1])?;

    let (preimage, recid) = if typed {
        // Typed: everything before the last three fields, under the same type byte.
        let cut = spans[n - 3];
        if sig_v > 1 {
            return Err(RawTxError::InvalidRlp);
        }
        let mut out = vec![bytes[0]];
        out.extend_from_slice(&list_header(cut));
        out.extend_from_slice(&payload[..cut]);
        (out, sig_v as u8)
    } else {
        if n != 9 {
            return Err(RawTxError::Truncated);
        }
        let cut = spans[6];
        let mut body = payload[..cut].to_vec();
        let recid = if sig_v == 27 || sig_v == 28 {
            // Pre-EIP-155: the six fields alone, no chainId suffix.
            (sig_v - 27) as u8
        } else if sig_v >= 35 {
            body.extend_from_slice(&encode_uint((sig_v - 35) / 2));
            body.push(0x80);
            body.push(0x80);
            ((sig_v - 35) % 2) as u8
        } else {
            return Err(RawTxError::Unprotected);
        };
        let mut out = list_header(body.len());
        out.extend_from_slice(&body);
        (out, recid)
    };

    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&r);
    sig[32..64].copy_from_slice(&sig_s);
    sig[64] = recid;
    Ok((keccak256(&preimage), sig))
}

/// `r` / `s` as a left-padded 32-byte word. RLP strips leading zeros, so a 31-byte
/// component is normal; longer than 32 is not a signature.
fn item_bytes32(item: &Rlp<'_>) -> Result<[u8; 32], RawTxError> {
    let b = item.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    if b.is_empty() || b.len() > 32 {
        return Err(RawTxError::Unsigned);
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// List header for a payload of `len` bytes.
fn list_header(len: usize) -> Vec<u8> {
    if len <= 55 {
        return vec![0xc0 + len as u8];
    }
    let be = (len as u64).to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(7);
    let lenb = &be[start..];
    let mut out = vec![0xf7 + lenb.len() as u8];
    out.extend_from_slice(lenb);
    out
}

/// Payload slice of a list, i.e. the input with its list header removed.
fn list_payload(buf: &[u8]) -> Result<&[u8], RawTxError> {
    let p = *buf.first().ok_or(RawTxError::Truncated)?;
    let (start, len) = if (0xc0..=0xf7).contains(&p) {
        (1usize, (p - 0xc0) as usize)
    } else if p >= 0xf8 {
        let ll = (p - 0xf7) as usize;
        if buf.len() < 1 + ll {
            return Err(RawTxError::Truncated);
        }
        let mut n = 0usize;
        for b in &buf[1..1 + ll] {
            n = (n << 8) | *b as usize;
        }
        (1 + ll, n)
    } else {
        return Err(RawTxError::InvalidRlp);
    };
    buf.get(start..start + len).ok_or(RawTxError::Truncated)
}

/// Byte offset of each item within a list payload. `count` comes from the decode above,
/// so the walk cannot disagree with it about how many items there are.
fn item_offsets(payload: &[u8], count: usize) -> Result<Vec<usize>, RawTxError> {
    let mut offs = Vec::with_capacity(count);
    let mut at = 0usize;
    for _ in 0..count {
        offs.push(at);
        let rest = payload.get(at..).ok_or(RawTxError::Truncated)?;
        at += item_len(rest)?;
    }
    if at != payload.len() {
        return Err(RawTxError::InvalidRlp);
    }
    Ok(offs)
}

/// Encoded length of the item starting at `buf[0]`, header included.
fn item_len(buf: &[u8]) -> Result<usize, RawTxError> {
    let p = *buf.first().ok_or(RawTxError::Truncated)?;
    let (hdr, len) = match p {
        0x00..=0x7f => (0usize, 1usize),
        0x80..=0xb7 => (1, (p - 0x80) as usize),
        0xb8..=0xbf => long(buf, (p - 0xb7) as usize)?,
        0xc0..=0xf7 => (1, (p - 0xc0) as usize),
        _ => long(buf, (p - 0xf7) as usize)?,
    };
    let total = hdr + len;
    if buf.len() < total {
        return Err(RawTxError::Truncated);
    }
    Ok(total)
}

fn long(buf: &[u8], ll: usize) -> Result<(usize, usize), RawTxError> {
    if ll == 0 || ll > 8 || buf.len() < 1 + ll {
        return Err(RawTxError::InvalidRlp);
    }
    let mut n = 0usize;
    for b in &buf[1..1 + ll] {
        n = (n << 8) | *b as usize;
    }
    Ok((1 + ll, n))
}

fn parse_chain_id(bytes: &[u8]) -> Result<u64, RawTxError> {
    match bytes[0] {
        0x01..=0x04 => parse_typed(bytes[0], &bytes[1..]),
        0x05..=0x7f => Err(RawTxError::UnknownType(bytes[0])),
        _ => parse_legacy(bytes),
    }
}

fn parse_typed(ty: u8, payload: &[u8]) -> Result<u64, RawTxError> {
    let items = decode_list(payload)?;
    let min = match ty {
        0x01 => 11, // EIP-2930
        0x02 => 12, // EIP-1559
        0x03 => 14, // EIP-4844
        0x04 => 13, // EIP-7702
        _ => return Err(RawTxError::UnknownType(ty)),
    };
    if items.len() < min {
        return Err(RawTxError::Truncated);
    }
    require_sig(&items[items.len() - 2], &items[items.len() - 1])?;
    rlp_u64(&items[0])
}

fn parse_legacy(bytes: &[u8]) -> Result<u64, RawTxError> {
    let items = decode_list(bytes)?;
    if items.len() != 9 {
        return Err(RawTxError::Truncated);
    }
    require_sig(&items[7], &items[8])?;
    let v = rlp_u64(&items[6])?;
    if v == 27 || v == 28 {
        return Err(RawTxError::Unprotected);
    }
    if v < 35 {
        return Err(RawTxError::Unprotected);
    }
    Ok((v - 35) / 2)
}

fn decode_list(bytes: &[u8]) -> Result<Vec<Rlp<'_>>, RawTxError> {
    match decode(bytes) {
        Ok(Rlp::List(v)) => Ok(v),
        Ok(Rlp::Bytes(_)) => Err(RawTxError::InvalidRlp),
        Err(RlpError::Truncated) => Err(RawTxError::Truncated),
        Err(_) => Err(RawTxError::InvalidRlp),
    }
}

fn rlp_u64(item: &Rlp<'_>) -> Result<u64, RawTxError> {
    let b = item.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    if b.len() > 8 {
        return Err(RawTxError::InvalidRlp);
    }
    if b.len() > 1 && b[0] == 0 {
        return Err(RawTxError::InvalidRlp);
    }
    let mut n = 0u64;
    for x in b {
        n = (n << 8) | u64::from(*x);
    }
    Ok(n)
}

fn require_sig(r: &Rlp<'_>, s: &Rlp<'_>) -> Result<(), RawTxError> {
    let rb = r.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    let sb = s.as_bytes().map_err(|_| RawTxError::InvalidRlp)?;
    if rb.is_empty() || sb.is_empty() || rb.iter().all(|b| *b == 0) || sb.iter().all(|b| *b == 0) {
        return Err(RawTxError::Unsigned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        assert!(b.len() <= 55);
        let mut v = vec![0x80 + b.len() as u8];
        v.extend_from_slice(b);
        v
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for i in items {
            payload.extend_from_slice(i);
        }
        assert!(payload.len() <= 55);
        let mut v = vec![0xc0 + payload.len() as u8];
        v.extend(payload);
        v
    }

    fn be(n: u64) -> Vec<u8> {
        if n == 0 {
            return rlp_bytes(&[]);
        }
        let b = n.to_be_bytes();
        let i = b.iter().position(|x| *x != 0).unwrap_or(7);
        rlp_bytes(&b[i..])
    }

    fn addr20() -> Vec<u8> {
        let mut v = vec![0x94];
        v.extend_from_slice(&[0u8; 20]);
        v
    }

    /// Envelope of `n_items` fields with a 20-byte recipient at `to_idx`.
    fn envelope_with_to(ty: Option<u8>, n_items: usize, to_idx: usize, to: &[u8; 20]) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = (0..n_items).map(|_| rlp_bytes(&[])).collect();
        let mut a = vec![0x94];
        a.extend_from_slice(to);
        items[to_idx] = a;
        let list = rlp_list(&items);
        match ty {
            Some(t) => {
                let mut out = vec![t];
                out.extend(list);
                out
            }
            None => list,
        }
    }

    #[test]
    fn to_address_is_read_at_the_right_index_for_every_type() {
        let want = [0xABu8; 20];
        // (type, field count, index of `to`) straight from the EIP field orders.
        for (ty, n, idx) in [
            (None, 9usize, 3usize), // legacy
            (Some(0x01), 11, 4),    // EIP-2930
            (Some(0x02), 12, 5),    // EIP-1559
            (Some(0x03), 14, 5),    // EIP-4844
            (Some(0x04), 13, 5),    // EIP-7702
        ] {
            let raw = envelope_with_to(ty, n, idx, &want);
            assert_eq!(
                tx_to_address(&raw).unwrap(),
                Some(want),
                "type {ty:?} index {idx}"
            );
        }
    }

    #[test]
    fn effective_gas_price_follows_the_envelope_shape() {
        // Legacy: gasPrice at index 1, paid in full whatever the base fee.
        let mut items: Vec<Vec<u8>> = (0..9).map(|_| rlp_bytes(&[])).collect();
        items[1] = be(7);
        assert_eq!(
            tx_gas_price(&rlp_list(&items)).unwrap(),
            TxGasPrice::Fixed(7)
        );
        assert_eq!(TxGasPrice::Fixed(7).effective(0), 7);
        assert_eq!(TxGasPrice::Fixed(7).effective(3), 7);

        // EIP-1559: tip 2, cap 100. base + min(tip, cap - base).
        let mut items: Vec<Vec<u8>> = (0..12).map(|_| rlp_bytes(&[])).collect();
        items[2] = be(2);
        items[3] = be(100);
        let mut envelope = vec![0x02u8];
        envelope.extend(rlp_list(&items));
        let p = tx_gas_price(&envelope).unwrap();
        assert_eq!(
            p,
            TxGasPrice::Dynamic {
                max_priority: 2,
                max_fee: 100
            }
        );
        assert_eq!(
            p.effective(0),
            2,
            "Parlia base fee is zero: sender pays the tip"
        );
        assert_eq!(p.effective(10), 12, "base + tip while the cap has room");
        assert_eq!(p.effective(99), 100, "cap binds: base + (cap - base)");
    }

    #[test]
    fn a_gas_price_wider_than_u128_is_refused_not_truncated() {
        let mut items: Vec<Vec<u8>> = (0..9).map(|_| rlp_bytes(&[])).collect();
        items[1] = rlp_bytes(&[0xFF; 17]);
        assert_eq!(
            tx_gas_price(&rlp_list(&items)),
            Err(RawTxError::InvalidRlp),
            "a wrapped price would be a plausible wrong number"
        );
    }

    #[test]
    fn contract_address_matches_the_consensus_rule() {
        // keccak(rlp([sender, nonce]))[12..] - the vector is the well-known
        // 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 / nonce 0 pair from EIP-161.
        let sender = [
            0x6a, 0xc7, 0xea, 0x33, 0xf8, 0x83, 0x1e, 0xa9, 0xdc, 0xc5, 0x33, 0x93, 0xaa, 0xa8,
            0x8b, 0x25, 0xa7, 0x85, 0xdb, 0xf0,
        ];
        assert_eq!(
            hex::encode(contract_address(&sender, 0)),
            "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
        );
    }

    #[test]
    fn contract_creation_has_no_recipient() {
        // Empty string at the `to` position is the canonical "create".
        let raw = rlp_list(&(0..9).map(|_| rlp_bytes(&[])).collect::<Vec<_>>());
        assert_eq!(tx_to_address(&raw).unwrap(), None);
    }

    #[test]
    fn a_short_envelope_is_an_error_not_a_neighbouring_field() {
        // Three fields: index 3 does not exist, so legacy `to` must not fall back to one
        // of the fields that does.
        let raw = rlp_list(&(0..3).map(|_| rlp_bytes(&[])).collect::<Vec<_>>());
        assert_eq!(tx_to_address(&raw), Err(RawTxError::Truncated));
    }

    #[test]
    fn a_recipient_that_is_not_twenty_bytes_is_refused() {
        let mut items: Vec<Vec<u8>> = (0..9).map(|_| rlp_bytes(&[])).collect();
        items[3] = rlp_bytes(&[1, 2, 3]);
        assert_eq!(
            tx_to_address(&rlp_list(&items)),
            Err(RawTxError::InvalidRlp)
        );
    }

    /// Minimal signed EIP-1559 skeleton (dummy r/s).
    fn dummy_eip1559(chain_id: u64) -> Vec<u8> {
        dummy_typed(0x02, chain_id, 12)
    }

    /// Typed tx with `n_items` RLP fields (chainId first, dummy r/s last).
    fn dummy_typed(ty: u8, chain_id: u64, n_items: usize) -> Vec<u8> {
        let z = rlp_bytes(&[]);
        let r = rlp_bytes(&[1]);
        let s = rlp_bytes(&[1]);
        let mut items = vec![be(chain_id)];
        while items.len() + 2 < n_items {
            items.push(z.clone());
        }
        items.push(r);
        items.push(s);
        let mut out = vec![ty];
        out.extend(rlp_list(&items));
        out
    }

    fn dummy_legacy(chain_id: u64, unprotected: bool) -> Vec<u8> {
        let v = if unprotected { 27 } else { 35 + 2 * chain_id };
        let z = rlp_bytes(&[]);
        rlp_list(&[
            z.clone(),
            z.clone(),
            be(21_000),
            addr20(),
            z.clone(),
            z,
            be(v),
            rlp_bytes(&[1]),
            rlp_bytes(&[1]),
        ])
    }

    #[test]
    fn empty_and_huge_rejected() {
        assert_eq!(validate_bsc_raw_tx(&[]).unwrap_err(), RawTxError::Empty);
        let huge = vec![0x02; MAX_RAW_TX + 1];
        assert_eq!(
            validate_bsc_raw_tx(&huge).unwrap_err(),
            RawTxError::TooLarge
        );
    }

    #[test]
    fn eip1559_chain_id_56_ok() {
        let raw = dummy_eip1559(56);
        let hash = validate_bsc_raw_tx(&raw).expect("bsc typed2");
        assert_eq!(hash, keccak256(&raw));
    }

    #[test]
    fn eip1559_eth_mainnet_rejected() {
        let raw = dummy_eip1559(1);
        assert_eq!(
            validate_bsc_raw_tx(&raw).unwrap_err(),
            RawTxError::WrongChain
        );
    }

    #[test]
    fn typed_access_blob_setcode_chain_id() {
        for (ty, n) in [(0x01, 11), (0x03, 14), (0x04, 13)] {
            let eth = dummy_typed(ty, 1, n);
            assert_eq!(
                validate_bsc_raw_tx(&eth).unwrap_err(),
                RawTxError::WrongChain,
                "type 0x{ty:02x} chainId=1"
            );
            let bsc = dummy_typed(ty, 56, n);
            validate_bsc_raw_tx(&bsc).unwrap_or_else(|e| panic!("type 0x{ty:02x} chainId=56: {e}"));
        }
    }

    #[test]
    fn legacy_eip155_56_ok() {
        let raw = dummy_legacy(56, false);
        validate_bsc_raw_tx(&raw).expect("legacy 56");
    }

    #[test]
    fn legacy_unprotected_rejected() {
        let raw = dummy_legacy(56, true);
        assert_eq!(
            validate_bsc_raw_tx(&raw).unwrap_err(),
            RawTxError::Unprotected
        );
    }

    #[test]
    fn unknown_type_rejected() {
        let mut raw = dummy_eip1559(56);
        raw[0] = 0x2a;
        assert_eq!(
            validate_bsc_raw_tx(&raw).unwrap_err(),
            RawTxError::UnknownType(0x2a)
        );
    }

    /// `n` nested single-element lists — the cheapest way to drive recursion.
    fn nested_lists(n: usize) -> Vec<u8> {
        let mut cur = vec![0xc0u8];
        for _ in 0..n {
            let len = cur.len();
            let mut out = Vec::with_capacity(len + 9);
            if len <= 55 {
                out.push(0xc0 + len as u8);
            } else {
                let be = (len as u64).to_be_bytes();
                let start = be.iter().position(|&b| b != 0).unwrap_or(7);
                out.push(0xf7 + (8 - start) as u8);
                out.extend_from_slice(&be[start..]);
            }
            out.extend_from_slice(&cur);
            cur = out;
        }
        cur
    }

    /// Before the RLP depth cap this aborted the process with a stack overflow
    /// (`STATUS_STACK_OVERFLOW` / SIGSEGV) — not a catchable panic — from a
    /// single `eth_sendRawTransaction` body well under [`MAX_RAW_TX`].
    #[test]
    fn deeply_nested_raw_tx_is_rejected_not_a_stack_overflow() {
        let raw = nested_lists(100_000);
        assert!(raw.len() <= MAX_RAW_TX, "input len {}", raw.len());
        assert_eq!(
            validate_bsc_raw_tx(&raw).unwrap_err(),
            RawTxError::InvalidRlp
        );
    }

    #[test]
    fn unsigned_typed_rejected() {
        let mut raw = dummy_eip1559(56);
        // last sig byte is s; zero it out by replacing trailing 0x01 with 0x80 (empty)
        *raw.last_mut().unwrap() = 0x80;
        assert_eq!(validate_bsc_raw_tx(&raw).unwrap_err(), RawTxError::Unsigned);
    }
}
