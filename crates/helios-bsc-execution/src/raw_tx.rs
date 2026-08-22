//! Local checks on `eth_sendRawTransaction` bytes before the untrusted upstream.
//!
//! Broadcast is still unverified (drop / MEV). These checks stop replay of
//! other-chain txs and bind the wallet's returned hash to keccak256(raw).

use crate::rlp::{decode, Rlp, RlpError};
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
