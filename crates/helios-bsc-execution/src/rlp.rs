//! Minimal RLP decode for MPT nodes and account leaves.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RlpError {
    #[error("rlp truncated")]
    Truncated,
    #[error("rlp trailing bytes")]
    Trailing,
    #[error("rlp invalid length")]
    Invalid,
    #[error("rlp nested too deeply")]
    TooDeep,
    #[error("rlp non-canonical encoding")]
    NonCanonical,
}

/// Max list nesting. Real MPT nodes, consensus receipts and EIP-2718 txs nest
/// four deep at most; the cap exists because `decode_one` recurses, so hostile
/// bytes (e.g. an `eth_sendRawTransaction` body) would otherwise overflow the
/// thread stack and abort the process rather than return an error.
pub const MAX_RLP_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rlp<'a> {
    Bytes(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

pub fn decode(input: &[u8]) -> Result<Rlp<'_>, RlpError> {
    let (item, rest) = decode_one(input, 0)?;
    if !rest.is_empty() {
        return Err(RlpError::Trailing);
    }
    Ok(item)
}

fn decode_one(input: &[u8], depth: usize) -> Result<(Rlp<'_>, &[u8]), RlpError> {
    let (prefix, rest) = input.split_first().ok_or(RlpError::Truncated)?;
    let p = *prefix;
    if p <= 0x7f {
        return Ok((Rlp::Bytes(&input[..1]), rest));
    }
    if p <= 0xb7 {
        let len = (p - 0x80) as usize;
        if rest.len() < len {
            return Err(RlpError::Truncated);
        }
        let (b, tail) = rest.split_at(len);
        // A lone byte < 0x80 is its own encoding; `0x81 xx` would be a second
        // spelling of the same value.
        if len == 1 && b[0] < 0x80 {
            return Err(RlpError::NonCanonical);
        }
        return Ok((Rlp::Bytes(b), tail));
    }
    if p <= 0xbf {
        let ll = (p - 0xb7) as usize;
        if rest.len() < ll {
            return Err(RlpError::Truncated);
        }
        let (lb, after) = rest.split_at(ll);
        let len = be_len(lb)?;
        if len <= 55 {
            return Err(RlpError::NonCanonical);
        }
        if after.len() < len {
            return Err(RlpError::Truncated);
        }
        let (b, tail) = after.split_at(len);
        return Ok((Rlp::Bytes(b), tail));
    }
    if p <= 0xf7 {
        let len = (p - 0xc0) as usize;
        if rest.len() < len {
            return Err(RlpError::Truncated);
        }
        let (payload, tail) = rest.split_at(len);
        return Ok((Rlp::List(decode_list(payload, depth + 1)?), tail));
    }
    let ll = (p - 0xf7) as usize;
    if rest.len() < ll {
        return Err(RlpError::Truncated);
    }
    let (lb, after) = rest.split_at(ll);
    let len = be_len(lb)?;
    if len <= 55 {
        return Err(RlpError::NonCanonical);
    }
    if after.len() < len {
        return Err(RlpError::Truncated);
    }
    let (payload, tail) = after.split_at(len);
    Ok((Rlp::List(decode_list(payload, depth + 1)?), tail))
}

fn decode_list(mut payload: &[u8], depth: usize) -> Result<Vec<Rlp<'_>>, RlpError> {
    if depth > MAX_RLP_DEPTH {
        return Err(RlpError::TooDeep);
    }
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = decode_one(payload, depth)?;
        items.push(item);
        payload = rest;
    }
    Ok(items)
}

fn be_len(b: &[u8]) -> Result<usize, RlpError> {
    if b.is_empty() || (b[0] == 0 && b.len() > 1) {
        return Err(RlpError::Invalid);
    }
    let mut n: usize = 0;
    for x in b {
        n = n.checked_shl(8).ok_or(RlpError::Invalid)?;
        n = n.checked_add(*x as usize).ok_or(RlpError::Invalid)?;
    }
    Ok(n)
}

impl<'a> Rlp<'a> {
    pub fn as_bytes(&self) -> Result<&'a [u8], RlpError> {
        match self {
            Rlp::Bytes(b) => Ok(b),
            Rlp::List(_) => Err(RlpError::Invalid),
        }
    }

    pub fn as_list(&self) -> Result<&[Rlp<'a>], RlpError> {
        match self {
            Rlp::List(v) => Ok(v),
            Rlp::Bytes(_) => Err(RlpError::Invalid),
        }
    }
}

/// RLP string / byte array. A single byte `< 0x80` is encoded as itself.
pub(crate) fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    encode_string(data)
}

fn encode_string(data: &[u8]) -> Vec<u8> {
    if data.len() <= 55 {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
        out
    } else {
        let lenb = len_be(data.len());
        let mut out = Vec::with_capacity(1 + lenb.len() + data.len());
        out.push(0xb7 + lenb.len() as u8);
        out.extend_from_slice(&lenb);
        out.extend_from_slice(data);
        out
    }
}

/// Unsigned integer: big-endian, no leading zeros. Zero → empty string (`0x80`).
pub(crate) fn encode_uint(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap();
    encode_bytes(&be[start..])
}

/// Concatenate already-encoded RLP items into a list.
pub(crate) fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut payload = Vec::with_capacity(payload_len);
    for item in items {
        payload.extend_from_slice(item);
    }
    if payload.len() <= 55 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(0xc0 + payload.len() as u8);
        out.extend_from_slice(&payload);
        out
    } else {
        let lenb = len_be(payload.len());
        let mut out = Vec::with_capacity(1 + lenb.len() + payload.len());
        out.push(0xf7 + lenb.len() as u8);
        out.extend_from_slice(&lenb);
        out.extend_from_slice(&payload);
        out
    }
}

fn len_be(len: usize) -> Vec<u8> {
    let be = (len as u64).to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_string() {
        assert_eq!(decode(&[0x80]).unwrap(), Rlp::Bytes(&[]));
        assert_eq!(decode(&[0x01]).unwrap(), Rlp::Bytes(&[0x01]));
    }

    #[test]
    fn uint_zero_is_empty_string() {
        assert_eq!(encode_uint(0), vec![0x80]);
    }

    #[test]
    fn uint_56() {
        assert_eq!(encode_uint(56), vec![56]);
    }

    #[test]
    fn encode_bytes_roundtrip() {
        assert_eq!(decode(&encode_bytes(&[])).unwrap(), Rlp::Bytes(&[]));
        assert_eq!(decode(&encode_bytes(&[0x01])).unwrap(), Rlp::Bytes(&[0x01]));
        assert_eq!(decode(&encode_bytes(&[0x80])).unwrap(), Rlp::Bytes(&[0x80]));
        let long = vec![0xabu8; 60];
        assert_eq!(decode(&encode_bytes(&long)).unwrap(), Rlp::Bytes(&long));
    }

    /// `n` nested single-element lists around an empty list.
    fn nested_lists(n: usize) -> Vec<u8> {
        let mut cur = vec![0xc0u8];
        for _ in 0..n {
            cur = encode_list(&[cur]);
        }
        cur
    }

    #[test]
    fn depth_cap_replaces_stack_overflow() {
        // At the cap: still decodable.
        assert!(decode(&nested_lists(MAX_RLP_DEPTH - 1)).is_ok());
        // Past it: a plain error, not a recursion that aborts the process.
        assert_eq!(
            decode(&nested_lists(MAX_RLP_DEPTH + 1)).unwrap_err(),
            RlpError::TooDeep
        );
        // The shape a hostile 512 KiB `eth_sendRawTransaction` body would use.
        assert_eq!(
            decode(&nested_lists(100_000)).unwrap_err(),
            RlpError::TooDeep
        );
    }

    #[test]
    fn single_byte_in_string_form_is_non_canonical() {
        // `0x00`..`0x7f` must be spelled as themselves, never as `0x81 xx`.
        assert_eq!(decode(&[0x81, 0x00]).unwrap_err(), RlpError::NonCanonical);
        assert_eq!(decode(&[0x81, 0x7f]).unwrap_err(), RlpError::NonCanonical);
        // 0x80 and above genuinely need the length prefix.
        assert_eq!(decode(&[0x81, 0x80]).unwrap(), Rlp::Bytes(&[0x80]));
        assert_eq!(decode(&[0x00]).unwrap(), Rlp::Bytes(&[0x00]));
    }

    #[test]
    fn long_form_under_56_bytes_is_non_canonical() {
        // String: `0xb8 01 ff` is a second spelling of `0x81 ff`.
        assert_eq!(
            decode(&[0xb8, 0x01, 0xff]).unwrap_err(),
            RlpError::NonCanonical
        );
        let mut fifty_five = vec![0xb8, 0x37];
        fifty_five.extend_from_slice(&[0xaau8; 55]);
        assert_eq!(decode(&fifty_five).unwrap_err(), RlpError::NonCanonical);
        // List: `0xf8 01 c0` is a second spelling of `0xc1 c0`.
        assert_eq!(
            decode(&[0xf8, 0x01, 0xc0]).unwrap_err(),
            RlpError::NonCanonical
        );
        // 56 bytes is the first length that legitimately needs long form.
        let mut fifty_six = vec![0xb8, 0x38];
        fifty_six.extend_from_slice(&[0xaau8; 56]);
        assert_eq!(decode(&fifty_six).unwrap(), Rlp::Bytes(&[0xaau8; 56]));
    }

    #[test]
    fn leading_zero_length_prefix_rejected() {
        // `0xb9 00 38 ...` — length 56 written in two bytes.
        let mut padded = vec![0xb9, 0x00, 0x38];
        padded.extend_from_slice(&[0xaau8; 56]);
        assert_eq!(decode(&padded).unwrap_err(), RlpError::Invalid);
    }

    #[test]
    fn trailing_bytes_rejected() {
        assert_eq!(decode(&[0x80, 0x80]).unwrap_err(), RlpError::Trailing);
    }
}
