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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rlp<'a> {
    Bytes(&'a [u8]),
    List(Vec<Rlp<'a>>),
}

pub fn decode(input: &[u8]) -> Result<Rlp<'_>, RlpError> {
    let (item, rest) = decode_one(input)?;
    if !rest.is_empty() {
        return Err(RlpError::Trailing);
    }
    Ok(item)
}

fn decode_one(input: &[u8]) -> Result<(Rlp<'_>, &[u8]), RlpError> {
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
        return Ok((Rlp::Bytes(b), tail));
    }
    if p <= 0xbf {
        let ll = (p - 0xb7) as usize;
        if rest.len() < ll {
            return Err(RlpError::Truncated);
        }
        let (lb, after) = rest.split_at(ll);
        let len = be_len(lb)?;
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
        return Ok((Rlp::List(decode_list(payload)?), tail));
    }
    let ll = (p - 0xf7) as usize;
    if rest.len() < ll {
        return Err(RlpError::Truncated);
    }
    let (lb, after) = rest.split_at(ll);
    let len = be_len(lb)?;
    if after.len() < len {
        return Err(RlpError::Truncated);
    }
    let (payload, tail) = after.split_at(len);
    Ok((Rlp::List(decode_list(payload)?), tail))
}

fn decode_list(mut payload: &[u8]) -> Result<Vec<Rlp<'_>>, RlpError> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = decode_one(payload)?;
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
}
