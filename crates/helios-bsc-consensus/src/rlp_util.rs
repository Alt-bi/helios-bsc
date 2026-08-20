//! Minimal RLP encoder matching go-ethereum `rlp.Encode` for SealHash.

pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
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
pub fn encode_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap();
    encode_bytes(&be[start..])
}

pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
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
    fn uint_zero_is_empty_string() {
        assert_eq!(encode_uint(0), vec![0x80]);
    }

    #[test]
    fn uint_56() {
        assert_eq!(encode_uint(56), vec![56]);
    }
}
