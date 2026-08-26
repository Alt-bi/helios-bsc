//! Hex / keccak helpers for RPC fixtures and consensus.

use crate::error::TypesError;
use tiny_keccak::{Hasher, Keccak};

pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, TypesError> {
    let raw = strip_0x(s);
    if !raw.len().is_multiple_of(2) {
        return Err(TypesError::InvalidHex(format!(
            "odd-length hex ({})",
            raw.len()
        )));
    }
    hex::decode(raw).map_err(|e| TypesError::InvalidHex(e.to_string()))
}

pub fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], TypesError> {
    let v = decode_hex(s)?;
    if v.len() != N {
        return Err(TypesError::InvalidHexLength {
            expected: N,
            got: v.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn decode_u64(s: &str) -> Result<u64, TypesError> {
    let raw = strip_0x(s);
    if raw.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(raw, 16).map_err(|e| TypesError::InvalidHex(e.to_string()))
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

pub fn address_from_pubkey_uncompressed(pubkey65: &[u8]) -> Result<[u8; 20], TypesError> {
    if pubkey65.len() != 65 || pubkey65[0] != 0x04 {
        return Err(TypesError::InvalidHex(
            "expected uncompressed secp256k1 pubkey (65 bytes, 0x04 prefix)".into(),
        ));
    }
    let hash = keccak256(&pubkey65[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

pub fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}
