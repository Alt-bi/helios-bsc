//! `eth_getProof` JSON → verified account.

use crate::mpt::{
    verify_account_proof, verify_bytecode, verify_storage_proof, Account, MptError,
    EMPTY_CODE_HASH, EMPTY_TRIE_ROOT,
};
use helios_bsc_types::{decode_hex, decode_hex_fixed, hexutil, TypesError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error(transparent)]
    Types(#[from] TypesError),
    #[error(transparent)]
    Mpt(#[from] MptError),
    #[error("proof JSON: {0}")]
    Json(String),
    #[error("claimed field mismatch: {0}")]
    ClaimMismatch(&'static str),
    #[error("stateRoot mismatch")]
    StateRootMismatch,
    #[error("too many proof nodes")]
    TooManyNodes,
    #[error("proof node too large")]
    NodeTooLarge,
}

/// EIP-1186 proofs on BSC are ~8–12 nodes; 32 is a DoS cap, not a protocol constant.
pub const MAX_PROOF_NODES: usize = 32;
/// Decoded MPT node size cap (branch ~532 B).
pub const MAX_PROOF_NODE_BYTES: usize = 16 * 1024;
/// geth `params.MaxCodeSize`.
pub const MAX_CODE_SIZE: usize = 24_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProofEntry {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub proof: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthAccountProof {
    pub address: String,
    pub account_proof: Vec<String>,
    pub balance: String,
    pub code_hash: String,
    pub nonce: String,
    pub storage_hash: String,
    #[serde(default)]
    pub storage_proof: Vec<StorageProofEntry>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAccount {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance_wei: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// True iff both hex quantities decode to the same integer (leading zeros ignored).
pub fn qty_equal(a: &str, b: &str) -> bool {
    match (decode_qty(a), decode_qty(b)) {
        (Ok(x), Ok(y)) => strip_int(&x) == strip_int(&y),
        _ => false,
    }
}

pub fn encode_qty(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".into()
    } else {
        format!("0x{trimmed}")
    }
}

pub fn verify_eth_get_proof(
    state_root: &[u8; 32],
    expected_address: &[u8; 20],
    proof: &EthAccountProof,
) -> Result<VerifiedAccount, ProofError> {
    let addr = decode_hex_fixed::<20>(&proof.address)?;
    if &addr != expected_address {
        return Err(ProofError::ClaimMismatch("address"));
    }
    if proof.account_proof.len() > MAX_PROOF_NODES {
        return Err(ProofError::TooManyNodes);
    }
    for sp in &proof.storage_proof {
        if sp.proof.len() > MAX_PROOF_NODES {
            return Err(ProofError::TooManyNodes);
        }
    }
    let nodes: Vec<Vec<u8>> = proof
        .account_proof
        .iter()
        .map(|s| decode_hex(s))
        .collect::<Result<_, _>>()?;
    if nodes.iter().any(|n| n.len() > MAX_PROOF_NODE_BYTES) {
        return Err(ProofError::NodeTooLarge);
    }
    let account: Account = verify_account_proof(state_root, &addr, &nodes)?;
    let absent = account.nonce == 0
        && strip_int(&account.balance).is_empty()
        && account.storage_root == EMPTY_TRIE_ROOT
        && account.code_hash == EMPTY_CODE_HASH;

    let claimed_balance = encode_qty(&decode_qty(&proof.balance)?);
    let got_balance = encode_qty(&account.balance);
    if claimed_balance != got_balance {
        return Err(ProofError::ClaimMismatch("balance"));
    }
    let claimed_nonce = parse_qty_u64(&proof.nonce)?;
    if claimed_nonce != account.nonce {
        return Err(ProofError::ClaimMismatch("nonce"));
    }
    let claimed_storage = decode_hex_fixed::<32>(&proof.storage_hash)?;
    if claimed_storage != account.storage_root
        && !(absent && claimed_storage.iter().all(|b| *b == 0))
    {
        return Err(ProofError::ClaimMismatch("storageHash"));
    }
    let claimed_code = decode_hex_fixed::<32>(&proof.code_hash)?;
    if claimed_code != account.code_hash && !(absent && claimed_code.iter().all(|b| *b == 0)) {
        return Err(ProofError::ClaimMismatch("codeHash"));
    }

    Ok(VerifiedAccount {
        address: addr,
        nonce: account.nonce,
        balance_wei: strip_int(&account.balance),
        storage_root: account.storage_root,
        code_hash: account.code_hash,
    })
}

fn strip_int(b: &[u8]) -> Vec<u8> {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[i..].to_vec()
}

fn decode_qty(s: &str) -> Result<Vec<u8>, TypesError> {
    let raw = hexutil::strip_0x(s);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.len() % 2 == 1 {
        decode_hex(&format!("0x0{raw}"))
    } else {
        decode_hex(s)
    }
}

fn parse_qty_u64(s: &str) -> Result<u64, ProofError> {
    let v = decode_qty(s)?;
    if v.len() > 8 {
        return Err(ProofError::Json("nonce too large".into()));
    }
    let mut n = 0u64;
    for x in v {
        n = (n << 8) | u64::from(x);
    }
    Ok(n)
}

impl From<serde_json::Error> for ProofError {
    fn from(e: serde_json::Error) -> Self {
        ProofError::Json(e.to_string())
    }
}

pub fn pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[32 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    out
}

pub fn encode_data32(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(pad32(bytes)))
}

/// Drop storageProof entries the caller did not request (and drop all if `keys` is empty).
pub fn retain_requested_storage(proof: &mut EthAccountProof, keys: &[String]) {
    if keys.is_empty() {
        proof.storage_proof.clear();
        return;
    }
    let want: Vec<[u8; 32]> = keys
        .iter()
        .filter_map(|k| {
            let raw = hexutil::strip_0x(k);
            let even = if raw.len() % 2 == 1 {
                format!("0{raw}")
            } else {
                raw.to_string()
            };
            hex::decode(even).ok().map(|b| pad32(&b))
        })
        .collect();
    proof.storage_proof.retain(|e| {
        decode_qty(&e.key)
            .ok()
            .map(|k| want.iter().any(|w| pad32(&k) == *w))
            .unwrap_or(false)
    });
}

/// Verify a storage slot from an EIP-1186 proof already checked at `account`.
pub fn verify_storage_slot(
    account: &VerifiedAccount,
    slot: &[u8; 32],
    proof: &EthAccountProof,
) -> Result<Vec<u8>, ProofError> {
    if account.storage_root == EMPTY_TRIE_ROOT {
        return Ok(Vec::new());
    }
    let want = format!("0x{}", hex::encode(slot));
    let entry = proof
        .storage_proof
        .iter()
        .find(|e| {
            decode_qty(&e.key)
                .ok()
                .map(|k| pad32(&k) == *slot)
                .unwrap_or(false)
                || e.key.eq_ignore_ascii_case(&want)
        })
        .ok_or(ProofError::ClaimMismatch("storageProof"))?;
    let nodes: Vec<Vec<u8>> = entry
        .proof
        .iter()
        .map(|s| decode_hex(s))
        .collect::<Result<_, _>>()?;
    if nodes.iter().any(|n| n.len() > MAX_PROOF_NODE_BYTES) {
        return Err(ProofError::NodeTooLarge);
    }
    let value = verify_storage_proof(&account.storage_root, slot, &nodes)?;
    let claimed = decode_qty(&entry.value)?;
    if strip_int(&value) != strip_int(&claimed) && encode_qty(&value) != encode_qty(&claimed) {
        return Err(ProofError::ClaimMismatch("storage value"));
    }
    Ok(value)
}

pub fn verify_account_code(account: &VerifiedAccount, code: &[u8]) -> Result<(), ProofError> {
    if account.code_hash == EMPTY_CODE_HASH {
        if !code.is_empty() {
            return Err(ProofError::ClaimMismatch("empty code"));
        }
        return Ok(());
    }
    verify_bytecode(code, &account.code_hash).map_err(ProofError::from)
}
