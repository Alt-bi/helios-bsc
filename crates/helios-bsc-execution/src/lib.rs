//! Verified execution-layer reads (`eth_getProof` vs consensus `stateRoot`).

mod call;
mod mpt;
mod proof;
mod raw_tx;
mod rlp;

use helios_bsc_types::{HexAddress, HexHash, TrustClass};
use thiserror::Error;

pub use call::{
    eth_call_verified, eth_call_with_db, load_proven_account, CallBlock, CallError, CallTx, Miss,
    ProofDb, ProveAtSafe, CALL_GAS_CAP, MAX_CALL_ACCOUNTS, MAX_CALL_DATA, MAX_PROOF_ROUNDS,
    MAX_PROOF_STORAGE_KEYS,
};
pub use mpt::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
pub use proof::{
    encode_data32, encode_qty, pad32, qty_equal, retain_requested_storage, verify_account_code,
    verify_eth_get_proof, verify_storage_slot, EthAccountProof, ProofError, StorageProofEntry,
    VerifiedAccount, MAX_CODE_SIZE, MAX_PROOF_NODES, MAX_PROOF_NODE_BYTES,
};
pub use raw_tx::{validate_bsc_raw_tx, RawTxError, MAX_RAW_TX};

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("proof verification failed: {0}")]
    ProofFailed(String),
    #[error("upstream cannot prove at safe block (need hash/number eth_getProof)")]
    UpstreamProofCapabilityMissing,
}

#[derive(Debug, Clone)]
pub struct VerifiedBalance {
    pub address: HexAddress,
    pub balance_wei_hex: String,
    pub block_hash: HexHash,
    pub block_number: u64,
    pub trust: TrustClass,
}

pub fn verify_balance_proof(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof: &EthAccountProof,
    block_hash: HexHash,
    block_number: u64,
) -> Result<VerifiedBalance, ExecutionError> {
    let acc = verify_eth_get_proof(state_root, address, proof)?;
    Ok(VerifiedBalance {
        address: format!("0x{}", hex::encode(acc.address)),
        balance_wei_hex: encode_qty(&acc.balance_wei),
        block_hash,
        block_number,
        trust: TrustClass::Verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::verify_account_proof;
    use helios_bsc_types::{decode_hex, decode_hex_fixed};
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        address: String,
        state_root: String,
        proof: EthAccountProof,
    }

    fn load() -> (Fixture, Vec<u8>) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet/proof_wbnb_tip.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        let f: Fixture = serde_json::from_str(&raw).unwrap();
        (f, raw.into_bytes())
    }

    fn load_slot0() -> Fixture {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet/proof_wbnb_slot0.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn wbnb_tip_proof_verifies() {
        let (f, _) = load();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).unwrap();
        assert_eq!(acc.nonce, 1);
        assert_eq!(encode_qty(&acc.balance_wei), "0x17995dc3eaf5784b4a762");
        assert!(f.proof.account_proof.len() <= MAX_PROOF_NODES);
        let mut huge = f.proof.clone();
        huge.account_proof
            .resize(MAX_PROOF_NODES + 1, "0x80".into());
        assert!(matches!(
            verify_eth_get_proof(&root, &addr, &huge).unwrap_err(),
            ProofError::TooManyNodes
        ));
    }

    #[test]
    fn storage_proof_too_many_nodes_rejected() {
        let mut f = load_slot0();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        f.proof.storage_proof[0]
            .proof
            .resize(MAX_PROOF_NODES + 1, "0x80".into());
        assert!(matches!(
            verify_eth_get_proof(&root, &addr, &f.proof).unwrap_err(),
            ProofError::TooManyNodes
        ));
    }

    #[test]
    fn mutated_proof_node_rejected() {
        let (mut f, _) = load();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let mut node = decode_hex(&f.proof.account_proof[3]).unwrap();
        let i = node.len() / 2;
        node[i] ^= 0x01;
        f.proof.account_proof[3] = format!("0x{}", hex::encode(node));
        assert!(verify_eth_get_proof(&root, &addr, &f.proof).is_err());
    }

    #[test]
    fn empty_hashes_match_keccak() {
        use crate::mpt::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
        use helios_bsc_types::keccak256;
        assert_eq!(keccak256(&[]), EMPTY_CODE_HASH);
        assert_eq!(keccak256(&[0x80]), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn lying_bytecode_rejected() {
        use crate::mpt::{verify_bytecode, EMPTY_CODE_HASH};
        assert!(verify_bytecode(&[0x00], &EMPTY_CODE_HASH).is_err());
        assert!(verify_bytecode(&[], &EMPTY_CODE_HASH).is_ok());
    }

    #[test]
    fn wbnb_bytecode_matches_code_hash() {
        use crate::mpt::verify_bytecode;
        let (f, _) = load();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).unwrap();
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mainnet/wbnb_code.hex");
        let hex = std::fs::read_to_string(&path).unwrap();
        let code = decode_hex(hex.trim()).unwrap();
        verify_bytecode(&code, &acc.code_hash).unwrap();
        verify_account_code(&acc, &code).unwrap();
        assert!(verify_account_code(&acc, &[0x00]).is_err());
    }

    #[test]
    fn empty_storage_root_is_zero_slot() {
        use crate::mpt::{verify_storage_proof, EMPTY_TRIE_ROOT};
        let slot = [0u8; 32];
        let v = verify_storage_proof(&EMPTY_TRIE_ROOT, &slot, &[]).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn wbnb_slot0_storage_verifies() {
        let f = load_slot0();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).unwrap();
        let slot = [0u8; 32];
        let val = verify_storage_slot(&acc, &slot, &f.proof).unwrap();
        // Packed "Wrapped BNB" in slot 0.
        assert_eq!(
            encode_data32(&val),
            "0x5772617070656420424e42000000000000000000000000000000000000000016"
        );
        let mut extra = f.proof.clone();
        extra.storage_proof.push(StorageProofEntry {
            key: "0x1".into(),
            value: "0x1".into(),
            proof: vec![],
        });
        retain_requested_storage(&mut extra, &["0x0".into()]);
        assert_eq!(extra.storage_proof.len(), 1);
        retain_requested_storage(&mut extra, &[]);
        assert!(extra.storage_proof.is_empty());
    }

    #[test]
    fn lying_storage_value_rejected() {
        let mut f = load_slot0();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).unwrap();
        f.proof.storage_proof[0].value = "0x1".into();
        let slot = [0u8; 32];
        assert!(verify_storage_slot(&acc, &slot, &f.proof).is_err());
    }

    #[test]
    fn qty_equal_strips_leading_zeros() {
        assert!(qty_equal("0x1", "0x01"));
        assert!(qty_equal("0x0", "0x00"));
        assert!(qty_equal(
            "0x17995dc3eaf5784b4a762",
            "0x017995dc3eaf5784b4a762"
        ));
        assert!(!qty_equal("0x1", "0x2"));
        assert!(!qty_equal("nope", "0x1"));
    }

    #[test]
    fn lying_claimed_balance_rejected() {
        let (mut f, _) = load();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        f.proof.balance = "0x1".into();
        assert!(verify_eth_get_proof(&root, &addr, &f.proof).is_err());
    }

    #[test]
    fn absent_account_exclusion_is_empty() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet/proof_absent.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Cap {
            address: String,
            state_root: String,
            proof: EthAccountProof,
        }
        let f: Cap = serde_json::from_str(&raw).expect("absent json");
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).expect("exclusion");
        assert_eq!(acc.nonce, 0);
        assert!(acc.balance_wei.is_empty());
    }

    #[test]
    fn wrong_state_root_rejected() {
        let (f, _) = load();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let nodes: Vec<Vec<u8>> = f
            .proof
            .account_proof
            .iter()
            .map(|s| decode_hex(s).unwrap())
            .collect();
        let bad = [0x11u8; 32];
        assert!(verify_account_proof(&bad, &addr, &nodes).is_err());
    }
}
