//! Constrained verified `eth_call` (revm + iterative EIP-1186 proofs).
//!
//! Unproven accounts/slots are `CallError::Missing`, never a fake empty account
//! or zero slot. Does not proxy upstream `eth_call`.

use crate::mpt::EMPTY_CODE_HASH;
use crate::proof::{
    pad32, verify_account_code, verify_eth_get_proof, verify_storage_slot, EthAccountProof,
    ProofError, MAX_CODE_SIZE,
};
use crate::EMPTY_TRIE_ROOT;
use helios_bsc_types::BSC_MAINNET_CHAIN_ID;
use revm::primitives::{
    AccountInfo, Address, Bytecode, Bytes, EVMError, ExecutionResult, HaltReason, SpecId, TxKind,
    B256, KECCAK_EMPTY, U256,
};
use revm::{Database, Evm};
use std::collections::HashMap;
use thiserror::Error;

/// geth RPC gas cap used for `eth_call`.
pub const CALL_GAS_CAP: u64 = 50_000_000;
/// Max prove-and-retry rounds (initial `to` plus misses).
pub const MAX_PROOF_ROUNDS: u32 = 8;
/// Max distinct accounts loaded into [`ProofDb`] for one call.
pub const MAX_CALL_ACCOUNTS: usize = 32;
/// Max `tx.data` bytes.
pub const MAX_CALL_DATA: usize = 128 * 1024;
/// Max proven storage keys per account (DoS / upstream proof size).
pub const MAX_PROOF_STORAGE_KEYS: usize = 64;

#[derive(Debug, Clone)]
pub struct CallTx {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub data: Vec<u8>,
    pub value: [u8; 32],
    pub gas: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CallBlock {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub beneficiary: [u8; 20],
    pub gas_limit: u64,
    pub difficulty: [u8; 32],
    pub prevrandao: [u8; 32],
    pub basefee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Miss {
    Account([u8; 20]),
    Storage { address: [u8; 20], slot: [u8; 32] },
    BlockHash(u64),
}

#[derive(Debug, Error)]
pub enum CallError {
    #[error("missing proof for {0:?}")]
    Missing(Miss),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("execution reverted")]
    Revert(Vec<u8>),
    #[error("execution halt: {0}")]
    Halt(&'static str),
    #[error("proof or gas budget exceeded")]
    Budget,
    #[error("invalid call: {0}")]
    Invalid(&'static str),
}

/// Untrusted proof/code source at a verified Safe block (hash + number).
pub trait ProveAtSafe {
    fn get_proof(
        &self,
        address: &[u8; 20],
        slots: &[[u8; 32]],
        block_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<EthAccountProof, CallError>;

    fn get_code(
        &self,
        address: &[u8; 20],
        block_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<Vec<u8>, CallError>;
}

struct ProvenAccount {
    info: AccountInfo,
    storage_root: [u8; 32],
    storage: HashMap<U256, U256>,
}

/// Fail-closed revm database: only MPT-proven account/slot data.
#[derive(Default)]
pub struct ProofDb {
    accounts: HashMap<Address, ProvenAccount>,
    codes: HashMap<B256, Bytecode>,
}

impl ProofDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fully known account (tests / already-verified state). Does not MPT-check.
    pub fn insert_account(
        &mut self,
        address: [u8; 20],
        nonce: u64,
        balance: [u8; 32],
        storage_root: [u8; 32],
        code: &[u8],
    ) {
        let bytecode = if code.is_empty() {
            Bytecode::new()
        } else {
            Bytecode::new_raw(Bytes::copy_from_slice(code))
        };
        let code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            bytecode.hash_slow()
        };
        self.codes.insert(code_hash, bytecode.clone());
        let info = AccountInfo {
            balance: U256::from_be_bytes(balance),
            nonce,
            code_hash,
            code: Some(bytecode),
        };
        self.accounts.insert(
            Address::from(address),
            ProvenAccount {
                info,
                storage_root,
                storage: HashMap::new(),
            },
        );
    }

    /// Record a proven storage slot on an already-inserted account.
    pub fn insert_slot(&mut self, address: [u8; 20], slot: [u8; 32], value: [u8; 32]) {
        if let Some(acc) = self.accounts.get_mut(&Address::from(address)) {
            if acc.storage.len() >= MAX_PROOF_STORAGE_KEYS {
                return;
            }
            acc.storage
                .insert(U256::from_be_bytes(slot), U256::from_be_bytes(value));
        }
    }
}

fn is_precompile(address: Address) -> bool {
    let n = address.into_array();
    n[..19] == [0u8; 19] && (1..=0x0b).contains(&n[19])
}

fn addr_bytes(address: Address) -> [u8; 20] {
    address.into_array()
}

fn u256_to_slot(index: U256) -> [u8; 32] {
    index.to_be_bytes()
}

fn call_gas(tx: &CallTx, block: &CallBlock) -> u64 {
    let user = tx.gas.unwrap_or(CALL_GAS_CAP);
    user.min(CALL_GAS_CAP).min(block.gas_limit)
}

fn decode_slot_key(s: &str) -> Result<[u8; 32], ProofError> {
    let raw = helios_bsc_types::hexutil::strip_0x(s);
    let even = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let b = hex::decode(even).map_err(|e| ProofError::Json(e.to_string()))?;
    Ok(pad32(&b))
}

fn halt_str(reason: HaltReason) -> &'static str {
    match reason {
        HaltReason::OutOfGas(_) => "out of gas",
        HaltReason::OpcodeNotFound => "invalid opcode",
        HaltReason::InvalidFEOpcode => "invalid fe opcode",
        HaltReason::NotActivated => "not activated",
        HaltReason::StackUnderflow => "stack underflow",
        HaltReason::StackOverflow => "stack overflow",
        HaltReason::OutOfOffset => "out of offset",
        HaltReason::CreateCollision => "create collision",
        HaltReason::OverflowPayment => "overflow payment",
        HaltReason::PrecompileError => "precompile",
        HaltReason::NonceOverflow => "nonce overflow",
        HaltReason::CreateContractSizeLimit => "code size",
        HaltReason::CreateContractStartingWithEF => "code starts with 0xef",
        HaltReason::StateChangeDuringStaticCall => "state change",
        HaltReason::CallNotAllowedInsideStatic => "static call",
        HaltReason::OutOfFunds => "out of funds",
        HaltReason::CallTooDeep => "call too deep",
        _ => "halt",
    }
}

impl Database for ProofDb {
    type Error = CallError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(acc) = self.accounts.get(&address) {
            return Ok(Some(acc.info.clone()));
        }
        if is_precompile(address) {
            return Ok(Some(AccountInfo::default()));
        }
        Err(CallError::Missing(Miss::Account(addr_bytes(address))))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        self.codes
            .get(&code_hash)
            .cloned()
            .ok_or(CallError::Invalid("code hash"))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let acc = self
            .accounts
            .get(&address)
            .ok_or(CallError::Missing(Miss::Account(addr_bytes(address))))?;
        if let Some(v) = acc.storage.get(&index) {
            return Ok(*v);
        }
        if acc.storage_root == EMPTY_TRIE_ROOT {
            return Ok(U256::ZERO);
        }
        Err(CallError::Missing(Miss::Storage {
            address: addr_bytes(address),
            slot: u256_to_slot(index),
        }))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Err(CallError::Missing(Miss::BlockHash(number)))
    }
}

/// Verify `proof` (+ optional bytecode) against `state_root` and insert into `db`.
pub fn load_proven_account(
    db: &mut ProofDb,
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof: &EthAccountProof,
    code: &[u8],
) -> Result<(), CallError> {
    if code.len() > MAX_CODE_SIZE {
        return Err(CallError::Invalid("code too large"));
    }
    let verified = verify_eth_get_proof(state_root, address, proof)?;
    verify_account_code(&verified, code)?;

    let addr = Address::from(*address);
    let is_new = !db.accounts.contains_key(&addr);
    if is_new && db.accounts.len() >= MAX_CALL_ACCOUNTS {
        return Err(CallError::Budget);
    }

    let mut storage: HashMap<U256, U256> = db
        .accounts
        .get(&addr)
        .map(|a| a.storage.clone())
        .unwrap_or_default();

    if verified.storage_root != EMPTY_TRIE_ROOT {
        for entry in &proof.storage_proof {
            let key = decode_slot_key(&entry.key)?;
            let val = verify_storage_slot(&verified, &key, proof)?;
            if storage.len() >= MAX_PROOF_STORAGE_KEYS
                && !storage.contains_key(&U256::from_be_bytes(key))
            {
                return Err(CallError::Budget);
            }
            storage.insert(U256::from_be_bytes(key), U256::from_be_bytes(pad32(&val)));
        }
    }

    let bytecode = if code.is_empty() {
        Bytecode::new()
    } else {
        Bytecode::new_raw(Bytes::copy_from_slice(code))
    };
    let code_hash = B256::from(verified.code_hash);
    if code_hash != KECCAK_EMPTY {
        db.codes.insert(code_hash, bytecode.clone());
    }
    let info = AccountInfo {
        balance: U256::from_be_bytes(pad32(&verified.balance_wei)),
        nonce: verified.nonce,
        code_hash,
        code: Some(bytecode),
    };
    db.accounts.insert(
        addr,
        ProvenAccount {
            info,
            storage_root: verified.storage_root,
            storage,
        },
    );
    Ok(())
}

fn fetch_and_load<P: ProveAtSafe>(
    prover: &P,
    db: &mut ProofDb,
    block: &CallBlock,
    address: &[u8; 20],
    slots: &[[u8; 32]],
) -> Result<(), CallError> {
    if slots.len() > MAX_PROOF_STORAGE_KEYS {
        return Err(CallError::Budget);
    }
    let proof = prover.get_proof(address, slots, &block.hash, block.number)?;
    let verified = verify_eth_get_proof(&block.state_root, address, &proof)?;
    let code = if verified.code_hash == EMPTY_CODE_HASH {
        Vec::new()
    } else {
        prover.get_code(address, &block.hash, block.number)?
    };
    load_proven_account(db, &block.state_root, address, &proof, &code)
}

/// Run `eth_call` against an already-populated [`ProofDb`] (no proof fetch).
pub fn eth_call_with_db(
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
) -> Result<Vec<u8>, CallError> {
    if tx.data.len() > MAX_CALL_DATA {
        return Err(CallError::Invalid("calldata too large"));
    }
    let gas = call_gas(tx, block);
    let mut evm = Evm::builder()
        .with_db(&mut *db)
        .with_spec_id(SpecId::CANCUN)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = BSC_MAINNET_CHAIN_ID;
            cfg.disable_base_fee = true;
            cfg.disable_eip3607 = true;
        })
        .modify_block_env(|b| {
            b.number = U256::from(block.number);
            b.coinbase = Address::from(block.beneficiary);
            b.timestamp = U256::from(block.timestamp);
            b.gas_limit = U256::from(block.gas_limit);
            b.basefee = U256::from(block.basefee);
            b.difficulty = U256::from_be_bytes(block.difficulty);
            b.prevrandao = Some(B256::from(block.prevrandao));
        })
        .modify_tx_env(|t| {
            t.caller = Address::from(tx.from);
            t.gas_limit = gas;
            t.gas_price = U256::ZERO;
            t.transact_to = TxKind::Call(Address::from(tx.to));
            t.value = U256::from_be_bytes(tx.value);
            t.data = Bytes::copy_from_slice(&tx.data);
            t.nonce = None;
            t.chain_id = Some(BSC_MAINNET_CHAIN_ID);
        })
        .build();

    match evm.transact() {
        Ok(res) => match res.result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Err(CallError::Revert(output.to_vec())),
            ExecutionResult::Halt { reason, .. } => Err(CallError::Halt(halt_str(reason))),
        },
        Err(EVMError::Database(e)) => Err(e),
        Err(EVMError::Transaction(_)) => Err(CallError::Invalid("transaction")),
        Err(EVMError::Header(_)) => Err(CallError::Invalid("header")),
        Err(EVMError::Custom(_)) => Err(CallError::Halt("custom")),
        Err(EVMError::Precompile(_)) => Err(CallError::Halt("precompile")),
    }
}

/// Verified `eth_call`: iterative proofs at `block.state_root`, then revm.
pub fn eth_call_verified<P: ProveAtSafe>(
    prover: &P,
    block: &CallBlock,
    tx: &CallTx,
) -> Result<Vec<u8>, CallError> {
    if tx.data.len() > MAX_CALL_DATA {
        return Err(CallError::Invalid("calldata too large"));
    }

    let mut db = ProofDb::new();
    let mut rounds = 0u32;

    if !is_precompile(Address::from(tx.to)) {
        fetch_and_load(prover, &mut db, block, &tx.to, &[])?;
        rounds += 1;
    }

    loop {
        match eth_call_with_db(&mut db, block, tx) {
            Ok(out) => return Ok(out),
            Err(CallError::Missing(Miss::BlockHash(n))) => {
                return Err(CallError::Missing(Miss::BlockHash(n)));
            }
            Err(CallError::Missing(miss)) => {
                if rounds >= MAX_PROOF_ROUNDS {
                    return Err(CallError::Budget);
                }
                rounds += 1;
                match miss {
                    Miss::Account(address) => {
                        fetch_and_load(prover, &mut db, block, &address, &[])?;
                    }
                    Miss::Storage { address, slot } => {
                        fetch_and_load(prover, &mut db, block, &address, &[slot])?;
                    }
                    Miss::BlockHash(_) => unreachable!(),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_data32, encode_qty, verify_eth_get_proof};
    use helios_bsc_types::{decode_hex, decode_hex_fixed};
    use serde::Deserialize;
    use std::path::PathBuf;

    // PUSH1 0x2a; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN
    const RETURN_42_FULL: [u8; 10] = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    // PUSH1 0x00; SLOAD; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN
    const SLOAD0_RETURN: [u8; 11] = [
        0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ];

    fn sample_block(state_root: [u8; 32]) -> CallBlock {
        CallBlock {
            number: 1,
            hash: [2u8; 32],
            state_root,
            timestamp: 1,
            beneficiary: [0u8; 20],
            gas_limit: CALL_GAS_CAP,
            difficulty: [0u8; 32],
            prevrandao: [0u8; 32],
            basefee: 0,
        }
    }

    fn call_tx(from: [u8; 20], to: [u8; 20], data: Vec<u8>) -> CallTx {
        CallTx {
            from,
            to,
            data,
            value: [0u8; 32],
            gas: Some(100_000),
        }
    }

    fn insert_eoa(db: &mut ProofDb, address: [u8; 20]) {
        db.insert_account(address, 0, [0u8; 32], EMPTY_TRIE_ROOT, &[]);
    }

    #[test]
    fn revm_returns_constant_from_inserted_account() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &RETURN_42_FULL);
        let out = eth_call_with_db(
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
        )
        .expect("call");
        let mut want = [0u8; 32];
        want[31] = 0x2a;
        assert_eq!(out, want);
    }

    #[test]
    fn unproven_sload_is_missing_not_zero() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], [0x01u8; 32], &SLOAD0_RETURN);
        let err = eth_call_with_db(
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
        )
        .unwrap_err();
        match err {
            CallError::Missing(Miss::Storage { address, slot }) => {
                assert_eq!(address, to);
                assert_eq!(slot, [0u8; 32]);
            }
            other => panic!("expected Missing storage, got {other:?}"),
        }
    }

    #[test]
    fn empty_trie_sload_is_zero() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &SLOAD0_RETURN);
        let out = eth_call_with_db(
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
        )
        .expect("sload 0");
        assert_eq!(out, vec![0u8; 32]);
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        address: String,
        state_root: String,
        proof: EthAccountProof,
    }

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mainnet")
    }

    fn load_tip() -> Fixture {
        let raw = std::fs::read_to_string(fixtures_dir().join("proof_wbnb_tip.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn load_slot0() -> Fixture {
        let raw = std::fs::read_to_string(fixtures_dir().join("proof_wbnb_slot0.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn load_wbnb_code() -> Vec<u8> {
        let hex = std::fs::read_to_string(fixtures_dir().join("wbnb_code.hex")).unwrap();
        decode_hex(hex.trim()).unwrap()
    }

    struct StaticProver {
        address: [u8; 20],
        proof: EthAccountProof,
        code: Vec<u8>,
        allow_slots: bool,
    }

    impl ProveAtSafe for StaticProver {
        fn get_proof(
            &self,
            address: &[u8; 20],
            slots: &[[u8; 32]],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<EthAccountProof, CallError> {
            if address != &self.address {
                return Err(CallError::Missing(Miss::Account(*address)));
            }
            if !slots.is_empty() && !self.allow_slots {
                return Err(CallError::Missing(Miss::Storage {
                    address: *address,
                    slot: slots[0],
                }));
            }
            let mut proof = self.proof.clone();
            if slots.is_empty() {
                proof.storage_proof.clear();
            }
            Ok(proof)
        }

        fn get_code(
            &self,
            address: &[u8; 20],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<Vec<u8>, CallError> {
            if address != &self.address {
                return Err(CallError::Missing(Miss::Account(*address)));
            }
            Ok(self.code.clone())
        }
    }

    #[test]
    fn wbnb_load_proven_account_ok() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let code = load_wbnb_code();
        let mut db = ProofDb::new();
        load_proven_account(&mut db, &root, &addr, &f.proof, &code).expect("load");
        let info = db
            .accounts
            .get(&Address::from(addr))
            .expect("inserted")
            .info
            .clone();
        assert_eq!(info.nonce, 1);
        assert_eq!(
            encode_qty(&pad32(&info.balance.to_be_bytes::<32>())),
            "0x17995dc3eaf5784b4a762"
        );

        let mut bad = f.proof.clone();
        let mut node = decode_hex(&bad.account_proof[3]).unwrap();
        let i = node.len() / 2;
        node[i] ^= 0x01;
        bad.account_proof[3] = format!("0x{}", hex::encode(node));
        let mut db2 = ProofDb::new();
        assert!(load_proven_account(&mut db2, &root, &addr, &bad, &code).is_err());
    }

    #[test]
    fn wbnb_totalsupply_eth_call() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let acc = verify_eth_get_proof(&root, &addr, &f.proof).unwrap();
        let prover = StaticProver {
            address: addr,
            proof: f.proof.clone(),
            code: load_wbnb_code(),
            allow_slots: false,
        };
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let data = decode_hex("0x18160ddd").unwrap();
        let out = eth_call_verified(&prover, &block, &call_tx(addr, addr, data)).expect("call");
        assert_eq!(out.len(), 32);
        assert_eq!(encode_data32(&acc.balance_wei), encode_data32(&out));
        assert_eq!(encode_qty(&out), "0x17995dc3eaf5784b4a762");
    }

    #[test]
    fn wbnb_name_unproven_slot_fail_closed() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let prover = StaticProver {
            address: addr,
            proof: f.proof,
            code: load_wbnb_code(),
            allow_slots: false,
        };
        let data = decode_hex("0x06fdde03").unwrap();
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let err = eth_call_verified(&prover, &block, &call_tx(addr, addr, data)).unwrap_err();
        match err {
            CallError::Missing(_) | CallError::Proof(_) => {}
            CallError::Revert(out) => {
                panic!(
                    "unproven name must not revert with output 0x{}",
                    hex::encode(out)
                )
            }
            other => panic!("expected Missing/Proof, got {other:?}"),
        }
    }

    #[test]
    fn wbnb_name_with_slot0() {
        let f = load_slot0();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let prover = StaticProver {
            address: addr,
            proof: f.proof,
            code: load_wbnb_code(),
            allow_slots: true,
        };
        let data = decode_hex("0x06fdde03").unwrap();
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let out = eth_call_verified(&prover, &block, &call_tx(addr, addr, data)).expect("name");
        assert!(
            out.windows(b"Wrapped BNB".len())
                .any(|w| w == b"Wrapped BNB"),
            "ABI name missing Wrapped BNB: 0x{}",
            hex::encode(&out)
        );
    }
}
