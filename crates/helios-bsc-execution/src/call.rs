//! Constrained verified `eth_call` / best-effort `eth_estimateGas`.
//!
//! Unproven accounts/slots are `CallError::Missing`, never a fake empty account
//! or zero slot. `BLOCKHASH` uses locally verified headers only: in-window
//! unknown is `Missing`, never a fake zero. Does not proxy upstream `eth_call`
//! or `eth_estimateGas`. Estimate is a geth/reth-style binary search (not a
//! single `gas_used`).

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
/// Max miss-retry proof fetches. Seed of `to`/`from`/coinbase/`accessList` is not charged.
pub const MAX_PROOF_ROUNDS: u32 = 8;
/// Max distinct accounts loaded into [`ProofDb`] for one call.
pub const MAX_CALL_ACCOUNTS: usize = 32;
/// Max `tx.data` bytes.
pub const MAX_CALL_DATA: usize = 128 * 1024;
/// Max proven storage keys per account (DoS / upstream proof size).
pub const MAX_PROOF_STORAGE_KEYS: usize = 64;
/// Intrinsic gas for a simple transaction (estimate floor / cap check).
pub const TX_GAS: u64 = 21_000;
/// Binary-search iteration cap for [`eth_estimate_gas_verified`].
pub const MAX_ESTIMATE_ITERS: u32 = 64;
/// Yellow-paper / geth `BLOCKHASH` lookback.
const BLOCKHASH_WINDOW: u64 = 256;

#[derive(Debug, Clone)]
pub struct CallTx {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub data: Vec<u8>,
    pub value: [u8; 32],
    pub gas: Option<u64>,
    /// EIP-2930 access list: prefetch these accounts/slots as seed (not miss-retries).
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
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
    /// Locally verified header hashes at `number` (cap 256). Never invent zeros.
    pub historical_hashes: Vec<(u64, [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Miss {
    Account([u8; 20]),
    Storage {
        address: [u8; 20],
        slot: [u8; 32],
    },
    BlockHash(u64),
    /// Bytecode for this `keccak256(code)` was never loaded.
    CodeHash([u8; 32]),
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
    block_hashes: HashMap<u64, B256>,
    /// Executing block number (`BLOCKHASH` protocol window).
    block_number: u64,
}

impl ProofDb {
    pub fn new() -> Self {
        Self::default()
    }

    fn seed_block_hashes(&mut self, block: &CallBlock) {
        self.block_number = block.number;
        self.block_hashes.clear();
        for (n, hash) in block
            .historical_hashes
            .iter()
            .take(BLOCKHASH_WINDOW as usize)
        {
            self.block_hashes.insert(*n, B256::from(*hash));
        }
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

/// The slot a `storageProof[].key` denotes. Over-long keys are refused, not folded:
/// `pad32` keeps the **low** 32 bytes, so a 33-byte key would alias a real slot and
/// seed the revm state map under a slot the caller never asked about.
fn decode_slot_key(s: &str) -> Result<[u8; 32], ProofError> {
    let raw = helios_bsc_types::hexutil::strip_0x(s);
    let even = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let b = hex::decode(even).map_err(|e| ProofError::Json(e.to_string()))?;
    if b.len() > 32 {
        return Err(ProofError::ClaimMismatch(
            "storageProof key wider than a slot",
        ));
    }
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
            .ok_or(CallError::Missing(Miss::CodeHash(code_hash.0)))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let Some(acc) = self.accounts.get(&address) else {
            // Include the slot so the next proof fetch covers account + key.
            return Err(CallError::Missing(Miss::Storage {
                address: addr_bytes(address),
                slot: u256_to_slot(index),
            }));
        };
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
        // Yellow-paper / geth: current and older-than-256 are protocol zeros.
        if number >= self.block_number
            || number.saturating_add(BLOCKHASH_WINDOW) < self.block_number
        {
            return Ok(B256::ZERO);
        }
        match self.block_hashes.get(&number) {
            Some(h) => Ok(*h),
            None => Err(CallError::Missing(Miss::BlockHash(number))),
        }
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

/// Execute `tx` at `gas` against `db`. Does not fetch proofs.
fn transact_call(
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
    gas: u64,
) -> Result<ExecutionResult, CallError> {
    db.seed_block_hashes(block);
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
        Ok(res) => Ok(res.result),
        Err(EVMError::Database(e)) => Err(e),
        Err(EVMError::Transaction(_)) => Err(CallError::Invalid("transaction")),
        Err(EVMError::Header(_)) => Err(CallError::Invalid("header")),
        Err(EVMError::Custom(_)) => Err(CallError::Halt("custom")),
        Err(EVMError::Precompile(_)) => Err(CallError::Halt("precompile")),
    }
}

fn execution_output(res: ExecutionResult) -> Result<Vec<u8>, CallError> {
    match res {
        ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
        ExecutionResult::Revert { output, .. } => Err(CallError::Revert(output.to_vec())),
        ExecutionResult::Halt { reason, .. } => Err(CallError::Halt(halt_str(reason))),
    }
}

fn seed_call_accounts<P: ProveAtSafe>(
    prover: &P,
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
) -> Result<(), CallError> {
    access_list_within_caps(tx)?;
    let mut seen: Vec<[u8; 20]> = Vec::with_capacity(3);
    for address in [tx.to, tx.from, block.beneficiary] {
        if is_precompile(Address::from(address)) {
            continue;
        }
        if seen.iter().any(|a| a == &address) {
            continue;
        }
        seen.push(address);
        fetch_and_load(prover, db, block, &address, &[])?;
    }
    seed_access_list(prover, db, block, tx)
}

/// Access-list size caps (parse uses the same numbers as [`CallError::Invalid`]).
fn access_list_within_caps(tx: &CallTx) -> Result<(), CallError> {
    if tx.access_list.len() > MAX_CALL_ACCOUNTS {
        return Err(CallError::Invalid("accessList too large"));
    }
    let mut total_keys = 0usize;
    for (_address, slots) in &tx.access_list {
        if slots.len() > MAX_PROOF_STORAGE_KEYS {
            return Err(CallError::Invalid("accessList too large"));
        }
        total_keys = total_keys.saturating_add(slots.len());
        if total_keys > MAX_PROOF_STORAGE_KEYS {
            return Err(CallError::Invalid("accessList too large"));
        }
    }
    Ok(())
}

/// Prefetch EIP-2930 `accessList` into [`ProofDb`]. Seed — does not consume miss rounds.
/// Exceeding remaining ProofDb caps during load is [`CallError::Budget`].
fn seed_access_list<P: ProveAtSafe>(
    prover: &P,
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
) -> Result<(), CallError> {
    if tx.access_list.is_empty() {
        return Ok(());
    }
    for (address, slots) in &tx.access_list {
        if is_precompile(Address::from(*address)) {
            continue;
        }
        fetch_and_load(prover, db, block, address, slots)?;
    }
    Ok(())
}

fn slot_is_proven(db: &ProofDb, address: &[u8; 20], slot: &[u8; 32]) -> bool {
    match db.accounts.get(&Address::from(*address)) {
        None => false,
        Some(acc) => {
            acc.storage_root == EMPTY_TRIE_ROOT
                || acc.storage.contains_key(&U256::from_be_bytes(*slot))
        }
    }
}

/// Fetch proofs for Missing account/slot and retry the same `gas`. One `rounds`
/// counter for the whole call/estimate (not per mid). An omitted storage key is
/// `Missing` immediately — do not spin until [`MAX_PROOF_ROUNDS`].
fn transact_call_proven<P: ProveAtSafe>(
    prover: &P,
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
    gas: u64,
    rounds: &mut u32,
) -> Result<ExecutionResult, CallError> {
    loop {
        match transact_call(db, block, tx, gas) {
            Ok(res) => return Ok(res),
            Err(CallError::Missing(Miss::BlockHash(n))) => {
                return Err(CallError::Missing(Miss::BlockHash(n)));
            }
            Err(CallError::Missing(Miss::CodeHash(h))) => {
                return Err(CallError::Missing(Miss::CodeHash(h)));
            }
            Err(CallError::Missing(miss)) => {
                if *rounds >= MAX_PROOF_ROUNDS {
                    return Err(CallError::Budget);
                }
                *rounds += 1;
                match miss {
                    Miss::Account(address) => {
                        fetch_and_load(prover, db, block, &address, &[])?;
                    }
                    Miss::Storage { address, slot } => {
                        fetch_and_load(prover, db, block, &address, &[slot])?;
                        if !slot_is_proven(db, &address, &slot) {
                            return Err(CallError::Missing(Miss::Storage { address, slot }));
                        }
                    }
                    Miss::BlockHash(_) | Miss::CodeHash(_) => unreachable!(),
                }
            }
            Err(e) => return Err(e),
        }
    }
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
    db.seed_block_hashes(block);
    execution_output(transact_call(db, block, tx, call_gas(tx, block))?)
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
    db.seed_block_hashes(block);
    let mut rounds = 0u32;
    seed_call_accounts(prover, &mut db, block, tx)?;
    execution_output(transact_call_proven(
        prover,
        &mut db,
        block,
        tx,
        call_gas(tx, block),
        &mut rounds,
    )?)
}

fn estimate_gas_search<P: ProveAtSafe>(
    prover: &P,
    db: &mut ProofDb,
    block: &CallBlock,
    tx: &CallTx,
    rounds: &mut u32,
) -> Result<u64, CallError> {
    let hi_cap = call_gas(tx, block);
    if hi_cap < TX_GAS {
        return Err(CallError::Halt("out of gas"));
    }

    let cap_res = transact_call_proven(prover, db, block, tx, hi_cap, rounds)?;
    let mut lo = match cap_res {
        ExecutionResult::Success { gas_used, .. } => gas_used.saturating_sub(1),
        ExecutionResult::Revert { output, .. } => {
            return Err(CallError::Revert(output.to_vec()));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(CallError::Halt(halt_str(reason)));
        }
    };

    let mut hi = hi_cap;
    let mut iters = 0u32;
    while lo.saturating_add(1) < hi && iters < MAX_ESTIMATE_ITERS {
        iters += 1;
        let mid = lo + (hi - lo) / 2;
        match transact_call_proven(prover, db, block, tx, mid, rounds) {
            Ok(ExecutionResult::Success { gas_used, .. }) => {
                hi = mid;
                let hint = gas_used.saturating_sub(1);
                if hint > lo && hint < hi {
                    lo = hint;
                }
            }
            // After cap-success, mid revert/halt/intrinsic = need more gas (geth/reth).
            Ok(ExecutionResult::Revert { .. })
            | Ok(ExecutionResult::Halt { .. })
            | Err(CallError::Invalid("transaction"))
            | Err(CallError::Halt(_)) => {
                lo = mid;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(hi)
}

/// Proof-backed best-effort `eth_estimateGas` (binary search, not `gas_used`).
pub fn eth_estimate_gas_verified<P: ProveAtSafe>(
    prover: &P,
    block: &CallBlock,
    tx: &CallTx,
) -> Result<u64, CallError> {
    if tx.data.len() > MAX_CALL_DATA {
        return Err(CallError::Invalid("calldata too large"));
    }

    let mut db = ProofDb::new();
    db.seed_block_hashes(block);
    let mut rounds = 0u32;
    seed_call_accounts(prover, &mut db, block, tx)?;
    estimate_gas_search(prover, &mut db, block, tx, &mut rounds)
}

#[cfg(test)]
mod tests {
    /// `pad32` keeps the **low** 32 bytes, so a 33-byte `storageProof[].key` would fold
    /// onto a real slot and seed the revm state map under a slot nobody asked about.
    #[test]
    fn over_long_slot_key_refused_not_folded() {
        use super::decode_slot_key;
        assert_eq!(decode_slot_key("0x01").unwrap()[31], 1);
        let word = format!("0x{}", "ab".repeat(32));
        assert!(decode_slot_key(&word).is_ok());
        // Same low 32 bytes, one byte wider.
        let wide = format!("0xff{}", "ab".repeat(32));
        assert!(decode_slot_key(&wide).is_err());
    }

    use super::*;
    use crate::{encode_data32, encode_qty, verify_eth_get_proof};
    use helios_bsc_types::{decode_hex, decode_hex_fixed, keccak256};
    use serde::Deserialize;
    use std::path::PathBuf;

    // PUSH1 0x2a; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN
    const RETURN_42_FULL: [u8; 10] = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    // PUSH1 0x00; SLOAD; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN
    const SLOAD0_RETURN: [u8; 11] = [
        0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ];
    // PUSH1 0x00; PUSH1 0x00; REVERT
    const ALWAYS_REVERT: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];

    struct DenyProver;

    impl ProveAtSafe for DenyProver {
        fn get_proof(
            &self,
            address: &[u8; 20],
            slots: &[[u8; 32]],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<EthAccountProof, CallError> {
            if slots.is_empty() {
                Err(CallError::Missing(Miss::Account(*address)))
            } else {
                Err(CallError::Missing(Miss::Storage {
                    address: *address,
                    slot: slots[0],
                }))
            }
        }

        fn get_code(
            &self,
            address: &[u8; 20],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<Vec<u8>, CallError> {
            Err(CallError::Missing(Miss::Account(*address)))
        }
    }

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
            historical_hashes: Vec::new(),
        }
    }

    // PUSH1 n; BLOCKHASH; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
    fn blockhash_return(n: u8) -> [u8; 11] {
        [
            0x60, n, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ]
    }

    fn call_blockhash(db: &mut ProofDb, block: &CallBlock, n: u8) -> Result<Vec<u8>, CallError> {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        insert_eoa(db, from);
        insert_eoa(db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &blockhash_return(n));
        eth_call_with_db(db, block, &call_tx(from, to, vec![]))
    }

    fn call_tx(from: [u8; 20], to: [u8; 20], data: Vec<u8>) -> CallTx {
        CallTx {
            from,
            to,
            data,
            value: [0u8; 32],
            gas: Some(100_000),
            access_list: Vec::new(),
        }
    }

    fn insert_eoa(db: &mut ProofDb, address: [u8; 20]) {
        db.insert_account(address, 0, [0u8; 32], EMPTY_TRIE_ROOT, &[]);
    }

    fn rlp_len_be(len: usize) -> Vec<u8> {
        let be = (len as u64).to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        be[start..].to_vec()
    }

    fn rlp_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        if data.len() <= 55 {
            let mut o = Vec::with_capacity(1 + data.len());
            o.push(0x80 + data.len() as u8);
            o.extend_from_slice(data);
            o
        } else {
            let lenb = rlp_len_be(data.len());
            let mut o = Vec::with_capacity(1 + lenb.len() + data.len());
            o.push(0xb7 + lenb.len() as u8);
            o.extend_from_slice(&lenb);
            o.extend_from_slice(data);
            o
        }
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for i in items {
            payload.extend_from_slice(i);
        }
        if payload.len() <= 55 {
            let mut o = vec![0xc0 + payload.len() as u8];
            o.extend_from_slice(&payload);
            o
        } else {
            let lenb = rlp_len_be(payload.len());
            let mut o = Vec::with_capacity(1 + lenb.len() + payload.len());
            o.push(0xf7 + lenb.len() as u8);
            o.extend_from_slice(&lenb);
            o.extend_from_slice(&payload);
            o
        }
    }

    /// Single-leaf account trie: `address` is present; any other address is exclusion.
    fn single_leaf_account(
        address: [u8; 20],
        code: &[u8],
        storage_root: [u8; 32],
    ) -> ([u8; 32], EthAccountProof) {
        let code_hash = keccak256(code);
        let account = rlp_list(&[
            rlp_bytes(&[1]),
            rlp_bytes(&[]),
            rlp_bytes(&storage_root),
            rlp_bytes(&code_hash),
        ]);
        let mut hp = vec![0x20];
        hp.extend_from_slice(&keccak256(&address));
        let leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account)]);
        let state_root = keccak256(&leaf);
        let proof = EthAccountProof {
            address: format!("0x{}", hex::encode(address)),
            account_proof: vec![format!("0x{}", hex::encode(leaf))],
            balance: "0x0".into(),
            code_hash: format!("0x{}", hex::encode(code_hash)),
            nonce: "0x1".into(),
            storage_hash: format!("0x{}", hex::encode(storage_root)),
            storage_proof: vec![],
        };
        (state_root, proof)
    }

    /// Serves a single-leaf proof for `to` (inclusion) and exclusion for anyone else.
    struct CountingProver {
        to: [u8; 20],
        proof: EthAccountProof,
        code: Vec<u8>,
        fetches: std::cell::Cell<u32>,
    }

    impl ProveAtSafe for CountingProver {
        fn get_proof(
            &self,
            address: &[u8; 20],
            _slots: &[[u8; 32]],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<EthAccountProof, CallError> {
            self.fetches.set(self.fetches.get() + 1);
            if address == &self.to {
                let mut proof = self.proof.clone();
                proof.storage_proof.clear();
                return Ok(proof);
            }
            Ok(EthAccountProof {
                address: format!("0x{}", hex::encode(address)),
                account_proof: self.proof.account_proof.clone(),
                balance: "0x0".into(),
                code_hash: format!("0x{}", hex::encode([0u8; 32])),
                nonce: "0x0".into(),
                storage_hash: format!("0x{}", hex::encode([0u8; 32])),
                storage_proof: vec![],
            })
        }

        fn get_code(
            &self,
            address: &[u8; 20],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<Vec<u8>, CallError> {
            if address == &self.to {
                Ok(self.code.clone())
            } else {
                Err(CallError::Missing(Miss::Account(*address)))
            }
        }
    }

    fn miss_addr(i: u8) -> [u8; 20] {
        let mut a = [0xeeu8; 20];
        a[19] = i;
        a
    }

    /// CALL `n` distinct non-precompile addresses (each a miss after seed).
    fn call_n_addrs(n: u8) -> Vec<u8> {
        let mut code = Vec::new();
        for i in 0..n {
            code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00]);
            code.push(0x73);
            code.extend_from_slice(&miss_addr(i));
            code.extend_from_slice(&[0x61, 0x20, 0x00]);
            code.push(0xf1);
            code.push(0x50);
        }
        code.push(0x00);
        code
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
    fn unknown_code_hash_is_missing_not_invalid() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &RETURN_42_FULL);
        let code_hash = db.accounts.get(&Address::from(to)).unwrap().info.code_hash;
        db.codes.remove(&code_hash);
        if let Some(acc) = db.accounts.get_mut(&Address::from(to)) {
            acc.info.code = None;
        }
        let err = eth_call_with_db(
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
        )
        .unwrap_err();
        match err {
            CallError::Missing(Miss::CodeHash(h)) => assert_eq!(h, code_hash.0),
            CallError::Invalid(_) => panic!("code hash miss must not be Invalid"),
            other => panic!("expected Missing(CodeHash), got {other:?}"),
        }
    }

    #[test]
    fn seed_three_then_storage_miss_is_not_budget() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let beneficiary = [0x33u8; 20];
        let (root, proof) = single_leaf_account(to, &SLOAD0_RETURN, [0x01u8; 32]);
        let prover = CountingProver {
            to,
            proof,
            code: SLOAD0_RETURN.to_vec(),
            fetches: std::cell::Cell::new(0),
        };
        let mut block = sample_block(root);
        block.beneficiary = beneficiary;
        let err = eth_call_verified(&prover, &block, &call_tx(from, to, vec![])).unwrap_err();
        match err {
            CallError::Missing(Miss::Storage { address, slot }) => {
                assert_eq!(address, to);
                assert_eq!(slot, [0u8; 32]);
            }
            CallError::Budget => panic!("seed must not consume miss budget"),
            other => panic!("expected Missing storage, got {other:?}"),
        }
        assert_eq!(
            prover.fetches.get(),
            4,
            "spy must see 3 seed fetches + 1 storage miss, not Budget"
        );
    }

    #[test]
    fn seed_does_not_reduce_miss_retry_budget() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let beneficiary = [0x33u8; 20];
        let code = call_n_addrs(MAX_PROOF_ROUNDS as u8);
        let (root, proof) = single_leaf_account(to, &code, EMPTY_TRIE_ROOT);
        let prover = CountingProver {
            to,
            proof,
            code,
            fetches: std::cell::Cell::new(0),
        };
        let mut block = sample_block(root);
        block.beneficiary = beneficiary;
        let tx = CallTx {
            from,
            to,
            data: vec![],
            value: [0u8; 32],
            gas: Some(1_000_000),
            access_list: Vec::new(),
        };
        eth_call_verified(&prover, &block, &tx).expect("8 miss-retries after seed");
        assert_eq!(
            prover.fetches.get(),
            3 + MAX_PROOF_ROUNDS,
            "3 seed + 8 miss fetches"
        );

        let code9 = call_n_addrs(MAX_PROOF_ROUNDS as u8 + 1);
        let (root9, proof9) = single_leaf_account(to, &code9, EMPTY_TRIE_ROOT);
        let prover9 = CountingProver {
            to,
            proof: proof9,
            code: code9,
            fetches: std::cell::Cell::new(0),
        };
        let mut block9 = sample_block(root9);
        block9.beneficiary = beneficiary;
        let err = eth_call_verified(&prover9, &block9, &tx).unwrap_err();
        match err {
            CallError::Budget => {}
            other => panic!("9th miss-retry must be Budget, got {other:?}"),
        }
        assert_eq!(
            prover9.fetches.get(),
            3 + MAX_PROOF_ROUNDS,
            "9th miss is Budget without another fetch"
        );
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

    #[test]
    fn estimate_gas_constant_return() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &RETURN_42_FULL);
        let block = sample_block([0u8; 32]);
        let tx = call_tx(from, to, vec![]);
        let mut rounds = 0;
        let gas =
            estimate_gas_search(&DenyProver, &mut db, &block, &tx, &mut rounds).expect("estimate");
        assert!(gas >= TX_GAS, "{gas}");
        assert!(gas <= CALL_GAS_CAP, "{gas}");
        let mut funded = tx.clone();
        funded.gas = Some(gas);
        eth_call_with_db(&mut db, &block, &funded).expect("call at estimate");
        if gas > TX_GAS {
            let mut under = tx.clone();
            under.gas = Some(gas - 1);
            let err = eth_call_with_db(&mut db, &block, &under).unwrap_err();
            match err {
                CallError::Halt(_) | CallError::Revert(_) | CallError::Invalid(_) => {}
                other => panic!("expected Halt/Revert/Invalid at estimate-1, got {other:?}"),
            }
        }
    }

    #[test]
    fn estimate_gas_unproven_sload_is_missing() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], [0x01u8; 32], &SLOAD0_RETURN);
        let err = estimate_gas_search(
            &DenyProver,
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
            &mut 0,
        )
        .unwrap_err();
        match err {
            CallError::Missing(_) => {}
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn estimate_gas_empty_trie_sload_ok() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &SLOAD0_RETURN);
        let gas = estimate_gas_search(
            &DenyProver,
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
            &mut 0,
        )
        .expect("estimate");
        assert!(gas >= TX_GAS, "{gas}");
        assert!(gas <= CALL_GAS_CAP, "{gas}");
    }

    #[test]
    fn estimate_gas_always_revert_is_revert() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let mut db = ProofDb::new();
        insert_eoa(&mut db, from);
        insert_eoa(&mut db, [0u8; 20]);
        db.insert_account(to, 1, [0u8; 32], EMPTY_TRIE_ROOT, &ALWAYS_REVERT);
        let err = estimate_gas_search(
            &DenyProver,
            &mut db,
            &sample_block([0u8; 32]),
            &call_tx(from, to, vec![]),
            &mut 0,
        )
        .unwrap_err();
        match err {
            CallError::Revert(_) => {}
            other => panic!("expected Revert, not a gas qty, got {other:?}"),
        }
    }

    #[test]
    fn blockhash_parent_with_inserted_hash() {
        let parent = [0xabu8; 32];
        let mut block = sample_block([0u8; 32]);
        block.number = 10;
        block.historical_hashes = vec![(9, parent)];
        let mut db = ProofDb::new();
        let out = call_blockhash(&mut db, &block, 9).expect("blockhash");
        assert_eq!(out, parent);
    }

    #[test]
    fn blockhash_in_window_absent_is_missing_not_zero() {
        let mut block = sample_block([0u8; 32]);
        block.number = 10;
        let mut db = ProofDb::new();
        let err = call_blockhash(&mut db, &block, 9).unwrap_err();
        match err {
            CallError::Missing(Miss::BlockHash(n)) => assert_eq!(n, 9),
            other => panic!("expected Missing(BlockHash(9)), got {other:?}"),
        }
    }

    #[test]
    fn blockhash_current_or_future_is_protocol_zero() {
        let mut block = sample_block([0u8; 32]);
        block.number = 10;
        block.historical_hashes = vec![(10, [0xffu8; 32])];
        let mut db = ProofDb::new();
        let out = call_blockhash(&mut db, &block, 10).expect("current");
        assert_eq!(out, vec![0u8; 32]);
        let mut db = ProofDb::new();
        let out = call_blockhash(&mut db, &block, 11).expect("future");
        assert_eq!(out, vec![0u8; 32]);
    }

    #[test]
    fn blockhash_older_than_256_is_protocol_zero() {
        let mut block = sample_block([0u8; 32]);
        block.number = 300;
        block.historical_hashes = vec![(0, [0xcd; 32])];
        let mut db = ProofDb::new();
        let out = call_blockhash(&mut db, &block, 0).expect("old");
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

    /// Account proof verifies, but requested storage keys are stripped (lying / truncated RPC).
    struct OmitSlotsProver {
        address: [u8; 20],
        proof: EthAccountProof,
        code: Vec<u8>,
        fetches: std::cell::Cell<u32>,
    }

    impl ProveAtSafe for OmitSlotsProver {
        fn get_proof(
            &self,
            address: &[u8; 20],
            _slots: &[[u8; 32]],
            _block_hash: &[u8; 32],
            _block_number: u64,
        ) -> Result<EthAccountProof, CallError> {
            self.fetches.set(self.fetches.get() + 1);
            if address != &self.address {
                return Err(CallError::Missing(Miss::Account(*address)));
            }
            let mut proof = self.proof.clone();
            proof.storage_proof.clear();
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
    fn omitted_storage_key_is_missing_not_budget() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let prover = OmitSlotsProver {
            address: addr,
            proof: f.proof,
            code: load_wbnb_code(),
            fetches: std::cell::Cell::new(0),
        };
        let data = decode_hex("0x06fdde03").unwrap();
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let err =
            eth_call_verified(&prover, &block, &call_tx(addr, addr, data.clone())).unwrap_err();
        match err {
            CallError::Missing(Miss::Storage { .. }) => {}
            other => panic!("expected Missing storage, got {other:?}"),
        }
        assert!(
            prover.fetches.get() < MAX_PROOF_ROUNDS,
            "omitted slot must not spin to Budget (fetches={})",
            prover.fetches.get()
        );
        let err =
            eth_estimate_gas_verified(&prover, &block, &call_tx(addr, addr, data)).unwrap_err();
        match err {
            CallError::Missing(Miss::Storage { .. }) => {}
            other => panic!("estimate expected Missing storage, got {other:?}"),
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

    #[test]
    fn missing_from_account_is_not_invented() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let prover = StaticProver {
            address: addr,
            proof: f.proof,
            code: load_wbnb_code(),
            allow_slots: false,
        };
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let from = [0x11u8; 20];
        let data = decode_hex("0x18160ddd").unwrap();
        let err = eth_call_verified(&prover, &block, &call_tx(from, addr, data)).unwrap_err();
        match err {
            CallError::Missing(Miss::Account(a)) => assert_eq!(a, from),
            other => panic!("expected Missing from, got {other:?}"),
        }
    }

    #[test]
    fn precompile_to_ecrecover_is_not_missing_account() {
        let mut ecrecover = [0u8; 20];
        ecrecover[19] = 0x01;
        let f = load_tip();
        let prover = StaticProver {
            address: decode_hex_fixed::<20>(&f.address).unwrap(),
            proof: f.proof,
            code: load_wbnb_code(),
            allow_slots: false,
        };
        let mut block = sample_block(decode_hex_fixed::<32>(&f.state_root).unwrap());
        block.beneficiary = ecrecover;
        let res = eth_call_verified(&prover, &block, &call_tx(ecrecover, ecrecover, vec![]));
        match res {
            Ok(_) => {}
            Err(CallError::Missing(Miss::Account(a))) => {
                assert_ne!(a, ecrecover, "precompile 0x01 must not require a proof");
            }
            Err(_) => {}
        }
    }

    #[test]
    fn wbnb_totalsupply_estimate_gas() {
        let f = load_tip();
        let root = decode_hex_fixed::<32>(&f.state_root).unwrap();
        let addr = decode_hex_fixed::<20>(&f.address).unwrap();
        let prover = StaticProver {
            address: addr,
            proof: f.proof.clone(),
            code: load_wbnb_code(),
            allow_slots: false,
        };
        let mut block = sample_block(root);
        block.beneficiary = addr;
        let data = decode_hex("0x18160ddd").unwrap();
        let gas = eth_estimate_gas_verified(&prover, &block, &call_tx(addr, addr, data))
            .expect("estimate");
        assert!(gas >= TX_GAS, "{gas}");
        assert!(gas <= CALL_GAS_CAP, "{gas}");
    }

    #[test]
    fn wbnb_name_estimate_unproven_slot_fail_closed() {
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
        let err =
            eth_estimate_gas_verified(&prover, &block, &call_tx(addr, addr, data)).unwrap_err();
        match err {
            CallError::Missing(_) | CallError::Proof(_) => {}
            other => panic!("expected Missing/Proof, got {other:?}"),
        }
    }

    #[test]
    fn wbnb_name_estimate_with_slot0() {
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
        let gas = eth_estimate_gas_verified(&prover, &block, &call_tx(addr, addr, data))
            .expect("estimate");
        assert!(gas >= TX_GAS, "{gas}");
        assert!(gas <= CALL_GAS_CAP, "{gas}");
    }

    #[test]
    fn wbnb_name_prefetch_access_list_slot0() {
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
        let mut tx = call_tx(addr, addr, data);
        tx.access_list = vec![(addr, vec![[0u8; 32]])];
        let out = eth_call_verified(&prover, &block, &tx).expect("name");
        assert!(
            out.windows(b"Wrapped BNB".len())
                .any(|w| w == b"Wrapped BNB"),
            "ABI name missing Wrapped BNB: 0x{}",
            hex::encode(&out)
        );
    }

    #[test]
    fn wbnb_name_estimate_prefetch_access_list_slot0() {
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
        let mut tx = call_tx(addr, addr, data);
        tx.access_list = vec![(addr, vec![[0u8; 32]])];
        let gas = eth_estimate_gas_verified(&prover, &block, &tx).expect("estimate");
        assert!(gas >= TX_GAS, "{gas}");
        assert!(gas <= CALL_GAS_CAP, "{gas}");
    }

    #[test]
    fn access_list_seed_does_not_reduce_miss_retry_budget() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let beneficiary = [0x33u8; 20];
        let code = call_n_addrs(MAX_PROOF_ROUNDS as u8);
        let (root, proof) = single_leaf_account(to, &code, EMPTY_TRIE_ROOT);
        let prover = CountingProver {
            to,
            proof,
            code,
            fetches: std::cell::Cell::new(0),
        };
        let mut block = sample_block(root);
        block.beneficiary = beneficiary;
        let extra = miss_addr(0xff);
        let mut tx = call_tx(from, to, vec![]);
        tx.gas = Some(1_000_000);
        tx.access_list = vec![(extra, vec![])];
        eth_call_verified(&prover, &block, &tx).expect("8 miss-retries after accessList seed");
        assert_eq!(
            prover.fetches.get(),
            3 + 1 + MAX_PROOF_ROUNDS,
            "3 seed + 1 accessList + 8 miss fetches"
        );
    }

    #[test]
    fn access_list_too_large_is_invalid() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let (root, proof) = single_leaf_account(to, &RETURN_42_FULL, EMPTY_TRIE_ROOT);
        let prover = CountingProver {
            to,
            proof,
            code: RETURN_42_FULL.to_vec(),
            fetches: std::cell::Cell::new(0),
        };
        let mut tx = call_tx(from, to, vec![]);
        tx.access_list = (0..=MAX_CALL_ACCOUNTS)
            .map(|i| (miss_addr(i as u8), Vec::new()))
            .collect();
        let err = eth_call_verified(&prover, &sample_block(root), &tx).unwrap_err();
        match err {
            CallError::Invalid(msg) => assert!(msg.contains("accessList too large"), "{msg}"),
            other => panic!("expected Invalid accessList too large, got {other:?}"),
        }
        assert_eq!(prover.fetches.get(), 0, "oversized list must not fetch");
    }

    #[test]
    fn access_list_new_accounts_over_proofdb_cap_is_budget() {
        let from = [0x11u8; 20];
        let to = [0x22u8; 20];
        let beneficiary = [0x33u8; 20];
        let (root, proof) = single_leaf_account(to, &RETURN_42_FULL, EMPTY_TRIE_ROOT);
        let prover = CountingProver {
            to,
            proof,
            code: RETURN_42_FULL.to_vec(),
            fetches: std::cell::Cell::new(0),
        };
        let mut block = sample_block(root);
        block.beneficiary = beneficiary;
        let mut tx = call_tx(from, to, vec![]);
        // 3 seed accounts + 30 new exclusion addresses → 33rd insert is Budget.
        tx.access_list = (0..30).map(|i| (miss_addr(i), Vec::new())).collect();
        let err = eth_call_verified(&prover, &block, &tx).unwrap_err();
        match err {
            CallError::Budget => {}
            other => panic!("expected Budget, got {other:?}"),
        }
    }
}
