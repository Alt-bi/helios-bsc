//! Fail-closed local JSON-RPC (wallet mode: latest → Safe).

use crate::bind::{listen_is_loopback, rpc_http_host_reject};
use crate::sync::{
    accept_lookback_resync, append_new, append_new_with_snapshot, is_link_err, safe_of,
    walk_from_checkpoint, walk_headers, write_checkpoint_file,
};
use crate::upstream::RpcUpstream;
use anyhow::{bail, Result};
use helios_bsc_config::{
    expected_safe_lag_blocks, mainnet_current_fork, mainnet_n_seal, max_reorg_depth,
    safe_lag_seconds, safe_lag_within_slo, PROVIDER_PROOF_LOOKBACK,
};
use helios_bsc_consensus::{
    checkpoint_at_snapshot, header_hash, proof_lag, within_proof_window, Snapshot, VerifiedBlock,
};
use helios_bsc_execution::{
    encode_data32, encode_qty, eth_call_verified, eth_estimate_gas_verified, pad32,
    retain_requested_storage, validate_bsc_raw_tx, verify_account_code, verify_eth_get_proof,
    verify_storage_slot, verify_tx_list, CallBlock, CallError, CallTx, EthAccountProof, ProofError,
    ProveAtSafe, VerifiedAccount, CALL_GAS_CAP, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT,
    MAX_CALL_ACCOUNTS, MAX_CALL_DATA, MAX_CODE_SIZE, MAX_RAW_TX,
};
use helios_bsc_rpc::{
    jsonrpc_id_ok, jsonrpc_is_v2, jsonrpc_params_len, jsonrpc_params_ok, method_policy, rpc_err,
    rpc_err_data, rpc_ok, unverified_passthrough_ok, wallet_block_number_allowed,
    wallet_block_tag_str, BlockId, MethodPolicy, ERR_EXECUTION, ERR_INVALID, ERR_METHOD,
    ERR_NOT_SYNCED, ERR_PARAMS, ERR_PARSE, ERR_PROOF_FAILED, ERR_STATE_ROOT,
    MAX_PROOF_STORAGE_KEYS, MAX_RPC_BATCH, MAX_RPC_METHOD, MAX_RPC_PARAMS,
};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, keccak256, Checkpoint, RpcBlockHeader, SafeHead,
    BSC_MAINNET_CHAIN_ID,
};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

/// JSON-RPC is POST-only. Caps memory if a client streams a huge body.
pub const MAX_RPC_BODY: usize = 1024 * 1024;

pub struct Node {
    up: Box<dyn RpcUpstream>,
    lookback: u64,
    max_sync: u64,
    chain: Mutex<Vec<VerifiedBlock>>,
    snapshot: Mutex<Option<Snapshot>>,
    checkpoint_store: Option<PathBuf>,
    fork_id: String,
    origin: Option<Checkpoint>,
    origin_checkpoint: Option<u64>,
    proof_ok: AtomicU64,
    proof_fail: AtomicU64,
    headers_verified: AtomicU64,
    allow_unverified_passthrough: bool,
    backup_transport: bool,
}

impl Node {
    pub fn bootstrap(up: Box<dyn RpcUpstream>, lookback: u64) -> Result<Self> {
        let tip = up.block_number()?;
        let from = tip.saturating_sub(lookback.saturating_sub(1));
        eprintln!("sync {from}..={tip}");
        let chain = walk_headers(up.as_ref(), from, tip)?;
        let _ = safe_of(&chain)?;
        let n = chain.len() as u64;
        Ok(Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(None),
            checkpoint_store: None,
            fork_id: "fermi".into(),
            origin: None,
            origin_checkpoint: None,
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(n),
            allow_unverified_passthrough: false,
            backup_transport: false,
        })
    }

    /// Sync from a weak-subjectivity checkpoint: seals + parent-link + sealing-set membership.
    pub fn bootstrap_from_checkpoint(
        up: Box<dyn RpcUpstream>,
        lookback: u64,
        max_sync: u64,
        checkpoint: Checkpoint,
    ) -> Result<Self> {
        let tip = up.block_number()?;
        eprintln!(
            "sync from checkpoint {} ..= {tip} (sealing set n={})",
            checkpoint.number,
            checkpoint.sealing_set.len()
        );
        let origin_n = checkpoint.number;
        let fork_id = checkpoint.fork_id.clone();
        let (chain, snapshot) =
            walk_from_checkpoint(up.as_ref(), checkpoint.clone(), tip, max_sync)?;
        let _ = safe_of(&chain)?;
        let n = chain.len() as u64;
        Ok(Self {
            up,
            lookback,
            max_sync,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(Some(snapshot)),
            checkpoint_store: None,
            fork_id,
            origin: Some(checkpoint),
            origin_checkpoint: Some(origin_n),
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(n),
            allow_unverified_passthrough: false,
            backup_transport: false,
        })
    }

    /// Test helper: inject an already-walked chain (no bootstrap). `refresh` still
    /// talks to `up` and requires a Safe head for serving methods.
    pub fn from_parts(up: Box<dyn RpcUpstream>, lookback: u64, chain: Vec<VerifiedBlock>) -> Self {
        Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(None),
            checkpoint_store: None,
            fork_id: "fermi".into(),
            origin: None,
            origin_checkpoint: None,
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(0),
            allow_unverified_passthrough: false,
            backup_transport: false,
        }
    }

    pub fn from_parts_with_snapshot(
        up: Box<dyn RpcUpstream>,
        lookback: u64,
        chain: Vec<VerifiedBlock>,
        snapshot: Snapshot,
        fork_id: impl Into<String>,
    ) -> Self {
        let origin_n = snapshot.number;
        Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(Some(snapshot)),
            checkpoint_store: None,
            fork_id: fork_id.into(),
            origin: None,
            origin_checkpoint: Some(origin_n),
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(0),
            allow_unverified_passthrough: false,
            backup_transport: false,
        }
    }

    pub fn set_checkpoint_store(&mut self, path: PathBuf) {
        self.checkpoint_store = Some(path);
    }

    pub fn set_allow_unverified_passthrough(&mut self, yes: bool) {
        self.allow_unverified_passthrough = yes;
        if yes {
            eprintln!(
                "warning: --allow-unverified-passthrough on (receipts/txs header-bound to Safe; gasPrice unbound)"
            );
        }
    }

    pub fn set_backup_transport(&mut self, yes: bool) {
        self.backup_transport = yes;
    }

    fn bump_proof_ok(&self) {
        self.proof_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn bump_proof_fail(&self) {
        self.proof_fail.fetch_add(1, Ordering::Relaxed);
    }

    fn bump_headers(&self, n: u64) {
        if n > 0 {
            self.headers_verified.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Write last verified header + current sealing set for the next process start.
    pub fn persist_verified_tip(&self) {
        let Some(path) = self.checkpoint_store.as_ref() else {
            return;
        };
        let (hash, state_root, number, snap, stored) = {
            let chain = self.chain.lock().expect("chain lock");
            let snapshot = self.snapshot.lock().expect("snapshot lock");
            let Some(last) = chain.last() else {
                return;
            };
            let Some(snap) = snapshot.as_ref() else {
                return;
            };
            (
                last.hash,
                last.state_root,
                last.number,
                snap.clone(),
                last.header.clone(),
            )
        };
        let header = if let Some(h) = stored {
            h
        } else {
            let hash_hex = format!("0x{}", hex::encode(hash));
            match self.up.header_by_hash(&hash_hex) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("checkpoint store: header fetch failed: {e}");
                    return;
                }
            }
        };
        match header_hash(&header) {
            Ok(got) if got == hash => {}
            Ok(_) => {
                eprintln!("checkpoint store: re-fetched header hash mismatch");
                return;
            }
            Err(e) => {
                eprintln!("checkpoint store: re-fetched header rlp: {e}");
                return;
            }
        }
        if decode_u64(&header.number).ok() != Some(number) {
            eprintln!("checkpoint store: re-fetched header number mismatch");
            return;
        }
        if decode_hex_fixed::<32>(&header.state_root).ok() != Some(state_root) {
            eprintln!("checkpoint store: re-fetched header stateRoot mismatch");
            return;
        }
        match checkpoint_at_snapshot(
            &header,
            &snap,
            self.fork_id.clone(),
            Some("helios-bsc last-verified".into()),
        ) {
            Ok(cp) => {
                if let Err(e) = write_checkpoint_file(path, &cp) {
                    eprintln!("checkpoint store: {e}");
                }
            }
            Err(e) => eprintln!("checkpoint store: {e}"),
        }
    }

    /// Catch up to the live tip. Used on every wallet read and by the background poller.
    pub fn poll_sync(&self) -> Result<(u64, SafeHead)> {
        self.refresh()
    }

    fn refresh(&self) -> Result<(u64, SafeHead)> {
        let mut chain = self.chain.lock().expect("chain lock");
        let mut snapshot = self.snapshot.lock().expect("snapshot lock");
        let tip = self.up.block_number()?;
        let last = chain.last().map(|b| b.number).unwrap_or(0);
        let mut grew = false;
        let verified_this;
        if snapshot.is_some() {
            if tip > last.saturating_add(self.max_sync) {
                bail!(
                    "tip jumped {} blocks; pass a fresh --checkpoint (max-sync {})",
                    tip.saturating_sub(last),
                    self.max_sync
                );
            }
            match append_new_with_snapshot(self.up.as_ref(), &mut chain, tip, snapshot.as_mut()) {
                Ok(()) => {}
                Err(e) if is_link_err(&e) => {
                    let Some(cp) = self.origin.clone() else {
                        return Err(e);
                    };
                    eprintln!(
                        "reorg/link break ({e}); replay from checkpoint {}",
                        cp.number
                    );
                    let (c, s) = walk_from_checkpoint(self.up.as_ref(), cp, tip, self.max_sync)?;
                    *chain = c;
                    *snapshot = Some(s);
                }
                Err(e) => return Err(e),
            }
            let new_last = chain.last().map(|b| b.number).unwrap_or(0);
            grew = new_last > last;
            verified_this = new_last.saturating_sub(last);
        } else if tip > last.saturating_add(self.lookback) || chain.len() < 16 {
            let from = tip.saturating_sub(self.lookback.saturating_sub(1));
            *chain = walk_headers(self.up.as_ref(), from, tip)?;
            verified_this = chain.len() as u64;
        } else if let Err(e) = append_new(self.up.as_ref(), &mut chain, tip) {
            if is_link_err(&e) {
                eprintln!(
                    "reorg/link break ({e}); resync lookback (max reorg {})",
                    max_reorg_depth()
                );
                let from = tip.saturating_sub(self.lookback.saturating_sub(1));
                let walked = walk_headers(self.up.as_ref(), from, tip)?;
                let old = chain.clone();
                *chain = accept_lookback_resync(&old, walked)?;
                verified_this = chain.len() as u64;
            } else {
                return Err(e);
            }
        } else {
            verified_this = chain
                .last()
                .map(|b| b.number.saturating_sub(last))
                .unwrap_or(0);
        }
        let safe = safe_of(&chain)?;
        drop(chain);
        drop(snapshot);
        self.bump_headers(verified_this);
        if grew {
            self.persist_verified_tip();
        }
        Ok((tip, safe))
    }

    /// JSON-RPC 2.0 envelope: single object, batch array, or parse error.
    /// Batch notifications (no `id` member) are omitted from the response array.
    /// A single notification returns JSON `null` (HTTP 204 at the socket).
    pub fn dispatch(&self, body: &Value) -> Value {
        match body {
            Value::Array(arr) if arr.is_empty() => {
                rpc_err(Value::Null, ERR_INVALID, "invalid_request")
            }
            Value::Array(arr) if arr.len() > MAX_RPC_BATCH => {
                rpc_err(Value::Null, ERR_INVALID, "invalid_request")
            }
            Value::Array(arr) => {
                let mut out = Vec::new();
                for x in arr {
                    if !x.is_object() {
                        out.push(rpc_err(Value::Null, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    if x.get("id").is_none() {
                        continue;
                    }
                    let id = x.get("id").cloned().unwrap_or(Value::Null);
                    if !jsonrpc_id_ok(&id) {
                        out.push(rpc_err(Value::Null, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    if !jsonrpc_is_v2(x) {
                        out.push(rpc_err(id, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    out.push(self.handle(x));
                }
                Value::Array(out)
            }
            Value::Object(_) => {
                if body.get("id").is_none() {
                    return Value::Null;
                }
                let id = body.get("id").cloned().unwrap_or(Value::Null);
                if !jsonrpc_id_ok(&id) {
                    return rpc_err(Value::Null, ERR_INVALID, "invalid_request");
                }
                if !jsonrpc_is_v2(body) {
                    return rpc_err(id, ERR_INVALID, "invalid_request");
                }
                self.handle(body)
            }
            _ => rpc_err(Value::Null, ERR_INVALID, "invalid_request"),
        }
    }

    pub fn dispatch_bytes(&self, buf: &[u8]) -> Value {
        match serde_json::from_slice::<Value>(buf) {
            Ok(body) => self.dispatch(&body),
            Err(_) => rpc_err(Value::Null, ERR_PARSE, "parse_error"),
        }
    }

    pub fn handle(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        if req.get("id").is_some() && !jsonrpc_id_ok(&id) {
            return rpc_err(Value::Null, ERR_INVALID, "invalid_request");
        }
        if !jsonrpc_is_v2(req) {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        }
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        };
        if method.is_empty()
            || method.len() > MAX_RPC_METHOD
            || !method.bytes().all(|b| b.is_ascii_graphic())
        {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        }
        if !jsonrpc_params_ok(req) {
            return rpc_err(id, ERR_PARAMS, "params must be an array");
        }
        if jsonrpc_params_len(req) > MAX_RPC_PARAMS {
            return rpc_err(id, ERR_PARAMS, "too many params");
        }
        match method {
            "eth_chainId" => rpc_ok(id, json!("0x38")),
            "eth_protocolVersion" => rpc_ok(id, json!("0x41")),
            "net_version" => rpc_ok(id, json!("56")),
            "net_listening" => rpc_ok(id, json!(true)),
            "net_peerCount" => rpc_ok(id, json!("0x0")),
            "web3_clientVersion" => rpc_ok(
                id,
                json!(format!("helios-bsc/{}", env!("CARGO_PKG_VERSION"))),
            ),
            "eth_accounts" => rpc_ok(id, json!([])),
            "eth_mining" => rpc_ok(id, json!(false)),
            "eth_hashrate" => rpc_ok(id, json!("0x0")),
            "web3_sha3" => self.web3_sha3(id, req),
            "eth_syncing" => self.eth_syncing(id),
            "eth_blockNumber" => match self.refresh() {
                Ok((_, safe)) => rpc_ok(id, json!(format!("0x{:x}", safe.number))),
                Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
            },
            "helios_bsc_syncStatus" => match self.refresh() {
                Ok((tip, safe)) => rpc_ok(id, self.status_fields(tip, &safe)),
                Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
            },
            "eth_getBalance" => self.account_field(id, req, AccountField::Balance),
            "eth_getTransactionCount" => self.account_field(id, req, AccountField::Nonce),
            "eth_getCode" => self.get_code(id, req),
            "eth_call" => self.eth_call(id, req),
            "eth_estimateGas" => self.eth_estimate_gas(id, req),
            "eth_getStorageAt" => self.get_storage(id, req),
            "eth_getProof" => self.get_eth_proof(id, req),
            "eth_getBlockByNumber" => self.get_block_by_number(id, req),
            "eth_getBlockByHash" => self.get_block_by_hash(id, req),
            "eth_getBlockTransactionCountByNumber" => self.tx_count_by_number(id, req),
            "eth_getBlockTransactionCountByHash" => self.tx_count_by_hash(id, req),
            "eth_getTransactionByBlockNumberAndIndex" => self.tx_by_block_number_and_index(id, req),
            "eth_getTransactionByBlockHashAndIndex" => self.tx_by_block_hash_and_index(id, req),
            "eth_getUncleCountByBlockNumber" => self.uncle_count_by_number(id, req),
            "eth_getUncleCountByBlockHash" => self.uncle_count_by_hash(id, req),
            "eth_getUncleByBlockNumberAndIndex" => self.uncle_by_number(id, req),
            "eth_getUncleByBlockHashAndIndex" => self.uncle_by_hash(id, req),
            "eth_coinbase" => rpc_ok(id, json!("0x0000000000000000000000000000000000000000")),
            "eth_sendRawTransaction" => self.send_raw(id, req),
            "eth_getTransactionReceipt" | "eth_getTransactionByHash" => {
                self.unverified_mined(id, req, method)
            }
            "eth_getRawTransactionByHash" => self.get_raw_tx_by_hash(id, req),
            "eth_gasPrice" | "eth_maxPriorityFeePerGas" | "eth_feeHistory" | "eth_blobBaseFee" => {
                self.unverified_qty(id, req, method)
            }
            "helios_bsc_getVerificationStatus" => self.verification_status(id),
            _ => match method_policy(method) {
                MethodPolicy::Unsupported => rpc_err(id, ERR_METHOD, "method_unsupported"),
                MethodPolicy::Unverified if unverified_passthrough_ok(method) => {
                    rpc_err(id, ERR_METHOD, "unverified_passthrough_disabled")
                }
                MethodPolicy::Unverified => rpc_err(id, ERR_METHOD, "method_unsupported"),
                MethodPolicy::Verified => rpc_err(id, ERR_METHOD, "method_unsupported"),
            },
        }
    }

    fn web3_sha3(&self, id: Value, req: &Value) -> Value {
        let Some(hex) = req
            .get("params")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .and_then(Value::as_str)
        else {
            return rpc_err(id, ERR_PARAMS, "data hex required");
        };
        match decode_hex(hex) {
            Ok(bytes) if bytes.len() > MAX_RAW_TX => {
                rpc_err(id, ERR_PARAMS, "web3_sha3 payload too large")
            }
            Ok(bytes) => rpc_ok(id, json!(format!("0x{}", hex::encode(keccak256(&bytes))))),
            Err(e) => rpc_err(id, ERR_PARAMS, &format!("invalid hex: {e}")),
        }
    }

    fn eth_syncing(&self, id: Value) -> Value {
        match self.refresh() {
            Ok(_) => rpc_ok(id, json!(false)),
            Err(_) => {
                let n = self
                    .chain
                    .lock()
                    .ok()
                    .and_then(|c| c.last().map(|b| b.number))
                    .unwrap_or(0);
                let hx = format!("0x{n:x}");
                rpc_ok(
                    id,
                    json!({
                        "startingBlock": hx,
                        "currentBlock": hx,
                        "highestBlock": hx,
                    }),
                )
            }
        }
    }

    fn status_fields(&self, tip: u64, safe: &SafeHead) -> Value {
        let sealing = self.snapshot.lock().expect("snapshot lock").is_some();
        let lag = proof_lag(tip, safe.number);
        let interval_ms = mainnet_current_fork().block_interval_ms;
        json!({
            "trustClass": "verified",
            "finality": "confirmation-depth",
            "forkId": self.fork_id,
            "tip": tip,
            "safe": safe.number,
            "safeHash": safe.hash,
            "lag": lag,
            "safeLagBlocks": lag,
            "safeLagSeconds": safe_lag_seconds(lag, interval_ms),
            "blockIntervalMs": interval_ms,
            "distinctSealers": safe.distinct_sealers,
            "requiredSealers": safe.required_sealers,
            "nSeal": mainnet_n_seal(),
            "proofWindow": PROVIDER_PROOF_LOOKBACK,
            "inProofWindow": within_proof_window(tip, safe.number),
            "sealingSetEnforced": sealing,
            "originCheckpoint": self.origin_checkpoint,
            "proofOk": self.proof_ok.load(Ordering::Relaxed),
            "proofFail": self.proof_fail.load(Ordering::Relaxed),
            "headersVerified": self.headers_verified.load(Ordering::Relaxed),
            "unverifiedPassthrough": self.allow_unverified_passthrough,
            "backupTransport": self.backup_transport,
            "expectedSafeLagBlocks": expected_safe_lag_blocks(),
            "safeLagWithinBound": safe_lag_within_slo(lag),
        })
    }

    fn verification_status(&self, id: Value) -> Value {
        match self.refresh() {
            Ok((tip, safe)) => rpc_ok(id, self.status_fields(tip, &safe)),
            Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        }
    }

    fn account_field(&self, id: Value, req: &Value, field: AccountField) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return rpc_err(id, ERR_PARAMS, "invalid params");
        };
        let Some(addr) = params.first().and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "address required");
        };
        if let Err(e) = require_rpc_address(addr) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        let tag = match wallet_block_id_str(id.clone(), params.get(1)) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = match self.resolve_wallet_exec_block(id.clone(), tag, tip, &safe) {
            Ok(b) => b,
            Err(e) => return e,
        };
        match self.verified_account(id.clone(), addr, tip, &local) {
            Ok(acc) => match field {
                AccountField::Balance => rpc_ok(id, json!(encode_qty(&acc.balance_wei))),
                AccountField::Nonce => rpc_ok(id, json!(format!("0x{:x}", acc.nonce))),
            },
            Err(e) => e,
        }
    }

    fn get_code(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return rpc_err(id, ERR_PARAMS, "invalid params");
        };
        let Some(addr) = params.first().and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "address required");
        };
        if let Err(e) = require_rpc_address(addr) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        let tag = match wallet_block_id_str(id.clone(), params.get(1)) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = match self.resolve_wallet_exec_block(id.clone(), tag, tip, &safe) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let acc = match self.verified_account(id.clone(), addr, tip, &local) {
            Ok(a) => a,
            Err(e) => return e,
        };
        if acc.code_hash == EMPTY_CODE_HASH {
            return rpc_ok(id, json!("0x"));
        }
        let hash = format!("0x{}", hex::encode(local.hash));
        let number = format!("0x{:x}", local.number);
        let code = match self
            .up
            .get_code(addr, &hash)
            .or_else(|_| self.up.get_code(addr, &number))
        {
            Ok(c) => c,
            Err(e) => {
                return rpc_err(
                    id,
                    ERR_PROOF_FAILED,
                    &format!("proof_verification_failed: {e}"),
                )
            }
        };
        if code.len() > MAX_CODE_SIZE {
            return rpc_err(id, ERR_PROOF_FAILED, "bytecode exceeds MaxCodeSize");
        }
        match verify_account_code(&acc, &code) {
            Ok(()) => rpc_ok(id, json!(format!("0x{}", hex::encode(code)))),
            Err(e) => rpc_err(
                id,
                ERR_PROOF_FAILED,
                &format!("proof_verification_failed: {e}"),
            ),
        }
    }

    fn prepare_verified_call(&self, id: Value, req: &Value) -> Result<(CallTx, CallBlock), Value> {
        let tx = match parse_eth_call_tx(req) {
            Ok(t) => t,
            Err(e) => return Err(rpc_err(id, ERR_PARAMS, &e)),
        };
        let tag = wallet_block_id_str(
            id.clone(),
            req.get("params")
                .and_then(Value::as_array)
                .and_then(|p| p.get(1)),
        )?;
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return Err(rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}"))),
        };
        let local = self.resolve_wallet_exec_block(id, tag, tip, &safe)?;
        let block = {
            let chain = self.chain.lock().expect("chain lock");
            call_block_from_verified(&local, &chain)
        };
        Ok((tx, block))
    }

    fn eth_call(&self, id: Value, req: &Value) -> Value {
        let (tx, block) = match self.prepare_verified_call(id.clone(), req) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let prover = UpstreamProve {
            up: self.up.as_ref(),
        };
        match eth_call_verified(&prover, &block, &tx) {
            Ok(out) => {
                self.bump_proof_ok();
                rpc_ok(id, json!(format!("0x{}", hex::encode(out))))
            }
            Err(e) => self.map_call_error(id, e),
        }
    }

    fn eth_estimate_gas(&self, id: Value, req: &Value) -> Value {
        let (tx, block) = match self.prepare_verified_call(id.clone(), req) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let prover = UpstreamProve {
            up: self.up.as_ref(),
        };
        match eth_estimate_gas_verified(&prover, &block, &tx) {
            Ok(gas) => {
                self.bump_proof_ok();
                rpc_ok(id, json!(format!("0x{gas:x}")))
            }
            Err(e) => self.map_call_error(id, e),
        }
    }

    fn map_call_error(&self, id: Value, e: CallError) -> Value {
        if matches!(
            &e,
            CallError::Missing(_) | CallError::Proof(_) | CallError::Budget
        ) {
            self.bump_proof_fail();
        }
        let (code, msg, data) = call_error_rpc(e);
        match data {
            Some(d) => rpc_err_data(id, code, &msg, json!(d)),
            None => rpc_err(id, code, &msg),
        }
    }

    fn get_eth_proof(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return rpc_err(id, ERR_PARAMS, "invalid params");
        };
        let Some(addr) = params.first().and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "address required");
        };
        if let Err(e) = require_rpc_address(addr) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        let keys = match parse_storage_keys(params.get(1)) {
            Ok(k) => k,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let tag = match wallet_block_id_str(id.clone(), params.get(2)) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = match self.resolve_wallet_exec_block(id.clone(), tag, tip, &safe) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let (acc, mut proof) = match self.verified_proof(id.clone(), addr, tip, &local, &keys) {
            Ok(v) => v,
            Err(e) => return e,
        };
        proof.address = format!("0x{}", hex::encode(acc.address));
        proof.nonce = format!("0x{:x}", acc.nonce);
        proof.balance = encode_qty(&acc.balance_wei);
        proof.code_hash = format!("0x{}", hex::encode(acc.code_hash));
        proof.storage_hash = format!("0x{}", hex::encode(acc.storage_root));
        for k in &keys {
            let slot = match parse_slot(k) {
                Ok(s) => s,
                Err(e) => return rpc_err(id, ERR_PARAMS, &e),
            };
            if let Err(e) = verify_storage_slot(&acc, &slot, &proof) {
                self.bump_proof_fail();
                return rpc_err(
                    id,
                    ERR_PROOF_FAILED,
                    &format!("proof_verification_failed: {e}"),
                );
            }
        }
        retain_requested_storage(&mut proof, &keys);
        match serde_json::to_value(&proof) {
            Ok(v) => rpc_ok(id, v),
            Err(e) => rpc_err(
                id,
                ERR_PROOF_FAILED,
                &format!("proof_verification_failed: {e}"),
            ),
        }
    }

    fn get_storage(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return rpc_err(id, ERR_PARAMS, "invalid params");
        };
        let Some(addr) = params.first().and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "address required");
        };
        if let Err(e) = require_rpc_address(addr) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        let Some(slot_hex) = params.get(1).and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "storage slot required");
        };
        let tag = match wallet_block_id_str(id.clone(), params.get(2)) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let slot = match parse_slot(slot_hex) {
            Ok(s) => s,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = match self.resolve_wallet_exec_block(id.clone(), tag, tip, &safe) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let key = format!("0x{}", hex::encode(slot));
        let (acc, proof) =
            match self.verified_proof(id.clone(), addr, tip, &local, std::slice::from_ref(&key)) {
                Ok(v) => v,
                Err(e) => return e,
            };
        match verify_storage_slot(&acc, &slot, &proof) {
            Ok(val) => rpc_ok(id, json!(encode_data32(&val))),
            Err(e) => rpc_err(
                id,
                ERR_PROOF_FAILED,
                &format!("proof_verification_failed: {e}"),
            ),
        }
    }

    fn get_block_by_number(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        if let Some(first) = params.and_then(|p| p.first()) {
            if !first.is_null() && !first.is_string() {
                return rpc_err(id, ERR_PARAMS, "invalid params");
            }
        }
        if wants_full_txs(params) {
            return rpc_err(id, ERR_METHOD, "method_unsupported");
        }
        let tag =
            params
                .and_then(|p| p.first())
                .and_then(|v| if v.is_null() { None } else { v.as_str() });
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        if wallet_block_number_allowed(tag, safe.number, &safe.hash).is_none() {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            );
        }
        let local = {
            let chain = self.chain.lock().expect("chain lock");
            wallet_get_block_by_number(tag, safe.number, &safe.hash, &chain).cloned()
        };
        let Some(local) = local else {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            );
        };
        self.verified_header_json(id, &local)
    }

    /// Parlia: uncles are forbidden (header `sha3Uncles` is the empty list hash).
    fn uncle_count_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(_) => rpc_ok(id, json!("0x0")),
            Err(e) => e,
        }
    }

    fn uncle_count_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(_) => rpc_ok(id, json!("0x0")),
            Err(e) => e,
        }
    }

    fn uncle_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(_) => rpc_ok(id, Value::Null),
            Err(e) => e,
        }
    }

    fn uncle_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(_) => rpc_ok(id, Value::Null),
            Err(e) => e,
        }
    }

    fn local_block_by_number(&self, req: &Value) -> Result<VerifiedBlock, Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").and_then(Value::as_array);
        if let Some(first) = params.and_then(|p| p.first()) {
            if !first.is_null() && !first.is_string() {
                return Err(rpc_err(id, ERR_PARAMS, "invalid params"));
            }
        }
        let tag =
            params
                .and_then(|p| p.first())
                .and_then(|v| if v.is_null() { None } else { v.as_str() });
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return Err(rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}"))),
        };
        if wallet_block_number_allowed(tag, safe.number, &safe.hash).is_none() {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            ));
        }
        let chain = self.chain.lock().expect("chain lock");
        wallet_get_block_by_number(tag, safe.number, &safe.hash, &chain)
            .cloned()
            .ok_or_else(|| {
                rpc_err(
                    id,
                    ERR_NOT_SYNCED,
                    "wallet mode only serves Safe or below (latest→Safe)",
                )
            })
    }

    fn local_block_by_hash(&self, req: &Value) -> Result<VerifiedBlock, Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return Err(rpc_err(id, ERR_PARAMS, "invalid params"));
        };
        let Some(hash) = params.first().and_then(Value::as_str) else {
            return Err(rpc_err(id, ERR_PARAMS, "block hash required"));
        };
        if decode_hex_fixed::<32>(hash).is_err() {
            return Err(rpc_err(id, ERR_PARAMS, "bad block hash"));
        }
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return Err(rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}"))),
        };
        let chain = self.chain.lock().expect("chain lock");
        wallet_get_block_by_hash(hash, safe.number, &chain)
            .cloned()
            .ok_or_else(|| {
                rpc_err(
                    id,
                    ERR_NOT_SYNCED,
                    "wallet mode only serves verified hashes at or below Safe",
                )
            })
    }

    fn get_block_by_hash(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(params) = params else {
            return rpc_err(id, ERR_PARAMS, "invalid params");
        };
        let Some(hash) = params.first().and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "block hash required");
        };
        if wants_full_txs(Some(params)) {
            return rpc_err(id, ERR_METHOD, "method_unsupported");
        }
        if decode_hex_fixed::<32>(hash).is_err() {
            return rpc_err(id, ERR_PARAMS, "bad block hash");
        }
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = {
            let chain = self.chain.lock().expect("chain lock");
            wallet_get_block_by_hash(hash, safe.number, &chain).cloned()
        };
        let Some(local) = local else {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves verified hashes at or below Safe",
            );
        };
        self.verified_header_json(id, &local)
    }

    fn verified_header_json(&self, id: Value, local: &VerifiedBlock) -> Value {
        match self.bound_block_txs(local) {
            Ok(bound) => rpc_ok(id, rpc_block_json(&bound.header, &bound.hashes)),
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    fn load_verified_header(&self, local: &VerifiedBlock) -> Result<RpcBlockHeader, (i64, String)> {
        let hdr = if let Some(h) = local.header.clone() {
            h
        } else {
            let hash = format!("0x{}", hex::encode(local.hash));
            self.up
                .header_by_hash(&hash)
                .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?
        };
        header_matches_local(&hdr, local)?;
        let mut hdr = hdr;
        hdr.hash = format!("0x{}", hex::encode(local.hash));
        Ok(hdr)
    }

    /// Bind untrusted raw txs to the sealed `transactionsRoot`. Empty root → no fetch.
    fn bind_tx_hashes(&self, hdr: &RpcBlockHeader) -> Result<Vec<[u8; 32]>, (i64, String)> {
        let root = decode_hex_fixed::<32>(&hdr.transactions_root).map_err(|e| {
            (
                ERR_PROOF_FAILED,
                format!("proof_verification_failed: transactionsRoot: {e}"),
            )
        })?;
        if root == EMPTY_TRIE_ROOT {
            return Ok(Vec::new());
        }
        let raws = self
            .up
            .block_raw_transactions(&hdr.hash)
            .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
        // No envelopes: omit hashes (do not invent, do not fail the header read).
        if raws.is_empty() {
            return Ok(Vec::new());
        }
        verify_tx_list(&raws, &root)
            .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))
    }

    fn bound_block_txs(&self, local: &VerifiedBlock) -> Result<BoundTxs, (i64, String)> {
        let header = self.load_verified_header(local)?;
        let hashes = self.bind_tx_hashes(&header)?;
        Ok(BoundTxs { header, hashes })
    }

    fn tx_count_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(local) => self.verified_tx_count(id, &local),
            Err(e) => e,
        }
    }

    fn tx_count_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(local) => self.verified_tx_count(id, &local),
            Err(e) => e,
        }
    }

    fn verified_tx_count(&self, id: Value, local: &VerifiedBlock) -> Value {
        match self.bound_block_txs(local) {
            Ok(bound) => rpc_ok(id, json!(format!("0x{:x}", bound.hashes.len()))),
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    fn tx_by_block_number_and_index(&self, id: Value, req: &Value) -> Value {
        let local = match self.local_block_by_number(req) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let index = match parse_tx_index(req) {
            Ok(i) => i,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        self.tx_at_index(id, &local, index)
    }

    fn tx_by_block_hash_and_index(&self, id: Value, req: &Value) -> Value {
        let local = match self.local_block_by_hash(req) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let index = match parse_tx_index(req) {
            Ok(i) => i,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        self.tx_at_index(id, &local, index)
    }

    fn tx_at_index(&self, id: Value, local: &VerifiedBlock, index: u64) -> Value {
        let bound = match self.bound_block_txs(local) {
            Ok(v) => v,
            Err((code, msg)) => return rpc_err(id, code, &msg),
        };
        let Ok(i) = usize::try_from(index) else {
            return rpc_ok(id, Value::Null);
        };
        let Some(hash) = bound.hashes.get(i) else {
            return rpc_ok(id, Value::Null);
        };
        rpc_ok(
            id,
            json!({
                "hash": format!("0x{}", hex::encode(hash)),
                "blockHash": bound.header.hash,
                "blockNumber": bound.header.number,
                "transactionIndex": format!("0x{index:x}"),
            }),
        )
    }

    fn unverified_mined(&self, id: Value, req: &Value, method: &str) -> Value {
        if !self.allow_unverified_passthrough {
            return rpc_err(id, ERR_METHOD, "unverified_passthrough_disabled");
        }
        let want = match query_tx_hash(req) {
            Ok(h) => h,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let params = req.get("params").cloned().unwrap_or(json!([]));
        let raw = match self.up.unverified_call(method, &params) {
            Ok(v) => v,
            Err(e) => return rpc_err(id, -32000, &format!("unverified_upstream: {e}")),
        };
        if raw.is_null() {
            return rpc_ok(id, Value::Null);
        }
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let chain = self.chain.lock().expect("chain lock");
        match bind_mined_object(&raw, &safe, &chain, Some(&want)) {
            Ok(()) => rpc_ok(id, raw),
            Err(msg) => rpc_err(id, ERR_NOT_SYNCED, &msg),
        }
    }

    fn unverified_qty(&self, id: Value, req: &Value, method: &str) -> Value {
        if !self.allow_unverified_passthrough {
            return rpc_err(id, ERR_METHOD, "unverified_passthrough_disabled");
        }
        let params = req.get("params").cloned().unwrap_or(json!([]));
        match self.up.unverified_call(method, &params) {
            Ok(v) => {
                if let Err(msg) = bind_fee_result(method, &v) {
                    return rpc_err(id, ERR_PARAMS, &msg);
                }
                if method == "eth_feeHistory" && v.get("oldestBlock").is_some_and(|x| !x.is_null())
                {
                    let (_, safe) = match self.refresh() {
                        Ok(x) => x,
                        Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
                    };
                    let chain = self.chain.lock().expect("chain lock");
                    if let Err((code, msg)) = bind_fee_oldest_block(&v, &safe, &chain) {
                        return rpc_err(id, code, &msg);
                    }
                }
                rpc_ok(id, v)
            }
            Err(e) => rpc_err(id, -32000, &format!("unverified_upstream: {e}")),
        }
    }

    fn get_raw_tx_by_hash(&self, id: Value, req: &Value) -> Value {
        if !self.allow_unverified_passthrough {
            return rpc_err(id, ERR_METHOD, "unverified_passthrough_disabled");
        }
        let want = match query_tx_hash(req) {
            Ok(h) => h,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let params = req.get("params").cloned().unwrap_or(json!([]));
        let raw = match self
            .up
            .unverified_call("eth_getRawTransactionByHash", &params)
        {
            Ok(v) => v,
            Err(e) => return rpc_err(id, -32000, &format!("unverified_upstream: {e}")),
        };
        if raw.is_null() {
            return rpc_ok(id, Value::Null);
        }
        let Some(hex) = raw.as_str() else {
            return rpc_err(id, ERR_PROOF_FAILED, "upstream raw tx is not hex");
        };
        let bytes = match decode_hex(hex) {
            Ok(b) => b,
            Err(e) => return rpc_err(id, ERR_PROOF_FAILED, &format!("upstream raw tx hex: {e}")),
        };
        if bytes.len() > MAX_RAW_TX {
            return rpc_err(id, ERR_PROOF_FAILED, "upstream raw tx too large");
        }
        // Prefer validate_bsc_raw_tx (chainId 56). Some valid mainnet txs fail
        // that check; still require keccak256(raw) == query hash and the size cap.
        let got = match validate_bsc_raw_tx(&bytes) {
            Ok(h) => h,
            Err(_) => keccak256(&bytes),
        };
        if got != want {
            return rpc_err(id, ERR_PROOF_FAILED, "upstream raw tx hash mismatch");
        }
        rpc_ok(id, json!(format!("0x{}", hex::encode(bytes))))
    }

    fn send_raw(&self, id: Value, req: &Value) -> Value {
        let params = req.get("params").and_then(Value::as_array);
        let Some(raw) = params.and_then(|p| p.first()).and_then(Value::as_str) else {
            return rpc_err(id, ERR_PARAMS, "raw tx required");
        };
        let bytes = match decode_hex(raw) {
            Ok(b) => b,
            Err(e) => return rpc_err(id, ERR_PARAMS, &format!("invalid hex: {e}")),
        };
        let want = match validate_bsc_raw_tx(&bytes) {
            Ok(h) => h,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e.to_string()),
        };
        match self.up.send_raw_transaction(raw) {
            Ok(got) => match decode_hex_fixed::<32>(&got) {
                Ok(got) if got == want => rpc_ok(id, json!(format!("0x{}", hex::encode(want)))),
                Ok(_) => rpc_err(id, ERR_PROOF_FAILED, "upstream tx hash mismatch"),
                Err(e) => rpc_err(id, ERR_PROOF_FAILED, &format!("upstream tx hash: {e}")),
            },
            Err(e) => rpc_err(id, -32000, &format!("broadcast_failed: {e}")),
        }
    }

    /// Wallet-mode exec header: tags → Safe; hex/hash iff local verified and `n ≤ Safe`.
    /// Proof window is `proof_lag(tip, requested.number) ≤ 112` (fail-closed).
    fn resolve_wallet_exec_block(
        &self,
        id: Value,
        tag: Option<&str>,
        tip: u64,
        safe: &SafeHead,
    ) -> Result<VerifiedBlock, Value> {
        let local = {
            let chain = self.chain.lock().expect("chain lock");
            wallet_get_block_by_number(tag, safe.number, &safe.hash, &chain)
                .cloned()
                .or_else(|| {
                    tag.and_then(|t| wallet_get_block_by_hash(t, safe.number, &chain).cloned())
                })
        };
        let Some(local) = local else {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            ));
        };
        let lag = proof_lag(tip, local.number);
        if lag > PROVIDER_PROOF_LOOKBACK {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                &format!("proof window exceeded: lag {lag} > {PROVIDER_PROOF_LOOKBACK}"),
            ));
        }
        Ok(local)
    }

    fn verified_account(
        &self,
        id: Value,
        addr: &str,
        tip: u64,
        exec: &VerifiedBlock,
    ) -> Result<VerifiedAccount, Value> {
        self.verified_proof(id, addr, tip, exec, &[])
            .map(|(acc, _)| acc)
    }

    fn verified_proof(
        &self,
        id: Value,
        addr: &str,
        tip: u64,
        exec: &VerifiedBlock,
        keys: &[String],
    ) -> Result<(VerifiedAccount, EthAccountProof), Value> {
        let lag = proof_lag(tip, exec.number);
        if lag > PROVIDER_PROOF_LOOKBACK {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                &format!("proof window exceeded: lag {lag} > {PROVIDER_PROOF_LOOKBACK}"),
            ));
        }
        let hash = format!("0x{}", hex::encode(exec.hash));
        let raw = self
            .up
            .get_proof_at_safe(addr, keys, &hash, exec.number)
            .map_err(|e| {
                self.bump_proof_fail();
                rpc_err(
                    id.clone(),
                    ERR_PROOF_FAILED,
                    &format!("proof_verification_failed: {e}"),
                )
            })?;
        let proof: EthAccountProof = serde_json::from_value(raw).map_err(|e| {
            self.bump_proof_fail();
            rpc_err(
                id.clone(),
                ERR_PROOF_FAILED,
                &format!("proof_verification_failed: {e}"),
            )
        })?;
        let want = decode_hex_fixed::<20>(addr)
            .map_err(|e| rpc_err(id.clone(), ERR_PARAMS, &format!("bad address: {e}")))?;
        let acc = verify_eth_get_proof(&exec.state_root, &want, &proof).map_err(|e| {
            self.bump_proof_fail();
            rpc_err(
                id,
                ERR_PROOF_FAILED,
                &format!("proof_verification_failed: {e}"),
            )
        })?;
        self.bump_proof_ok();
        Ok((acc, proof))
    }
}

/// Hex in the revert *message* is capped (existing); full bytes go in `error.data`.
const REVERT_MSG_HEX_CAP: usize = 256;
/// JSON-RPC `error.data` revert payload cap (bytes, not hex chars).
const REVERT_DATA_CAP: usize = 32 * 1024;

/// Map a verified-call error to JSON-RPC `(code, message, optional error.data hex)`.
fn call_error_rpc(e: CallError) -> (i64, String, Option<String>) {
    match e {
        CallError::Missing(_) | CallError::Proof(_) | CallError::Budget => (
            ERR_PROOF_FAILED,
            format!("proof_verification_failed: {e}"),
            None,
        ),
        CallError::Invalid(msg) => (ERR_PARAMS, msg.to_string(), None),
        CallError::Revert(data) => revert_rpc(&data),
        CallError::Halt(reason) => (ERR_EXECUTION, format!("execution_halt: {reason}"), None),
    }
}

fn revert_rpc(data: &[u8]) -> (i64, String, Option<String>) {
    let truncated = data.len() > REVERT_DATA_CAP;
    let data_bytes = if truncated {
        &data[..REVERT_DATA_CAP]
    } else {
        data
    };
    let data_hex = format!("0x{}", hex::encode(data_bytes));
    let msg = if truncated {
        "execution reverted (data truncated)".into()
    } else if data.is_empty() {
        "execution reverted".into()
    } else if data.len() <= REVERT_MSG_HEX_CAP {
        format!("execution reverted: 0x{}", hex::encode(data))
    } else {
        "execution reverted".into()
    };
    (ERR_EXECUTION, msg, Some(data_hex))
}

/// Untrusted Safe proofs/code only — never proxies `eth_call` / `eth_estimateGas`.
struct UpstreamProve<'a> {
    up: &'a dyn RpcUpstream,
}

impl ProveAtSafe for UpstreamProve<'_> {
    fn get_proof(
        &self,
        address: &[u8; 20],
        slots: &[[u8; 32]],
        block_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<EthAccountProof, CallError> {
        let addr = format!("0x{}", hex::encode(address));
        let keys: Vec<String> = slots
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect();
        let hash = format!("0x{}", hex::encode(block_hash));
        let raw = self
            .up
            .get_proof_at_safe(&addr, &keys, &hash, block_number)
            .map_err(|e| CallError::Proof(ProofError::Json(e.to_string())))?;
        serde_json::from_value(raw).map_err(|e| CallError::Proof(e.into()))
    }

    fn get_code(
        &self,
        address: &[u8; 20],
        block_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<Vec<u8>, CallError> {
        let addr = format!("0x{}", hex::encode(address));
        let hash = format!("0x{}", hex::encode(block_hash));
        self.up
            .get_code(&addr, &hash)
            .or_else(|_| self.up.get_code(&addr, &format!("0x{block_number:x}")))
            .map_err(|e| CallError::Proof(ProofError::Json(e.to_string())))
    }
}

/// Verified header hashes for BLOCKHASH: `n <= Safe` in the 256-window, cap 256.
fn historical_hashes_at_safe(chain: &[VerifiedBlock], safe_number: u64) -> Vec<(u64, [u8; 32])> {
    let mut out: Vec<(u64, [u8; 32])> = Vec::new();
    for b in chain {
        if b.number > safe_number {
            continue;
        }
        if b.number.saturating_add(256) < safe_number {
            continue;
        }
        out.push((b.number, b.hash));
        if out.len() >= 256 {
            break;
        }
    }
    out
}

fn call_block_from_verified(local: &VerifiedBlock, chain: &[VerifiedBlock]) -> CallBlock {
    let mut block = CallBlock {
        number: local.number,
        hash: local.hash,
        state_root: local.state_root,
        timestamp: local.milli_timestamp / 1000,
        beneficiary: local.miner,
        gas_limit: nonzero_gas_limit(local.gas_limit),
        difficulty: [0u8; 32],
        prevrandao: [0u8; 32],
        basefee: 0,
        historical_hashes: historical_hashes_at_safe(chain, local.number),
    };
    if let Some(h) = &local.header {
        if let Ok(ts) = decode_u64(&h.timestamp) {
            block.timestamp = ts;
        }
        if let Ok(gl) = decode_u64(&h.gas_limit) {
            block.gas_limit = nonzero_gas_limit(gl);
        }
        if let Ok(m) = decode_hex_fixed::<20>(&h.miner) {
            block.beneficiary = m;
        }
        if let Ok(mix) = decode_hex_fixed::<32>(&h.mix_hash) {
            block.prevrandao = mix;
        }
        if let Ok(d) = decode_qty_pad32(&h.difficulty) {
            block.difficulty = d;
        }
        if let Some(bf) = &h.base_fee_per_gas {
            if let Ok(n) = decode_u64(bf) {
                block.basefee = n;
            }
        }
    }
    block
}

fn nonzero_gas_limit(n: u64) -> u64 {
    if n == 0 {
        CALL_GAS_CAP
    } else {
        n
    }
}

fn parse_eth_call_tx(req: &Value) -> Result<CallTx, String> {
    let params = req
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(|| "invalid params".to_string())?;
    if params.len() > 2 {
        return Err("state overrides not supported".into());
    }
    let tx = params
        .first()
        .ok_or_else(|| "tx object required".to_string())?;
    let Some(map) = tx.as_object() else {
        return Err("tx object required".into());
    };
    for k in ["stateOverride", "blobVersionedHashes", "authorizationList"] {
        if map.contains_key(k) {
            return Err(format!("{k} not supported"));
        }
    }
    let to = match map.get("to") {
        None | Some(Value::Null) => return Err("to address required".into()),
        Some(Value::String(s)) => require_rpc_address(s)?,
        Some(_) => return Err("to address required".into()),
    };
    let from = match map.get("from") {
        None | Some(Value::Null) => [0u8; 20],
        Some(Value::String(s)) => require_rpc_address(s)?,
        Some(_) => return Err("from is not an address".into()),
    };
    let data = parse_call_data(map)?;
    let value = match map.get("value") {
        None | Some(Value::Null) => [0u8; 32],
        Some(Value::String(s)) => decode_qty_pad32(s)?,
        Some(_) => return Err("value is not hex".into()),
    };
    let gas = match map.get("gas") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(decode_u64(s).map_err(|e| format!("invalid gas: {e}"))?),
        Some(_) => return Err("gas is not hex".into()),
    };
    let access_list = parse_access_list(map)?;
    Ok(CallTx {
        from,
        to,
        data,
        value,
        gas,
        access_list,
    })
}

type CallAccessList = Vec<([u8; 20], Vec<[u8; 32]>)>;

fn parse_access_list(map: &serde_json::Map<String, Value>) -> Result<CallAccessList, String> {
    match map.get("accessList") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > MAX_CALL_ACCOUNTS {
                return Err("accessList too large".into());
            }
            let mut out = Vec::with_capacity(items.len());
            let mut total_keys = 0usize;
            for item in items {
                let obj = item
                    .as_object()
                    .ok_or_else(|| "accessList entry is not an object".to_string())?;
                let address = match obj.get("address") {
                    None | Some(Value::Null) => return Err("accessList address required".into()),
                    Some(Value::String(s)) => require_rpc_address(s)?,
                    Some(_) => return Err("accessList address is not an address".into()),
                };
                let slots = match obj.get("storageKeys") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(keys)) => {
                        if keys.len() > MAX_PROOF_STORAGE_KEYS {
                            return Err("accessList too large".into());
                        }
                        let mut slots = Vec::with_capacity(keys.len());
                        for k in keys {
                            let s = k
                                .as_str()
                                .ok_or_else(|| "accessList storage key is not hex".to_string())?;
                            slots
                                .push(parse_slot(s).map_err(|_| {
                                    "accessList storage key is not hex".to_string()
                                })?);
                        }
                        slots
                    }
                    Some(_) => return Err("accessList storageKeys must be an array".into()),
                };
                total_keys = total_keys.saturating_add(slots.len());
                if total_keys > MAX_PROOF_STORAGE_KEYS {
                    return Err("accessList too large".into());
                }
                out.push((address, slots));
            }
            Ok(out)
        }
        Some(_) => Err("accessList must be an array".into()),
    }
}

fn parse_call_data(map: &serde_json::Map<String, Value>) -> Result<Vec<u8>, String> {
    let data = match map.get("data") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("data is not hex".into()),
    };
    let input = match map.get("input") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("input is not hex".into()),
    };
    let hex = match (data, input) {
        (Some(d), Some(i)) if !d.eq_ignore_ascii_case(i) => {
            return Err("data/input mismatch".into());
        }
        (Some(d), _) | (None, Some(d)) => d,
        (None, None) => return Ok(Vec::new()),
    };
    let bytes = decode_hex(hex).map_err(|e| format!("invalid data: {e}"))?;
    if bytes.len() > MAX_CALL_DATA {
        return Err("calldata too large".into());
    }
    Ok(bytes)
}

fn decode_qty_pad32(s: &str) -> Result<[u8; 32], String> {
    let raw = s.trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Ok([0u8; 32]);
    }
    if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("value is not hex".into());
    }
    if raw.len() > 64 {
        return Err("value too large".into());
    }
    let even = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = hex::decode(even).map_err(|e| format!("invalid value: {e}"))?;
    Ok(pad32(&bytes))
}

/// EIP-1898 object (and any non-string) block id is invalid, not silent Safe.
fn wallet_block_id_str(id: Value, raw: Option<&Value>) -> Result<Option<&str>, Value> {
    wallet_block_tag_str(raw).map_err(|e| rpc_err(id, ERR_PARAMS, e))
}

/// Wallet-mode `eth_getBlockByNumber`: tag must resolve to a local verified block at or below Safe.
fn wallet_get_block_by_number<'a>(
    tag: Option<&str>,
    safe_number: u64,
    safe_hash: &str,
    chain: &'a [VerifiedBlock],
) -> Option<&'a VerifiedBlock> {
    match wallet_block_number_allowed(tag, safe_number, safe_hash)? {
        BlockId::Safe => chain.iter().find(|b| b.number == safe_number),
        BlockId::Number(n) => chain.iter().find(|b| b.number == n),
    }
}

/// Wallet-mode `eth_getBlockByHash`: hash must be in the local verified chain at or below Safe.
fn wallet_get_block_by_hash<'a>(
    hash: &str,
    safe_number: u64,
    chain: &'a [VerifiedBlock],
) -> Option<&'a VerifiedBlock> {
    let want = decode_hex_fixed::<32>(hash).ok()?;
    chain
        .iter()
        .find(|b| b.hash == want && b.number <= safe_number)
}

fn hex_eq_loose(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("0x").trim_start_matches("0X");
    let b = b.trim_start_matches("0x").trim_start_matches("0X");
    a.eq_ignore_ascii_case(b)
}

fn is_nullish_json(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => {
            let t = s.trim();
            t.is_empty() || t.eq_ignore_ascii_case("0x")
        }
        _ => false,
    }
}

/// 32-byte zero hash. `0x0` is a block number, not a hash.
fn is_zero_block_hash(s: &str) -> bool {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    raw.len() == 64 && raw.bytes().all(|b| b == b'0')
}

fn is_empty_block_hash(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => {
            let t = s.trim();
            t.is_empty() || t.eq_ignore_ascii_case("0x") || is_zero_block_hash(t)
        }
        _ => false,
    }
}

fn bind_optional_hash32(v: Option<&Value>, field: &str) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => decode_hex_fixed::<32>(s)
            .map(|_| ())
            .map_err(|_| format!("{field} is not a 32-byte hash")),
        Some(_) => Err(format!("{field} not a string")),
    }
}

fn bind_optional_address(v: Option<&Value>, field: &str, allow_null: bool) -> Result<(), String> {
    match v {
        None => Ok(()),
        Some(Value::Null) if allow_null => Ok(()),
        Some(Value::Null) => Err(format!("{field} must be an address")),
        Some(Value::String(s)) => decode_hex_fixed::<20>(s)
            .map(|_| ())
            .map_err(|_| format!("{field} is not a 20-byte address")),
        Some(_) => Err(format!("{field} not a string")),
    }
}

fn bind_optional_chain_id(v: Option<&Value>) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            let n = decode_u64(s).map_err(|_| "chainId invalid".to_string())?;
            if n == BSC_MAINNET_CHAIN_ID {
                Ok(())
            } else {
                Err("chainId is not BSC mainnet 56".into())
            }
        }
        Some(Value::Number(n)) if n.as_u64() == Some(BSC_MAINNET_CHAIN_ID) => Ok(()),
        Some(_) => Err("chainId is not BSC mainnet 56".into()),
    }
}

fn require_rpc_address(s: &str) -> Result<[u8; 20], String> {
    decode_hex_fixed::<20>(s).map_err(|_| "address is not 20 bytes".into())
}

fn query_tx_hash(req: &Value) -> Result<[u8; 32], String> {
    let s = req
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.first())
        .and_then(Value::as_str)
        .ok_or_else(|| "tx hash required".to_string())?;
    decode_hex_fixed::<32>(s).map_err(|_| "tx hash is not 32 bytes".into())
}

/// Receipt `transactionHash` / tx `hash` must equal the requested hash when present.
fn bind_result_tx_hash(
    map: &serde_json::Map<String, Value>,
    want: Option<&[u8; 32]>,
) -> Result<(), String> {
    let Some(want) = want else {
        return Ok(());
    };
    let mut present = false;
    for field in ["hash", "transactionHash"] {
        match map.get(field) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => {
                present = true;
                let got = decode_hex_fixed::<32>(s)
                    .map_err(|_| format!("{field} is not a 32-byte hash"))?;
                if &got != want {
                    return Err(format!("{field} does not match request"));
                }
            }
            Some(_) => return Err(format!("{field} not a string")),
        }
    }
    if !present {
        return Err("receipt/tx hash missing".into());
    }
    Ok(())
}

const MAX_RECEIPT_LOGS: usize = 1024;
const MAX_LOG_TOPICS: usize = 4;
const MAX_LOG_DATA: usize = 64 * 1024;
const MAX_FEE_HISTORY_ITEMS: usize = 1024;

fn bind_optional_logs(
    v: Option<&Value>,
    want_tx: Option<&[u8; 32]>,
    receipt_block: Option<&str>,
) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(logs)) => {
            if logs.len() > MAX_RECEIPT_LOGS {
                return Err("too many logs".into());
            }
            for log in logs {
                let map = log
                    .as_object()
                    .ok_or_else(|| "log is not an object".to_string())?;
                match map.get("address") {
                    None | Some(Value::Null) => return Err("log.address missing".into()),
                    Some(Value::String(s)) => {
                        decode_hex_fixed::<20>(s).map_err(|_| "log.address is not 20 bytes")?;
                    }
                    Some(_) => return Err("log.address not a string".into()),
                }
                if let Some(data) = map.get("data") {
                    match data {
                        Value::Null => {}
                        Value::String(s) => {
                            let bytes = decode_hex(s).map_err(|_| "log.data is not hex")?;
                            if bytes.len() > MAX_LOG_DATA {
                                return Err("log.data too large".into());
                            }
                        }
                        _ => return Err("log.data not a hex string".into()),
                    }
                }
                if let Some(topics) = map.get("topics") {
                    let arr = topics
                        .as_array()
                        .ok_or_else(|| "log.topics is not an array".to_string())?;
                    if arr.len() > MAX_LOG_TOPICS {
                        return Err("too many log topics".into());
                    }
                    for t in arr {
                        let s = t
                            .as_str()
                            .ok_or_else(|| "log topic not a string".to_string())?;
                        decode_hex_fixed::<32>(s).map_err(|_| "log topic is not 32 bytes")?;
                    }
                }
                if let Some(want) = want_tx {
                    if let Some(Value::String(s)) = map.get("transactionHash") {
                        let got = decode_hex_fixed::<32>(s)
                            .map_err(|_| "log.transactionHash is not a 32-byte hash")?;
                        if &got != want {
                            return Err("log.transactionHash does not match request".into());
                        }
                    }
                }
                if let (Some(rb), Some(Value::String(lb))) = (receipt_block, map.get("blockHash")) {
                    if !hex_eq_loose(rb, lb) {
                        return Err("log.blockHash does not match receipt".into());
                    }
                }
            }
            Ok(())
        }
        Some(_) => Err("logs not an array".into()),
    }
}

fn bind_optional_qty(v: Option<&Value>, field: &str) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => decode_u64(s)
            .map(|_| ())
            .map_err(|_| format!("{field} is not a hex quantity")),
        Some(_) => Err(format!("{field} not a hex quantity")),
    }
}

fn bind_optional_hex_cap(v: Option<&Value>, field: &str, max: usize) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            let bytes = decode_hex(s).map_err(|_| format!("{field} is not hex"))?;
            if bytes.len() > max {
                return Err(format!("{field} too large"));
            }
            Ok(())
        }
        Some(_) => Err(format!("{field} not a hex string")),
    }
}

fn bind_qty_array(v: Option<&Value>, field: &str) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(a)) => {
            if a.len() > MAX_FEE_HISTORY_ITEMS {
                return Err(format!("too many {field}"));
            }
            for x in a {
                bind_optional_qty(Some(x), field)?;
            }
            Ok(())
        }
        Some(_) => Err(format!("{field} is not an array")),
    }
}

fn bind_optional_tx_type(v: Option<&Value>) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            let n = decode_u64(s).map_err(|_| "type invalid".to_string())?;
            if n <= 4 {
                Ok(())
            } else {
                Err("tx type is not 0x0..=0x4".into())
            }
        }
        Some(_) => Err("type not a hex quantity".into()),
    }
}

fn bind_optional_status(v: Option<&Value>) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            let n = decode_u64(s).map_err(|_| "status invalid".to_string())?;
            if n <= 1 {
                Ok(())
            } else {
                Err("status is not 0x0 or 0x1".into())
            }
        }
        Some(_) => Err("status not a hex quantity".into()),
    }
}

/// Unverified fee oracles: known methods only; hex qty or `eth_feeHistory` object.
/// `oldestBlock` if present is a hex qty; local chain bind is `bind_fee_oldest_block`.
fn bind_fee_result(method: &str, v: &Value) -> Result<(), String> {
    match method {
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" | "eth_blobBaseFee" => {
            let s = v
                .as_str()
                .ok_or_else(|| "fee oracle not a hex quantity".to_string())?;
            decode_u64(s).map_err(|_| "fee oracle invalid quantity".to_string())?;
            Ok(())
        }
        "eth_feeHistory" => {
            let o = v
                .as_object()
                .ok_or_else(|| "feeHistory is not an object".to_string())?;
            bind_optional_qty(o.get("oldestBlock"), "oldestBlock")?;
            bind_qty_array(o.get("baseFeePerGas"), "baseFeePerGas")?;
            bind_qty_array(o.get("baseFeePerBlobGas"), "baseFeePerBlobGas")?;
            match o.get("gasUsedRatio") {
                None | Some(Value::Null) => {}
                Some(Value::Array(a)) => {
                    if a.len() > MAX_FEE_HISTORY_ITEMS {
                        return Err("too many gasUsedRatio".into());
                    }
                    for x in a {
                        let ok = match x {
                            Value::Number(n) => n.as_f64().is_some(),
                            Value::String(s) => s.parse::<f64>().is_ok(),
                            _ => false,
                        };
                        if !ok {
                            return Err("gasUsedRatio element is not a number".into());
                        }
                    }
                }
                Some(_) => return Err("gasUsedRatio is not an array".into()),
            }
            match o.get("reward") {
                None | Some(Value::Null) => {}
                Some(Value::Array(rows)) => {
                    if rows.len() > MAX_FEE_HISTORY_ITEMS {
                        return Err("too many reward".into());
                    }
                    for row in rows {
                        bind_qty_array(Some(row), "reward")?;
                    }
                }
                Some(_) => return Err("reward is not an array".into()),
            }
            Ok(())
        }
        _ => Err(format!("unknown fee method: {method}")),
    }
}

/// `oldestBlock` if present must equal a local `VerifiedBlock.number` ≤ Safe.
fn bind_fee_oldest_block(
    v: &Value,
    safe: &SafeHead,
    chain: &[VerifiedBlock],
) -> Result<(), (i64, String)> {
    let Some(o) = v.as_object() else {
        return Ok(());
    };
    match o.get("oldestBlock") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            let n = decode_u64(s)
                .map_err(|_| (ERR_PARAMS, "oldestBlock is not a hex quantity".to_string()))?;
            let Some(local) = chain.iter().find(|b| b.number == n) else {
                return Err((
                    ERR_NOT_SYNCED,
                    "feeHistory oldestBlock not in local verified chain".into(),
                ));
            };
            if local.number > safe.number {
                return Err((
                    ERR_NOT_SYNCED,
                    "feeHistory oldestBlock is above local Safe".into(),
                ));
            }
            Ok(())
        }
        Some(_) => Err((ERR_PARAMS, "oldestBlock not a hex quantity".into())),
    }
}

/// Header-bind a mined receipt/tx to the local Safe chain. Pending (null hash+number) is ok.
fn bind_mined_object(
    obj: &Value,
    safe: &SafeHead,
    chain: &[VerifiedBlock],
    want_tx: Option<&[u8; 32]>,
) -> Result<(), String> {
    let Some(map) = obj.as_object() else {
        return Err("unverified result is not an object".into());
    };
    bind_optional_hash32(map.get("transactionHash"), "transactionHash")?;
    bind_optional_hash32(map.get("hash"), "hash")?;
    bind_result_tx_hash(map, want_tx)?;
    bind_optional_chain_id(map.get("chainId"))?;
    bind_optional_address(map.get("from"), "from", false)?;
    bind_optional_address(map.get("to"), "to", true)?;
    bind_optional_address(map.get("contractAddress"), "contractAddress", true)?;
    bind_optional_status(map.get("status"))?;
    bind_optional_tx_type(map.get("type"))?;
    bind_optional_qty(map.get("gasUsed"), "gasUsed")?;
    bind_optional_qty(map.get("cumulativeGasUsed"), "cumulativeGasUsed")?;
    bind_optional_hex_cap(map.get("input"), "input", MAX_RAW_TX)?;
    bind_optional_hex_cap(map.get("data"), "data", MAX_RAW_TX)?;
    match map.get("logsBloom") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            decode_hex_fixed::<256>(s).map_err(|_| "logsBloom is not 256 bytes".to_string())?;
        }
        Some(_) => return Err("logsBloom not a hex string".into()),
    }
    let receipt_block = map.get("blockHash").and_then(Value::as_str);
    bind_optional_logs(map.get("logs"), want_tx, receipt_block)?;
    let hash_v = map.get("blockHash");
    let num_v = map.get("blockNumber");
    let hash_empty = is_empty_block_hash(hash_v);
    let num_empty = is_nullish_json(num_v);
    if hash_empty && num_empty {
        return Ok(());
    }
    if hash_empty != num_empty {
        return Err("receipt/tx pending fields inconsistent".into());
    }
    let hash = hash_v
        .and_then(Value::as_str)
        .ok_or_else(|| "receipt/tx blockHash not a string".to_string())?;
    let local = chain
        .iter()
        .find(|b| {
            let h = format!("0x{}", hex::encode(b.hash));
            hex_eq_loose(&h, hash)
        })
        .ok_or_else(|| "receipt/tx blockHash not in local verified chain".to_string())?;
    if local.number > safe.number {
        return Err("receipt/tx is above local Safe".into());
    }
    if let Some(ns) = num_v.and_then(Value::as_str) {
        let n = decode_u64(ns).map_err(|_| "receipt/tx blockNumber invalid".to_string())?;
        if n != local.number {
            return Err("receipt/tx blockNumber does not match local header".into());
        }
    }
    Ok(())
}

fn header_matches_local(hdr: &RpcBlockHeader, local: &VerifiedBlock) -> Result<(), (i64, String)> {
    let got_number = decode_u64(&hdr.number)
        .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
    if got_number != local.number {
        return Err((
            ERR_PROOF_FAILED,
            "proof_verification_failed: header number mismatch".into(),
        ));
    }
    let got_root = decode_hex_fixed::<32>(&hdr.state_root)
        .map_err(|e| (ERR_STATE_ROOT, format!("state_root_mismatch: {e}")))?;
    if got_root != local.state_root {
        return Err((
            ERR_STATE_ROOT,
            "state_root_mismatch: header stateRoot != local verified".into(),
        ));
    }
    let computed = header_hash(hdr)
        .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
    if computed != local.hash {
        return Err((
            ERR_PROOF_FAILED,
            "proof_verification_failed: header hash mismatch".into(),
        ));
    }
    Ok(())
}

fn wants_full_txs(params: Option<&Vec<Value>>) -> bool {
    params.and_then(|p| p.get(1)).and_then(Value::as_bool) == Some(true)
}

struct BoundTxs {
    header: RpcBlockHeader,
    hashes: Vec<[u8; 32]>,
}

fn rpc_block_json(hdr: &RpcBlockHeader, tx_hashes: &[[u8; 32]]) -> Value {
    let mut v = serde_json::to_value(hdr).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut v {
        let txs: Vec<Value> = tx_hashes
            .iter()
            .map(|h| json!(format!("0x{}", hex::encode(h))))
            .collect();
        map.insert("transactions".into(), Value::Array(txs));
        map.insert("uncles".into(), json!([]));
        map.retain(|_, val| !val.is_null());
    }
    v
}

fn parse_tx_index(req: &Value) -> Result<u64, String> {
    let s = req
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.get(1))
        .and_then(Value::as_str)
        .ok_or_else(|| "transaction index required".to_string())?;
    decode_u64(s).map_err(|e| format!("invalid transaction index: {e}"))
}

fn parse_storage_keys(v: Option<&Value>) -> Result<Vec<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => {
            if a.len() > MAX_PROOF_STORAGE_KEYS {
                return Err("too many storage keys".into());
            }
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                let s = x
                    .as_str()
                    .ok_or_else(|| "storage key is not a hex quantity".to_string())?;
                let _ = parse_slot(s)?;
                out.push(s.to_string());
            }
            Ok(out)
        }
        Some(_) => Err("storage keys must be an array".into()),
    }
}

/// Quantity-style storage key: hex, at most 32 bytes, left-padded. Junk / oversize rejected.
fn parse_slot(s: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        return Err("storage key is not a hex quantity".into());
    }
    let raw = s.trim_start_matches("0x").trim_start_matches("0X");
    if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("storage key is not a hex quantity".into());
    }
    if raw.len() > 64 {
        return Err("storage key is not 32 bytes".into());
    }
    let even = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = hex::decode(even).map_err(|e| format!("bad slot: {e}"))?;
    if bytes.len() > 32 {
        return Err("storage key is not 32 bytes".into());
    }
    Ok(pad32(&bytes))
}

enum AccountField {
    Balance,
    Nonce,
}

pub fn serve(node: Arc<Node>, listen: &str) -> Result<()> {
    let server = Server::http(listen).map_err(|e| anyhow::anyhow!("bind {listen}: {e}"))?;
    eprintln!("helios-bsc RPC on http://{listen}  (wallet mode: latest→Safe)");
    let loopback_only = listen_is_loopback(listen);
    // Keep Safe inside the proof window while idle (~4 Fermi blocks).
    let poller = Arc::clone(&node);
    let _ = std::thread::Builder::new()
        .name("helios-bsc-sync".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1800));
            if let Err(e) = poller.poll_sync() {
                eprintln!("background sync: {e}");
            }
        });
    for mut req in server.incoming_requests() {
        let host = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str().to_string());
        if let Some(code) = rpc_http_host_reject(host.as_deref(), loopback_only) {
            let _ = req.respond(Response::from_string("forbidden host").with_status_code(code));
            continue;
        }
        if let Some(code) = rpc_http_reject(req.method() == &Method::Post, 0) {
            if code == 405 {
                let _ = req.respond(Response::from_string("POST only").with_status_code(405));
                continue;
            }
        }
        let content_type = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Content-Type"))
            .map(|h| h.value.as_str().to_string());
        if let Some(code) = rpc_http_content_type_reject(content_type.as_deref()) {
            let _ =
                req.respond(Response::from_string("unsupported media type").with_status_code(code));
            continue;
        }
        let mut buf = Vec::new();
        let mut limited = req.as_reader().take((MAX_RPC_BODY as u64) + 1);
        limited.read_to_end(&mut buf).ok();
        if let Some(code) = rpc_http_reject(true, buf.len()) {
            let _ = req.respond(Response::from_string("payload too large").with_status_code(code));
            continue;
        }
        let out = node.dispatch_bytes(&buf);
        if out.is_null() {
            let _ = req.respond(Response::from_string("").with_status_code(204));
            continue;
        }
        let mut resp = Response::from_string(out.to_string());
        if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
            resp = resp.with_header(h);
        }
        // Never Access-Control-Allow-Origin: * — a page could then call 127.0.0.1:8545.
        let _ = req.respond(resp);
    }
    Ok(())
}

/// `None` = accept. `Some(status)` = HTTP error (405 POST-only / 413 body cap).
pub fn rpc_http_reject(is_post: bool, body_len: usize) -> Option<u16> {
    if !is_post {
        return Some(405);
    }
    if body_len > MAX_RPC_BODY {
        return Some(413);
    }
    None
}

/// Missing Content-Type is ok (curl). JSON media types ok. `text/html` etc. → 415.
pub fn rpc_http_content_type_reject(content_type: Option<&str>) -> Option<u16> {
    let raw = content_type.map(str::trim).filter(|s| !s.is_empty())?;
    let media = raw.split(';').next().unwrap_or(raw).trim();
    let m = media.to_ascii_lowercase();
    if m == "application/json" || m == "application/json-rpc" || m == "application/jsonrequest" {
        None
    } else {
        Some(415)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(n: u64, marker: u8) -> VerifiedBlock {
        let mut hash = [0u8; 32];
        hash[31] = marker;
        let mut state_root = [0u8; 32];
        state_root[30] = marker;
        VerifiedBlock {
            number: n,
            hash,
            state_root,
            miner: [0u8; 20],
            ..Default::default()
        }
    }

    fn hash_hex(b: &VerifiedBlock) -> String {
        format!("0x{}", hex::encode(b.hash))
    }

    #[test]
    fn get_block_by_number_allows_safe_and_below_in_chain() {
        let chain = vec![blk(1, 1), blk(2, 2), blk(100, 100), blk(110, 110)];
        let safe_hash = hash_hex(&chain[2]);
        assert_eq!(
            wallet_get_block_by_number(Some("latest"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
        assert_eq!(
            wallet_get_block_by_number(Some("0x1"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(1)
        );
        assert_eq!(
            wallet_get_block_by_number(Some("0x64"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
        assert!(wallet_get_block_by_number(Some("0x65"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("0x6e"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("0x3"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("pending"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("earliest"), 100, &safe_hash, &chain).is_none());
        assert_eq!(
            wallet_get_block_by_number(Some(&safe_hash), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
    }

    #[test]
    fn get_block_by_hash_only_verified_at_or_below_safe() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let h1 = hash_hex(&chain[0]);
        let h_safe = hash_hex(&chain[1]);
        let h_tip = hash_hex(&chain[2]);
        assert_eq!(
            wallet_get_block_by_hash(&h1, 100, &chain).map(|b| b.number),
            Some(1)
        );
        assert_eq!(
            wallet_get_block_by_hash(&h_safe, 100, &chain).map(|b| b.number),
            Some(100)
        );
        assert!(wallet_get_block_by_hash(&h_tip, 100, &chain).is_none());
        assert!(wallet_get_block_by_hash(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            100,
            &chain
        )
        .is_none());
    }

    fn load_fixture_header() -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet/header_116664000.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn header_mismatch_is_fail_closed() {
        let hdr = load_fixture_header();
        let local = VerifiedBlock {
            number: decode_u64(&hdr.number).unwrap(),
            hash: header_hash(&hdr).unwrap(),
            state_root: decode_hex_fixed::<32>(&hdr.state_root).unwrap(),
            miner: [0u8; 20],
            milli_timestamp: helios_bsc_consensus::milli_timestamp(&hdr).unwrap(),
            gas_limit: decode_u64(&hdr.gas_limit).unwrap(),
            header: Some(hdr.clone()),
        };
        assert!(header_matches_local(&hdr, &local).is_ok());
        let mut bad = hdr.clone();
        bad.number = "0x65".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_PROOF_FAILED
        );
        let mut bad = hdr.clone();
        bad.state_root =
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_STATE_ROOT
        );
        let mut bad = hdr.clone();
        bad.transactions_root =
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_PROOF_FAILED
        );
    }

    #[test]
    fn rpc_http_is_post_only_and_capped() {
        assert_eq!(rpc_http_reject(false, 16), Some(405));
        assert_eq!(rpc_http_reject(true, 16), None);
        assert_eq!(rpc_http_reject(true, MAX_RPC_BODY), None);
        assert_eq!(rpc_http_reject(true, MAX_RPC_BODY + 1), Some(413));
    }

    #[test]
    fn rpc_http_content_type_json_or_missing() {
        assert_eq!(rpc_http_content_type_reject(None), None);
        assert_eq!(rpc_http_content_type_reject(Some("")), None);
        assert_eq!(rpc_http_content_type_reject(Some("application/json")), None);
        assert_eq!(
            rpc_http_content_type_reject(Some("application/json; charset=utf-8")),
            None
        );
        assert_eq!(rpc_http_content_type_reject(Some("Application/JSON")), None);
        assert_eq!(
            rpc_http_content_type_reject(Some("application/json-rpc")),
            None
        );
        assert_eq!(rpc_http_content_type_reject(Some("text/html")), Some(415));
        assert_eq!(rpc_http_content_type_reject(Some("text/plain")), Some(415));
        assert_eq!(
            rpc_http_content_type_reject(Some("application/x-www-form-urlencoded")),
            Some(415)
        );
    }

    #[test]
    fn parse_slot_quantity_or_32_bytes_rejects_junk() {
        assert_eq!(parse_slot("0x0").unwrap(), [0u8; 32]);
        assert_eq!(parse_slot("0x1").unwrap()[31], 1);
        let full = format!("0x{}", "ab".repeat(32));
        assert!(parse_slot(&full).is_ok());
        assert!(parse_slot("not-hex").is_err());
        assert!(parse_slot("0xgg").is_err());
        assert!(parse_slot("").is_err());
        assert!(parse_slot(&format!("0x{}", "aa".repeat(33))).is_err());
        assert!(parse_storage_keys(Some(&json!([1]))).is_err());
        assert!(parse_storage_keys(Some(&json!("0x0"))).is_err());
        assert!(parse_storage_keys(Some(&json!(["0x0", "junk"]))).is_err());
        assert_eq!(parse_storage_keys(Some(&json!(["0x0"]))).unwrap().len(), 1);
        let too_many: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
            .map(|i| json!(format!("0x{i:x}")))
            .collect();
        assert!(parse_storage_keys(Some(&Value::Array(too_many))).is_err());
    }

    #[test]
    fn bind_mined_pending_ok_mined_above_safe_rejected() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        let pending = json!({"blockHash": Value::Null, "blockNumber": Value::Null});
        assert!(bind_mined_object(&pending, &safe, &chain, None).is_ok());
        let at_safe = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "status": "0x1",
        });
        assert!(bind_mined_object(&at_safe, &safe, &chain, None).is_ok());
        let at_zero = json!({
            "blockHash": hash_hex(&chain[0]),
            "blockNumber": "0x1",
        });
        assert!(bind_mined_object(&at_zero, &safe, &chain, None).is_ok());
        let above = json!({
            "blockHash": hash_hex(&chain[2]),
            "blockNumber": "0x6e",
        });
        let err = bind_mined_object(&above, &safe, &chain, None).unwrap_err();
        assert!(err.contains("above local Safe"), "{err}");
        let unknown = json!({
            "blockHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "blockNumber": "0x64",
        });
        assert!(bind_mined_object(&unknown, &safe, &chain, None).is_err());
        let bad_chain = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "chainId": "0x1",
        });
        let err = bind_mined_object(&bad_chain, &safe, &chain, None).unwrap_err();
        assert!(err.contains("chainId"), "{err}");
        let txh = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let want = decode_hex_fixed::<32>(txh).unwrap();
        let ok_chain = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "chainId": "0x38",
            "to": Value::Null,
            "transactionHash": txh,
        });
        assert!(bind_mined_object(&ok_chain, &safe, &chain, None).is_ok());
        assert!(bind_mined_object(&ok_chain, &safe, &chain, Some(&want)).is_ok());
        let other = [0xbbu8; 32];
        let err = bind_mined_object(&ok_chain, &safe, &chain, Some(&other)).unwrap_err();
        assert!(err.contains("does not match request"), "{err}");
        let pending_no_hash = json!({"blockHash": Value::Null, "blockNumber": Value::Null});
        let err = bind_mined_object(&pending_no_hash, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("hash missing"), "{err}");
        let bad_tx = json!({
            "blockHash": Value::Null,
            "blockNumber": Value::Null,
            "transactionHash": "0x01",
        });
        assert!(bind_mined_object(&bad_tx, &safe, &chain, None).is_err());
        let bad_status = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "status": "0x2",
        });
        let err = bind_mined_object(&bad_status, &safe, &chain, None).unwrap_err();
        assert!(err.contains("status"), "{err}");
        let bad_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{"address": "0x01"}],
        });
        let err = bind_mined_object(&bad_logs, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.address"), "{err}");
        let ok_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "topics": [txh],
            }],
        });
        assert!(bind_mined_object(&ok_logs, &safe, &chain, Some(&want)).is_ok());
        let bad_log_block = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "blockHash": hash_hex(&chain[0]),
            }],
        });
        let err = bind_mined_object(&bad_log_block, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.blockHash"), "{err}");
        let bad_data = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": "0xgg",
            }],
        });
        let err = bind_mined_object(&bad_data, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.data"), "{err}");
        let bad_ty = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "type": "0x5",
        });
        let err = bind_mined_object(&bad_ty, &safe, &chain, None).unwrap_err();
        assert!(err.contains("type"), "{err}");
        let bad_gas = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "gasUsed": true,
        });
        let err = bind_mined_object(&bad_gas, &safe, &chain, None).unwrap_err();
        assert!(err.contains("gasUsed"), "{err}");
        let bad_contract = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "contractAddress": "0x01",
        });
        let err = bind_mined_object(&bad_contract, &safe, &chain, None).unwrap_err();
        assert!(err.contains("contractAddress"), "{err}");
        let huge_input = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "input": format!("0x{}", "aa".repeat(MAX_RAW_TX + 1)),
        });
        let err = bind_mined_object(&huge_input, &safe, &chain, None).unwrap_err();
        assert!(err.contains("input"), "{err}");
        let ok_input = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "input": "0xabcdef",
            "contractAddress": Value::Null,
        });
        assert!(bind_mined_object(&ok_input, &safe, &chain, None).is_ok());
        let bad_bloom = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logsBloom": "0x01",
        });
        let err = bind_mined_object(&bad_bloom, &safe, &chain, None).unwrap_err();
        assert!(err.contains("logsBloom"), "{err}");
    }

    #[test]
    fn bind_logs_txhash_topics_and_cap() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        let txh = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let want = decode_hex_fixed::<32>(txh).unwrap();
        let addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let other = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let mismatch = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": addr,
                "transactionHash": other,
            }],
        });
        let err = bind_mined_object(&mismatch, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("log.transactionHash"), "{err}");
        let five: Vec<Value> = (0..5).map(|_| json!(txh)).collect();
        let too_topics = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": addr,
                "topics": five,
            }],
        });
        let err = bind_mined_object(&too_topics, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("topics"), "{err}");
        let logs: Vec<Value> = (0..=MAX_RECEIPT_LOGS)
            .map(|_| json!({"address": addr}))
            .collect();
        let too_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": logs,
        });
        let err = bind_mined_object(&too_logs, &safe, &chain, None).unwrap_err();
        assert!(err.contains("logs"), "{err}");
    }

    #[test]
    fn fee_history_caps_arrays() {
        assert!(bind_fee_result(
            "eth_feeHistory",
            &json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x1"]})
        )
        .is_ok());
        let too: Vec<Value> = (0..=MAX_FEE_HISTORY_ITEMS).map(|_| json!("0x1")).collect();
        let err = bind_fee_result(
            "eth_feeHistory",
            &json!({"oldestBlock": "0x1", "baseFeePerGas": too}),
        )
        .unwrap_err();
        assert!(err.contains("too many"), "{err}");
        let err = bind_fee_result("eth_feeHistory", &json!({"reward": [[true]]})).unwrap_err();
        assert!(err.contains("reward"), "{err}");
        assert!(
            bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": [0.5, "0.25", 1]})).is_ok()
        );
        for bad in [json!([true]), json!([{}]), json!([[0.1]]), json!([false])] {
            let err = bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": bad})).unwrap_err();
            assert!(err.contains("gasUsedRatio"), "{err}");
        }
        let too_ratio: Vec<Value> = (0..=MAX_FEE_HISTORY_ITEMS).map(|_| json!(0.5)).collect();
        let err =
            bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": too_ratio})).unwrap_err();
        assert!(err.contains("too many"), "{err}");
        let err = bind_fee_result("eth_unknownFee", &json!("0x1")).unwrap_err();
        assert!(err.contains("unknown"), "{err}");
        assert!(bind_fee_result("eth_feeHistory", &json!({"baseFeePerGas": ["0x1"]})).is_ok());
        let err = bind_fee_result("eth_feeHistory", &json!({"oldestBlock": "latest"})).unwrap_err();
        assert!(err.contains("oldestBlock"), "{err}");
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        assert!(bind_fee_oldest_block(&json!({"baseFeePerGas": ["0x1"]}), &safe, &chain).is_ok());
        assert!(bind_fee_oldest_block(&json!({"oldestBlock": "0x64"}), &safe, &chain).is_ok());
        assert!(bind_fee_oldest_block(&json!({"oldestBlock": "0x1"}), &safe, &chain).is_ok());
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "0x6e"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_NOT_SYNCED, "{msg}");
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "0xff"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_NOT_SYNCED, "{msg}");
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "latest"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_PARAMS, "{msg}");
    }

    #[test]
    fn hydrated_block_txs_unsupported() {
        assert!(!wants_full_txs(None));
        assert!(!wants_full_txs(Some(&vec![json!("latest")])));
        assert!(!wants_full_txs(Some(&vec![json!("latest"), json!(false)])));
        assert!(wants_full_txs(Some(&vec![json!("latest"), json!(true)])));
    }

    #[test]
    fn call_error_rpc_revert_halt_are_execution_not_proof_failed() {
        use helios_bsc_execution::Miss;

        let (code, msg, data) = call_error_rpc(CallError::Revert(vec![0x08, 0xc3, 0x79, 0xa0]));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(code, 3);
        assert!(msg.starts_with("execution reverted"), "{msg}");
        assert!(!msg.contains("proof"), "{msg}");
        assert_eq!(data.as_deref(), Some("0x08c379a0"));

        let (code, msg, data) = call_error_rpc(CallError::Revert(vec![]));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution reverted");
        assert_eq!(data.as_deref(), Some("0x"));

        let mid = vec![0xab; REVERT_MSG_HEX_CAP + 1];
        let (code, msg, data) = call_error_rpc(CallError::Revert(mid.clone()));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution reverted");
        let want = format!("0x{}", hex::encode(&mid));
        assert_eq!(data.as_deref(), Some(want.as_str()));

        let big = vec![0xcd; REVERT_DATA_CAP + 8];
        let (code, msg, data) = call_error_rpc(CallError::Revert(big));
        assert_eq!(code, ERR_EXECUTION);
        assert!(msg.contains("truncated"), "{msg}");
        assert!(!msg.contains("proof"), "{msg}");
        let hex = data.expect("data");
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + REVERT_DATA_CAP * 2);

        let (code, msg, data) = call_error_rpc(CallError::Halt("out of gas"));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution_halt: out of gas");
        assert!(data.is_none());
        assert!(!msg.contains("proof"), "{msg}");

        let (code, msg, data) = call_error_rpc(CallError::Halt("precompile"));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution_halt: precompile");
        assert!(data.is_none());

        let (code, msg, data) = call_error_rpc(CallError::Missing(Miss::Account([1u8; 20])));
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(msg.contains("proof_verification_failed"), "{msg}");
        assert!(data.is_none());

        let (code, _, data) = call_error_rpc(CallError::Budget);
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(data.is_none());

        let (code, _, data) = call_error_rpc(CallError::Proof(ProofError::Json("x".into())));
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(data.is_none());

        let (code, msg, data) = call_error_rpc(CallError::Invalid("calldata too large"));
        assert_eq!(code, ERR_PARAMS);
        assert_eq!(msg, "calldata too large");
        assert!(data.is_none());
    }

    fn sample_call_req(tx: Value) -> Value {
        json!({"params": [tx]})
    }

    #[test]
    fn parse_eth_call_tx_access_list() {
        let to = "0x0000000000000000000000000000000000000001";
        let omitted = parse_eth_call_tx(&sample_call_req(json!({"to": to}))).unwrap();
        assert!(omitted.access_list.is_empty());

        let with = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{
                "address": "0x0000000000000000000000000000000000000002",
                "storageKeys": ["0x0", "0x1"]
            }]
        })))
        .unwrap();
        assert_eq!(with.access_list.len(), 1);
        assert_eq!(with.access_list[0].0[19], 2);
        assert_eq!(with.access_list[0].1.len(), 2);
        assert_eq!(with.access_list[0].1[0], [0u8; 32]);

        let junk = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{"address": "not-an-address", "storageKeys": []}]
        })));
        assert!(junk.is_err(), "{junk:?}");

        let mut huge = Vec::new();
        for i in 0..=MAX_CALL_ACCOUNTS {
            huge.push(json!({
                "address": format!("0x{:040x}", i + 1),
                "storageKeys": []
            }));
        }
        let err =
            parse_eth_call_tx(&sample_call_req(json!({"to": to, "accessList": huge}))).unwrap_err();
        assert!(err.contains("accessList too large"), "{err}");

        let too_many_keys: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
            .map(|i| json!(format!("0x{i:x}")))
            .collect();
        let err = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{"address": to, "storageKeys": too_many_keys}]
        })))
        .unwrap_err();
        assert!(err.contains("accessList too large"), "{err}");
    }
}
