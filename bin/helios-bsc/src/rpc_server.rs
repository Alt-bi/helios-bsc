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
    encode_data32, encode_qty, pad32, retain_requested_storage, validate_bsc_raw_tx,
    verify_account_code, verify_eth_get_proof, verify_storage_slot, EthAccountProof,
    VerifiedAccount, EMPTY_CODE_HASH, MAX_CODE_SIZE, MAX_RAW_TX,
};
use helios_bsc_rpc::{
    jsonrpc_id_ok, jsonrpc_is_v2, jsonrpc_params_len, jsonrpc_params_ok, method_policy, rpc_err,
    rpc_ok, unverified_passthrough_ok, wallet_block_number_allowed, wallet_tag_is_safe, BlockId,
    MethodPolicy, ERR_INVALID, ERR_METHOD, ERR_NOT_SYNCED, ERR_PARAMS, ERR_PARSE, ERR_PROOF_FAILED,
    ERR_STATE_ROOT, MAX_PROOF_STORAGE_KEYS, MAX_RPC_BATCH, MAX_RPC_METHOD, MAX_RPC_PARAMS,
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
            "eth_getStorageAt" => self.get_storage(id, req),
            "eth_getProof" => self.get_eth_proof(id, req),
            "eth_getBlockByNumber" => self.get_block_by_number(id, req),
            "eth_getBlockByHash" => self.get_block_by_hash(id, req),
            "eth_getUncleCountByBlockNumber" => self.uncle_count_by_number(id, req),
            "eth_getUncleCountByBlockHash" => self.uncle_count_by_hash(id, req),
            "eth_getUncleByBlockNumberAndIndex" => self.uncle_by_number(id, req),
            "eth_getUncleByBlockHashAndIndex" => self.uncle_by_hash(id, req),
            "eth_coinbase" => rpc_ok(id, json!("0x0000000000000000000000000000000000000000")),
            "eth_sendRawTransaction" => self.send_raw(id, req),
            "eth_getTransactionReceipt" | "eth_getTransactionByHash" => {
                self.unverified_mined(id, req, method)
            }
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
        let tag = params.get(1).and_then(Value::as_str);
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        if !wallet_tag_is_safe(tag, safe.number, &safe.hash) {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves the local Safe head (latest→Safe)",
            );
        }
        match self.verified_account(id.clone(), addr, tip, &safe) {
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
        let tag = params.get(1).and_then(Value::as_str);
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        if !wallet_tag_is_safe(tag, safe.number, &safe.hash) {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves the local Safe head (latest→Safe)",
            );
        }
        let acc = match self.verified_account(id.clone(), addr, tip, &safe) {
            Ok(a) => a,
            Err(e) => return e,
        };
        if acc.code_hash == EMPTY_CODE_HASH {
            return rpc_ok(id, json!("0x"));
        }
        let code = match self
            .up
            .get_code(addr, &safe.hash)
            .or_else(|_| self.up.get_code(addr, &format!("0x{:x}", safe.number)))
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
        let keys: Vec<String> = match params.get(1) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(_) => return rpc_err(id, ERR_PARAMS, "storage keys must be an array"),
        };
        if keys.len() > MAX_PROOF_STORAGE_KEYS {
            return rpc_err(id, ERR_PARAMS, "too many storage keys");
        }
        let tag = params.get(2).and_then(Value::as_str);
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        if !wallet_tag_is_safe(tag, safe.number, &safe.hash) {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves the local Safe head (latest→Safe)",
            );
        }
        let (acc, mut proof) = match self.verified_proof(id.clone(), addr, tip, &safe, &keys) {
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
        let tag = params.get(2).and_then(Value::as_str);
        let slot = match parse_slot(slot_hex) {
            Ok(s) => s,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let (tip, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        if !wallet_tag_is_safe(tag, safe.number, &safe.hash) {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves the local Safe head (latest→Safe)",
            );
        }
        let key = format!("0x{}", hex::encode(slot));
        let (acc, proof) =
            match self.verified_proof(id.clone(), addr, tip, &safe, std::slice::from_ref(&key)) {
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
        let hdr = if let Some(h) = local.header.clone() {
            h
        } else {
            let hash = format!("0x{}", hex::encode(local.hash));
            match self.up.header_by_hash(&hash) {
                Ok(h) => h,
                Err(e) => {
                    return rpc_err(
                        id,
                        ERR_PROOF_FAILED,
                        &format!("proof_verification_failed: {e}"),
                    )
                }
            }
        };
        if let Err((code, msg)) = header_matches_local(&hdr, local) {
            return rpc_err(id, code, &msg);
        }
        let mut hdr = hdr;
        hdr.hash = format!("0x{}", hex::encode(local.hash));
        rpc_ok(id, rpc_block_json(&hdr))
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
            Ok(v) => match bind_fee_result(method, &v) {
                Ok(()) => rpc_ok(id, v),
                Err(msg) => rpc_err(id, ERR_PARAMS, &msg),
            },
            Err(e) => rpc_err(id, -32000, &format!("unverified_upstream: {e}")),
        }
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

    fn verified_account(
        &self,
        id: Value,
        addr: &str,
        tip: u64,
        safe: &SafeHead,
    ) -> Result<VerifiedAccount, Value> {
        self.verified_proof(id, addr, tip, safe, &[])
            .map(|(acc, _)| acc)
    }

    fn verified_proof(
        &self,
        id: Value,
        addr: &str,
        tip: u64,
        safe: &SafeHead,
        keys: &[String],
    ) -> Result<(VerifiedAccount, EthAccountProof), Value> {
        let lag = proof_lag(tip, safe.number);
        if lag > PROVIDER_PROOF_LOOKBACK {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                &format!("proof window exceeded: lag {lag} > {PROVIDER_PROOF_LOOKBACK}"),
            ));
        }
        let raw = self
            .up
            .get_proof_at_safe(addr, keys, &safe.hash, safe.number)
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
        let root = decode_hex_fixed::<32>(&safe.state_root).map_err(|e| {
            self.bump_proof_fail();
            rpc_err(
                id.clone(),
                ERR_STATE_ROOT,
                &format!("state_root_mismatch: {e}"),
            )
        })?;
        let want = decode_hex_fixed::<20>(addr)
            .map_err(|e| rpc_err(id.clone(), ERR_PARAMS, &format!("bad address: {e}")))?;
        let acc = verify_eth_get_proof(&root, &want, &proof).map_err(|e| {
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
                            if bytes.len() > 64 * 1024 {
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

/// Unverified fee oracles: hex quantity or a JSON object (`eth_feeHistory`).
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
            if let Some(arr) = o.get("baseFeePerGas") {
                let a = arr
                    .as_array()
                    .ok_or_else(|| "baseFeePerGas is not an array".to_string())?;
                for x in a {
                    bind_optional_qty(Some(x), "baseFeePerGas")?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
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
    bind_optional_status(map.get("status"))?;
    bind_optional_tx_type(map.get("type"))?;
    bind_optional_qty(map.get("gasUsed"), "gasUsed")?;
    bind_optional_qty(map.get("cumulativeGasUsed"), "cumulativeGasUsed")?;
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

fn rpc_block_json(hdr: &RpcBlockHeader) -> Value {
    let mut v = serde_json::to_value(hdr).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut v {
        map.insert("transactions".into(), json!([]));
        map.insert("uncles".into(), json!([]));
        map.retain(|_, val| !val.is_null());
    }
    v
}

fn parse_slot(s: &str) -> Result<[u8; 32], String> {
    let raw = s.trim_start_matches("0x").trim_start_matches("0X");
    let even = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = hex::decode(even).map_err(|e| format!("bad slot: {e}"))?;
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
        assert_eq!(
            wallet_get_block_by_number(Some(&safe_hash), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
        assert!(!wallet_tag_is_safe(Some("0x1"), 100, &safe_hash));
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
    }

    #[test]
    fn hydrated_block_txs_unsupported() {
        assert!(!wants_full_txs(None));
        assert!(!wants_full_txs(Some(&vec![json!("latest")])));
        assert!(!wants_full_txs(Some(&vec![json!("latest"), json!(false)])));
        assert!(wants_full_txs(Some(&vec![json!("latest"), json!(true)])));
    }
}
