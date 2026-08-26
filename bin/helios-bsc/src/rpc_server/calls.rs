//! eth_call and eth_estimateGas: request parsing, the proof-fetching prover, and revert mapping.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

/// Hex in the revert *message* is capped (existing); full bytes go in `error.data`.
pub(crate) const REVERT_MSG_HEX_CAP: usize = 256;
/// JSON-RPC `error.data` revert payload cap (bytes, not hex chars).
pub(crate) const REVERT_DATA_CAP: usize = 32 * 1024;

/// Map a verified-call error to JSON-RPC `(code, message, optional error.data hex)`.
pub(crate) fn call_error_rpc(e: CallError) -> (i64, String, Option<String>) {
    match e {
        CallError::Missing(_) | CallError::Proof(_) | CallError::Budget => (
            ERR_PROOF_FAILED,
            format!("proof_verification_failed: {e}"),
            None,
        ),
        CallError::Invalid(msg) => (ERR_PARAMS, msg.to_string(), None),
        // Fail-closed, not a proof failure: the upstream did nothing wrong, the local
        // EVM simply cannot reproduce this chain precompile. Same -32001 the other
        // "cannot answer this verifiably" cases use.
        CallError::UnsupportedPrecompile(a) => (
            ERR_PROOF_FAILED,
            format!("unsupported_precompile: 0x{}", hex::encode(a)),
            None,
        ),
        CallError::Revert(data) => revert_rpc(&data),
        CallError::Halt(reason) => (ERR_EXECUTION, format!("execution_halt: {reason}"), None),
    }
}

pub(crate) fn revert_rpc(data: &[u8]) -> (i64, String, Option<String>) {
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
pub(crate) struct UpstreamProve<'a> {
    pub(crate) up: &'a dyn RpcUpstream,
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
pub(crate) fn historical_hashes_at_safe(
    chain: &[VerifiedBlock],
    safe_number: u64,
) -> Vec<(u64, [u8; 32])> {
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

pub(crate) fn call_block_from_verified(
    local: &VerifiedBlock,
    chain: &[VerifiedBlock],
) -> CallBlock {
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
        excess_blob_gas: 0,
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
        if let Some(eb) = &h.excess_blob_gas {
            if let Ok(n) = decode_u64(eb) {
                block.excess_blob_gas = n;
            }
        }
    }
    block
}

pub(crate) fn nonzero_gas_limit(n: u64) -> u64 {
    if n == 0 {
        CALL_GAS_CAP
    } else {
        n
    }
}

pub(crate) fn parse_eth_call_tx(req: &Value) -> Result<CallTx, String> {
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

pub(crate) type CallAccessList = Vec<([u8; 20], Vec<[u8; 32]>)>;

pub(crate) fn parse_access_list(
    map: &serde_json::Map<String, Value>,
) -> Result<CallAccessList, String> {
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

pub(crate) fn parse_call_data(map: &serde_json::Map<String, Value>) -> Result<Vec<u8>, String> {
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

pub(crate) fn decode_qty_pad32(s: &str) -> Result<[u8; 32], String> {
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

impl Node {
    pub(super) fn prepare_verified_call(
        &self,
        id: Value,
        req: &Value,
    ) -> Result<(CallTx, CallBlock), Value> {
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
        // One lock acquisition for both the executing header and its BLOCKHASH window.
        let block = {
            let chain = self.chain.lock().expect("chain lock");
            let local = self.resolve_wallet_exec_block_in(id, tag, tip, &safe, &chain)?;
            call_block_from_verified(&local, &chain)
        };
        Ok((tx, block))
    }

    pub(super) fn eth_call(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn eth_estimate_gas(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn map_call_error(&self, id: Value, e: CallError) -> Value {
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
}
