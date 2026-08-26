//! Account state: balance, nonce, code, storage and eth_getProof, each an MPT proof against a stateRoot this client sealed itself.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

pub(crate) fn parse_storage_keys(v: Option<&Value>) -> Result<Vec<String>, String> {
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
pub(crate) fn parse_slot(s: &str) -> Result<[u8; 32], String> {
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

pub(crate) enum AccountField {
    Balance,
    Nonce,
}

impl Node {
    pub(super) fn account_field(&self, id: Value, req: &Value, field: AccountField) -> Value {
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

    pub(super) fn get_code(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn get_eth_proof(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn get_storage(&self, id: Value, req: &Value) -> Value {
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

    /// Wallet-mode exec header: tags → Safe; hex/hash iff local verified and `n ≤ Safe`.
    /// Proof window is `proof_lag(tip, requested.number) ≤ 112` (fail-closed).
    pub(super) fn resolve_wallet_exec_block(
        &self,
        id: Value,
        tag: Option<&str>,
        tip: u64,
        safe: &SafeHead,
    ) -> Result<VerifiedBlock, Value> {
        let chain = self.chain.lock().expect("chain lock");
        self.resolve_wallet_exec_block_in(id, tag, tip, safe, &chain)
    }

    /// As [`Self::resolve_wallet_exec_block`], against a chain the caller already holds.
    ///
    /// `eth_call` needs this: resolving the block under one lock acquisition and then
    /// re-locking to collect the BLOCKHASH window is two instants, and a reorg landing
    /// between them executes a block from the old chain against ancestor hashes from the
    /// new one. Every value stays verified, but they stop describing one chain.
    pub(super) fn resolve_wallet_exec_block_in(
        &self,
        id: Value,
        tag: Option<&str>,
        tip: u64,
        safe: &SafeHead,
        chain: &[VerifiedBlock],
    ) -> Result<VerifiedBlock, Value> {
        let local = wallet_get_block_by_number(tag, safe.number, &safe.hash, chain)
            .cloned()
            .or_else(|| tag.and_then(|t| wallet_get_block_by_hash(t, safe.number, chain).cloned()));
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

    pub(super) fn verified_account(
        &self,
        id: Value,
        addr: &str,
        tip: u64,
        exec: &VerifiedBlock,
    ) -> Result<VerifiedAccount, Value> {
        self.verified_proof(id, addr, tip, exec, &[])
            .map(|(acc, _)| acc)
    }

    pub(super) fn verified_proof(
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
