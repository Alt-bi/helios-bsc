//! Blocks and transaction envelopes: header reads at or below Safe, uncle answers Parlia makes constant, and the transactionsRoot binding behind counts and by-index lookups.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

/// EIP-1898 object (and any non-string) block id is invalid, not silent Safe.
pub(crate) fn wallet_block_id_str(id: Value, raw: Option<&Value>) -> Result<Option<&str>, Value> {
    wallet_block_tag_str(raw).map_err(|e| rpc_err(id, ERR_PARAMS, e))
}

/// Wallet-mode `eth_getBlockByNumber`: tag must resolve to a local verified block at or below Safe.
pub(crate) fn wallet_get_block_by_number<'a>(
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
pub(crate) fn wallet_get_block_by_hash<'a>(
    hash: &str,
    safe_number: u64,
    chain: &'a [VerifiedBlock],
) -> Option<&'a VerifiedBlock> {
    let want = decode_hex_fixed::<32>(hash).ok()?;
    chain
        .iter()
        .find(|b| b.hash == want && b.number <= safe_number)
}

pub(crate) fn hex_eq_loose(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("0x").trim_start_matches("0X");
    let b = b.trim_start_matches("0x").trim_start_matches("0X");
    a.eq_ignore_ascii_case(b)
}

pub(crate) fn is_nullish_json(v: Option<&Value>) -> bool {
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
pub(crate) fn is_zero_block_hash(s: &str) -> bool {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    raw.len() == 64 && raw.bytes().all(|b| b == b'0')
}

pub(crate) fn is_empty_block_hash(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => {
            let t = s.trim();
            t.is_empty() || t.eq_ignore_ascii_case("0x") || is_zero_block_hash(t)
        }
        _ => false,
    }
}

pub(crate) fn header_matches_local(
    hdr: &RpcBlockHeader,
    local: &VerifiedBlock,
) -> Result<(), (i64, String)> {
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

pub(crate) fn wants_full_txs(params: Option<&Vec<Value>>) -> bool {
    params.and_then(|p| p.get(1)).and_then(Value::as_bool) == Some(true)
}

pub(crate) struct BoundTxs {
    header: RpcBlockHeader,
    txs: TxBind,
}

/// Outcome of binding a block's transaction hashes to the sealed `transactionsRoot`.
///
/// `Empty` and `Omitted` both render as `[]` in `eth_getBlock*` (documented: no raw
/// envelopes → hashes omitted, never a fabricated list), but they are *not* the same
/// claim and must not collapse for a count or an index lookup. `Empty` proves the
/// block has no transactions — the sealed root is the empty-trie root. `Omitted`
/// proves nothing: the root is non-empty, so the block certainly has transactions,
/// the upstream just declined to serve the envelopes. Answering `0x0` there, or
/// `null` for index 0, hands a wallet an unverified claim wearing a verified method's
/// clothes; both fail closed with `-32001` instead.
pub(crate) enum TxBind {
    Empty,
    Omitted,
    List(Vec<[u8; 32]>),
}

impl TxBind {
    /// Hash list for `eth_getBlock*`: nothing to show for `Empty` or `Omitted`.
    fn hashes(&self) -> &[[u8; 32]] {
        match self {
            TxBind::List(v) => v,
            TxBind::Empty | TxBind::Omitted => &[],
        }
    }
}

pub(crate) fn rpc_block_json(hdr: &RpcBlockHeader, tx_hashes: &[[u8; 32]]) -> Value {
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

pub(crate) fn parse_tx_index(req: &Value) -> Result<u64, String> {
    let s = req
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.get(1))
        .and_then(Value::as_str)
        .ok_or_else(|| "transaction index required".to_string())?;
    decode_u64(s).map_err(|e| format!("invalid transaction index: {e}"))
}

impl Node {
    pub(super) fn get_block_by_number(&self, id: Value, req: &Value) -> Value {
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
    pub(super) fn uncle_count_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(_) => rpc_ok(id, json!("0x0")),
            Err(e) => e,
        }
    }

    pub(super) fn uncle_count_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(_) => rpc_ok(id, json!("0x0")),
            Err(e) => e,
        }
    }

    pub(super) fn uncle_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(_) => rpc_ok(id, Value::Null),
            Err(e) => e,
        }
    }

    pub(super) fn uncle_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(_) => rpc_ok(id, Value::Null),
            Err(e) => e,
        }
    }

    pub(super) fn local_block_by_number(&self, req: &Value) -> Result<VerifiedBlock, Value> {
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

    pub(super) fn local_block_by_hash(&self, req: &Value) -> Result<VerifiedBlock, Value> {
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

    pub(super) fn get_block_by_hash(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn verified_header_json(&self, id: Value, local: &VerifiedBlock) -> Value {
        match self.bound_block_txs(local) {
            Ok(bound) => rpc_ok(id, rpc_block_json(&bound.header, bound.txs.hashes())),
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    pub(super) fn load_verified_header(
        &self,
        local: &VerifiedBlock,
    ) -> Result<RpcBlockHeader, (i64, String)> {
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
    pub(super) fn bind_tx_hashes(&self, hdr: &RpcBlockHeader) -> Result<TxBind, (i64, String)> {
        let root = decode_hex_fixed::<32>(&hdr.transactions_root).map_err(|e| {
            (
                ERR_PROOF_FAILED,
                format!("proof_verification_failed: transactionsRoot: {e}"),
            )
        })?;
        if root == EMPTY_TRIE_ROOT {
            return Ok(TxBind::Empty);
        }
        let raws = self
            .up
            .block_raw_transactions(&hdr.hash)
            .map_err(|e| (ERR_UPSTREAM, format!("unverified_upstream: {e}")))?;
        // No envelopes: omit hashes (do not invent, do not fail the header read).
        // Distinct from `Empty` — see [`TxBind`].
        if raws.is_empty() {
            return Ok(TxBind::Omitted);
        }
        let hashes = verify_tx_list(&raws, &root)
            .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
        Ok(TxBind::List(hashes))
    }

    /// Verified tx hashes **and** the envelopes they were derived from.
    ///
    /// `bind_tx_hashes` drops the raw bytes once the root matches, which is all
    /// `eth_getBlock*` needs. A receipt's `to` is a field of the envelope, so the receipt
    /// path keeps them: once the list is bound to `transactionsRoot`, reading a field out
    /// of it is reading verified data.
    pub(super) fn bind_tx_envelopes(
        &self,
        hdr: &RpcBlockHeader,
    ) -> Result<Option<Vec<Vec<u8>>>, (i64, String)> {
        let root = decode_hex_fixed::<32>(&hdr.transactions_root).map_err(|e| {
            (
                ERR_PROOF_FAILED,
                format!("proof_verification_failed: transactionsRoot: {e}"),
            )
        })?;
        if root == EMPTY_TRIE_ROOT {
            return Ok(None);
        }
        let raws = self
            .up
            .block_raw_transactions(&hdr.hash)
            .map_err(|e| (ERR_UPSTREAM, format!("unverified_upstream: {e}")))?;
        if raws.is_empty() {
            return Ok(None);
        }
        verify_tx_list(&raws, &root)
            .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
        Ok(Some(raws))
    }

    pub(super) fn bound_block_txs(&self, local: &VerifiedBlock) -> Result<BoundTxs, (i64, String)> {
        let header = self.load_verified_header(local)?;
        let txs = self.bind_tx_hashes(&header)?;
        Ok(BoundTxs { header, txs })
    }

    pub(super) fn local_block_by_number_or_hash(
        &self,
        req: &Value,
    ) -> Result<VerifiedBlock, Value> {
        let tag = req
            .get("params")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .and_then(Value::as_str);
        if tag.is_some_and(|s| decode_hex_fixed::<32>(s).is_ok()) {
            self.local_block_by_hash(req)
        } else {
            self.local_block_by_number(req)
        }
    }

    pub(super) fn tx_count_by_number(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_number(req) {
            Ok(local) => self.verified_tx_count(id, &local),
            Err(e) => e,
        }
    }

    pub(super) fn tx_count_by_hash(&self, id: Value, req: &Value) -> Value {
        match self.local_block_by_hash(req) {
            Ok(local) => self.verified_tx_count(id, &local),
            Err(e) => e,
        }
    }

    pub(super) fn verified_tx_count(&self, id: Value, local: &VerifiedBlock) -> Value {
        match self.bound_block_txs(local) {
            Ok(bound) => match bound.txs {
                TxBind::Empty => rpc_ok(id, json!("0x0")),
                TxBind::List(v) => rpc_ok(id, json!(format!("0x{:x}", v.len()))),
                TxBind::Omitted => rpc_err(id, ERR_PROOF_FAILED, TX_ENVELOPES_UNAVAILABLE),
            },
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    pub(super) fn tx_by_block_number_and_index(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn tx_by_block_hash_and_index(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn tx_at_index(&self, id: Value, local: &VerifiedBlock, index: u64) -> Value {
        let bound = match self.bound_block_txs(local) {
            Ok(v) => v,
            Err((code, msg)) => return rpc_err(id, code, &msg),
        };
        let hashes = match &bound.txs {
            TxBind::List(v) => v.as_slice(),
            TxBind::Empty => &[][..],
            // Non-empty root, no envelopes: `null` would claim "no tx at this index".
            TxBind::Omitted => return rpc_err(id, ERR_PROOF_FAILED, TX_ENVELOPES_UNAVAILABLE),
        };
        let Ok(i) = usize::try_from(index) else {
            return rpc_ok(id, Value::Null);
        };
        let Some(hash) = hashes.get(i) else {
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
}
