//! Receipts, raw transactions, and the opt-in unverified passthrough: consensus RLP re-encoded from untrusted JSON and bound to the sealed receiptsRoot.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

pub(crate) enum ReceiptBind {
    Empty,
    Omitted,
    List(Vec<BoundReceipt>),
}

pub(crate) struct BoundReceipt {
    pub(crate) json: Value,
    pub(crate) tx_hash: Option<[u8; 32]>,
    pub(crate) logs: Vec<ConsensusLog>,
}

pub(crate) struct ParsedReceipt {
    consensus: ConsensusReceipt,
    tx_hash: Option<[u8; 32]>,
}

/// Overwrite every locally-known field of an upstream receipt with the verified value.
///
/// The receipt-level `blockHash` / `blockNumber` / `transactionIndex` were already
/// overwritten here because an upstream must not get to name the block. The `logs[]`
/// array was not, and it carries the same fields: only `address` / `topics` / `data`
/// are bound by `receiptsRoot`, so a receipt that hashes correctly could still ship
/// `logs[0].blockNumber` / `blockHash` / `transactionHash` / `logIndex` pointing at
/// some other block or tx, and `eth_getBlockReceipts` (a *verified* method, no flag)
/// echoed them straight to the wallet. Rebuild each log from the parsed consensus
/// values plus the local header instead — the same shape `eth_getLogs` emits.
///
/// `gasUsed` is **derived**, not echoed. `receiptsRoot` binds `cumulativeGasUsed`, and a
/// receipt's own gas is the difference between its cumulative total and the previous
/// receipt's, so the value can be computed from consensus-verified data rather than taken
/// on an upstream's word. It was previously only checked for being a hex quantity — which
/// let a verified method hand a wallet any number at all.
pub(crate) fn decorate_receipt_json(
    mut v: Value,
    hdr: &RpcBlockHeader,
    index: usize,
    tx_hash: Option<[u8; 32]>,
    logs: &[ConsensusLog],
    first_log_index: u64,
    gas_used: u64,
) -> Value {
    if let Value::Object(map) = &mut v {
        map.insert("blockHash".into(), json!(hdr.hash.clone()));
        map.insert("blockNumber".into(), json!(hdr.number.clone()));
        map.insert("transactionIndex".into(), json!(format!("0x{index:x}")));
        map.insert("gasUsed".into(), json!(format!("0x{gas_used:x}")));
        if let Some(h) = tx_hash {
            map.insert(
                "transactionHash".into(),
                json!(format!("0x{}", hex::encode(h))),
            );
        }
        let rebuilt: Vec<Value> = logs
            .iter()
            .enumerate()
            .map(|(j, log)| {
                rpc_log_json(
                    log,
                    hdr,
                    tx_hash,
                    index as u64,
                    first_log_index.saturating_add(j as u64),
                )
            })
            .collect();
        map.insert("logs".into(), Value::Array(rebuilt));
    }
    v
}

pub(crate) fn parse_consensus_receipt_json(v: &Value) -> Result<ParsedReceipt, String> {
    let map = v
        .as_object()
        .ok_or_else(|| "receipt is not an object".to_string())?;
    let status = match map.get("status") {
        Some(Value::String(s)) => {
            let n = decode_u64(s).map_err(|_| "status invalid".to_string())?;
            if n > 1 {
                return Err("status is not 0x0 or 0x1".into());
            }
            n
        }
        _ => return Err("status missing".into()),
    };
    let cumulative_gas_used = match map.get("cumulativeGasUsed") {
        Some(Value::String(s)) => {
            decode_u64(s).map_err(|_| "cumulativeGasUsed is not a hex quantity".to_string())?
        }
        _ => return Err("cumulativeGasUsed missing".into()),
    };
    let logs_bloom = match map.get("logsBloom") {
        Some(Value::String(s)) => {
            decode_hex_fixed::<256>(s).map_err(|_| "logsBloom is not 256 bytes".to_string())?
        }
        _ => return Err("logsBloom missing".into()),
    };
    let tx_type = match map.get("type") {
        None | Some(Value::Null) => 0u8,
        Some(Value::String(s)) => {
            let n = decode_u64(s).map_err(|_| "type invalid".to_string())?;
            if n > 4 {
                return Err("tx type is not 0x0..=0x4".into());
            }
            n as u8
        }
        Some(_) => return Err("type not a hex quantity".into()),
    };
    let logs = match map.get("logs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_RECEIPT_LOGS {
                return Err("too many logs".into());
            }
            let mut out = Vec::with_capacity(arr.len());
            for log in arr {
                out.push(parse_consensus_log_json(log)?);
            }
            out
        }
        Some(_) => return Err("logs not an array".into()),
    };
    let tx_hash = match map.get("transactionHash") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            decode_hex_fixed::<32>(s)
                .map_err(|_| "transactionHash is not a 32-byte hash".to_string())?,
        ),
        Some(_) => return Err("transactionHash not a string".into()),
    };
    // `receiptsRoot` binds status / cumulativeGasUsed / logsBloom / type / logs and
    // nothing else. `gasUsed` is no longer among the echoed fields — it is recomputed from
    // the verified cumulative totals in `decorate_receipt_json`; the check below only keeps
    // a malformed value from reaching that point. The rest are still echoed, so they are at
    // least *structurally* validated as `docs/rpc-matrix.md` promises: without this an
    // upstream could hand a wallet `"to": 12345` or a 4-byte `from` through a verified
    // method. Same checks the passthrough path (`bind_mined_object`) already applies.
    bind_optional_address(map.get("from"), "from", false)?;
    bind_optional_address(map.get("to"), "to", true)?;
    bind_optional_address(map.get("contractAddress"), "contractAddress", true)?;
    bind_optional_qty(map.get("gasUsed"), "gasUsed")?;
    bind_optional_qty(map.get("effectiveGasPrice"), "effectiveGasPrice")?;
    Ok(ParsedReceipt {
        consensus: ConsensusReceipt {
            status,
            cumulative_gas_used,
            logs_bloom,
            logs,
            tx_type,
        },
        tx_hash,
    })
}

pub(crate) fn parse_consensus_log_json(v: &Value) -> Result<ConsensusLog, String> {
    let map = v
        .as_object()
        .ok_or_else(|| "log is not an object".to_string())?;
    let address = match map.get("address") {
        Some(Value::String(s)) => {
            decode_hex_fixed::<20>(s).map_err(|_| "log.address is not 20 bytes".to_string())?
        }
        _ => return Err("log.address missing".into()),
    };
    let mut topics = Vec::new();
    match map.get("topics") {
        None | Some(Value::Null) => {}
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_LOG_TOPICS {
                return Err("too many log topics".into());
            }
            for t in arr {
                let s = t
                    .as_str()
                    .ok_or_else(|| "log topic not a string".to_string())?;
                topics.push(decode_hex_fixed::<32>(s).map_err(|_| "log topic is not 32 bytes")?);
            }
        }
        Some(_) => return Err("log.topics is not an array".into()),
    }
    let data = match map.get("data") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => {
            let bytes = decode_hex(s).map_err(|_| "log.data is not hex")?;
            if bytes.len() > MAX_LOG_DATA {
                return Err("log.data too large".into());
            }
            bytes
        }
        Some(_) => return Err("log.data not a hex string".into()),
    };
    Ok(ConsensusLog {
        address,
        topics,
        data,
    })
}

pub(crate) fn parse_log_addresses(
    filter: Option<&serde_json::Map<String, Value>>,
) -> Result<Vec<[u8; 20]>, String> {
    match filter.and_then(|m| m.get("address")) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => {
            let a = decode_hex_fixed::<20>(s).map_err(|_| "address is not 20 bytes".to_string())?;
            Ok(vec![a])
        }
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                let s = x
                    .as_str()
                    .ok_or_else(|| "address is not 20 bytes".to_string())?;
                out.push(decode_hex_fixed::<20>(s).map_err(|_| "address is not 20 bytes")?);
            }
            Ok(out)
        }
        Some(_) => Err("address must be a 20-byte hex or array".into()),
    }
}

pub(crate) fn parse_log_topics(
    filter: Option<&serde_json::Map<String, Value>>,
) -> Result<Vec<Option<Vec<[u8; 32]>>>, String> {
    match filter.and_then(|m| m.get("topics")) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_LOG_TOPICS {
                return Err("too many topics (max 4)".into());
            }
            let mut out = Vec::with_capacity(arr.len());
            for t in arr {
                out.push(parse_topic_spec(t)?);
            }
            Ok(out)
        }
        Some(_) => Err("topics must be an array".into()),
    }
}

pub(crate) fn parse_topic_spec(v: &Value) -> Result<Option<Vec<[u8; 32]>>, String> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            let t = decode_hex_fixed::<32>(s).map_err(|_| "topic is not 32 bytes".to_string())?;
            Ok(Some(vec![t]))
        }
        Value::Array(arr) => {
            let mut ors = Vec::with_capacity(arr.len());
            for x in arr {
                let s = x
                    .as_str()
                    .ok_or_else(|| "topic is not 32 bytes".to_string())?;
                ors.push(decode_hex_fixed::<32>(s).map_err(|_| "topic is not 32 bytes")?);
            }
            Ok(Some(ors))
        }
        _ => Err("topic must be null, 32-byte hex, or array of 32-byte hex".into()),
    }
}

pub(crate) fn log_matches(
    log: &ConsensusLog,
    addresses: &[[u8; 20]],
    topics: &[Option<Vec<[u8; 32]>>],
) -> bool {
    if !addresses.is_empty() && !addresses.iter().any(|a| a == &log.address) {
        return false;
    }
    if topics.len() > log.topics.len() {
        return false;
    }
    for (i, spec) in topics.iter().enumerate() {
        let Some(ors) = spec else {
            continue;
        };
        if ors.is_empty() {
            continue;
        }
        if !ors.iter().any(|t| t == &log.topics[i]) {
            return false;
        }
    }
    true
}

pub(crate) fn rpc_log_json(
    log: &ConsensusLog,
    hdr: &RpcBlockHeader,
    tx_hash: Option<[u8; 32]>,
    tx_index: u64,
    log_index: u64,
) -> Value {
    let topics: Vec<Value> = log
        .topics
        .iter()
        .map(|t| json!(format!("0x{}", hex::encode(t))))
        .collect();
    json!({
        "address": format!("0x{}", hex::encode(log.address)),
        "topics": topics,
        "data": format!("0x{}", hex::encode(&log.data)),
        "blockNumber": hdr.number,
        "blockHash": hdr.hash,
        "transactionHash": tx_hash.map(|h| format!("0x{}", hex::encode(h))),
        "transactionIndex": format!("0x{tx_index:x}"),
        "logIndex": format!("0x{log_index:x}"),
        "removed": false,
    })
}

pub(crate) fn log_filter_block_number(
    tag: Option<&str>,
    safe_number: u64,
    safe_hash: &str,
) -> Option<u64> {
    match tag {
        None | Some("") | Some("latest") | Some("safe") | Some("finalized") => Some(safe_number),
        Some("pending") | Some("earliest") => None,
        Some(t) if t.eq_ignore_ascii_case(safe_hash) => Some(safe_number),
        Some(t) if t.starts_with("0x") || t.starts_with("0X") => {
            if decode_hex_fixed::<32>(t).is_ok() {
                None
            } else {
                decode_u64(t).ok()
            }
        }
        _ => None,
    }
}

impl Node {
    /// Bind untrusted receipt JSON to sealed `receiptsRoot`. Empty root → no fetch.
    /// Empty fetch + non-empty root → omitted (cannot prove; do not invent).
    pub(super) fn bind_receipts(&self, hdr: &RpcBlockHeader) -> Result<ReceiptBind, (i64, String)> {
        let root = decode_hex_fixed::<32>(&hdr.receipts_root).map_err(|e| {
            (
                ERR_PROOF_FAILED,
                format!("proof_verification_failed: receiptsRoot: {e}"),
            )
        })?;
        if root == EMPTY_TRIE_ROOT {
            return Ok(ReceiptBind::Empty);
        }
        // A provider that cannot serve receipts at all is a capability gap in the data
        // plane, not a lie about them. `-32001` claims verification failed and sends an
        // operator hunting a mismatch that never happened; `-32000` is the documented
        // transport code and names the provider. The read still fails either way.
        let jsons = self
            .up
            .block_receipts_json(&hdr.hash)
            .map_err(|e| (ERR_UPSTREAM, format!("unverified_upstream: {e}")))?;
        if jsons.is_empty() {
            return Ok(ReceiptBind::Omitted);
        }
        if jsons.len() > MAX_ORDERED_TRIE_ITEMS {
            return Err((
                ERR_PROOF_FAILED,
                "proof_verification_failed: too many receipts".into(),
            ));
        }
        let mut raws = Vec::with_capacity(jsons.len());
        let mut items = Vec::with_capacity(jsons.len());
        // Block-wide log index, the same counter `eth_getLogs` uses, so the two methods
        // cannot disagree about `logIndex` for the same block.
        let mut log_index: u64 = 0;
        // Running total the derived `gasUsed` is taken against. Both counters are folded
        // over the same ordered list the trie is built from, so neither can drift from it.
        let mut prev_cumulative: u64 = 0;
        for (i, v) in jsons.iter().enumerate() {
            let parsed = parse_consensus_receipt_json(v).map_err(|e| {
                (
                    ERR_PROOF_FAILED,
                    format!("proof_verification_failed: receipt {i}: {e}"),
                )
            })?;
            let raw = encode_consensus_receipt(&parsed.consensus).map_err(|e| {
                (
                    ERR_PROOF_FAILED,
                    format!("proof_verification_failed: receipt {i}: {e}"),
                )
            })?;
            raws.push(raw);
            // Saturating because verification of the whole list happens below: a
            // non-monotonic cumulative sequence cannot survive `verify_receipt_list`, so
            // the clamped value can never reach a caller.
            let gas_used = parsed
                .consensus
                .cumulative_gas_used
                .saturating_sub(prev_cumulative);
            prev_cumulative = parsed.consensus.cumulative_gas_used;
            let json = decorate_receipt_json(
                v.clone(),
                hdr,
                i,
                parsed.tx_hash,
                &parsed.consensus.logs,
                log_index,
                gas_used,
            );
            log_index = log_index.saturating_add(parsed.consensus.logs.len() as u64);
            items.push(BoundReceipt {
                json,
                tx_hash: parsed.tx_hash,
                logs: parsed.consensus.logs,
            });
        }
        verify_receipt_list(&raws, &root)
            .map_err(|e| (ERR_PROOF_FAILED, format!("proof_verification_failed: {e}")))?;
        // `receiptsRoot` proves *what* each receipt says, never *which transaction it
        // belongs to*. An upstream could serve receipt 5's consensus fields — which verify
        // — while labelling them with transaction 2's hash, and a wallet would read a
        // correctly-verified receipt for the wrong transaction. The position in this list
        // is the transaction index, so binding the block's hashes to `transactionsRoot`
        // and comparing by index closes that.
        //
        // `TxBind::Omitted` means the upstream declined the envelopes: the pairing is
        // unprovable rather than wrong. Leave the label alone there instead of failing an
        // otherwise verified read — `docs/rpc-matrix.md` records that this is conditional.
        if let Some(envelopes) = self.bind_tx_envelopes(hdr)? {
            // Sealed header field, so it is consensus-verified. Parlia's is the constant
            // zero; reading it keeps the arithmetic right if that ever changes.
            let base_fee = hdr
                .base_fee_per_gas
                .as_deref()
                .and_then(|h| u128::from_str_radix(h.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            for (i, item) in items.iter_mut().enumerate() {
                let Some(envelope) = envelopes.get(i) else {
                    return Err((
                        ERR_PROOF_FAILED,
                        "proof_verification_failed: more receipts than bound transactions".into(),
                    ));
                };
                if let Some(claimed) = item.tx_hash {
                    if keccak256(envelope) != claimed {
                        return Err((
                            ERR_PROOF_FAILED,
                            format!(
                                "proof_verification_failed: receipt {i}: transactionHash does not match transactionsRoot"
                            ),
                        ));
                    }
                }
                // `to` is a field of an envelope now bound to the sealed root, so it can
                // be read rather than believed. A decode failure cannot come from a lying
                // upstream here — the list already hashed into `transactionsRoot` — so it
                // would be a bug in this client: leave the echoed value rather than
                // inventing a recipient.
                if let Ok(to) = tx_to_address(envelope) {
                    let Value::Object(map) = &mut item.json else {
                        continue;
                    };
                    map.insert(
                        "to".into(),
                        match to {
                            Some(a) => json!(format!("0x{}", hex::encode(a))),
                            None => Value::Null,
                        },
                    );
                    // The sender is not a field of the envelope: it is recovered from the
                    // signature over it. Because the envelope is bound to the sealed root,
                    // the recovered address is as verified as the bytes it comes from.
                    // `effectiveGasPrice` is what the sender actually paid per unit of
                    // gas: the envelope's own price for a legacy tx, and EIP-1559's
                    // `base + min(tip, cap - base)` otherwise. The base fee comes from the
                    // sealed header, so no arm of this is taken on an upstream's word.
                    if let Ok(price) = tx_gas_price(envelope) {
                        map.insert(
                            "effectiveGasPrice".into(),
                            json!(format!("0x{:x}", price.effective(base_fee))),
                        );
                    }
                    if let Some(from) = tx_signing_hash(envelope)
                        .ok()
                        .and_then(|(digest, sig)| ecrecover(&digest, &sig).ok())
                    {
                        map.insert("from".into(), json!(format!("0x{}", hex::encode(from))));
                        // A call has no contract address; a creation's is fixed by
                        // consensus as keccak(rlp([sender, nonce]))[12..].
                        match to {
                            Some(_) => {
                                map.insert("contractAddress".into(), Value::Null);
                            }
                            None => {
                                if let Ok(nonce) = tx_nonce(envelope) {
                                    let addr = contract_address(&from, nonce);
                                    map.insert(
                                        "contractAddress".into(),
                                        json!(format!("0x{}", hex::encode(addr))),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(ReceiptBind::List(items))
    }

    pub(super) fn bound_block_receipts(
        &self,
        local: &VerifiedBlock,
    ) -> Result<(RpcBlockHeader, ReceiptBind), (i64, String)> {
        let header = self.load_verified_header(local)?;
        let bind = self.bind_receipts(&header)?;
        Ok((header, bind))
    }

    pub(super) fn get_block_receipts(&self, id: Value, req: &Value) -> Value {
        let local = match self.local_block_by_number_or_hash(req) {
            Ok(b) => b,
            Err(e) => return e,
        };
        match self.bound_block_receipts(&local) {
            Ok((_, ReceiptBind::List(list))) => {
                rpc_ok(id, Value::Array(list.into_iter().map(|r| r.json).collect()))
            }
            Ok((_, ReceiptBind::Empty | ReceiptBind::Omitted)) => rpc_ok(id, json!([])),
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    pub(super) fn get_transaction_receipt(&self, id: Value, req: &Value) -> Value {
        let want = match query_tx_hash(req) {
            Ok(h) => h,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let params = req.get("params").cloned().unwrap_or(json!([]));
        let raw = match self
            .up
            .unverified_call("eth_getTransactionReceipt", &params)
        {
            Ok(v) => v,
            Err(e) => return rpc_err(id, -32000, &format!("unverified_upstream: {e}")),
        };
        if raw.is_null() {
            return rpc_ok(id, Value::Null);
        }
        let (hash_empty, num_empty, block_hash) = {
            let Some(map) = raw.as_object() else {
                return rpc_err(id, ERR_PROOF_FAILED, "receipt is not an object");
            };
            let hash_v = map.get("blockHash");
            let num_v = map.get("blockNumber");
            (
                is_empty_block_hash(hash_v),
                is_nullish_json(num_v),
                hash_v.and_then(Value::as_str).map(str::to_string),
            )
        };
        if hash_empty && num_empty {
            return self.passthrough_mined(id, raw, Some(&want));
        }
        if hash_empty != num_empty {
            return rpc_err(id, ERR_NOT_SYNCED, "receipt/tx pending fields inconsistent");
        }
        let hash = match block_hash {
            Some(s) => s,
            None => return rpc_err(id, ERR_NOT_SYNCED, "receipt/tx blockHash not a string"),
        };
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let local = {
            let chain = self.chain.lock().expect("chain lock");
            chain
                .iter()
                .find(|b| {
                    let h = format!("0x{}", hex::encode(b.hash));
                    hex_eq_loose(&h, &hash)
                })
                .cloned()
        };
        let Some(local) = local else {
            return rpc_err(
                id,
                ERR_NOT_SYNCED,
                "receipt/tx blockHash not in local verified chain",
            );
        };
        if local.number > safe.number {
            return rpc_err(id, ERR_NOT_SYNCED, "receipt/tx is above local Safe");
        }
        match self.bound_block_receipts(&local) {
            Ok((_, ReceiptBind::List(list))) => {
                match list.into_iter().find(|r| r.tx_hash.as_ref() == Some(&want)) {
                    Some(r) => rpc_ok(id, r.json),
                    None => rpc_ok(id, Value::Null),
                }
            }
            Ok((_, ReceiptBind::Empty)) => rpc_ok(id, Value::Null),
            Ok((_, ReceiptBind::Omitted)) => self.passthrough_mined(id, raw, Some(&want)),
            Err((code, msg)) => rpc_err(id, code, &msg),
        }
    }

    pub(super) fn passthrough_mined(
        &self,
        id: Value,
        raw: Value,
        want: Option<&[u8; 32]>,
    ) -> Value {
        if !self.allow_unverified_passthrough {
            return rpc_err(id, ERR_METHOD, "unverified_passthrough_disabled");
        }
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let chain = self.chain.lock().expect("chain lock");
        match bind_mined_object(&raw, &safe, &chain, want) {
            Ok(()) => rpc_ok(id, raw),
            Err(msg) => rpc_err(id, ERR_NOT_SYNCED, &msg),
        }
    }

    pub(super) fn unverified_mined(&self, id: Value, req: &Value, method: &str) -> Value {
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

    pub(super) fn unverified_qty(&self, id: Value, req: &Value, method: &str) -> Value {
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

    pub(super) fn get_raw_tx_by_hash(&self, id: Value, req: &Value) -> Value {
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

    pub(super) fn send_raw(&self, id: Value, req: &Value) -> Value {
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
}
