//! Shape checks on untrusted JSON: every field an upstream can choose, bound to something already verified or refused.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

pub(crate) fn bind_optional_hash32(v: Option<&Value>, field: &str) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => decode_hex_fixed::<32>(s)
            .map(|_| ())
            .map_err(|_| format!("{field} is not a 32-byte hash")),
        Some(_) => Err(format!("{field} not a string")),
    }
}

pub(crate) fn bind_optional_address(
    v: Option<&Value>,
    field: &str,
    allow_null: bool,
) -> Result<(), String> {
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

pub(crate) fn bind_optional_chain_id(v: Option<&Value>) -> Result<(), String> {
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

pub(crate) fn require_rpc_address(s: &str) -> Result<[u8; 20], String> {
    decode_hex_fixed::<20>(s).map_err(|_| "address is not 20 bytes".into())
}

pub(crate) fn query_tx_hash(req: &Value) -> Result<[u8; 32], String> {
    let s = req
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.first())
        .and_then(Value::as_str)
        .ok_or_else(|| "tx hash required".to_string())?;
    decode_hex_fixed::<32>(s).map_err(|_| "tx hash is not 32 bytes".into())
}

/// Receipt `transactionHash` / tx `hash` must equal the requested hash when present.
pub(crate) fn bind_result_tx_hash(
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

pub(crate) fn bind_optional_logs(
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

pub(crate) fn bind_optional_qty(v: Option<&Value>, field: &str) -> Result<(), String> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => decode_u64(s)
            .map(|_| ())
            .map_err(|_| format!("{field} is not a hex quantity")),
        Some(_) => Err(format!("{field} not a hex quantity")),
    }
}

pub(crate) fn bind_optional_hex_cap(
    v: Option<&Value>,
    field: &str,
    max: usize,
) -> Result<(), String> {
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

pub(crate) fn bind_qty_array(v: Option<&Value>, field: &str) -> Result<(), String> {
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

pub(crate) fn bind_optional_tx_type(v: Option<&Value>) -> Result<(), String> {
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

pub(crate) fn bind_optional_status(v: Option<&Value>) -> Result<(), String> {
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
pub(crate) fn bind_fee_result(method: &str, v: &Value) -> Result<(), String> {
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
pub(crate) fn bind_fee_oldest_block(
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
pub(crate) fn bind_mined_object(
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
