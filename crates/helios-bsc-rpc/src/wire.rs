//! JSON-RPC envelopes, error codes, wallet-mode block tags.

use serde_json::{json, Value};

pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID: i64 = -32600;
pub const ERR_PROOF_FAILED: i64 = -32001;
pub const ERR_STATE_ROOT: i64 = -32002;
pub const ERR_NOT_SYNCED: i64 = -32003;
pub const ERR_METHOD: i64 = -32601;
pub const ERR_PARAMS: i64 = -32602;

pub fn rpc_ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

pub fn rpc_err(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
}

/// JSON-RPC 2.0 requires `"jsonrpc":"2.0"`. Missing / other versions are invalid request.
pub fn jsonrpc_is_v2(req: &Value) -> bool {
    req.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
}

/// JSON-RPC 2.0 `id`: string (≤ [`MAX_RPC_ID`]), integer number, or null.
/// Fractional numbers are forbidden by the spec.
pub fn jsonrpc_id_ok(id: &Value) -> bool {
    match id {
        Value::Null => true,
        Value::String(s) => s.len() <= MAX_RPC_ID,
        Value::Number(n) => n.as_i64().is_some() || n.as_u64().is_some(),
        _ => false,
    }
}

/// Max members in a JSON-RPC batch (DoS). Oversize → single `-32600`, not N responses.
pub const MAX_RPC_BATCH: usize = 64;
/// Max JSON-RPC method name length (DoS).
pub const MAX_RPC_METHOD: usize = 64;
/// Max storage keys on `eth_getProof` (DoS / upstream proof size).
pub const MAX_PROOF_STORAGE_KEYS: usize = 64;
/// Max JSON-RPC `id` string length (DoS).
pub const MAX_RPC_ID: usize = 128;
/// Max positional params in one call (DoS). `eth_getProof` uses 3.
pub const MAX_RPC_PARAMS: usize = 16;

/// Positional params: omitted/null/`[]` ok; object or other types are invalid.
pub fn jsonrpc_params_ok(req: &Value) -> bool {
    match req.get("params") {
        None | Some(Value::Null) | Some(Value::Array(_)) => true,
        Some(_) => false,
    }
}

pub fn jsonrpc_params_len(req: &Value) -> usize {
    req.get("params")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

/// Wallet-mode block id for header-verified `eth_getBlockByNumber`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockId {
    /// Local Safe head (`latest` / `safe` / `finalized` / omitted / exact Safe hash).
    Safe,
    /// Hex height `n` with `n <= Safe` (caller still checks the number is in-chain).
    Number(u64),
}

/// Wallet mode: `latest` / `safe` / `finalized` / omitted → local Safe.
/// Hex number or hash allowed only if it is exactly the local Safe head.
pub fn wallet_tag_is_safe(tag: Option<&str>, safe_number: u64, safe_hash: &str) -> bool {
    match tag {
        None | Some("") | Some("latest") | Some("safe") | Some("finalized") => true,
        Some(t) if t.eq_ignore_ascii_case(safe_hash) => true,
        Some(t) if t.starts_with("0x") || t.starts_with("0X") => {
            parse_hex_u64(t).is_some_and(|n| n == safe_number)
        }
        _ => false,
    }
}

/// Wallet mode for `eth_getBlockByNumber`: tags map to Safe; hex heights `n <= Safe`
/// are allowed (existence in the local verified chain is checked by the server).
/// `pending` and heights above Safe are rejected.
pub fn wallet_block_number_allowed(
    tag: Option<&str>,
    safe_number: u64,
    safe_hash: &str,
) -> Option<BlockId> {
    match tag {
        None | Some("") | Some("latest") | Some("safe") | Some("finalized") => Some(BlockId::Safe),
        Some("pending") => None,
        Some(t) if t.eq_ignore_ascii_case(safe_hash) => Some(BlockId::Safe),
        Some(t) if t.starts_with("0x") || t.starts_with("0X") => {
            parse_hex_u64(t).and_then(|n| (n <= safe_number).then_some(BlockId::Number(n)))
        }
        _ => None,
    }
}

fn parse_hex_u64(t: &str) -> Option<u64> {
    u64::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn latest_maps_to_safe() {
        assert!(wallet_tag_is_safe(Some("latest"), 100, "0xabc"));
        assert!(wallet_tag_is_safe(None, 100, "0xabc"));
        assert!(wallet_tag_is_safe(Some("safe"), 100, "0xabc"));
        assert!(wallet_tag_is_safe(Some("finalized"), 100, "0xabc"));
    }

    #[test]
    fn other_heights_rejected() {
        assert!(!wallet_tag_is_safe(Some("0x1"), 100, "0xabc"));
        assert!(wallet_tag_is_safe(Some("0x64"), 100, "0xabc"));
        assert!(wallet_tag_is_safe(Some("0xABC"), 100, "0xabc"));
    }

    #[test]
    fn get_block_allows_at_or_below_safe() {
        assert_eq!(
            wallet_block_number_allowed(Some("latest"), 100, "0xabc"),
            Some(BlockId::Safe)
        );
        assert_eq!(
            wallet_block_number_allowed(None, 100, "0xabc"),
            Some(BlockId::Safe)
        );
        assert_eq!(
            wallet_block_number_allowed(Some("safe"), 100, "0xabc"),
            Some(BlockId::Safe)
        );
        assert_eq!(
            wallet_block_number_allowed(Some("finalized"), 100, "0xabc"),
            Some(BlockId::Safe)
        );
        assert_eq!(
            wallet_block_number_allowed(Some("0x1"), 100, "0xabc"),
            Some(BlockId::Number(1))
        );
        assert_eq!(
            wallet_block_number_allowed(Some("0x64"), 100, "0xabc"),
            Some(BlockId::Number(100))
        );
        assert_eq!(
            wallet_block_number_allowed(Some("0xABC"), 100, "0xabc"),
            Some(BlockId::Safe)
        );
        assert_eq!(
            wallet_block_number_allowed(Some("0x65"), 100, "0xabc"),
            None
        );
        assert_eq!(
            wallet_block_number_allowed(Some("pending"), 100, "0xabc"),
            None
        );
        // Balances stay exact-Safe: 0x1 is still rejected there.
        assert!(!wallet_tag_is_safe(Some("0x1"), 100, "0xabc"));
    }

    #[test]
    fn envelopes() {
        let v = rpc_ok(json!(1), json!("0x38"));
        assert_eq!(v["result"], "0x38");
        let e = rpc_err(json!(1), ERR_METHOD, "method_unsupported");
        assert_eq!(e["error"]["code"], ERR_METHOD);
    }

    #[test]
    fn jsonrpc_version_must_be_2() {
        assert!(jsonrpc_is_v2(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId"})
        ));
        assert!(!jsonrpc_is_v2(
            &json!({"jsonrpc":"1.0","id":1,"method":"eth_chainId"})
        ));
        assert!(!jsonrpc_is_v2(&json!({"id":1,"method":"eth_chainId"})));
        assert!(!jsonrpc_is_v2(
            &json!({"jsonrpc":2,"id":1,"method":"eth_chainId"})
        ));
    }

    #[test]
    fn jsonrpc_id_types() {
        assert!(jsonrpc_id_ok(&json!(1)));
        assert!(jsonrpc_id_ok(&json!("abc")));
        assert!(jsonrpc_id_ok(&Value::Null));
        assert!(!jsonrpc_id_ok(&json!(true)));
        assert!(!jsonrpc_id_ok(&json!([])));
        assert!(!jsonrpc_id_ok(&json!({})));
        assert!(!jsonrpc_id_ok(&json!(1.5)));
        assert!(!jsonrpc_id_ok(&json!("x".repeat(MAX_RPC_ID + 1))));
        assert_eq!(MAX_RPC_BATCH, 64);
        assert_eq!(MAX_RPC_METHOD, 64);
        assert_eq!(MAX_PROOF_STORAGE_KEYS, 64);
        assert_eq!(MAX_RPC_PARAMS, 16);
        assert_eq!(MAX_RPC_ID, 128);
        assert!(MAX_RPC_METHOD >= "helios_bsc_getVerificationStatus".len());
    }

    #[test]
    fn jsonrpc_params_must_be_array() {
        assert!(jsonrpc_params_ok(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId"})
        ));
        assert!(jsonrpc_params_ok(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})
        ));
        assert!(jsonrpc_params_ok(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":null})
        ));
        assert!(!jsonrpc_params_ok(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":{}})
        ));
        assert!(!jsonrpc_params_ok(
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":"x"})
        ));
    }
}
