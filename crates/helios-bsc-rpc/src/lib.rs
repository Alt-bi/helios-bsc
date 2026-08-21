//! Local JSON-RPC policy surface (fail-closed).
//!
//! This crate is the fail-closed method matrix + JSON-RPC 2.0 envelope helpers;
//! the HTTP server is tiny_http in the `helios-bsc` binary.

use helios_bsc_types::TrustClass;

pub mod wire;
pub use wire::{
    jsonrpc_id_ok, jsonrpc_is_v2, jsonrpc_params_len, jsonrpc_params_ok, rpc_err, rpc_ok,
    wallet_block_number_allowed, wallet_tag_is_safe, BlockId, ERR_INVALID, ERR_METHOD,
    ERR_NOT_SYNCED, ERR_PARAMS, ERR_PARSE, ERR_PROOF_FAILED, ERR_STATE_ROOT,
    MAX_PROOF_STORAGE_KEYS, MAX_RPC_BATCH, MAX_RPC_ID, MAX_RPC_METHOD, MAX_RPC_PARAMS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodPolicy {
    Verified,
    Unverified,
    Unsupported,
}

impl MethodPolicy {
    pub fn trust(self) -> TrustClass {
        match self {
            Self::Verified => TrustClass::Verified,
            Self::Unverified => TrustClass::Unverified,
            Self::Unsupported => TrustClass::Unsupported,
        }
    }
}

/// Namespaces that must never be served (no keys, no tracing, no engine).
fn namespace_blocked(method: &str) -> bool {
    method.starts_with("debug_")
        || method.starts_with("trace_")
        || method.starts_with("personal_")
        || method.starts_with("admin_")
        || method.starts_with("miner_")
        || method.starts_with("txpool_")
        || method.starts_with("engine_")
        || method.starts_with("les_")
        || method.starts_with("clique_")
        || method.starts_with("parlia_")
        || method.starts_with("rpc_")
        || method.starts_with("bsc_")
}

/// MVP-1 / Demo Slice method policy.
pub fn method_policy(method: &str) -> MethodPolicy {
    if namespace_blocked(method) {
        return MethodPolicy::Unsupported;
    }
    match method {
        "eth_chainId" | "net_version" | "net_listening" | "net_peerCount" => MethodPolicy::Verified,
        "web3_clientVersion"
        | "web3_sha3"
        | "eth_accounts"
        | "eth_syncing"
        | "eth_mining"
        | "eth_hashrate"
        | "eth_protocolVersion" => MethodPolicy::Verified,
        "eth_blockNumber" => MethodPolicy::Verified, // wallet mode → Safe height
        "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_getCode"
        | "eth_getStorageAt"
        | "eth_getProof"
        | "eth_call"
        | "eth_estimateGas" => MethodPolicy::Verified,
        "eth_getBlockByNumber" | "eth_getBlockByHash" => MethodPolicy::Verified,
        "eth_getUncleCountByBlockNumber"
        | "eth_getUncleCountByBlockHash"
        | "eth_getUncleByBlockNumberAndIndex"
        | "eth_getUncleByBlockHashAndIndex"
        | "eth_coinbase" => MethodPolicy::Verified,
        "eth_sendRawTransaction" => MethodPolicy::Unverified,
        "eth_getTransactionReceipt"
        | "eth_getTransactionByHash"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "eth_feeHistory"
        | "eth_blobBaseFee" => MethodPolicy::Unverified,
        "helios_bsc_syncStatus" | "helios_bsc_getVerificationStatus" => MethodPolicy::Verified,
        "eth_getLogs"
        | "eth_newFilter"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter"
        | "eth_uninstallFilter"
        | "eth_getFilterChanges"
        | "eth_getFilterLogs"
        | "eth_subscribe"
        | "eth_unsubscribe"
        | "eth_getBlockTransactionCountByNumber"
        | "eth_getBlockTransactionCountByHash"
        | "eth_getTransactionByBlockNumberAndIndex"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_sendTransaction"
        | "eth_sign"
        | "eth_signTransaction"
        | "eth_signTypedData"
        | "eth_signTypedData_v4" => MethodPolicy::Unsupported,
        _ => MethodPolicy::Unsupported,
    }
}

/// Opt-in `--allow-unverified-passthrough` allow-list (not sendRaw: that is always on).
/// Receipts/txs are still header-bound to the local Safe chain at serve time.
pub fn unverified_passthrough_ok(method: &str) -> bool {
    matches!(
        method,
        "eth_getTransactionReceipt"
            | "eth_getTransactionByHash"
            | "eth_gasPrice"
            | "eth_maxPriorityFeePerGas"
            | "eth_feeHistory"
            | "eth_blobBaseFee"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_is_verified_policy() {
        assert_eq!(method_policy("eth_getBalance"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_getProof"), MethodPolicy::Verified);
    }

    #[test]
    fn call_and_estimate_gas_are_verified() {
        assert_eq!(method_policy("eth_call"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_estimateGas"), MethodPolicy::Verified);
        assert!(!unverified_passthrough_ok("eth_estimateGas"));
    }

    #[test]
    fn meta_sync_is_verified() {
        assert_eq!(
            method_policy("helios_bsc_syncStatus"),
            MethodPolicy::Verified
        );
    }

    #[test]
    fn send_raw_is_unverified() {
        assert_eq!(
            method_policy("eth_sendRawTransaction"),
            MethodPolicy::Unverified
        );
    }

    #[test]
    fn get_block_by_number_is_verified() {
        assert_eq!(
            method_policy("eth_getBlockByNumber"),
            MethodPolicy::Verified
        );
    }

    #[test]
    fn get_block_by_hash_is_verified() {
        assert_eq!(method_policy("eth_getBlockByHash"), MethodPolicy::Verified);
        assert_eq!(
            method_policy("eth_getUncleCountByBlockNumber"),
            MethodPolicy::Verified
        );
        assert_eq!(method_policy("eth_coinbase"), MethodPolicy::Verified);
    }

    #[test]
    fn jsonrpc_envelope_codes() {
        assert_eq!(ERR_PARSE, -32700);
        assert_eq!(ERR_INVALID, -32600);
        assert_eq!(ERR_METHOD, -32601);
        assert_eq!(ERR_PARAMS, -32602);
    }

    #[test]
    fn get_logs_still_unsupported() {
        assert_eq!(method_policy("eth_getLogs"), MethodPolicy::Unsupported);
        assert_eq!(method_policy("eth_call"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_estimateGas"), MethodPolicy::Verified);
        assert!(!unverified_passthrough_ok("eth_estimateGas"));
        assert_eq!(method_policy("eth_newFilter"), MethodPolicy::Unsupported);
        assert_eq!(method_policy("eth_subscribe"), MethodPolicy::Unsupported);
        assert_eq!(
            method_policy("eth_getFilterChanges"),
            MethodPolicy::Unsupported
        );
        assert!(!unverified_passthrough_ok("eth_getLogs"));
        assert!(!unverified_passthrough_ok("eth_subscribe"));
        assert_eq!(
            method_policy("eth_getBlockTransactionCountByNumber"),
            MethodPolicy::Unsupported
        );
        assert_eq!(
            method_policy("eth_getTransactionByBlockHashAndIndex"),
            MethodPolicy::Unsupported
        );
        assert_eq!(
            method_policy("eth_sendTransaction"),
            MethodPolicy::Unsupported
        );
        assert_eq!(method_policy("eth_sign"), MethodPolicy::Unsupported);
        assert_eq!(
            method_policy("personal_unlockAccount"),
            MethodPolicy::Unsupported
        );
        assert_eq!(
            method_policy("debug_traceTransaction"),
            MethodPolicy::Unsupported
        );
        assert_eq!(method_policy("txpool_content"), MethodPolicy::Unsupported);
        assert_eq!(
            method_policy("engine_newPayloadV3"),
            MethodPolicy::Unsupported
        );
        assert_eq!(method_policy("les_serverInfo"), MethodPolicy::Unsupported);
        assert_eq!(
            method_policy("parlia_getSnapshot"),
            MethodPolicy::Unsupported
        );
        assert_eq!(
            method_policy("bsc_getValidators"),
            MethodPolicy::Unsupported
        );
        assert!(!unverified_passthrough_ok("eth_sendTransaction"));
        assert!(!unverified_passthrough_ok("eth_sendRawTransaction"));
    }

    #[test]
    fn verification_status_is_verified() {
        assert_eq!(
            method_policy("helios_bsc_getVerificationStatus"),
            MethodPolicy::Verified
        );
    }

    #[test]
    fn wallet_meta_is_verified() {
        assert_eq!(method_policy("eth_syncing"), MethodPolicy::Verified);
        assert_eq!(method_policy("web3_clientVersion"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_accounts"), MethodPolicy::Verified);
        assert_eq!(method_policy("web3_sha3"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_mining"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_hashrate"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_protocolVersion"), MethodPolicy::Verified);
        assert_eq!(method_policy("net_listening"), MethodPolicy::Verified);
        assert_eq!(method_policy("net_peerCount"), MethodPolicy::Verified);
        assert_eq!(method_policy("eth_gasPrice"), MethodPolicy::Unverified);
        assert_eq!(
            method_policy("eth_maxPriorityFeePerGas"),
            MethodPolicy::Unverified
        );
        assert_eq!(method_policy("eth_feeHistory"), MethodPolicy::Unverified);
        assert_eq!(
            method_policy("eth_getTransactionReceipt"),
            MethodPolicy::Unverified
        );
        assert_eq!(
            method_policy("eth_getTransactionByHash"),
            MethodPolicy::Unverified
        );
        assert!(unverified_passthrough_ok("eth_getTransactionReceipt"));
        assert!(unverified_passthrough_ok("eth_gasPrice"));
        assert!(unverified_passthrough_ok("eth_feeHistory"));
        assert!(unverified_passthrough_ok("eth_maxPriorityFeePerGas"));
        assert!(!unverified_passthrough_ok("eth_sendRawTransaction"));
        assert!(!unverified_passthrough_ok("eth_getBalance"));
        assert!(!unverified_passthrough_ok("eth_call"));
        assert!(!unverified_passthrough_ok("eth_estimateGas"));
    }
}
