//! `eth_getBlockByNumber` JSON header (fixture / RPC).

use serde::{Deserialize, Serialize};

/// Full header as returned by public JSON-RPC (hex-encoded fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockHeader {
    pub hash: String,
    pub parent_hash: String,
    pub sha3_uncles: String,
    pub miner: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub difficulty: String,
    pub number: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub timestamp: String,
    pub extra_data: String,
    pub mix_hash: String,
    pub nonce: String,
    #[serde(default)]
    pub base_fee_per_gas: Option<String>,
    #[serde(default)]
    pub withdrawals_root: Option<String>,
    #[serde(default)]
    pub blob_gas_used: Option<String>,
    #[serde(default)]
    pub excess_blob_gas: Option<String>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<String>,
    #[serde(default)]
    pub requests_hash: Option<String>,
}
