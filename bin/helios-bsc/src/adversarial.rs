//! PR 10: lying upstream through `Node::handle` (no network).

use crate::diff::{diff_vs_oracle, soak_list, SOAK_ADDRESSES};
use crate::rpc_server::FinalityMode;
use crate::sync::{
    confirm_checkpoint_with_oracle, walk_from_checkpoint, walk_from_checkpoint_inturn, walk_headers,
};
use crate::{Node, RpcUpstream};
use anyhow::{anyhow, Result};
use helios_bsc_consensus::{header_hash, newest_safe, Snapshot, VerifiedBlock};
use helios_bsc_execution::{
    encode_consensus_receipt, encode_data32, encode_qty, ordered_trie_root, ConsensusReceipt,
    EMPTY_TRIE_ROOT, MAX_CALL_ACCOUNTS, MAX_RAW_TX, TX_GAS,
};
use helios_bsc_mock::{
    cycling_sealer_chain, distinct_sealer_chain, header_from_verified, headers_from_chain, n_seal,
    relink_dummy_chain, MockRpc, Scenario, WBNB_ADDRESS, WRONG_STATE_ROOT,
};
use helios_bsc_rpc::{
    ERR_INVALID, ERR_METHOD, ERR_NOT_SYNCED, ERR_PARAMS, ERR_PARSE, ERR_PROOF_FAILED,
    ERR_STATE_ROOT, MAX_PROOF_STORAGE_KEYS, MAX_RPC_BATCH, MAX_RPC_ID, MAX_RPC_METHOD,
    MAX_RPC_PARAMS,
};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, keccak256, Checkpoint, RpcBlockHeader, SafeHead,
};
use serde_json::{json, Value};

struct MockUpstream {
    tip: u64,
    headers: Vec<RpcBlockHeader>,
    /// Epoch boundaries below `headers`. Served by number only: they must not appear in a
    /// `headers_range` walk, which is why they are a separate list rather than prepended.
    epoch_headers: Vec<RpcBlockHeader>,
    proof: Value,
    /// When set, `header_by_hash` lies about `stateRoot` (hash/number still match).
    lie_state_root: bool,
    balance: String,
    fail_balance: bool,
    unverified: Value,
    code: Vec<u8>,
    /// When set, `send_raw_transaction` returns this hash instead of keccak(raw).
    lie_raw_hash: Option<String>,
    receipts: Vec<Value>,
    /// Upstream `eth_blockNumber` calls, shared with the test that wants to count them.
    block_number_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Name of a method that should panic instead of answering. `headers_range` panics
    /// from inside `resync_locked`, i.e. while the chain and snapshot locks are held,
    /// which is the case that used to take the whole RPC surface down with it.
    panic_in: Option<&'static str>,
}

impl MockUpstream {
    fn from_rpc(rpc: MockRpc) -> Result<Self> {
        Ok(Self {
            tip: rpc.tip_number()?,
            headers: rpc.headers().to_vec(),
            epoch_headers: helios_bsc_mock::epoch_headers()?,
            proof: rpc.proof_json(),
            lie_state_root: false,
            balance: rpc
                .proof_json()
                .get("balance")
                .and_then(Value::as_str)
                .unwrap_or("0x0")
                .to_string(),
            fail_balance: false,
            unverified: Value::Null,
            code: Vec::new(),
            lie_raw_hash: None,
            receipts: Vec::new(),
            block_number_calls: std::sync::Arc::default(),
            panic_in: None,
        })
    }

    fn for_chain(chain: &[VerifiedBlock], proof: Value) -> Self {
        Self {
            tip: chain.last().map(|b| b.number).unwrap_or(0),
            headers: headers_from_chain(chain),
            epoch_headers: Vec::new(),
            proof,
            lie_state_root: false,
            balance: "0x0".into(),
            fail_balance: false,
            unverified: Value::Null,
            code: Vec::new(),
            lie_raw_hash: None,
            receipts: Vec::new(),
            block_number_calls: std::sync::Arc::default(),
            panic_in: None,
        }
    }
}

impl RpcUpstream for MockUpstream {
    fn block_number(&self) -> Result<u64> {
        self.block_number_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.tip)
    }

    fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader> {
        self.headers
            .iter()
            .chain(self.epoch_headers.iter())
            .find(|h| decode_u64(&h.number).ok() == Some(n))
            .cloned()
            .ok_or_else(|| anyhow!("header {n} missing"))
    }

    fn header_by_hash(&self, hash: &str) -> Result<RpcBlockHeader> {
        let mut h = self
            .headers
            .iter()
            .find(|h| h.hash.eq_ignore_ascii_case(hash))
            .cloned()
            .ok_or_else(|| anyhow!("header {hash} missing"))?;
        if self.lie_state_root {
            h.state_root = format!("0x{}", hex::encode(WRONG_STATE_ROOT));
        }
        Ok(h)
    }

    fn headers_range(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        assert!(
            self.panic_in != Some("headers_range"),
            "injected panic under the chain lock"
        );
        let mut out: Vec<RpcBlockHeader> = self
            .headers
            .iter()
            .filter(|h| {
                decode_u64(&h.number)
                    .ok()
                    .is_some_and(|n| n >= from && n <= to)
            })
            .cloned()
            .collect();
        out.sort_by_key(|h| decode_u64(&h.number).unwrap_or(0));
        Ok(out)
    }

    fn get_proof_keys(&self, _address: &str, _keys: &[String], _block: &str) -> Result<Value> {
        Ok(self.proof.clone())
    }

    fn get_balance(&self, _address: &str, _block: &str) -> Result<String> {
        if self.fail_balance {
            return Err(anyhow!("historical state not available"));
        }
        Ok(self.balance.clone())
    }

    fn get_transaction_count(&self, _address: &str, _block: &str) -> Result<String> {
        Ok(self
            .proof
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or("0x0")
            .to_string())
    }

    fn get_code(&self, _address: &str, _block: &str) -> Result<Vec<u8>> {
        Ok(self.code.clone())
    }

    fn send_raw_transaction(&self, raw: &str) -> Result<String> {
        if let Some(h) = &self.lie_raw_hash {
            return Ok(h.clone());
        }
        let bytes = decode_hex(raw)?;
        Ok(format!("0x{}", hex::encode(keccak256(&bytes))))
    }

    fn unverified_call(&self, _method: &str, _params: &Value) -> Result<Value> {
        Ok(self.unverified.clone())
    }

    fn block_receipts_json(&self, _block_hash: &str) -> Result<Vec<Value>> {
        Ok(self.receipts.clone())
    }
}

fn req(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}

fn err_code(v: &Value) -> i64 {
    v["error"]["code"].as_i64().expect("error.code")
}

fn bootstrap_err(scenario: Scenario) -> String {
    let up = MockUpstream::from_rpc(MockRpc::new(scenario)).unwrap();
    match Node::bootstrap(Box::new(up), 130) {
        Ok(_) => panic!("{scenario:?} bootstrap unexpectedly succeeded"),
        Err(e) => e.to_string(),
    }
}

fn safe_chain_with_fixture_root() -> (Vec<VerifiedBlock>, MockRpc) {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let root = rpc.fixture_state_root();
    let mut chain = distinct_sealer_chain(15);
    chain[0].state_root = root;
    relink_dummy_chain(&mut chain);
    (chain, rpc)
}

fn node_from_chain(chain: Vec<VerifiedBlock>, proof: Value) -> Node {
    let up = MockUpstream::for_chain(&chain, proof);
    Node::from_parts(Box::new(up), 130, chain)
}

/// Like [`node_from_chain`], but hands back the upstream's `eth_blockNumber` counter.
fn node_counting_block_number(
    chain: Vec<VerifiedBlock>,
    proof: Value,
) -> (Node, std::sync::Arc<std::sync::atomic::AtomicU64>) {
    let up = MockUpstream::for_chain(&chain, proof);
    let calls = std::sync::Arc::clone(&up.block_number_calls);
    (Node::from_parts(Box::new(up), 130, chain), calls)
}

fn load_wbnb_code() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/mainnet/wbnb_code.hex");
    let s = std::fs::read_to_string(&path).unwrap();
    helios_bsc_types::decode_hex(s.trim()).unwrap()
}

/// MockUpstream serves one proof; set Safe miner = WBNB so revm coinbase is already proven.
fn node_wbnb_eth_call(mut chain: Vec<VerifiedBlock>, proof: Value) -> Node {
    chain[0].miner = decode_hex_fixed::<20>(WBNB_ADDRESS).unwrap();
    let mut up = MockUpstream::for_chain(&chain, proof);
    up.code = load_wbnb_code();
    Node::from_parts(Box::new(up), 130, chain)
}

#[test]
fn bootstrap_mutated_seal_err() {
    let err = bootstrap_err(Scenario::MutatedSeal);
    assert!(
        err.contains("seal") || err.contains("recover") || err.contains("coinbase"),
        "{err}"
    );
}

#[test]
fn bootstrap_coinbase_mismatch_err() {
    let err = bootstrap_err(Scenario::CoinbaseMismatch);
    assert!(
        err.contains("coinbase") || err.contains("mismatch") || err.contains("seal"),
        "{err}"
    );
}

#[test]
fn bootstrap_broken_parent_err() {
    let err = bootstrap_err(Scenario::BrokenParent);
    assert!(err.contains("parent_hash") || err.contains("seal"), "{err}");
}

#[test]
fn bootstrap_truncated_history_no_safe() {
    let err = bootstrap_err(Scenario::TruncatedHistory);
    assert!(err.contains("no Safe") || err.contains("Safe"), "{err}");
}

#[test]
fn walk_mutated_seal_rejected() {
    let up = MockUpstream::from_rpc(MockRpc::new(Scenario::MutatedSeal)).unwrap();
    let tip = up.tip;
    assert!(walk_headers(&up, tip - 4, tip).is_err());
}

#[test]
fn walk_lied_rpc_hash_field_rejected() {
    let mut up = MockUpstream::from_rpc(MockRpc::new(Scenario::HonestFixtures)).unwrap();
    let tip = up.tip;
    up.headers[0].hash = format!("0x{}", hex::encode([0x11u8; 32]));
    let err = walk_headers(&up, tip - 4, tip).unwrap_err();
    let s = format!("{err:#}").to_ascii_lowercase();
    assert!(s.contains("hash"), "{err:#}");
}

#[test]
fn wallet_meta_when_synced() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let syncing = node.handle(&req("eth_syncing", json!([])));
    assert_eq!(syncing["result"], json!(false));
    let ver = node.handle(&req("web3_clientVersion", json!([])));
    let s = ver["result"].as_str().unwrap();
    assert!(s.starts_with("helios-bsc/"), "{s}");
    let acc = node.handle(&req("eth_accounts", json!([])));
    assert_eq!(acc["result"], json!([]));
    let listen = node.handle(&req("net_listening", json!([])));
    assert_eq!(listen["result"], json!(true));
    let peers = node.handle(&req("net_peerCount", json!([])));
    assert_eq!(peers["result"], json!("0x0"));
    let mining = node.handle(&req("eth_mining", json!([])));
    assert_eq!(mining["result"], json!(false));
    let hr = node.handle(&req("eth_hashrate", json!([])));
    assert_eq!(hr["result"], json!("0x0"));
    let sha = node.handle(&req("web3_sha3", json!(["0x"])));
    assert_eq!(
        sha["result"],
        json!("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );
    let bad = node.handle(&req("web3_sha3", json!(["0xgg"])));
    assert_eq!(err_code(&bad), ERR_PARAMS);
    let call = node.handle(&req("eth_gasPrice", json!([])));
    assert_eq!(err_code(&call), ERR_METHOD);
}

#[test]
fn jsonrpc_parse_error() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.dispatch_bytes(b"not-json{");
    assert_eq!(v["error"]["code"], json!(ERR_PARSE));
}

#[test]
fn jsonrpc_invalid_and_batch() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let missing = node.handle(&json!({"jsonrpc":"2.0","id":1}));
    assert_eq!(err_code(&missing), ERR_INVALID);
    let no_ver = node.dispatch(&json!({"id":1,"method":"eth_chainId","params":[]}));
    assert_eq!(err_code(&no_ver), ERR_INVALID);
    let v1 = node.dispatch(&json!({"jsonrpc":"1.0","id":1,"method":"eth_chainId","params":[]}));
    assert_eq!(err_code(&v1), ERR_INVALID);
    let empty_batch = node.dispatch(&json!([]));
    assert_eq!(empty_batch["error"]["code"], json!(ERR_INVALID));
    let batch = node.dispatch(&json!([
        {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
        {"jsonrpc":"2.0","method":"eth_accounts","params":[]},
        {"jsonrpc":"2.0","id":2,"method":"eth_call","params":[]},
        "not-an-object"
    ]));
    let arr = batch.as_array().expect("batch array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["result"], json!("0x38"));
    assert_eq!(arr[1]["error"]["code"], json!(ERR_PARAMS));
    assert_eq!(arr[2]["error"]["code"], json!(ERR_INVALID));
    let note = node.dispatch(&json!({"jsonrpc":"2.0","method":"eth_chainId","params":[]}));
    assert!(note.is_null(), "{note}");
    let bad_id =
        node.dispatch(&json!({"jsonrpc":"2.0","id":true,"method":"eth_chainId","params":[]}));
    assert_eq!(err_code(&bad_id), ERR_INVALID);
    let huge: Vec<Value> = (0..=MAX_RPC_BATCH)
        .map(|i| json!({"jsonrpc":"2.0","id":i,"method":"eth_chainId","params":[]}))
        .collect();
    let over = node.dispatch(&Value::Array(huge));
    assert_eq!(over["error"]["code"], json!(ERR_INVALID));
    let obj_params =
        node.handle(&json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":{}}));
    assert_eq!(err_code(&obj_params), ERR_PARAMS);
    let proto = node.handle(&req("eth_protocolVersion", json!([])));
    assert_eq!(proto["result"], json!("0x41"));
    let long_m = "x".repeat(MAX_RPC_METHOD + 1);
    let long = node.handle(&json!({"jsonrpc":"2.0","id":1,"method":long_m,"params":[]}));
    assert_eq!(err_code(&long), ERR_INVALID);
    let sp = node.handle(&json!({"jsonrpc":"2.0","id":1,"method":"eth getBalance","params":[]}));
    assert_eq!(err_code(&sp), ERR_INVALID);
    let long_id = "i".repeat(MAX_RPC_ID + 1);
    let lid =
        node.handle(&json!({"jsonrpc":"2.0","id":long_id,"method":"eth_chainId","params":[]}));
    assert_eq!(err_code(&lid), ERR_INVALID);
    let frac = node.handle(&json!({"jsonrpc":"2.0","id":1.5,"method":"eth_chainId","params":[]}));
    assert_eq!(err_code(&frac), ERR_INVALID);
    let too_params: Vec<Value> = (0..=MAX_RPC_PARAMS).map(|_| json!(null)).collect();
    let tp =
        node.handle(&json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":too_params}));
    assert_eq!(err_code(&tp), ERR_PARAMS);
}

#[test]
fn jsonrpc_method_non_ascii_nul_tab_is_invalid_request() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    for method in ["eth_chainId\0", "eth_chainId\t", "eth_chainIdé"] {
        let v = node.handle(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}));
        assert_eq!(err_code(&v), ERR_INVALID, "{method:?}: {v}");
    }
}

#[test]
fn fourteen_sealers_block_number_is_not_synced() {
    let chain = cycling_sealer_chain(20, 14);
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req("eth_blockNumber", json!([])));
    assert_eq!(err_code(&v), ERR_NOT_SYNCED);
    let bal = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(err_code(&bal), ERR_NOT_SYNCED);
    assert!(bal["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not_synced"));
    let syncing = node.handle(&req("eth_syncing", json!([])));
    assert!(syncing["result"].is_object(), "{syncing}");
    assert_ne!(syncing["result"], json!(false));
}

#[test]
fn truncated_history_does_not_serve_tip_as_latest() {
    let chain = cycling_sealer_chain(20, 14);
    let tip = chain.last().unwrap().number;
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req("eth_blockNumber", json!([])));
    assert_eq!(err_code(&v), ERR_NOT_SYNCED);
    assert_ne!(v.get("result"), Some(&json!(format!("0x{tip:x}"))));
}

#[test]
fn lying_balance_get_balance_is_proof_failed() {
    let (chain, _) = safe_chain_with_fixture_root();
    let proof = MockRpc::new(Scenario::LyingBalance).proof_json();
    let node = node_from_chain(chain, proof);
    let v = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
    assert!(v.get("result").is_none());
}

#[test]
fn lying_proof_other_account_is_proof_failed() {
    let (chain, _) = safe_chain_with_fixture_root();
    let proof = MockRpc::new(Scenario::WrongAddress).proof_json();
    let node = node_from_chain(chain, proof);
    let v = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
}

#[test]
fn lying_proof_wrong_state_root_is_proof_failed() {
    let (mut chain, rpc) = safe_chain_with_fixture_root();
    chain[0].state_root = WRONG_STATE_ROOT;
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
}

#[test]
fn honest_get_proof_at_safe() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getProof", json!([WBNB_ADDRESS, [], "latest"])));
    let proof = v["result"].as_object().expect("proof object");
    assert!(!proof["accountProof"].as_array().unwrap().is_empty());
    assert_eq!(proof["nonce"].as_str().unwrap().to_ascii_lowercase(), "0x1");
    let too_many: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
        .map(|i| json!(format!("0x{i:064x}")))
        .collect();
    let over = node.handle(&req(
        "eth_getProof",
        json!([WBNB_ADDRESS, too_many, "latest"]),
    ));
    assert_eq!(err_code(&over), ERR_PARAMS, "{over}");
    let junk = node.handle(&req(
        "eth_getProof",
        json!([WBNB_ADDRESS, ["not-a-slot"], "latest"]),
    ));
    assert_eq!(err_code(&junk), ERR_PARAMS, "{junk}");
    let not_str = node.handle(&req("eth_getProof", json!([WBNB_ADDRESS, [1], "latest"])));
    assert_eq!(err_code(&not_str), ERR_PARAMS, "{not_str}");
    let oversized = node.handle(&req(
        "eth_getProof",
        json!([WBNB_ADDRESS, [format!("0x{}", "aa".repeat(33))], "latest"]),
    ));
    assert_eq!(err_code(&oversized), ERR_PARAMS, "{oversized}");
}

#[test]
fn lying_get_proof_rejected() {
    let (chain, _) = safe_chain_with_fixture_root();
    let proof = MockRpc::new(Scenario::LyingBalance).proof_json();
    let node = node_from_chain(chain, proof);
    let v = node.handle(&req("eth_getProof", json!([WBNB_ADDRESS, [], "latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
}

#[test]
fn honest_get_proof_with_storage_slot() {
    let (proof, root) = load_wbnb_slot0();
    let mut chain = distinct_sealer_chain(15);
    chain[0].state_root = root;
    relink_dummy_chain(&mut chain);
    let node = node_from_chain(chain, proof);
    let v = node.handle(&req(
        "eth_getProof",
        json!([WBNB_ADDRESS, ["0x0"], "latest"]),
    ));
    let slots = v["result"]["storageProof"]
        .as_array()
        .expect("storageProof");
    assert_eq!(slots.len(), 1);
    assert_eq!(
        slots[0]["value"].as_str().unwrap().to_ascii_lowercase(),
        "0x5772617070656420424e42000000000000000000000000000000000000000016"
    );
}

#[test]
fn honest_mock_get_balance_ok() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let proof = rpc.account_proof().unwrap();
    let acc = helios_bsc_execution::verify_eth_get_proof(
        &rpc.fixture_state_root(),
        &rpc.wbnb_address(),
        &proof,
    )
    .unwrap();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(v["result"], json!(encode_qty(&acc.balance_wei)));
    let short = node.handle(&req("eth_getBalance", json!(["0x1", "latest"])));
    assert_eq!(err_code(&short), ERR_PARAMS, "{short}");
    for m in [
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getProof",
    ] {
        let params = if m == "eth_getStorageAt" {
            json!(["0x1", "0x0", "latest"])
        } else if m == "eth_getProof" {
            json!(["0x1", [], "latest"])
        } else {
            json!(["0x1", "latest"])
        };
        let bad = node.handle(&req(m, params));
        assert_eq!(err_code(&bad), ERR_PARAMS, "{m}: {bad}");
    }
    let nonce = node.handle(&req(
        "eth_getTransactionCount",
        json!([WBNB_ADDRESS, "latest"]),
    ));
    assert_eq!(nonce["result"], json!(format!("0x{:x}", acc.nonce)));
}

fn load_wbnb_slot0() -> (serde_json::Value, [u8; 32]) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/mainnet/proof_wbnb_slot0.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root = decode_hex_fixed::<32>(v["stateRoot"].as_str().unwrap()).unwrap();
    (v["proof"].clone(), root)
}

#[test]
fn honest_get_storage_at_slot0() {
    let (proof, root) = load_wbnb_slot0();
    let mut chain = distinct_sealer_chain(15);
    chain[0].state_root = root;
    relink_dummy_chain(&mut chain);
    let node = node_from_chain(chain, proof);
    let v = node.handle(&req(
        "eth_getStorageAt",
        json!([WBNB_ADDRESS, "0x0", "latest"]),
    ));
    assert_eq!(
        v["result"],
        json!("0x5772617070656420424e42000000000000000000000000000000000000000016"),
        "{v}"
    );
    let junk = node.handle(&req(
        "eth_getStorageAt",
        json!([WBNB_ADDRESS, "not-a-slot", "latest"]),
    ));
    assert_eq!(err_code(&junk), ERR_PARAMS, "{junk}");
}

#[test]
fn honest_get_code_wbnb() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let code = load_wbnb_code();
    let mut up = MockUpstream::for_chain(&chain, rpc.proof_json());
    up.code = code.clone();
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getCode", json!([WBNB_ADDRESS, "latest"])));
    let got = v["result"].as_str().expect("code hex");
    assert_eq!(got.to_ascii_lowercase(), format!("0x{}", hex::encode(code)));
}

#[test]
fn empty_get_code_for_absent_account() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/mainnet/proof_absent.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let root = decode_hex_fixed::<32>(v["stateRoot"].as_str().unwrap()).unwrap();
    let addr = v["address"].as_str().unwrap();
    let mut chain = distinct_sealer_chain(15);
    chain[0].state_root = root;
    relink_dummy_chain(&mut chain);
    let mut up = MockUpstream::for_chain(&chain, v["proof"].clone());
    up.code = vec![0xff]; // must not be served: exclusion → empty codeHash
    let node = Node::from_parts(Box::new(up), 130, chain);
    let out = node.handle(&req("eth_getCode", json!([addr, "latest"])));
    assert_eq!(out["result"], json!("0x"), "{out}");
    let nonce = node.handle(&req("eth_getTransactionCount", json!([addr, "latest"])));
    assert_eq!(nonce["result"], json!("0x0"), "{nonce}");
}

#[test]
fn lying_get_code_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let mut up = MockUpstream::for_chain(&chain, rpc.proof_json());
    up.code = vec![0x00];
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getCode", json!([WBNB_ADDRESS, "latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
}

#[test]
fn get_storage_without_slot_proof_fails() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_getStorageAt",
        json!([WBNB_ADDRESS, "0x0", "latest"]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED);
}

#[test]
fn honest_mock_eth_block_number_equals_safe_not_tip() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let tip = chain.last().unwrap().number;
    let safe_n = chain[0].number;
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_blockNumber", json!([])));
    assert_eq!(v["result"], json!(format!("0x{safe_n:x}")));
    assert_ne!(v["result"], json!(format!("0x{tip:x}")));
}

#[test]
fn eth_call_and_estimate_gas_never_proxy() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let mut up = MockUpstream::for_chain(&chain, rpc.proof_json());
    up.unverified = json!("0xdeadbeef");
    let mut node = Node::from_parts(Box::new(up), 130, chain);
    node.set_allow_unverified_passthrough(true);
    let est = node.handle(&req(
        "eth_estimateGas",
        json!([{"to": WBNB_ADDRESS}, "latest"]),
    ));
    assert_ne!(est.get("result"), Some(&json!("0xdeadbeef")), "{est}");
    if let Some(code) = est
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
    {
        assert_ne!(code, ERR_METHOD, "{est}");
    }
    let v = node.handle(&req("eth_call", json!([{"to": WBNB_ADDRESS}, "latest"])));
    assert_ne!(v.get("result"), Some(&json!("0xdeadbeef")), "{v}");
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
}

#[test]
fn eth_call_wbnb_totalsupply_ok() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let proof = rpc.proof_json();
    let want = encode_data32(&{
        let bal = proof["balance"].as_str().unwrap();
        let raw = bal.trim_start_matches("0x").trim_start_matches("0X");
        let even = if raw.len() % 2 == 1 {
            format!("0{raw}")
        } else {
            raw.to_string()
        };
        hex::decode(even).unwrap()
    });
    let node = node_wbnb_eth_call(chain, proof);
    let v = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "from": WBNB_ADDRESS, "data": "0x18160ddd"},
            "latest"
        ]),
    ));
    let got = v["result"].as_str().map(|s| s.to_ascii_lowercase());
    assert_eq!(got.as_deref(), Some(want.as_str()), "{v}");
}

#[test]
fn eth_call_unproven_sload_fail_closed() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_wbnb_eth_call(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "from": WBNB_ADDRESS, "data": "0x06fdde03"},
            "latest"
        ]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
}

#[test]
fn eth_call_pending_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let pending = node.handle(&req("eth_call", json!([{"to": WBNB_ADDRESS}, "pending"])));
    assert_eq!(err_code(&pending), ERR_NOT_SYNCED, "{pending}");
    let earliest = node.handle(&req("eth_call", json!([{"to": WBNB_ADDRESS}, "earliest"])));
    assert_eq!(err_code(&earliest), ERR_NOT_SYNCED, "{earliest}");
    let missing_to = node.handle(&req("eth_call", json!([{}, "latest"])));
    assert_eq!(err_code(&missing_to), ERR_PARAMS, "{missing_to}");
}

fn call_object(data: Option<&str>) -> Value {
    match data {
        Some(d) => json!({"to": WBNB_ADDRESS, "from": WBNB_ADDRESS, "data": d}),
        None => json!({"to": WBNB_ADDRESS, "from": WBNB_ADDRESS}),
    }
}

fn assert_call_constraints_rejected(node: &Node, method: &str) {
    let third = node.handle(&req(method, json!([{"to": WBNB_ADDRESS}, "latest", {}])));
    assert_eq!(err_code(&third), ERR_PARAMS, "{method} 3rd param: {third}");
    let state = node.handle(&req(
        method,
        json!([{"to": WBNB_ADDRESS, "stateOverride": {}}, "latest"]),
    ));
    assert_eq!(
        err_code(&state),
        ERR_PARAMS,
        "{method} stateOverride: {state}"
    );
    let blob = node.handle(&req(
        method,
        json!([{"to": WBNB_ADDRESS, "blobVersionedHashes": []}, "latest"]),
    ));
    assert_eq!(
        err_code(&blob),
        ERR_PARAMS,
        "{method} blobVersionedHashes: {blob}"
    );
    let auth = node.handle(&req(
        method,
        json!([{"to": WBNB_ADDRESS, "authorizationList": []}, "latest"]),
    ));
    assert_eq!(
        err_code(&auth),
        ERR_PARAMS,
        "{method} authorizationList: {auth}"
    );
    let to_null = node.handle(&req(method, json!([{"to": Value::Null}, "latest"])));
    assert_eq!(
        err_code(&to_null),
        ERR_PARAMS,
        "{method} to null: {to_null}"
    );
}

#[test]
fn eth_estimate_gas_wbnb_totalsupply_ok() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_wbnb_eth_call(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_estimateGas",
        json!([call_object(Some("0x18160ddd")), "latest"]),
    ));
    let hex = v["result"].as_str().unwrap_or("");
    assert!(hex.starts_with("0x"), "{v}");
    let gas = decode_u64(hex).expect("qty");
    assert!(gas >= TX_GAS, "{v}");
}

#[test]
fn eth_estimate_gas_unproven_name_fail_closed() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_wbnb_eth_call(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_estimateGas",
        json!([call_object(Some("0x06fdde03")), "latest"]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
}

#[test]
fn eth_estimate_gas_name_with_slot0_ok() {
    let (proof, root) = load_wbnb_slot0();
    let mut chain = distinct_sealer_chain(15);
    chain[0].state_root = root;
    relink_dummy_chain(&mut chain);
    let node = node_wbnb_eth_call(chain, proof);
    let v = node.handle(&req(
        "eth_estimateGas",
        json!([call_object(Some("0x06fdde03")), "latest"]),
    ));
    let hex = v["result"].as_str().unwrap_or("");
    assert!(hex.starts_with("0x"), "{v}");
    let gas = decode_u64(hex).expect("qty");
    assert!(gas >= TX_GAS, "{v}");
}

#[test]
fn eth_estimate_gas_pending_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let pending = node.handle(&req(
        "eth_estimateGas",
        json!([{"to": WBNB_ADDRESS}, "pending"]),
    ));
    assert_eq!(err_code(&pending), ERR_NOT_SYNCED, "{pending}");
    let earliest = node.handle(&req(
        "eth_estimateGas",
        json!([{"to": WBNB_ADDRESS}, "earliest"]),
    ));
    assert_eq!(err_code(&earliest), ERR_NOT_SYNCED, "{earliest}");
    let missing_to = node.handle(&req("eth_estimateGas", json!([{}, "latest"])));
    assert_eq!(err_code(&missing_to), ERR_PARAMS, "{missing_to}");
}

#[test]
fn eth_call_and_estimate_gas_reject_overrides() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    assert_call_constraints_rejected(&node, "eth_call");
    assert_call_constraints_rejected(&node, "eth_estimateGas");
}

#[test]
fn get_block_latest_is_safe_header() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let safe_hash = format!("0x{}", hex::encode(chain[0].hash));
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getBlockByNumber", json!(["latest", false])));
    assert_eq!(v["result"]["hash"], json!(safe_hash));
    assert_eq!(v["result"]["transactions"], json!([]));
}

#[test]
fn get_block_tx_count_and_index_empty_root() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let safe_hash = format!("0x{}", hex::encode(chain[0].hash));
    let node = node_from_chain(chain, rpc.proof_json());
    let n = node.handle(&req(
        "eth_getBlockTransactionCountByNumber",
        json!(["latest"]),
    ));
    assert_eq!(n["result"], json!("0x0"), "{n}");
    let h = node.handle(&req(
        "eth_getBlockTransactionCountByHash",
        json!([safe_hash]),
    ));
    assert_eq!(h["result"], json!("0x0"), "{h}");
    let by_n = node.handle(&req(
        "eth_getTransactionByBlockNumberAndIndex",
        json!(["latest", "0x0"]),
    ));
    assert!(by_n["result"].is_null(), "{by_n}");
    let by_h = node.handle(&req(
        "eth_getTransactionByBlockHashAndIndex",
        json!([safe_hash, "0x0"]),
    ));
    assert!(by_h["result"].is_null(), "{by_h}");
    let by_hash = node.handle(&req("eth_getBlockByHash", json!([safe_hash, false])));
    assert_eq!(by_hash["result"]["transactions"], json!([]), "{by_hash}");
}

#[test]
fn get_block_above_safe_errors() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let tip = chain.last().unwrap().number;
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_getBlockByNumber",
        json!([format!("0x{tip:x}"), false]),
    ));
    assert_eq!(err_code(&v), ERR_NOT_SYNCED);
}

#[test]
fn parlia_uncles_are_empty_at_safe() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let safe_hash = format!("0x{}", hex::encode(chain[0].hash));
    let tip = chain.last().unwrap().number;
    let node = node_from_chain(chain, rpc.proof_json());
    let n = node.handle(&req("eth_getUncleCountByBlockNumber", json!(["latest"])));
    assert_eq!(n["result"], json!("0x0"), "{n}");
    let h = node.handle(&req("eth_getUncleCountByBlockHash", json!([safe_hash])));
    assert_eq!(h["result"], json!("0x0"), "{h}");
    let u = node.handle(&req(
        "eth_getUncleByBlockNumberAndIndex",
        json!(["latest", "0x0"]),
    ));
    assert!(u["result"].is_null(), "{u}");
    let above = node.handle(&req(
        "eth_getUncleCountByBlockNumber",
        json!([format!("0x{tip:x}")]),
    ));
    assert_eq!(err_code(&above), ERR_NOT_SYNCED);
    let coin = node.handle(&req("eth_coinbase", json!([])));
    assert_eq!(
        coin["result"],
        json!("0x0000000000000000000000000000000000000000")
    );
}

#[test]
fn get_block_hydrated_unsupported() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getBlockByNumber", json!(["latest", true])));
    assert_eq!(err_code(&v), ERR_METHOD);
}

#[test]
fn get_block_lying_state_root_fail_closed() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let mut up = MockUpstream::for_chain(&chain, rpc.proof_json());
    up.lie_state_root = true;
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getBlockByNumber", json!(["latest", false])));
    assert_eq!(err_code(&v), ERR_STATE_ROOT);
}

#[test]
fn get_block_prefers_stored_header_over_lying_refetch() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/mainnet/header_116664000.json");
    let hdr: RpcBlockHeader =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let hash = header_hash(&hdr).unwrap();
    let mut chain = distinct_sealer_chain(15);
    chain[0].number = decode_u64(&hdr.number).unwrap();
    chain[0].hash = hash;
    chain[0].state_root = decode_hex_fixed::<32>(&hdr.state_root).unwrap();
    chain[0].header = Some(hdr.clone());
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.lie_state_root = true;
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getBlockByNumber", json!(["latest", false])));
    // Stored header Hash()/stateRoot match. Lying refetch would be ERR_STATE_ROOT.
    // Fixture transactionsRoot is non-empty; mock has no raw envelopes → hashes omitted.
    assert_eq!(
        v["result"]["hash"],
        json!(format!("0x{}", hex::encode(hash))),
        "{v}"
    );
    assert_eq!(v["result"]["transactions"], json!([]), "{v}");
}

#[test]
fn filters_and_subscribe_unsupported() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    for m in [
        "eth_newFilter",
        "eth_newBlockFilter",
        "eth_subscribe",
        "eth_getFilterChanges",
        "eth_newPendingTransactionFilter",
        "eth_uninstallFilter",
        "eth_getFilterLogs",
        "eth_unsubscribe",
    ] {
        let v = node.handle(&req(m, json!([])));
        assert_eq!(err_code(&v), ERR_METHOD, "{m}: {v}");
    }
}

#[test]
fn pending_tag_not_synced() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "pending"])));
    assert_eq!(err_code(&v), ERR_NOT_SYNCED);
    let earliest = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "earliest"])));
    assert_eq!(err_code(&earliest), ERR_NOT_SYNCED);
    let blk = node.handle(&req("eth_getBlockByNumber", json!(["earliest", false])));
    assert_eq!(err_code(&blk), ERR_NOT_SYNCED);
}

#[test]
fn walk_honest_fixtures_parent_links() {
    let up = MockUpstream::from_rpc(MockRpc::new(Scenario::HonestFixtures)).unwrap();
    let tip = up.tip;
    let chain = walk_headers(&up, tip - 4, tip).expect("honest fixtures");
    assert_eq!(chain.len(), 5);
    assert_eq!(
        chain[0].hash,
        decode_hex_fixed::<32>(&up.headers[0].hash).unwrap()
    );
}

fn dummy_sealing_set() -> Vec<String> {
    (1..=21).map(|i| format!("0x{:040x}", 0xee00 + i)).collect()
}

#[test]
fn checkpoint_walk_rejects_unauthorized_sealer() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let mut cp = rpc.checkpoint().unwrap();
    cp.sealing_set = dummy_sealing_set();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let tip = up.tip;
    let err = walk_from_checkpoint(&up, cp, tip, 130)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not in active sealing set"),
        "unexpected error: {err}"
    );
}

#[test]
fn padded_fixture_set_fails_inturn() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let tip = up.tip;
    let err = walk_from_checkpoint(&up, cp, tip, 130)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("difficulty") || err.contains("in-turn"),
        "padded set must not fake in-turn: {err}"
    );
}

#[test]
fn checkpoint_walk_accepts_authorized_sealers() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let tip = up.tip;
    let (chain, snap) = walk_from_checkpoint_inturn(&up, cp, tip, 130, false).expect("authorized");
    assert_eq!(chain.last().unwrap().number, tip);
    assert_eq!(snap.number, tip);
    assert_ne!(chain[0].miner, [0u8; 20]);
}

#[test]
fn checkpoint_too_far_behind_tip() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let tip = up.tip;
    let err = walk_from_checkpoint(&up, cp, tip, 1)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("blocks behind tip") || err.contains("CheckpointTooFar"),
        "{err}"
    );
}

#[test]
fn bootstrap_from_checkpoint_unauthorized_err() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let mut cp = rpc.checkpoint().unwrap();
    cp.sealing_set = dummy_sealing_set();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let err = match Node::bootstrap_from_checkpoint(Box::new(up), 130, 130, cp) {
        Ok(_) => panic!("unauthorized checkpoint unexpectedly bootstrapped"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("not in active sealing set"), "{err}");
}

#[test]
fn persist_last_verified_roundtrip() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let up = MockUpstream::from_rpc(rpc).unwrap();
    let tip = up.tip;
    let (chain, snap) = walk_from_checkpoint_inturn(&up, cp, tip, 130, false).unwrap();
    let path = std::env::temp_dir().join(format!(
        "helios-bsc-last-verified-{}-{tip}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut node = Node::from_parts_with_snapshot(Box::new(up), 130, chain, snap, "fermi");
    node.set_checkpoint_store(path.clone());
    node.persist_verified_tip();
    let raw = std::fs::read_to_string(&path).expect("persisted checkpoint");
    let loaded: Checkpoint = serde_json::from_str(&raw).unwrap();
    assert_eq!(loaded.number, tip);
    assert_eq!(loaded.sealing_set.len(), 21);
    let rpc2 = MockRpc::new(Scenario::HonestFixtures);
    let up2 = MockUpstream::from_rpc(rpc2).unwrap();
    let (chain2, snap2) = walk_from_checkpoint_inturn(&up2, loaded, tip, 130, false).unwrap();
    assert_eq!(chain2.last().unwrap().number, tip);
    assert_eq!(snap2.number, tip);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn verification_status_reports_no_sealing_set_in_lookback_mode() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("helios_bsc_getVerificationStatus", json!([])));
    assert_eq!(v["result"]["sealingSetEnforced"], json!(false));
    assert_eq!(v["result"]["finality"], json!("confirmation-depth"));
    assert_eq!(v["result"]["requiredSealers"], json!(15));
    assert_eq!(v["result"]["trustClass"], json!("verified"));
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st["result"]["sealingSetEnforced"], json!(false));
    assert_eq!(st["result"]["finality"], json!("confirmation-depth"));
    assert_eq!(st["result"]["trustClass"], json!("verified"));
    assert_eq!(st["result"]["safeLagBlocks"], st["result"]["lag"]);
    assert!(st["result"]["safeLagSeconds"].as_u64().is_some());
    assert_eq!(st["result"]["blockIntervalMs"], json!(450));
    assert_eq!(st["result"]["unverifiedPassthrough"], json!(false));
    assert_eq!(st["result"]["backupTransport"], json!(false));
    let mut node_b = node_from_chain(distinct_sealer_chain(15), rpc.proof_json());
    node_b.set_backup_transport(true);
    let st_b = node_b.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st_b["result"]["backupTransport"], json!(true));
    assert_eq!(st["result"]["expectedSafeLagBlocks"], json!(120));
}

#[test]
fn proof_counters_ok_and_fail() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain.clone(), rpc.proof_json());
    let ok = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert!(ok.get("result").is_some(), "{ok}");
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert!(st["result"]["proofOk"].as_u64().unwrap() >= 1);
    assert_eq!(st["result"]["proofFail"].as_u64().unwrap(), 0);

    let lying = MockRpc::new(Scenario::LyingBalance).proof_json();
    let node_bad = node_from_chain(chain, lying);
    let _ = node_bad.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    let st_bad = node_bad.handle(&req("helios_bsc_syncStatus", json!([])));
    assert!(st_bad["result"]["proofFail"].as_u64().unwrap() >= 1);
}

#[test]
fn metrics_are_off_by_default_and_opt_in() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let mut node = node_from_chain(chain, rpc.proof_json());
    assert!(!node.metrics_enabled(), "metrics must default to off");
    node.set_metrics_enabled(true);
    assert!(node.metrics_enabled());
}

#[test]
fn metrics_text_is_prometheus_and_tracks_proof_counters() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain.clone(), rpc.proof_json());
    let ok = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    assert!(ok.get("result").is_some(), "{ok}");

    let m = node.metrics_text();
    for name in [
        "helios_bsc_headers_verified_total",
        "helios_bsc_header_verify_fail_total",
        "helios_bsc_proof_success_total",
        "helios_bsc_proof_fail_total",
        "helios_bsc_upstream_errors_total",
        "helios_bsc_safe_lag_blocks",
        "helios_bsc_safe_lag_seconds",
        "helios_bsc_checkpoint_age_seconds",
        "helios_bsc_finality_mode",
    ] {
        assert!(
            m.contains(&format!("# TYPE {name} ")),
            "missing {name}:\n{m}"
        );
        assert!(
            m.lines().any(|l| l.starts_with(&format!("{name} "))),
            "no sample line for {name}:\n{m}"
        );
    }
    assert!(m.contains("helios_bsc_proof_success_total 1"), "{m}");
    assert!(m.contains("helios_bsc_proof_fail_total 0"), "{m}");
    assert!(m.contains("helios_bsc_finality_mode 0"), "{m}");

    // A rejected proof must move proof_fail, not upstream_errors.
    let lying = MockRpc::new(Scenario::LyingBalance).proof_json();
    let bad = node_from_chain(chain, lying);
    let _ = bad.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));
    let mb = bad.metrics_text();
    assert!(mb.contains("helios_bsc_proof_fail_total 1"), "{mb}");
    assert!(mb.contains("helios_bsc_upstream_errors_total 0"), "{mb}");
}

/// Regression: a scrape must not queue behind a sync holding the chain lock.
/// A live run stalled `/metrics` for 180s because it took that mutex; the gauges
/// are published to atomics instead, so this must return while the lock is held.
#[test]
fn metrics_do_not_take_the_chain_lock() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let _ = node.handle(&req("eth_getBalance", json!([WBNB_ADDRESS, "latest"])));

    let held = node.lock_chain_for_test();
    // Would deadlock (std Mutex is not reentrant) if metrics touched the chain.
    let m = node.metrics_text();
    drop(held);

    assert!(m.contains("helios_bsc_tip_block "), "{m}");
    assert!(m.contains("helios_bsc_safe_lag_blocks "), "{m}");
}

/// Before the first sync the gauges must say "unknown" (-1), never a fake 0 that
/// would read as "tip is block 0" or "zero lag" on a dashboard.
#[test]
fn metrics_report_unknown_before_first_sync() {
    let node = node_from_chain(
        Vec::new(),
        MockRpc::new(Scenario::HonestFixtures).proof_json(),
    );
    let m = node.metrics_text();
    assert!(m.contains("helios_bsc_tip_block -1"), "{m}");
    assert!(m.contains("helios_bsc_safe_block -1"), "{m}");
    assert!(m.contains("helios_bsc_safe_lag_blocks -1"), "{m}");
    assert!(m.contains("helios_bsc_checkpoint_age_seconds -1"), "{m}");
}

fn snapshot_for_chain(chain: &[VerifiedBlock]) -> Snapshot {
    let g = &chain[0];
    let mut set: Vec<String> = chain
        .iter()
        .map(|b| format!("0x{}", hex::encode(b.miner)))
        .collect();
    set.sort();
    set.dedup();
    let mut i = 1u8;
    while set.len() < 21 {
        let a = format!("0x{:040x}", 0xee00 + u32::from(i));
        if !set.iter().any(|s| s.eq_ignore_ascii_case(&a)) {
            set.push(a);
        }
        i = i.wrapping_add(1);
        if i == 0 {
            break;
        }
    }
    let cp = Checkpoint {
        chain_id: 56,
        number: g.number,
        hash: format!("0x{}", hex::encode(g.hash)),
        parent_hash: format!("0x{}", hex::encode([0u8; 32])),
        state_root: format!("0x{}", hex::encode(g.state_root)),
        timestamp: 1_768_357_801,
        fork_id: "fermi".into(),
        sealing_set: set,
        vote_keys: None,
        attestation: None,
    };
    Snapshot::from_checkpoint(&cp).unwrap()
}

/// Node with a sealing-set snapshot, so the fast-finality fields have somewhere to live.
fn node_with_snapshot() -> Node {
    let chain = distinct_sealer_chain(15);
    let snap = snapshot_for_chain(&chain);
    let up = MockUpstream::for_chain(&chain, json!({}));
    Node::from_parts_with_snapshot(Box::new(up), 130, chain, snap, "fermi")
}

#[test]
fn finality_is_confirmation_depth_until_an_attestation_is_seen() {
    let node = node_with_snapshot();

    let m = node.metrics_text();
    // `-1`, never `0`: a dashboard must not read "no finalized head yet" as "lag zero".
    assert!(m.contains("helios_bsc_finalized_block -1"), "{m}");
    assert!(m.contains("helios_bsc_finalized_lag_blocks -1"), "{m}");
    assert!(m.contains("helios_bsc_justified_block -1"), "{m}");
    assert!(m.contains("helios_bsc_finality_mode 0"), "{m}");

    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st["result"]["finality"], json!("confirmation-depth"));
    assert_eq!(st["result"]["finalizedBlock"], Value::Null);
    assert_eq!(st["result"]["finalizedHash"], Value::Null);
    assert_eq!(st["result"]["justifiedBlock"], Value::Null);
    assert_eq!(st["result"]["finalizedLagBlocks"], Value::Null);
    // A snapshot without BLS vote keys is a normal state, not an error.
    assert_eq!(st["result"]["fastFinalityAvailable"], json!(false));
}

#[test]
fn published_finality_reaches_metrics_and_sync_status() {
    let node = node_with_snapshot();
    let st0 = node.handle(&req("helios_bsc_syncStatus", json!([])));
    let tip = st0["result"]["tip"].as_u64().expect("tip");
    // The finality lag is measured against the snapshot head, not the upstream tip — the
    // two are sampled at different instants. See `status_fields`.
    // `finalityHead` is the verified head the lags are measured against; `refresh`
    // publishes it together with the heads themselves.
    let head = st0["result"]["finalityHead"]
        .as_u64()
        .expect("finalityHead");
    assert_eq!(head, tip, "with a settled mock chain the two coincide");

    // Live mainnet lag: justified = head-1, finalized = head-2.
    let justified_hash = [0xa1u8; 32];
    let finalized_hash = [0xb2u8; 32];
    node.publish_finality_for_test((head - 1, justified_hash), (head - 2, finalized_hash));

    let m = node.metrics_text();
    assert!(
        m.contains(&format!("helios_bsc_finalized_block {}", head - 2)),
        "{m}"
    );
    assert!(
        m.contains(&format!("helios_bsc_justified_block {}", head - 1)),
        "{m}"
    );
    assert!(m.contains("helios_bsc_finalized_lag_blocks 2"), "{m}");
    assert!(m.contains("helios_bsc_finality_mode 1"), "{m}");

    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    let r = &st["result"];
    assert_eq!(r["finality"], json!("fast-finality"));
    assert_eq!(r["finalizedBlock"], json!(head - 2));
    assert_eq!(r["justifiedBlock"], json!(head - 1));
    assert_eq!(r["finalizedLagBlocks"], json!(2));
    assert_eq!(r["justifiedLagBlocks"], json!(1));
    assert_eq!(
        r["finalizedHash"],
        json!(format!("0x{}", hex::encode(finalized_hash)))
    );
    assert_eq!(
        r["justifiedHash"],
        json!(format!("0x{}", hex::encode(justified_hash)))
    );

    // Confirmation-depth reporting must be untouched — this change is additive, and no
    // block tag resolves to the finalized head.
    assert_eq!(r["safe"], json!(tip - 15));
    assert_eq!(r["safeLagBlocks"], r["lag"]);
    assert_eq!(r["requiredSealers"], json!(15));
}

#[test]
fn finality_gauges_do_not_take_the_chain_lock() {
    let node = node_with_snapshot();
    let tip = node.handle(&req("helios_bsc_syncStatus", json!([])))["result"]["tip"]
        .as_u64()
        .expect("tip");
    node.publish_finality_for_test((tip - 1, [0xa1u8; 32]), (tip - 2, [0xb2u8; 32]));

    let held = node.lock_chain_for_test();
    // Would deadlock (std Mutex is not reentrant) if a finality gauge touched the chain.
    let m = node.metrics_text();
    drop(held);

    assert!(m.contains("helios_bsc_finalized_block "), "{m}");
    assert!(m.contains("helios_bsc_finalized_lag_blocks "), "{m}");
    assert!(m.contains("helios_bsc_justified_block "), "{m}");
}

/// Without a checkpoint there is no snapshot, so there are no BLS vote keys and no
/// attestation — `fast_finality_head` then answers with the confirmation-depth head.
/// That is the safe direction but a silent one: `soak --finality fast` used to print
/// `GATE: PASS` having compared at lag ~108, never touching the mode it gates. The soak
/// now refuses that configuration up front; this pins the fallback it refuses on.
#[test]
fn fast_finality_head_without_a_snapshot_is_confirmation_depth() {
    let chain = distinct_sealer_chain(15);
    let conf = crate::sync::safe_of(&chain).expect("safe");
    let head = crate::sync::fast_finality_head(&chain, None, &conf);
    assert_eq!(
        head.number, conf.number,
        "no snapshot must not move the head"
    );
    assert_eq!(head.hash, conf.hash);
    assert_eq!(head.state_root, conf.state_root);
}

/// A finalized head only moves the read head when the client verified that exact block
/// itself. An attestation naming a block we never walked is an upstream's word.
#[test]
fn fast_finality_head_must_be_in_the_local_chain() {
    let chain = distinct_sealer_chain(15);
    let snap = snapshot_for_chain(&chain);
    let up = MockUpstream::for_chain(&chain, json!({}));
    let mut node = Node::from_parts_with_snapshot(Box::new(up), 130, chain, snap, "fermi");
    node.set_finality_mode(FinalityMode::Fast);

    let before = node.handle(&req("helios_bsc_syncStatus", json!([])));
    let conf_safe = before["result"]["safe"].as_u64().expect("safe");
    let tip = before["result"]["tip"].as_u64().expect("tip");

    // Real number, hash that is not in the chain.
    node.publish_finality_for_test((tip, [0x77u8; 32]), (tip - 1, [0x88u8; 32]));
    let after = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(
        after["result"]["safe"].as_u64(),
        Some(conf_safe),
        "unverified finalized hash must not move the read head"
    );
    assert_eq!(after["result"]["safeSource"], json!("confirmation-depth"));
}

/// Enabling the flag can only make reads fresher. If BLS finality stalls behind the
/// confirmation-depth head, tags stay on the confirmation-depth head.
#[test]
fn stalled_fast_finality_does_not_move_reads_backwards() {
    // 21 blocks, not the usual 16: with exactly 15 distinct sealers Safe lands on the
    // very first block, leaving nothing verified below it to stall on.
    let chain = distinct_sealer_chain(20);
    // A block strictly below the confirmation-depth Safe head, taken from the chain so
    // the hash is one the client really verified — the point is the height, not the hash.
    let expected_safe = newest_safe(&chain, 21).expect("safe").number;
    let stale_block = chain
        .iter()
        .find(|b| b.number == expected_safe - 1)
        .expect("a verified block below Safe")
        .clone();

    let snap = snapshot_for_chain(&chain);
    let up = MockUpstream::for_chain(&chain, json!({}));
    let mut node = Node::from_parts_with_snapshot(Box::new(up), 130, chain, snap, "fermi");
    node.set_finality_mode(FinalityMode::Fast);

    let conf_safe = node.handle(&req("helios_bsc_syncStatus", json!([])))["result"]["safe"]
        .as_u64()
        .expect("safe");
    let stale = stale_block.number;
    assert!(
        stale < conf_safe,
        "fixture must put the stale head below Safe"
    );

    node.publish_finality_for_test((stale, stale_block.hash), (stale, stale_block.hash));
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st["result"]["safe"].as_u64(), Some(conf_safe));
    assert_eq!(st["result"]["safeSource"], json!("confirmation-depth"));
    // The finality fields still report the stalled head honestly.
    assert_eq!(st["result"]["finalizedBlock"].as_u64(), Some(stale));
}

/// Default build must be byte-for-byte the confirmation-depth behaviour even when a
/// finalized head is known — the flag is the only thing that changes what tags mean.
#[test]
fn finality_flag_is_opt_in() {
    let node = node_with_snapshot();
    let st0 = node.handle(&req("helios_bsc_syncStatus", json!([])));
    let conf_safe = st0["result"]["safe"].as_u64().expect("safe");
    let head = st0["result"]["finalityHead"].as_u64().expect("head");
    assert_eq!(st0["result"]["finalityMode"], json!("confirmation-depth"));

    node.publish_finality_for_test((head - 1, [0xa1u8; 32]), (head - 2, [0xb2u8; 32]));
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(
        st["result"]["safe"].as_u64(),
        Some(conf_safe),
        "without --finality fast the read head must not move"
    );
    assert_eq!(st["result"]["safeSource"], json!("confirmation-depth"));
    // ...while still *reporting* fast finality.
    assert_eq!(st["result"]["finality"], json!("fast-finality"));
}

#[test]
fn sync_status_keeps_every_pre_existing_key() {
    // Wallets and `scripts/soak_vs_oracle.py` read these by name; a later refactor must
    // not be able to drop one silently while the new finality keys distract review.
    let node = node_with_snapshot();
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    let r = st["result"].as_object().expect("status object");
    for key in [
        "trustClass",
        "finality",
        "forkId",
        "tip",
        "safe",
        "safeHash",
        "lag",
        "safeLagBlocks",
        "safeLagSeconds",
        "blockIntervalMs",
        "distinctSealers",
        "requiredSealers",
        "nSeal",
        "proofWindow",
        "inProofWindow",
        "sealingSetEnforced",
        "originCheckpoint",
        "proofOk",
        "proofFail",
        "headersVerified",
        "unverifiedPassthrough",
        "backupTransport",
        "expectedSafeLagBlocks",
        "safeLagWithinBound",
    ] {
        assert!(r.contains_key(key), "syncStatus lost key {key}: {st}");
    }
}

#[test]
fn sync_status_sealing_set_enforced_with_checkpoint() {
    let chain = distinct_sealer_chain(15);
    let snap = snapshot_for_chain(&chain);
    let up = MockUpstream::for_chain(&chain, json!({}));
    let node = Node::from_parts_with_snapshot(Box::new(up), 130, chain, snap, "fermi");
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st["result"]["sealingSetEnforced"], json!(true));
    assert_eq!(st["result"]["originCheckpoint"], json!(0));
    let vs = node.handle(&req("helios_bsc_getVerificationStatus", json!([])));
    assert_eq!(vs["result"]["sealingSetEnforced"], json!(true));
}

#[test]
fn oracle_agrees_on_checkpoint() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let oracle = MockUpstream::from_rpc(rpc).unwrap();
    confirm_checkpoint_with_oracle(&cp, &oracle).expect("honest oracle");
}

#[test]
fn lying_oracle_state_root_rejected() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let cp = rpc.checkpoint().unwrap();
    let mut oracle = MockUpstream::from_rpc(rpc).unwrap();
    oracle.lie_state_root = true;
    let err = confirm_checkpoint_with_oracle(&cp, &oracle)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("stateRoot") || err.contains("checkpoint"),
        "{err}"
    );
}

fn fixture_safe_head(rpc: &MockRpc) -> SafeHead {
    SafeHead {
        number: 1,
        hash: rpc.headers()[0].hash.clone(),
        state_root: format!("0x{}", hex::encode(rpc.fixture_state_root())),
        distinct_sealers: 15,
        required_sealers: 15,
    }
}

#[test]
fn soak_list_has_at_least_ten() {
    assert!(SOAK_ADDRESSES.len() >= 10);
    let list = soak_list(WBNB_ADDRESS);
    assert!(list.len() >= 12);
    assert_eq!(list[0], ("probe", WBNB_ADDRESS));
}

#[test]
fn diff_oracle_match_on_wbnb() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let safe = fixture_safe_head(&rpc);
    let proofs = MockUpstream::from_rpc(rpc).unwrap();
    let oracle = MockUpstream {
        balance: proofs.balance.clone(),
        ..MockUpstream::from_rpc(MockRpc::new(Scenario::HonestFixtures)).unwrap()
    };
    let report = diff_vs_oracle(&proofs, &oracle, &[("WBNB", WBNB_ADDRESS)], &safe);
    assert_eq!(report.compared, 1);
    assert_eq!(report.matched, 1);
    assert_eq!(report.mismatched, 0);
}

#[test]
fn diff_oracle_mismatch_fail_closed() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let safe = fixture_safe_head(&rpc);
    let proofs = MockUpstream::from_rpc(rpc).unwrap();
    let mut oracle = MockUpstream::from_rpc(MockRpc::new(Scenario::HonestFixtures)).unwrap();
    oracle.balance = "0x1".into();
    let report = diff_vs_oracle(&proofs, &oracle, &[("WBNB", WBNB_ADDRESS)], &safe);
    assert_eq!(report.mismatched, 1);
    assert_eq!(report.matched, 0);
}

#[test]
fn diff_oracle_historical_skip() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let safe = fixture_safe_head(&rpc);
    let proofs = MockUpstream::from_rpc(rpc).unwrap();
    let mut oracle = MockUpstream::from_rpc(MockRpc::new(Scenario::HonestFixtures)).unwrap();
    oracle.fail_balance = true;
    let report = diff_vs_oracle(&proofs, &oracle, &[("WBNB", WBNB_ADDRESS)], &safe);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.compared, 0);
}

#[test]
fn receipt_disabled_without_flag() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req("eth_getTransactionReceipt", json!(["0x01"])));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
    let g = node.handle(&req("eth_gasPrice", json!([])));
    assert_eq!(err_code(&g), ERR_METHOD);
}

fn dummy_eip1559(chain_id: u64) -> Vec<u8> {
    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        let mut v = vec![0x80 + b.len() as u8];
        v.extend_from_slice(b);
        v
    }
    fn be(n: u64) -> Vec<u8> {
        if n == 0 {
            return rlp_bytes(&[]);
        }
        let b = n.to_be_bytes();
        let i = b.iter().position(|x| *x != 0).unwrap_or(7);
        rlp_bytes(&b[i..])
    }
    let z = rlp_bytes(&[]);
    let mut to = vec![0x94];
    to.extend_from_slice(&[0u8; 20]);
    let mut payload = Vec::new();
    for item in [
        be(chain_id),
        z.clone(),
        z.clone(),
        z.clone(),
        be(21_000),
        to,
        z.clone(),
        z.clone(),
        vec![0xc0],
        z,
        rlp_bytes(&[1]),
        rlp_bytes(&[1]),
    ] {
        payload.extend(item);
    }
    let mut out = vec![0x02, 0xc0 + payload.len() as u8];
    out.extend(payload);
    out
}

#[test]
fn send_raw_rejects_bad_hex_locally() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let empty = node.handle(&req("eth_sendRawTransaction", json!(["0x"])));
    assert_eq!(err_code(&empty), ERR_PARAMS);
    let odd = node.handle(&req("eth_sendRawTransaction", json!(["0xgg"])));
    assert_eq!(err_code(&odd), ERR_PARAMS);
    let eth = dummy_eip1559(1);
    let wrong = node.handle(&req(
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(eth))]),
    ));
    assert_eq!(err_code(&wrong), ERR_PARAMS, "{wrong}");
    let msg = wrong["error"]["message"].as_str().unwrap();
    assert!(msg.contains("chainId"), "{msg}");
    let sign = node.handle(&req("eth_sign", json!([])));
    assert_eq!(err_code(&sign), ERR_METHOD);
    let send = node.handle(&req("eth_sendTransaction", json!([{}])));
    assert_eq!(err_code(&send), ERR_METHOD);
    let dbg = node.handle(&req("debug_traceTransaction", json!([])));
    assert_eq!(err_code(&dbg), ERR_METHOD);
}

#[test]
fn blocked_namespaces_are_method_not_found() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    for m in [
        "rpc_modules",
        "clique_getSnapshot",
        "les_serverInfo",
        "parlia_getSnapshot",
        "bsc_getValidators",
    ] {
        let v = node.handle(&req(m, json!([])));
        assert_eq!(err_code(&v), ERR_METHOD, "{m}: {v}");
    }
}

#[test]
fn send_raw_rejects_oversize_body() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let huge = format!("0x{}", "00".repeat(MAX_RAW_TX + 1));
    let v = node.handle(&req("eth_sendRawTransaction", json!([huge])));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
}

#[test]
fn send_raw_binds_local_hash() {
    let chain = distinct_sealer_chain(15);
    let raw = dummy_eip1559(56);
    let hex_raw = format!("0x{}", hex::encode(&raw));
    let want = format!("0x{}", hex::encode(keccak256(&raw)));
    let node = node_from_chain(chain.clone(), json!({}));
    let v = node.handle(&req("eth_sendRawTransaction", json!([hex_raw.clone()])));
    assert_eq!(v["result"], json!(want), "{v}");

    let mut lying = MockUpstream::for_chain(&chain, json!({}));
    lying.lie_raw_hash = Some(format!("0x{}", "ff".repeat(32)));
    let node = Node::from_parts(Box::new(lying), 130, chain);
    let bad = node.handle(&req("eth_sendRawTransaction", json!([hex_raw])));
    assert_eq!(err_code(&bad), ERR_PROOF_FAILED, "{bad}");
    let msg = bad["error"]["message"].as_str().unwrap();
    assert!(msg.contains("hash"), "{msg}");
}

fn chain_omitted_receipts_root() -> Vec<VerifiedBlock> {
    let mut chain = distinct_sealer_chain(15);
    let mut hdr = header_from_verified(&chain[0], [0u8; 32]);
    hdr.receipts_root = format!("0x{}", hex::encode([0x11u8; 32]));
    let hash = header_hash(&hdr).unwrap();
    hdr.hash = format!("0x{}", hex::encode(hash));
    chain[0].hash = hash;
    chain[0].header = Some(hdr);
    chain
}

#[test]
fn receipt_header_bound_with_flag() {
    let chain = chain_omitted_receipts_root();
    let safe = newest_safe(&chain, 21).expect("safe");
    let txh = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!({
        "blockHash": safe.hash,
        "blockNumber": format!("0x{:x}", safe.number),
        "status": "0x1",
        "transactionHash": txh,
    });
    let mut node = Node::from_parts(Box::new(up), 130, chain.clone());
    node.set_allow_unverified_passthrough(true);
    let short = node.handle(&req("eth_getTransactionReceipt", json!(["0x01"])));
    assert_eq!(err_code(&short), ERR_PARAMS, "{short}");
    let v = node.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert_eq!(v["result"]["status"], json!("0x1"), "{v}");

    let empty_root = distinct_sealer_chain(15);
    let empty_safe = newest_safe(&empty_root, 21).expect("safe");
    let mut empty_up = MockUpstream::for_chain(&empty_root, json!({}));
    empty_up.unverified = json!({
        "blockHash": empty_safe.hash,
        "blockNumber": format!("0x{:x}", empty_safe.number),
        "status": "0x1",
        "transactionHash": txh,
    });
    let mut empty_node = Node::from_parts(Box::new(empty_up), 130, empty_root);
    empty_node.set_allow_unverified_passthrough(true);
    let empty = empty_node.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert!(empty["result"].is_null(), "{empty}");

    let swapped = {
        let mut u = MockUpstream::for_chain(&chain, json!({}));
        u.unverified = json!({
            "blockHash": safe.hash,
            "blockNumber": format!("0x{:x}", safe.number),
            "transactionHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        });
        u
    };
    let mut swap_node = Node::from_parts(Box::new(swapped), 130, chain.clone());
    swap_node.set_allow_unverified_passthrough(true);
    let swap = swap_node.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert_eq!(err_code(&swap), ERR_NOT_SYNCED, "{swap}");
    let msg = swap["error"]["message"].as_str().unwrap();
    assert!(msg.contains("match request"), "{msg}");

    let pending_up = {
        let mut u = MockUpstream::for_chain(&chain, json!({}));
        u.unverified = json!({
            "blockHash": Value::Null,
            "blockNumber": Value::Null,
            "hash": txh,
        });
        u
    };
    let mut pending_node = Node::from_parts(Box::new(pending_up), 130, chain.clone());
    pending_node.set_allow_unverified_passthrough(true);
    let p = pending_node.handle(&req("eth_getTransactionByHash", json!([txh])));
    assert!(p.get("result").is_some(), "{p}");
    assert!(p["result"]["blockHash"].is_null());

    let tip = chain.last().unwrap();
    let mut lying = MockUpstream::for_chain(&chain, json!({}));
    lying.unverified = json!({
        "blockHash": format!("0x{}", hex::encode(tip.hash)),
        "blockNumber": format!("0x{:x}", tip.number),
        "status": "0x1",
        "transactionHash": txh,
    });
    let mut node_bad = Node::from_parts(Box::new(lying), 130, chain);
    node_bad.set_allow_unverified_passthrough(true);
    let bad = node_bad.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert_eq!(err_code(&bad), ERR_NOT_SYNCED);
    let call = node.handle(&req("eth_call", json!([{}, "latest"])));
    assert_eq!(err_code(&call), ERR_PARAMS);
}

#[test]
fn gas_price_passthrough_with_flag() {
    let chain = distinct_sealer_chain(15);
    let off = Node::from_parts(
        Box::new(MockUpstream::for_chain(&chain, json!({}))),
        130,
        chain.clone(),
    );
    let off_hist = off.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&off_hist), ERR_METHOD, "{off_hist}");
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!("0x12a05f200");
    let mut node = Node::from_parts(Box::new(up), 130, chain.clone());
    node.set_allow_unverified_passthrough(true);
    let v = node.handle(&req("eth_gasPrice", json!([])));
    assert_eq!(v["result"], json!("0x12a05f200"));
    let tip = node.handle(&req("eth_maxPriorityFeePerGas", json!([])));
    assert_eq!(tip["result"], json!("0x12a05f200"));
    let hist_bad = node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&hist_bad), ERR_PARAMS, "{hist_bad}");
    let mut obj_up = MockUpstream::for_chain(&chain, json!({}));
    obj_up.unverified = json!({"gasPrice": "0x1"});
    let mut obj_node = Node::from_parts(Box::new(obj_up), 130, chain.clone());
    obj_node.set_allow_unverified_passthrough(true);
    let obj = obj_node.handle(&req("eth_gasPrice", json!([])));
    assert_eq!(err_code(&obj), ERR_PARAMS, "{obj}");
    let mut hist_up = MockUpstream::for_chain(&chain, json!({}));
    hist_up.unverified = json!({"oldestBlock": "0x0", "baseFeePerGas": ["0x1"]});
    let mut hist_node = Node::from_parts(Box::new(hist_up), 130, chain.clone());
    hist_node.set_allow_unverified_passthrough(true);
    let hist = hist_node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(hist["result"]["oldestBlock"], json!("0x0"), "{hist}");
    let mut no_ob_up = MockUpstream::for_chain(&chain, json!({}));
    no_ob_up.unverified = json!({"baseFeePerGas": ["0x1"]});
    let mut no_ob = Node::from_parts(Box::new(no_ob_up), 130, chain.clone());
    no_ob.set_allow_unverified_passthrough(true);
    let no = no_ob.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(no["result"]["baseFeePerGas"], json!(["0x1"]), "{no}");
    let mut junk_up = MockUpstream::for_chain(&chain, json!({}));
    junk_up.unverified = json!({"oldestBlock": "latest", "baseFeePerGas": ["0x1"]});
    let mut junk_node = Node::from_parts(Box::new(junk_up), 130, chain.clone());
    junk_node.set_allow_unverified_passthrough(true);
    let junk = junk_node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&junk), ERR_PARAMS, "{junk}");
    let mut above_up = MockUpstream::for_chain(&chain, json!({}));
    above_up.unverified = json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x1"]});
    let mut above_node = Node::from_parts(Box::new(above_up), 130, chain.clone());
    above_node.set_allow_unverified_passthrough(true);
    let above = above_node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&above), ERR_NOT_SYNCED, "{above}");
    let mut miss_up = MockUpstream::for_chain(&chain, json!({}));
    miss_up.unverified = json!({"oldestBlock": "0xff", "baseFeePerGas": ["0x1"]});
    let mut miss_node = Node::from_parts(Box::new(miss_up), 130, chain.clone());
    miss_node.set_allow_unverified_passthrough(true);
    let miss = miss_node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&miss), ERR_NOT_SYNCED, "{miss}");
    let mut bad_hist_up = MockUpstream::for_chain(&chain, json!({}));
    bad_hist_up.unverified = json!({"oldestBlock": "0x1", "baseFeePerGas": "0x1"});
    let mut bad_hist = Node::from_parts(Box::new(bad_hist_up), 130, chain);
    bad_hist.set_allow_unverified_passthrough(true);
    let bh = bad_hist.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(err_code(&bh), ERR_PARAMS, "{bh}");
    let st = node.handle(&req("helios_bsc_syncStatus", json!([])));
    assert_eq!(st["result"]["unverifiedPassthrough"], json!(true));
    assert_eq!(st["result"]["safeLagWithinBound"], json!(true));
}

#[test]
fn blob_base_fee_passthrough_with_flag() {
    let chain = distinct_sealer_chain(15);
    let off = Node::from_parts(
        Box::new(MockUpstream::for_chain(&chain, json!({}))),
        130,
        chain.clone(),
    );
    let v = off.handle(&req("eth_blobBaseFee", json!([])));
    assert_eq!(err_code(&v), ERR_METHOD);

    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!("0x12a05f200");
    let mut node = Node::from_parts(Box::new(up), 130, chain.clone());
    node.set_allow_unverified_passthrough(true);
    let v = node.handle(&req("eth_blobBaseFee", json!([])));
    assert_eq!(v["result"], json!("0x12a05f200"));

    let mut obj_up = MockUpstream::for_chain(&chain, json!({}));
    obj_up.unverified = json!({"blobBaseFee": "0x1"});
    let mut obj_node = Node::from_parts(Box::new(obj_up), 130, chain.clone());
    obj_node.set_allow_unverified_passthrough(true);
    let obj = obj_node.handle(&req("eth_blobBaseFee", json!([])));
    assert_eq!(err_code(&obj), ERR_PARAMS, "{obj}");

    let mut bad_up = MockUpstream::for_chain(&chain, json!({}));
    bad_up.unverified = json!("not-hex");
    let mut bad_node = Node::from_parts(Box::new(bad_up), 130, chain);
    bad_node.set_allow_unverified_passthrough(true);
    let bad = bad_node.handle(&req("eth_blobBaseFee", json!([])));
    assert_eq!(err_code(&bad), ERR_PARAMS, "{bad}");
}

#[test]
fn eth_call_null_to_is_invalid_params() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req("eth_call", json!([{"to": Value::Null}, "latest"])));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
}

#[test]
fn eth_call_state_override_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_call",
        json!([{"to": WBNB_ADDRESS, "stateOverride": {}}, "latest"]),
    ));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
}

#[test]
fn eth_call_third_params_element_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_call",
        json!([{"to": WBNB_ADDRESS}, "latest", {}]),
    ));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
}

#[test]
fn eth_call_blob_and_auth_list_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let blob = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "blobVersionedHashes": []},
            "latest"
        ]),
    ));
    assert_eq!(err_code(&blob), ERR_PARAMS, "{blob}");
    let auth = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "authorizationList": []},
            "latest"
        ]),
    ));
    assert_eq!(err_code(&auth), ERR_PARAMS, "{auth}");
}

#[test]
fn eth_call_lying_get_code_is_proof_failed() {
    let (mut chain, rpc) = safe_chain_with_fixture_root();
    chain[0].miner = decode_hex_fixed::<20>(WBNB_ADDRESS).unwrap();
    let mut up = MockUpstream::for_chain(&chain, rpc.proof_json());
    up.code = vec![0x00];
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "from": WBNB_ADDRESS, "data": "0x18160ddd"},
            "latest"
        ]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
}

#[test]
fn eth_call_object_block_id_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_call",
        json!([{"to": WBNB_ADDRESS}, {"blockNumber": "latest"}]),
    ));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
    let est = node.handle(&req(
        "eth_estimateGas",
        json!([{"to": WBNB_ADDRESS}, {"blockHash": "0x00"}]),
    ));
    assert_eq!(err_code(&est), ERR_PARAMS, "{est}");
}

fn rlp_len_be(len: usize) -> Vec<u8> {
    let be = (len as u64).to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[start..].to_vec()
}

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    if data.len() <= 55 {
        let mut o = Vec::with_capacity(1 + data.len());
        o.push(0x80 + data.len() as u8);
        o.extend_from_slice(data);
        o
    } else {
        let lenb = rlp_len_be(data.len());
        let mut o = Vec::with_capacity(1 + lenb.len() + data.len());
        o.push(0xb7 + lenb.len() as u8);
        o.extend_from_slice(&lenb);
        o.extend_from_slice(data);
        o
    }
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for i in items {
        payload.extend_from_slice(i);
    }
    if payload.len() <= 55 {
        let mut o = vec![0xc0 + payload.len() as u8];
        o.extend_from_slice(&payload);
        o
    } else {
        let lenb = rlp_len_be(payload.len());
        let mut o = Vec::with_capacity(1 + lenb.len() + payload.len());
        o.push(0xf7 + lenb.len() as u8);
        o.extend_from_slice(&lenb);
        o.extend_from_slice(&payload);
        o
    }
}

/// Single-leaf account trie so `eth_call` can run custom bytecode at Safe.
fn single_leaf_account_proof(address: [u8; 20], code: &[u8]) -> ([u8; 32], Value) {
    let code_hash = keccak256(code);
    let account = rlp_list(&[
        rlp_bytes(&[1]),
        rlp_bytes(&[]),
        rlp_bytes(&EMPTY_TRIE_ROOT),
        rlp_bytes(&code_hash),
    ]);
    let mut hp = vec![0x20];
    hp.extend_from_slice(&keccak256(&address));
    let leaf = rlp_list(&[rlp_bytes(&hp), rlp_bytes(&account)]);
    let state_root = keccak256(&leaf);
    let addr_hex = format!("0x{}", hex::encode(address));
    let proof = json!({
        "address": addr_hex,
        "accountProof": [format!("0x{}", hex::encode(leaf))],
        "balance": "0x0",
        "codeHash": format!("0x{}", hex::encode(code_hash)),
        "nonce": "0x1",
        "storageHash": format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
        "storageProof": []
    });
    (state_root, proof)
}

#[test]
fn eth_call_blockhash_of_safe_parent() {
    // Safe = chain[2] (number 2); parent number 1 is in-chain (15 subsequent sealers).
    let mut chain = distinct_sealer_chain(17);
    let safe = newest_safe(&chain, 21).expect("safe");
    let safe_n = safe.number;
    assert!(
        safe_n >= 1,
        "need Safe number N with parent N-1 in the dummy chain"
    );
    let parent_n = safe_n - 1;
    assert!(parent_n <= u64::from(u8::MAX), "PUSH1 BLOCKHASH argument");
    assert!(
        chain.iter().any(|b| b.number == parent_n),
        "parent of Safe must be in the dummy chain (too short otherwise)"
    );

    let addr = [0x22u8; 20];
    // PUSH1 parent_n; BLOCKHASH; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
    let code = vec![
        0x60,
        parent_n as u8,
        0x40,
        0x60,
        0x00,
        0x52,
        0x60,
        0x20,
        0x60,
        0x00,
        0xf3,
    ];
    let (root, proof) = single_leaf_account_proof(addr, &code);
    for b in &mut chain {
        if b.number == safe_n {
            b.state_root = root;
            b.miner = addr;
        }
    }
    relink_dummy_chain(&mut chain);
    let parent_hash = chain
        .iter()
        .find(|b| b.number == parent_n)
        .expect("parent")
        .hash;
    let mut up = MockUpstream::for_chain(&chain, proof);
    up.code = code;
    let node = Node::from_parts(Box::new(up), 130, chain);
    let addr_hex = format!("0x{}", hex::encode(addr));
    let v = node.handle(&req(
        "eth_call",
        json!([{"to": addr_hex, "from": addr_hex, "data": "0x"}, "latest"]),
    ));
    let got = v["result"].as_str().unwrap_or("");
    let zeros = format!("0x{}", hex::encode([0u8; 32]));
    assert_ne!(
        got.to_ascii_lowercase(),
        zeros,
        "in-window BLOCKHASH must not be Missing-as-zero: {v}"
    );
    let want = format!("0x{}", hex::encode(parent_hash));
    assert_eq!(
        got.to_ascii_lowercase(),
        want.to_ascii_lowercase(),
        "BLOCKHASH(Safe-1) must match the locally verified parent hash: {v}"
    );
    assert_eq!(got.len(), 2 + 64, "{v}");
}

#[test]
fn eth_call_unproven_name_still_proof_failed() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_wbnb_eth_call(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_call",
        json!([
            {"to": WBNB_ADDRESS, "from": WBNB_ADDRESS, "data": "0x06fdde03"},
            "latest"
        ]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
    assert_ne!(err_code(&v), 3, "{v}");
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("proof_verification_failed"), "{v}");
}

#[test]
fn eth_estimate_gas_unproven_name_still_proof_failed() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_wbnb_eth_call(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_estimateGas",
        json!([call_object(Some("0x06fdde03")), "latest"]),
    ));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
    assert_ne!(err_code(&v), 3, "{v}");
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("proof_verification_failed"), "{v}");
}

#[test]
fn get_balance_exact_safe_hex_ok() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let safe_n = chain[0].number;
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_getBalance",
        json!([WBNB_ADDRESS, format!("0x{safe_n:x}")]),
    ));
    assert!(v.get("result").is_some(), "{v}");
}

#[test]
fn get_balance_at_safe_minus_one_when_in_chain() {
    let rpc = MockRpc::new(Scenario::HonestFixtures);
    let root = rpc.fixture_state_root();
    let mut chain = distinct_sealer_chain(16);
    for b in &mut chain {
        b.state_root = root;
    }
    relink_dummy_chain(&mut chain);
    let safe = newest_safe(&chain, n_seal()).expect("safe");
    assert!(safe.number >= 1, "need a pre-Safe block");
    let below = safe.number - 1;
    assert!(
        chain.iter().any(|b| b.number == below),
        "safe-1 must be in-chain"
    );
    let node = node_from_chain(chain, rpc.proof_json());
    let v = node.handle(&req(
        "eth_getBalance",
        json!([WBNB_ADDRESS, format!("0x{below:x}")]),
    ));
    if v.get("error").is_some() {
        assert_ne!(err_code(&v), ERR_NOT_SYNCED, "{v}");
    } else {
        assert!(v.get("result").is_some(), "{v}");
    }
}

#[test]
fn get_balance_above_safe_not_synced() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let safe_n = chain[0].number;
    let tip = chain.last().unwrap().number;
    let node = node_from_chain(chain, rpc.proof_json());
    let above = node.handle(&req(
        "eth_getBalance",
        json!([WBNB_ADDRESS, format!("0x{:x}", safe_n + 1)]),
    ));
    assert_eq!(err_code(&above), ERR_NOT_SYNCED, "{above}");
    let at_tip = node.handle(&req(
        "eth_getBalance",
        json!([WBNB_ADDRESS, format!("0x{tip:x}")]),
    ));
    assert_eq!(err_code(&at_tip), ERR_NOT_SYNCED, "{at_tip}");
}

#[test]
fn get_balance_and_eth_call_object_block_id_rejected() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let bal = node.handle(&req(
        "eth_getBalance",
        json!([WBNB_ADDRESS, {"blockNumber": "latest"}]),
    ));
    assert_eq!(err_code(&bal), ERR_PARAMS, "{bal}");
    let call = node.handle(&req(
        "eth_call",
        json!([{"to": WBNB_ADDRESS}, {"blockNumber": "0x0"}]),
    ));
    assert_eq!(err_code(&call), ERR_PARAMS, "{call}");
}

#[test]
fn eth_call_access_list_junk_address_is_invalid_params() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    for method in ["eth_call", "eth_estimateGas"] {
        let v = node.handle(&req(
            method,
            json!([
                {
                    "to": WBNB_ADDRESS,
                    "accessList": [{"address": "not-an-address", "storageKeys": []}]
                },
                "latest"
            ]),
        ));
        assert_eq!(err_code(&v), ERR_PARAMS, "{method} junk: {v}");
        assert_eq!(err_code(&v), -32602, "{method} junk: {v}");
    }
}

#[test]
fn eth_call_access_list_too_large_is_invalid_params() {
    let (chain, rpc) = safe_chain_with_fixture_root();
    let node = node_from_chain(chain, rpc.proof_json());
    let huge: Vec<Value> = (0..=MAX_CALL_ACCOUNTS)
        .map(|i| {
            json!({
                "address": format!("0x{:040x}", i + 1),
                "storageKeys": []
            })
        })
        .collect();
    let too_many_keys: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
        .map(|i| json!(format!("0x{i:x}")))
        .collect();
    for method in ["eth_call", "eth_estimateGas"] {
        let v = node.handle(&req(
            method,
            json!([{"to": WBNB_ADDRESS, "accessList": huge}, "latest"]),
        ));
        assert_eq!(err_code(&v), ERR_PARAMS, "{method} huge: {v}");
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("accessList too large"), "{method} huge: {v}");

        let keys = node.handle(&req(
            method,
            json!([
                {
                    "to": WBNB_ADDRESS,
                    "accessList": [{"address": WBNB_ADDRESS, "storageKeys": too_many_keys}]
                },
                "latest"
            ]),
        ));
        assert_eq!(err_code(&keys), ERR_PARAMS, "{method} keys: {keys}");
        let msg = keys["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("accessList too large"),
            "{method} keys: {keys}"
        );
    }
}

#[test]
fn get_raw_tx_by_hash_disabled_without_flag() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let txh = format!("0x{}", "11".repeat(32));
    let v = node.handle(&req("eth_getRawTransactionByHash", json!([txh])));
    assert_eq!(err_code(&v), ERR_METHOD, "{v}");
}

#[test]
fn get_raw_tx_by_hash_keccak_bind_with_flag() {
    let chain = distinct_sealer_chain(15);
    let raw = dummy_eip1559(56);
    let hex_raw = format!("0x{}", hex::encode(&raw));
    let txh = format!("0x{}", hex::encode(keccak256(&raw)));

    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!(hex_raw.clone());
    let mut node = Node::from_parts(Box::new(up), 130, chain.clone());
    node.set_allow_unverified_passthrough(true);
    let v = node.handle(&req("eth_getRawTransactionByHash", json!([txh.clone()])));
    assert_eq!(v["result"], json!(hex_raw), "{v}");

    let mut lying = MockUpstream::for_chain(&chain, json!({}));
    lying.unverified = json!(format!("0x{}", hex::encode(dummy_eip1559(1))));
    let mut node_bad = Node::from_parts(Box::new(lying), 130, chain);
    node_bad.set_allow_unverified_passthrough(true);
    let bad = node_bad.handle(&req("eth_getRawTransactionByHash", json!([txh])));
    assert_eq!(err_code(&bad), ERR_PROOF_FAILED, "{bad}");
}

#[test]
fn dummy_empty_receipts_root_get_block_receipts_empty() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req("eth_getBlockReceipts", json!(["latest"])));
    assert_eq!(v["result"], json!([]), "{v}");
}

#[test]
fn get_logs_latest_empty_on_dummy() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req(
        "eth_getLogs",
        json!([{"fromBlock":"latest","toBlock":"latest"}]),
    ));
    assert_eq!(v["result"], json!([]), "{v}");
    let omitted = node.handle(&req("eth_getLogs", json!([{}])));
    assert_eq!(omitted["result"], json!([]), "{omitted}");
}

#[test]
fn get_logs_multi_block_range_invalid() {
    let chain = distinct_sealer_chain(15);
    let node = node_from_chain(chain, json!({}));
    let v = node.handle(&req(
        "eth_getLogs",
        json!([{"fromBlock":"0x0","toBlock":"0x1"}]),
    ));
    assert_eq!(err_code(&v), ERR_PARAMS, "{v}");
}

#[test]
fn get_logs_not_passthrough_deadbeef() {
    let chain = distinct_sealer_chain(15);
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!([{
        "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "topics": [],
        "data": "0xdeadbeef",
        "blockHash": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    }]);
    up.receipts = vec![json!({
        "status": "0x1",
        "cumulativeGasUsed": "0x1",
        "logsBloom": format!("0x{}", hex::encode([0u8; 256])),
        "logs": [{
            "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "topics": [],
            "data": "0xdeadbeef",
        }],
        "type": "0x0",
    })];
    let mut node = Node::from_parts(Box::new(up), 130, chain);
    node.set_allow_unverified_passthrough(true);
    let v = node.handle(&req("eth_getLogs", json!([{"fromBlock":"latest"}])));
    assert_eq!(v["result"], json!([]), "{v}");
    let s = v.to_string();
    assert!(!s.contains("deadbeef"), "{v}");
}

#[test]
fn get_block_receipts_root_mismatch_is_proof_failed() {
    let mut chain = distinct_sealer_chain(15);
    let rec = ConsensusReceipt {
        status: 1,
        cumulative_gas_used: 21_000,
        logs_bloom: [0u8; 256],
        logs: Vec::new(),
        tx_type: 2,
    };
    let raw = encode_consensus_receipt(&rec).unwrap();
    let root = ordered_trie_root(&[raw]);
    let mut hdr = header_from_verified(&chain[0], [0u8; 32]);
    hdr.receipts_root = format!("0x{}", hex::encode(root));
    let hash = header_hash(&hdr).unwrap();
    hdr.hash = format!("0x{}", hex::encode(hash));
    chain[0].hash = hash;
    chain[0].header = Some(hdr);
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.receipts = vec![json!({
        "status": "0x0",
        "cumulativeGasUsed": "0x1",
        "logsBloom": format!("0x{}", hex::encode([0u8; 256])),
        "logs": [],
        "type": "0x2",
        "transactionHash": format!("0x{}", "11".repeat(32)),
    })];
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getBlockReceipts", json!(["latest"])));
    assert_eq!(err_code(&v), ERR_PROOF_FAILED, "{v}");
}

#[test]
fn pending_receipt_still_passthrough_only() {
    let chain = distinct_sealer_chain(15);
    let txh = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.unverified = json!({
        "blockHash": Value::Null,
        "blockNumber": Value::Null,
        "transactionHash": txh,
        "status": "0x1",
    });
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert_eq!(err_code(&v), ERR_METHOD, "{v}");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("unverified_passthrough"), "{msg}");
}

#[test]
fn get_transaction_receipt_verified_without_flag() {
    let mut chain = distinct_sealer_chain(15);
    let rec = ConsensusReceipt {
        status: 1,
        cumulative_gas_used: 21_000,
        logs_bloom: [0u8; 256],
        logs: Vec::new(),
        tx_type: 2,
    };
    let raw = encode_consensus_receipt(&rec).unwrap();
    let root = ordered_trie_root(&[raw]);
    let mut hdr = header_from_verified(&chain[0], [0u8; 32]);
    hdr.receipts_root = format!("0x{}", hex::encode(root));
    let hash = header_hash(&hdr).unwrap();
    hdr.hash = format!("0x{}", hex::encode(hash));
    chain[0].hash = hash;
    chain[0].header = Some(hdr.clone());
    let txh = format!("0x{}", "11".repeat(32));
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.receipts = vec![json!({
        "status": "0x1",
        "cumulativeGasUsed": "0x5208",
        "logsBloom": format!("0x{}", hex::encode([0u8; 256])),
        "logs": [],
        "type": "0x2",
        "transactionHash": txh,
    })];
    up.unverified = json!({
        "blockHash": hdr.hash,
        "blockNumber": hdr.number,
        "transactionHash": txh,
        "status": "0x1",
    });
    let node = Node::from_parts(Box::new(up), 130, chain);
    let v = node.handle(&req("eth_getTransactionReceipt", json!([txh])));
    assert_eq!(v["result"]["status"], json!("0x1"), "{v}");
    assert_eq!(v["result"]["transactionHash"], json!(txh), "{v}");
    let blk = node.handle(&req("eth_getBlockReceipts", json!(["latest"])));
    assert_eq!(blk["result"].as_array().map(|a| a.len()), Some(1), "{blk}");
}

/// A 64-element batch is inside `MAX_RPC_BATCH`, and each element used to call
/// `refresh` — so one request in the size limit fired 64 upstream `eth_blockNumber`
/// calls and spent the operator's quota on itself. Inside one block interval the chain
/// cannot have moved, so the published sync answers them all.
#[test]
fn a_full_batch_costs_one_upstream_poll() {
    let chain = distinct_sealer_chain(15);
    let (node, calls) = node_counting_block_number(chain, json!({}));
    let batch: Vec<Value> = (0..MAX_RPC_BATCH)
        .map(|i| json!({"jsonrpc": "2.0", "id": i + 1, "method": "eth_blockNumber"}))
        .collect();
    let out = node.dispatch(&Value::Array(batch));
    assert_eq!(
        out.as_array().map(Vec::len),
        Some(MAX_RPC_BATCH),
        "every element must still be answered"
    );
    let n = calls.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(n, 1, "{MAX_RPC_BATCH} requests took {n} upstream polls");
}

/// The coalescing window must not swallow the background poller: it is what keeps the
/// window fed, so a poller that answered from its own cache would freeze the chain.
#[test]
fn the_background_poller_always_reaches_the_upstream() {
    let chain = distinct_sealer_chain(15);
    let (node, calls) = node_counting_block_number(chain, json!({}));
    for _ in 0..3 {
        let _ = node.poll_sync();
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "poll_sync must not coalesce"
    );
}

/// A panic while handling a request used to end the worker thread outright: `serve_one`
/// runs inside `while let Ok(req) = server.recv()`, so the loop simply exited. Four of
/// those and the listener accepted connections nobody answered — with the process still
/// up and `/metrics`, which reads only atomics, still reporting a healthy client.
///
/// The panic is injected in `headers_range`, i.e. *under* the chain and snapshot locks,
/// so the follow-up requests also exercise the poisoned-mutex path.
#[test]
fn a_panicking_request_is_answered_not_fatal() {
    let chain = distinct_sealer_chain(15);
    let mut up = MockUpstream::for_chain(&chain, json!({}));
    up.panic_in = Some("headers_range");
    // A tip far above the chain forces `resync_locked` into `headers_range`.
    up.tip = chain.last().unwrap().number + 5_000;
    let node = Node::from_parts(Box::new(up), 130, chain);

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}"#;
    for attempt in 1..=3 {
        assert!(
            node.dispatch_caught(body).is_err(),
            "attempt {attempt} should report a caught panic, not unwind"
        );
    }
    std::panic::set_hook(prev);

    assert!(
        node.metrics_text()
            .contains("helios_bsc_request_panics_total 3"),
        "every caught panic must be countable: {}",
        node.metrics_text()
    );
}

/// The caught panic is reported as JSON-RPC "Internal error", not as a bad request: the
/// request was well-formed and the failure is ours.
#[test]
fn a_caught_panic_is_internal_error_not_invalid_request() {
    assert_eq!(helios_bsc_rpc::ERR_INTERNAL, -32603);
}
