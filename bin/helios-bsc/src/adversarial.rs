//! PR 10: lying upstream through `Node::handle` (no network).

use crate::diff::{diff_vs_oracle, soak_list, SOAK_ADDRESSES};
use crate::sync::{
    confirm_checkpoint_with_oracle, walk_from_checkpoint, walk_from_checkpoint_inturn, walk_headers,
};
use crate::{Node, RpcUpstream};
use anyhow::{anyhow, Result};
use helios_bsc_consensus::{header_hash, newest_safe, Snapshot, VerifiedBlock};
use helios_bsc_execution::{encode_data32, encode_qty, MAX_RAW_TX, TX_GAS};
use helios_bsc_mock::{
    cycling_sealer_chain, distinct_sealer_chain, headers_from_chain, relink_dummy_chain, MockRpc,
    Scenario, WBNB_ADDRESS, WRONG_STATE_ROOT,
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
    proof: Value,
    /// When set, `header_by_hash` lies about `stateRoot` (hash/number still match).
    lie_state_root: bool,
    balance: String,
    fail_balance: bool,
    unverified: Value,
    code: Vec<u8>,
    /// When set, `send_raw_transaction` returns this hash instead of keccak(raw).
    lie_raw_hash: Option<String>,
}

impl MockUpstream {
    fn from_rpc(rpc: MockRpc) -> Result<Self> {
        Ok(Self {
            tip: rpc.tip_number()?,
            headers: rpc.headers().to_vec(),
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
        })
    }

    fn for_chain(chain: &[VerifiedBlock], proof: Value) -> Self {
        Self {
            tip: chain.last().map(|b| b.number).unwrap_or(0),
            headers: headers_from_chain(chain),
            proof,
            lie_state_root: false,
            balance: "0x0".into(),
            fail_balance: false,
            unverified: Value::Null,
            code: Vec::new(),
            lie_raw_hash: None,
        }
    }
}

impl RpcUpstream for MockUpstream {
    fn block_number(&self) -> Result<u64> {
        Ok(self.tip)
    }

    fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader> {
        self.headers
            .iter()
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
    assert!(v.get("result").is_some(), "{v}");
    assert_eq!(v["result"]["stateRoot"], json!(hdr.state_root));
    assert_eq!(
        v["result"]["hash"],
        json!(format!("0x{}", hex::encode(hash)))
    );
    assert_eq!(v["result"]["transactions"], json!([]));
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
        "eth_getLogs",
        "eth_getBlockTransactionCountByNumber",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_newPendingTransactionFilter",
        "eth_uninstallFilter",
        "eth_getFilterLogs",
        "eth_unsubscribe",
        "eth_getBlockTransactionCountByHash",
        "eth_getTransactionByBlockNumberAndIndex",
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
        attestation: None,
    };
    Snapshot::from_checkpoint(&cp).unwrap()
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
    assert_eq!(err_code(&v), ERR_METHOD);
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("unverified_passthrough"), "{msg}");
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

#[test]
fn receipt_header_bound_with_flag() {
    let chain = distinct_sealer_chain(15);
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
    hist_up.unverified = json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x1"]});
    let mut hist_node = Node::from_parts(Box::new(hist_up), 130, chain.clone());
    hist_node.set_allow_unverified_passthrough(true);
    let hist = hist_node.handle(&req("eth_feeHistory", json!(["0x4", "latest", []])));
    assert_eq!(hist["result"]["oldestBlock"], json!("0x1"), "{hist}");
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
