//! Untrusted JSON-RPC data plane (headers + eth_getProof).

use anyhow::{anyhow, Context, Result};
use helios_bsc_execution::{MAX_ORDERED_TRIE_ITEMS, MAX_RAW_TX};
use helios_bsc_types::{decode_hex, decode_hex_fixed, keccak256, RpcBlockHeader};
use serde_json::{json, Value};

/// Untrusted header / proof / broadcast source.
pub trait RpcUpstream: Send + Sync {
    fn block_number(&self) -> Result<u64>;
    fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader>;
    fn header_by_hash(&self, hash: &str) -> Result<RpcBlockHeader>;
    fn headers_range(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>>;
    fn get_proof_keys(&self, address: &str, keys: &[String], block: &str) -> Result<Value>;
    fn get_balance(&self, address: &str, block: &str) -> Result<String>;
    fn get_transaction_count(&self, address: &str, block: &str) -> Result<String> {
        let _ = (address, block);
        Err(anyhow!("eth_getTransactionCount not available"))
    }
    fn get_code(&self, address: &str, block: &str) -> Result<Vec<u8>>;
    fn send_raw_transaction(&self, raw: &str) -> Result<String>;
    /// Untrusted JSON-RPC call for the opt-in passthrough allow-list.
    fn unverified_call(&self, method: &str, params: &Value) -> Result<Value>;

    /// Raw txs for `eth_getBlockByHash(hash, false)` + `eth_getRawTransactionByHash`.
    /// Default is empty (mocks / stubs). HTTP implementations must fetch and keccak-bind.
    fn block_raw_transactions(&self, block_hash: &str) -> Result<Vec<Vec<u8>>> {
        let _ = block_hash;
        Ok(vec![])
    }

    /// Untrusted `eth_getBlockReceipts(blockHash)` JSON objects.
    /// Default is empty (mocks / stubs). HTTP implementations must fetch.
    fn block_receipts_json(&self, block_hash: &str) -> Result<Vec<Value>> {
        let _ = block_hash;
        Ok(vec![])
    }

    fn get_proof(&self, address: &str, block: &str) -> Result<Value> {
        self.get_proof_keys(address, &[], block)
    }

    /// Safe proofs: **number first** (Ankr hash is often `not supported`), then hash.
    /// Retries a few times — provider windows jitter around newest-Safe.
    fn get_proof_at_safe(
        &self,
        address: &str,
        keys: &[String],
        safe_hash: &str,
        safe_number: u64,
    ) -> Result<Value> {
        let number = format!("0x{safe_number:x}");
        match self.get_proof_keys(address, keys, &number) {
            Ok(v) => Ok(v),
            Err(e_num) => {
                let msg = e_num.to_string().to_ascii_lowercase();
                // Ankr hash is often "not supported"; don't burn the proof window on it.
                if !msg.contains("not supported") {
                    if let Ok(v) = self.get_proof_keys(address, keys, safe_hash) {
                        return Ok(v);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(800));
                self.get_proof_keys(address, keys, &number)
                    .map_err(|e_retry| anyhow!("by-number: {e_num}; retry: {e_retry}"))
            }
        }
    }
}

/// Primary then backup. Both untrusted; Node still verifies seals / MPT.
/// Failover is transport-only (HTTP/RPC errors), not a second trust oracle.
pub struct Failover {
    primary: Box<dyn RpcUpstream>,
    backup: Box<dyn RpcUpstream>,
}

impl Failover {
    pub fn new(primary: Box<dyn RpcUpstream>, backup: Box<dyn RpcUpstream>) -> Self {
        Self { primary, backup }
    }

    fn fallback<T>(&self, op: impl Fn(&dyn RpcUpstream) -> Result<T>) -> Result<T> {
        match op(self.primary.as_ref()) {
            Ok(v) => Ok(v),
            Err(e1) => {
                op(self.backup.as_ref()).map_err(|e2| anyhow!("primary: {e1}; backup: {e2}"))
            }
        }
    }
}

impl RpcUpstream for Failover {
    fn block_number(&self) -> Result<u64> {
        self.fallback(|u| u.block_number())
    }
    fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader> {
        self.fallback(|u| u.header_by_number(n))
    }
    fn header_by_hash(&self, hash: &str) -> Result<RpcBlockHeader> {
        self.fallback(|u| u.header_by_hash(hash))
    }
    fn headers_range(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        self.fallback(|u| u.headers_range(from, to))
    }
    fn get_proof_keys(&self, address: &str, keys: &[String], block: &str) -> Result<Value> {
        self.fallback(|u| u.get_proof_keys(address, keys, block))
    }
    fn get_balance(&self, address: &str, block: &str) -> Result<String> {
        self.fallback(|u| u.get_balance(address, block))
    }
    fn get_transaction_count(&self, address: &str, block: &str) -> Result<String> {
        self.fallback(|u| u.get_transaction_count(address, block))
    }
    fn get_code(&self, address: &str, block: &str) -> Result<Vec<u8>> {
        self.fallback(|u| u.get_code(address, block))
    }
    fn send_raw_transaction(&self, raw: &str) -> Result<String> {
        self.fallback(|u| u.send_raw_transaction(raw))
    }
    fn unverified_call(&self, method: &str, params: &Value) -> Result<Value> {
        self.fallback(|u| u.unverified_call(method, params))
    }
    fn block_raw_transactions(&self, block_hash: &str) -> Result<Vec<Vec<u8>>> {
        self.fallback(|u| u.block_raw_transactions(block_hash))
    }
    fn block_receipts_json(&self, block_hash: &str) -> Result<Vec<Value>> {
        self.fallback(|u| u.block_receipts_json(block_hash))
    }
}

/// Data-plane client. `backup` is optional transport failover (not an oracle).
pub fn open_data_plane(primary: impl Into<String>, backup: Option<String>) -> Box<dyn RpcUpstream> {
    let primary = Upstream::new(primary);
    match backup.filter(|s| !s.trim().is_empty()) {
        None => Box::new(primary),
        Some(b) => Box::new(Failover::new(Box::new(primary), Box::new(Upstream::new(b)))),
    }
}

/// Hard ceiling on one upstream JSON-RPC response body.
///
/// `Response::into_json` reads through `into_reader()`, which ureq does **not** bound
/// (only `into_string()` carries a limit). The data plane is untrusted by definition, so
/// without this a hostile or merely broken upstream could stream until the process is
/// killed — and every per-item cap in this tree (`MAX_RAW_TX`, `MAX_ORDERED_TRIE_ITEMS`,
/// `MAX_PROOF_NODES`) applies only *after* the body is already in memory.
///
/// 64 MiB is a DoS ceiling, not a protocol constant: the largest legitimate response is a
/// full block's `eth_getBlockReceipts`, a couple of MiB at BSC's gas limit.
pub const MAX_UPSTREAM_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

fn read_capped_json(resp: ureq::Response) -> Result<Value> {
    read_capped(resp.into_reader())
}

fn read_capped(r: impl std::io::Read) -> Result<Value> {
    use std::io::Read;
    let mut buf = Vec::new();
    r.take(MAX_UPSTREAM_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .context("read response body")?;
    if buf.len() as u64 > MAX_UPSTREAM_RESPONSE_BYTES {
        return Err(anyhow!(
            "upstream response exceeds {MAX_UPSTREAM_RESPONSE_BYTES} bytes"
        ));
    }
    serde_json::from_slice(&buf).with_context(|| {
        // A free endpoint under load answers with an HTML error page or a plain-text
        // rate-limit notice, and "expected value at line 1 column 1" sends the operator
        // looking for a bug in the client. Show what actually came back.
        let head: String = String::from_utf8_lossy(&buf[..buf.len().min(200)])
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        format!(
            "parse response body ({} bytes, starts: {:?})",
            buf.len(),
            head.trim()
        )
    })
}

/// Re-associate one JSON-RPC batch's responses with the numbers that were requested.
///
/// Split out from the HTTP call so the adversarial shapes are unit-testable.
fn headers_from_batch(arr: &[Value], from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
    // JSON-RPC batch responses may arrive in any order, so `id` is what re-associates
    // a result with its request. An upstream that repeats or invents ids would make
    // this list silently short or misordered; `verify_header_chain` would then reject
    // it as a parent-link break, which reads like a reorg. Insist on exactly the
    // requested set instead, so the real cause is the reported one.
    let want = (to - from + 1) as usize;
    if arr.len() != want {
        return Err(anyhow!(
            "batch returned {} responses for {want} requests",
            arr.len()
        ));
    }
    let mut rows: Vec<(u64, RpcBlockHeader)> = Vec::new();
    for item in arr {
        if let Some(err) = item.get("error") {
            return Err(anyhow!("batch rpc error: {err}"));
        }
        let id = item
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| (from..=to).contains(id))
            .ok_or_else(|| anyhow!("batch response id outside {from}..={to}"))?;
        if rows.iter().any(|(seen, _)| *seen == id) {
            return Err(anyhow!("batch response repeats id {id}"));
        }
        let hdr: RpcBlockHeader =
            serde_json::from_value(item.get("result").cloned().unwrap_or(Value::Null))
                .with_context(|| format!("header {id}"))?;
        rows.push((id, hdr));
    }
    rows.sort_by_key(|(id, _)| *id);
    Ok(rows.into_iter().map(|(_, h)| h).collect())
}

/// HTTP JSON-RPC client (ureq).
pub struct Upstream {
    url: String,
}

impl Upstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    fn post_json(&self, body: &Value) -> Result<Value> {
        const ATTEMPTS: u64 = 4;
        let mut last = anyhow!("no attempt");
        for attempt in 0..ATTEMPTS {
            match ureq::post(&self.url)
                .set("Content-Type", "application/json")
                .set("User-Agent", "helios-bsc")
                .timeout(std::time::Duration::from_secs(30))
                .send_json(body)
            {
                Ok(resp) => {
                    return read_capped_json(resp).context("upstream JSON");
                }
                Err(e) => {
                    last = anyhow!("upstream HTTP: {e}");
                    // No backoff after the last attempt — the caller is about to see the
                    // error either way, and 1.6 s of it was pure added latency on failure.
                    if attempt + 1 < ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(400 * (attempt + 1)));
                    }
                }
            }
        }
        Err(last)
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp = self.post_json(&body)?;
        if let Some(err) = resp.get("error") {
            return Err(anyhow!("rpc error: {err}"));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// One JSON-RPC batch of at most 8 headers (Ankr free times out on larger batches).
    fn headers_one_batch(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        let batch: Vec<Value> = (from..=to)
            .map(|i| {
                json!({
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "eth_getBlockByNumber",
                    "params": [format!("0x{i:x}"), false]
                })
            })
            .collect();
        let resp = self.post_json(&Value::Array(batch))?;
        let arr = resp
            .as_array()
            .ok_or_else(|| anyhow!("batch response not array: {resp}"))?;
        headers_from_batch(arr, from, to)
    }

    fn header_chunks(from: u64, to: u64) -> Vec<(u64, u64)> {
        let mut chunks = Vec::new();
        let mut n = from;
        while n <= to {
            let end = n.saturating_add(7).min(to);
            chunks.push((n, end));
            n = end + 1;
        }
        chunks
    }

    fn headers_range_batch(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        let mut out = Vec::new();
        for (a, b) in Self::header_chunks(from, to) {
            out.extend(self.headers_one_batch(a, b)?);
        }
        Ok(out)
    }

    /// Three concurrent 8-header batches. Falls back to serial batches on any error.
    fn headers_range_parallel(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        const PARALLEL: usize = 3;
        let chunks = Self::header_chunks(from, to);
        let mut out = Vec::with_capacity(to.saturating_sub(from).saturating_add(1) as usize);
        for group in chunks.chunks(PARALLEL) {
            let collected = std::thread::scope(|scope| {
                let handles: Vec<_> = group
                    .iter()
                    .map(|&(a, b)| scope.spawn(move || self.headers_one_batch(a, b)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| match h.join() {
                        Ok(r) => r,
                        Err(_) => Err(anyhow!("header batch thread panicked")),
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            for batch in collected {
                out.extend(batch);
            }
        }
        Ok(out)
    }
}

impl RpcUpstream for Upstream {
    fn block_number(&self) -> Result<u64> {
        let v = self.call("eth_blockNumber", json!([]))?;
        let s = v.as_str().ok_or_else(|| anyhow!("blockNumber not hex"))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16).context("parse blockNumber")
    }

    fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader> {
        let v = self.call("eth_getBlockByNumber", json!([format!("0x{n:x}"), false]))?;
        serde_json::from_value(v).context("decode header")
    }

    fn header_by_hash(&self, hash: &str) -> Result<RpcBlockHeader> {
        let v = self.call("eth_getBlockByHash", json!([hash, false]))?;
        if v.is_null() {
            return Err(anyhow!("eth_getBlockByHash: header not found"));
        }
        serde_json::from_value(v).context("decode header")
    }

    fn headers_range(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
        if from > to {
            return Ok(Vec::new());
        }
        match self.headers_range_parallel(from, to) {
            Ok(v) => Ok(v),
            Err(e) => {
                eprintln!("parallel header fetch failed ({e:#}); serial batches");
                match self.headers_range_batch(from, to) {
                    Ok(v) => Ok(v),
                    Err(e2) => {
                        eprintln!(
                            "batch fetch failed ({e2:#}); falling back to single-header calls"
                        );
                        let mut out = Vec::new();
                        for n in from..=to {
                            out.push(self.header_by_number(n)?);
                        }
                        Ok(out)
                    }
                }
            }
        }
    }

    fn get_proof_keys(&self, address: &str, keys: &[String], block: &str) -> Result<Value> {
        self.call("eth_getProof", json!([address, keys, block]))
    }

    fn get_balance(&self, address: &str, block: &str) -> Result<String> {
        let v = self.call("eth_getBalance", json!([address, block]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("eth_getBalance: expected hex qty"))
    }

    fn get_transaction_count(&self, address: &str, block: &str) -> Result<String> {
        let v = self.call("eth_getTransactionCount", json!([address, block]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("eth_getTransactionCount: expected hex qty"))
    }

    fn get_code(&self, address: &str, block: &str) -> Result<Vec<u8>> {
        let v = self.call("eth_getCode", json!([address, block]))?;
        let s = v.as_str().unwrap_or("0x");
        helios_bsc_types::decode_hex(s).map_err(|e| anyhow!("eth_getCode hex: {e}"))
    }

    fn send_raw_transaction(&self, raw: &str) -> Result<String> {
        let v = self.call("eth_sendRawTransaction", json!([raw]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("sendRawTransaction: expected hash"))
    }

    fn unverified_call(&self, method: &str, params: &Value) -> Result<Value> {
        self.call(method, params.clone())
    }

    fn block_raw_transactions(&self, block_hash: &str) -> Result<Vec<Vec<u8>>> {
        let v = self.call("eth_getBlockByHash", json!([block_hash, false]))?;
        if v.is_null() {
            return Err(anyhow!("eth_getBlockByHash: header not found"));
        }
        let txs = v
            .get("transactions")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("eth_getBlockByHash: transactions missing"))?;
        if txs.len() > MAX_ORDERED_TRIE_ITEMS {
            return Err(anyhow!("too many transactions"));
        }
        let mut hashes = Vec::with_capacity(txs.len());
        for t in txs {
            let s = t
                .as_str()
                .ok_or_else(|| anyhow!("eth_getBlockByHash: tx hash not a string"))?;
            let h = decode_hex_fixed::<32>(s).map_err(|e| anyhow!("tx hash: {e}"))?;
            hashes.push(h);
        }
        let mut raws = Vec::with_capacity(hashes.len());
        for h in &hashes {
            let hx = format!("0x{}", hex::encode(h));
            let raw_v = self.call("eth_getRawTransactionByHash", json!([hx]))?;
            if raw_v.is_null() {
                return Err(anyhow!("eth_getRawTransactionByHash: missing {hx}"));
            }
            let s = raw_v
                .as_str()
                .ok_or_else(|| anyhow!("eth_getRawTransactionByHash: expected hex"))?;
            let raw = decode_hex(s).map_err(|e| anyhow!("raw tx hex: {e}"))?;
            if raw.len() > MAX_RAW_TX {
                return Err(anyhow!("raw tx too large"));
            }
            if keccak256(&raw) != *h {
                return Err(anyhow!("raw tx keccak mismatch"));
            }
            raws.push(raw);
        }
        Ok(raws)
    }

    fn block_receipts_json(&self, block_hash: &str) -> Result<Vec<Value>> {
        let v = self.call("eth_getBlockReceipts", json!([block_hash]))?;
        if v.is_null() {
            return Ok(Vec::new());
        }
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("eth_getBlockReceipts: expected array"))?;
        if arr.len() > MAX_ORDERED_TRIE_ITEMS {
            return Err(anyhow!("too many receipts"));
        }
        Ok(arr.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_header(n: u64) -> Value {
        let path = format!(
            "{}/../../fixtures/mainnet/header_{n}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn batch_item(id: u64, n: u64) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": fixture_header(n)})
    }

    #[test]
    fn batch_ids_reassociate_out_of_order_results() {
        let arr = vec![
            batch_item(116_664_001, 116_664_001),
            batch_item(116_663_999, 116_663_999),
            batch_item(116_664_000, 116_664_000),
        ];
        let got = headers_from_batch(&arr, 116_663_999, 116_664_001).unwrap();
        let numbers: Vec<u64> = got
            .iter()
            .map(|h| u64::from_str_radix(h.number.trim_start_matches("0x"), 16).unwrap())
            .collect();
        assert_eq!(numbers, vec![116_663_999, 116_664_000, 116_664_001]);
        // And the parent links line up, i.e. the reassociation was by id, not by position.
        assert_eq!(got[1].parent_hash, got[0].hash);
        assert_eq!(got[2].parent_hash, got[1].hash);
    }

    /// Each of these used to surface downstream as a parent-link break, i.e. as a reorg.
    #[test]
    fn malformed_batch_shapes_rejected() {
        let ok = batch_item(116_663_999, 116_663_999);
        let short = vec![ok.clone()];
        assert!(headers_from_batch(&short, 116_663_999, 116_664_000)
            .unwrap_err()
            .to_string()
            .contains("1 responses for 2 requests"));

        // Two answers for the same block, none for the other.
        let dup = vec![ok.clone(), ok.clone()];
        assert!(headers_from_batch(&dup, 116_663_999, 116_664_000)
            .unwrap_err()
            .to_string()
            .contains("repeats id"));

        // An id nobody asked for.
        let stray = vec![ok.clone(), batch_item(1, 116_664_000)];
        assert!(headers_from_batch(&stray, 116_663_999, 116_664_000)
            .unwrap_err()
            .to_string()
            .contains("outside"));

        // A missing id is not silently treated as request 0.
        let no_id = vec![ok, json!({"result": fixture_header(116_664_000)})];
        assert!(headers_from_batch(&no_id, 116_663_999, 116_664_000).is_err());
    }

    /// `ureq`'s `into_reader()` is unbounded; only `into_string()` carries a limit.
    #[test]
    fn oversized_response_body_is_refused_not_buffered() {
        use std::io::Read as _;
        let flood = std::io::repeat(b'a').take(MAX_UPSTREAM_RESPONSE_BYTES * 4);
        let err = read_capped(flood).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");

        // A body right at the cap is still parsed (padded whitespace around a real value).
        let mut body = vec![b' '; MAX_UPSTREAM_RESPONSE_BYTES as usize - 2];
        body.extend_from_slice(b"{}");
        assert_eq!(read_capped(&body[..]).unwrap(), json!({}));
    }

    #[test]
    fn header_chunks_cover_inclusive_range() {
        assert_eq!(
            Upstream::header_chunks(1, 20),
            vec![(1, 8), (9, 16), (17, 20)]
        );
        assert!(Upstream::header_chunks(5, 4).is_empty());
        assert_eq!(Upstream::header_chunks(10, 10), vec![(10, 10)]);
    }

    struct Stub {
        n: Option<u64>,
    }

    impl Stub {
        fn ok(n: u64) -> Self {
            Self { n: Some(n) }
        }
        fn down() -> Self {
            Self { n: None }
        }
    }

    impl RpcUpstream for Stub {
        fn block_number(&self) -> Result<u64> {
            self.n.ok_or_else(|| anyhow!("down"))
        }
        fn header_by_number(&self, _: u64) -> Result<RpcBlockHeader> {
            Err(anyhow!("unused"))
        }
        fn header_by_hash(&self, _: &str) -> Result<RpcBlockHeader> {
            Err(anyhow!("unused"))
        }
        fn headers_range(&self, _: u64, _: u64) -> Result<Vec<RpcBlockHeader>> {
            Err(anyhow!("unused"))
        }
        fn get_proof_keys(&self, _: &str, _: &[String], _: &str) -> Result<Value> {
            Err(anyhow!("unused"))
        }
        fn get_balance(&self, _: &str, _: &str) -> Result<String> {
            Err(anyhow!("unused"))
        }
        fn get_code(&self, _: &str, _: &str) -> Result<Vec<u8>> {
            Err(anyhow!("unused"))
        }
        fn send_raw_transaction(&self, _: &str) -> Result<String> {
            Err(anyhow!("unused"))
        }
        fn unverified_call(&self, _: &str, _: &Value) -> Result<Value> {
            Err(anyhow!("unused"))
        }
    }

    #[test]
    fn failover_uses_backup_when_primary_errors() {
        let backup = Stub::ok(99);
        let f = Failover::new(Box::new(Stub::down()), Box::new(backup));
        assert_eq!(f.block_number().unwrap(), 99);
    }

    #[test]
    fn failover_prefers_primary() {
        let primary = Stub::ok(1);
        let backup = Stub::ok(2);
        let f = Failover::new(Box::new(primary), Box::new(backup));
        assert_eq!(f.block_number().unwrap(), 1);
    }

    #[test]
    fn failover_both_down() {
        let f = Failover::new(Box::new(Stub::down()), Box::new(Stub::down()));
        let err = f.block_number().unwrap_err().to_string();
        assert!(err.contains("primary"), "{err}");
        assert!(err.contains("backup"), "{err}");
    }
}
