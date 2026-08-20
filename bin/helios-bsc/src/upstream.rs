//! Untrusted JSON-RPC data plane (headers + eth_getProof).

use anyhow::{anyhow, Context, Result};
use helios_bsc_types::RpcBlockHeader;
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
}

/// Data-plane client. `backup` is optional transport failover (not an oracle).
pub fn open_data_plane(primary: impl Into<String>, backup: Option<String>) -> Box<dyn RpcUpstream> {
    let primary = Upstream::new(primary);
    match backup.filter(|s| !s.trim().is_empty()) {
        None => Box::new(primary),
        Some(b) => Box::new(Failover::new(Box::new(primary), Box::new(Upstream::new(b)))),
    }
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
        let mut last = anyhow!("no attempt");
        for attempt in 0..4 {
            match ureq::post(&self.url)
                .set("Content-Type", "application/json")
                .set("User-Agent", "helios-bsc")
                .timeout(std::time::Duration::from_secs(30))
                .send_json(body)
            {
                Ok(resp) => {
                    return resp.into_json().context("upstream JSON");
                }
                Err(e) => {
                    last = anyhow!("upstream HTTP: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(400 * (attempt + 1)));
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
        let mut rows: Vec<(u64, RpcBlockHeader)> = Vec::new();
        for item in arr {
            if let Some(err) = item.get("error") {
                return Err(anyhow!("batch rpc error: {err}"));
            }
            let id = item.get("id").and_then(Value::as_u64).unwrap_or(0);
            let hdr: RpcBlockHeader =
                serde_json::from_value(item.get("result").cloned().unwrap_or(Value::Null))
                    .with_context(|| format!("header {id}"))?;
            rows.push((id, hdr));
        }
        rows.sort_by_key(|(id, _)| *id);
        Ok(rows.into_iter().map(|(_, h)| h).collect())
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
                eprintln!("parallel header fetch failed ({e}); serial batches");
                match self.headers_range_batch(from, to) {
                    Ok(v) => Ok(v),
                    Err(e2) => {
                        eprintln!("batch fetch failed ({e2}); falling back to single-header calls");
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
