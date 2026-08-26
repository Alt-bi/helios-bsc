//! Logs and poll-based filters: eth_getLogs over a range, the filter store, and the receipts-to-logs path both share.
//!
//! Moved out of `rpc_server.rs`; see that file's header for why, and the commit
//! that created this file for the proof that nothing but the filing changed.

use super::*;

/// Blocks whose receipts are fetched concurrently when serving a log range.
///
/// A span is latency-bound: one upstream round trip per block, and nothing to compute in
/// between. Kept small so a single request cannot open a burst of connections against an
/// operator's provider.
const LOG_FETCH_PARALLEL: usize = 4;

const MAX_FILTERS: usize = 64;

/// Why a span of logs produced no list.
///
/// The cap is its own variant rather than a message, because two of the three callers
/// have to act on it and only one of them can act on it the same way. `eth_getLogs` and
/// `eth_getFilterLogs` are handed a span by their caller and can only refuse; a
/// `eth_getFilterChanges` poll chose the span itself, from a cursor, and refusing there
/// wedges the filter forever -- the cursor does not advance, so the next poll re-reads
/// the same span and fails identically until someone re-creates the filter.
///
/// Matching on the message text instead would make a control decision out of a string
/// nothing pins. `is_link_err` did exactly that and silently stopped detecting reorgs;
/// the compiler enforces this.
pub(super) enum LogsError {
    /// More than [`MAX_GET_LOGS`] matched. The count is deliberately not carried: the
    /// collection stops at the cap, so the only honest statement is "more than".
    Capped,
    /// Anything else, already shaped as a JSON-RPC `(code, message)`.
    Rpc(i64, String),
}

impl From<(i64, String)> for LogsError {
    fn from((code, msg): (i64, String)) -> Self {
        LogsError::Rpc(code, msg)
    }
}

/// Idle time after which a filter is forgotten, matching geth's default.
const FILTER_TTL: Duration = Duration::from_secs(300);

/// What a filter id refers to.
enum FilterKind {
    /// A log filter. The original filter object is kept verbatim so a poll re-runs the
    /// same validated path `eth_getLogs` takes, with only the block bounds replaced — the
    /// two cannot drift into disagreeing about what the filter matches.
    Logs {
        filter: serde_json::Map<String, Value>,
        /// Lower bound the caller asked for. Fixed: `eth_getFilterLogs` answers the whole
        /// range every time, so it cannot read the cursor, which has moved on.
        from_block: u64,
        /// Upper bound the caller asked for, or `None` for an open-ended filter that
        /// follows the head.
        to_block: Option<u64>,
        /// Next block `eth_getFilterChanges` reports from.
        cursor: u64,
    },
    /// A block filter: hashes of blocks verified since the last poll.
    Blocks { cursor: u64 },
}

struct StoredFilter {
    kind: FilterKind,
    touched: Instant,
}

/// Filter ids and their state.
///
/// Ids are sequential per process and never reused, so a poll against an id that has
/// expired is a clean "filter not found" rather than someone else's results.
#[derive(Default)]
pub(super) struct FilterStore {
    next_id: u64,
    map: std::collections::HashMap<u64, StoredFilter>,
}

impl FilterStore {
    fn sweep(&mut self) {
        self.map.retain(|_, f| f.touched.elapsed() < FILTER_TTL);
    }

    fn insert(&mut self, kind: FilterKind) -> Result<u64, String> {
        self.sweep();
        if self.map.len() >= MAX_FILTERS {
            // Drop the least recently polled rather than refuse: a caller that abandoned
            // a filter should not lock out the one that is still being used.
            if let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, f)| f.touched)
                .map(|(id, _)| *id)
            {
                self.map.remove(&oldest);
            }
        }
        if self.map.len() >= MAX_FILTERS {
            return Err("too many filters".into());
        }
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.map.insert(
            id,
            StoredFilter {
                kind,
                touched: Instant::now(),
            },
        );
        Ok(id)
    }
}

/// Parse a `0x`-prefixed filter id.
fn parse_filter_id(req: &Value) -> Option<u64> {
    let s = req
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.first())
        .and_then(Value::as_str)?;
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

impl Node {
    pub(super) fn get_logs(&self, id: Value, req: &Value) -> Value {
        let filter = match req.get("params").and_then(Value::as_array) {
            None => None,
            Some(p) if p.is_empty() => None,
            Some(p) => match p.first() {
                Some(Value::Object(m)) => Some(m),
                Some(Value::Null) => None,
                _ => return rpc_err(id, ERR_PARAMS, "eth_getLogs filter must be an object"),
            },
        };
        let blocks = match self.resolve_get_logs_blocks(id.clone(), filter) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let addresses = match parse_log_addresses(filter) {
            Ok(a) => a,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        let topics = match parse_log_topics(filter) {
            Ok(t) => t,
            Err(e) => return rpc_err(id, ERR_PARAMS, &e),
        };
        match self.collect_logs(&blocks, &addresses, &topics) {
            Ok(out) => rpc_ok(id, Value::Array(out)),
            Err(LogsError::Capped) => rpc_err(
                id,
                ERR_PARAMS,
                &format!(
                    "query matched more than {MAX_GET_LOGS} logs; narrow the block range or the address/topic filter"
                ),
            ),
            Err(LogsError::Rpc(code, msg)) => rpc_err(id, code, &msg),
        }
    }

    /// `eth_newFilter`: validate now, poll later.
    ///
    /// The filter object is validated at creation, so a malformed `address` or `topics`
    /// is an error the caller sees immediately rather than on a poll minutes later. It is
    /// then stored verbatim and replayed through the same path `eth_getLogs` uses, with
    /// only the block bounds substituted, so the two cannot drift apart.
    pub(super) fn new_filter(&self, id: Value, req: &Value) -> Value {
        let filter = match req
            .get("params")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
        {
            Some(Value::Object(m)) => m.clone(),
            None | Some(Value::Null) => serde_json::Map::new(),
            _ => return rpc_err(id, ERR_PARAMS, "eth_newFilter filter must be an object"),
        };
        if !is_nullish_json(filter.get("blockHash")) {
            return rpc_err(
                id,
                ERR_PARAMS,
                "eth_newFilter does not take blockHash: a filter follows a range, so use eth_getLogs for a single block",
            );
        }
        if let Err(e) = parse_log_addresses(Some(&filter)) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        if let Err(e) = parse_log_topics(Some(&filter)) {
            return rpc_err(id, ERR_PARAMS, &e);
        }
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let from_s = match wallet_block_tag_str(filter.get("fromBlock")) {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_PARAMS, e),
        };
        let to_s = match wallet_block_tag_str(filter.get("toBlock")) {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_PARAMS, e),
        };
        let Some(cursor) = log_filter_block_number(from_s, safe.number, &safe.hash) else {
            return rpc_err(id, ERR_NOT_SYNCED, WALLET_TAG_ONLY);
        };
        // An explicit height closes the filter there; a tag leaves it following the head,
        // which is what a wallet polling for new events wants.
        let to_block = match to_s {
            Some(t) if t.starts_with("0x") || t.starts_with("0X") => {
                match log_filter_block_number(to_s, safe.number, &safe.hash) {
                    Some(n) => Some(n),
                    None => return rpc_err(id, ERR_NOT_SYNCED, WALLET_TAG_ONLY),
                }
            }
            _ => None,
        };
        let mut store = self.filters.lock().expect("filter lock");
        match store.insert(FilterKind::Logs {
            filter,
            from_block: cursor,
            to_block,
            cursor,
        }) {
            Ok(n) => rpc_ok(id, json!(format!("0x{n:x}"))),
            Err(e) => rpc_err(id, ERR_PARAMS, &e),
        }
    }

    /// `eth_newBlockFilter`: hashes of blocks this client verifies from now on.
    pub(super) fn new_block_filter(&self, id: Value) -> Value {
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let mut store = self.filters.lock().expect("filter lock");
        // Start after the current head: a new filter reports what happens next, not a
        // backlog the caller never asked for.
        match store.insert(FilterKind::Blocks {
            cursor: safe.number.saturating_add(1),
        }) {
            Ok(n) => rpc_ok(id, json!(format!("0x{n:x}"))),
            Err(e) => rpc_err(id, ERR_PARAMS, &e),
        }
    }

    pub(super) fn uninstall_filter(&self, id: Value, req: &Value) -> Value {
        let Some(fid) = parse_filter_id(req) else {
            return rpc_err(id, ERR_PARAMS, FILTER_ID_HEX);
        };
        let mut store = self.filters.lock().expect("filter lock");
        store.sweep();
        rpc_ok(id, json!(store.map.remove(&fid).is_some()))
    }

    /// `eth_getFilterChanges`: what happened since the last poll, then advance.
    ///
    /// The cursor moves only over blocks this call actually read, so a poll that stops at
    /// the span cap resumes exactly where it left off: a caller behind a busy chain
    /// catches up over several calls instead of losing the gap.
    pub(super) fn get_filter_changes(&self, id: Value, req: &Value) -> Value {
        let Some(fid) = parse_filter_id(req) else {
            return rpc_err(id, ERR_PARAMS, FILTER_ID_HEX);
        };
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let head = safe.number;
        let snapshot = {
            let mut store = self.filters.lock().expect("filter lock");
            store.sweep();
            let Some(f) = store.map.get_mut(&fid) else {
                return rpc_err(id, ERR_PARAMS, FILTER_NOT_FOUND);
            };
            f.touched = Instant::now();
            match &f.kind {
                FilterKind::Blocks { cursor } => Err(*cursor),
                FilterKind::Logs {
                    filter,
                    to_block,
                    cursor,
                    ..
                } => Ok((filter.clone(), *to_block, *cursor)),
            }
        };

        let (filter, to_block, cursor) = match snapshot {
            Err(from) => {
                if from > head {
                    return rpc_ok(id, json!([]));
                }
                let to = head.min(from.saturating_add(MAX_GET_LOGS_RANGE - 1));
                let mut hashes: Vec<(u64, String)> = {
                    let chain = self.chain.lock().expect("chain lock");
                    chain
                        .iter()
                        .filter(|b| b.number >= from && b.number <= to)
                        .map(|b| (b.number, format!("0x{}", hex::encode(b.hash))))
                        .collect()
                };
                hashes.sort_by_key(|(n, _)| *n);
                let mut store = self.filters.lock().expect("filter lock");
                if let Some(f) = store.map.get_mut(&fid) {
                    if let FilterKind::Blocks { cursor } = &mut f.kind {
                        *cursor = to.saturating_add(1);
                    }
                }
                return rpc_ok(
                    id,
                    Value::Array(hashes.into_iter().map(|(_, h)| json!(h)).collect()),
                );
            }
            Ok(v) => v,
        };

        let end = to_block.unwrap_or(head).min(head);
        if cursor > end {
            return rpc_ok(id, json!([]));
        }
        let mut end = end.min(cursor.saturating_add(MAX_GET_LOGS_RANGE - 1));
        // A poll does not choose its span -- the cursor does -- so refusing it here told
        // the caller to do something they had no way to do, and left the cursor where it
        // was: every later poll re-read the same span and failed identically, and the
        // filter stayed wedged until someone re-installed it.
        //
        // Halving is the answer the cursor was built for. The doc on this method already
        // promises that a poll stopping short resumes where it left off, so reading fewer
        // blocks is a supported outcome and not a partial one: the caller catches up over
        // the next polls. Bounded at seven attempts, since the span starts at most
        // `MAX_GET_LOGS_RANGE` (128) wide and each try halves it.
        let logs = loop {
            match self.logs_for_span(&filter, cursor, end) {
                Ok(v) => break v,
                Err(LogsError::Rpc(code, msg)) => return rpc_err(id, code, &msg),
                Err(LogsError::Capped) if end > cursor => {
                    end = cursor.saturating_add((end - cursor) / 2);
                }
                // One block on its own is over the cap. Nothing is left to narrow, and
                // this is the only case where the caller really does have to change the
                // filter -- so it is the only case that says so. Skipping the block
                // instead would drop logs a caller has no way to learn they missed.
                Err(LogsError::Capped) => {
                    return rpc_err(
                        id,
                        ERR_PARAMS,
                        &format!(
                            "block {cursor} alone matches more than {MAX_GET_LOGS} logs; a poll cannot narrow past a single block, so install a filter with a tighter address/topic filter"
                        ),
                    )
                }
            }
        };
        let mut store = self.filters.lock().expect("filter lock");
        if let Some(f) = store.map.get_mut(&fid) {
            if let FilterKind::Logs { cursor: c, .. } = &mut f.kind {
                *c = end.saturating_add(1);
            }
        }
        rpc_ok(id, Value::Array(logs))
    }

    /// `eth_getFilterLogs`: everything the filter matches, cursor untouched.
    pub(super) fn get_filter_logs(&self, id: Value, req: &Value) -> Value {
        let Some(fid) = parse_filter_id(req) else {
            return rpc_err(id, ERR_PARAMS, FILTER_ID_HEX);
        };
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        };
        let (filter, to_block, from) = {
            let mut store = self.filters.lock().expect("filter lock");
            store.sweep();
            let Some(f) = store.map.get_mut(&fid) else {
                return rpc_err(id, ERR_PARAMS, FILTER_NOT_FOUND);
            };
            f.touched = Instant::now();
            match &f.kind {
                FilterKind::Logs {
                    filter,
                    from_block,
                    to_block,
                    ..
                } => (filter.clone(), *to_block, *from_block),
                FilterKind::Blocks { .. } => {
                    return rpc_err(id, ERR_PARAMS, "eth_getFilterLogs needs a log filter")
                }
            }
        };
        let end = to_block.unwrap_or(safe.number).min(safe.number);
        if from > end {
            return rpc_ok(id, json!([]));
        }
        match self.logs_for_span(&filter, from, end) {
            Ok(v) => rpc_ok(id, Value::Array(v)),
            // This method answers the filter's whole range every time and never moves a
            // cursor, so there is no smaller span to fall back to. Naming the two things
            // that would actually change the outcome beats "narrow the block range",
            // which the caller cannot do to a filter that already exists.
            Err(LogsError::Capped) => rpc_err(
                id,
                ERR_PARAMS,
                &format!(
                    "filter matched more than {MAX_GET_LOGS} logs over its own range; eth_getFilterLogs always answers the whole range, so install a new filter with a narrower fromBlock/toBlock or a tighter address/topic filter"
                ),
            ),
            Err(LogsError::Rpc(code, msg)) => rpc_err(id, code, &msg),
        }
    }

    /// Run a stored filter over an explicit block span, through the `eth_getLogs` path.
    pub(super) fn logs_for_span(
        &self,
        filter: &serde_json::Map<String, Value>,
        from: u64,
        to: u64,
    ) -> Result<Vec<Value>, LogsError> {
        let span = to.saturating_sub(from).saturating_add(1);
        if span > MAX_GET_LOGS_RANGE {
            return Err(LogsError::Rpc(
                ERR_PARAMS,
                format!(
                    "filter span is {span} blocks; this client keeps no log index and serves at most {MAX_GET_LOGS_RANGE}"
                ),
            ));
        }
        let mut f = filter.clone();
        f.insert("fromBlock".into(), json!(format!("0x{from:x}")));
        f.insert("toBlock".into(), json!(format!("0x{to:x}")));
        let addresses = parse_log_addresses(Some(&f)).map_err(|e| LogsError::Rpc(ERR_PARAMS, e))?;
        let topics = parse_log_topics(Some(&f)).map_err(|e| LogsError::Rpc(ERR_PARAMS, e))?;
        let blocks = self
            .resolve_get_logs_blocks(Value::Null, Some(&f))
            .map_err(|v| {
                let code = v["error"]["code"].as_i64().unwrap_or(ERR_PARAMS);
                let msg = v["error"]["message"]
                    .as_str()
                    .unwrap_or("filter span unavailable")
                    .to_string();
                LogsError::Rpc(code, msg)
            })?;
        self.collect_logs(&blocks, &addresses, &topics)
    }

    /// Matching logs over an ascending run of locally verified blocks.
    ///
    /// Shared by `eth_getLogs` and the filter methods so the two can never disagree about
    /// what a filter matches, how `logIndex` is numbered, or when a block is refusable.
    pub(super) fn collect_logs(
        &self,
        blocks: &[VerifiedBlock],
        addresses: &[[u8; 20]],
        topics: &[Option<Vec<[u8; 32]>>],
    ) -> Result<Vec<Value>, LogsError> {
        let mut out = Vec::new();
        for group in blocks.chunks(LOG_FETCH_PARALLEL) {
            // Each block is an independent upstream round trip, so a span is latency-bound
            // rather than CPU-bound: 128 blocks served one at a time is over two minutes.
            // Fetching a few at once is the difference between a usable range query and a
            // timeout. Results are consumed in block order regardless of completion order.
            let fetched: Vec<Result<(RpcBlockHeader, ReceiptBind), (i64, String)>> =
                std::thread::scope(|scope| {
                    let handles: Vec<_> = group
                        .iter()
                        .map(|b| scope.spawn(move || self.bound_block_receipts(b)))
                        .collect();
                    handles
                        .into_iter()
                        .map(|h| {
                            h.join().unwrap_or_else(|_| {
                                Err((
                                    ERR_INTERNAL,
                                    "internal_error: receipt fetch thread panicked".to_string(),
                                ))
                            })
                        })
                        .collect()
                });
            for (local, res) in group.iter().zip(fetched) {
                let (header, bind) = res?;
                let receipts = match bind {
                ReceiptBind::List(list) => list,
                // Proven to have no transactions: it contributes no logs.
                ReceiptBind::Empty => continue,
                // The upstream declined the receipts, so this block's logs are unknown.
                // Answering without them would report "no matching logs here" for a block
                // nobody checked — a wrong answer rather than a partial one.
                ReceiptBind::Omitted => {
                    return Err(LogsError::Rpc(
                        ERR_PROOF_FAILED,
                        format!(
                            "proof_verification_failed: upstream served no receipts for block {}, so its logs cannot be proven absent",
                            local.number
                        ),
                    ))
                }
            };
                // Block-wide index, restarting per block exactly as geth reports it.
                let mut log_index: u64 = 0;
                for (tx_i, rec) in receipts.iter().enumerate() {
                    for log in &rec.logs {
                        if log_matches(log, addresses, topics) {
                            // Truncating here would hand back a list that looks complete
                            // and is not: a caller reading 1024 transfers has no way to
                            // learn a 1025th matched. Everywhere else this client answers
                            // "I cannot prove that" rather than a plausible number, and a
                            // silently short log list is the same defect wearing a
                            // result's clothes. geth refuses the same way.
                            if out.len() >= MAX_GET_LOGS {
                                return Err(LogsError::Capped);
                            }
                            out.push(rpc_log_json(
                                log,
                                &header,
                                rec.tx_hash,
                                tx_i as u64,
                                log_index,
                            ));
                        }
                        log_index = log_index.saturating_add(1);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Blocks an `eth_getLogs` filter selects, ascending, all locally verified.
    pub(super) fn resolve_get_logs_blocks(
        &self,
        id: Value,
        filter: Option<&serde_json::Map<String, Value>>,
    ) -> Result<Vec<VerifiedBlock>, Value> {
        let block_hash = filter.and_then(|m| m.get("blockHash"));
        let from_v = filter.and_then(|m| m.get("fromBlock"));
        let to_v = filter.and_then(|m| m.get("toBlock"));
        let has_range = !is_nullish_json(from_v) || !is_nullish_json(to_v);
        if !is_nullish_json(block_hash) {
            if has_range {
                return Err(rpc_err(
                    id,
                    ERR_PARAMS,
                    "cannot specify both blockHash and fromBlock/toBlock",
                ));
            }
            let hash = block_hash
                .and_then(Value::as_str)
                .ok_or_else(|| rpc_err(id.clone(), ERR_PARAMS, "blockHash must be a string"))?;
            if decode_hex_fixed::<32>(hash).is_err() {
                return Err(rpc_err(id, ERR_PARAMS, "blockHash is not 32 bytes"));
            }
            let (_, safe) = match self.refresh() {
                Ok(v) => v,
                Err(e) => return Err(rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}"))),
            };
            let chain = self.chain.lock().expect("chain lock");
            return wallet_get_block_by_hash(hash, safe.number, &chain)
                .cloned()
                .map(|b| vec![b])
                .ok_or_else(|| {
                    rpc_err(
                        id,
                        ERR_NOT_SYNCED,
                        "wallet mode only serves verified hashes at or below Safe",
                    )
                });
        }
        let from_s =
            wallet_block_tag_str(from_v).map_err(|e| rpc_err(id.clone(), ERR_PARAMS, e))?;
        let to_s = wallet_block_tag_str(to_v).map_err(|e| rpc_err(id.clone(), ERR_PARAMS, e))?;
        let (_, safe) = match self.refresh() {
            Ok(v) => v,
            Err(e) => return Err(rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}"))),
        };
        let from_n = log_filter_block_number(from_s, safe.number, &safe.hash).ok_or_else(|| {
            rpc_err(
                id.clone(),
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            )
        })?;
        let to_n = log_filter_block_number(to_s, safe.number, &safe.hash).ok_or_else(|| {
            rpc_err(
                id.clone(),
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            )
        })?;
        if to_n < from_n {
            return Err(rpc_err(
                id,
                ERR_PARAMS,
                "eth_getLogs fromBlock is above toBlock",
            ));
        }
        let span = to_n - from_n + 1;
        if span > MAX_GET_LOGS_RANGE {
            return Err(rpc_err(
                id,
                ERR_PARAMS,
                &format!(
                    "eth_getLogs range is {span} blocks; this client keeps no log index and serves at most {MAX_GET_LOGS_RANGE}"
                ),
            ));
        }
        if to_n > safe.number {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                "wallet mode only serves Safe or below (latest→Safe)",
            ));
        }
        let chain = self.chain.lock().expect("chain lock");
        let mut blocks: Vec<VerifiedBlock> = chain
            .iter()
            .filter(|b| b.number >= from_n && b.number <= to_n)
            .cloned()
            .collect();
        blocks.sort_by_key(|b| b.number);
        // Every block in the span must be one this client walked and verified. A gap is
        // a range this client cannot answer, not a range with fewer logs in it.
        if blocks.len() as u64 != span {
            return Err(rpc_err(
                id,
                ERR_NOT_SYNCED,
                "eth_getLogs range reaches outside the locally verified chain",
            ));
        }
        Ok(blocks)
    }
}
