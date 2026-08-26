//! Fail-closed local JSON-RPC (wallet mode: latest → Safe).
//!
//! This file was 4,773 lines, with a single 2,594-line `impl Node` in the middle of it.
//! It is the largest thing an auditor has to read here and the place a reviewer is least
//! able to say what changed, which is a poor combination for the file that decides what
//! this client will and will not answer.
//!
//! It now keeps the parts that are genuinely about the whole server — the `Node` and its
//! state, sync and refresh, metrics, and the dispatch table that names every method — and
//! hands each surface to its own module:
//!
//! | module | what it decides |
//! |---|---|
//! | [`http`] | the listener, its workers, and the rejections before dispatch |
//! | [`state`] | balances, nonces, code, storage, `eth_getProof` |
//! | [`calls`] | `eth_call` / `eth_estimateGas` and the prover behind them |
//! | [`blocks`] | headers, uncles, transaction counts and by-index lookups |
//! | [`receipts`] | receipts, raw envelopes, the opt-in passthrough |
//! | [`logs`] | log ranges and poll-based filters |
//! | [`validate`] | shape checks on every field an upstream chooses |
//!
//! The split was mechanical and is checkable as such: `scripts/check_pure_move.py`
//! compares the token multiset before and after, and reports zero code tokens added or
//! removed. Nothing outside this file changed — not `main.rs`, not the adversarial suite.

// Submodules are a filing decision, not an interface one: the `pub use` below re-exports
// the transport entry points at `crate::rpc_server::*`, so every path outside this file
// reads exactly as it did.
//
// `logs` is the exception, and the direction to move the others in: it exports nothing.
// The only thing the parent needs from it by name is the store the `Node` owns, and
// keeping the rest unreachable from here is the part of a split that is worth something
// beyond a smaller file.
mod blocks;
mod calls;
mod http;
mod logs;
mod receipts;
mod state;
mod validate;

pub(crate) use blocks::*;
pub(crate) use calls::*;
pub use http::*;
use logs::FilterStore;
pub(crate) use receipts::*;
pub(crate) use state::*;
pub(crate) use validate::*;

use crate::bind::{
    listen_is_loopback, proof_refused_warning, rpc_http_host_reject, tag_only_upstream_warning,
};
use crate::sync::{
    accept_lookback_resync, append_new, append_new_with_snapshot, is_link_err, safe_of,
    walk_from_checkpoint, walk_headers, write_checkpoint_file,
};
use crate::upstream::RpcUpstream;
use anyhow::{bail, Result};
use helios_bsc_config::{
    expected_safe_lag_blocks, mainnet_current_fork, mainnet_min_distinct_sealers, mainnet_n_seal,
    max_reorg_depth, safe_lag_seconds, safe_lag_within_slo, PROVIDER_PROOF_LOOKBACK,
};
#[cfg(test)]
use helios_bsc_consensus::VoteData;
use helios_bsc_consensus::{
    checkpoint_age_secs, checkpoint_at_snapshot, ecrecover, header_hash, proof_lag, unix_now,
    within_proof_window, Snapshot, VerifiedBlock,
};
use helios_bsc_execution::{
    contract_address, encode_consensus_receipt, encode_data32, encode_qty, eth_call_verified,
    eth_estimate_gas_verified, pad32, retain_requested_storage, tx_gas_price, tx_nonce,
    tx_signing_hash, tx_to_address, validate_bsc_raw_tx, verify_account_code, verify_eth_get_proof,
    verify_receipt_list, verify_storage_slot, verify_tx_list, CallBlock, CallError, CallTx,
    ConsensusLog, ConsensusReceipt, EthAccountProof, ProofError, ProveAtSafe, VerifiedAccount,
    CALL_GAS_CAP, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT, MAX_CALL_ACCOUNTS, MAX_CALL_DATA,
    MAX_CODE_SIZE, MAX_LOG_TOPICS, MAX_ORDERED_TRIE_ITEMS, MAX_RAW_TX, MAX_RECEIPT_LOGS,
};
use helios_bsc_rpc::{
    jsonrpc_id_ok, jsonrpc_is_v2, jsonrpc_params_len, jsonrpc_params_ok, rpc_err, rpc_err_data,
    rpc_ok, wallet_block_number_allowed, wallet_block_tag_str, BlockId, ERR_EXECUTION,
    ERR_INTERNAL, ERR_INVALID, ERR_METHOD, ERR_NOT_SYNCED, ERR_PARAMS, ERR_PARSE, ERR_PROOF_FAILED,
    ERR_STATE_ROOT, ERR_UPSTREAM, MAX_PROOF_STORAGE_KEYS, MAX_RPC_BATCH, MAX_RPC_METHOD,
    MAX_RPC_PARAMS,
};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, keccak256, Checkpoint, RpcBlockHeader, SafeHead,
    BSC_MAINNET_CHAIN_ID,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};

/// JSON-RPC is POST-only. Caps memory if a client streams a huge body.
pub const MAX_RPC_BODY: usize = 1024 * 1024;

pub struct Node {
    up: Box<dyn RpcUpstream>,
    lookback: u64,
    max_sync: u64,
    chain: Mutex<Vec<VerifiedBlock>>,
    snapshot: Mutex<Option<Snapshot>>,
    /// Verified states this client can rewind to when the branch it was following turns
    /// out to have lost.
    ///
    /// Oldest first, one every [`ROLLBACK_EVERY`] blocks. A `Snapshot` is a value: cloning
    /// one captures the sealing set, the `recents` window and the attestation exactly as
    /// they stood at that block, which is the entire state a re-walk needs. The chain
    /// prefix does not have to be stored -- it is already in `chain`, and recovery
    /// truncates rather than refetches.
    ///
    /// Taken only inside `resync_locked`, which already holds `chain` and `snapshot`, so
    /// the lock order is chain -> snapshot -> rollbacks and no other path can invert it.
    rollbacks: Mutex<VecDeque<Snapshot>>,
    checkpoint_store: Option<PathBuf>,
    fork_id: String,
    origin: Option<Checkpoint>,
    origin_checkpoint: Option<u64>,
    proof_ok: AtomicU64,
    proof_fail: AtomicU64,
    headers_verified: AtomicU64,
    /// Sync failures after the tip was fetched (seal / parent-link / Safe).
    header_verify_fail: AtomicU64,
    /// Upstream `eth_blockNumber` failures (transport, not verification).
    upstream_errors: AtomicU64,
    /// Requests whose handling panicked and was caught. Never expected to move; if it
    /// does, the answers around it are `-32603` and the client needs a restart.
    panics: AtomicU64,
    /// Last observed tip / Safe, published after each sync so `/metrics` never has to
    /// take the chain lock. [`NO_BLOCK`] means "not known yet".
    last_tip: AtomicU64,
    last_safe: AtomicU64,
    /// Last observed fast-finality heads (BEP-126): the newest attestation's target
    /// (justified) and source (finalized). Published on the same path as `last_tip` /
    /// `last_safe` for the same reason — a scrape must never take the chain lock.
    /// [`NO_BLOCK`] means "no attestation seen yet", which is a normal state.
    last_justified: AtomicU64,
    last_finalized: AtomicU64,
    /// Consistent view of fast finality, published by `refresh` from one read under the
    /// snapshot lock.
    ///
    /// Reading the snapshot again from `status_fields` looked equivalent and was not: the
    /// background sync can advance it between `refresh` sampling the tip and the status
    /// read, which reported a justified head *above* the tip and a finality lag of 0 while
    /// the real lag was 2. Numbers, hashes and the head they are measured against have to
    /// come from the same instant.
    finality: Mutex<FinalityView>,
    /// Which finality rule block tags resolve to. Default is confirmation depth.
    finality_mode: FinalityMode,
    /// Serialises checkpoint persistence. The background sync thread and any request
    /// thread can both reach `persist_verified_tip`, and two writers racing on the same
    /// file is how a checkpoint ends up truncated — the one outcome tmp+rename exists to
    /// prevent.
    persist_lock: Mutex<()>,
    allow_unverified_passthrough: bool,
    backup_transport: bool,
    metrics_enabled: bool,
    /// Poll-based log and block filters. See [`FilterStore`].
    filters: Mutex<FilterStore>,
}

/// Sentinel for an unpublished `last_tip` / `last_safe` / finality gauge.
const NO_BLOCK: u64 = u64::MAX;

/// Which rule decides the head that block tags resolve to.
///
/// The design doc specifies fast finality as feature-flagged, and it stays that way:
/// changing what `latest` means for a wallet is a behavioural change, and the ≥24h
/// differential soak is the gate for making it the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FinalityMode {
    /// Newest block with ≥`floor(2N/3)+1` distinct subsequent sealers. ~106–113 blocks.
    #[default]
    ConfirmationDepth,
    /// BLS-finalized head (BEP-126) when one is known, else confirmation depth. ~2 blocks.
    Fast,
}

/// Fast-finality heads and the verified head they were measured against, all sampled at
/// the same instant. See [`Node::finality`].
#[derive(Clone, Default)]
struct FinalityView {
    /// Verified head at the time of the read; the lags are relative to this, not to a
    /// tip sampled elsewhere.
    head: u64,
    available: bool,
    justified: Option<(u64, [u8; 32])>,
    finalized: Option<(u64, [u8; 32])>,
    /// Head block tags resolved to at that same instant, and whether fast finality is
    /// what chose it. Carried here rather than re-derived in `status_fields`, because a
    /// concurrent sync can publish a newer view between a request's own `refresh` and its
    /// status read — comparing the two produced a `safeSource` that disagreed with the
    /// `safe` printed beside it.
    read_head: Option<SafeHead>,
    read_head_is_fast: bool,
    /// When the sync that produced this view finished. `None` until the first one does.
    ///
    /// Lives here rather than in its own field so a reader cannot pair a freshness stamp
    /// with a different sample than the one it describes.
    synced_at: Option<Instant>,
}

/// A request whose handling panicked and was caught.
///
/// Deliberately empty: the panic payload is already on stderr through the default hook,
/// and none of it belongs in a reply to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPanicked;

/// Request threads serving the local JSON-RPC listener.
///
/// More than one because the listener must stay answerable while a request is blocked:
/// `helios_bsc_syncStatus` triggers a sync, and against an upstream that does not support
/// JSON-RPC batching a cold walk is one round-trip per header — minutes. A single accept
/// loop would hold `/metrics` behind it for that whole time, which is precisely when a
/// scrape is worth having. Fixed and small, so this cannot become a thread-spawn amplifier.
const RPC_WORKER_THREADS: usize = 4;

/// How far apart retained rollback points are, in blocks.
pub(crate) const ROLLBACK_EVERY: u64 = 16;

/// How many rollback points are retained.
///
/// 16 x 16 = 256 blocks, roughly twelve times `max_reorg_depth()` (21) and comfortably
/// inside the 512-block window `append_new_with_snapshot` keeps -- a point below that is
/// useless, because the blocks a rewind would keep have already been dropped. Each entry
/// is one `Snapshot`: a 21-address validator set, an ~87-entry `recents` map and a
/// bounded ancestor list, so the whole store is tens of kilobytes.
pub(crate) const ROLLBACK_KEEP: usize = 16;

impl Node {
    pub fn bootstrap(up: Box<dyn RpcUpstream>, lookback: u64) -> Result<Self> {
        let tip = up.block_number()?;
        let from = tip.saturating_sub(lookback.saturating_sub(1));
        eprintln!("sync {from}..={tip}");
        let chain = walk_headers(up.as_ref(), from, tip)?;
        let safe = safe_of(&chain)?;
        let n = chain.len() as u64;
        Ok(Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(None),
            rollbacks: Mutex::new(VecDeque::new()),
            checkpoint_store: None,
            fork_id: "fermi".into(),
            origin: None,
            origin_checkpoint: None,
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(n),
            header_verify_fail: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            panics: AtomicU64::new(0),
            last_tip: AtomicU64::new(tip),
            last_safe: AtomicU64::new(safe.number),
            // Lookback bootstrap carries no snapshot, so no attestation is known yet.
            last_justified: AtomicU64::new(NO_BLOCK),
            last_finalized: AtomicU64::new(NO_BLOCK),
            allow_unverified_passthrough: false,
            backup_transport: false,
            finality: Mutex::new(FinalityView::default()),
            finality_mode: FinalityMode::default(),
            persist_lock: Mutex::new(()),
            metrics_enabled: false,
            filters: Mutex::new(FilterStore::default()),
        })
    }

    /// Sync from a weak-subjectivity checkpoint: seals + parent-link + sealing-set membership.
    pub fn bootstrap_from_checkpoint(
        up: Box<dyn RpcUpstream>,
        lookback: u64,
        max_sync: u64,
        checkpoint: Checkpoint,
    ) -> Result<Self> {
        let tip = up.block_number()?;
        eprintln!(
            "sync from checkpoint {} ..= {tip} (sealing set n={})",
            checkpoint.number,
            checkpoint.sealing_set.len()
        );
        let origin_n = checkpoint.number;
        let fork_id = checkpoint.fork_id.clone();
        let (mut chain, mut snapshot) =
            walk_from_checkpoint(up.as_ref(), checkpoint.clone(), tip, max_sync)?;
        // Confirmation depth names no head until ~112 blocks of distinct sealers sit
        // behind the tip, so a checkpoint written at `latest` has nothing to serve yet —
        // and `write-checkpoint --block latest` followed by `run` exited with "no Safe
        // head in lookback" and no hint that waiting was the whole fix. The chain
        // produces ~2.2 blocks a second; extend the walk until a head exists.
        //
        // This is a wait, not a weakening: the threshold is unchanged, and a checkpoint
        // that is genuinely unusable still fails, just with a message that says so.
        let safe = {
            let deadline = Instant::now() + Duration::from_secs(180);
            loop {
                match safe_of(&chain) {
                    Ok(s) => break s,
                    Err(e) => {
                        if Instant::now() >= deadline {
                            return Err(e.context(
                                "no confirmation-depth head after 180s — the checkpoint is too close to the tip for its sealing set to have produced enough distinct sealers",
                            ));
                        }
                        let lag = chain.last().map(|b| b.number).unwrap_or(0);
                        eprintln!(
                            "waiting for a confirmation-depth head (walked to {lag}, need ~{} distinct sealers)",
                            mainnet_min_distinct_sealers()
                        );
                        std::thread::sleep(Duration::from_millis(1500));
                        let newer = up.block_number()?;
                        append_new_with_snapshot(
                            up.as_ref(),
                            &mut chain,
                            newer,
                            Some(&mut snapshot),
                        )?;
                    }
                }
            }
        };
        let n = chain.len() as u64;
        let justified = snapshot.justified().map(|(b, _)| b);
        let finalized = snapshot.finalized().map(|(b, _)| b);
        Ok(Self {
            up,
            lookback,
            max_sync,
            chain: Mutex::new(chain),
            // Seeded with the state the walk ended on: recovery has somewhere to rewind
            // to from the first sync, rather than only after `ROLLBACK_EVERY` blocks.
            rollbacks: Mutex::new(VecDeque::from([snapshot.clone()])),
            snapshot: Mutex::new(Some(snapshot)),
            checkpoint_store: None,
            fork_id,
            origin: Some(checkpoint),
            origin_checkpoint: Some(origin_n),
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(n),
            header_verify_fail: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            panics: AtomicU64::new(0),
            last_tip: AtomicU64::new(tip),
            last_safe: AtomicU64::new(safe.number),
            last_justified: AtomicU64::new(justified.unwrap_or(NO_BLOCK)),
            last_finalized: AtomicU64::new(finalized.unwrap_or(NO_BLOCK)),
            allow_unverified_passthrough: false,
            backup_transport: false,
            finality: Mutex::new(FinalityView::default()),
            finality_mode: FinalityMode::default(),
            persist_lock: Mutex::new(()),
            metrics_enabled: false,
            filters: Mutex::new(FilterStore::default()),
        })
    }

    /// Test helper: inject an already-walked chain (no bootstrap). `refresh` still
    /// talks to `up` and requires a Safe head for serving methods.
    pub fn from_parts(up: Box<dyn RpcUpstream>, lookback: u64, chain: Vec<VerifiedBlock>) -> Self {
        Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            snapshot: Mutex::new(None),
            rollbacks: Mutex::new(VecDeque::new()),
            checkpoint_store: None,
            fork_id: "fermi".into(),
            origin: None,
            origin_checkpoint: None,
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(0),
            header_verify_fail: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            panics: AtomicU64::new(0),
            last_tip: AtomicU64::new(NO_BLOCK),
            last_safe: AtomicU64::new(NO_BLOCK),
            last_justified: AtomicU64::new(NO_BLOCK),
            last_finalized: AtomicU64::new(NO_BLOCK),
            allow_unverified_passthrough: false,
            backup_transport: false,
            finality: Mutex::new(FinalityView::default()),
            finality_mode: FinalityMode::default(),
            persist_lock: Mutex::new(()),
            metrics_enabled: false,
            filters: Mutex::new(FilterStore::default()),
        }
    }

    pub fn from_parts_with_snapshot(
        up: Box<dyn RpcUpstream>,
        lookback: u64,
        chain: Vec<VerifiedBlock>,
        snapshot: Snapshot,
        fork_id: impl Into<String>,
    ) -> Self {
        let origin_n = snapshot.number;
        Self {
            up,
            lookback,
            max_sync: lookback,
            chain: Mutex::new(chain),
            // Seeded with the state the walk ended on: recovery has somewhere to rewind
            // to from the first sync, rather than only after `ROLLBACK_EVERY` blocks.
            rollbacks: Mutex::new(VecDeque::from([snapshot.clone()])),
            snapshot: Mutex::new(Some(snapshot)),
            checkpoint_store: None,
            fork_id: fork_id.into(),
            origin: None,
            origin_checkpoint: Some(origin_n),
            proof_ok: AtomicU64::new(0),
            proof_fail: AtomicU64::new(0),
            headers_verified: AtomicU64::new(0),
            header_verify_fail: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            panics: AtomicU64::new(0),
            last_tip: AtomicU64::new(NO_BLOCK),
            last_safe: AtomicU64::new(NO_BLOCK),
            last_justified: AtomicU64::new(NO_BLOCK),
            last_finalized: AtomicU64::new(NO_BLOCK),
            allow_unverified_passthrough: false,
            backup_transport: false,
            finality: Mutex::new(FinalityView::default()),
            finality_mode: FinalityMode::default(),
            persist_lock: Mutex::new(()),
            metrics_enabled: false,
            filters: Mutex::new(FilterStore::default()),
        }
    }

    pub fn set_checkpoint_store(&mut self, path: PathBuf) {
        self.checkpoint_store = Some(path);
    }

    pub fn set_allow_unverified_passthrough(&mut self, yes: bool) {
        self.allow_unverified_passthrough = yes;
        if yes {
            eprintln!(
                "warning: --allow-unverified-passthrough on (receipts/txs header-bound to Safe; gasPrice unbound)"
            );
        }
    }

    pub fn set_backup_transport(&mut self, yes: bool) {
        self.backup_transport = yes;
    }

    pub fn set_metrics_enabled(&mut self, yes: bool) {
        self.metrics_enabled = yes;
    }

    pub fn set_finality_mode(&mut self, mode: FinalityMode) {
        self.finality_mode = mode;
    }

    /// Head that block tags resolve to: `latest` / `safe` / `finalized`, and the ceiling
    /// on historical reads.
    ///
    /// Confirmation depth unless `--finality fast`. In fast mode the BLS-finalized head
    /// is used only when it is **newer** than confirmation depth and names a block this
    /// client verified itself — an attestation pointing at a block we never walked is an
    /// upstream's word, not a head. Taking the newer of the two also means enabling the
    /// flag can never move reads backwards: both rules are complete finality rules on
    /// their own, so the head is final under at least one of them either way.
    fn read_head(
        &self,
        chain: &[VerifiedBlock],
        snapshot: Option<&Snapshot>,
        conf_safe: &SafeHead,
    ) -> SafeHead {
        if self.finality_mode != FinalityMode::Fast {
            return conf_safe.clone();
        }
        // One definition of the rule, shared with `soak --finality fast`: the gate and
        // the thing it gates must not be able to disagree about which head that is.
        // `distinct_sealers` / `required_sealers` stay the confirmation-depth counts;
        // `safeSource` on `helios_bsc_syncStatus` says which rule actually chose.
        crate::sync::fast_finality_head(chain, snapshot, conf_safe)
    }

    /// True when the snapshot carries the BLS vote keys `FinalityMode::Fast` needs.
    ///
    /// `read_head` falls back to confirmation depth without them, which is the safe
    /// direction but a silent one — the caller uses this to say so at startup instead.
    pub fn fast_finality_armed(&self) -> bool {
        self.snapshot
            .lock()
            .expect("snapshot lock")
            .as_ref()
            .is_some_and(Snapshot::fast_finality_available)
    }

    /// One `eth_getProof` at the read head, to find out at startup what an operator
    /// currently finds out on their first `eth_getBalance`.
    ///
    /// Providers split into those that serve `eth_getProof` at a **named block** and
    /// those that only serve it for the tag `latest` — `docs/proof-provider-matrix.md`
    /// measures which. This client can never use the tag: the whole point is to prove
    /// against a header it sealed itself, and `latest` on the upstream is whatever that
    /// upstream says it is. So a tag-only provider cannot serve this client at all, at
    /// any lag, under any finality rule.
    ///
    /// Without this probe that surfaces as `proof_verification_failed` on the first
    /// balance read, wrapped in two retries and a backup attempt, with the real cause —
    /// `-32602 distance to target block exceeds maximum proof window` — somewhere in the
    /// middle of the string. It reads like a fault in this client. It is a provider that
    /// was never going to work.
    ///
    /// A warning, not a refusal: a provider having a bad minute at startup must not stop
    /// a client that would serve fine once it recovers.
    pub fn proof_capability_warning(&self) -> Option<String> {
        // The published view is empty until the first `refresh`, and at startup that has
        // not happened yet -- reading it and giving up is how this probe spent its first
        // live run printing nothing at all. Sync first if there is nothing published.
        let published = self
            .finality
            .lock()
            .expect("finality lock")
            .read_head
            .clone();
        let head = match published {
            Some(h) => h,
            None => match self.poll_sync() {
                Ok((_, safe)) => safe,
                // No head means nothing to prove against, and the operator already has a
                // louder error than this one.
                Err(_) => return None,
            },
        };
        // Address zero: every node has it, it needs no fixture, and a verified exclusion
        // is as good an answer as any. This asks whether the provider will answer at a
        // named block at all, not what the answer is.
        let zero = "0x0000000000000000000000000000000000000000";
        let err = match self.up.get_proof(zero, &format!("0x{:x}", head.number)) {
            Ok(_) => return None,
            Err(e) => e.to_string(),
        };
        let lag = proof_lag(self.last_tip.load(Ordering::Relaxed), head.number);
        let at = format!("its own verified head {} (lag {lag})", head.number);
        // If the tag works where the number does not, the provider is tag-only and no
        // amount of waiting, retrying or shortening the lag will help. Say that outright
        // rather than leaving the operator to tune a knob that cannot reach.
        if self.up.get_proof(zero, "latest").is_ok() {
            return Some(tag_only_upstream_warning(&at, &err));
        }
        Some(proof_refused_warning(&at, &err))
    }

    pub fn metrics_enabled(&self) -> bool {
        self.metrics_enabled
    }

    /// Hold the chain lock, so a test can prove `/metrics` does not need it.
    #[cfg(test)]
    pub fn lock_chain_for_test(&self) -> std::sync::MutexGuard<'_, Vec<VerifiedBlock>> {
        self.chain.lock().expect("chain lock")
    }

    /// Run `f` while the finality lock is held, so a test can park a concurrent
    /// `refresh` exactly at its publish step. See [`Node::finality`].
    #[cfg(test)]
    pub fn hold_finality_lock_for_test<T>(&self, f: impl FnOnce() -> T) -> T {
        let _held = self.finality.lock().expect("finality lock");
        f()
    }

    /// Non-blocking probe: is the chain lock held by somebody else right now?
    #[cfg(test)]
    pub fn chain_lock_is_held_for_test(&self) -> bool {
        self.chain.try_lock().is_err()
    }

    /// Last published tip gauge; `None` is the [`NO_BLOCK`] "no sync yet" sentinel.
    #[cfg(test)]
    pub fn published_tip_for_test(&self) -> Option<u64> {
        let t = self.last_tip.load(Ordering::Relaxed);
        (t != NO_BLOCK).then_some(t)
    }

    /// Publish a fast-finality pair exactly as a successful `refresh` would.
    ///
    /// The mock chain has no real BLS attestations, and forging one here would prove
    /// nothing: whether a signature is genuine is settled in `helios-bsc-consensus`
    /// against live mainnet fixtures. What these tests cover instead is the reporting
    /// path — that a known head reaches `/metrics` and `syncStatus`, and that an unknown
    /// one reads as `-1` / `null` rather than zero.
    #[cfg(test)]
    pub fn publish_finality_for_test(
        &self,
        justified: (u64, [u8; 32]),
        finalized: (u64, [u8; 32]),
    ) {
        if let Some(snap) = self.snapshot.lock().expect("snapshot lock").as_mut() {
            snap.attestation = Some(VoteData {
                source_number: finalized.0,
                source_hash: finalized.1,
                target_number: justified.0,
                target_hash: justified.1,
            });
        }
        self.last_justified.store(justified.0, Ordering::Relaxed);
        self.last_finalized.store(finalized.0, Ordering::Relaxed);
        let mut view = self.finality.lock().expect("finality lock");
        view.available = true;
        view.justified = Some(justified);
        view.finalized = Some(finalized);
    }

    /// Prometheus text exposition (`docs/slo.md`).
    ///
    /// **Lock-free by construction.** It reads only atomics published by the last
    /// successful sync — never the chain mutex, and never `refresh()`. Both matter:
    /// a scrape must not drive upstream RPC load, and it must not queue behind a sync
    /// that is holding the chain lock across slow network I/O. Otherwise scrapes time
    /// out exactly when the node is struggling, which is when metrics are needed most.
    /// Values are therefore as of the last sync: a stalled poller surfaces as a
    /// growing `safe_lag`, it does not hide behind a fetch.
    pub fn metrics_text(&self) -> String {
        let raw_tip = self.last_tip.load(Ordering::Relaxed);
        let raw_safe = self.last_safe.load(Ordering::Relaxed);
        let raw_justified = self.last_justified.load(Ordering::Relaxed);
        let raw_finalized = self.last_finalized.load(Ordering::Relaxed);
        let tip = (raw_tip != NO_BLOCK).then_some(raw_tip);
        let safe = (raw_safe != NO_BLOCK).then_some(raw_safe);
        let justified = (raw_justified != NO_BLOCK).then_some(raw_justified);
        let finalized = (raw_finalized != NO_BLOCK).then_some(raw_finalized);
        let interval_ms = mainnet_current_fork().block_interval_ms;
        let lag = match (tip, safe) {
            (Some(t), Some(s)) => Some(proof_lag(t, s)),
            _ => None,
        };
        let finalized_lag = match (tip, finalized) {
            (Some(t), Some(f)) => Some(proof_lag(t, f)),
            _ => None,
        };
        let checkpoint_age = self
            .origin
            .as_ref()
            .map(|cp| checkpoint_age_secs(cp.timestamp, unix_now()));

        let mut out = String::with_capacity(2048);
        let mut counter = |name: &str, help: &str, v: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"
            ));
        };
        counter(
            "helios_bsc_headers_verified_total",
            "Headers whose seal and parent link verified since process start.",
            self.headers_verified.load(Ordering::Relaxed),
        );
        counter(
            "helios_bsc_header_verify_fail_total",
            "Sync attempts rejected after the tip was fetched (seal, parent link, or no Safe).",
            self.header_verify_fail.load(Ordering::Relaxed),
        );
        counter(
            "helios_bsc_proof_success_total",
            "Merkle proofs that verified against a Safe stateRoot.",
            self.proof_ok.load(Ordering::Relaxed),
        );
        counter(
            "helios_bsc_proof_fail_total",
            "Merkle proofs rejected (root mismatch or malformed trie node).",
            self.proof_fail.load(Ordering::Relaxed),
        );
        counter(
            "helios_bsc_upstream_errors_total",
            "Upstream transport failures fetching the tip (not a verification failure).",
            self.upstream_errors.load(Ordering::Relaxed),
        );
        counter(
            "helios_bsc_request_panics_total",
            "Requests whose handling panicked and was answered -32603. Alert on any increase.",
            self.panics.load(Ordering::Relaxed),
        );

        let mut gauge = |name: &str, help: &str, v: String| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n"
            ));
        };
        gauge(
            "helios_bsc_tip_block",
            "Highest locally verified block number (-1 before the first sync).",
            tip.map_or_else(|| "-1".into(), |t| t.to_string()),
        );
        gauge(
            "helios_bsc_safe_block",
            "Confirmation-depth Safe head (-1 when no Safe head exists yet).",
            safe.map_or_else(|| "-1".into(), |s| s.to_string()),
        );
        gauge(
            "helios_bsc_safe_lag_blocks",
            "Tip minus Safe, in blocks (-1 when no Safe head exists yet).",
            lag.map_or_else(|| "-1".into(), |l| l.to_string()),
        );
        gauge(
            "helios_bsc_safe_lag_seconds",
            "Tip minus Safe, in seconds (-1 when no Safe head exists yet).",
            lag.map_or_else(
                || "-1".into(),
                |l| safe_lag_seconds(l, interval_ms).to_string(),
            ),
        );
        gauge(
            "helios_bsc_safe_lag_within_bound",
            "1 when Safe lag is inside the documented SLO bound, else 0.",
            lag.map_or_else(
                || "0".into(),
                |l| u8::from(safe_lag_within_slo(l)).to_string(),
            ),
        );
        gauge(
            "helios_bsc_checkpoint_age_seconds",
            "Age of the origin checkpoint (-1 when running without one).",
            checkpoint_age.map_or_else(|| "-1".into(), |a| a.to_string()),
        );
        gauge(
            "helios_bsc_finalized_block",
            "Fast-finality finalized head: the newest attestation's source (-1 when no attestation has been seen).",
            finalized.map_or_else(|| "-1".into(), |f| f.to_string()),
        );
        gauge(
            "helios_bsc_finalized_lag_blocks",
            "Tip minus the fast-finality finalized head, in blocks (-1 when no attestation has been seen).",
            finalized_lag.map_or_else(|| "-1".into(), |l| l.to_string()),
        );
        gauge(
            "helios_bsc_justified_block",
            "Fast-finality justified head: the newest attestation's target (-1 when no attestation has been seen).",
            justified.map_or_else(|| "-1".into(), |j| j.to_string()),
        );
        gauge(
            "helios_bsc_finality_mode",
            "0 = confirmation-depth, 1 = fast finality (BLS attestation, finalized head known).",
            u8::from(finalized.is_some()).to_string(),
        );
        gauge(
            "helios_bsc_sealing_set_enforced",
            "1 when a checkpoint supplies the sealing set, else 0 (lookback-only).",
            u8::from(self.origin_checkpoint.is_some()).to_string(),
        );
        gauge(
            "helios_bsc_unverified_passthrough_enabled",
            "1 when --allow-unverified-passthrough is on, else 0.",
            u8::from(self.allow_unverified_passthrough).to_string(),
        );
        out
    }

    fn bump_proof_ok(&self) {
        self.proof_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn bump_proof_fail(&self) {
        self.proof_fail.fetch_add(1, Ordering::Relaxed);
    }

    fn bump_headers(&self, n: u64) {
        if n > 0 {
            self.headers_verified.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Write last verified header + current sealing set for the next process start.
    pub fn persist_verified_tip(&self) {
        let Some(path) = self.checkpoint_store.as_ref() else {
            return;
        };
        // Held for the whole read-then-write: two writers could otherwise interleave and
        // leave the newer checkpoint overwritten by the older one's snapshot.
        let _persist = self.persist_lock.lock().expect("persist lock");
        let (hash, state_root, number, snap, stored) = {
            let chain = self.chain.lock().expect("chain lock");
            let snapshot = self.snapshot.lock().expect("snapshot lock");
            let Some(last) = chain.last() else {
                return;
            };
            let Some(snap) = snapshot.as_ref() else {
                return;
            };
            (
                last.hash,
                last.state_root,
                last.number,
                snap.clone(),
                last.header.clone(),
            )
        };
        let header = if let Some(h) = stored {
            h
        } else {
            let hash_hex = format!("0x{}", hex::encode(hash));
            match self.up.header_by_hash(&hash_hex) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("checkpoint store: header fetch failed: {e}");
                    return;
                }
            }
        };
        match header_hash(&header) {
            Ok(got) if got == hash => {}
            Ok(_) => {
                eprintln!("checkpoint store: re-fetched header hash mismatch");
                return;
            }
            Err(e) => {
                eprintln!("checkpoint store: re-fetched header rlp: {e}");
                return;
            }
        }
        if decode_u64(&header.number).ok() != Some(number) {
            eprintln!("checkpoint store: re-fetched header number mismatch");
            return;
        }
        if decode_hex_fixed::<32>(&header.state_root).ok() != Some(state_root) {
            eprintln!("checkpoint store: re-fetched header stateRoot mismatch");
            return;
        }
        match checkpoint_at_snapshot(
            &header,
            &snap,
            self.fork_id.clone(),
            Some("helios-bsc last-verified".into()),
        ) {
            Ok(cp) => {
                if let Err(e) = write_checkpoint_file(path, &cp) {
                    eprintln!("checkpoint store: {e}");
                }
            }
            Err(e) => eprintln!("checkpoint store: {e}"),
        }
    }

    /// Catch up to the live tip. The background poller. Always goes to the upstream: it is what keeps the coalescing
    /// window below fed, so a coalesced answer is never older than one poll interval.
    pub fn poll_sync(&self) -> Result<(u64, SafeHead)> {
        self.refresh_now()
    }

    /// Reuse the last published sync if the chain cannot have moved since.
    ///
    /// Every served method calls this first, and it used to mean one upstream
    /// `eth_blockNumber` per request — so a single 64-element JSON-RPC batch, well inside
    /// `MAX_RPC_BATCH`, fired 64 upstream calls and burned the operator's quota from one
    /// request. Each of those also serialised behind the chain lock, so four worker
    /// threads answered like one.
    ///
    /// The window is the fork's block interval, because that is the fastest the chain can
    /// produce anything new: inside it a fresh poll cannot return a different head, so
    /// skipping it costs no accuracy at all. It is not a cache with a staleness budget.
    fn refresh(&self) -> Result<(u64, SafeHead)> {
        if let Some(fresh) = self.published_if_fresh() {
            return Ok(fresh);
        }
        self.refresh_now()
    }

    /// `(head, read head)` from the last sync, or `None` if it is older than one block.
    fn published_if_fresh(&self) -> Option<(u64, SafeHead)> {
        let view = self.finality.lock().expect("finality lock");
        let window = Duration::from_millis(mainnet_current_fork().block_interval_ms);
        if view.synced_at?.elapsed() >= window {
            return None;
        }
        Some((view.head, view.read_head.clone()?))
    }

    fn refresh_now(&self) -> Result<(u64, SafeHead)> {
        // Outside the locks on purpose. This is a network call with a 30 s cap and three
        // backoff retries behind it; holding `chain` and `snapshot` across it let one slow
        // upstream stall every worker for minutes. A tip that goes stale while we wait for
        // the locks is harmless — `resync_locked` treats an already-passed height as a
        // no-op, and the head published below is read back off the chain, never from this
        // number, so no consumer can see a head the client has not verified.
        //
        // Transport failure here is not a verification failure — count it apart so a
        // flaky provider never looks like a lying one on the metrics dashboard.
        let tip = match self.up.block_number() {
            Ok(t) => t,
            Err(e) => {
                self.upstream_errors.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let mut chain = self.chain.lock().expect("chain lock");
        let mut snapshot = self.snapshot.lock().expect("snapshot lock");
        let (safe, conf_safe, verified_this, grew) =
            match self.resync_locked(&mut chain, &mut snapshot, tip) {
                Ok(v) => v,
                Err(e) => {
                    self.header_verify_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            };
        // The head is the highest header this client actually verified, read back off the
        // chain rather than taken from the `tip` sampled before the locks. A concurrent
        // sync can have advanced past that number while this thread waited, and pairing an
        // older tip with a newer chain is how a head, its lag and its source end up
        // describing different instants.
        let head = chain.last().map(|b| b.number).unwrap_or(tip);
        // Read the fast-finality heads while the snapshot is still locked, and keep them
        // together with the head they are measured against. Everything published below
        // comes from this one sample, so no consumer can mix two instants.
        let mut view = match snapshot.as_ref() {
            Some(s) => FinalityView {
                head,
                available: s.fast_finality_available(),
                justified: s.justified(),
                finalized: s.finalized(),
                ..FinalityView::default()
            },
            None => FinalityView {
                head,
                ..FinalityView::default()
            },
        };
        view.read_head_is_fast = safe.number != conf_safe.number;
        view.read_head = Some(safe.clone());
        view.synced_at = Some(Instant::now());
        // Publish **while the chain lock is still held**. `docs/slo.md` promises that
        // `helios_bsc_tip_block` and the finality gauges are "published together", and
        // publishing after the drop broke that with four worker threads: the whole sync
        // is serialised by this lock, so a thread descheduled between `drop(chain)` and
        // these stores could be overtaken by a newer sync and then overwrite it with its
        // own older sample — tip, safe and the finality view going *backwards* and
        // staying there until the next sync. These are plain atomic stores plus one
        // uncontended mutex, no I/O, so the critical section does not grow measurably.
        // `/metrics` still reads only atomics and never takes this lock.
        self.last_tip.store(head, Ordering::Relaxed);
        // `last_safe` is the confirmation-depth head, whatever tags resolve to — the SLO
        // bound and its alerts are defined against that rule, so the gauge must not start
        // meaning something else when the flag is on.
        self.last_safe.store(conf_safe.number, Ordering::Relaxed);
        self.last_justified.store(
            view.justified.map_or(NO_BLOCK, |(b, _)| b),
            Ordering::Relaxed,
        );
        self.last_finalized.store(
            view.finalized.map_or(NO_BLOCK, |(b, _)| b),
            Ordering::Relaxed,
        );
        // Lock order is chain → snapshot → finality everywhere (`status_fields` takes
        // snapshot then finality and holds neither across the other).
        *self.finality.lock().expect("finality lock") = view;
        drop(chain);
        drop(snapshot);
        self.bump_headers(verified_this);
        // Must stay outside: `persist_verified_tip` re-takes chain and snapshot.
        if grew {
            self.persist_verified_tip();
        }
        Ok((head, safe))
    }

    /// Advance the locked chain to `tip`. Returns `(safe, newly_verified, grew)`.
    fn resync_locked(
        &self,
        chain: &mut Vec<VerifiedBlock>,
        snapshot: &mut Option<Snapshot>,
        tip: u64,
    ) -> Result<(SafeHead, SafeHead, u64, bool)> {
        let last = chain.last().map(|b| b.number).unwrap_or(0);
        let mut grew = false;
        let verified_this;
        if snapshot.is_some() {
            if tip > last.saturating_add(self.max_sync) {
                bail!(
                    "tip jumped {} blocks; pass a fresh --checkpoint (max-sync {})",
                    tip.saturating_sub(last),
                    self.max_sync
                );
            }
            match append_new_with_snapshot(self.up.as_ref(), chain, tip, snapshot.as_mut()) {
                Ok(()) => {}
                Err(e) if is_link_err(&e) => {
                    self.recover_from_link_break(chain, snapshot, tip, e)?
                }
                Err(e) => return Err(e),
            }
            if let Some(s) = snapshot.as_ref() {
                self.record_rollback(s, chain.first().map(|b| b.number).unwrap_or(0));
            }
            let new_last = chain.last().map(|b| b.number).unwrap_or(0);
            grew = new_last > last;
            verified_this = new_last.saturating_sub(last);
        } else if tip > last.saturating_add(self.lookback) || chain.len() < 16 {
            let from = tip.saturating_sub(self.lookback.saturating_sub(1));
            *chain = walk_headers(self.up.as_ref(), from, tip)?;
            verified_this = chain.len() as u64;
        } else if let Err(e) = append_new(self.up.as_ref(), chain, tip) {
            if is_link_err(&e) {
                eprintln!(
                    "reorg/link break ({e}); resync lookback (max reorg {})",
                    max_reorg_depth()
                );
                let from = tip.saturating_sub(self.lookback.saturating_sub(1));
                let walked = walk_headers(self.up.as_ref(), from, tip)?;
                let old = chain.clone();
                *chain = accept_lookback_resync(&old, walked)?;
                verified_this = chain.len() as u64;
            } else {
                return Err(e);
            }
        } else {
            verified_this = chain
                .last()
                .map(|b| b.number.saturating_sub(last))
                .unwrap_or(0);
        }
        let conf_safe = safe_of(chain)?;
        let head = self.read_head(chain, snapshot.as_ref(), &conf_safe);
        Ok((head, conf_safe, verified_this, grew))
    }

    /// Rewind to the newest verified state the canonical chain still contains, and walk
    /// forward from there.
    ///
    /// Recovery used to have exactly one starting point: the checkpoint this process
    /// booted from, fixed at bootstrap and never moved. That works for the first
    /// `max_sync` blocks of uptime -- about two hours at the default -- and after that
    /// `walk_from_checkpoint` refuses the lag outright and no later attempt can do better,
    /// because the thing it starts from only ever gets further away. A reorg past that
    /// point left the process up, on an orphaned branch, answering `-32003` until someone
    /// restarted it: exactly the failure a month-long run is meant to survive.
    ///
    /// So the client keeps its own rollback points as it goes. Each candidate is *tried*
    /// rather than reasoned about: the chain is truncated to the point, the retained
    /// snapshot is restored, and the walk forward re-runs the same parent-link, cascading
    /// and seal checks as any other sync. A point that was itself on the losing branch
    /// fails that walk at its first header, and the next one back is tried. Nothing is
    /// committed until a walk succeeds, so a failed recovery leaves the node exactly as it
    /// was -- the same discipline as `append_new_with_snapshot`, and for the same reason.
    fn recover_from_link_break(
        &self,
        chain: &mut Vec<VerifiedBlock>,
        snapshot: &mut Option<Snapshot>,
        tip: u64,
        err: anyhow::Error,
    ) -> Result<()> {
        // `{err:#}` rather than `{err}`: the cause is what says *why* this is a reorg, and
        // plain Display prints only the outermost context -- the same property that
        // stopped `is_link_err` seeing it at all.
        eprintln!("reorg/link break ({err:#})");
        let points: Vec<Snapshot> = {
            let rb = self.rollbacks.lock().expect("rollback lock");
            rb.iter().rev().cloned().collect()
        };
        let head = chain.last().map(|b| b.number).unwrap_or(0);
        let floor = chain.first().map(|b| b.number).unwrap_or(0);
        let mut tried = 0usize;
        for point in points {
            // Below the chain's own window there is nothing to rewind to: `KEEP` has
            // already dropped the blocks a truncation would have kept.
            if point.number < floor || point.number > tip {
                continue;
            }
            let mut candidate: Vec<VerifiedBlock> = chain
                .iter()
                .take_while(|b| b.number <= point.number)
                .cloned()
                .collect();
            // A snapshot describes the state *after* its own block, so the prefix has to
            // end exactly there, or the walk would check the next header against the
            // wrong parent.
            if candidate.last().map(|b| b.number) != Some(point.number) {
                continue;
            }
            let mut restored = point.clone();
            tried += 1;
            match append_new_with_snapshot(
                self.up.as_ref(),
                &mut candidate,
                tip,
                Some(&mut restored),
            ) {
                Ok(()) => {
                    eprintln!(
                        "reorg recovered: rewound {} block(s) to {} and re-walked to {tip}",
                        head.saturating_sub(point.number),
                        point.number
                    );
                    *chain = candidate;
                    *snapshot = Some(restored);
                    // Every point above the fork describes the branch that lost. Keeping
                    // them would offer a later recovery a starting state this client has
                    // just established is not on the chain.
                    let mut rb = self.rollbacks.lock().expect("rollback lock");
                    while rb.back().is_some_and(|s| s.number > point.number) {
                        rb.pop_back();
                    }
                    return Ok(());
                }
                // This point was on the losing branch as well: go further back.
                Err(again) if is_link_err(&again) => continue,
                // Not a fork. A transport or seal failure would meet every older point the
                // same way, so stop here and leave the node untouched.
                Err(other) => return Err(other),
            }
        }
        let span = ROLLBACK_EVERY.saturating_mul(ROLLBACK_KEEP as u64);
        let Some(cp) = self.origin.clone() else {
            return Err(err.context(format!(
                "reorg recovery: {tried} rollback point(s) tried and none was on the canonical chain, and this process booted without a --checkpoint to replay from"
            )));
        };
        let cp_number = cp.number;
        eprintln!("no usable rollback point ({tried} tried); replay from checkpoint {cp_number}");
        let (c, s) =
            walk_from_checkpoint(self.up.as_ref(), cp, tip, self.max_sync).map_err(|replay| {
                // Reached only when the reorg is deeper than everything retained, which on
                // this chain means something considerably worse than a reorg. The origin
                // checkpoint does not move, so once uptime has carried the chain more than
                // `max_sync` past it this replay cannot reach the tip and no later attempt
                // will either: every sync from here fails identically while the process
                // stays up. That is a restart, and the operator has to be told so rather
                // than left reading the same line repeat.
                let behind = tip.saturating_sub(cp_number);
                anyhow::anyhow!("reorg recovery failed: {replay:#}. {tried} rollback point(s) covering up to {span} blocks were tried first and none was on the canonical chain. The fallback replays from the checkpoint this process booted from ({cp_number}), now {behind} blocks behind the tip; nothing recovers that in place. Write a fresh checkpoint and restart.")
            })?;
        *chain = c;
        *snapshot = Some(s);
        // The replay established a different chain; nothing retained describes it.
        self.rollbacks.lock().expect("rollback lock").clear();
        Ok(())
    }

    /// Block numbers of the retained rollback points, oldest first.
    ///
    /// `pub(crate)` for the reorg tests. How deep a reorg this client can absorb without a
    /// restart is decided entirely by the retention arithmetic below, and a test that only
    /// watched a recovery succeed would not notice that arithmetic quietly narrowing.
    #[cfg(test)]
    pub(crate) fn rollback_points(&self) -> Vec<u64> {
        self.rollbacks
            .lock()
            .expect("rollback lock")
            .iter()
            .map(|s| s.number)
            .collect()
    }

    /// Retain the current verified state as a rollback point, every [`ROLLBACK_EVERY`]
    /// blocks.
    ///
    /// `chain_floor` is the oldest block the chain still holds. Points below it are
    /// dropped rather than kept as dead weight: recovery truncates the live chain to a
    /// point, and it cannot truncate to a block that has already been aged out.
    fn record_rollback(&self, snapshot: &Snapshot, chain_floor: u64) {
        let mut rb = self.rollbacks.lock().expect("rollback lock");
        while rb.front().is_some_and(|s| s.number < chain_floor) {
            rb.pop_front();
        }
        let due = match rb.back() {
            Some(newest) => snapshot.number >= newest.number.saturating_add(ROLLBACK_EVERY),
            None => true,
        };
        if !due {
            return;
        }
        rb.push_back(snapshot.clone());
        while rb.len() > ROLLBACK_KEEP {
            rb.pop_front();
        }
    }

    /// JSON-RPC 2.0 envelope: single object, batch array, or parse error.
    /// Batch notifications (no `id` member) are omitted from the response array.
    /// A single notification returns JSON `null` (HTTP 204 at the socket).
    pub fn dispatch(&self, body: &Value) -> Value {
        match body {
            Value::Array(arr) if arr.is_empty() => {
                rpc_err(Value::Null, ERR_INVALID, "invalid_request")
            }
            Value::Array(arr) if arr.len() > MAX_RPC_BATCH => {
                rpc_err(Value::Null, ERR_INVALID, "invalid_request")
            }
            Value::Array(arr) => {
                let mut out = Vec::new();
                for x in arr {
                    if !x.is_object() {
                        out.push(rpc_err(Value::Null, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    if x.get("id").is_none() {
                        continue;
                    }
                    let id = x.get("id").cloned().unwrap_or(Value::Null);
                    if !jsonrpc_id_ok(&id) {
                        out.push(rpc_err(Value::Null, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    if !jsonrpc_is_v2(x) {
                        out.push(rpc_err(id, ERR_INVALID, "invalid_request"));
                        continue;
                    }
                    out.push(self.handle(x));
                }
                Value::Array(out)
            }
            Value::Object(_) => {
                if body.get("id").is_none() {
                    return Value::Null;
                }
                let id = body.get("id").cloned().unwrap_or(Value::Null);
                if !jsonrpc_id_ok(&id) {
                    return rpc_err(Value::Null, ERR_INVALID, "invalid_request");
                }
                if !jsonrpc_is_v2(body) {
                    return rpc_err(id, ERR_INVALID, "invalid_request");
                }
                self.handle(body)
            }
            _ => rpc_err(Value::Null, ERR_INVALID, "invalid_request"),
        }
    }

    /// [`Node::dispatch_bytes`], with a panic turned into `Err(())` instead of unwinding
    /// into the worker loop. See the call site in `serve_one` for why that matters.
    ///
    /// `AssertUnwindSafe` is the honest annotation rather than a workaround: everything
    /// this touches is behind a mutex, and a panic that leaves one poisoned makes every
    /// later access panic too — caught here, reported, never silently used.
    pub fn dispatch_caught(&self, buf: &[u8]) -> std::result::Result<Value, RequestPanicked> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dispatch_bytes(buf))).map_err(
            |_| {
                self.panics.fetch_add(1, Ordering::Relaxed);
                RequestPanicked
            },
        )
    }

    pub fn dispatch_bytes(&self, buf: &[u8]) -> Value {
        match serde_json::from_slice::<Value>(buf) {
            Ok(body) => self.dispatch(&body),
            Err(_) => rpc_err(Value::Null, ERR_PARSE, "parse_error"),
        }
    }

    pub fn handle(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        if req.get("id").is_some() && !jsonrpc_id_ok(&id) {
            return rpc_err(Value::Null, ERR_INVALID, "invalid_request");
        }
        if !jsonrpc_is_v2(req) {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        }
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        };
        if method.is_empty()
            || method.len() > MAX_RPC_METHOD
            || !method.bytes().all(|b| b.is_ascii_graphic())
        {
            return rpc_err(id, ERR_INVALID, "invalid_request");
        }
        if !jsonrpc_params_ok(req) {
            return rpc_err(id, ERR_PARAMS, "params must be an array");
        }
        if jsonrpc_params_len(req) > MAX_RPC_PARAMS {
            return rpc_err(id, ERR_PARAMS, "too many params");
        }
        match method {
            "eth_chainId" => rpc_ok(id, json!("0x38")),
            "eth_protocolVersion" => rpc_ok(id, json!("0x41")),
            "net_version" => rpc_ok(id, json!("56")),
            "net_listening" => rpc_ok(id, json!(true)),
            "net_peerCount" => rpc_ok(id, json!("0x0")),
            "web3_clientVersion" => rpc_ok(
                id,
                json!(format!("helios-bsc/{}", env!("CARGO_PKG_VERSION"))),
            ),
            "eth_accounts" => rpc_ok(id, json!([])),
            "eth_mining" => rpc_ok(id, json!(false)),
            "eth_hashrate" => rpc_ok(id, json!("0x0")),
            "web3_sha3" => self.web3_sha3(id, req),
            "eth_syncing" => self.eth_syncing(id),
            "eth_blockNumber" => match self.refresh() {
                Ok((_, safe)) => rpc_ok(id, json!(format!("0x{:x}", safe.number))),
                Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
            },
            "helios_bsc_syncStatus" => match self.refresh() {
                Ok((tip, safe)) => rpc_ok(id, self.status_fields(tip, &safe)),
                Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
            },
            "eth_getBalance" => self.account_field(id, req, AccountField::Balance),
            "eth_getTransactionCount" => self.account_field(id, req, AccountField::Nonce),
            "eth_getCode" => self.get_code(id, req),
            "eth_call" => self.eth_call(id, req),
            "eth_estimateGas" => self.eth_estimate_gas(id, req),
            "eth_getStorageAt" => self.get_storage(id, req),
            "eth_getProof" => self.get_eth_proof(id, req),
            "eth_getBlockByNumber" => self.get_block_by_number(id, req),
            "eth_getBlockByHash" => self.get_block_by_hash(id, req),
            "eth_getBlockTransactionCountByNumber" => self.tx_count_by_number(id, req),
            "eth_getBlockTransactionCountByHash" => self.tx_count_by_hash(id, req),
            "eth_getTransactionByBlockNumberAndIndex" => self.tx_by_block_number_and_index(id, req),
            "eth_getTransactionByBlockHashAndIndex" => self.tx_by_block_hash_and_index(id, req),
            "eth_getUncleCountByBlockNumber" => self.uncle_count_by_number(id, req),
            "eth_getUncleCountByBlockHash" => self.uncle_count_by_hash(id, req),
            "eth_getUncleByBlockNumberAndIndex" => self.uncle_by_number(id, req),
            "eth_getUncleByBlockHashAndIndex" => self.uncle_by_hash(id, req),
            "eth_coinbase" => rpc_ok(id, json!("0x0000000000000000000000000000000000000000")),
            "eth_sendRawTransaction" => self.send_raw(id, req),
            "eth_getBlockReceipts" => self.get_block_receipts(id, req),
            "eth_getLogs" => self.get_logs(id, req),
            "eth_newFilter" => self.new_filter(id, req),
            "eth_newBlockFilter" => self.new_block_filter(id),
            "eth_uninstallFilter" => self.uninstall_filter(id, req),
            "eth_getFilterChanges" => self.get_filter_changes(id, req),
            "eth_getFilterLogs" => self.get_filter_logs(id, req),
            "eth_getTransactionReceipt" => self.get_transaction_receipt(id, req),
            "eth_getTransactionByHash" => self.unverified_mined(id, req, method),
            "eth_getRawTransactionByHash" => self.get_raw_tx_by_hash(id, req),
            "eth_gasPrice" | "eth_maxPriorityFeePerGas" | "eth_feeHistory" | "eth_blobBaseFee" => {
                self.unverified_qty(id, req, method)
            }
            "helios_bsc_getVerificationStatus" => self.verification_status(id),
            // Every method the passthrough allow-list names has an explicit arm above,
            // which is where `unverified_passthrough_disabled` comes from. This arm is
            // only reached by a method with no handler at all, and each `MethodPolicy`
            // used to answer exactly the same thing here — including a guard on
            // `unverified_passthrough_ok` that could never be true. The table is still
            // the specification; `every_passthrough_method_has_its_own_arm` and
            // `the_dispatcher_agrees_with_the_method_policy_table` keep the two aligned.
            _ => rpc_err(id, ERR_METHOD, "method_unsupported"),
        }
    }

    fn web3_sha3(&self, id: Value, req: &Value) -> Value {
        let Some(hex) = req
            .get("params")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .and_then(Value::as_str)
        else {
            return rpc_err(id, ERR_PARAMS, "data hex required");
        };
        match decode_hex(hex) {
            Ok(bytes) if bytes.len() > MAX_RAW_TX => {
                rpc_err(id, ERR_PARAMS, "web3_sha3 payload too large")
            }
            Ok(bytes) => rpc_ok(id, json!(format!("0x{}", hex::encode(keccak256(&bytes))))),
            Err(e) => rpc_err(id, ERR_PARAMS, &format!("invalid hex: {e}")),
        }
    }

    fn eth_syncing(&self, id: Value) -> Value {
        match self.refresh() {
            Ok(_) => rpc_ok(id, json!(false)),
            Err(_) => {
                let n = self
                    .chain
                    .lock()
                    .ok()
                    .and_then(|c| c.last().map(|b| b.number))
                    .unwrap_or(0);
                let hx = format!("0x{n:x}");
                rpc_ok(
                    id,
                    json!({
                        "startingBlock": hx,
                        "currentBlock": hx,
                        "highestBlock": hx,
                    }),
                )
            }
        }
    }

    fn status_fields(&self, tip: u64, safe: &SafeHead) -> Value {
        // One lock, three answers: whether a sealing set is enforced and, if the
        // snapshot carries a BEP-126 attestation, the justified/finalized pair.
        // `fast_finality_available` is false until the BLS vote keys are known — a
        // normal state at a checkpoint before the first epoch activation, not an error.
        let sealing = self.snapshot.lock().expect("snapshot lock").is_some();
        // One consistent sample published by `refresh` — never a fresh snapshot read, see
        // [`Node::finality`]. The caller's own `(tip, safe)` are only a fallback for the
        // window before any view has been published: a concurrent sync can publish a
        // newer one between a request's `refresh` and this read, and mixing the two is
        // how the head, its lag and its source end up describing different instants.
        let view = self.finality.lock().expect("finality lock").clone();
        let (fast_available, justified, finalized) =
            (view.available, view.justified, view.finalized);
        let finality_head = view.head;
        let safe = view.read_head.as_ref().unwrap_or(safe);
        let tip = if view.read_head.is_some() {
            view.head
        } else {
            tip
        };
        let lag = proof_lag(tip, safe.number);
        let interval_ms = mainnet_current_fork().block_interval_ms;
        // `safe` / `safeLagBlocks` / `lag` keep meaning confirmation depth; the
        // fast-finality fields are reported alongside them, not instead of them.
        json!({
            "trustClass": "verified",
            "finality": if finalized.is_some() { "fast-finality" } else { "confirmation-depth" },
            "forkId": self.fork_id,
            "tip": tip,
            "safe": safe.number,
            "safeHash": safe.hash,
            "lag": lag,
            "safeLagBlocks": lag,
            "safeLagSeconds": safe_lag_seconds(lag, interval_ms),
            "blockIntervalMs": interval_ms,
            "distinctSealers": safe.distinct_sealers,
            "requiredSealers": safe.required_sealers,
            "nSeal": mainnet_n_seal(),
            "proofWindow": PROVIDER_PROOF_LOOKBACK,
            "inProofWindow": within_proof_window(tip, safe.number),
            "sealingSetEnforced": sealing,
            "originCheckpoint": self.origin_checkpoint,
            "proofOk": self.proof_ok.load(Ordering::Relaxed),
            "proofFail": self.proof_fail.load(Ordering::Relaxed),
            "headersVerified": self.headers_verified.load(Ordering::Relaxed),
            "unverifiedPassthrough": self.allow_unverified_passthrough,
            "backupTransport": self.backup_transport,
            "expectedSafeLagBlocks": expected_safe_lag_blocks(),
            "safeLagWithinBound": safe_lag_within_slo(lag),
            "fastFinalityAvailable": fast_available,
            "justifiedBlock": justified.map(|(b, _)| b),
            "justifiedHash": justified.map(|(_, h)| format!("0x{}", hex::encode(h))),
            "finalizedBlock": finalized.map(|(b, _)| b),
            "finalizedHash": finalized.map(|(_, h)| format!("0x{}", hex::encode(h))),
            "finalizedLagBlocks": finalized.map(|(b, _)| proof_lag(finality_head, b)),
            "justifiedLagBlocks": justified.map(|(b, _)| proof_lag(finality_head, b)),
            "finalityHead": finality_head,
            // Which rule chose the head that `latest` / `safe` / `finalized` resolve to.
            // `distinctSealers` / `requiredSealers` always describe confirmation depth.
            "finalityMode": match self.finality_mode {
                FinalityMode::Fast => "fast",
                FinalityMode::ConfirmationDepth => "confirmation-depth",
            },
            "safeSource": if view.read_head_is_fast { "fast-finality" } else { "confirmation-depth" },
        })
    }

    fn verification_status(&self, id: Value) -> Value {
        match self.refresh() {
            Ok((tip, safe)) => rpc_ok(id, self.status_fields(tip, &safe)),
            Err(e) => rpc_err(id, ERR_NOT_SYNCED, &format!("not_synced: {e}")),
        }
    }
}

/// Non-empty `transactionsRoot` but the upstream served no raw envelopes: a count or an
/// index lookup has nothing verified to answer with.
const TX_ENVELOPES_UNAVAILABLE: &str =
    "proof_verification_failed: upstream served no transaction envelopes";

const MAX_LOG_DATA: usize = 64 * 1024;
const MAX_FEE_HISTORY_ITEMS: usize = 1024;
const MAX_GET_LOGS: usize = MAX_RECEIPT_LOGS;

/// Largest `eth_getLogs` span, in blocks.
///
/// This client keeps no log index, so every block in a range costs one upstream
/// `eth_getBlockReceipts` and one `receiptsRoot` verification. The cap is what stops a
/// single request from turning into an unbounded fan-out; it sits just above the
/// confirmation-depth window (~112), so any range a wallet could ask for over the blocks
/// this client can actually see is servable. Wider ranges are `-32602` and say why.
const MAX_GET_LOGS_RANGE: u64 = 128;

/// Live filters per process. Each is a few hundred bytes and an unauthenticated caller
/// can create them, so the count is bounded and the oldest idle one is dropped when the
/// cap is reached rather than letting a loopback client grow the map without limit.
const FILTER_ID_HEX: &str = "filter id must be a hex quantity";
const FILTER_NOT_FOUND: &str = "filter not found";
const WALLET_TAG_ONLY: &str = "wallet mode only serves Safe or below (latest→Safe)";

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(n: u64, marker: u8) -> VerifiedBlock {
        let mut hash = [0u8; 32];
        hash[31] = marker;
        let mut state_root = [0u8; 32];
        state_root[30] = marker;
        VerifiedBlock {
            number: n,
            hash,
            state_root,
            miner: [0u8; 20],
            ..Default::default()
        }
    }

    fn hash_hex(b: &VerifiedBlock) -> String {
        format!("0x{}", hex::encode(b.hash))
    }

    #[test]
    fn get_block_by_number_allows_safe_and_below_in_chain() {
        let chain = vec![blk(1, 1), blk(2, 2), blk(100, 100), blk(110, 110)];
        let safe_hash = hash_hex(&chain[2]);
        assert_eq!(
            wallet_get_block_by_number(Some("latest"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
        assert_eq!(
            wallet_get_block_by_number(Some("0x1"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(1)
        );
        assert_eq!(
            wallet_get_block_by_number(Some("0x64"), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
        assert!(wallet_get_block_by_number(Some("0x65"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("0x6e"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("0x3"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("pending"), 100, &safe_hash, &chain).is_none());
        assert!(wallet_get_block_by_number(Some("earliest"), 100, &safe_hash, &chain).is_none());
        assert_eq!(
            wallet_get_block_by_number(Some(&safe_hash), 100, &safe_hash, &chain).map(|b| b.number),
            Some(100)
        );
    }

    #[test]
    fn get_block_by_hash_only_verified_at_or_below_safe() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let h1 = hash_hex(&chain[0]);
        let h_safe = hash_hex(&chain[1]);
        let h_tip = hash_hex(&chain[2]);
        assert_eq!(
            wallet_get_block_by_hash(&h1, 100, &chain).map(|b| b.number),
            Some(1)
        );
        assert_eq!(
            wallet_get_block_by_hash(&h_safe, 100, &chain).map(|b| b.number),
            Some(100)
        );
        assert!(wallet_get_block_by_hash(&h_tip, 100, &chain).is_none());
        assert!(wallet_get_block_by_hash(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            100,
            &chain
        )
        .is_none());
    }

    fn load_fixture_header() -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet/header_116664000.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn header_mismatch_is_fail_closed() {
        let hdr = load_fixture_header();
        let local = VerifiedBlock {
            number: decode_u64(&hdr.number).unwrap(),
            hash: header_hash(&hdr).unwrap(),
            state_root: decode_hex_fixed::<32>(&hdr.state_root).unwrap(),
            miner: [0u8; 20],
            milli_timestamp: helios_bsc_consensus::milli_timestamp(&hdr).unwrap(),
            gas_limit: decode_u64(&hdr.gas_limit).unwrap(),
            header: Some(hdr.clone()),
        };
        assert!(header_matches_local(&hdr, &local).is_ok());
        let mut bad = hdr.clone();
        bad.number = "0x65".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_PROOF_FAILED
        );
        let mut bad = hdr.clone();
        bad.state_root =
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_STATE_ROOT
        );
        let mut bad = hdr.clone();
        bad.transactions_root =
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        assert_eq!(
            header_matches_local(&bad, &local).unwrap_err().0,
            ERR_PROOF_FAILED
        );
    }

    #[test]
    fn rpc_http_is_post_only_and_capped() {
        assert_eq!(rpc_http_reject(false, 16), Some(405));
        assert_eq!(rpc_http_reject(true, 16), None);
        assert_eq!(rpc_http_reject(true, MAX_RPC_BODY), None);
        assert_eq!(rpc_http_reject(true, MAX_RPC_BODY + 1), Some(413));
    }

    #[test]
    fn rpc_http_content_type_json_or_missing() {
        assert_eq!(rpc_http_content_type_reject(None), None);
        assert_eq!(rpc_http_content_type_reject(Some("")), None);
        assert_eq!(rpc_http_content_type_reject(Some("application/json")), None);
        assert_eq!(
            rpc_http_content_type_reject(Some("application/json; charset=utf-8")),
            None
        );
        assert_eq!(rpc_http_content_type_reject(Some("Application/JSON")), None);
        assert_eq!(
            rpc_http_content_type_reject(Some("application/json-rpc")),
            None
        );
        assert_eq!(rpc_http_content_type_reject(Some("text/html")), Some(415));
        assert_eq!(rpc_http_content_type_reject(Some("text/plain")), Some(415));
        assert_eq!(
            rpc_http_content_type_reject(Some("application/x-www-form-urlencoded")),
            Some(415)
        );
    }

    #[test]
    fn parse_slot_quantity_or_32_bytes_rejects_junk() {
        assert_eq!(parse_slot("0x0").unwrap(), [0u8; 32]);
        assert_eq!(parse_slot("0x1").unwrap()[31], 1);
        let full = format!("0x{}", "ab".repeat(32));
        assert!(parse_slot(&full).is_ok());
        assert!(parse_slot("not-hex").is_err());
        assert!(parse_slot("0xgg").is_err());
        assert!(parse_slot("").is_err());
        assert!(parse_slot(&format!("0x{}", "aa".repeat(33))).is_err());
        assert!(parse_storage_keys(Some(&json!([1]))).is_err());
        assert!(parse_storage_keys(Some(&json!("0x0"))).is_err());
        assert!(parse_storage_keys(Some(&json!(["0x0", "junk"]))).is_err());
        assert_eq!(parse_storage_keys(Some(&json!(["0x0"]))).unwrap().len(), 1);
        let too_many: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
            .map(|i| json!(format!("0x{i:x}")))
            .collect();
        assert!(parse_storage_keys(Some(&Value::Array(too_many))).is_err());
    }

    #[test]
    fn bind_mined_pending_ok_mined_above_safe_rejected() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        let pending = json!({"blockHash": Value::Null, "blockNumber": Value::Null});
        assert!(bind_mined_object(&pending, &safe, &chain, None).is_ok());
        let at_safe = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "status": "0x1",
        });
        assert!(bind_mined_object(&at_safe, &safe, &chain, None).is_ok());
        let at_zero = json!({
            "blockHash": hash_hex(&chain[0]),
            "blockNumber": "0x1",
        });
        assert!(bind_mined_object(&at_zero, &safe, &chain, None).is_ok());
        let above = json!({
            "blockHash": hash_hex(&chain[2]),
            "blockNumber": "0x6e",
        });
        let err = bind_mined_object(&above, &safe, &chain, None).unwrap_err();
        assert!(err.contains("above local Safe"), "{err}");
        let unknown = json!({
            "blockHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "blockNumber": "0x64",
        });
        assert!(bind_mined_object(&unknown, &safe, &chain, None).is_err());
        let bad_chain = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "chainId": "0x1",
        });
        let err = bind_mined_object(&bad_chain, &safe, &chain, None).unwrap_err();
        assert!(err.contains("chainId"), "{err}");
        let txh = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let want = decode_hex_fixed::<32>(txh).unwrap();
        let ok_chain = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "chainId": "0x38",
            "to": Value::Null,
            "transactionHash": txh,
        });
        assert!(bind_mined_object(&ok_chain, &safe, &chain, None).is_ok());
        assert!(bind_mined_object(&ok_chain, &safe, &chain, Some(&want)).is_ok());
        let other = [0xbbu8; 32];
        let err = bind_mined_object(&ok_chain, &safe, &chain, Some(&other)).unwrap_err();
        assert!(err.contains("does not match request"), "{err}");
        let pending_no_hash = json!({"blockHash": Value::Null, "blockNumber": Value::Null});
        let err = bind_mined_object(&pending_no_hash, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("hash missing"), "{err}");
        let bad_tx = json!({
            "blockHash": Value::Null,
            "blockNumber": Value::Null,
            "transactionHash": "0x01",
        });
        assert!(bind_mined_object(&bad_tx, &safe, &chain, None).is_err());
        let bad_status = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "status": "0x2",
        });
        let err = bind_mined_object(&bad_status, &safe, &chain, None).unwrap_err();
        assert!(err.contains("status"), "{err}");
        let bad_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{"address": "0x01"}],
        });
        let err = bind_mined_object(&bad_logs, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.address"), "{err}");
        let ok_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "topics": [txh],
            }],
        });
        assert!(bind_mined_object(&ok_logs, &safe, &chain, Some(&want)).is_ok());
        let bad_log_block = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "blockHash": hash_hex(&chain[0]),
            }],
        });
        let err = bind_mined_object(&bad_log_block, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.blockHash"), "{err}");
        let bad_data = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": [{
                "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": "0xgg",
            }],
        });
        let err = bind_mined_object(&bad_data, &safe, &chain, None).unwrap_err();
        assert!(err.contains("log.data"), "{err}");
        let bad_ty = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "type": "0x5",
        });
        let err = bind_mined_object(&bad_ty, &safe, &chain, None).unwrap_err();
        assert!(err.contains("type"), "{err}");
        let bad_gas = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "gasUsed": true,
        });
        let err = bind_mined_object(&bad_gas, &safe, &chain, None).unwrap_err();
        assert!(err.contains("gasUsed"), "{err}");
        let bad_contract = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "contractAddress": "0x01",
        });
        let err = bind_mined_object(&bad_contract, &safe, &chain, None).unwrap_err();
        assert!(err.contains("contractAddress"), "{err}");
        let huge_input = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "input": format!("0x{}", "aa".repeat(MAX_RAW_TX + 1)),
        });
        let err = bind_mined_object(&huge_input, &safe, &chain, None).unwrap_err();
        assert!(err.contains("input"), "{err}");
        let ok_input = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "input": "0xabcdef",
            "contractAddress": Value::Null,
        });
        assert!(bind_mined_object(&ok_input, &safe, &chain, None).is_ok());
        let bad_bloom = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logsBloom": "0x01",
        });
        let err = bind_mined_object(&bad_bloom, &safe, &chain, None).unwrap_err();
        assert!(err.contains("logsBloom"), "{err}");
    }

    #[test]
    fn bind_logs_txhash_topics_and_cap() {
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        let txh = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let want = decode_hex_fixed::<32>(txh).unwrap();
        let addr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let other = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let mismatch = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": addr,
                "transactionHash": other,
            }],
        });
        let err = bind_mined_object(&mismatch, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("log.transactionHash"), "{err}");
        let five: Vec<Value> = (0..5).map(|_| json!(txh)).collect();
        let too_topics = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "transactionHash": txh,
            "logs": [{
                "address": addr,
                "topics": five,
            }],
        });
        let err = bind_mined_object(&too_topics, &safe, &chain, Some(&want)).unwrap_err();
        assert!(err.contains("topics"), "{err}");
        let logs: Vec<Value> = (0..=MAX_RECEIPT_LOGS)
            .map(|_| json!({"address": addr}))
            .collect();
        let too_logs = json!({
            "blockHash": hash_hex(&chain[1]),
            "blockNumber": "0x64",
            "logs": logs,
        });
        let err = bind_mined_object(&too_logs, &safe, &chain, None).unwrap_err();
        assert!(err.contains("logs"), "{err}");
    }

    #[test]
    fn fee_history_caps_arrays() {
        assert!(bind_fee_result(
            "eth_feeHistory",
            &json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x1"]})
        )
        .is_ok());
        let too: Vec<Value> = (0..=MAX_FEE_HISTORY_ITEMS).map(|_| json!("0x1")).collect();
        let err = bind_fee_result(
            "eth_feeHistory",
            &json!({"oldestBlock": "0x1", "baseFeePerGas": too}),
        )
        .unwrap_err();
        assert!(err.contains("too many"), "{err}");
        let err = bind_fee_result("eth_feeHistory", &json!({"reward": [[true]]})).unwrap_err();
        assert!(err.contains("reward"), "{err}");
        assert!(
            bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": [0.5, "0.25", 1]})).is_ok()
        );
        for bad in [json!([true]), json!([{}]), json!([[0.1]]), json!([false])] {
            let err = bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": bad})).unwrap_err();
            assert!(err.contains("gasUsedRatio"), "{err}");
        }
        let too_ratio: Vec<Value> = (0..=MAX_FEE_HISTORY_ITEMS).map(|_| json!(0.5)).collect();
        let err =
            bind_fee_result("eth_feeHistory", &json!({"gasUsedRatio": too_ratio})).unwrap_err();
        assert!(err.contains("too many"), "{err}");
        let err = bind_fee_result("eth_unknownFee", &json!("0x1")).unwrap_err();
        assert!(err.contains("unknown"), "{err}");
        assert!(bind_fee_result("eth_feeHistory", &json!({"baseFeePerGas": ["0x1"]})).is_ok());
        let err = bind_fee_result("eth_feeHistory", &json!({"oldestBlock": "latest"})).unwrap_err();
        assert!(err.contains("oldestBlock"), "{err}");
        let chain = vec![blk(1, 1), blk(100, 100), blk(110, 110)];
        let safe = SafeHead {
            number: 100,
            hash: hash_hex(&chain[1]),
            state_root: format!("0x{}", hex::encode(chain[1].state_root)),
            distinct_sealers: 15,
            required_sealers: 15,
        };
        assert!(bind_fee_oldest_block(&json!({"baseFeePerGas": ["0x1"]}), &safe, &chain).is_ok());
        assert!(bind_fee_oldest_block(&json!({"oldestBlock": "0x64"}), &safe, &chain).is_ok());
        assert!(bind_fee_oldest_block(&json!({"oldestBlock": "0x1"}), &safe, &chain).is_ok());
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "0x6e"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_NOT_SYNCED, "{msg}");
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "0xff"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_NOT_SYNCED, "{msg}");
        let (code, msg) =
            bind_fee_oldest_block(&json!({"oldestBlock": "latest"}), &safe, &chain).unwrap_err();
        assert_eq!(code, ERR_PARAMS, "{msg}");
    }

    #[test]
    fn hydrated_block_txs_unsupported() {
        assert!(!wants_full_txs(None));
        assert!(!wants_full_txs(Some(&vec![json!("latest")])));
        assert!(!wants_full_txs(Some(&vec![json!("latest"), json!(false)])));
        assert!(wants_full_txs(Some(&vec![json!("latest"), json!(true)])));
    }

    #[test]
    fn call_error_rpc_revert_halt_are_execution_not_proof_failed() {
        use helios_bsc_execution::Miss;

        let (code, msg, data) = call_error_rpc(CallError::Revert(vec![0x08, 0xc3, 0x79, 0xa0]));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(code, 3);
        assert!(msg.starts_with("execution reverted"), "{msg}");
        assert!(!msg.contains("proof"), "{msg}");
        assert_eq!(data.as_deref(), Some("0x08c379a0"));

        let (code, msg, data) = call_error_rpc(CallError::Revert(vec![]));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution reverted");
        assert_eq!(data.as_deref(), Some("0x"));

        let mid = vec![0xab; REVERT_MSG_HEX_CAP + 1];
        let (code, msg, data) = call_error_rpc(CallError::Revert(mid.clone()));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution reverted");
        let want = format!("0x{}", hex::encode(&mid));
        assert_eq!(data.as_deref(), Some(want.as_str()));

        let big = vec![0xcd; REVERT_DATA_CAP + 8];
        let (code, msg, data) = call_error_rpc(CallError::Revert(big));
        assert_eq!(code, ERR_EXECUTION);
        assert!(msg.contains("truncated"), "{msg}");
        assert!(!msg.contains("proof"), "{msg}");
        let hex = data.expect("data");
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + REVERT_DATA_CAP * 2);

        let (code, msg, data) = call_error_rpc(CallError::Halt("out of gas"));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution_halt: out of gas");
        assert!(data.is_none());
        assert!(!msg.contains("proof"), "{msg}");

        let (code, msg, data) = call_error_rpc(CallError::Halt("precompile"));
        assert_eq!(code, ERR_EXECUTION);
        assert_eq!(msg, "execution_halt: precompile");
        assert!(data.is_none());

        let (code, msg, data) = call_error_rpc(CallError::Missing(Miss::Account([1u8; 20])));
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(msg.contains("proof_verification_failed"), "{msg}");
        assert!(data.is_none());

        let (code, _, data) = call_error_rpc(CallError::Budget);
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(data.is_none());

        let (code, _, data) = call_error_rpc(CallError::Proof(ProofError::Json("x".into())));
        assert_eq!(code, ERR_PROOF_FAILED);
        assert!(data.is_none());

        let (code, msg, data) = call_error_rpc(CallError::Invalid("calldata too large"));
        assert_eq!(code, ERR_PARAMS);
        assert_eq!(msg, "calldata too large");
        assert!(data.is_none());
    }

    fn sample_call_req(tx: Value) -> Value {
        json!({"params": [tx]})
    }

    #[test]
    fn parse_eth_call_tx_access_list() {
        let to = "0x0000000000000000000000000000000000000001";
        let omitted = parse_eth_call_tx(&sample_call_req(json!({"to": to}))).unwrap();
        assert!(omitted.access_list.is_empty());

        let with = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{
                "address": "0x0000000000000000000000000000000000000002",
                "storageKeys": ["0x0", "0x1"]
            }]
        })))
        .unwrap();
        assert_eq!(with.access_list.len(), 1);
        assert_eq!(with.access_list[0].0[19], 2);
        assert_eq!(with.access_list[0].1.len(), 2);
        assert_eq!(with.access_list[0].1[0], [0u8; 32]);

        let junk = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{"address": "not-an-address", "storageKeys": []}]
        })));
        assert!(junk.is_err(), "{junk:?}");

        let mut huge = Vec::new();
        for i in 0..=MAX_CALL_ACCOUNTS {
            huge.push(json!({
                "address": format!("0x{:040x}", i + 1),
                "storageKeys": []
            }));
        }
        let err =
            parse_eth_call_tx(&sample_call_req(json!({"to": to, "accessList": huge}))).unwrap_err();
        assert!(err.contains("accessList too large"), "{err}");

        let too_many_keys: Vec<Value> = (0..=MAX_PROOF_STORAGE_KEYS)
            .map(|i| json!(format!("0x{i:x}")))
            .collect();
        let err = parse_eth_call_tx(&sample_call_req(json!({
            "to": to,
            "accessList": [{"address": to, "storageKeys": too_many_keys}]
        })))
        .unwrap_err();
        assert!(err.contains("accessList too large"), "{err}");
    }
}
