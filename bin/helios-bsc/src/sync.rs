//! Header walk + newest-Safe from an untrusted upstream.

use crate::upstream::RpcUpstream;
use anyhow::{bail, Context, Result};
use helios_bsc_config::{mainnet_n_seal, max_reorg_depth, PROVIDER_PROOF_LOOKBACK};
use helios_bsc_consensus::{
    checkpoint_slo_label, header_matches_checkpoint, milli_timestamp, newest_safe, proof_lag,
    verify_cascading_vs_parent, verify_seal_coinbase, ConsensusError, LightEngine, Snapshot,
    VerifiedBlock,
};
use helios_bsc_types::{decode_hex_fixed, decode_u64, Checkpoint, RpcBlockHeader, SafeHead};
use std::time::{Duration, Instant};

/// `--require-checkpoint` fail-closed; otherwise warn that membership is off.
pub fn checkpoint_policy(require: bool, provided: bool) -> Result<()> {
    if require && !provided {
        bail!("--require-checkpoint needs --checkpoint (sealing-set membership)");
    }
    if !provided {
        eprintln!(
            "warning: no --checkpoint; sealing-set membership is NOT checked (sealingSetEnforced=false)"
        );
    }
    Ok(())
}

/// Consecutive number + parent-hash link against the previous verified block.
pub fn link_ok(prev: &VerifiedBlock, _hash: [u8; 32], parent: [u8; 32], number: u64) -> Result<()> {
    let got = number;
    let want = prev.number + 1;
    if got != want {
        bail!("non-consecutive header {got} after {want}");
    }
    if parent != prev.hash {
        bail!("parent_hash mismatch at {number}");
    }
    Ok(())
}

pub fn verify_header_chain(headers: &[RpcBlockHeader]) -> Result<Vec<VerifiedBlock>> {
    verify_header_chain_from(headers, None)
}

/// Verify seals and parent-links. `prev` is the last already-accepted block (append path).
pub fn verify_header_chain_from(
    headers: &[RpcBlockHeader],
    prev: Option<&VerifiedBlock>,
) -> Result<Vec<VerifiedBlock>> {
    let mut chain = Vec::with_capacity(headers.len());
    let mut parent_header: Option<&RpcBlockHeader> = None;
    for h in headers {
        let signer = verify_seal_coinbase(h).with_context(|| format!("seal {}", h.number))?;
        let number = decode_u64(&h.number)?;
        let hash = decode_hex_fixed::<32>(&h.hash)?;
        let parent = decode_hex_fixed::<32>(&h.parent_hash)?;
        let link_prev = chain.last().or(prev);
        if let Some(p) = link_prev {
            link_ok(p, hash, parent, number)?;
        }
        if let Some(ph) = parent_header {
            let p_milli = milli_timestamp(ph)?;
            let p_gas = decode_u64(&ph.gas_limit)?;
            verify_cascading_vs_parent(p_milli, p_gas, h)
                .with_context(|| format!("cascading {}", h.number))?;
        } else if let Some(p) = prev {
            verify_cascading_vs_parent(p.milli_timestamp, p.gas_limit, h)
                .with_context(|| format!("cascading {}", h.number))?;
        }
        chain.push(VerifiedBlock {
            number,
            hash,
            state_root: decode_hex_fixed::<32>(&h.state_root)?,
            miner: signer,
            milli_timestamp: milli_timestamp(h)?,
            gas_limit: decode_u64(&h.gas_limit)?,
            header: Some(h.clone()),
        });
        parent_header = Some(h);
    }
    Ok(chain)
}

pub fn walk_headers(up: &dyn RpcUpstream, from: u64, to: u64) -> Result<Vec<VerifiedBlock>> {
    let headers = up.headers_range(from, to)?;
    verify_header_chain(&headers)
}

/// Parent-link / consecutive-number failures — typically a 1-block reorg at tip.
pub fn is_link_err(err: &anyhow::Error) -> bool {
    let s = err.to_string().to_ascii_lowercase();
    s.contains("parent_hash mismatch")
        || s.contains("parent hash mismatch")
        || s.contains("non-consecutive header")
}

/// True if `new` shares a hash with `old` at a height within `depth` of `old`'s tip.
///
/// Lookback-only resync after a link break must not silently follow an unbounded
/// alternate window. Checkpoint replay is a different path (trusted origin).
pub fn reorg_within_depth(old: &[VerifiedBlock], new: &[VerifiedBlock], depth: u64) -> bool {
    if old.is_empty() || new.is_empty() {
        return true;
    }
    let old_tip = old.last().map(|b| b.number).unwrap_or(0);
    let min_n = old_tip.saturating_sub(depth);
    old.iter()
        .rev()
        .take_while(|b| b.number >= min_n)
        .any(|b| new.iter().any(|n| n.hash == b.hash && n.number == b.number))
}

pub fn accept_lookback_resync(
    old: &[VerifiedBlock],
    new: Vec<VerifiedBlock>,
) -> Result<Vec<VerifiedBlock>> {
    let depth = max_reorg_depth();
    if reorg_within_depth(old, &new, depth) {
        return Ok(new);
    }
    bail!("reorg deeper than {depth} blocks — fail-closed (pass --checkpoint)")
}

/// After a slow header walk the Safe block ages past the provider proof window.
/// Catch up to the live tip and recompute Safe before `eth_getProof`.
///
/// `lookback` is the no-checkpoint window. `max_sync` is how far a checkpoint
/// walk may trail the live tip (restart after downtime).
pub fn catch_up(
    up: &dyn RpcUpstream,
    chain: &mut Vec<VerifiedBlock>,
    lookback: u64,
    max_sync: u64,
    snapshot: Option<&mut Snapshot>,
) -> Result<u64> {
    let tip = up.block_number().context("eth_blockNumber catch-up")?;
    let last = chain.last().map(|b| b.number).unwrap_or(0);
    if snapshot.is_some() {
        if tip > last.saturating_add(max_sync) {
            bail!(
                "tip jumped {} blocks during walk; pass a fresh --checkpoint (max-sync {max_sync})",
                tip.saturating_sub(last)
            );
        }
        append_new_with_snapshot(up, chain, tip, snapshot)?;
    } else if tip > last.saturating_add(lookback) || chain.len() < 16 {
        let from = tip.saturating_sub(lookback.saturating_sub(1));
        *chain = walk_headers(up, from, tip)?;
    } else if let Err(e) = append_new(up, chain, tip) {
        if is_link_err(&e) {
            eprintln!(
                "reorg/link break ({e}); resync lookback (max reorg {depth})",
                depth = max_reorg_depth()
            );
            let from = tip.saturating_sub(lookback.saturating_sub(1));
            let walked = walk_headers(up, from, tip)?;
            *chain = accept_lookback_resync(chain, walked)?;
        } else {
            return Err(e);
        }
    }
    Ok(tip)
}

/// Keep catching up until newest-Safe is inside the provider proof window, or `timeout`.
///
/// Live Safe lag jitters ~106–112 vs Ankr ~108; a short wait often recovers a window
/// that a slow header walk just missed. Does **not** lower the 15-sealer threshold.
/// Head that reads resolve to under `--finality fast`, or `conf_safe` unchanged.
///
/// Single definition of the rule, shared by the RPC server and the soak so the soak
/// actually exercises the mode it is the gate for. Three conditions, all necessary:
///
/// * the snapshot must carry a BLS-finalized head at all (no vote keys ⇒ none),
/// * it must be **newer** than confirmation depth, so enabling fast finality can never
///   move reads backwards — both are complete finality rules, so the newer of the two is
///   final under at least one of them either way,
/// * and it must name a block **in the local verified chain**. An attestation pointing at
///   a block this client never walked is an upstream's word, not a head.
///
/// `distinct_sealers` / `required_sealers` are carried over from `conf_safe` on purpose:
/// they describe the confirmation-depth rule, and retyping them into vote counts would
/// silently change what those fields mean.
pub fn fast_finality_head(
    chain: &[VerifiedBlock],
    snapshot: Option<&Snapshot>,
    conf_safe: &SafeHead,
) -> SafeHead {
    let Some((number, hash)) = snapshot.and_then(Snapshot::finalized) else {
        return conf_safe.clone();
    };
    if number <= conf_safe.number {
        return conf_safe.clone();
    }
    let Some(block) = chain.iter().find(|b| b.number == number && b.hash == hash) else {
        return conf_safe.clone();
    };
    SafeHead {
        number: block.number,
        hash: format!("0x{}", hex::encode(block.hash)),
        state_root: format!("0x{}", hex::encode(block.state_root)),
        distinct_sealers: conf_safe.distinct_sealers,
        required_sealers: conf_safe.required_sealers,
    }
}

pub fn wait_until_in_window(
    up: &dyn RpcUpstream,
    chain: &mut Vec<VerifiedBlock>,
    lookback: u64,
    max_sync: u64,
    snapshot: Option<&mut Snapshot>,
    timeout: Duration,
) -> Result<(u64, SafeHead)> {
    wait_until_in_window_with(up, chain, lookback, max_sync, snapshot, timeout, false)
}

/// `fast` selects the BLS-finalized head when one is usable; see [`fast_finality_head`].
pub fn wait_until_in_window_with(
    up: &dyn RpcUpstream,
    chain: &mut Vec<VerifiedBlock>,
    lookback: u64,
    max_sync: u64,
    mut snapshot: Option<&mut Snapshot>,
    timeout: Duration,
    fast: bool,
) -> Result<(u64, SafeHead)> {
    let deadline = Instant::now() + timeout;
    loop {
        let tip = catch_up(up, chain, lookback, max_sync, snapshot.as_deref_mut())?;
        let conf_safe = safe_of(chain)?;
        let safe = if fast {
            fast_finality_head(chain, snapshot.as_deref(), &conf_safe)
        } else {
            conf_safe
        };
        let lag = proof_lag(tip, safe.number);
        if lag <= PROVIDER_PROOF_LOOKBACK {
            return Ok((tip, safe));
        }
        if Instant::now() >= deadline {
            bail!(
                "Safe lag {lag} > proof window {PROVIDER_PROOF_LOOKBACK} after {}s — swap RPC key",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(900));
    }
}

pub fn safe_of(chain: &[VerifiedBlock]) -> Result<SafeHead> {
    newest_safe(chain, mainnet_n_seal()).context("no Safe head in lookback")
}

pub fn append_new(
    up: &dyn RpcUpstream,
    chain: &mut Vec<VerifiedBlock>,
    new_tip: u64,
) -> Result<()> {
    append_new_with_snapshot(up, chain, new_tip, None)
}

pub fn append_new_with_snapshot(
    up: &dyn RpcUpstream,
    chain: &mut Vec<VerifiedBlock>,
    new_tip: u64,
    mut snapshot: Option<&mut Snapshot>,
) -> Result<()> {
    let last = chain.last().map(|b| b.number).unwrap_or(0);
    if new_tip <= last {
        return Ok(());
    }
    let headers = up.headers_range(last + 1, new_tip)?;
    if let Some(snap) = snapshot.as_mut() {
        for h in &headers {
            // Ordered before `apply_header`, which mutates the snapshot: a rejection
            // after it advanced would strand the snapshot one block ahead of `chain`,
            // and every later sync would fail the parent-link check for good. Same
            // ordering as `LightEngine::apply_header`.
            if let Some(prev) = chain.last() {
                verify_cascading_vs_parent(prev.milli_timestamp, prev.gas_limit, h)
                    .with_context(|| format!("cascading {}", h.number))?;
            }
            let signer = snap
                .apply_header(h)
                .with_context(|| format!("snapshot {}", h.number))?;
            chain.push(VerifiedBlock {
                number: decode_u64(&h.number)?,
                hash: decode_hex_fixed::<32>(&h.hash)?,
                state_root: decode_hex_fixed::<32>(&h.state_root)?,
                miner: signer,
                milli_timestamp: milli_timestamp(h)?,
                gas_limit: decode_u64(&h.gas_limit)?,
                header: Some(h.clone()),
            });
        }
    } else {
        let extra = verify_header_chain_from(&headers, chain.last())?;
        chain.extend(extra);
    }
    const KEEP: usize = 512;
    if chain.len() > KEEP {
        let drop = chain.len() - KEEP;
        chain.drain(0..drop);
    }
    Ok(())
}

/// Walk `checkpoint.number+1 ..= to` with sealing-set membership. Fails if the
/// checkpoint is more than `max_sync` blocks behind `to`.
pub fn walk_from_checkpoint(
    up: &dyn RpcUpstream,
    checkpoint: Checkpoint,
    to: u64,
    max_sync: u64,
) -> Result<(Vec<VerifiedBlock>, Snapshot)> {
    walk_from_checkpoint_inturn(up, checkpoint, to, max_sync, true)
}

/// Like [`walk_from_checkpoint`], but padded test sealing sets cannot match live in-turn.
pub fn walk_from_checkpoint_inturn(
    up: &dyn RpcUpstream,
    checkpoint: Checkpoint,
    to: u64,
    max_sync: u64,
    enforce_inturn: bool,
) -> Result<(Vec<VerifiedBlock>, Snapshot)> {
    let lag = to.saturating_sub(checkpoint.number);
    if lag > max_sync {
        return Err(ConsensusError::CheckpointTooFar {
            lag,
            limit: max_sync,
        }
        .into());
    }
    let header = up.header_by_number(checkpoint.number)?;
    let mut engine = LightEngine::from_checkpoint_and_header(checkpoint, &header)?;
    engine.snapshot.enforce_inturn = enforce_inturn;
    if to > engine.tip_number() {
        let headers = up.headers_range(engine.tip_number() + 1, to)?;
        engine.apply_headers(&headers)?;
    }
    Ok((engine.chain, engine.snapshot))
}

/// Host of an RPC URL (`https://rpc.ankr.com/bsc/KEY` → `rpc.ankr.com`).
pub fn rpc_host(url: &str) -> String {
    let s = url.trim().trim_end_matches('/');
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let hostport = rest.split('/').next().unwrap_or(rest);
    let host = hostport.split('@').next_back().unwrap_or(hostport);
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
}

/// Two URLs are independent iff their hosts differ (two Ankr keys are the same source).
pub fn independent_rpc_hosts(a: &str, b: &str) -> bool {
    let ha = rpc_host(a);
    let hb = rpc_host(b);
    !ha.is_empty() && !hb.is_empty() && ha != hb
}

/// Doctor line for a checkpoint file: age + n_seal, never the sealing-set list or keys.
pub fn doctor_checkpoint_line(path: &std::path::Path, now: u64) -> String {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("checkpoint.json");
    if !path.is_file() {
        return format!("{name}: absent");
    }
    let Ok(raw) = std::fs::read_to_string(path) else {
        return format!("{name}: present (unreadable)");
    };
    let Ok(cp) = serde_json::from_str::<Checkpoint>(&raw) else {
        return format!("{name}: present (invalid JSON)");
    };
    let age = now.saturating_sub(cp.timestamp);
    format!(
        "{name}: present number={} age={}s n_seal={} fork={} slo={}",
        cp.number,
        age,
        cp.sealing_set.len(),
        cp.fork_id,
        checkpoint_slo_label(age)
    )
}

/// Doctor line: `{VAR}: unset` or `{VAR}: host=example.com` (never the key).
pub fn env_host_line(var: &str, value: Option<&str>) -> String {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => format!("{var}: unset"),
        Some(v) => format!("{var}: host={}", rpc_host(v)),
    }
}

/// None if either URL is missing; otherwise OK / SAME HOST.
pub fn env_independence_line(label: &str, a: Option<&str>, b: Option<&str>) -> Option<String> {
    let a = a.map(str::trim).filter(|s| !s.is_empty())?;
    let b = b.map(str::trim).filter(|s| !s.is_empty())?;
    if independent_rpc_hosts(a, b) {
        Some(format!("{label}: independent OK"))
    } else {
        Some(format!("{label}: SAME HOST — fail-closed for that pair"))
    }
}

/// Second source must agree on checkpoint number / hash / parentHash / stateRoot.
pub fn confirm_checkpoint_with_oracle(
    checkpoint: &Checkpoint,
    oracle: &dyn RpcUpstream,
) -> Result<()> {
    let by_number = oracle
        .header_by_number(checkpoint.number)
        .context("checkpoint oracle eth_getBlockByNumber")?;
    header_matches_checkpoint(checkpoint, &by_number).context("checkpoint oracle (by number)")?;
    let by_hash = oracle
        .header_by_hash(&checkpoint.hash)
        .context("checkpoint oracle eth_getBlockByHash")?;
    header_matches_checkpoint(checkpoint, &by_hash).context("checkpoint oracle (by hash)")?;
    Ok(())
}

pub fn write_checkpoint_file(path: &std::path::Path, cp: &Checkpoint) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let json = serde_json::to_string_pretty(cp)?;
    atomic_write(path, json.as_bytes())
}

/// Write to a unique sibling temp file, flush it to disk, then rename over the target.
///
/// The temp name carries the pid and a per-process counter rather than being a fixed
/// `path.tmp`: two writers sharing one name can interleave a partial write with the other's
/// rename, which is exactly the truncated-checkpoint outcome the rename is meant to prevent.
///
/// There is deliberately **no `remove_file` before the rename**. It used to be there, and
/// it gave away the only property this function exists for: between the remove and the
/// rename the checkpoint did not exist at all, so a crash — or a failing rename — left the
/// operator with *no* trust anchor rather than a stale one. `std::fs::rename` replaces an
/// existing file on Windows too (std calls `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`),
/// verified on this platform, so the remove bought nothing.
///
/// `sync_all` before the rename matters for the same reason: without it the rename can
/// publish a name whose contents are still in the page cache, which is the truncated file
/// the temp-then-rename dance is supposed to rule out.
pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{}.{seq}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);

    let write_then_sync = || -> Result<()> {
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
        f.write_all(bytes)
            .with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("sync {tmp:?}"))?;
        Ok(())
    };
    if let Err(e) = write_then_sync() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Leave the previous checkpoint in place; drop our partial one.
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!("rename {tmp:?} → {path:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of temp-then-rename is that the target is *never* absent and never
    /// partial. An earlier version removed the target first, so a crash between the
    /// remove and the rename destroyed the operator's trust anchor outright.
    #[test]
    fn atomic_write_replaces_without_ever_unlinking() {
        let dir =
            std::env::temp_dir().join(format!("helios_atomic_{}_{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("checkpoint.json");

        atomic_write(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        // Replacing an existing file must succeed (this is the Windows-sensitive part:
        // `rename` has to overwrite, which is why the `remove_file` was there).
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        // No temp files survive a successful write.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");

        // A failing write leaves the previous checkpoint intact rather than no file.
        let unwritable = dir.join("nope").join("deep").join("checkpoint.json");
        assert!(atomic_write(&unwritable, b"third").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        std::fs::remove_dir_all(&dir).ok();
    }
    use serde_json::Value;
    use std::path::PathBuf;

    const FIXTURES: &[&str] = &[
        "header_116663998.json",
        "header_116663999.json",
        "header_116664000.json",
        "header_116664001.json",
        "header_116664002.json",
    ];

    fn load(name: &str) -> RpcBlockHeader {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/mainnet")
            .join(name);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&raw).expect("header json")
    }

    fn load_chain() -> Vec<RpcBlockHeader> {
        FIXTURES.iter().map(|n| load(n)).collect()
    }

    fn blk(n: u64, hash0: u8) -> VerifiedBlock {
        let mut hash = [0u8; 32];
        hash[0] = hash0;
        VerifiedBlock {
            number: n,
            hash,
            state_root: hash,
            miner: [0u8; 20],
            ..Default::default()
        }
    }

    #[test]
    fn fixture_chain_parent_links() {
        let headers = load_chain();
        let chain = verify_header_chain(&headers).expect("fixture chain");
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0].number, 116_663_998);
        assert_eq!(chain[4].number, 116_664_002);
        for w in chain.windows(2) {
            assert_eq!(w[1].number, w[0].number + 1);
        }
    }

    #[test]
    fn broken_parent_rejected() {
        let mut headers = load_chain();
        let mut parent = decode_hex_fixed::<32>(&headers[2].parent_hash).unwrap();
        parent[0] ^= 0x01;
        headers[2].parent_hash = format!("0x{}", hex::encode(parent));
        assert!(verify_header_chain(&headers).is_err());
    }

    #[test]
    fn gap_rejected() {
        let headers = load_chain();
        let gapped = [headers[0].clone(), headers[1].clone(), headers[3].clone()];
        let err = verify_header_chain(&gapped).unwrap_err().to_string();
        assert!(
            err.contains("non-consecutive header"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn link_ok_accepts_child() {
        let prev = blk(10, 0xaa);
        let mut hash = [0u8; 32];
        hash[0] = 0xbb;
        link_ok(&prev, hash, prev.hash, 11).unwrap();
    }

    #[test]
    fn link_ok_rejects_gap() {
        let prev = blk(10, 0xaa);
        let err = link_ok(&prev, [0u8; 32], prev.hash, 12)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "non-consecutive header 12 after 11");
    }

    #[test]
    fn link_ok_rejects_parent() {
        let prev = blk(10, 0xaa);
        let err = link_ok(&prev, [0u8; 32], [0u8; 32], 11)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "parent_hash mismatch at 11");
    }

    #[test]
    fn append_stitches_to_existing_chain() {
        let headers = load_chain();
        let prefix = verify_header_chain(&headers[..3]).unwrap();
        let extra = verify_header_chain_from(&headers[3..], prefix.last()).expect("stitch");
        assert_eq!(extra[0].number, prefix.last().unwrap().number + 1);
    }

    #[test]
    fn append_rejects_splice() {
        let headers = load_chain();
        let prefix = verify_header_chain(&headers[..2]).unwrap();
        // Skip header 2 — batch starts at header 3, parent ≠ prefix tip.
        assert!(verify_header_chain_from(&headers[3..], prefix.last()).is_err());
    }

    #[test]
    fn ankr_keys_are_same_host() {
        assert_eq!(
            rpc_host("https://rpc.ankr.com/bsc/aaaaaaaa"),
            "rpc.ankr.com"
        );
        assert_eq!(
            rpc_host("https://bsc-mainnet.public.blastapi.io"),
            "bsc-mainnet.public.blastapi.io"
        );
        assert!(!independent_rpc_hosts(
            "https://rpc.ankr.com/bsc/key1",
            "https://rpc.ankr.com/bsc/key2"
        ));
        assert!(independent_rpc_hosts(
            "https://rpc.ankr.com/bsc/key1",
            "https://bsc-mainnet.public.blastapi.io"
        ));
    }

    #[test]
    fn env_host_line_redacts_key() {
        let key = "https://rpc.ankr.com/bsc/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let line = env_host_line("HELIOS_BSC_UPSTREAM", Some(key));
        assert!(line.contains("rpc.ankr.com"));
        assert!(!line.contains("aaaaaaaa"));
        assert_eq!(
            env_host_line("HELIOS_BSC_ORACLE", None),
            "HELIOS_BSC_ORACLE: unset"
        );
        assert!(env_independence_line("soak", Some(key), Some(key))
            .unwrap()
            .contains("SAME HOST"));
        assert!(env_independence_line(
            "soak",
            Some(key),
            Some("https://bsc-mainnet.public.blastapi.io")
        )
        .unwrap()
        .contains("independent OK"));
    }

    #[test]
    fn checkpoint_policy_require_needs_file() {
        assert!(checkpoint_policy(true, false).is_err());
        assert!(checkpoint_policy(true, true).is_ok());
        assert!(checkpoint_policy(false, true).is_ok());
        assert!(checkpoint_policy(false, false).is_ok());
    }

    struct ReorgUp {
        tip: u64,
        honest: Vec<RpcBlockHeader>,
        lie_parent: bool,
    }

    impl crate::upstream::RpcUpstream for ReorgUp {
        fn block_number(&self) -> Result<u64> {
            Ok(self.tip)
        }
        fn header_by_number(&self, n: u64) -> Result<RpcBlockHeader> {
            self.honest
                .iter()
                .find(|h| decode_u64(&h.number).ok() == Some(n))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing {n}"))
        }
        fn header_by_hash(&self, hash: &str) -> Result<RpcBlockHeader> {
            self.honest
                .iter()
                .find(|h| h.hash.eq_ignore_ascii_case(hash))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing hash"))
        }
        fn headers_range(&self, from: u64, to: u64) -> Result<Vec<RpcBlockHeader>> {
            // First catch-up append: lie about parent so the stitch fails.
            if self.lie_parent && from == 116_664_001 {
                let mut h = self.honest[3].clone();
                h.parent_hash = format!("0x{}", hex::encode([0x11u8; 32]));
                return Ok(vec![h]);
            }
            Ok(self
                .honest
                .iter()
                .filter(|h| {
                    decode_u64(&h.number)
                        .ok()
                        .is_some_and(|n| n >= from && n <= to)
                })
                .cloned()
                .collect())
        }
        fn get_proof_keys(&self, _: &str, _: &[String], _: &str) -> Result<Value> {
            Err(anyhow::anyhow!("unused"))
        }
        fn get_balance(&self, _: &str, _: &str) -> Result<String> {
            Err(anyhow::anyhow!("unused"))
        }
        fn get_code(&self, _: &str, _: &str) -> Result<Vec<u8>> {
            Err(anyhow::anyhow!("unused"))
        }
        fn send_raw_transaction(&self, _: &str) -> Result<String> {
            Err(anyhow::anyhow!("unused"))
        }
        fn unverified_call(&self, _: &str, _: &Value) -> Result<Value> {
            Err(anyhow::anyhow!("unused"))
        }
    }

    #[test]
    fn catch_up_resyncs_lookback_after_parent_mismatch() {
        let honest = load_chain();
        let mut chain = verify_header_chain(&honest[..3]).unwrap();
        assert_eq!(chain.last().unwrap().number, 116_664_000);
        let up = ReorgUp {
            tip: 116_664_002,
            honest,
            lie_parent: true,
        };
        let tip = catch_up(&up, &mut chain, 5, 5, None).expect("resync");
        assert_eq!(tip, 116_664_002);
        assert_eq!(chain.first().unwrap().number, 116_663_998);
        assert_eq!(chain.last().unwrap().number, 116_664_002);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn catch_up_parent_break_no_overlap_fail_closed() {
        let honest = load_chain();
        let mut chain: Vec<_> = (0..21).map(|i| lite(116_663_980 + i, 0xff)).collect();
        assert_eq!(chain.last().unwrap().number, 116_664_000);
        let before = chain.clone();
        let up = ReorgUp {
            tip: 116_664_002,
            honest,
            lie_parent: false,
        };
        let err = catch_up(&up, &mut chain, 5, 5, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("21"), "{err}");
        assert_eq!(chain, before);
    }

    fn lite(n: u64, marker: u8) -> VerifiedBlock {
        let mut hash = [0u8; 32];
        hash[0] = marker;
        hash[7] = n as u8;
        VerifiedBlock {
            number: n,
            hash,
            state_root: hash,
            miner: [0u8; 20],
            ..Default::default()
        }
    }

    #[test]
    fn reorg_within_depth_requires_recent_hash_overlap() {
        let old: Vec<_> = (0..30).map(|i| lite(i, i as u8)).collect();
        let shallow: Vec<_> = (20..35).map(|i| lite(i, i as u8)).collect();
        assert!(reorg_within_depth(&old, &shallow, 21));
        let disjoint: Vec<_> = (20..35).map(|i| lite(i, 0xff)).collect();
        assert!(!reorg_within_depth(&old, &disjoint, 21));
        let deep_only: Vec<_> = (0..5).map(|i| lite(i, i as u8)).collect();
        assert!(!reorg_within_depth(&old, &deep_only, 21));
        assert!(reorg_within_depth(&[], &shallow, 21));
        let err = accept_lookback_resync(&old, disjoint)
            .unwrap_err()
            .to_string();
        assert!(err.contains("deeper than"), "{err}");
        assert!(err.contains("21"), "{err}");
    }

    #[test]
    fn wait_window_accepts_lag_at_lookback() {
        assert!(proof_lag(1000, 888) <= PROVIDER_PROOF_LOOKBACK);
        assert!(proof_lag(1000, 887) > PROVIDER_PROOF_LOOKBACK);
    }

    #[test]
    fn link_err_detects_parent_and_gap() {
        assert!(is_link_err(&anyhow::anyhow!("parent_hash mismatch at 12")));
        assert!(is_link_err(&anyhow::anyhow!("parent hash mismatch")));
        assert!(is_link_err(&anyhow::anyhow!(
            "non-consecutive header 12 after 11"
        )));
        assert!(!is_link_err(&anyhow::anyhow!("seal recovery failed")));
    }

    #[test]
    fn doctor_checkpoint_line_has_no_set_or_hash() {
        assert_eq!(
            doctor_checkpoint_line(std::path::Path::new("no-such-checkpoint.json"), 0),
            "no-such-checkpoint.json: absent"
        );
        let dir = std::env::temp_dir();
        let path = dir.join(format!("helios-bsc-doctor-cp-{}.json", std::process::id()));
        let secret_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cp = Checkpoint {
            chain_id: 56,
            number: 116_664_087,
            hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            parent_hash: "0xcc".into(),
            state_root: "0xdd".into(),
            timestamp: 1_000,
            fork_id: "fermi".into(),
            sealing_set: vec![secret_addr.into()],
            vote_keys: None,
            attestation: Some("do-not-print".into()),
        };
        std::fs::write(&path, serde_json::to_string(&cp).unwrap()).unwrap();
        let line = doctor_checkpoint_line(&path, 1_000 + 3600);
        let _ = std::fs::remove_file(&path);
        assert!(line.contains("present"));
        assert!(line.contains("number=116664087"));
        assert!(line.contains("age=3600s"));
        assert!(line.contains("n_seal=1"));
        assert!(line.contains("fork=fermi"));
        assert!(line.contains("slo=ok"));
        assert!(!line.contains("aaaaaaaa"));
        assert!(!line.contains("bbbbbbbb"));
        assert!(!line.contains("do-not-print"));
    }

    #[test]
    fn checkpoint_write_replaces_without_tmp() {
        let dir = std::env::temp_dir().join(format!("helios-bsc-atomic-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("checkpoint.json");
        let tmp = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".tmp");
            std::path::PathBuf::from(s)
        };
        let mut cp = Checkpoint {
            chain_id: 56,
            number: 1,
            hash: format!("0x{}", "aa".repeat(32)),
            parent_hash: format!("0x{}", "bb".repeat(32)),
            state_root: format!("0x{}", "cc".repeat(32)),
            timestamp: 1,
            fork_id: "fermi".into(),
            sealing_set: vec![format!("0x{}", "11".repeat(20))],
            vote_keys: None,
            attestation: None,
        };
        write_checkpoint_file(&path, &cp).unwrap();
        cp.number = 2;
        write_checkpoint_file(&path, &cp).unwrap();
        let loaded: Checkpoint =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.number, 2);
        assert!(!tmp.exists(), "tmp file left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
