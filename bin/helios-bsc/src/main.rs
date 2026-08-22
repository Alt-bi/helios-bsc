//! helios-bsc CLI — Parlia light client / verified local JSON-RPC.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use helios_bsc::bind::assert_listen_policy;
use helios_bsc::diff::{
    addr_key, diff_one, proof_error_retryable, rotate_front, soak_empty_burst, soak_list,
    soak_repeat_full_list, unmatched, DiffOutcome, DiffReport, SOAK_ADDRESSES,
};
use helios_bsc::rpc_server::{self, FinalityMode, Node};
use helios_bsc::sync::{
    checkpoint_policy, confirm_checkpoint_with_oracle, doctor_checkpoint_line, env_host_line,
    env_independence_line, independent_rpc_hosts, rpc_host, safe_of, wait_until_in_window,
    wait_until_in_window_with, walk_from_checkpoint, walk_headers, write_checkpoint_file,
};
use helios_bsc::upstream::{open_data_plane, RpcUpstream, Upstream};
use helios_bsc_config::{
    expected_safe_lag_blocks, expected_safe_lag_seconds, mainnet_current_fork,
    mainnet_min_distinct_sealers, mainnet_n_seal, miner_history_check_len, params_at,
    pasteur_status_line, BSC_UPSTREAM_COMMIT, BSC_UPSTREAM_TAG, DEFAULT_LOOKBACK, DEFAULT_MAX_SYNC,
    PROVIDER_PROOF_LOOKBACK,
};
use helios_bsc_consensus::{
    assert_checkpoint_age, checkpoint_at_snapshot, proof_lag, sealing_set_from_activated_epoch,
    vote_keys_from_activated_epoch, within_proof_window, CHECKPOINT_WARN_AGE_SECS,
};
use helios_bsc_execution::{verify_eth_get_proof, EthAccountProof};
use helios_bsc_types::{decode_hex_fixed, decode_u64, Checkpoint, RpcBlockHeader};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::info;

const WBNB: &str = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";

#[derive(Parser, Debug)]
#[command(
    name = "helios-bsc",
    about = "Trust-minimized BSC (Parlia) light client — local verified JSON-RPC",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

/// `--finality` on `run`. Mirrors [`FinalityMode`]; kept separate so the CLI surface is
/// not tied to an internal type's naming.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum FinalityArg {
    ConfirmationDepth,
    Fast,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print build / network parameter summary.
    Info,
    /// Env + host check (does not print API keys).
    Doctor,
    /// Walk recent headers, compute newest Safe, verify eth_getProof via MPT.
    ProbeSafe {
        #[arg(long, env = "HELIOS_BSC_UPSTREAM")]
        upstream: String,
        #[arg(long, default_value_t = DEFAULT_LOOKBACK)]
        lookback: u64,
        /// Max blocks from --checkpoint to tip (restart after downtime). Default ~2 h.
        #[arg(long, default_value_t = DEFAULT_MAX_SYNC)]
        max_sync: u64,
        #[arg(long, default_value = WBNB)]
        address: String,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long, default_value_t = 24)]
        max_checkpoint_age_hours: u64,
        #[arg(long)]
        allow_stale_checkpoint: bool,
        /// Persist last verified header here (default: --checkpoint path).
        #[arg(long)]
        checkpoint_store: Option<PathBuf>,
        #[arg(long)]
        no_checkpoint_store: bool,
        /// Second RPC for checkpoint hash/number/stateRoot (env HELIOS_BSC_CHECKPOINT_ORACLE).
        #[arg(long, env = "HELIOS_BSC_CHECKPOINT_ORACLE")]
        checkpoint_oracle: Option<String>,
        #[arg(long)]
        require_multisource_checkpoint: bool,
        #[arg(long)]
        require_checkpoint: bool,
        /// Independent oracle for balance soak at Safe (env HELIOS_BSC_ORACLE). Must ≠ upstream host.
        #[arg(long, env = "HELIOS_BSC_ORACLE")]
        oracle: Option<String>,
        /// Transport failover if primary RPC errors (env HELIOS_BSC_BACKUP). Not an oracle.
        #[arg(long, env = "HELIOS_BSC_BACKUP")]
        backup: Option<String>,
    },
    /// Sync headers and serve verified JSON-RPC (wallet mode: latest → Safe).
    Run {
        #[arg(long, env = "HELIOS_BSC_UPSTREAM")]
        upstream: String,
        /// Transport failover if primary RPC errors (env HELIOS_BSC_BACKUP). Not an oracle.
        #[arg(long, env = "HELIOS_BSC_BACKUP")]
        backup: Option<String>,
        #[arg(long, default_value = "127.0.0.1:8545")]
        listen: String,
        #[arg(long, default_value_t = DEFAULT_LOOKBACK)]
        lookback: u64,
        #[arg(long, default_value_t = DEFAULT_MAX_SYNC)]
        max_sync: u64,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long, default_value_t = 24)]
        max_checkpoint_age_hours: u64,
        #[arg(long)]
        allow_stale_checkpoint: bool,
        /// Persist last verified header here (default: --checkpoint path).
        #[arg(long)]
        checkpoint_store: Option<PathBuf>,
        #[arg(long)]
        no_checkpoint_store: bool,
        /// Second RPC for checkpoint hash/number/stateRoot (env HELIOS_BSC_CHECKPOINT_ORACLE).
        #[arg(long, env = "HELIOS_BSC_CHECKPOINT_ORACLE")]
        checkpoint_oracle: Option<String>,
        #[arg(long)]
        require_multisource_checkpoint: bool,
        #[arg(long)]
        require_checkpoint: bool,
        /// Permit a non-loopback bind (no in-process RPC auth; use firewall + proxy).
        #[arg(long)]
        allow_non_loopback: bool,
        /// Opt-in: receipts/txs header-bound to Safe; gasPrice / feeHistory / maxPriorityFeePerGas unbound.
        #[arg(long)]
        allow_unverified_passthrough: bool,
        /// Serve Prometheus metrics on `GET /metrics` (same bind; off by default).
        #[arg(long)]
        metrics: bool,
        /// Which finality rule `latest` / `safe` / `finalized` resolve to.
        ///
        /// `confirmation-depth` (default) is ~106–113 blocks behind the tip. `fast` uses
        /// the BEP-126 BLS-finalized head, ~2 blocks behind, and falls back to
        /// confirmation depth whenever no finalized head is known — for instance from a
        /// checkpoint without BLS vote keys. Opt-in until the ≥24h soak covers it.
        #[arg(long, value_enum, default_value_t = FinalityArg::ConfirmationDepth)]
        finality: FinalityArg,
    },
    /// Write a checkpoint JSON from a trusted header + operator sealing set.
    WriteCheckpoint {
        #[arg(long, env = "HELIOS_BSC_UPSTREAM")]
        upstream: String,
        /// Block number hex (`0x…`) or `latest`.
        #[arg(long)]
        block: String,
        /// Comma-separated sealing-set addresses (do not invent from recent miners).
        #[arg(long)]
        sealing_set: Option<String>,
        /// Epoch block whose extraData is the *next* set. Only after minerHistoryCheckLen at --block.
        #[arg(long)]
        sealing_set_from_epoch: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Loop MPT-verified balances vs an independent oracle at Safe (no local RPC server).
    Soak {
        #[arg(long, env = "HELIOS_BSC_UPSTREAM")]
        upstream: String,
        /// Transport failover if primary RPC errors (env HELIOS_BSC_BACKUP). Not an oracle.
        #[arg(long, env = "HELIOS_BSC_BACKUP")]
        backup: Option<String>,
        /// Independent oracle (env HELIOS_BSC_ORACLE). Must be a different host.
        #[arg(long, env = "HELIOS_BSC_ORACLE")]
        oracle: String,
        #[arg(long, default_value_t = DEFAULT_LOOKBACK)]
        lookback: u64,
        #[arg(long, default_value_t = DEFAULT_MAX_SYNC)]
        max_sync: u64,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long, default_value_t = 24)]
        max_checkpoint_age_hours: u64,
        #[arg(long)]
        allow_stale_checkpoint: bool,
        #[arg(long, env = "HELIOS_BSC_CHECKPOINT_ORACLE")]
        checkpoint_oracle: Option<String>,
        #[arg(long)]
        require_multisource_checkpoint: bool,
        #[arg(long)]
        require_checkpoint: bool,
        #[arg(long, default_value_t = 4)]
        rounds: u32,
        /// Seconds between rounds.
        #[arg(long, default_value_t = 30.0)]
        interval: f64,
        #[arg(long)]
        once: bool,
        /// Demo Slice gate: unique MPT↔oracle matches required (default 10).
        #[arg(long, default_value_t = 10)]
        min_unique: u32,
        /// eth_getProof calls per burst (Ankr free ~3 then prune).
        #[arg(long, default_value_t = 2)]
        burst: usize,
        /// Seconds to wait after a burst so the provider window recovers.
        #[arg(long, default_value_t = 8.0)]
        pause: f64,
        /// If >0, keep soaking until this many seconds (1h = 3600) even after min-unique.
        #[arg(long, default_value_t = 0)]
        duration_secs: u64,
        /// Which head to soak: confirmation depth (default) or the BEP-126 BLS
        /// finalized head that `run --finality fast` serves.
        #[arg(long, value_enum, default_value_t = FinalityArg::ConfirmationDepth)]
        finality: FinalityArg,
    },
    /// Check a checkpoint file against upstream (and optional oracle). No header walk.
    VerifyCheckpoint {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long, env = "HELIOS_BSC_UPSTREAM")]
        upstream: String,
        #[arg(long, default_value_t = 24)]
        max_checkpoint_age_hours: u64,
        #[arg(long)]
        allow_stale_checkpoint: bool,
        #[arg(long, env = "HELIOS_BSC_CHECKPOINT_ORACLE")]
        checkpoint_oracle: Option<String>,
        #[arg(long)]
        require_multisource_checkpoint: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Commands::Info => print_info(),
        Commands::Doctor => doctor(),
        Commands::ProbeSafe {
            upstream,
            lookback,
            max_sync,
            address,
            checkpoint,
            max_checkpoint_age_hours,
            allow_stale_checkpoint,
            checkpoint_store,
            no_checkpoint_store,
            checkpoint_oracle,
            require_multisource_checkpoint,
            require_checkpoint,
            oracle,
            backup,
        } => probe_safe(ProbeSafeArgs {
            url: &upstream,
            lookback,
            max_sync,
            address: &address,
            checkpoint: checkpoint.as_deref(),
            max_age_hours: max_checkpoint_age_hours,
            allow_stale: allow_stale_checkpoint,
            store: store_path(checkpoint.as_ref(), checkpoint_store, no_checkpoint_store),
            oracle_url: checkpoint_oracle.as_deref(),
            require_multisource: require_multisource_checkpoint,
            soak_oracle: oracle.as_deref(),
            require_checkpoint,
            backup: backup.as_deref(),
        }),
        Commands::Run {
            upstream,
            backup,
            listen,
            lookback,
            max_sync,
            checkpoint,
            max_checkpoint_age_hours,
            allow_stale_checkpoint,
            checkpoint_store,
            no_checkpoint_store,
            checkpoint_oracle,
            require_multisource_checkpoint,
            require_checkpoint,
            allow_non_loopback,
            allow_unverified_passthrough,
            metrics,
            finality,
        } => {
            info!(%listen, lookback, max_sync, "starting verified RPC");
            assert_listen_policy(&listen, allow_non_loopback)?;
            checkpoint_policy(require_checkpoint, checkpoint.is_some())?;
            let store = store_path(checkpoint.as_ref(), checkpoint_store, no_checkpoint_store);
            let has_backup = backup.as_deref().is_some_and(|s| !s.trim().is_empty());
            let mut node = if let Some(path) = checkpoint {
                let cp = load_checkpoint(&path, max_checkpoint_age_hours, allow_stale_checkpoint)?;
                confirm_loaded_checkpoint(
                    &cp,
                    Some(path.as_path()),
                    &upstream,
                    checkpoint_oracle.as_deref(),
                    require_multisource_checkpoint,
                )?;
                if let Some(b) = backup.as_deref() {
                    eprintln!("data-plane backup {}", rpc_host(b));
                }
                let up = open_data_plane(upstream, backup);
                Node::bootstrap_from_checkpoint(up, lookback, max_sync, cp)?
            } else {
                if require_multisource_checkpoint {
                    bail!("--require-multisource-checkpoint needs --checkpoint");
                }
                if let Some(b) = backup.as_deref() {
                    eprintln!("data-plane backup {}", rpc_host(b));
                }
                let up = open_data_plane(upstream, backup);
                Node::bootstrap(up, lookback)?
            };
            if let Some(path) = store {
                node.set_checkpoint_store(path);
                node.persist_verified_tip();
            }
            if allow_unverified_passthrough {
                node.set_allow_unverified_passthrough(true);
            }
            if has_backup {
                node.set_backup_transport(true);
            }
            if metrics {
                node.set_metrics_enabled(true);
                eprintln!("metrics on http://{listen}/metrics");
            }
            if finality == FinalityArg::Fast {
                node.set_finality_mode(FinalityMode::Fast);
                eprintln!(
                    "finality: fast (BEP-126 BLS); falls back to confirmation depth \
                     when no finalized head is known"
                );
            }
            rpc_server::serve(Arc::new(node), &listen)
        }
        Commands::WriteCheckpoint {
            upstream,
            block,
            sealing_set,
            sealing_set_from_epoch,
            out,
        } => write_checkpoint(
            &upstream,
            &block,
            sealing_set.as_deref(),
            sealing_set_from_epoch.as_deref(),
            &out,
        ),
        Commands::Soak {
            upstream,
            backup,
            oracle,
            lookback,
            max_sync,
            checkpoint,
            max_checkpoint_age_hours,
            allow_stale_checkpoint,
            checkpoint_oracle,
            require_multisource_checkpoint,
            require_checkpoint,
            rounds,
            interval,
            once,
            min_unique,
            burst,
            pause,
            duration_secs,
            finality,
        } => soak(SoakArgs {
            upstream: &upstream,
            backup: backup.as_deref(),
            oracle: &oracle,
            lookback,
            max_sync,
            checkpoint: checkpoint.as_deref(),
            max_age_hours: max_checkpoint_age_hours,
            allow_stale: allow_stale_checkpoint,
            checkpoint_oracle: checkpoint_oracle.as_deref(),
            require_multisource: require_multisource_checkpoint,
            require_checkpoint,
            rounds: if once { 1 } else { rounds },
            interval,
            min_unique,
            burst,
            pause,
            duration_secs,
            fast_finality: finality == FinalityArg::Fast,
        }),
        Commands::VerifyCheckpoint {
            checkpoint,
            upstream,
            max_checkpoint_age_hours,
            allow_stale_checkpoint,
            checkpoint_oracle,
            require_multisource_checkpoint,
        } => verify_checkpoint(
            &checkpoint,
            &upstream,
            max_checkpoint_age_hours,
            allow_stale_checkpoint,
            checkpoint_oracle.as_deref(),
            require_multisource_checkpoint,
        ),
    }
}

fn print_info() -> Result<()> {
    let fork = mainnet_current_fork();
    let live = params_at(0, now_unix());
    println!("helios-bsc {}", env!("CARGO_PKG_VERSION"));
    println!("status:       Demo Slice (probe-safe + local RPC)");
    println!("chain_id:     56 (BSC mainnet)");
    println!(
        "upstream_pin: bnb-chain/bsc {} ({})",
        BSC_UPSTREAM_TAG,
        &BSC_UPSTREAM_COMMIT[..12]
    );
    println!("fork_profile: {} (pin)", fork.name);
    println!("live_fork:    {}", live.name);
    println!("{}", pasteur_status_line(now_unix()));
    println!(
        "epoch_length: {} (post-Maxwell; not legacy 200)",
        fork.epoch_length
    );
    println!("turn_length:  {}", fork.turn_length);
    println!("block_time_ms:{}", fork.block_interval_ms);
    println!("N_seal:       {}", mainnet_n_seal());
    println!(
        "min_sealers:  {} (floor(2N/3)+1)",
        mainnet_min_distinct_sealers()
    );
    println!(
        "epoch_delay:  {} blocks (minerHistoryCheckLen)",
        miner_history_check_len(mainnet_n_seal(), fork.turn_length)
    );
    println!(
        "safe_lag_est: ~{} blocks / ~{}s in-turn upper (live ~108–112)",
        expected_safe_lag_blocks(),
        expected_safe_lag_seconds()
    );
    println!(
        "proof_window: {} blocks (Ankr free; swap key if proofs fail)",
        PROVIDER_PROOF_LOOKBACK
    );
    println!(
        "max_sync:     {DEFAULT_MAX_SYNC} blocks (~2h) from --checkpoint to tip; lookback {DEFAULT_LOOKBACK} without checkpoint"
    );
    println!(
        "checkpoint:   --checkpoint FILE; --require-multisource-checkpoint + --checkpoint-oracle"
    );
    println!(
        "soak:         soak --oracle URL [--min-unique 10] [--duration-secs 3600]  (MPT vs independent host)"
    );
    println!(
        "verify:       verify-checkpoint --checkpoint FILE [--require-multisource-checkpoint]"
    );
    println!("membership:   --require-checkpoint  (fail if no --checkpoint file)");
    println!(
        "write-cp:     write-checkpoint --sealing-set … or --sealing-set-from-epoch (activated extraData)"
    );
    println!("bind:         127.0.0.1:8545 default; --allow-non-loopback for LAN (no RPC auth)");
    println!(
        "unverified:   run --allow-unverified-passthrough  (receipts header-bound to Safe; gasPrice unbound)"
    );
    println!("doctor:       helios-bsc doctor  (env hosts, no keys)");
    println!("design:       docs/design.md");
    println!("phase0:       docs/phase0-checklist.md");
    Ok(())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

fn doctor() -> Result<()> {
    print_info()?;
    println!("--- env (hosts only) ---");
    let up = env_opt("HELIOS_BSC_UPSTREAM");
    let oracle = env_opt("HELIOS_BSC_ORACLE");
    let ckpt = env_opt("HELIOS_BSC_CHECKPOINT_ORACLE");
    let backup = env_opt("HELIOS_BSC_BACKUP");
    println!("{}", env_host_line("HELIOS_BSC_UPSTREAM", up.as_deref()));
    println!("{}", env_host_line("HELIOS_BSC_BACKUP", backup.as_deref()));
    println!("{}", env_host_line("HELIOS_BSC_ORACLE", oracle.as_deref()));
    println!(
        "{}",
        env_host_line("HELIOS_BSC_CHECKPOINT_ORACLE", ckpt.as_deref())
    );
    if let Some(line) = env_independence_line("soak pair", up.as_deref(), oracle.as_deref()) {
        println!("{line}");
    }
    if let Some(line) = env_independence_line("checkpoint pair", up.as_deref(), ckpt.as_deref()) {
        println!("{line}");
    }
    println!(
        "{}",
        doctor_checkpoint_line(std::path::Path::new("checkpoint.json"), now_unix())
    );
    println!("doctor:      done (keys never printed)");
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn store_path(
    checkpoint: Option<&PathBuf>,
    checkpoint_store: Option<PathBuf>,
    no_store: bool,
) -> Option<PathBuf> {
    if no_store {
        None
    } else {
        checkpoint_store.or_else(|| checkpoint.cloned())
    }
}

fn load_checkpoint(
    path: &std::path::Path,
    max_age_hours: u64,
    allow_stale: bool,
) -> Result<Checkpoint> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
    let cp: Checkpoint = serde_json::from_str(&raw).context("checkpoint JSON")?;
    cp.validate_basic().context("checkpoint")?;
    let max_secs = max_age_hours.saturating_mul(3600);
    let age = checkpoint_age_secs(cp.timestamp, now_unix());
    if age > CHECKPOINT_WARN_AGE_SECS {
        eprintln!("checkpoint age {age}s (>6h) — prefer a fresher root of trust");
    }
    if let Err(e) = assert_checkpoint_age(cp.timestamp, now_unix(), max_secs) {
        if allow_stale {
            eprintln!("allowing stale checkpoint: {e}");
        } else {
            return Err(e.into());
        }
    }
    Ok(cp)
}

fn confirm_loaded_checkpoint(
    cp: &Checkpoint,
    checkpoint_path: Option<&std::path::Path>,
    upstream: &str,
    oracle_url: Option<&str>,
    require: bool,
) -> Result<()> {
    if require {
        if checkpoint_path.is_none() {
            bail!("--require-multisource-checkpoint needs --checkpoint");
        }
        let Some(url) = oracle_url.filter(|u| !u.trim().is_empty()) else {
            bail!(
                "--require-multisource-checkpoint needs --checkpoint-oracle / HELIOS_BSC_CHECKPOINT_ORACLE"
            );
        };
        if !independent_rpc_hosts(upstream, url) {
            bail!(
                "checkpoint oracle must be a different host than upstream (both {})",
                rpc_host(url)
            );
        }
        confirm_checkpoint_with_oracle(cp, &Upstream::new(url))?;
        eprintln!("checkpoint oracle OK ({})", rpc_host(url));
        return Ok(());
    }
    if let Some(url) = oracle_url.filter(|u| !u.trim().is_empty()) {
        if !independent_rpc_hosts(upstream, url) {
            eprintln!(
                "ignoring --checkpoint-oracle: same host as upstream ({})",
                rpc_host(url)
            );
            return Ok(());
        }
        confirm_checkpoint_with_oracle(cp, &Upstream::new(url))?;
        eprintln!("checkpoint oracle OK ({})", rpc_host(url));
    }
    Ok(())
}

fn checkpoint_age_secs(timestamp: u64, now: u64) -> u64 {
    helios_bsc_consensus::checkpoint_age_secs(timestamp, now)
}

fn parse_sealing_set(s: &str) -> Result<Vec<String>> {
    let set: Vec<String> = s
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    if set.is_empty() {
        bail!("sealing-set is empty — pass comma-separated validator addresses");
    }
    for a in &set {
        decode_hex_fixed::<20>(a).with_context(|| format!("sealing-set address {a}"))?;
    }
    Ok(set)
}

fn fetch_header(up: &Upstream, block: &str) -> Result<RpcBlockHeader> {
    if block.eq_ignore_ascii_case("latest") {
        let n = up.block_number()?;
        return up.header_by_number(n);
    }
    let n = u64::from_str_radix(block.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .context("block number")?;
    up.header_by_number(n)
}

fn write_checkpoint(
    url: &str,
    block: &str,
    sealing_set: Option<&str>,
    sealing_set_from_epoch: Option<&str>,
    out: &std::path::Path,
) -> Result<()> {
    let up = Upstream::new(url);
    let header = fetch_header(&up, block)?;
    let number = decode_u64(&header.number)?;
    let timestamp = decode_u64(&header.timestamp)?;
    // Vote keys only ever come from an activated epoch's extraData, never from an
    // operator-supplied address list — so `--sealing-set` yields a checkpoint that runs
    // confirmation-depth until the client sees an epoch header for itself.
    let mut vote_keys: Option<Vec<String>> = None;
    let set = match (sealing_set, sealing_set_from_epoch) {
        (Some(s), None) => parse_sealing_set(s)?,
        (None, Some(epoch_id)) => {
            let epoch_header = fetch_header(&up, epoch_id)?;
            vote_keys = Some(vote_keys_from_activated_epoch(&epoch_header, number)?);
            sealing_set_from_activated_epoch(&epoch_header, number)?
        }
        (Some(_), Some(_)) => {
            bail!("pass either --sealing-set or --sealing-set-from-epoch, not both")
        }
        (None, None) => bail!(
            "need --sealing-set (operator addresses) or --sealing-set-from-epoch (activated epoch extraData, not miners)"
        ),
    };
    let fork = params_at(number, timestamp);
    let attestation = if sealing_set_from_epoch.is_some() {
        Some("helios-bsc write-checkpoint from activated epoch extraData".into())
    } else {
        Some("helios-bsc write-checkpoint".into())
    };
    let cp = Checkpoint::from_rpc_header(&header, set, fork.name, attestation)?;
    let cp = match vote_keys {
        Some(keys) => cp.with_vote_keys(keys),
        None => cp,
    };
    cp.validate_basic()?;
    write_checkpoint_file(out, &cp)?;
    println!(
        "wrote checkpoint {} hash={} n_seal={} fork={} fastFinality={}",
        cp.number,
        cp.hash,
        cp.sealing_set.len(),
        cp.fork_id,
        if cp.vote_keys.is_some() { "yes" } else { "no" }
    );
    Ok(())
}

struct ProbeSafeArgs<'a> {
    url: &'a str,
    backup: Option<&'a str>,
    lookback: u64,
    max_sync: u64,
    address: &'a str,
    checkpoint: Option<&'a std::path::Path>,
    max_age_hours: u64,
    allow_stale: bool,
    store: Option<PathBuf>,
    oracle_url: Option<&'a str>,
    require_multisource: bool,
    soak_oracle: Option<&'a str>,
    require_checkpoint: bool,
}

fn probe_safe(args: ProbeSafeArgs<'_>) -> Result<()> {
    let ProbeSafeArgs {
        url,
        lookback,
        max_sync,
        address,
        checkpoint,
        max_age_hours,
        allow_stale,
        store,
        oracle_url,
        require_multisource,
        soak_oracle,
        require_checkpoint,
        backup,
    } = args;
    checkpoint_policy(require_checkpoint, checkpoint.is_some())?;
    let store = store.as_deref();
    if let Some(b) = backup {
        eprintln!("data-plane backup {}", rpc_host(b));
    }
    let up = open_data_plane(url, backup.map(str::to_string));
    let tip0 = up.block_number().context("eth_blockNumber")?;
    let mut snap_hold = None;
    let mut chain = if let Some(path) = checkpoint {
        let cp = load_checkpoint(path, max_age_hours, allow_stale)?;
        confirm_loaded_checkpoint(&cp, Some(path), url, oracle_url, require_multisource)?;
        eprintln!("sync from checkpoint {} ..= {tip0}", cp.number);
        let fork = cp.fork_id.clone();
        let (chain, snap) = walk_from_checkpoint(up.as_ref(), cp, tip0, max_sync)?;
        snap_hold = Some((snap, fork));
        chain
    } else {
        if require_multisource {
            bail!("--require-multisource-checkpoint needs --checkpoint");
        }
        let from = tip0.saturating_sub(lookback.saturating_sub(1));
        eprintln!(
            "fetching headers {from}..={tip0} (no checkpoint: sealing-set membership not checked)"
        );
        walk_headers(up.as_ref(), from, tip0)?
    };
    let (tip, _) = wait_until_in_window(
        up.as_ref(),
        &mut chain,
        lookback,
        max_sync,
        snap_hold.as_mut().map(|(s, _)| s),
        Duration::from_secs(25),
    )?;
    if let (Some(store_path), Some((snap, fork))) = (store, snap_hold.as_ref()) {
        if let Some(last) = chain.last() {
            let hash = format!("0x{}", hex::encode(last.hash));
            if let Ok(header) = up.header_by_hash(&hash) {
                if let Ok(out) = checkpoint_at_snapshot(
                    &header,
                    snap,
                    fork.clone(),
                    Some("helios-bsc last-verified".into()),
                ) {
                    let _ = write_checkpoint_file(store_path, &out);
                }
            }
        }
    }
    let safe = safe_of(&chain)?;
    let lag = proof_lag(tip, safe.number);
    println!("tip:          {tip}");
    println!("safe:         {}  hash={}", safe.number, safe.hash);
    println!(
        "distinct:     {} (need {})",
        safe.distinct_sealers, safe.required_sealers
    );
    println!(
        "safe_lag:     {lag} blocks (~{}s)",
        helios_bsc_config::safe_lag_seconds(lag, mainnet_current_fork().block_interval_ms)
    );
    println!(
        "proof_window: {PROVIDER_PROOF_LOOKBACK}  in_window={}",
        within_proof_window(tip, safe.number)
    );

    if lag > PROVIDER_PROOF_LOOKBACK {
        bail!(
            "Safe lag {lag} > proof window {PROVIDER_PROOF_LOOKBACK} — fail-closed. Swap RPC key."
        );
    }

    let raw = up
        .get_proof_at_safe(address, &[], &safe.hash, safe.number)
        .with_context(|| {
            format!(
                "eth_getProof at Safe {} (lag {lag}) — provider window too shallow, swap key",
                safe.number
            )
        })?;
    let proof: EthAccountProof = serde_json::from_value(raw).context("decode eth_getProof")?;
    let root = decode_hex_fixed::<32>(&safe.state_root)?;
    let want = decode_hex_fixed::<20>(address)?;
    let acc = verify_eth_get_proof(&root, &want, &proof).context("MPT verify")?;
    println!(
        "mpt:          OK  nonce={} balance={}",
        acc.nonce,
        helios_bsc_execution::encode_qty(&acc.balance_wei)
    );

    if let Some(oracle_url) = soak_oracle.filter(|u| !u.trim().is_empty()) {
        if !independent_rpc_hosts(url, oracle_url) {
            bail!(
                "soak oracle must be a different host than upstream (both {})",
                rpc_host(oracle_url)
            );
        }
        let oracle = Upstream::new(oracle_url);
        let addrs = soak_list(address);
        println!(
            "diff vs oracle {} ({} addresses, Safe {})",
            rpc_host(oracle_url),
            addrs.len(),
            safe.number
        );
        let mut done = HashSet::new();
        let report = soak_until(
            up.as_ref(),
            &oracle,
            &addrs,
            &mut chain,
            snap_hold.as_mut().map(|(s, _)| s),
            SoakUntilOpts {
                burst: 2,
                pause: 8.0,
                min_unique: 1,
                max_empty: 6,
                lookback,
                max_sync,
                visit_all: false,
                // probe-safe reports the confirmation-depth Safe above; diff the
                // same head so the two numbers cannot disagree.
                fast_finality: false,
            },
            &mut done,
        )?;
        println!(
            "diff:         compared={} match={} mismatch={} skip={} unique={}",
            report.compared, report.matched, report.mismatched, report.skipped, report.unique
        );
        if report.mismatched > 0 {
            bail!("oracle mismatch (fail-closed)");
        }
        if report.compared == 0 {
            bail!("no addresses compared against oracle — fail-closed");
        }
    }

    println!("GATE:         PASS");
    Ok(())
}

struct SoakArgs<'a> {
    upstream: &'a str,
    backup: Option<&'a str>,
    oracle: &'a str,
    lookback: u64,
    max_sync: u64,
    checkpoint: Option<&'a std::path::Path>,
    max_age_hours: u64,
    allow_stale: bool,
    checkpoint_oracle: Option<&'a str>,
    require_multisource: bool,
    require_checkpoint: bool,
    rounds: u32,
    interval: f64,
    min_unique: u32,
    burst: usize,
    pause: f64,
    duration_secs: u64,
    /// Soak the head that `--finality fast` would serve, not confirmation depth.
    fast_finality: bool,
}

struct SoakUntilOpts {
    burst: usize,
    pause: f64,
    min_unique: u32,
    max_empty: u32,
    lookback: u64,
    max_sync: u64,
    /// Re-diff every address once (duration soak after unique is full).
    visit_all: bool,
    /// Compare at the BLS-finalized head instead of confirmation depth.
    fast_finality: bool,
}

#[derive(Debug, Default, Clone)]
struct SoakReport {
    compared: u32,
    matched: u32,
    mismatched: u32,
    skipped: u32,
    unique: u32,
    /// Comparisons that ran at the BLS-finalized head rather than confirmation depth.
    /// "Asked for fast finality" and "ran at fast finality" are different facts.
    compared_at_fast: u32,
}

fn soak_until(
    up: &dyn RpcUpstream,
    oracle: &Upstream,
    addrs: &[(&str, &str)],
    chain: &mut Vec<helios_bsc_consensus::VerifiedBlock>,
    mut snapshot: Option<&mut helios_bsc_consensus::Snapshot>,
    opts: SoakUntilOpts,
    done: &mut HashSet<String>,
) -> Result<SoakReport> {
    let burst = opts.burst.max(1);
    let mut give_up: HashSet<String> = HashSet::new();
    let mut pending = if opts.visit_all {
        addrs.to_vec()
    } else {
        unmatched(addrs, done)
    };
    let unique_cap = if opts.visit_all {
        usize::MAX
    } else {
        opts.min_unique as usize
    };
    let mut report = SoakReport::default();
    let mut empty = 0u32;
    while !pending.is_empty() && done.len() < unique_cap {
        let (tip, safe) = match wait_until_in_window_with(
            up,
            chain,
            opts.lookback,
            opts.max_sync,
            snapshot.as_deref_mut(),
            Duration::from_secs(20),
            opts.fast_finality,
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  wait window: {e}");
                report.skipped += 1;
                empty += 1;
                if empty >= opts.max_empty {
                    break;
                }
                std::thread::sleep(Duration::from_secs_f64(opts.pause.max(0.0)));
                continue;
            }
        };
        let lag = proof_lag(tip, safe.number);
        // Which head this burst *actually* used. `fast_finality_head` falls back to
        // confirmation depth whenever the snapshot carries no usable attestation, so a
        // run can ask for fast finality and never touch it. The gate needs the second
        // fact, not the first. Same derivation the RPC server publishes as
        // `read_head_is_fast`.
        let at_fast =
            opts.fast_finality && safe_of(chain).is_ok_and(|conf| conf.number != safe.number);
        let n = burst.min(pending.len());
        println!(
            "  burst n={n}  safe={}  tip={tip}  lag={lag}  head={}  unique={}/{}",
            safe.number,
            if at_fast { "fast" } else { "conf" },
            done.len(),
            opts.min_unique
        );
        let mut gained = 0u32;
        let mut compared_this = 0u32;
        for &(name, addr) in &pending[..n] {
            match diff_one(up, oracle, name, addr, &safe) {
                DiffOutcome::Match { local, remote } => {
                    report.compared += 1;
                    report.matched += 1;
                    compared_this += 1;
                    if at_fast {
                        report.compared_at_fast += 1;
                    }
                    if done.insert(addr_key(addr)) {
                        gained += 1;
                    }
                    eprintln!("  {name}  local={local}  oracle={remote}  OK");
                }
                DiffOutcome::Mismatch { local, remote } => {
                    eprintln!("  {name}  local={local}  oracle={remote}  MISMATCH");
                    bail!("oracle mismatch on {name} (fail-closed)");
                }
                DiffOutcome::SkipProof(e) => {
                    report.skipped += 1;
                    if proof_error_retryable(&e) {
                        eprintln!("  {name}  SKIP proof (retry): {e}");
                    } else {
                        give_up.insert(addr_key(addr));
                        eprintln!("  {name}  SKIP proof (drop): {e}");
                    }
                }
                DiffOutcome::SkipOracle(e) => {
                    report.skipped += 1;
                    eprintln!("  {name}  SKIP oracle: {e}");
                }
            }
        }
        if opts.visit_all {
            pending = pending.split_off(n.min(pending.len()));
        } else {
            pending = unmatched(&pending, done);
        }
        pending.retain(|(_, a)| !give_up.contains(&addr_key(a)));
        if soak_empty_burst(opts.visit_all, gained, compared_this) {
            empty += 1;
            if !opts.visit_all {
                let take = n.min(pending.len());
                rotate_front(&mut pending, take);
            }
            if empty >= opts.max_empty {
                break;
            }
        } else {
            empty = 0;
        }
        if !pending.is_empty() && (opts.visit_all || done.len() < unique_cap) {
            std::thread::sleep(Duration::from_secs_f64(opts.pause.max(0.0)));
        }
    }
    report.unique = done.len() as u32;
    Ok(report)
}

fn soak(args: SoakArgs<'_>) -> Result<()> {
    if args.rounds < 1 {
        bail!("--rounds must be >= 1");
    }
    if args.interval < 0.0 {
        bail!("--interval must be >= 0");
    }
    if args.min_unique < 1 {
        bail!("--min-unique must be >= 1");
    }
    if args.burst < 1 {
        bail!("--burst must be >= 1");
    }
    if args.pause < 0.0 {
        bail!("--pause must be >= 0");
    }
    checkpoint_policy(args.require_checkpoint, args.checkpoint.is_some())?;
    if !independent_rpc_hosts(args.upstream, args.oracle) {
        bail!(
            "soak oracle must be a different host than upstream (both {})",
            rpc_host(args.oracle)
        );
    }
    if let Some(b) = args.backup {
        if !independent_rpc_hosts(b, args.oracle) {
            bail!(
                "soak backup must be a different host than the oracle (both {})",
                rpc_host(args.oracle)
            );
        }
    }
    let up = open_data_plane(args.upstream, args.backup.map(str::to_string));
    let oracle = Upstream::new(args.oracle);
    let addrs: Vec<(&str, &str)> = SOAK_ADDRESSES.to_vec();
    println!("# helios-bsc soak (MPT vs independent oracle)");
    println!("upstream {}", rpc_host(args.upstream));
    if let Some(b) = args.backup {
        println!("backup   {}", rpc_host(b));
    }
    println!("oracle   {}", rpc_host(args.oracle));
    println!(
        "finality {}",
        if args.fast_finality {
            "fast (BEP-126 BLS finalized head)"
        } else {
            "confirmation-depth"
        }
    );
    println!(
        "rounds   {}  interval {}s  addresses {}  min_unique {}  burst {}  pause {}s  duration {}s",
        args.rounds,
        args.interval,
        addrs.len(),
        args.min_unique,
        args.burst,
        args.pause,
        args.duration_secs
    );

    let deadline = if args.duration_secs > 0 {
        Some(Instant::now() + Duration::from_secs(args.duration_secs))
    } else {
        None
    };

    let tip0 = up.block_number().context("eth_blockNumber")?;
    let mut snap_hold = None;
    let mut chain = if let Some(path) = args.checkpoint {
        let cp = load_checkpoint(path, args.max_age_hours, args.allow_stale)?;
        confirm_loaded_checkpoint(
            &cp,
            Some(path),
            args.upstream,
            args.checkpoint_oracle,
            args.require_multisource,
        )?;
        let (c, snap) = walk_from_checkpoint(up.as_ref(), cp, tip0, args.max_sync)?;
        snap_hold = Some(snap);
        c
    } else {
        if args.require_multisource {
            bail!("--require-multisource-checkpoint needs --checkpoint");
        }
        let from = tip0.saturating_sub(args.lookback.saturating_sub(1));
        eprintln!("headers {from}..={tip0} (kept across rounds; catch-up only)");
        walk_headers(up.as_ref(), from, tip0)?
    };

    // BLS vote keys only ever arrive with a checkpoint, and without them
    // `fast_finality_head` returns the confirmation-depth head. That fallback is the
    // safe direction, but silently: the run would print `GATE: PASS` having never
    // exercised the finality mode it was asked to gate. Refuse instead.
    if args.fast_finality
        && !snap_hold
            .as_ref()
            .is_some_and(helios_bsc_consensus::Snapshot::fast_finality_available)
    {
        bail!(
            "--finality fast needs a --checkpoint carrying BLS vote keys (write one with `write-checkpoint --sealing-set-from-epoch`); without them the soak falls back to confirmation depth and gates a mode it never ran"
        );
    }

    let mut tot = DiffReport::default();
    let mut fast_compared = 0u32;
    let mut done: HashSet<String> = HashSet::new();
    let mut round = 0u32;
    loop {
        round += 1;
        if deadline.is_none() && round > args.rounds {
            break;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        println!("== round {round}  unique_so_far={}", done.len());
        // Duration soaks fill unique first, then re-diff the full list each round.
        let visit_all = soak_repeat_full_list(args.duration_secs, done.len(), addrs.len());
        let round_target = if args.duration_secs > 0 {
            addrs.len() as u32
        } else {
            args.min_unique
        };
        let report = soak_until(
            up.as_ref(),
            &oracle,
            &addrs,
            &mut chain,
            snap_hold.as_mut(),
            SoakUntilOpts {
                burst: args.burst,
                pause: args.pause,
                min_unique: round_target,
                max_empty: 8,
                lookback: args.lookback,
                max_sync: args.max_sync,
                visit_all,
                fast_finality: args.fast_finality,
            },
            &mut done,
        )?;
        tot.compared += report.compared;
        tot.matched += report.matched;
        tot.mismatched += report.mismatched;
        tot.skipped += report.skipped;
        fast_compared += report.compared_at_fast;
        println!(
            "  round unique={}  compared={}  match={}  mismatch={}  skip={}",
            done.len(),
            report.compared,
            report.matched,
            report.mismatched,
            report.skipped
        );
        if tot.mismatched > 0 {
            bail!("oracle mismatch (fail-closed)");
        }
        let time_left = deadline.is_some_and(|d| Instant::now() < d);
        let more_fixed = deadline.is_none() && round < args.rounds;
        if time_left || more_fixed {
            if args.interval > 0.0 {
                std::thread::sleep(Duration::from_secs_f64(args.interval));
            }
            continue;
        }
        break;
    }
    let unique_best = done.len() as u32;
    println!(
        "# SUMMARY  compared={}  match={}  mismatch={}  skip={}  unique_best={}  at_fast_head={fast_compared}",
        tot.compared, tot.matched, tot.mismatched, tot.skipped, unique_best
    );
    if tot.mismatched > 0 {
        bail!("oracle mismatch (fail-closed)");
    }
    if tot.compared == 0 {
        bail!("no addresses compared against oracle — fail-closed");
    }
    if unique_best < args.min_unique {
        bail!(
            "unique matches {unique_best} < --min-unique {} (Ankr window/bursts). Swap to a deeper eth_getProof RPC.",
            args.min_unique
        );
    }
    // Vote keys were present at startup, so a zero here means every round fell back for
    // want of an attestation. Passing on that would certify the wrong head.
    if args.fast_finality && fast_compared == 0 {
        bail!(
            "--finality fast was requested but all {} comparisons ran at confirmation depth — no BLS-finalized head was ever reached",
            tot.compared
        );
    }
    println!("GATE:         PASS  unique={unique_best}  at_fast_head={fast_compared}");
    Ok(())
}

fn verify_checkpoint(
    path: &std::path::Path,
    upstream: &str,
    max_age_hours: u64,
    allow_stale: bool,
    oracle_url: Option<&str>,
    require_multisource: bool,
) -> Result<()> {
    let cp = load_checkpoint(path, max_age_hours, allow_stale)?;
    let age = checkpoint_age_secs(cp.timestamp, now_unix());
    let primary = Upstream::new(upstream);
    confirm_checkpoint_with_oracle(&cp, &primary).context("upstream disagrees with checkpoint")?;
    confirm_loaded_checkpoint(&cp, Some(path), upstream, oracle_url, require_multisource)?;
    println!("checkpoint:   {}", path.display());
    println!("number:       {}", cp.number);
    println!("hash:         {}", cp.hash);
    println!("stateRoot:    {}", cp.state_root);
    println!("n_seal:       {}", cp.sealing_set.len());
    println!(
        "fastFinality: {}",
        match &cp.vote_keys {
            Some(k) => format!("yes ({} BLS vote keys)", k.len()),
            None => "no (confirmation-depth until an epoch activates)".into(),
        }
    );
    println!("age_s:        {age}");
    println!("upstream:     {}", rpc_host(upstream));
    if let Some(url) = oracle_url.filter(|u| !u.trim().is_empty()) {
        println!("oracle:       {}", rpc_host(url));
    }
    println!("GATE:         PASS");
    Ok(())
}
