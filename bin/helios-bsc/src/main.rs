//! helios-bsc CLI — Parlia light client / verified local JSON-RPC.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use helios_bsc::bind::assert_listen_policy;
use helios_bsc::diff::{
    addr_key, diff_call_one, diff_finality_one, diff_one, proof_error_retryable, rotate_front,
    soak_empty_burst, soak_list, soak_repeat_full_list, unmatched, DiffOutcome, DiffReport,
    SOAK_ADDRESSES,
};
use helios_bsc::health::{judge, Health, HealthLimits, DEFAULT_MAX_LAG_SECONDS};
use helios_bsc::rpc_server::{self, FinalityMode, Node};
use helios_bsc::soak_state::{human_secs, SoakFingerprint, SoakState};
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
    assert_checkpoint_age, checkpoint_at_snapshot, epoch_seed_at, proof_lag,
    sealing_set_from_activated_epoch, vote_keys_from_activated_epoch, within_proof_window,
    EpochSeed, CHECKPOINT_WARN_AGE_SECS,
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
    /// Liveness probe for a running `run`: exit 0 while the head is moving, 1 otherwise.
    ///
    /// Asks the local RPC for `helios_bsc_syncStatus`, which is the one call that cannot
    /// be answered out of stale state. Reports; never restarts anything.
    Health {
        /// Local verified RPC to probe.
        #[arg(
            long,
            env = "HELIOS_BSC_LOCAL",
            default_value = "http://127.0.0.1:8545"
        )]
        url: String,
        /// Seconds of chain the Safe head may be behind the tip before this fails.
        #[arg(long, default_value_t = DEFAULT_MAX_LAG_SECONDS)]
        max_lag_seconds: u64,
        /// Optional additional bound in blocks. Unset by default: seconds is the honest
        /// unit for "the head stopped moving", and two bounds that disagree is one too many.
        #[arg(long)]
        max_lag_blocks: Option<u64>,
        /// Seconds to wait for a reply. Deliberately short and without retries: a probe
        /// that takes longer than the interval it runs on stops being a probe.
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
    },
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
        /// `fast` (default since the ≥24h soak passed 2026-08-24) uses the BEP-126
        /// BLS-finalized head, ~2 blocks behind the tip. It falls back to
        /// `confirmation-depth` — ~106–113 blocks — whenever no finalized head is known,
        /// for instance from a checkpoint carrying no BLS vote keys; the startup line
        /// says which rule is actually in force. `confirmation-depth` pins the older one.
        #[arg(long, value_enum, default_value_t = FinalityArg::Fast)]
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
        /// Optional: derived from --block when omitted.
        #[arg(long)]
        sealing_set_from_epoch: Option<String>,
        /// Second, independent host that must agree on the checkpoint header.
        ///
        /// The checkpoint is the whole root of trust — every later check is relative to
        /// it — so confirming it belongs at the moment it is created, not later.
        #[arg(long, env = "HELIOS_BSC_CHECKPOINT_ORACLE")]
        checkpoint_oracle: Option<String>,
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
        /// Carry the tally in this file so a crashed host resumes instead of restarting
        /// the duration clock. Soak time is summed over sessions and the gaps are
        /// reported, never folded into the total.
        #[arg(long)]
        state: Option<PathBuf>,
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

fn main() -> Result<()> {
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
        Commands::Health {
            url,
            max_lag_seconds,
            max_lag_blocks,
            timeout_secs,
        } => health_probe(
            &url,
            HealthLimits {
                max_lag_seconds: Some(max_lag_seconds),
                max_lag_blocks,
            },
            Duration::from_secs(timeout_secs),
        ),
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
            node.set_finality_mode(match finality {
                FinalityArg::Fast => FinalityMode::Fast,
                FinalityArg::ConfirmationDepth => FinalityMode::ConfirmationDepth,
            });
            // Say which rule is in force, not which one was asked for. Fast falls back to
            // confirmation depth without BLS vote keys — the safe direction, and until now
            // a silent one: the operator saw `--finality fast` accepted and a ~110-block
            // lag, with nothing on screen connecting the two.
            eprintln!(
                "{}",
                finality_startup_line(finality, node.fast_finality_armed())
            );
            // Ask the upstream, once, the question the first verified read will ask it.
            // A provider that only serves `eth_getProof` for the tag `latest` cannot
            // serve this client at all, and until now said so as a
            // `proof_verification_failed` on the operator's first balance query -- which
            // reads as a fault in the client rather than a provider that was never going
            // to work. See docs/proof-provider-matrix.md.
            if let Some(warning) = node.proof_capability_warning() {
                eprintln!("{warning}");
            }
            rpc_server::serve(Arc::new(node), &listen)
        }
        Commands::WriteCheckpoint {
            upstream,
            block,
            sealing_set,
            sealing_set_from_epoch,
            checkpoint_oracle,
            out,
        } => write_checkpoint(
            &upstream,
            &block,
            sealing_set.as_deref(),
            sealing_set_from_epoch.as_deref(),
            checkpoint_oracle.as_deref(),
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
            state,
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
            state: state.as_deref(),
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
    // Was still announcing "Demo Slice" three milestones later. `info` is the first
    // thing a new operator runs, so a stale line here is the first thing they read.
    println!("status:       MVP-2 — verified wallet reads, eth_call, receipts, logs, filters");
    println!("audited:      no");
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
        "soak:         soak --oracle URL [--min-unique 10] [--duration-secs 86400] [--state F]  (balance/nonce/slot0/eth_call vs independent host; --state resumes after a crash)"
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
    println!("docs:         docs/README.md  (start here: docs/quickstart.md)");
    Ok(())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

/// One request, one verdict, no retries.
///
/// Retrying here would be wrong twice over: the container runs this every 30 s, so a
/// probe that spends 90 s backing off overlaps its own next run; and a single failed
/// attempt is exactly the signal HEALTHCHECK is built to accumulate -- Docker already
/// applies its own `--retries` before it calls a container unhealthy. Doing it again in
/// here would just make the state change later and mean less.
fn health_probe(url: &str, limits: HealthLimits, timeout: Duration) -> Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "helios_bsc_syncStatus",
        "params": [],
    });
    let reply = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "helios-bsc-health")
        .send_json(&body);

    let verdict = match reply {
        Err(e) => Health::Unhealthy(format!("no answer from {}: {e}", rpc_host(url))),
        Ok(resp) => match resp.into_body().read_json::<serde_json::Value>() {
            Err(e) => Health::Unhealthy(format!("reply was not JSON: {e}")),
            Ok(envelope) => match helios_bsc::health::result_of(&envelope) {
                Err(reason) => Health::Unhealthy(reason),
                Ok(status) => judge(status, &limits),
            },
        },
    };

    if verdict.is_ok() {
        println!("healthy: {}", verdict.message());
        Ok(())
    } else {
        // stderr, and a plain non-zero exit. Docker records the last output line against
        // the container, so `docker inspect` carries the reason without a log dive.
        eprintln!("unhealthy: {}", verdict.message());
        std::process::exit(1);
    }
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
            // Not silent, and not fatal either: the operator asked for a second source
            // and did not get one, which is worth saying even though the run continues.
            eprintln!("{}", UNCONFIRMED_CHECKPOINT_WARNING);
            eprintln!(
                "ignoring --checkpoint-oracle: same host as upstream ({})",
                rpc_host(url)
            );
            return Ok(());
        }
        confirm_checkpoint_with_oracle(cp, &Upstream::new(url))?;
        eprintln!("checkpoint oracle OK ({})", rpc_host(url));
        return Ok(());
    }
    if checkpoint_path.is_some() {
        eprintln!("{}", UNCONFIRMED_CHECKPOINT_WARNING);
    }
    Ok(())
}

/// Said whenever a checkpoint is loaded without an independent source agreeing to it.
///
/// Everything this client verifies is verified *relative to the checkpoint*: the sealing
/// set comes from it, and every later header is checked against that set. A checkpoint
/// taken from a lying provider is therefore not one bad answer among many — it is a
/// self-consistent fake chain that passes every check downstream of it. That single fact
/// used to be the one thing the client never mentioned; `checkpoint_policy` already warns
/// when there is *no* checkpoint, and this is the symmetric case.
const UNCONFIRMED_CHECKPOINT_WARNING: &str = "warning: checkpoint not confirmed by a second source — it is the whole root of trust here, and every later check is relative to it. Pass --checkpoint-oracle <other-host> (add --require-multisource-checkpoint to make disagreement fatal).";

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

/// What `run` prints about finality at startup.
///
/// Three outcomes, not two: asking for fast and getting it is a different fact from
/// asking for fast and reading at confirmation depth anyway because the checkpoint
/// carries no BLS vote keys. The fallback stays — a deeper head is never the unsafe
/// answer — but it is named rather than inferred from a lag gauge.
fn finality_startup_line(arg: FinalityArg, armed: bool) -> String {
    match (arg, armed) {
        (FinalityArg::Fast, true) => {
            "finality: fast (BEP-126 BLS finalized head, ~2 blocks behind the tip)".into()
        }
        (FinalityArg::Fast, false) => concat!(
            "finality: confirmation-depth (~106-113 blocks) — fast is selected but this ",
            "checkpoint carries no BLS vote keys, so there is no finalized head to read at. ",
            "Write one with `write-checkpoint --sealing-set-from-epoch` to arm it."
        )
        .into(),
        (FinalityArg::ConfirmationDepth, _) => {
            "finality: confirmation-depth (~106-113 blocks behind the tip)".into()
        }
    }
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

/// Fail a checkpoint whose block sits between an epoch boundary and the height at which
/// that epoch's sealing set takes effect.
///
/// `walk_from_checkpoint` refuses such a checkpoint because adopting the announced set
/// would mean trusting an unverified header; catching it at write time turns a restart
/// failure into an immediate one, with a block number the operator can use instead.
/// The epoch whose `extraData` holds the sealing set in force at `number`.
///
/// The newest boundary at or below the block, and a refusal when that epoch has not
/// activated yet — the same window [`assert_outside_activation_window`] refuses, said
/// here so the operator gets a usable block number instead of a set that is about to be
/// replaced.
fn epoch_in_force(up: &Upstream, number: u64, epoch_length: u64) -> Result<u64> {
    if epoch_length == 0 {
        bail!("cannot derive an epoch: epoch length is 0 for block {number}");
    }
    let epoch_block = (number / epoch_length) * epoch_length;
    let Some(prev_block) = epoch_block.checked_sub(epoch_length) else {
        bail!("block {number} is in the first epoch; name a sealing set explicitly");
    };
    let epoch_header = fetch_header(up, &format!("0x{epoch_block:x}"))?;
    let prev_header = fetch_header(up, &format!("0x{prev_block:x}"))?;
    match epoch_seed_at(number, epoch_length, &epoch_header, &prev_header)? {
        EpochSeed::Active { epoch_block, .. } => Ok(epoch_block),
        EpochSeed::PendingActivation {
            epoch_block,
            activate_at,
        } => bail!(
            "block {number} is inside epoch {epoch_block}'s activation window (the set announced there takes effect at {activate_at}) — write the checkpoint at block {} instead",
            epoch_block.saturating_sub(1)
        ),
    }
}

fn assert_outside_activation_window(
    up: &Upstream,
    number: u64,
    epoch_length: u64,
    chosen_epoch: Option<u64>,
) -> Result<()> {
    if epoch_length == 0 {
        return Ok(());
    }
    let epoch_block = (number / epoch_length) * epoch_length;
    let Some(prev_block) = epoch_block.checked_sub(epoch_length) else {
        return Ok(());
    };
    let epoch_header = fetch_header(up, &format!("0x{epoch_block:x}"))?;
    let prev_header = fetch_header(up, &format!("0x{prev_block:x}"))?;
    match epoch_seed_at(number, epoch_length, &epoch_header, &prev_header)? {
        EpochSeed::Active { turn_length, .. } => {
            // An *already activated* epoch is not automatically the *current* one. Every
            // epoch below the checkpoint has activated, so `--sealing-set-from-epoch` with
            // a superseded one passed every check here and wrote a checkpoint carrying a
            // stale sealing set — which then failed at run time as
            // "difficulty 2 does not match in-turn (want 1)", a message that says nothing
            // about the real mistake.
            if let Some(chosen) = chosen_epoch.filter(|c| *c != epoch_block) {
                bail!(
                    "--sealing-set-from-epoch {chosen} is not the epoch in force at block {number}: that is {epoch_block}. Epoch {chosen} did activate, but {epoch_block} has since superseded it, so the set would be stale."
                );
            }
            println!("epoch     {epoch_block} active, turnLength={turn_length}");
            Ok(())
        }
        EpochSeed::PendingActivation {
            epoch_block,
            activate_at,
        } => bail!(
            "block {number} is inside epoch {epoch_block}'s activation window (the set announced there takes effect at {activate_at}) — write the checkpoint at block {} instead",
            epoch_block.saturating_sub(1)
        ),
    }
}

fn write_checkpoint(
    url: &str,
    block: &str,
    sealing_set: Option<&str>,
    sealing_set_from_epoch: Option<&str>,
    checkpoint_oracle: Option<&str>,
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
    let mut chosen_epoch: Option<u64> = None;
    let fork = params_at(number, timestamp);
    let set = match (sealing_set, sealing_set_from_epoch) {
        (Some(s), None) => parse_sealing_set(s)?,
        (None, Some(epoch_id)) => {
            let epoch_header = fetch_header(&up, epoch_id)?;
            chosen_epoch = Some(decode_u64(&epoch_header.number)?);
            vote_keys = Some(vote_keys_from_activated_epoch(&epoch_header, number)?);
            sealing_set_from_activated_epoch(&epoch_header, number)?
        }
        (Some(_), Some(_)) => {
            bail!("pass either --sealing-set or --sealing-set-from-epoch, not both")
        }
        // Neither flag: derive the epoch in force at `--block` and read the set from it.
        //
        // Naming it by hand never added any trust — the operator computed
        // `floor(block / epochLength) * epochLength` and typed it in, and the header still
        // came from the same upstream. What it did add was a barrier in front of the very
        // first command anyone runs, and an easy way to name a superseded epoch. The
        // trust control is `--checkpoint-oracle`, not this arithmetic.
        (None, None) => {
            let epoch_block = epoch_in_force(&up, number, fork.epoch_length)?;
            let epoch_header = fetch_header(&up, &format!("0x{epoch_block:x}"))?;
            chosen_epoch = Some(epoch_block);
            vote_keys = Some(vote_keys_from_activated_epoch(&epoch_header, number)?);
            sealing_set_from_activated_epoch(&epoch_header, number)?
        }
    };
    let attestation = if chosen_epoch.is_some() {
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
    // Before the file exists, not after: a checkpoint a second host will not vouch for
    // should never be written at all.
    match checkpoint_oracle.map(str::trim).filter(|u| !u.is_empty()) {
        Some(oracle) if !independent_rpc_hosts(url, oracle) => bail!(
            "--checkpoint-oracle must be a different host than --upstream (both {})",
            rpc_host(oracle)
        ),
        Some(oracle) => {
            confirm_checkpoint_with_oracle(&cp, &Upstream::new(oracle))
                .context("checkpoint oracle disagrees")?;
            println!("oracle    {} agrees", rpc_host(oracle));
        }
        None => eprintln!("{UNCONFIRMED_CHECKPOINT_WARNING}"),
    }
    // Refuse here what `walk_from_checkpoint` would refuse at run time, so the operator
    // finds out while writing the file rather than at the next restart. Roughly one block
    // in twelve falls in this window.
    assert_outside_activation_window(&up, number, fork.epoch_length, chosen_epoch)?;
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
        let mut report = SoakReport::default();
        soak_until(
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
            SoakSink {
                done: &mut done,
                report: &mut report,
                // probe-safe keeps no state file, so there is nothing to persist between
                // bursts — the run is a one-shot diagnostic, not a duration gate.
                persist: &mut |_, _| Ok(()),
            },
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
    /// Resumable tally; `None` keeps the old in-memory-only behaviour.
    state: Option<&'a std::path::Path>,
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
    checked_balance: u32,
    checked_nonce: u32,
    checked_slot0: u32,
    checked_call: u32,
    checked_finality: u32,
}

/// Everything a round writes to.
///
/// `persist` is called after every burst. A round runs for minutes; saving only when
/// [`soak_until`] returns meant a crashed host lost the whole round, and a round that
/// bailed saved nothing at all — `?` propagated straight past the caller's save. For a
/// module whose entire purpose is surviving a dead host, one round was the wrong
/// granularity.
struct SoakSink<'a> {
    done: &'a mut HashSet<String>,
    report: &'a mut SoakReport,
    persist: &'a mut dyn FnMut(&SoakReport, &HashSet<String>) -> Result<()>,
}

/// Write `base + round` to the soak state file, closing the open session at now.
///
/// Split out so the same accounting runs after every burst and again when the round
/// ends, however it ends. A partial round is real soak time and real comparisons; losing
/// them because the round did not finish is the overstatement's mirror image.
fn persist_soak(
    state: Option<&mut SoakState>,
    path: Option<&std::path::Path>,
    base: &DiffReport,
    base_fast: u32,
    round: &SoakReport,
    done: &HashSet<String>,
) -> Result<()> {
    let (Some(st), Some(path)) = (state, path) else {
        return Ok(());
    };
    st.compared = base.compared + round.compared;
    st.matched = base.matched + round.matched;
    st.mismatched = base.mismatched + round.mismatched;
    st.skipped = base.skipped + round.skipped;
    st.compared_at_fast = base_fast + round.compared_at_fast;
    st.checked_balance = base.checked_balance + round.checked_balance;
    st.checked_nonce = base.checked_nonce + round.checked_nonce;
    st.checked_slot0 = base.checked_slot0 + round.checked_slot0;
    st.checked_call = base.checked_call + round.checked_call;
    st.checked_finality = base.checked_finality + round.checked_finality;
    st.unique = {
        let mut v: Vec<String> = done.iter().cloned().collect();
        v.sort();
        v
    };
    st.touch_session(now_unix());
    st.save(path)
}

fn soak_until(
    up: &dyn RpcUpstream,
    oracle: &Upstream,
    addrs: &[(&str, &str)],
    chain: &mut Vec<helios_bsc_consensus::VerifiedBlock>,
    mut snapshot: Option<&mut helios_bsc_consensus::Snapshot>,
    opts: SoakUntilOpts,
    sink: SoakSink<'_>,
) -> Result<()> {
    let SoakSink {
        done,
        report,
        persist,
    } = sink;
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
    let mut empty = 0u32;
    // Once per round, not per address: `parlia_*` is served by few providers and the
    // ones that do serve it throttle hard.
    let mut finality_checked = false;
    // Bounded so an oracle that simply does not serve `parlia_*` costs a few lines per
    // round rather than one per burst. The zero it leaves in `# CHECKED` is the signal.
    let mut finality_attempts = 0u32;
    const FINALITY_ATTEMPTS_PER_ROUND: u32 = 3;
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
                eprintln!("  wait window: {e:#}");
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
        // Compare this client's BEP-126 heads with geth's own answer at the block our
        // snapshot is actually at -- the only direct coverage the attestation path gets.
        //
        // Once per round is the sampling rate, but "once" must mean one *verdict*, not
        // one attempt. The snapshot has adopted no attestation yet for the first bursts
        // after a bootstrap, and an oracle blip returns a skip; marking the round done on
        // either of those buys a silent `parlia_finality=0` in the summary, which is the
        // same fail-open shape the `# CHECKED` tally exists to expose.
        if !finality_checked && finality_attempts < FINALITY_ATTEMPTS_PER_ROUND {
            // `None` means the snapshot carries no attestation to compare, which costs no
            // oracle call and so must not spend an attempt.
            match snapshot.as_deref().and_then(|snap| {
                snap.justified()
                    .zip(snap.finalized())
                    .and_then(|((j, _), (f, _))| {
                        diff_finality_one(oracle, snap.number, snap.hash, (j, f))
                    })
            }) {
                Some(DiffOutcome::Match { local, remote, .. }) => {
                    finality_checked = true;
                    finality_attempts += 1;
                    report.compared += 1;
                    report.matched += 1;
                    report.checked_finality += 1;
                    eprintln!("  finality  local={local}  oracle={remote}  OK [parlia_finality]");
                }
                Some(DiffOutcome::Mismatch { local, remote }) => {
                    eprintln!("  finality  local={local}  oracle={remote}  MISMATCH");
                    bail!("parlia finality mismatch (fail-closed)");
                }
                Some(DiffOutcome::SkipProof(e) | DiffOutcome::SkipOracle(e)) => {
                    finality_attempts += 1;
                    let left = FINALITY_ATTEMPTS_PER_ROUND - finality_attempts;
                    eprintln!("  finality  SKIP ({left} attempt(s) left this round): {e}");
                }
                None => {}
            }
        }
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
                DiffOutcome::Match {
                    local,
                    remote,
                    checks,
                } => {
                    report.compared += 1;
                    report.matched += 1;
                    compared_this += 1;
                    report.checked_balance += 1;
                    report.checked_nonce += u32::from(checks.nonce);
                    report.checked_slot0 += u32::from(checks.slot0);
                    if at_fast {
                        report.compared_at_fast += 1;
                    }
                    if done.insert(addr_key(addr)) {
                        gained += 1;
                    }
                    eprintln!(
                        "  {name}  local={local}  oracle={remote}  OK [{}]",
                        checks.label()
                    );
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

            // A second, independent comparison for the same address: the EVM path rather
            // than the account trie. `None` means this address has no probe.
            if let Some(outcome) = diff_call_one(up, oracle, addr, &safe, chain) {
                match outcome {
                    DiffOutcome::Match { local, remote, .. } => {
                        report.compared += 1;
                        report.matched += 1;
                        compared_this += 1;
                        report.checked_call += 1;
                        if at_fast {
                            report.compared_at_fast += 1;
                        }
                        eprintln!("  {name}  local={local}  oracle={remote}  OK [eth_call]");
                    }
                    DiffOutcome::Mismatch { local, remote } => {
                        eprintln!("  {name}  local={local}  oracle={remote}  MISMATCH");
                        bail!("oracle eth_call mismatch on {name} (fail-closed)");
                    }
                    DiffOutcome::SkipProof(e) | DiffOutcome::SkipOracle(e) => {
                        report.skipped += 1;
                        eprintln!("  {name}  SKIP call: {e}");
                    }
                }
            }
        }
        persist(report, done)?;
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
    Ok(())
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

    // Resume before the clock is set: a crashed host must continue the duration gate,
    // not restart it.
    let fingerprint = SoakFingerprint {
        upstream: rpc_host(args.upstream),
        oracle: rpc_host(args.oracle),
        fast_finality: args.fast_finality,
        addresses: addrs.iter().map(|(_, a)| addr_key(a)).collect(),
    };
    let mut state = match args.state {
        Some(path) => {
            let resumed = SoakState::load(path, &fingerprint)?;
            let st = resumed.unwrap_or_else(|| SoakState::new(fingerprint.clone()));
            if st.soaked_secs() > 0 {
                println!(
                    "resume   {} soaked over {} session(s), compared={} unique={}{}",
                    human_secs(st.soaked_secs()),
                    st.sessions.len(),
                    st.compared,
                    st.unique.len(),
                    match st.largest_gap_secs() {
                        Some(g) => format!(", largest gap {}", human_secs(g)),
                        None => String::new(),
                    }
                );
            }
            Some(st)
        }
        None => None,
    };

    // With a state file the target is the *total*, so a resumed run asks only for what
    // is left. Without one this is unchanged.
    let this_session_secs = match (&state, args.duration_secs) {
        (_, 0) => 0,
        (Some(st), target) => st.remaining_secs(target),
        (None, target) => target,
    };
    // Already at the target: report and go straight to the summary. Falling through to
    // the fixed-round path would soak four more rounds right after saying there was
    // nothing left to do.
    let target_already_met = args.duration_secs > 0 && this_session_secs == 0;
    if target_already_met {
        println!(
            "already soaked {} >= --duration-secs {} — nothing left to run",
            human_secs(state.as_ref().map_or(0, SoakState::soaked_secs)),
            human_secs(args.duration_secs)
        );
    }

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
    if let Some(st) = state.as_ref() {
        tot.compared = st.compared;
        tot.matched = st.matched;
        tot.mismatched = st.mismatched;
        tot.skipped = st.skipped;
        tot.checked_balance = st.checked_balance;
        tot.checked_nonce = st.checked_nonce;
        tot.checked_slot0 = st.checked_slot0;
        tot.checked_call = st.checked_call;
        tot.checked_finality = st.checked_finality;
        fast_compared = st.compared_at_fast;
    }
    // A wedged walk and a slow one look identical for one round. They stop looking
    // identical quickly: the snapshot cannot skip a header, so a header it refuses is
    // refused again every round, forever. A 24h run that hits one spends 24h printing
    // the same error. Give up after a few barren rounds and say why.
    let mut barren_rounds = 0u32;
    const BARREN_ROUND_LIMIT: u32 = 3;
    let mut done: HashSet<String> = state.as_ref().map(SoakState::done_set).unwrap_or_default();
    // Both start *after* the catch-up walk. Walking a checkpoint forward can take
    // minutes, and charging that to the soak budget would let setup consume the window
    // -- with a short target it consumes all of it, and the recorded session would then
    // claim time during which nothing was compared.
    if !target_already_met {
        if let (Some(st), Some(path)) = (state.as_mut(), args.state) {
            st.open_session(now_unix());
            st.save(path)?;
        }
    }
    let deadline = if this_session_secs > 0 {
        Some(Instant::now() + Duration::from_secs(this_session_secs))
    } else {
        None
    };
    let mut round = 0u32;
    loop {
        round += 1;
        if target_already_met {
            break;
        }
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
        let mut report = SoakReport::default();
        let base = tot.clone();
        let base_fast = fast_compared;
        let outcome = {
            let mut st = state.as_mut();
            let mut persist = |r: &SoakReport, d: &HashSet<String>| {
                persist_soak(st.as_deref_mut(), args.state, &base, base_fast, r, d)
            };
            soak_until(
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
                SoakSink {
                    done: &mut done,
                    report: &mut report,
                    persist: &mut persist,
                },
            )
        };
        tot.compared += report.compared;
        tot.matched += report.matched;
        tot.mismatched += report.mismatched;
        tot.skipped += report.skipped;
        tot.checked_balance += report.checked_balance;
        tot.checked_nonce += report.checked_nonce;
        tot.checked_slot0 += report.checked_slot0;
        tot.checked_call += report.checked_call;
        tot.checked_finality += report.checked_finality;
        fast_compared += report.compared_at_fast;
        println!(
            "  round unique={}  compared={}  match={}  mismatch={}  skip={}",
            done.len(),
            report.compared,
            report.matched,
            report.mismatched,
            report.skipped
        );
        // Persist before the bails below — including `outcome` itself. A run that stops
        // for any reason should leave the hours it did complete on disk, and the round
        // that failed still soaked for as long as it ran.
        persist_soak(
            state.as_mut(),
            args.state,
            &tot,
            fast_compared,
            &SoakReport::default(),
            &done,
        )?;
        outcome?;
        if tot.mismatched > 0 {
            bail!("oracle mismatch (fail-closed)");
        }
        if report.compared == 0 {
            barren_rounds += 1;
            if barren_rounds >= BARREN_ROUND_LIMIT {
                bail!(
                    "{barren_rounds} consecutive rounds compared nothing — the walk is stuck, not slow. The errors above are the reason; a header the snapshot refuses is refused again every round."
                );
            }
        } else {
            barren_rounds = 0;
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
    // Which sub-checks the run actually reached. A storage or nonce column stuck at 0
    // means the oracle never served it and the trie went untested, which no amount of
    // OK lines would otherwise reveal.
    println!(
        "# CHECKED  balance={}  nonce={}  slot0={}  eth_call={}  parlia_finality={}",
        tot.checked_balance,
        tot.checked_nonce,
        tot.checked_slot0,
        tot.checked_call,
        tot.checked_finality
    );
    // Duration is a gate input, so it is reported as what it is: a sum over sessions,
    // with the worst interruption named. A reader must never have to assume continuity.
    if let Some(st) = state.as_ref() {
        println!(
            "# SOAKED   {} over {} session(s){}{}",
            human_secs(st.soaked_secs()),
            st.sessions.len(),
            match st.largest_gap_secs() {
                Some(g) => format!("  largest_gap={}", human_secs(g)),
                None => "  (uninterrupted)".to_string(),
            },
            if args.duration_secs > 0 {
                format!("  target={}", human_secs(args.duration_secs))
            } else {
                String::new()
            }
        );
    }
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
    // Same rule one level down. `--finality fast` gates the BEP-126 path, and the only
    // check that actually exercises attestation bookkeeping against geth is the
    // `parlia_*` cross-check. A run where it never produced a verdict — an oracle that
    // does not serve the namespace, or a snapshot that never adopted an attestation —
    // has not tested the thing it is about to certify.
    if args.fast_finality && tot.checked_finality == 0 {
        bail!(
            "--finality fast was requested but the parlia_* finality cross-check never ran (see the SKIP lines above). The soak oracle must serve parlia_getJustifiedNumber / parlia_getFinalizedNumber."
        );
    }
    // A resumable soak can be stopped early and restarted; without this the last
    // session would print PASS on a tally that never reached the target.
    if args.duration_secs > 0 {
        if let Some(st) = state.as_ref() {
            let short = st.remaining_secs(args.duration_secs);
            if short > 0 {
                bail!(
                    "soaked {} of --duration-secs {} — {} short. Re-run with the same --state to continue.",
                    human_secs(st.soaked_secs()),
                    human_secs(args.duration_secs),
                    human_secs(short)
                );
            }
        }
    }
    println!(
        "GATE:         PASS  unique={unique_best}  at_fast_head={fast_compared}  parlia_finality={}",
        tot.checked_finality
    );
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    /// The operator-facing default, flipped once the >=24h soak covered it. Pinned here
    /// because it is the one setting that changes what every wallet read resolves to, and
    /// a silent revert would look exactly like a slow provider.
    #[test]
    fn run_defaults_to_fast_finality() {
        let cli = Cli::try_parse_from(["helios-bsc", "run", "--upstream", "https://a.example"])
            .expect("run parses without --finality");
        match cli.cmd {
            Commands::Run { finality, .. } => assert_eq!(finality, FinalityArg::Fast),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    /// The soak keeps the older default on purpose: its fast mode additionally requires an
    /// oracle serving the `parlia_` namespace and fails closed without one, and most
    /// public BSC endpoints answer -32601. Defaulting a test harness to a hard failure
    /// helps nobody.
    #[test]
    fn soak_still_defaults_to_confirmation_depth() {
        let cli = Cli::try_parse_from([
            "helios-bsc",
            "soak",
            "--upstream",
            "https://a.example",
            "--oracle",
            "https://b.example",
        ])
        .expect("soak parses");
        match cli.cmd {
            Commands::Soak { finality, .. } => {
                assert_eq!(finality, FinalityArg::ConfirmationDepth)
            }
            other => panic!("expected Soak, got {other:?}"),
        }
    }

    /// The checkpoint is the whole root of trust: the sealing set comes from it and every
    /// later header is checked against that set, so a checkpoint from a lying provider is
    /// a self-consistent fake chain rather than one bad answer. Loading one unconfirmed
    /// used to say nothing at all. Pinned so the warning cannot quietly lose the parts
    /// that make it actionable.
    #[test]
    fn the_unconfirmed_checkpoint_warning_says_what_to_do() {
        let w = UNCONFIRMED_CHECKPOINT_WARNING;
        assert!(w.starts_with("warning:"), "{w}");
        assert!(
            w.contains("root of trust"),
            "it must say why it matters: {w}"
        );
        assert!(w.contains("--checkpoint-oracle"), "and how to fix it: {w}");
        assert!(
            w.contains("--require-multisource-checkpoint"),
            "and how to make it fatal: {w}"
        );
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Asking for fast and getting it, versus asking for fast and reading at confirmation
    /// depth anyway, must not print the same line.
    #[test]
    fn the_startup_line_names_the_rule_in_force_not_the_one_requested() {
        let armed = finality_startup_line(FinalityArg::Fast, true);
        assert!(armed.contains("fast"), "{armed}");
        assert!(armed.contains("~2 blocks"), "{armed}");

        let unarmed = finality_startup_line(FinalityArg::Fast, false);
        assert!(
            unarmed.starts_with("finality: confirmation-depth"),
            "an unarmed fast run reads at confirmation depth and must say so: {unarmed}"
        );
        assert!(
            unarmed.contains("no BLS vote keys"),
            "and must say why: {unarmed}"
        );
        assert!(
            unarmed.contains("--sealing-set-from-epoch"),
            "and how to fix it: {unarmed}"
        );
        assert_ne!(armed, unarmed);

        let conf = finality_startup_line(FinalityArg::ConfirmationDepth, true);
        assert!(conf.starts_with("finality: confirmation-depth"), "{conf}");
        assert!(
            !conf.contains("BLS vote keys"),
            "a deliberate choice is not a fallback: {conf}"
        );
    }
}
